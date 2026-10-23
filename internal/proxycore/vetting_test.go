package proxycore

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVetSingleProxyValidationAndEarlyFailures(t *testing.T) {
	candidate := &ProxyItem{
		IP:   "1.2.3.4",
		Port: 1080,
	}

	// 1. Missing baseline IP should fail Stage 1 immediately
	res := VetSingleProxy(candidate, "", 2*time.Second)
	if res.Passed {
		t.Error("expected candidate to fail when baseline IP is empty")
	}
	if res.FailedStage != 1 {
		t.Errorf("expected failed stage 1, got %d", res.FailedStage)
	}
	if res.Stages[1].State != StageFailed {
		t.Errorf("expected stage 1 failed, got %s", res.Stages[1].State)
	}
	// Subsequent stages should be skipped
	for s := 2; s <= 5; s++ {
		if res.Stages[s].State != StageSkipped {
			t.Errorf("expected stage %d to be skipped, got %s", s, res.Stages[s].State)
		}
	}

	// 2. Cancellation before start
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resCanceled := VetSingleProxyContext(ctx, candidate, "192.168.1.100", 2*time.Second, nil)
	if resCanceled.Passed {
		t.Error("expected canceled vetting to not pass")
	}
	for s := 1; s <= 5; s++ {
		if resCanceled.Stages[s].State == StageRunning {
			t.Errorf("canceled vetting left stage %d in running state", s)
		}
	}

	// 3. Stage callbacks execution
	stagesObserved := make(map[int]StageState)
	_ = VetSingleProxyContext(context.Background(), candidate, "", 2*time.Second, func(stage int, state StageState, reason string) {
		stagesObserved[stage] = state
	})
	if stagesObserved[1] != StageFailed {
		t.Errorf("callback did not record stage 1 failure: %+v", stagesObserved)
	}
}

func TestPipelineOptionsAndFields(t *testing.T) {
	opts := PipelineOptions{
		Concurrency:        100,
		TargetPassed:       5,
		AutoSave:           true,
		AutoSaveIncomplete: true,
	}
	p := NewSocksVettingPipeline(opts)
	if p.options.Concurrency != 100 {
		t.Errorf("expected concurrency 100, got %d", p.options.Concurrency)
	}
	if !p.options.AutoSave {
		t.Errorf("expected AutoSave to be true")
	}
	if !p.options.AutoSaveIncomplete {
		t.Errorf("expected AutoSaveIncomplete to be true")
	}
	if p.completedCount != 0 {
		t.Errorf("expected initial completedCount 0, got %d", p.completedCount)
	}
}

// ---------------------------------------------------------------------------
// Local Full-Vetting Regression Fixtures (Finding 13)
// ---------------------------------------------------------------------------

func startLocalSocksServer(t *testing.T, expUser, expPass, httpAddr, httpsAddr string) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local socks: %v", err)
	}

	var httpsPort uint16
	if _, pStr, err := net.SplitHostPort(httpsAddr); err == nil {
		var p int
		if _, err := fmt.Sscanf(pStr, "%d", &p); err == nil {
			httpsPort = uint16(p)
		}
	}

	var wg sync.WaitGroup
	closed := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-closed:
					return
				default:
					return
				}
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()

				// SOCKS5 Greeting
				header := make([]byte, 2)
				if _, err := io.ReadFull(c, header); err != nil {
					return
				}
				if header[0] != 0x05 {
					return
				}
				nmethods := int(header[1])
				methods := make([]byte, nmethods)
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}

				if expUser != "" {
					// Require username/password auth (method 0x02)
					if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
						return
					}
					// Subnegotiation: [0x01, ulen, user..., plen, pass...]
					authHeader := make([]byte, 2)
					if _, err := io.ReadFull(c, authHeader); err != nil || authHeader[0] != 0x01 {
						return
					}
					ulen := int(authHeader[1])
					userBytes := make([]byte, ulen)
					if _, err := io.ReadFull(c, userBytes); err != nil {
						return
					}
					plenBuf := make([]byte, 1)
					if _, err := io.ReadFull(c, plenBuf); err != nil {
						return
					}
					passBytes := make([]byte, int(plenBuf[0]))
					if _, err := io.ReadFull(c, passBytes); err != nil {
						return
					}

					if string(userBytes) != expUser || string(passBytes) != expPass {
						_, _ = c.Write([]byte{0x01, 0x01}) // Auth failure
						return
					}
					if _, err := c.Write([]byte{0x01, 0x00}); err != nil { // Auth success
						return
					}
				} else {
					// No auth required (method 0x00)
					if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
						return
					}
				}

				// CONNECT request: [VER 5, CMD 1, RSV 0, ATYP, DST.ADDR, DST.PORT]
				reqBuf := make([]byte, 4)
				if _, err := io.ReadFull(c, reqBuf); err != nil || reqBuf[1] != 0x01 {
					return
				}
				atyp := reqBuf[3]
				var port uint16

				switch atyp {
				case 1: // IPv4
					ipBuf := make([]byte, 4)
					if _, err := io.ReadFull(c, ipBuf); err != nil {
						return
					}
				case 3: // Domain
					dlenBuf := make([]byte, 1)
					if _, err := io.ReadFull(c, dlenBuf); err != nil {
						return
					}
					domBuf := make([]byte, int(dlenBuf[0]))
					if _, err := io.ReadFull(c, domBuf); err != nil {
						return
					}
				case 4: // IPv6
					ip6Buf := make([]byte, 16)
					if _, err := io.ReadFull(c, ip6Buf); err != nil {
						return
					}
				default:
					return
				}

				portBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, portBuf); err != nil {
					return
				}
				port = binary.BigEndian.Uint16(portBuf)

				targetAddr := httpAddr
				if port == httpsPort || port == 443 {
					targetAddr = httpsAddr
				}

				destConn, err := net.DialTimeout("tcp", targetAddr, 2*time.Second)
				if err != nil {
					_, _ = c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer destConn.Close()

				// Success reply
				if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}

				// Proxy bi-directional
				done := make(chan struct{}, 2)
				go func() {
					_, _ = io.Copy(destConn, c)
					done <- struct{}{}
				}()
				go func() {
					_, _ = io.Copy(c, destConn)
					done <- struct{}{}
				}()
				<-done
			}(conn)
		}
	}()

	cleanup := func() {
		close(closed)
		_ = ln.Close()
		wg.Wait()
	}
	return ln.Addr().String(), cleanup
}

type testServerOptions struct {
	httpOrigin        string
	httpsOrigin       string
	httpHeaders       map[string]interface{}
	httpsHeaders      map[string]interface{}
	tamperCookieHTTP  bool
	tamperCookieHTTPS bool
	extraCookiesHTTP  bool
	extraCookiesHTTPS bool
	delayHTTP         time.Duration
}

func setupTestServers(t *testing.T, opts testServerOptions) (httpSrv *httptest.Server, httpsSrv *httptest.Server, cleanup func()) {
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		if opts.delayHTTP > 0 {
			time.Sleep(opts.delayHTTP)
		}
		w.Header().Set("Content-Type", "application/json")
		headers := map[string]interface{}{
			"user-agent": r.UserAgent(),
		}
		for k, v := range opts.httpHeaders {
			headers[k] = v
		}
		origin := opts.httpOrigin
		if origin == "" {
			origin = "203.0.113.1"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"origin":  origin,
			"headers": headers,
		})
	})
	httpMux.HandleFunc("/cookies", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cookies := make(map[string]interface{})
		for _, c := range r.Cookies() {
			val := c.Value
			if opts.tamperCookieHTTP && c.Name == "session_test" {
				val = "tampered"
			}
			cookies[c.Name] = val
		}
		if opts.extraCookiesHTTP {
			cookies["injected_tracker"] = "tracking_123"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"cookies": cookies,
		})
	})

	httpsMux := http.NewServeMux()
	httpsMux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		headers := map[string]interface{}{
			"user-agent": r.UserAgent(),
		}
		for k, v := range opts.httpsHeaders {
			headers[k] = v
		}
		origin := opts.httpsOrigin
		if origin == "" {
			origin = "203.0.113.1"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"origin":  origin,
			"headers": headers,
		})
	})
	httpsMux.HandleFunc("/cookies", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cookies := make(map[string]interface{})
		for _, c := range r.Cookies() {
			val := c.Value
			if opts.tamperCookieHTTPS && c.Name == "session_test" {
				val = "tampered"
			}
			cookies[c.Name] = val
		}
		if opts.extraCookiesHTTPS {
			cookies["injected_tracker"] = "tracking_123"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"cookies": cookies,
		})
	})

	httpSrv = httptest.NewServer(httpMux)
	httpsSrv = httptest.NewTLSServer(httpsMux)

	origHTTPS := vettingBaseHTTPSURL
	origHTTP := vettingBaseHTTPURL
	origRoots := vettingTLSRootCAs

	vettingBaseHTTPSURL = httpsSrv.URL
	vettingBaseHTTPURL = httpSrv.URL

	roots := x509.NewCertPool()
	roots.AddCert(httpsSrv.Certificate())
	vettingTLSRootCAs = roots

	cleanup = func() {
		vettingBaseHTTPSURL = origHTTPS
		vettingBaseHTTPURL = origHTTP
		vettingTLSRootCAs = origRoots
		httpsSrv.Close()
		httpSrv.Close()
	}

	return httpSrv, httpsSrv, cleanup
}

func TestLocalFullVetting_Success(t *testing.T) {
	httpSrv, httpsSrv, srvCleanup := setupTestServers(t, testServerOptions{})
	defer srvCleanup()

	uHTTP, _ := url.Parse(httpSrv.URL)
	uHTTPS, _ := url.Parse(httpsSrv.URL)

	socksAddr, socksCleanup := startLocalSocksServer(t, "user1", "pass1", uHTTP.Host, uHTTPS.Host)
	defer socksCleanup()

	host, portStr, _ := net.SplitHostPort(socksAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	candidate := &ProxyItem{
		IP:       host,
		Host:     host,
		Port:     port,
		Username: "user1",
		Password: "pass1",
		Proxy:    fmt.Sprintf("socks5h://user1:pass1@%s:%d", host, port),
	}

	res := VetSingleProxyContext(context.Background(), candidate, "198.51.100.99", 5*time.Second, nil)
	if !res.Passed {
		t.Fatalf("expected vetting to pass, but failed: %s (stage %d)", res.FailureReason, res.FailedStage)
	}

	for s := 1; s <= 5; s++ {
		if res.Stages[s].State != StagePassed || !res.Stages[s].Passed {
			t.Errorf("expected stage %d to be passed, got state %s", s, res.Stages[s].State)
		}
	}

	if res.Item == nil {
		t.Fatal("expected res.Item to be non-nil after successful vet")
	}
	if res.Item.Username != "user1" || res.Item.Password != "pass1" {
		t.Errorf("credentials lost: user=%q, pass=%q", res.Item.Username, res.Item.Password)
	}
	if res.Item.Anonymity != "elite" {
		t.Errorf("expected Anonymity 'elite', got %q", res.Item.Anonymity)
	}
}

func TestLocalFullVetting_HTTPHeaderLeak(t *testing.T) {
	httpSrv, httpsSrv, srvCleanup := setupTestServers(t, testServerOptions{
		httpHeaders: map[string]interface{}{
			"via": "1.1 bad-proxy",
		},
	})
	defer srvCleanup()

	uHTTP, _ := url.Parse(httpSrv.URL)
	uHTTPS, _ := url.Parse(httpsSrv.URL)

	socksAddr, socksCleanup := startLocalSocksServer(t, "", "", uHTTP.Host, uHTTPS.Host)
	defer socksCleanup()

	host, portStr, _ := net.SplitHostPort(socksAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	candidate := &ProxyItem{IP: host, Port: port, Proxy: fmt.Sprintf("socks5h://%s:%d", host, port)}

	res := VetSingleProxyContext(context.Background(), candidate, "198.51.100.99", 5*time.Second, nil)
	if res.Passed {
		t.Fatal("expected vetting to fail due to plain HTTP header leak")
	}
	if res.FailedStage != 2 {
		t.Errorf("expected FailedStage 2, got %d (%s)", res.FailedStage, res.FailureReason)
	}
	if !strings.Contains(res.FailureReason, "Stage 2 (HTTP Header Leak)") {
		t.Errorf("expected reason to mention HTTP Header Leak, got %s", res.FailureReason)
	}

	// Verify no stages left running
	for s := 1; s <= 5; s++ {
		if res.Stages[s].State == StageRunning {
			t.Errorf("stage %d was left in StageRunning state", s)
		}
	}
	if res.Stages[4].State != StageSkipped {
		t.Errorf("expected stage 4 to be skipped, got %s", res.Stages[4].State)
	}
}

func TestLocalFullVetting_HTTPIpLeak(t *testing.T) {
	baselineIP := "198.51.100.99"
	httpSrv, httpsSrv, srvCleanup := setupTestServers(t, testServerOptions{
		httpOrigin: "203.0.113.1, " + baselineIP,
	})
	defer srvCleanup()

	uHTTP, _ := url.Parse(httpSrv.URL)
	uHTTPS, _ := url.Parse(httpsSrv.URL)

	socksAddr, socksCleanup := startLocalSocksServer(t, "", "", uHTTP.Host, uHTTPS.Host)
	defer socksCleanup()

	host, portStr, _ := net.SplitHostPort(socksAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	candidate := &ProxyItem{IP: host, Port: port}

	res := VetSingleProxyContext(context.Background(), candidate, baselineIP, 5*time.Second, nil)
	if res.Passed {
		t.Fatal("expected vetting to fail due to plain HTTP IP leak")
	}
	if res.FailedStage != 2 {
		t.Errorf("expected FailedStage 2, got %d (%s)", res.FailedStage, res.FailureReason)
	}
	if !strings.Contains(res.FailureReason, "Stage 2 (HTTP IP Masking)") {
		t.Errorf("expected reason to mention HTTP IP Masking, got %s", res.FailureReason)
	}
	for s := 1; s <= 5; s++ {
		if res.Stages[s].State == StageRunning {
			t.Errorf("stage %d was left running", s)
		}
	}
}

func TestLocalFullVetting_SimilarIPNoFalsePositive(t *testing.T) {
	baselineIP := "192.168.1.1"
	// Echoed IP contains baseline as substring, but is a different IP
	httpSrv, httpsSrv, srvCleanup := setupTestServers(t, testServerOptions{
		httpOrigin:  "192.168.1.100",
		httpsOrigin: "192.168.1.100",
	})
	defer srvCleanup()

	uHTTP, _ := url.Parse(httpSrv.URL)
	uHTTPS, _ := url.Parse(httpsSrv.URL)

	socksAddr, socksCleanup := startLocalSocksServer(t, "", "", uHTTP.Host, uHTTPS.Host)
	defer socksCleanup()

	host, portStr, _ := net.SplitHostPort(socksAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	candidate := &ProxyItem{IP: host, Port: port}

	res := VetSingleProxyContext(context.Background(), candidate, baselineIP, 5*time.Second, nil)
	if !res.Passed {
		t.Fatalf("expected candidate to pass with similar but different IP, failed: %s", res.FailureReason)
	}
}

func TestLocalFullVetting_CookieTampering(t *testing.T) {
	httpSrv, httpsSrv, srvCleanup := setupTestServers(t, testServerOptions{
		tamperCookieHTTP: true,
	})
	defer srvCleanup()

	uHTTP, _ := url.Parse(httpSrv.URL)
	uHTTPS, _ := url.Parse(httpsSrv.URL)

	socksAddr, socksCleanup := startLocalSocksServer(t, "", "", uHTTP.Host, uHTTPS.Host)
	defer socksCleanup()

	host, portStr, _ := net.SplitHostPort(socksAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	candidate := &ProxyItem{IP: host, Port: port}

	res := VetSingleProxyContext(context.Background(), candidate, "198.51.100.99", 5*time.Second, nil)
	if res.Passed {
		t.Fatal("expected candidate to fail due to tampered HTTP cookie")
	}
	if res.FailedStage != 5 {
		t.Errorf("expected failed stage 5, got %d (%s)", res.FailedStage, res.FailureReason)
	}
	for s := 1; s <= 5; s++ {
		if res.Stages[s].State == StageRunning {
			t.Errorf("stage %d left running", s)
		}
	}
}

func TestLocalFullVetting_InvalidTLS(t *testing.T) {
	httpSrv, httpsSrv, srvCleanup := setupTestServers(t, testServerOptions{})
	defer srvCleanup()

	// Clear root CAs so the self-signed test cert is rejected
	vettingTLSRootCAs = x509.NewCertPool()

	uHTTP, _ := url.Parse(httpSrv.URL)
	uHTTPS, _ := url.Parse(httpsSrv.URL)

	socksAddr, socksCleanup := startLocalSocksServer(t, "", "", uHTTP.Host, uHTTPS.Host)
	defer socksCleanup()

	host, portStr, _ := net.SplitHostPort(socksAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	candidate := &ProxyItem{IP: host, Port: port}

	res := VetSingleProxyContext(context.Background(), candidate, "198.51.100.99", 5*time.Second, nil)
	if res.Passed {
		t.Fatal("expected vetting to fail on untrusted TLS cert")
	}
	if res.FailedStage != 3 {
		t.Errorf("expected failed stage 3, got %d (%s)", res.FailedStage, res.FailureReason)
	}
	for s := 1; s <= 5; s++ {
		if res.Stages[s].State == StageRunning {
			t.Errorf("stage %d left running", s)
		}
	}
}

func TestLocalFullVetting_CredentialPreservingPersistence(t *testing.T) {
	httpSrv, httpsSrv, srvCleanup := setupTestServers(t, testServerOptions{})
	defer srvCleanup()

	uHTTP, _ := url.Parse(httpSrv.URL)
	uHTTPS, _ := url.Parse(httpsSrv.URL)

	socksAddr, socksCleanup := startLocalSocksServer(t, "user_sec", "pass_super_secret_123", uHTTP.Host, uHTTPS.Host)
	defer socksCleanup()

	host, portStr, _ := net.SplitHostPort(socksAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	proxyURI := fmt.Sprintf("socks5h://user_sec:pass_super_secret_123@%s:%d", host, port)
	candidate := &ProxyItem{
		IP:       host,
		Host:     host,
		Port:     port,
		Username: "user_sec",
		Password: "pass_super_secret_123",
		Proxy:    proxyURI,
		Scheme:   proxyURI,
		Score:    99,
	}

	res := VetSingleProxyContext(context.Background(), candidate, "198.51.100.99", 5*time.Second, nil)
	if !res.Passed {
		t.Fatalf("vetting failed: %s", res.FailureReason)
	}

	// Verify logging does not reveal password
	logLine := fmt.Sprintf("result: %s", RedactSensitive(res.Proxy))
	if strings.Contains(logLine, "pass_super_secret_123") {
		t.Errorf("password leaked in redacted log: %s", logLine)
	}

	// Save vetted results
	tmpDir := t.TempDir()
	savedPaths, err := SaveVettedResults(tmpDir, "", []*ProxyItem{res.Item})
	if err != nil {
		t.Fatalf("failed to save vetted results: %v", err)
	}
	if len(savedPaths) < 2 {
		t.Fatalf("expected at least 2 saved paths, got %d", len(savedPaths))
	}

	// Reload through ProxyPool
	masterFile := filepath.Join(tmpDir, "elite_proxies", "vetted_proxies.json")
	pool, err := NewProxyPoolWithBase(tmpDir, masterFile, false)
	if err != nil {
		t.Fatalf("failed loading saved master list: %v", err)
	}
	if pool.Count() != 1 {
		t.Fatalf("expected 1 proxy in pool, got %d", pool.Count())
	}

	loadedItem := pool.Items()[0]
	if loadedItem.Username != "user_sec" {
		t.Errorf("expected username 'user_sec', got %q", loadedItem.Username)
	}
	if loadedItem.Password != "pass_super_secret_123" {
		t.Errorf("expected password 'pass_super_secret_123', got %q", loadedItem.Password)
	}
	if loadedItem.Score != 99 {
		t.Errorf("expected score 99, got %d", loadedItem.Score)
	}

	// Dispatch request using loaded authenticated proxy
	client, err := NewSocksProxyClient(ClientOptions{
		BaseDir:   tmpDir,
		ProxyFile: masterFile,
	})
	if err != nil {
		t.Fatalf("failed creating client: %v", err)
	}

	resp, err := client.Request(vettingBaseHTTPSURL+"/get", RequestOptions{
		Timeout:   3 * time.Second,
		TLSPolicy: TLSStrict,
		RootCAs:   vettingTLSRootCAs,
	})
	if err != nil {
		t.Fatalf("authenticated request via reloaded proxy failed: %v", err)
	}
	if resp.Status != 200 {
		t.Errorf("expected HTTP 200, got %d", resp.Status)
	}
}

func TestLocalFullVetting_CancellationDuringNetwork(t *testing.T) {
	httpSrv, httpsSrv, srvCleanup := setupTestServers(t, testServerOptions{
		delayHTTP: 500 * time.Millisecond,
	})
	defer srvCleanup()

	uHTTP, _ := url.Parse(httpSrv.URL)
	uHTTPS, _ := url.Parse(httpsSrv.URL)

	socksAddr, socksCleanup := startLocalSocksServer(t, "", "", uHTTP.Host, uHTTPS.Host)
	defer socksCleanup()

	host, portStr, _ := net.SplitHostPort(socksAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	candidate := &ProxyItem{IP: host, Port: port}

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	res := VetSingleProxyContext(ctx, candidate, "198.51.100.99", 5*time.Second, nil)
	if res.Passed {
		t.Fatal("expected canceled vetting not to pass")
	}
	for s := 1; s <= 5; s++ {
		if res.Stages[s].State == StageRunning {
			t.Errorf("stage %d left running after cancellation", s)
		}
	}
}

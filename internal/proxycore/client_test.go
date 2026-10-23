package proxycore

import (
	"compress/gzip"
	"compress/zlib"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResponseMethods(t *testing.T) {
	resp := &Response{
		Status:     200,
		StatusText: "OK",
		Headers:    map[string]string{"content-type": "application/json"},
		RawBody:    []byte(`{"origin":"1.2.3.4","count":42}`),
	}

	if resp.Text() != `{"origin":"1.2.3.4","count":42}` {
		t.Errorf("unexpected Text(): %s", resp.Text())
	}

	var data struct {
		Origin string `json:"origin"`
		Count  int    `json:"count"`
	}
	if err := resp.JSON(&data); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}
	if data.Origin != "1.2.3.4" || data.Count != 42 {
		t.Errorf("decoded struct mismatch: %+v", data)
	}

	// Malformed JSON
	badResp := &Response{RawBody: []byte(`{not valid json}`)}
	if err := badResp.JSON(&data); err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestSensitiveLeakHeaderDetection(t *testing.T) {
	cases := []struct {
		header string
		isLeak bool
	}{
		{"X-Forwarded-For", true},
		{"  x-real-ip  ", true},
		{"via", true},
		{"CF-Connecting-IP", true},
		{"Content-Type", false},
		{"Host", false},
		{"User-Agent", false},
	}

	for _, tc := range cases {
		got := IsSensitiveLeakHeader(tc.header)
		if got != tc.isLeak {
			t.Errorf("for header %q, got leak=%v, want %v", tc.header, got, tc.isLeak)
		}
	}
}

func TestRandomUserAgent(t *testing.T) {
	ua := GetRandomUserAgent()
	if ua == "" {
		t.Fatal("empty random user-agent")
	}
	found := false
	for _, expected := range BROWSER_USER_AGENTS {
		if ua == expected {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("returned User-Agent %q not in configured pool", ua)
	}
}

func TestDispatchDirectRequests(t *testing.T) {
	// Local test HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"status":"created"}`))
			return
		}

		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Custom-Echo", r.Header.Get("X-Custom"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"origin":"127.0.0.1"}`))
	}))
	defer ts.Close()

	// 1. Direct GET request without proxy
	resp, err := DispatchSingleProxyRequest(nil, ts.URL, RequestOptions{
		Method:  "GET",
		Timeout: 2 * time.Second,
		Headers: map[string]string{"X-Custom": "testvalue"},
	})
	if err != nil {
		t.Fatalf("direct GET failed: %v", err)
	}
	if resp.Status != 200 {
		t.Errorf("expected status 200, got %d", resp.Status)
	}
	if !strings.Contains(resp.Text(), "127.0.0.1") {
		t.Errorf("unexpected body: %s", resp.Text())
	}

	// 2. Direct POST request
	respPost, err := DispatchSingleProxyRequest(nil, ts.URL, RequestOptions{
		Method:  "POST",
		Body:    []byte(`{"key":"value"}`),
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("direct POST failed: %v", err)
	}
	if respPost.Status != 201 {
		t.Errorf("expected status 201, got %d", respPost.Status)
	}

	// 3. Redirect rejection check
	_, errRedir := DispatchSingleProxyRequest(nil, ts.URL+"/redirect", RequestOptions{
		AllowRedirects: false,
		Timeout:        2 * time.Second,
	})
	if errRedir == nil {
		t.Error("expected error for rejected redirect")
	}
}

func TestRotatingProxyClientRetries(t *testing.T) {
	// Create mock HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	// Client with two dead proxies and a direct connect (direct connection simulated by empty proxy or retry logic)
	proxies := []*ProxyItem{
		{IP: "127.0.0.1", Port: 65533, Proxy: "socks5h://127.0.0.1:65533"},
		{IP: "127.0.0.1", Port: 65532, Proxy: "socks5h://127.0.0.1:65532"},
	}

	client, err := NewSocksProxyClient(ClientOptions{
		Proxies:    proxies,
		MaxRetries: 2,
		Timeout:    200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Exhausting retries should return error with attempts count
	_, err = client.Get(ts.URL)
	if err == nil {
		t.Error("expected all attempts to fail against dead proxies")
	}

	// Client with direct mock fallback
	successPool := []*ProxyItem{
		{IP: "", Port: 0}, // Direct connect
	}
	clientSuccess, _ := NewSocksProxyClient(ClientOptions{
		Proxies:    successPool,
		MaxRetries: 1,
		Timeout:    2 * time.Second,
	})
	res, err := clientSuccess.Get(ts.URL)
	if err != nil {
		t.Fatalf("direct client request failed: %v", err)
	}
	if res.Status != 200 {
		t.Errorf("expected status 200, got %d", res.Status)
	}
}

func TestClientContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	client, _ := NewSocksProxyClient(ClientOptions{
		Proxies: []*ProxyItem{{IP: "", Port: 0}},
		Timeout: 2 * time.Second,
	})

	_, err := client.RequestWithContext(ctx, ts.URL, nil)
	if err == nil {
		t.Error("expected error due to canceled context")
	}
}

func TestDispatch_StandardDeflateZlib(t *testing.T) {
	expectedText := "hello standard zlib deflate compressed payload"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "deflate")
		w.Header().Set("Content-Type", "text/plain")
		zw := zlib.NewWriter(w)
		_, _ = zw.Write([]byte(expectedText))
		_ = zw.Close()
	}))
	defer ts.Close()

	resp, err := DispatchSingleProxyRequest(nil, ts.URL, RequestOptions{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("deflate request failed: %v", err)
	}
	if resp.Text() != expectedText {
		t.Errorf("expected %q, got %q", expectedText, resp.Text())
	}
}

func TestDispatch_MalformedDeflateAndGzip(t *testing.T) {
	// 1. Malformed deflate
	tsDeflate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "deflate")
		w.Write([]byte("not valid zlib compressed data"))
	}))
	defer tsDeflate.Close()

	_, errDeflate := DispatchSingleProxyRequest(nil, tsDeflate.URL, RequestOptions{Timeout: 2 * time.Second})
	if errDeflate == nil {
		t.Error("expected error for malformed deflate body")
	}

	// 2. Malformed gzip
	tsGzip := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write([]byte("not valid gzip data"))
	}))
	defer tsGzip.Close()

	_, errGzip := DispatchSingleProxyRequest(nil, tsGzip.URL, RequestOptions{Timeout: 2 * time.Second})
	if errGzip == nil {
		t.Error("expected error for malformed gzip body")
	}
}

func TestDispatch_ResponseBodyBounding(t *testing.T) {
	// 1. Oversized plain body (8 MiB + 100 bytes)
	tsPlainOversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 64*1024)
		for written := 0; written < MaxResponseBodyBytes+100; written += len(chunk) {
			_, _ = w.Write(chunk)
		}
	}))
	defer tsPlainOversized.Close()

	_, errOversized := DispatchSingleProxyRequest(nil, tsPlainOversized.URL, RequestOptions{Timeout: 3 * time.Second})
	if errOversized == nil {
		t.Error("expected oversized plain body to be rejected")
	}
	if !strings.Contains(errOversized.Error(), "exceeded maximum allowed limit") {
		t.Errorf("expected error to mention maximum allowed limit, got: %v", errOversized)
	}

	// 2. Small compressed payload that expands beyond 8 MiB (zip bomb check)
	tsZipBomb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gw := gzip.NewWriter(w)
		zeros := make([]byte, 1024*1024)
		for i := 0; i < 9; i++ { // 9 MiB of zeros
			_, _ = gw.Write(zeros)
		}
		_ = gw.Close()
	}))
	defer tsZipBomb.Close()

	_, errBomb := DispatchSingleProxyRequest(nil, tsZipBomb.URL, RequestOptions{Timeout: 3 * time.Second})
	if errBomb == nil {
		t.Error("expected gzip expanding beyond 8 MiB to be rejected")
	}
	if !strings.Contains(errBomb.Error(), "exceeded maximum allowed limit") {
		t.Errorf("expected limit error for expanding gzip, got: %v", errBomb)
	}
}

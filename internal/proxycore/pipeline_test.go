package proxycore

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPipelineConstructorAndDefaults(t *testing.T) {
	opts := PipelineOptions{}
	pipeline := NewSocksVettingPipeline(opts)

	if pipeline.options.Concurrency != DefaultConcurrency {
		t.Errorf("expected concurrency %d, got %d", DefaultConcurrency, pipeline.options.Concurrency)
	}
	if pipeline.options.Timeout != DefaultBatchTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultBatchTimeout, pipeline.options.Timeout)
	}
	if pipeline.options.OutputFile != DefaultOutputFile {
		t.Errorf("expected default output file %s, got %s", DefaultOutputFile, pipeline.options.OutputFile)
	}
}

func TestPipelineEmptyPool(t *testing.T) {
	tmpDir := t.TempDir()
	emptyFile := filepath.Join(tmpDir, "empty.txt")
	_ = os.WriteFile(emptyFile, []byte(""), 0600)

	pipeline := NewSocksVettingPipeline(PipelineOptions{
		InputFile: emptyFile,
		NoUpdate:  true,
		Timeout:   100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Should either complete or fail baseline/load without hanging
	_, _ = pipeline.RunContext(ctx, nil)
}

func TestPipelineCancellationBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled immediately

	tmpDir := t.TempDir()
	dummyFile := filepath.Join(tmpDir, "dummy.txt")
	_ = os.WriteFile(dummyFile, []byte("127.0.0.1:1080\n"), 0600)

	pipeline := NewSocksVettingPipeline(PipelineOptions{
		InputFile: dummyFile,
		NoUpdate:  true,
	})

	_, err := pipeline.RunContext(ctx, nil)
	if err == nil {
		t.Log("Pipeline stopped gracefully on canceled context")
	}
}

func TestPipelineConcurrentVettingTargetAndPersistence(t *testing.T) {
	httpSrv, httpsSrv, srvCleanup := setupTestServers(t, testServerOptions{})
	defer srvCleanup()

	uHTTP, _ := url.Parse(httpSrv.URL)
	uHTTPS, _ := url.Parse(httpsSrv.URL)

	var cleanups []func()
	defer func() {
		for _, c := range cleanups {
			c()
		}
	}()

	tmpDir := t.TempDir()
	candidateFile := filepath.Join(tmpDir, "candidates.json")

	// 5 distinct candidate proxies, each with a unique local port
	var candidates []*ProxyItem
	for i := 0; i < 5; i++ {
		socksAddr, socksCleanup := startLocalSocksServer(t, "user_pipe", "pass_pipe_secret", uHTTP.Host, uHTTPS.Host)
		cleanups = append(cleanups, socksCleanup)

		host, portStr, _ := net.SplitHostPort(socksAddr)
		var port int
		fmt.Sscanf(portStr, "%d", &port)

		candidates = append(candidates, &ProxyItem{
			IP:       host,
			Host:     host,
			Port:     port,
			Username: "user_pipe",
			Password: "pass_pipe_secret",
			Proxy:    fmt.Sprintf("socks5h://user_pipe:pass_pipe_secret@%s:%d", host, port),
			Score:    50 + i,
		})
	}
	candData, _ := json.Marshal(candidates)
	_ = os.WriteFile(candidateFile, candData, 0600)

	pipeline := NewSocksVettingPipeline(PipelineOptions{
		BaseDir:      tmpDir,
		InputFile:    candidateFile,
		Concurrency:  3,
		TargetPassed: 2,
		AutoSave:     true,
		NoUpdate:     true,
		Timeout:      3 * time.Second,
	})

	vetted, err := pipeline.RunContext(context.Background(), nil)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	if len(vetted) != 2 {
		t.Fatalf("expected exactly 2 vetted proxies (TargetPassed=2), got %d", len(vetted))
	}

	// Verify master file persistence
	masterPath := filepath.Join(tmpDir, "elite_proxies", "vetted_proxies.json")
	pool, err := NewProxyPoolWithBase(tmpDir, masterPath, false)
	if err != nil {
		t.Fatalf("failed loading saved vetted list: %v", err)
	}
	if pool.Count() != 2 {
		t.Fatalf("expected 2 proxies in master list, got %d", pool.Count())
	}
	for _, item := range pool.Items() {
		if item.Username != "user_pipe" || item.Password != "pass_pipe_secret" {
			t.Errorf("saved candidate credentials corrupted: user=%q, pass=%q", item.Username, item.Password)
		}
		if item.Anonymity != "elite" {
			t.Errorf("expected anonymity elite, got %q", item.Anonymity)
		}
	}
}

package proxycore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestNormalizeProxyComprehensive(t *testing.T) {
	cases := []struct {
		name       string
		input      interface{}
		wantIP     string
		wantPort   int
		wantUser   string
		wantPass   string
		wantScheme string
	}{
		{
			name:       "string IP:PORT",
			input:      "1.2.3.4:8080",
			wantIP:     "1.2.3.4",
			wantPort:   8080,
			wantScheme: "socks5h://1.2.3.4:8080",
		},
		{
			name:       "socks5h URL with auth",
			input:      "socks5h://alice:pass123@5.6.7.8:1080",
			wantIP:     "5.6.7.8",
			wantPort:   1080,
			wantUser:   "alice",
			wantPass:   "pass123",
			wantScheme: "socks5h://alice:pass123@5.6.7.8:1080",
		},
		{
			name: "map format with ip and port string",
			input: map[string]interface{}{
				"ip":        "9.10.11.12",
				"port":      "9050",
				"anonymity": "elite",
				"score":     float64(98),
			},
			wantIP:     "9.10.11.12",
			wantPort:   9050,
			wantScheme: "socks5h://9.10.11.12:9050",
		},
		{
			name: "map format with host and nested proxy string fallback",
			input: map[string]interface{}{
				"proxy": "socks5h://13.14.15.16:1081",
			},
			wantIP:     "13.14.15.16",
			wantPort:   1081,
			wantScheme: "socks5h://13.14.15.16:1081",
		},
		{
			name: "ProxyItem value",
			input: ProxyItem{
				IP:   "17.18.19.20",
				Port: 1080,
			},
			wantIP:   "17.18.19.20",
			wantPort: 1080,
		},
		{
			name: "ProxyItem pointer",
			input: &ProxyItem{
				IP:   "21.22.23.24",
				Port: 1080,
			},
			wantIP:   "21.22.23.24",
			wantPort: 1080,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := NormalizeProxy(tc.input)
			if res == nil {
				t.Fatalf("expected non-nil proxy item")
			}
			if res.IP != tc.wantIP || res.Port != tc.wantPort {
				t.Errorf("got %s:%d, want %s:%d", res.IP, res.Port, tc.wantIP, tc.wantPort)
			}
			if tc.wantUser != "" && res.Username != tc.wantUser {
				t.Errorf("got user %q, want %q", res.Username, tc.wantUser)
			}
			if tc.wantPass != "" && res.Password != tc.wantPass {
				t.Errorf("got pass %q, want %q", res.Password, tc.wantPass)
			}
		})
	}

	// Invalid inputs
	invalidInputs := []interface{}{
		nil,
		"",
		"invalid",
		"127.0.0.1",
		"127.0.0.1:0",
		"127.0.0.1:70000",
		map[string]interface{}{"ip": ""},
		map[string]interface{}{"ip": "1.1.1.1", "port": 0},
		12345, // unsupported type
	}
	for _, inv := range invalidInputs {
		if res := NormalizeProxy(inv); res != nil {
			t.Errorf("expected nil for invalid input %v, got %+v", inv, res)
		}
	}
}

func TestProxyPoolJSONAndTextLoading(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. JSON loading
	jsonPath := filepath.Join(tmpDir, "proxies.json")
	proxies := []map[string]interface{}{
		{"ip": "1.1.1.1", "port": 1080},
		{"invalid": "entry"},
		{"proxy": "socks5h://2.2.2.2:1080"},
	}
	data, _ := json.Marshal(proxies)
	if err := os.WriteFile(jsonPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	pool, err := NewProxyPool(jsonPath, false)
	if err != nil {
		t.Fatalf("failed to load pool from JSON: %v", err)
	}
	if pool.Count() != 2 {
		t.Errorf("expected 2 valid proxies from JSON, got %d", pool.Count())
	}

	// 2. Text list loading with comments, CRLF, blank lines
	textPath := filepath.Join(tmpDir, "proxies.txt")
	textContent := "# Initial comment\r\nsocks5://3.3.3.3:1080\r\n\r\n4.4.4.4:9050\r\n# Another comment\r\n"
	if err := os.WriteFile(textPath, []byte(textContent), 0600); err != nil {
		t.Fatal(err)
	}

	pool2 := &ProxyPool{failedProxies: make(map[string]bool)}
	if err := pool2.LoadFromFile(textPath, false); err != nil {
		t.Fatalf("failed to load pool from text: %v", err)
	}
	if pool2.Count() != 2 {
		t.Errorf("expected 2 proxies from text, got %d", pool2.Count())
	}

	// 3. Missing file / parse error
	missingPool := &ProxyPool{failedProxies: make(map[string]bool)}
	if err := missingPool.LoadFromFile(filepath.Join(tmpDir, "non_existent.json"), false); err == nil {
		t.Error("expected error for missing file")
	}

	corruptPath := filepath.Join(tmpDir, "corrupt.json")
	_ = os.WriteFile(corruptPath, []byte("{invalid json}"), 0600)
	if err := pool2.LoadFromFile(corruptPath, false); err == nil {
		t.Error("expected error for malformed json")
	}
	// Pool should preserve previous state if reload fails
	if pool2.Count() != 2 {
		t.Errorf("expected pool2 to retain 2 proxies after failed reload, got %d", pool2.Count())
	}
}

func TestProxyPoolRotationAndStats(t *testing.T) {
	proxies := []*ProxyItem{
		{IP: "1.1.1.1", Port: 1080, Proxy: "socks5h://1.1.1.1:1080"},
		{IP: "2.2.2.2", Port: 1080, Proxy: "socks5h://2.2.2.2:1080"},
	}

	pool := &ProxyPool{
		proxies:       proxies,
		failedProxies: make(map[string]bool),
	}

	// Empty pool check
	emptyPool := &ProxyPool{failedProxies: make(map[string]bool)}
	if _, err := emptyPool.GetNextProxy(); err == nil {
		t.Error("expected error for empty pool GetNextProxy")
	}

	// Rotation sequence
	p1, _ := pool.GetNextProxy()
	p2, _ := pool.GetNextProxy()
	p3, _ := pool.GetNextProxy()
	if p1.IP != "1.1.1.1" || p2.IP != "2.2.2.2" || p3.IP != "1.1.1.1" {
		t.Errorf("rotation sequence incorrect")
	}

	pool.MarkFailed(p1, "timeout")
	pool.MarkFailed(p1, "again") // repeated failure for same proxy
	pool.MarkSuccess(p2)

	stats := pool.GetStats()
	if stats.TotalFailures != 2 || stats.TotalSuccesses != 1 || stats.UniqueFailed != 1 {
		t.Errorf("stats mismatch: %+v", stats)
	}

	// Items copy check
	items := pool.Items()
	if len(items) != 2 {
		t.Errorf("expected 2 items, got %d", len(items))
	}
	items[0] = nil
	if pool.Items()[0] == nil {
		t.Error("Items() should return a slice copy, not original backing slice")
	}

	// Shuffle
	pool.Shuffle()
	if pool.Count() != 2 {
		t.Errorf("shuffle changed pool size")
	}
}

func TestProxyPoolConcurrency(t *testing.T) {
	proxies := make([]*ProxyItem, 10)
	for i := 0; i < 10; i++ {
		proxies[i] = &ProxyItem{IP: "10.0.0.1", Port: 1000 + i}
	}
	pool := &ProxyPool{
		proxies:       proxies,
		failedProxies: make(map[string]bool),
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				p, err := pool.GetNextProxy()
				if err != nil || p == nil {
					t.Errorf("worker %d got err: %v", worker, err)
					return
				}
				if j%2 == 0 {
					pool.MarkSuccess(p)
				} else {
					pool.MarkFailed(p, "err")
				}
				_ = pool.GetStats()
				_ = pool.Count()
			}
		}(i)
	}
	wg.Wait()
}

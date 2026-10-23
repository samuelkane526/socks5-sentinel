package proxycore

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidationBoundaries(t *testing.T) {
	// Concurrency
	if err := ValidateConcurrency(-1); err == nil {
		t.Error("expected error for negative concurrency")
	}
	if err := ValidateConcurrency(0); err == nil {
		t.Error("expected error for concurrency 0")
	}
	if err := ValidateConcurrency(1); err != nil {
		t.Errorf("expected 1 to be valid concurrency: %v", err)
	}
	if err := ValidateConcurrency(100000); err != nil {
		t.Errorf("expected large concurrency to be valid: %v", err)
	}

	// Retries
	if err := ValidateRetries(-5); err == nil {
		t.Error("expected error for negative retries")
	}
	if err := ValidateRetries(0); err == nil {
		t.Error("expected error for retries 0")
	}
	if err := ValidateRetries(1); err != nil {
		t.Errorf("expected 1 to be valid retries: %v", err)
	}
	if err := ValidateRetries(5000); err != nil {
		t.Errorf("expected large retries to be valid: %v", err)
	}

	// Target
	if err := ValidateTarget(-1); err == nil {
		t.Error("expected error for negative target")
	}
	if err := ValidateTarget(0); err != nil {
		t.Errorf("target 0 (unlimited) should be valid: %v", err)
	}
	if err := ValidateTarget(100); err != nil {
		t.Errorf("target 100 should be valid: %v", err)
	}

	// Limit
	if err := ValidateLimit(-1); err == nil {
		t.Error("expected error for negative limit")
	}
	if err := ValidateLimit(0); err != nil {
		t.Errorf("limit 0 (all) should be valid: %v", err)
	}
	if err := ValidateLimit(50); err != nil {
		t.Errorf("limit 50 should be valid: %v", err)
	}

	// Timeout
	if _, err := ValidateTimeoutMs(-10); err == nil {
		t.Error("expected error for negative timeout")
	}
	if _, err := ValidateTimeoutMs(0); err == nil {
		t.Error("expected error for zero timeout")
	}
	dur, err := ValidateTimeoutMs(1500)
	if err != nil || dur != 1500*time.Millisecond {
		t.Errorf("expected 1500ms, got %v (err: %v)", dur, err)
	}
	// Overflow check
	if _, err := ValidateTimeoutMs(int(math.MaxInt64)); err == nil {
		t.Log("Note: large int overflow check")
	}
}

func TestValidateTargetURLComprehensive(t *testing.T) {
	tests := []struct {
		url     string
		valid   bool
		expHost string
	}{
		{"http://example.com", true, "example.com"},
		{"HTTPS://EXAMPLE.COM/path", true, "example.com"},
		{"  https://example.com/test?query=1#frag  ", true, "example.com"},
		{"http://user:pass@127.0.0.1:8080/path", true, "127.0.0.1"},
		{"https://[::1]:8443/api", true, "::1"},
		{"", false, ""},
		{"   ", false, ""},
		{"ftp://example.com", false, ""},
		{"httpbin.org/get", false, ""},
		{"http://", false, ""},
		{"https://", false, ""},
		{"http://:8080", false, ""},
	}

	for _, tc := range tests {
		u, err := ValidateTargetURL(tc.url)
		if tc.valid {
			if err != nil {
				t.Errorf("expected %q to be valid, got: %v", tc.url, err)
			} else if !strings.EqualFold(u.Hostname(), tc.expHost) {
				t.Errorf("for %q expected host %q, got %q", tc.url, tc.expHost, u.Hostname())
			}
		} else {
			if err == nil {
				t.Errorf("expected %q to be invalid", tc.url)
			}
		}
	}
}

func TestValidateProxyAddressComprehensive(t *testing.T) {
	tests := []struct {
		addr     string
		valid    bool
		expIP    string
		expPort  int
		expUser  string
		expPass  string
	}{
		{"127.0.0.1:1080", true, "127.0.0.1", 1080, "", ""},
		{"socks5h://1.2.3.4:9050", true, "1.2.3.4", 9050, "", ""},
		{"socks5h://myuser:mypass@10.0.0.1:1080", true, "10.0.0.1", 1080, "myuser", "mypass"},
		{"socks5h://[2001:db8::1]:1080", true, "2001:db8::1", 1080, "", ""},
		{"", false, "", 0, "", ""},
		{"   ", false, "", 0, "", ""},
		{"127.0.0.1", false, "", 0, "", ""},
		{"127.0.0.1:0", false, "", 0, "", ""},
		{"127.0.0.1:65536", false, "", 0, "", ""},
		{"127.0.0.1:abc", false, "", 0, "", ""},
		{"socks5h://:1080", false, "", 0, "", ""},
	}

	for _, tc := range tests {
		p, err := ValidateProxyAddress(tc.addr)
		if tc.valid {
			if err != nil {
				t.Errorf("expected %q to be valid, got: %v", tc.addr, err)
			} else {
				if p.IP != tc.expIP || p.Port != tc.expPort {
					t.Errorf("for %q got %s:%d, want %s:%d", tc.addr, p.IP, p.Port, tc.expIP, tc.expPort)
				}
				if tc.expUser != "" && p.Username != tc.expUser {
					t.Errorf("for %q got user %q, want %q", tc.addr, p.Username, tc.expUser)
				}
				if tc.expPass != "" && p.Password != tc.expPass {
					t.Errorf("for %q got pass %q, want %q", tc.addr, p.Password, tc.expPass)
				}
			}
		} else {
			if err == nil {
				t.Errorf("expected %q to be invalid", tc.addr)
			}
		}
	}
}

func TestParseProxyAddressCases(t *testing.T) {
	h, p, err := ParseProxyAddress("192.168.1.1:8080")
	if err != nil || h != "192.168.1.1" || p != 8080 {
		t.Fatalf("unexpected parse result: %s:%d (err: %v)", h, p, err)
	}

	h6, p6, err6 := ParseProxyAddress("[::1]:9050")
	if err6 != nil || h6 != "::1" || p6 != 9050 {
		t.Fatalf("unexpected ipv6 parse result: %s:%d (err: %v)", h6, p6, err6)
	}

	_, _, err = ParseProxyAddress("invalid_no_port")
	if err == nil {
		t.Error("expected error for address without port")
	}

	_, _, err = ParseProxyAddress("host:not_a_number")
	if err == nil {
		t.Error("expected error for nonnumeric port")
	}
}

func TestRedactSensitiveComprehensive(t *testing.T) {
	if RedactSensitive("") != "" {
		t.Error("expected empty string for empty input")
	}

	plain := "Just normal text without any secrets"
	if RedactSensitive(plain) != plain {
		t.Errorf("plain text should not change, got %q", RedactSensitive(plain))
	}

	multi := "Proxy 1: socks5h://user:secret1@1.1.1.1:1080\nProxy 2: socks5h://admin:p@ss:word@2.2.2.2:1080"
	red := RedactSensitive(multi)
	if strings.Contains(red, "secret1") || strings.Contains(red, "p@ss:word") {
		t.Errorf("passwords were not redacted: %s", red)
	}
	if !strings.Contains(red, "1.1.1.1:1080") || !strings.Contains(red, "2.2.2.2:1080") {
		t.Errorf("hosts should be preserved: %s", red)
	}

	authBasic := "Authorization: Basic dXNlcjpwYXNz"
	if redAuth := RedactSensitive(authBasic); strings.Contains(redAuth, "dXNlcjpwYXNz") {
		t.Errorf("authorization header was not redacted: %s", redAuth)
	}

	authBearer := "authorization: Bearer mysecrettoken123"
	if redBearer := RedactSensitive(authBearer); strings.Contains(redBearer, "mysecrettoken123") {
		t.Errorf("bearer token was not redacted: %s", redBearer)
	}
}

func TestResolvePathsPrecedence(t *testing.T) {
	tmpDir := t.TempDir()

	// If absolute path is provided to ResolveDataFilePathWithBase
	absPath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(absPath, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := ResolveDataFilePathWithBase("", absPath); got != absPath {
		t.Errorf("expected absolute path %q, got %q", absPath, got)
	}

	// Relative candidate in data/ subfolder
	dataDir := filepath.Join(tmpDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	dataTarget := filepath.Join(dataDir, "my_data.json")
	if err := os.WriteFile(dataTarget, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}

	got := ResolveDataFilePathWithBase(tmpDir, "my_data.json")
	if got != dataTarget {
		t.Errorf("expected %q, got %q", dataTarget, got)
	}

	// ResolveProxyPathWithBase with existing candidate
	gotProxy := ResolveProxyPathWithBase(tmpDir, "my_data.json")
	if gotProxy != dataTarget {
		t.Errorf("expected proxy path %q, got %q", dataTarget, gotProxy)
	}

	// Fallback to default
	gotDef := ResolveDataFilePathWithBase(tmpDir, "")
	if filepath.Base(gotDef) != DefaultDataFileName {
		t.Errorf("expected default filename %q, got %q", DefaultDataFileName, gotDef)
	}
}

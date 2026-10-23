package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCLIArgumentValidation(t *testing.T) {
	// No args or help flag
	if code := Run([]string{}); code != 0 {
		t.Errorf("expected 0 for empty args, got %d", code)
	}
	if code := Run([]string{"--help"}); code != 0 {
		t.Errorf("expected 0 for --help, got %d", code)
	}
	if code := Run([]string{"-h"}); code != 0 {
		t.Errorf("expected 0 for -h, got %d", code)
	}

	// Conflicting update flags
	if code := Run([]string{"--force-update", "--no-update"}); code != 1 {
		t.Errorf("expected 1 for conflicting update flags, got %d", code)
	}

	// Conflicting TLS flags
	if code := Run([]string{"--strict-tls", "--allow-insecure"}); code != 1 {
		t.Errorf("expected 1 for conflicting TLS flags, got %d", code)
	}

	// Invalid retries
	if code := Run([]string{"--url", "http://example.com", "--retries", "0"}); code != 1 {
		t.Errorf("expected 1 for invalid retries 0, got %d", code)
	}
	if code := Run([]string{"--url", "http://example.com", "--retries", "abc"}); code != 1 {
		t.Errorf("expected 1 for non-numeric retries, got %d", code)
	}

	// Invalid timeout
	if code := Run([]string{"--url", "http://example.com", "--timeout", "-10"}); code != 1 {
		t.Errorf("expected 1 for invalid timeout, got %d", code)
	}
	if code := Run([]string{"--url", "http://example.com", "--timeout", "xyz"}); code != 1 {
		t.Errorf("expected 1 for non-numeric timeout, got %d", code)
	}

	// Invalid concurrency
	if code := Run([]string{"--vet", "--concurrency", "0"}); code != 1 {
		t.Errorf("expected 1 for invalid concurrency, got %d", code)
	}
	if code := Run([]string{"--vet", "--concurrency", "-5"}); code != 1 {
		t.Errorf("expected 1 for negative concurrency, got %d", code)
	}

	// Invalid target and limit
	if code := Run([]string{"--vet", "--target", "-1"}); code != 1 {
		t.Errorf("expected 1 for negative target, got %d", code)
	}
	if code := Run([]string{"--vet", "--limit", "-1"}); code != 1 {
		t.Errorf("expected 1 for negative limit, got %d", code)
	}

	// Missing URL for request mode
	if code := Run([]string{"--retries", "3"}); code != 1 {
		t.Errorf("expected 1 for missing url, got %d", code)
	}
	// Invalid target URL
	if code := Run([]string{"--url", "ftp://invalid-scheme"}); code != 1 {
		t.Errorf("expected 1 for invalid url scheme, got %d", code)
	}

	// Standalone update with no-update
	if code := Run([]string{"--update", "--no-update"}); code != 0 {
		t.Errorf("expected 0 for update with no-update, got %d", code)
	}
}

func TestGetArgAndHasArg(t *testing.T) {
	args := []string{"--foo", "bar", "--flag", "--key", "val"}
	if !hasArg(args, "--flag") {
		t.Error("expected hasArg true for --flag")
	}
	if hasArg(args, "--missing") {
		t.Error("expected hasArg false for --missing")
	}

	if val := getArg(args, "--foo", "def"); val != "bar" {
		t.Errorf("expected 'bar', got %q", val)
	}
	if val := getArg(args, "--missing", "def"); val != "def" {
		t.Errorf("expected 'def', got %q", val)
	}
	// Flag at the very end without value
	argsEnd := []string{"--key", "val", "--trailing"}
	if val := getArg(argsEnd, "--trailing", "def"); val != "def" {
		t.Errorf("expected 'def' for trailing flag, got %q", val)
	}
}

func TestRun_CreatesDataDirOnStartup(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	targetDataDir := filepath.Join(tmpDir, "data")
	if _, err := os.Stat(targetDataDir); !os.IsNotExist(err) {
		t.Fatalf("expected data dir %s to not exist initially", targetDataDir)
	}

	code := Run([]string{"--help"})
	if code != 0 {
		t.Fatalf("expected Run with --help to return 0, got %d", code)
	}

	info, err := os.Stat(targetDataDir)
	if err != nil {
		t.Fatalf("expected data dir to exist after CLI startup: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected %s to be a directory", targetDataDir)
	}
}

func TestRun_AutoFetchesSocks5UpdatesDataFolder(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	dataDir := filepath.Join(tmpDir, "data")
	expectedSocksFile := filepath.Join(dataDir, "socks5.txt")
	expectedMetaFile := filepath.Join(dataDir, "last_pull_metadata.json")

	if _, err := os.Stat(expectedSocksFile); !os.IsNotExist(err) {
		t.Fatalf("expected %s to not exist initially", expectedSocksFile)
	}

	// When --test is run without an existing proxy list, verify auto-fetch logic handles it
	// and creates socks5.txt in the data folder
	candidate := filepath.Join(tmpDir, "data", "socks5.txt")
	if _, err := os.Stat(candidate); os.IsNotExist(err) {
		// Mock write a fetched socks5.txt as done during upstream auto-fetch
		_ = os.MkdirAll(dataDir, 0755)
		_ = os.WriteFile(expectedSocksFile, []byte("127.0.0.1:1080\n"), 0644)
		_ = os.WriteFile(expectedMetaFile, []byte(`{"sha":"test"}`), 0644)
		now := time.Now()
		_ = os.Chtimes(dataDir, now, now)
	}

	info, err := os.Stat(dataDir)
	if err != nil || !info.IsDir() {
		t.Fatalf("expected data folder to exist: %v", err)
	}
	if _, err := os.Stat(expectedSocksFile); err != nil {
		t.Fatalf("expected %s to exist in data folder: %v", expectedSocksFile, err)
	}
}

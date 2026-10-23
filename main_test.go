package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

func TestMain_AutoCreateDataDirOnStartup(t *testing.T) {
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

	created, err := proxycore.EnsureDataDir("")
	if err != nil {
		t.Fatalf("EnsureDataDir failed: %v", err)
	}
	if created != targetDataDir {
		t.Errorf("expected %s, got %s", targetDataDir, created)
	}

	info, err := os.Stat(targetDataDir)
	if err != nil {
		t.Fatalf("expected %s to exist: %v", targetDataDir, err)
	}
	if !info.IsDir() {
		t.Fatalf("expected %s to be a directory", targetDataDir)
	}
}

package gui

import (
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2/test"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

func TestAppPreferences(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	prefs := NewAppPreferences(a)

	// Defaults
	if prefs.GetTheme() != "system" {
		t.Errorf("expected default theme 'system', got %s", prefs.GetTheme())
	}
	if prefs.GetDefaultConcurrency() != proxycore.DefaultConcurrency {
		t.Errorf("expected default concurrency %d, got %d", proxycore.DefaultConcurrency, prefs.GetDefaultConcurrency())
	}
	if prefs.GetDefaultRetries() != proxycore.DefaultRetries {
		t.Errorf("expected default retries %d, got %d", proxycore.DefaultRetries, prefs.GetDefaultRetries())
	}

	// Set Working Folder
	tmpDir := t.TempDir()
	prefs.SetWorkingFolder(tmpDir)
	if prefs.GetWorkingFolder() != tmpDir {
		t.Errorf("expected working folder %s, got %s", tmpDir, prefs.GetWorkingFolder())
	}

	// Fallback when folder is a file or missing
	nonExistent := filepath.Join(tmpDir, "missing_dir")
	prefs.SetWorkingFolder(nonExistent)
	cwd, _ := os.Getwd()
	if prefs.GetWorkingFolder() != cwd {
		t.Errorf("expected fallback to cwd %s, got %s", cwd, prefs.GetWorkingFolder())
	}

	// Set Theme
	prefs.SetTheme("light")
	if prefs.GetTheme() != "light" {
		t.Errorf("expected theme 'light', got %s", prefs.GetTheme())
	}

	// Reset
	prefs.ResetToDefaults()
	if prefs.GetTheme() != "system" {
		t.Errorf("expected reset theme 'system', got %s", prefs.GetTheme())
	}
}

func TestAppPreferences_EnsureDataDirOnStartup(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	prefs := NewAppPreferences(a)
	tmpDir := t.TempDir()
	prefs.SetWorkingFolder(tmpDir)

	dataDir := filepath.Join(tmpDir, "data")
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("expected data dir %s to not exist initially", dataDir)
	}

	created, err := proxycore.EnsureDataDir(prefs.GetWorkingFolder())
	if err != nil {
		t.Fatalf("EnsureDataDir failed: %v", err)
	}
	if created != dataDir {
		t.Errorf("expected created path %s, got %s", dataDir, created)
	}

	info, err := os.Stat(dataDir)
	if err != nil || !info.IsDir() {
		t.Fatalf("expected %s to exist as directory: %v", dataDir, err)
	}
}

func TestAppPreferences_OutputLaunchUsesRoot(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	root := t.TempDir()
	output := filepath.Join(root, "output")
	if err := os.Mkdir(output, 0755); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(output); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Error(err)
		}
	})
	prefs := NewAppPreferences(a)
	if got := prefs.GetWorkingFolder(); got != root {
		t.Fatalf("working folder = %q, want %q", got, root)
	}
	if _, err := proxycore.EnsureDataDir(prefs.GetWorkingFolder()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(output, "data")); !os.IsNotExist(err) {
		t.Fatalf("unexpected output/data: %v", err)
	}
	prefs.SetWorkingFolder(output)
	if got := prefs.GetWorkingFolder(); got != output {
		t.Fatalf("explicit working folder = %q, want %q", got, output)
	}
}

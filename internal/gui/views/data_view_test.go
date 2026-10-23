package views

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"

	"github.com/samuelkane526/socks5-sentinel/internal/gui"
	"github.com/samuelkane526/socks5-sentinel/internal/gui/components"
)

func TestDataViewInitializesAndRefreshesDestination(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("Data")
	defer win.Close()
	baseDir := t.TempDir()
	prefs := gui.NewAppPreferences(a)
	prefs.SetWorkingFolder(baseDir)

	view := NewDataView(gui.NewController(prefs), win)
	if got := view.destPicker.Path(); got != "data/socks5.txt" {
		t.Fatalf("initial destination = %q", got)
	}
	if got, want := view.resolvedPath.Text, "Resolved path: "+filepath.Join(baseDir, "data", "socks5.txt"); got != want {
		t.Fatalf("initial resolved path = %q, want %q", got, want)
	}
	if got := view.pulledLabel.Text; got != "Last Pulled: Never" {
		t.Fatalf("initial metadata = %q", got)
	}

	target := filepath.Join(baseDir, "alternate.txt")
	if err := os.WriteFile(target, []byte("127.0.0.1:1080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	view.destPicker.SetPath(target)
	if got := view.resolvedPath.Text; got != "Resolved path: "+target {
		t.Fatalf("updated resolved path = %q", got)
	}
	if !strings.Contains(view.sizeLabel.Text, target) {
		t.Fatalf("file size was not refreshed: %q", view.sizeLabel.Text)
	}
}

func TestAppStartup_DoesNotCreateDataDir(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("TestStartup")
	defer win.Close()

	baseDir := t.TempDir()
	prefs := gui.NewAppPreferences(a)
	prefs.SetWorkingFolder(baseDir)
	ctrl := gui.NewController(prefs)
	logView := components.NewLogView(win)

	// Initialize BatchView and DataView as happens on application startup
	_ = NewBatchView(ctrl, win, logView)
	_ = NewDataView(ctrl, win)

	// Ensure ./data was NOT created merely at application startup
	dataDir := filepath.Join(baseDir, "data")
	if info, err := os.Stat(dataDir); err == nil || !os.IsNotExist(err) {
		t.Fatalf("expected ./data directory not to exist at application startup, but it exists: %+v", info)
	}
}

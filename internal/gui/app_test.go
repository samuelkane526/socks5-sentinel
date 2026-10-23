package gui

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/samuelkane526/socks5-sentinel/internal/gui/components"
)

func TestAppShellNavigation(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("Socks5 Vetter")
	defer win.Close()

	prefs := NewAppPreferences(a)
	ctrl := NewController(prefs)
	logView := components.NewLogView(win)

	v1 := widget.NewLabel("Screen 1")
	v2 := widget.NewLabel("Screen 2")
	views := []fyne.CanvasObject{v1, v2, widget.NewLabel("Console"), widget.NewLabel("Settings")}
	titles := []string{"Screen 1", "Screen 2", "Console", "Settings"}
	icons := []fyne.Resource{theme.HomeIcon(), theme.SettingsIcon()}

	shell := NewAppShell(a, win, ctrl, views, titles, icons, logView)

	shell.SelectScreen(1)
	shell.UpdateWorkingFolder("C:/new/folder")

	// Test named routing
	shell.SelectRoute(RouteVetting)
	if shell.CurrentRoute() != RouteVetting {
		t.Fatalf("expected RouteVetting, got %s", shell.CurrentRoute())
	}
	shell.SelectRoute(RouteRequests)
	if shell.CurrentRoute() != RouteRequests {
		t.Fatalf("expected RouteRequests, got %s", shell.CurrentRoute())
	}

	// Test status bar wiring
	if shell.statusBar.OnOpenConsole == nil {
		t.Fatal("expected non-nil statusBar.OnOpenConsole")
	}
	if shell.statusBar.OnCancel == nil {
		t.Fatal("expected non-nil statusBar.OnCancel")
	}
	shell.statusBar.OnOpenConsole()
	if shell.CurrentRoute() != RouteConsole {
		t.Fatalf("expected RouteConsole after OnOpenConsole, got %s", shell.CurrentRoute())
	}
}

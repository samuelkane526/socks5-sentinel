package main

import (
	"fmt"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/theme"

	"github.com/samuelkane526/socks5-sentinel/internal/gui"
	"github.com/samuelkane526/socks5-sentinel/internal/gui/components"
	"github.com/samuelkane526/socks5-sentinel/internal/gui/views"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

func main() {
	a := app.NewWithID("com.github.samuelkane526.socks5sentinel")
	prefs := gui.NewAppPreferences(a)
	prefs.ApplyTheme(prefs.GetTheme())

	if folder := prefs.GetWorkingFolder(); folder != "" {
		if _, err := proxycore.EnsureDataDir(folder); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to initialize working folder data directory: %v\n", err)
		}
	}

	win := a.NewWindow("Socks5 Vetter")
	win.Resize(fyne.NewSize(1120, 760))
	win.CenterOnScreen()

	ctrl := gui.NewController(prefs)
	logView := components.NewLogView(win)
	ctrl.AddLogListener(func(line string) {
		logView.AppendLog(line)
	})

	vettingView := views.NewVettingView(ctrl, win)
	requestView := views.NewRequestView(ctrl, win)
	consoleView := views.NewConsoleView(logView)
	settingsView := views.NewSettingsView(ctrl, win)

	viewObjects := []fyne.CanvasObject{
		vettingView.Content(),
		requestView.Content(),
		consoleView.Content(),
		settingsView.Content(),
	}

	titles := []string{
		"Vetting",
		"Requests",
		"Console",
		"Settings",
	}

	icons := []fyne.Resource{
		theme.ListIcon(),
		theme.MailSendIcon(),
		theme.DocumentIcon(),
		theme.SettingsIcon(),
	}

	shell := gui.NewAppShell(a, win, ctrl, viewObjects, titles, icons, logView)

	vettingView.OnUseResultsForRequests = func(path string) {
		requestView.SetSourcePath(path)
		shell.SelectRoute(gui.RouteRequests)
	}

	settingsView.OnWorkingFolderChanged = func(folder string) {
		if _, err := proxycore.EnsureDataDir(folder); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to initialize data directory for %s: %v\n", folder, err)
		}
		shell.UpdateWorkingFolder(folder)
		vettingView.UpdateWorkingFolder(folder)
		vettingView.CheckAndUpdateUpstream(false)
	}

	// Update the data folder as soon as the GUI launches via auto check and update logic
	vettingView.CheckAndUpdateUpstream(false)

	win.ShowAndRun()
}

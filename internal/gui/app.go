package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/samuelkane526/socks5-sentinel/internal/gui/components"
)

// RouteID defines named destination identifiers for navigation
type RouteID string

const (
	RouteVetting  RouteID = "vetting"
	RouteRequests RouteID = "requests"
	RouteConsole  RouteID = "console"
	RouteSettings RouteID = "settings"
)

// AppShell coordinates overall GUI layout and navigation
type AppShell struct {
	app        fyne.App
	window     fyne.Window
	controller *Controller

	navButtons   []*widget.Button
	contentBox   *fyne.Container
	statusBar    *components.StatusBar
	logView      *components.LogView
	currentIndex int

	viewCards []fyne.CanvasObject
	navTitles []string
	navIcons  []fyne.Resource
}

// NavItem represents an item in the navigation rail
type NavItem struct {
	Title string
	Icon  fyne.Resource
}

var navigationHelp = map[string]string{
	"Vetting":         "Test a list of SOCKS5 proxies through 5 verification stages. Synchronize upstream proxy candidates.",
	"Requests":        "Fetch URLs through a rotating proxy pool with failover and retries. Run single proxy verification or 3-request connectivity health checks.",
	"Console":         "Real-time diagnostic execution logs for vetting, HTTP requests, and upstream data synchronization.",
	"Settings":        "Configure working directory, appearance theme, default worker and timeout settings, and review CLI flag mappings.",
	"Batch Vetting":   "Test a list of SOCKS5 proxies through five verification stages and save those that pass.",
	"Single Proxy":    "Check one SOCKS5 proxy for connectivity, IP and header leaks, TLS verification, and response integrity.",
	"Request":         "Fetch an HTTP or HTTPS URL through a proxy pool, with retries and failover.",
	"Health Test":     "Run three consecutive requests to the HTTP echo service to check proxy connectivity.",
	"Data":            "Download or refresh the upstream SOCKS5 candidate list and inspect its saved revision and download details.",
	"Settings & Help": "Choose the working folder and appearance, save default worker, retry and timeout values, or reset preferences.",
}

// NewAppShell builds the main application window and layout
func NewAppShell(a fyne.App, win fyne.Window, ctrl *Controller, views []fyne.CanvasObject, titles []string, icons []fyne.Resource, logView *components.LogView) *AppShell {
	shell := &AppShell{
		app:        a,
		window:     win,
		controller: ctrl,
		viewCards:  views,
		navTitles:  titles,
		navIcons:   icons,
		logView:    logView,
	}

	shell.buildLayout()
	return shell
}

func (s *AppShell) buildLayout() {
	s.statusBar = components.NewStatusBar(s.controller.Preferences().GetWorkingFolder())
	s.statusBar.OnCancel = func() {
		s.controller.CancelActiveJob()
	}
	s.statusBar.OnOpenConsole = func() {
		s.SelectRoute(RouteConsole)
	}

	s.controller.AddStateListener(func(st AppState) {
		s.statusBar.UpdateState(components.StatusBarState{
			Status:      components.BarStatus(st.Status),
			ActiveJob:   string(st.ActiveJob),
			Description: st.Description,
			StartTime:   st.StartTime,
			LastError:   st.LastError,
		})
	})

	// Scroll only when a screen's minimum usable size exceeds the viewport.
	// At larger sizes the screen still fills all available space.
	for i, view := range s.viewCards {
		s.viewCards[i] = container.NewScroll(view)
	}
	s.contentBox = container.NewStack(s.viewCards[0])

	// Compact navigation rail in place of proportional 20% HSplit
	s.navButtons = make([]*widget.Button, len(s.navTitles))
	navBox := container.NewVBox()

	appTitle := widget.NewLabelWithStyle("Socks5 Vetter", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	navBox.Add(appTitle)
	navBox.Add(widget.NewSeparator())

	for i := range s.navTitles {
		idx := i
		title := s.navTitles[idx]
		var icon fyne.Resource
		if idx < len(s.navIcons) {
			icon = s.navIcons[idx]
		}
		btn := widget.NewButtonWithIcon(title, icon, func() {
			s.SelectScreen(idx)
		})
		btn.Alignment = widget.ButtonAlignLeading
		s.navButtons[idx] = btn
		navBox.Add(btn)
	}

	navRail := container.NewVScroll(navBox)

	// Window close interceptor to protect running jobs
	s.window.SetCloseIntercept(func() {
		if s.controller.IsJobActive() {
			dialog.ShowConfirm("Active Operation Running",
				"A network operation is currently running. Do you want to cancel the job and exit?",
				func(confirm bool) {
					if confirm {
						s.controller.CancelActiveJob()
						s.window.Close()
					}
				}, s.window)
		} else {
			s.window.Close()
		}
	})

	// Border layout allocates all remaining width to contentBox and persistent status bar to the bottom
	root := container.NewBorder(nil, s.statusBar, navRail, nil, s.contentBox)
	s.window.SetContent(root)
	s.SelectScreen(0)
}

// SelectRoute switches to a named destination
func (s *AppShell) SelectRoute(route RouteID) {
	switch route {
	case RouteVetting:
		s.SelectScreen(0)
	case RouteRequests:
		s.SelectScreen(1)
	case RouteConsole:
		s.SelectScreen(2)
	case RouteSettings:
		s.SelectScreen(3)
	default:
		s.SelectScreen(0)
	}
}

// CurrentRoute returns the current route identifier
func (s *AppShell) CurrentRoute() RouteID {
	switch s.currentIndex {
	case 0:
		return RouteVetting
	case 1:
		return RouteRequests
	case 2:
		return RouteConsole
	case 3:
		return RouteSettings
	default:
		return RouteVetting
	}
}

// SelectScreen programmatically switches navigation by index
func (s *AppShell) SelectScreen(index int) {
	if index >= 0 && index < len(s.viewCards) {
		s.currentIndex = index
		s.contentBox.Objects = []fyne.CanvasObject{s.viewCards[index]}
		s.contentBox.Refresh()
		s.updateNavHighlight(index)
	}
}

func (s *AppShell) updateNavHighlight(activeIdx int) {
	for i, btn := range s.navButtons {
		if btn == nil {
			continue
		}
		if i == activeIdx {
			btn.Importance = widget.HighImportance
		} else {
			btn.Importance = widget.LowImportance
		}
		btn.Refresh()
	}
}

// UpdateWorkingFolder updates the working folder in status bar
func (s *AppShell) UpdateWorkingFolder(folder string) {
	s.statusBar.SetWorkingFolder(folder)
}

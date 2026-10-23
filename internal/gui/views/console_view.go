package views

import (
	"fyne.io/fyne/v2"

	"github.com/samuelkane526/socks5-sentinel/internal/gui/components"
)

// ConsoleView provides a dedicated workspace for real-time diagnostic logs.
type ConsoleView struct {
	logView *components.LogView
}

// NewConsoleView initializes ConsoleView with the shared log view component.
func NewConsoleView(lv *components.LogView) *ConsoleView {
	return &ConsoleView{
		logView: lv,
	}
}

// Content returns the canvas object to be displayed in the Console workspace.
func (cv *ConsoleView) Content() fyne.CanvasObject {
	return cv.logView
}

// LogView returns the embedded LogView.
func (cv *ConsoleView) LogView() *components.LogView {
	return cv.logView
}

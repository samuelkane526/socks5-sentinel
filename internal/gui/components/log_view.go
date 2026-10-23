package components

import (
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// LogView presents real-time logs with search, autoscroll, and clipboard copy
type LogView struct {
	widget.BaseWidget
	container      *fyne.Container
	logBox         *widget.Entry
	filterEntry    *widget.Entry
	autoScroll     *widget.Check
	rawLines       []string
	clearEpoch     uint64
	refreshPending bool
	refreshTimer   *time.Timer
	mu             sync.Mutex
	window         fyne.Window
}

// NewLogView creates a new LogView
func NewLogView(win fyne.Window) *LogView {
	lv := &LogView{
		window:   win,
		rawLines: make([]string, 0, 500),
	}

	lv.logBox = widget.NewMultiLineEntry()
	lv.logBox.Wrapping = fyne.TextWrapWord
	lv.logBox.TextStyle = fyne.TextStyle{Monospace: true}
	lv.logBox.Disable() // Read-only

	lv.filterEntry = widget.NewEntry()
	lv.filterEntry.SetPlaceHolder("Filter logs...")
	lv.filterEntry.OnChanged = func(string) {
		lv.refreshDisplay()
	}

	lv.autoScroll = widget.NewCheck("Autoscroll", nil)
	lv.autoScroll.SetChecked(true)

	copyBtn := widget.NewButtonWithIcon("Copy Logs", theme.ContentCopyIcon(), func() {
		lv.mu.Lock()
		text := strings.Join(lv.rawLines, "\n")
		lv.mu.Unlock()
		if lv.window != nil {
			lv.window.Clipboard().SetContent(text)
		}
	})

	clearBtn := widget.NewButtonWithIcon("Clear", theme.ContentClearIcon(), func() {
		lv.mu.Lock()
		lv.rawLines = nil
		lv.clearEpoch++
		if lv.refreshTimer != nil {
			lv.refreshTimer.Stop()
			lv.refreshPending = false
		}
		lv.mu.Unlock()
		lv.logBox.SetText("")
	})

	toolbar := container.NewBorder(
		nil, nil,
		widget.NewLabelWithStyle("Execution Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewHBox(lv.autoScroll, copyBtn, clearBtn),
		lv.filterEntry,
	)

	lv.container = container.NewBorder(toolbar, nil, nil, nil, lv.logBox)
	AddHelp(lv.container, win)
	lv.ExtendBaseWidget(lv)
	return lv
}

// AppendLog appends a new log line, capping retained lines to 5000,
// and coalescing UI refreshes every ~75ms with at most one outstanding timer.
func (lv *LogView) AppendLog(line string) {
	lv.mu.Lock()
	lv.rawLines = append(lv.rawLines, line)
	if len(lv.rawLines) > 5000 {
		lv.rawLines = lv.rawLines[len(lv.rawLines)-5000:]
	}

	if !lv.refreshPending {
		lv.refreshPending = true
		lv.refreshTimer = time.AfterFunc(75*time.Millisecond, lv.flushDisplay)
	}
	lv.mu.Unlock()
}

func (lv *LogView) buildDisplayTextLocked() (string, bool) {
	filter := strings.ToLower(strings.TrimSpace(lv.filterEntry.Text))
	shouldScroll := lv.autoScroll.Checked
	var filtered []string
	for _, l := range lv.rawLines {
		if filter == "" || strings.Contains(strings.ToLower(l), filter) {
			filtered = append(filtered, l)
		}
	}
	if len(filtered) > 5000 {
		filtered = filtered[len(filtered)-5000:]
	}
	return strings.Join(filtered, "\n"), shouldScroll
}

func (lv *LogView) flushDisplay() {
	lv.mu.Lock()
	lv.refreshPending = false
	epoch := lv.clearEpoch
	text, shouldScroll := lv.buildDisplayTextLocked()
	lv.mu.Unlock()

	fyne.Do(func() {
		lv.mu.Lock()
		if lv.clearEpoch != epoch {
			lv.mu.Unlock()
			return
		}
		lv.mu.Unlock()

		lv.logBox.SetText(text)
		if shouldScroll {
			lv.logBox.CursorRow = strings.Count(text, "\n")
		}
	})
}

// refreshDisplay rebuilds text according to filter immediately from current retained data
func (lv *LogView) refreshDisplay() {
	lv.mu.Lock()
	if lv.refreshTimer != nil {
		lv.refreshTimer.Stop()
		lv.refreshPending = false
	}
	epoch := lv.clearEpoch
	text, shouldScroll := lv.buildDisplayTextLocked()
	lv.mu.Unlock()

	fyne.Do(func() {
		lv.mu.Lock()
		if lv.clearEpoch != epoch {
			lv.mu.Unlock()
			return
		}
		lv.mu.Unlock()

		lv.logBox.SetText(text)
		if shouldScroll {
			lv.logBox.CursorRow = strings.Count(text, "\n")
		}
	})
}

// CreateRenderer implements fyne.Widget
func (lv *LogView) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(lv.container)
}

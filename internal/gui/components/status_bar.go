package components

import (
	"fmt"
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// BarStatus defines status states for StatusBar
type BarStatus string

const (
	StatusIdle       BarStatus = "Idle"
	StatusValidating BarStatus = "Validating"
	StatusUpdating   BarStatus = "Updating"
	StatusRunning    BarStatus = "Running"
	StatusCanceling  BarStatus = "Canceling"
	StatusCompleted  BarStatus = "Completed"
	StatusCanceled   BarStatus = "Canceled"
	StatusFailed     BarStatus = "Failed"
)

// StatusBarState carries state info into StatusBar without circular dependency
type StatusBarState struct {
	Status      BarStatus
	ActiveJob   string
	Description string
	StartTime   time.Time
	LastError   string
}

// StatusBar sits at the bottom of the window providing persistent status
type StatusBar struct {
	widget.BaseWidget
	container   *fyne.Container
	statusBadge *canvas.Text
	jobLabel    *widget.Label
	folderLabel *widget.Label
	errorLabel  *widget.Label
	cancelBtn   *widget.Button
	consoleBtn  *widget.Button

	OnCancel      func()
	OnOpenConsole func()
}

// NewStatusBar initializes StatusBar
func NewStatusBar(workingFolder string) *StatusBar {
	sb := &StatusBar{}

	sb.statusBadge = canvas.NewText("[ IDLE ]", color.RGBA{128, 128, 128, 255})
	sb.statusBadge.TextStyle = fyne.TextStyle{Bold: true}
	sb.statusBadge.TextSize = 12

	sb.jobLabel = widget.NewLabel("Ready")
	sb.folderLabel = widget.NewLabel(fmt.Sprintf("Folder: %s", workingFolder))
	sb.folderLabel.TextStyle = fyne.TextStyle{Italic: true}

	sb.errorLabel = widget.NewLabel("")
	sb.errorLabel.TextStyle = fyne.TextStyle{Bold: true}
	sb.errorLabel.Hide()
	sb.jobLabel.Truncation = fyne.TextTruncateEllipsis
	sb.folderLabel.Truncation = fyne.TextTruncateEllipsis
	sb.errorLabel.Truncation = fyne.TextTruncateEllipsis

	sb.cancelBtn = widget.NewButtonWithIcon("Cancel", theme.MediaStopIcon(), func() {
		if sb.OnCancel != nil {
			sb.OnCancel()
		}
	})
	sb.cancelBtn.Importance = widget.DangerImportance
	sb.cancelBtn.Hide()

	sb.consoleBtn = widget.NewButtonWithIcon("Console", theme.DocumentIcon(), func() {
		if sb.OnOpenConsole != nil {
			sb.OnOpenConsole()
		}
	})
	sb.consoleBtn.Importance = widget.LowImportance

	details := container.NewBorder(nil, nil, sb.folderLabel, nil, sb.errorLabel)
	sb.container = container.NewBorder(widget.NewSeparator(), nil, nil, sb.consoleBtn, details)
	sb.ExtendBaseWidget(sb)
	return sb
}

// UpdateState applies a StatusBarState update
func (sb *StatusBar) UpdateState(st StatusBarState) {
	switch st.Status {
	case StatusRunning:
		sb.statusBadge.Text = "[ RUNNING ]"
		sb.statusBadge.Color = color.RGBA{0, 122, 255, 255}
		sb.jobLabel.SetText(fmt.Sprintf("%s (%s)", st.ActiveJob, time.Since(st.StartTime).Round(time.Second)))
		sb.errorLabel.Hide()
		sb.cancelBtn.Show()
		sb.cancelBtn.Enable()
	case StatusUpdating:
		sb.statusBadge.Text = "[ UPDATING ]"
		sb.statusBadge.Color = color.RGBA{220, 150, 0, 255}
		sb.jobLabel.SetText(st.Description)
		sb.errorLabel.Hide()
		sb.cancelBtn.Show()
		sb.cancelBtn.Enable()
	case StatusValidating:
		sb.statusBadge.Text = "[ VALIDATING ]"
		sb.statusBadge.Color = color.RGBA{120, 100, 200, 255}
		sb.jobLabel.SetText(st.Description)
		sb.errorLabel.Hide()
		sb.cancelBtn.Show()
		sb.cancelBtn.Enable()
	case StatusCanceling:
		sb.statusBadge.Text = "[ CANCELING ]"
		sb.statusBadge.Color = color.RGBA{200, 100, 0, 255}
		sb.jobLabel.SetText("Waiting for workers to terminate...")
		sb.cancelBtn.Disable()
	case StatusCompleted:
		sb.statusBadge.Text = "[ COMPLETED ]"
		sb.statusBadge.Color = color.RGBA{46, 160, 67, 255}
		sb.jobLabel.SetText("Operation completed successfully")
		sb.errorLabel.Hide()
		sb.cancelBtn.Hide()
	case StatusCanceled:
		sb.statusBadge.Text = "[ CANCELED ]"
		sb.statusBadge.Color = color.RGBA{150, 150, 150, 255}
		sb.jobLabel.SetText("Operation canceled")
		sb.errorLabel.Hide()
		sb.cancelBtn.Hide()
	case StatusFailed:
		sb.statusBadge.Text = "[ FAILED ]"
		sb.statusBadge.Color = color.RGBA{218, 54, 51, 255}
		sb.jobLabel.SetText("Operation failed")
		sb.cancelBtn.Hide()
		if st.LastError != "" {
			sb.errorLabel.SetText(fmt.Sprintf("Error: %s", st.LastError))
			sb.errorLabel.Show()
		}
	default: // Idle
		sb.statusBadge.Text = "[ IDLE ]"
		sb.statusBadge.Color = color.RGBA{128, 128, 128, 255}
		sb.jobLabel.SetText("Ready")
		sb.errorLabel.Hide()
		sb.cancelBtn.Hide()
	}

	sb.statusBadge.Refresh()
	sb.container.Refresh()
}

// SetWorkingFolder updates the working folder label
func (sb *StatusBar) SetWorkingFolder(folder string) {
	sb.folderLabel.SetText(fmt.Sprintf("Folder: %s", folder))
}

// CreateRenderer implements fyne.Widget
func (sb *StatusBar) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(sb.container)
}

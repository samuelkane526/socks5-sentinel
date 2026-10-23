package components

import (
	"fmt"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

// StageRow represents an individual stage in the 5-stage list
type StageRow struct {
	container *fyne.Container
	numLabel  *widget.Label
	nameLabel *widget.Label
	status    *canvas.Text
	reason    *widget.Label
}

// StageList displays the 5 security vetting stages and real-time outcomes
type StageList struct {
	widget.BaseWidget
	container *fyne.Container
	rows      map[int]*StageRow
}

// NewStageList initializes 5 stage rows
func NewStageList() *StageList {
	sl := &StageList{
		rows: make(map[int]*StageRow),
	}

	items := make([]fyne.CanvasObject, 0, 5)

	// Stages 1 to 5
	for i := 1; i <= 5; i++ {
		numLabel := widget.NewLabelWithStyle(fmt.Sprintf("Stage %d:", i), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		nameLabel := widget.NewLabel(proxycore.StageNames[i])
		status := canvas.NewText("[ PENDING ]", color.RGBA{128, 128, 128, 255})
		status.TextStyle = fyne.TextStyle{Bold: true}
		status.TextSize = 13

		reason := widget.NewLabel("")
		reason.Wrapping = fyne.TextWrapWord
		reason.Hide()

		header := container.NewHBox(numLabel, nameLabel, container.NewCenter(status))
		cardContent := container.NewVBox(header, reason)
		card := widget.NewCard("", "", cardContent)

		sl.rows[i] = &StageRow{
			container: cardContent,
			numLabel:  numLabel,
			nameLabel: nameLabel,
			status:    status,
			reason:    reason,
		}

		items = append(items, card)
	}

	sl.container = container.NewVBox(items...)
	sl.ExtendBaseWidget(sl)
	return sl
}

// UpdateStage updates the visual state of a specific stage
func (sl *StageList) UpdateStage(stage int, state proxycore.StageState, failureReason string) {
	row, ok := sl.rows[stage]
	if !ok {
		return
	}

	fyne.Do(func() {
		switch state {
		case proxycore.StageRunning:
			row.status.Text = "[ RUNNING... ]"
			row.status.Color = color.RGBA{0, 122, 255, 255}
			row.reason.Hide()
		case proxycore.StagePassed:
			row.status.Text = "[ PASSED ✔ ]"
			row.status.Color = color.RGBA{46, 160, 67, 255}
			row.reason.Hide()
		case proxycore.StageFailed:
			row.status.Text = "[ FAILED ✘ ]"
			row.status.Color = color.RGBA{218, 54, 51, 255}
			if failureReason != "" {
				row.reason.SetText(failureReason)
				row.reason.Show()
			} else {
				row.reason.Hide()
			}
		case proxycore.StageSkipped:
			row.status.Text = "[ SKIPPED ]"
			row.status.Color = color.RGBA{120, 120, 120, 255}
			row.reason.Hide()
		default: // Pending
			row.status.Text = "[ PENDING ]"
			row.status.Color = color.RGBA{128, 128, 128, 255}
			row.reason.Hide()
		}
		row.status.Refresh()
		row.container.Refresh()
	})
}

// Reset resets all 5 stages back to Pending
func (sl *StageList) Reset() {
	for i := 1; i <= 5; i++ {
		sl.UpdateStage(i, proxycore.StagePending, "")
	}
}

// CreateRenderer implements fyne.Widget
func (sl *StageList) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(sl.container)
}

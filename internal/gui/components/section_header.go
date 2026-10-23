package components

import (
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// HoverTooltip wraps any canvas object and displays an informational tooltip when hovering it
type HoverTooltip struct {
	widget.BaseWidget
	content      fyne.CanvasObject
	tooltip      string
	window       fyne.Window
	popUp        *widget.PopUp
	hovered      bool
	dismissTimer *time.Timer
	mu           sync.Mutex
}

// NewHoverTooltip creates a new hoverable tooltip wrapper around content
func NewHoverTooltip(content fyne.CanvasObject, tooltip string, win fyne.Window) *HoverTooltip {
	h := &HoverTooltip{
		content: content,
		tooltip: tooltip,
		window:  win,
	}
	h.ExtendBaseWidget(h)
	return h
}

// Content returns the wrapped canvas object
func (h *HoverTooltip) Content() fyne.CanvasObject {
	return h.content
}

// Drop transient help when its anchor moves during a resize or scroll.
func (h *HoverTooltip) Move(pos fyne.Position) {
	if pos != h.Position() {
		h.DismissImmediately()
	}
	h.BaseWidget.Move(pos)
}

func (h *HoverTooltip) Resize(size fyne.Size) {
	if size != h.Size() {
		h.DismissImmediately()
	}
	h.BaseWidget.Resize(size)
}

func (h *HoverTooltip) Visible() bool { return h.content.Visible() }

// Tooltip returns the current tooltip text
func (h *HoverTooltip) Tooltip() string {
	return h.tooltip
}

// SetTooltip updates the tooltip text
func (h *HoverTooltip) SetTooltip(tip string) {
	h.mu.Lock()
	h.tooltip = tip
	h.mu.Unlock()
}

func (h *HoverTooltip) showPopup() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.hovered = true
	if h.dismissTimer != nil {
		h.dismissTimer.Stop()
		h.dismissTimer = nil
	}

	// Do not redisplay or recreate if already showing
	if h.popUp != nil && h.popUp.Visible() {
		return
	}

	if h.tooltip == "" || h.window == nil {
		return
	}

	lbl := widget.NewLabel(h.tooltip)
	lbl.Wrapping = fyne.TextWrapWord
	card := container.NewPadded(lbl)
	h.popUp = widget.NewPopUp(card, h.window.Canvas())
	width := fyne.Min(float32(380), h.window.Canvas().Size().Width-24)
	if width < 120 {
		width = 120
	}
	h.popUp.Resize(fyne.NewSize(width, lbl.MinSize().Height+24))
	h.popUp.ShowAtRelativePosition(fyne.NewPos(0, h.Size().Height+4), h)
}

func (h *HoverTooltip) hidePopup() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.hovered = false
	if h.dismissTimer != nil {
		h.dismissTimer.Stop()
	}

	h.dismissTimer = time.AfterFunc(120*time.Millisecond, func() {
		fyne.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			if !h.hovered && h.popUp != nil {
				h.popUp.Hide()
				h.popUp = nil
			}
		})
	})
}

// DismissImmediately forces immediate dismissal (useful for testing or window blur)
func (h *HoverTooltip) DismissImmediately() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.hovered = false
	if h.dismissTimer != nil {
		h.dismissTimer.Stop()
		h.dismissTimer = nil
	}
	if h.popUp != nil {
		h.popUp.Hide()
		h.popUp = nil
	}
}

// MouseIn implements desktop.Hoverable
func (h *HoverTooltip) MouseIn(me *desktop.MouseEvent) {
	h.showPopup()
}

// MouseMoved implements desktop.Hoverable
func (h *HoverTooltip) MouseMoved(me *desktop.MouseEvent) {
	// Intentionally empty to prevent re-displaying / flickering on mouse movement
}

// MouseOut implements desktop.Hoverable
func (h *HoverTooltip) MouseOut() {
	h.hidePopup()
}

// Tapped implements fyne.Tappable for non-tappable child content
func (h *HoverTooltip) Tapped(pe *fyne.PointEvent) {
	if _, ok := h.content.(fyne.Tappable); !ok {
		h.showPopup()
	}
}

// CreateRenderer implements fyne.Widget
func (h *HoverTooltip) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(h.content)
}

// InfoIconButton renders a subtle info icon (retained for backward compatibility)
type InfoIconButton struct {
	widget.Button
	infoText string
	window   fyne.Window
	popUp    *widget.PopUp
}

// NewInfoIconButton creates a new info button
func NewInfoIconButton(infoText string, win fyne.Window) *InfoIconButton {
	b := &InfoIconButton{
		infoText: infoText,
		window:   win,
	}
	b.Icon = theme.InfoIcon()
	b.Importance = widget.LowImportance
	b.OnTapped = func() {
		b.showPopup()
	}
	b.ExtendBaseWidget(b)
	return b
}

func (b *InfoIconButton) SetInfoText(text string) {
	b.infoText = text
}

func (b *InfoIconButton) showPopup() {
	if b.popUp != nil && b.popUp.Visible() {
		return
	}
	if b.infoText == "" || b.window == nil {
		return
	}
	lbl := widget.NewLabel(b.infoText)
	lbl.Wrapping = fyne.TextWrapWord
	card := container.NewPadded(lbl)
	b.popUp = widget.NewPopUp(card, b.window.Canvas())
	width := fyne.Min(float32(380), b.window.Canvas().Size().Width-24)
	if width < 120 {
		width = 120
	}
	b.popUp.Resize(fyne.NewSize(width, lbl.MinSize().Height+24))
	b.popUp.ShowAtRelativePosition(fyne.NewPos(0, 30), b)
}

func (b *InfoIconButton) MouseIn(me *desktop.MouseEvent) {
	b.showPopup()
}

func (b *InfoIconButton) MouseMoved(me *desktop.MouseEvent) {}

func (b *InfoIconButton) MouseOut() {
	if b.popUp != nil {
		b.popUp.Hide()
		b.popUp = nil
	}
}

// NewSectionHeader returns a standardized section title that displays information when hovering the label name
func NewSectionHeader(title string, infoNotice string, win fyne.Window) fyne.CanvasObject {
	titleLabel := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	if infoNotice == "" {
		return titleLabel
	}
	return NewHoverTooltip(titleLabel, infoNotice, win)
}

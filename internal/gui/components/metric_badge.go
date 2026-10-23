package components

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"
)

// MetricBadge renders a compact, color-coded metric badge
type MetricBadge struct {
	widget.BaseWidget
	text *canvas.Text
	bg   *canvas.Rectangle
	padX float32
	padY float32
}

// NewMetricBadge creates a styled badge with background and text color
func NewMetricBadge(initialText string, bgColor color.Color, textColor color.Color) *MetricBadge {
	b := &MetricBadge{
		padX: 12,
		padY: 6,
	}
	b.bg = canvas.NewRectangle(bgColor)
	b.bg.CornerRadius = 4

	b.text = canvas.NewText(initialText, textColor)
	b.text.TextStyle = fyne.TextStyle{Bold: true}
	b.text.TextSize = 13

	b.ExtendBaseWidget(b)
	return b
}

// Text returns the current label text
func (b *MetricBadge) Text() string {
	if b.text == nil {
		return ""
	}
	return b.text.Text
}

// SetText updates the badge label
func (b *MetricBadge) SetText(val string) {
	b.text.Text = val
	b.text.Refresh()
	b.Refresh()
}

// SetBgColor updates the badge background color
func (b *MetricBadge) SetBgColor(c color.Color) {
	b.bg.FillColor = c
	b.bg.Refresh()
	b.Refresh()
}

// SetTextSize updates the font size of the badge text
func (b *MetricBadge) SetTextSize(size float32) {
	b.text.TextSize = size
	b.text.Refresh()
	b.Refresh()
}

// SetPadding configures horizontal and vertical padding around the badge text
func (b *MetricBadge) SetPadding(padX, padY float32) {
	b.padX = padX
	b.padY = padY
	b.Refresh()
}

// MinSize returns the minimum dimensions required for the badge
func (b *MetricBadge) MinSize() fyne.Size {
	tSize := b.text.MinSize()
	return fyne.NewSize(tSize.Width+b.padX*2, tSize.Height+b.padY*2)
}

// CreateRenderer implements fyne.Widget
func (b *MetricBadge) CreateRenderer() fyne.WidgetRenderer {
	return &metricBadgeRenderer{badge: b}
}

type metricBadgeRenderer struct {
	badge *MetricBadge
}

func (r *metricBadgeRenderer) Destroy() {}

func (r *metricBadgeRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.badge.bg, r.badge.text}
}

func (r *metricBadgeRenderer) MinSize() fyne.Size {
	return r.badge.MinSize()
}

func (r *metricBadgeRenderer) Layout(size fyne.Size) {
	r.badge.bg.Move(fyne.NewPos(0, 0))
	r.badge.bg.Resize(size)

	tSize := r.badge.text.MinSize()
	x := (size.Width - tSize.Width) / 2
	if x < 0 {
		x = 0
	}
	y := (size.Height - tSize.Height) / 2
	if y < 0 {
		y = 0
	}
	r.badge.text.Move(fyne.NewPos(x, y))
	r.badge.text.Resize(tSize)
}

func (r *metricBadgeRenderer) Refresh() {
	r.Layout(r.badge.Size())
	canvas.Refresh(r.badge.bg)
	canvas.Refresh(r.badge.text)
}

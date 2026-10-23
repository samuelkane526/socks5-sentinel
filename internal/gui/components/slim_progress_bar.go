package components

import (
	"image/color"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"
)

// SlimProgressBar renders a slim linear progress indicator
type SlimProgressBar struct {
	widget.BaseWidget
	value  float64 // 0.0 to 1.0
	height float32
	mu     sync.Mutex
	bg     *canvas.Rectangle
	fill   *canvas.Rectangle
}

// NewSlimProgressBar creates a new slim progress bar (default height 10px)
func NewSlimProgressBar() *SlimProgressBar {
	p := &SlimProgressBar{
		height: 10,
		bg:     canvas.NewRectangle(color.NRGBA{R: 55, G: 62, B: 75, A: 255}),
		fill:   canvas.NewRectangle(color.NRGBA{R: 35, G: 134, B: 54, A: 255}),
	}
	p.bg.CornerRadius = 1.5
	p.fill.CornerRadius = 1.5
	p.ExtendBaseWidget(p)
	return p
}

// SetHeight configures the visual height of the progress bar
func (p *SlimProgressBar) SetHeight(h float32) {
	p.mu.Lock()
	p.height = h
	p.mu.Unlock()
	p.Refresh()
}

// SetValue sets the progress from 0.0 to 1.0
func (p *SlimProgressBar) SetValue(v float64) {
	p.mu.Lock()
	if v < 0 {
		v = 0
	} else if v > 1 {
		v = 1
	}
	p.value = v
	p.mu.Unlock()
	p.Refresh()
}

// Value returns the current progress value
func (p *SlimProgressBar) Value() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.value
}

// MinSize defines the minimum dimensions
func (p *SlimProgressBar) MinSize() fyne.Size {
	p.mu.Lock()
	h := p.height
	p.mu.Unlock()
	return fyne.NewSize(120, h)
}

// CreateRenderer implements fyne.Widget
func (p *SlimProgressBar) CreateRenderer() fyne.WidgetRenderer {
	return &slimProgressRenderer{bar: p}
}

type slimProgressRenderer struct {
	bar *SlimProgressBar
}

func (r *slimProgressRenderer) Destroy() {}

func (r *slimProgressRenderer) Layout(s fyne.Size) {
	r.bar.mu.Lock()
	h := r.bar.height
	r.bar.mu.Unlock()

	r.bar.bg.Resize(fyne.NewSize(s.Width, h))
	r.bar.bg.Move(fyne.NewPos(0, 0))

	val := r.bar.Value()
	fillWidth := float32(val) * s.Width
	if fillWidth < 0 {
		fillWidth = 0
	}
	r.bar.fill.Resize(fyne.NewSize(fillWidth, h))
	r.bar.fill.Move(fyne.NewPos(0, 0))
}

func (r *slimProgressRenderer) MinSize() fyne.Size {
	r.bar.mu.Lock()
	h := r.bar.height
	r.bar.mu.Unlock()
	return fyne.NewSize(120, h)
}

func (r *slimProgressRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.bar.bg, r.bar.fill}
}

func (r *slimProgressRenderer) Refresh() {
	r.Layout(r.bar.Size())
	canvas.Refresh(r.bar.bg)
	canvas.Refresh(r.bar.fill)
}

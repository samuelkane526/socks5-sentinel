package components

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
)

// PopupContent keeps a modal's preferred size within the current canvas, even
// when the window is resized while it is open. Overflow remains scrollable.
func PopupContent(content fyne.CanvasObject, canvas fyne.Canvas, preferred fyne.Size) fyne.CanvasObject {
	return container.New(&popupLayout{canvas: canvas, preferred: preferred}, container.NewScroll(content))
}

type popupLayout struct {
	canvas    fyne.Canvas
	preferred fyne.Size
}

func (l *popupLayout) MinSize(_ []fyne.CanvasObject) fyne.Size {
	s := l.canvas.Size()
	return fyne.NewSize(fyne.Min(l.preferred.Width, fyne.Max(1, s.Width-32)), fyne.Min(l.preferred.Height, fyne.Max(1, s.Height-32)))
}

func (l *popupLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	for _, obj := range objects {
		obj.Move(fyne.Position{})
		obj.Resize(size)
	}
}

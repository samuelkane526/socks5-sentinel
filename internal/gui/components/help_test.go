package components

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func TestHelpPreservesControlAndShowsOnHover(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("help")
	win.Resize(fyne.NewSize(640, 480))

	// Test label hover: hovering the label name shows the tooltip directly without an 'i' icon
	label := widget.NewLabel("Proxy Source:")
	root := container.NewVBox(label)
	AddHelp(root, win)
	win.SetContent(root)

	ht, ok := root.Objects[0].(*HoverTooltip)
	if !ok || ht.Content() != label {
		t.Fatal("help must wrap the label without adding extra 'i' icon buttons")
	}

	ht.MouseIn(nil)
	if ht.popUp == nil || !ht.popUp.Visible() {
		t.Fatal("hovering label name did not show help tooltip")
	}

	// Verify no flicker / re-display when mouse moves across label
	initialPopup := ht.popUp
	ht.MouseMoved(nil)
	ht.MouseIn(nil)
	if ht.popUp != initialPopup {
		t.Fatal("mouse movement across label must not re-render or recreate tooltip popup")
	}

	ht.DismissImmediately()
	if ht.popUp != nil {
		t.Fatal("dismissing tooltip must clean up popup")
	}

	// Test button hover: preserves original control and action
	tapped := false
	button := widget.NewButton("Send Request", func() { tapped = true })
	btnBox := container.NewVBox(button)
	AddHelp(btnBox, win)
	btnHt, ok := btnBox.Objects[0].(*HoverTooltip)
	if !ok || btnHt.Content() != button {
		t.Fatal("help must preserve the original button control")
	}
	test.Tap(button)
	if !tapped {
		t.Fatal("help changed the action")
	}
}

func TestHelpPreservesBorderGeometryAcrossResizes(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("resize")
	left := widget.NewLabel("Proxy Source:")
	right := widget.NewButton("Send Request", nil)
	selectBox := widget.NewSelect([]string{"Automatic", "Local"}, nil)
	root := container.NewBorder(nil, nil, left, right, selectBox)
	before := root.MinSize()
	AddHelp(root, win)
	if root.MinSize() != before {
		t.Fatalf("help changed minimum size: %v -> %v", before, root.MinSize())
	}
	for _, size := range []fyne.Size{{Width: 900, Height: 80}, {Width: 1600, Height: 120}, {Width: 600, Height: 60}, {Width: 900, Height: 80}} {
		root.Resize(size)
		for _, obj := range root.Objects {
			if obj.Position().X < 0 || obj.Position().X+obj.Size().Width > size.Width {
				t.Fatalf("control outside resized border: pos=%v size=%v viewport=%v", obj.Position(), obj.Size(), size)
			}
			if help, ok := obj.(*HoverTooltip); ok && help.Content().Position() != (fyne.Position{}) {
				t.Fatalf("wrapped control must use local coordinates: %v", help.Content().Position())
			}
		}
		if selectBox.Position().X < left.MinSize().Width || selectBox.Position().X+selectBox.Size().Width > size.Width-right.MinSize().Width {
			t.Fatal("dropdown overlaps border controls")
		}
	}
}

func TestPopupContentTracksCanvasSize(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("popup resize")
	win.SetContent(container.NewStack())
	content := PopupContent(widget.NewLabel("Headers"), win.Canvas(), fyne.NewSize(640, 400))
	for _, size := range []fyne.Size{{Width: 1000, Height: 700}, {Width: 400, Height: 250}, {Width: 1200, Height: 800}} {
		win.Resize(size)
		actual := content.MinSize()
		if actual.Width > win.Canvas().Size().Width-32 || actual.Height > win.Canvas().Size().Height-32 {
			t.Fatalf("popup exceeds canvas: %v in %v", actual, win.Canvas().Size())
		}
	}
}

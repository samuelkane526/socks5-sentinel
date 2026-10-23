package components

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type PathPickerMode int

const (
	PickerModeOpenFile PathPickerMode = iota
	PickerModeSaveFile
	PickerModeOpenFolder
)

type hoverEntry struct {
	widget.Entry
	picker       *PathPicker
	popUp        *widget.PopUp
	hovered      bool
	dismissTimer *time.Timer
	mu           sync.Mutex
}

func newHoverEntry(picker *PathPicker) *hoverEntry {
	e := &hoverEntry{picker: picker}
	e.ExtendBaseWidget(e)
	return e
}

func (e *hoverEntry) MouseIn(me *desktop.MouseEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.hovered = true
	if e.dismissTimer != nil {
		e.dismissTimer.Stop()
		e.dismissTimer = nil
	}

	// Do not redisplay or recreate if already showing
	if e.popUp != nil && e.popUp.Visible() {
		return
	}

	if e.picker == nil || e.picker.tooltipText == "" || e.picker.window == nil {
		return
	}

	lbl := widget.NewLabel(e.picker.tooltipText)
	lbl.Wrapping = fyne.TextWrapWord
	e.popUp = widget.NewPopUp(container.NewPadded(lbl), e.picker.window.Canvas())
	e.popUp.ShowAtRelativePosition(fyne.NewPos(0, 35), e)
}

func (e *hoverEntry) MouseMoved(me *desktop.MouseEvent) {
	// Intentionally empty to avoid flickering on movement
}

func (e *hoverEntry) MouseOut() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.hovered = false
	if e.dismissTimer != nil {
		e.dismissTimer.Stop()
	}

	e.dismissTimer = time.AfterFunc(120*time.Millisecond, func() {
		fyne.Do(func() {
			e.mu.Lock()
			defer e.mu.Unlock()
			if !e.hovered && e.popUp != nil {
				e.popUp.Hide()
				e.popUp = nil
			}
		})
	})
}

// PathPicker provides a text entry with a linked Browse button
type PathPicker struct {
	widget.BaseWidget
	entry       *hoverEntry
	button      *widget.Button
	container   *fyne.Container
	window      fyne.Window
	mode        PathPickerMode
	onChanged   func(string)
	title       string
	placeholder string
	tooltipText string
}

// TruncatePath truncates long file paths in the middle with an ellipsis
func TruncatePath(path string, maxLen int) string {
	if len(path) <= maxLen || maxLen < 10 {
		return path
	}
	half := (maxLen - 3) / 2
	return path[:half] + "..." + path[len(path)-half:]
}

// NewPathPicker creates a path picker control
func NewPathPicker(win fyne.Window, mode PathPickerMode, placeholder string, onChanged func(string)) *PathPicker {
	p := &PathPicker{
		window:      win,
		mode:        mode,
		placeholder: placeholder,
		onChanged:   onChanged,
	}

	p.entry = newHoverEntry(p)
	p.entry.SetPlaceHolder(placeholder)
	p.entry.OnChanged = func(val string) {
		if p.onChanged != nil {
			p.onChanged(val)
		}
	}

	browseIcon := theme.FolderOpenIcon()
	if mode == PickerModeSaveFile {
		browseIcon = theme.DocumentSaveIcon()
	}

	p.button = widget.NewButtonWithIcon("Browse", browseIcon, p.openDialog)

	p.container = container.NewBorder(nil, nil, nil, p.button, p.entry)
	p.ExtendBaseWidget(p)
	return p
}

// PromptSaveFilePath prompts the user to select a destination folder and enter a filename
// without opening, truncating, or creating any files.
func PromptSaveFilePath(win fyne.Window, initialPath string, onSelected func(string)) {
	if win == nil || onSelected == nil {
		return
	}
	defaultFilename := "vetted_proxies.json"
	if initialPath != "" {
		base := filepath.Base(initialPath)
		if base != "." && base != "/" && base != "\\" && base != "" {
			defaultFilename = base
		}
	}

	d := dialog.NewFolderOpen(func(uri fyne.ListableURI, err error) {
		if err != nil {
			dialog.ShowError(fmt.Errorf("folder selection failed: %w", err), win)
			return
		}
		if uri == nil {
			return
		}
		folderPath := uri.Path()

		entry := widget.NewEntry()
		entry.SetText(defaultFilename)

		dialog.ShowCustomConfirm("Choose File Name", "Confirm", "Cancel", container.NewVBox(
			widget.NewLabel("Folder: "+folderPath),
			widget.NewLabel("File Name:"),
			entry,
		), func(confirm bool) {
			if !confirm {
				return
			}
			fname := strings.TrimSpace(entry.Text)
			if fname == "" {
				fname = defaultFilename
			}
			chosenPath := filepath.Join(folderPath, fname)
			onSelected(chosenPath)
		}, win)
	}, win)
	d.Show()
}

func (p *PathPicker) openDialog() {
	switch p.mode {
	case PickerModeOpenFile:
		d := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if reader != nil {
				_ = reader.Close()
			}
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed opening file: %w", err), p.window)
				return
			}
			if reader == nil {
				return
			}
			p.SetPath(reader.URI().Path())
		}, p.window)
		d.SetFilter(storage.NewExtensionFileFilter([]string{".json", ".txt"}))
		d.Show()
	case PickerModeSaveFile:
		PromptSaveFilePath(p.window, p.Path(), func(chosen string) {
			p.SetPath(chosen)
		})
	case PickerModeOpenFolder:
		d := dialog.NewFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed selecting folder: %w", err), p.window)
				return
			}
			if uri == nil {
				return
			}
			p.SetPath(uri.Path())
		}, p.window)
		d.Show()
	}
}

// SetPath programmatically updates entry value
func (p *PathPicker) SetPath(path string) {
	p.entry.SetText(path)
}

// Path returns current entered path
func (p *PathPicker) Path() string {
	return p.entry.Text
}

// SetTooltip sets the hover tooltip for this path picker
func (p *PathPicker) SetTooltip(tip string) {
	p.tooltipText = tip
}

// Tooltip returns current tooltip
func (p *PathPicker) Tooltip() string {
	return p.tooltipText
}

// SetResolvedPath updates the resolved path tooltip
func (p *PathPicker) SetResolvedPath(resolved string) {
	p.tooltipText = fmt.Sprintf("Resolved file: %s", resolved)
}

// SetEnabled enables or disables controls
func (p *PathPicker) SetEnabled(enabled bool) {
	if enabled {
		p.entry.Enable()
		p.button.Enable()
	} else {
		p.entry.Disable()
		p.button.Disable()
	}
}

// CreateRenderer implements fyne.Widget
func (p *PathPicker) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(p.container)
}

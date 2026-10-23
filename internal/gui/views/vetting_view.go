package views

import (
	"fyne.io/fyne/v2"

	"github.com/samuelkane526/socks5-sentinel/internal/gui"
)

// VettingView integrates batch vetting and upstream sources into a unified workspace.
type VettingView struct {
	controller *gui.Controller
	window     fyne.Window

	batchView *BatchView
	dataView  *DataView

	// Callback to hand off vetted proxies path to Requests
	OnUseResultsForRequests func(string)
}

// NewVettingView constructs the consolidated Vetting workspace.
func NewVettingView(ctrl *gui.Controller, win fyne.Window) *VettingView {
	vv := &VettingView{
		controller: ctrl,
		window:     win,
		batchView:  NewBatchView(ctrl, win, nil),
		dataView:   NewDataView(ctrl, win),
	}

	vv.buildUI()
	return vv
}

func (vv *VettingView) buildUI() {
	// Sync data destination selection into batch source
	vv.dataView.OnUseAsBatchSource = func(path string) {
		vv.batchView.sourcePicker.SetPath(path)
		vv.batchView.updateResolvedPath()
	}

	// Result handoff delegation
	vv.batchView.OnUseResultsForRequests = func(path string) {
		if vv.OnUseResultsForRequests != nil {
			vv.OnUseResultsForRequests(path)
		}
	}

	// Wire upstream check completion to refresh DataView metadata
	vv.batchView.OnUpstreamCheckComplete = func() {
		if vv.dataView != nil {
			fyne.Do(func() {
				vv.dataView.RefreshMetadata()
			})
		}
	}
}

// CheckAndUpdateUpstream triggers the auto check and update logic on the underlying BatchView
func (vv *VettingView) CheckAndUpdateUpstream(force bool) {
	if vv.batchView != nil {
		vv.batchView.CheckAndUpdateUpstream(force)
	}
}

// UpdateWorkingFolder updates paths across child views
func (vv *VettingView) UpdateWorkingFolder(folder string) {
	if vv.batchView != nil {
		vv.batchView.updateResolvedPath()
	}
	if vv.dataView != nil {
		vv.dataView.RefreshMetadata()
	}
}

// Content returns main container
func (vv *VettingView) Content() fyne.CanvasObject {
	return vv.batchView.Content()
}

// BatchView returns the underlying BatchView
func (vv *VettingView) BatchView() *BatchView {
	return vv.batchView
}

// DataView returns the underlying DataView
func (vv *VettingView) DataView() *DataView {
	return vv.dataView
}

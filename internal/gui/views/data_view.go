package views

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/samuelkane526/socks5-sentinel/internal/gui"
	"github.com/samuelkane526/socks5-sentinel/internal/gui/components"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

// DataView handles upstream GitHub proxy synchronization and metadata tracking
type DataView struct {
	controller *gui.Controller
	window     fyne.Window
	content    *fyne.Container

	destPicker   *components.PathPicker
	resolvedPath *widget.Label

	// Metadata labels
	shaLabel    *widget.Label
	msgLabel    *widget.Label
	dateLabel   *widget.Label
	sizeLabel   *widget.Label
	pulledLabel *widget.Label

	// Progress & status
	progressBar *widget.ProgressBar
	statusLabel *widget.Label

	updateBtn           *widget.Button
	forceBtn            *widget.Button
	cancelBtn           *widget.Button
	useAsBatchSourceBtn *widget.Button

	OnUseAsBatchSource func(string)
}

// NewDataView initializes DataView
func NewDataView(ctrl *gui.Controller, win fyne.Window) *DataView {
	dv := &DataView{
		controller: ctrl,
		window:     win,
	}

	dv.buildUI()
	return dv
}

func (dv *DataView) buildUI() {
	dv.destPicker = components.NewPathPicker(dv.window, components.PickerModeSaveFile, proxycore.DefaultDataFileName, func(string) {
		dv.RefreshMetadata()
	})

	dv.resolvedPath = widget.NewLabel("")
	dv.resolvedPath.TextStyle = fyne.TextStyle{Italic: true}

	dv.shaLabel = widget.NewLabel("Commit SHA: -")
	dv.msgLabel = widget.NewLabel("Commit Message: -")
	dv.dateLabel = widget.NewLabel("Upstream Date: -")
	dv.sizeLabel = widget.NewLabel("Local File Size: -")
	dv.pulledLabel = widget.NewLabel("Last Pulled: -")

	dv.progressBar = widget.NewProgressBar()
	dv.statusLabel = widget.NewLabel("Ready to check upstream")
	dv.statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	dv.updateBtn = widget.NewButtonWithIcon("Check & Update", theme.ViewRefreshIcon(), func() {
		dv.onSync(false)
	})
	dv.updateBtn.Importance = widget.HighImportance

	dv.forceBtn = widget.NewButtonWithIcon("Force Download", theme.DownloadIcon(), func() {
		dv.onSync(true)
	})

	dv.cancelBtn = widget.NewButtonWithIcon("Cancel", theme.MediaStopIcon(), func() {
		dv.controller.CancelActiveJob()
	})
	dv.cancelBtn.Disable()

	dv.useAsBatchSourceBtn = widget.NewButtonWithIcon("Use as Batch Source", theme.NavigateNextIcon(), func() {
		if dv.OnUseAsBatchSource != nil {
			dv.OnUseAsBatchSource(dv.destPicker.Path())
			dialog.ShowInformation("Batch Source Updated", fmt.Sprintf("Vetting source updated to %s", dv.destPicker.Path()), dv.window)
		}
	})

	vettingNotice := widget.NewLabel("Important: Freshly downloaded upstream candidates still require vetting before use.")
	vettingNotice.TextStyle = fyne.TextStyle{Italic: true}

	primaryActions := container.NewHBox(dv.updateBtn, dv.cancelBtn)
	primaryCard := widget.NewCard("Upstream Synchronization (github.com/proxifly/free-proxy-list)", "", container.NewVBox(
		vettingNotice,
		primaryActions,
		dv.progressBar,
		dv.statusLabel,
	))

	detailsAccordion := widget.NewAccordion(
		widget.NewAccordionItem("Details & Override Options (Force Download, Custom Path, Metadata)", container.NewVBox(
			widget.NewLabelWithStyle("Destination Data File:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			dv.destPicker,
			dv.resolvedPath,
			container.NewHBox(dv.forceBtn, dv.useAsBatchSourceBtn),
			widget.NewSeparator(),
			widget.NewLabelWithStyle("Tracking Metadata:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			dv.shaLabel,
			dv.msgLabel,
			dv.dateLabel,
			dv.sizeLabel,
			dv.pulledLabel,
		)),
	)

	dv.content = container.NewVBox(primaryCard, detailsAccordion)
	// SetPath invokes refreshMetadata, so all of its labels must exist first.
	dv.destPicker.SetPath("data/socks5.txt")

	components.AddHelp(dv.content, dv.window)
	dv.controller.AddStateListener(func(st gui.AppState) {
		switch st.Status {
		case gui.JobRunning:
			if st.ActiveJob == gui.JobDataUpdate {
				dv.destPicker.SetEnabled(false)
				dv.updateBtn.Disable()
				dv.forceBtn.Disable()
				dv.cancelBtn.Enable()
			}
		default:
			dv.destPicker.SetEnabled(true)
			dv.updateBtn.Enable()
			dv.forceBtn.Enable()
			dv.cancelBtn.Disable()
			dv.RefreshMetadata()
		}
	})
}

// RefreshMetadata updates UI display labels from local file and pull metadata
func (dv *DataView) RefreshMetadata() {
	baseDir := dv.controller.Preferences().GetWorkingFolder()
	targetFile := dv.destPicker.Path()
	if targetFile == "" || targetFile == proxycore.DefaultDataFileName {
		targetFile = proxycore.ResolveDataFilePathWithBase(baseDir, proxycore.DefaultDataFileName)
	} else if !filepath.IsAbs(targetFile) {
		targetFile = filepath.Join(baseDir, targetFile)
	}

	dv.resolvedPath.SetText(fmt.Sprintf("Resolved path: %s", targetFile))

	metaPath := filepath.Join(filepath.Dir(targetFile), "last_pull_metadata.json")
	meta := proxycore.GetStoredMetadata(metaPath)

	info, err := os.Stat(targetFile)
	if err == nil {
		dv.sizeLabel.SetText(fmt.Sprintf("Local File Size: %.2f MB (%s)", float64(info.Size())/(1024*1024), targetFile))
	} else {
		dv.sizeLabel.SetText("Local File Size: File does not exist yet (initial pull needed)")
	}

	if meta != nil {
		dv.shaLabel.SetText(fmt.Sprintf("Commit SHA: %s", meta.SHA))
		dv.msgLabel.SetText(fmt.Sprintf("Commit Message: %s", meta.CommitMessage))
		dv.dateLabel.SetText(fmt.Sprintf("Upstream Date: %s", meta.LastUpdatedDate))
		dv.pulledLabel.SetText(fmt.Sprintf("Last Pulled: %s", meta.LastPulledAt))
	} else {
		dv.shaLabel.SetText("Commit SHA: None recorded")
		dv.msgLabel.SetText("Commit Message: None recorded")
		dv.dateLabel.SetText("Upstream Date: Unknown")
		dv.pulledLabel.SetText("Last Pulled: Never")
	}
}

func (dv *DataView) onSync(force bool) {
	baseDir := dv.controller.Preferences().GetWorkingFolder()
	targetFile := dv.destPicker.Path()
	if targetFile == "" {
		targetFile = proxycore.DefaultDataFileName
	}

	dv.progressBar.SetValue(0)
	dv.statusLabel.SetText("Contacting GitHub API for upstream metadata...")

	desc := "Upstream Data Sync"
	if force {
		desc = "Force Upstream Data Download"
	}

	err := dv.controller.StartJob(gui.JobDataUpdate, desc, func(ctx context.Context, emit func(proxycore.Event)) error {
		_, refreshErr := proxycore.RefreshProxyDataIfNeededContext(ctx, proxycore.RefreshOptions{
			BaseDir:     baseDir,
			TargetFile:  targetFile,
			ForceUpdate: force,
			Verbose:     true,
		}, func(e proxycore.Event) {
			emit(e)

			switch e.Kind {
			case proxycore.EventRefreshProgress:
				fyne.Do(func() {
					if e.ProgressTotal > 0 {
						dv.progressBar.SetValue(float64(e.ProgressCurrent) / float64(e.ProgressTotal))
						dv.statusLabel.SetText(fmt.Sprintf("Downloading: %.1f MB / %.1f MB",
							float64(e.ProgressCurrent)/(1024*1024), float64(e.ProgressTotal)/(1024*1024)))
					} else {
						dv.statusLabel.SetText(fmt.Sprintf("Downloading: %.1f MB", float64(e.ProgressCurrent)/(1024*1024)))
					}
				})

			case proxycore.EventRefreshDone:
				fyne.Do(func() {
					dv.progressBar.SetValue(1.0)
					if resData, ok := e.Data.(*proxycore.RefreshResult); ok {
						if resData.Updated {
							dv.statusLabel.SetText(fmt.Sprintf("✔ Updated successfully! %.2f MB saved to %s",
								float64(resData.FileSizeBytes)/(1024*1024), filepath.Base(resData.TargetFilePath)))
						} else {
							dv.statusLabel.SetText(fmt.Sprintf("Proxy data is already up to date (%s)", resData.Reason))
						}
					}
				})
			}
		})

		fyne.Do(func() {
			dv.RefreshMetadata()
		})

		return refreshErr
	})

	if err != nil {
		dialog.ShowError(err, dv.window)
	}
}

// Content returns root container
func (dv *DataView) Content() fyne.CanvasObject {
	return container.NewScroll(dv.content)
}

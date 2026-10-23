package views

import (
	"context"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/samuelkane526/socks5-sentinel/internal/gui"
	"github.com/samuelkane526/socks5-sentinel/internal/gui/components"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

// centeredDividerLayout centers a divider line horizontally at 88% page width
// with 6% margins on each side (10% longer than 80%), keeping the line vertically centered and skinny
// with configurable vertical margin to spread out category sections.
type centeredDividerLayout struct {
	height  float32
	ratio   float32
	padding float32
}

func (d *centeredDividerLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	if len(objects) == 0 {
		return
	}
	w := size.Width * d.ratio
	x := (size.Width - w) / 2
	h := d.height
	if h <= 0 {
		h = 1
	}
	y := (size.Height - h) / 2
	objects[0].Move(fyne.NewPos(x, y))
	objects[0].Resize(fyne.NewSize(w, h))
}

func (d *centeredDividerLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	h := d.height
	if h <= 0 {
		h = 1
	}
	pad := d.padding
	if pad <= 0 {
		pad = 12
	}
	return fyne.NewSize(100, h+pad*2)
}

func newSectionDivider() fyne.CanvasObject {
	line := canvas.NewRectangle(color.NRGBA{R: 190, G: 195, B: 205, A: 200})
	return container.New(&centeredDividerLayout{height: 1, ratio: 0.88, padding: 12}, line)
}

func newCenteredSectionHeader(title string) fyne.CanvasObject {
	return widget.NewLabelWithStyle(title, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
}

// BatchView renders the 5-stage batch vetting dashboard
type BatchView struct {
	controller *gui.Controller
	window     fyne.Window
	content    *fyne.Container

	// Form inputs
	sourcePicker *components.PathPicker
	targetEntry  *widget.Entry
	workersEntry *widget.Entry
	limitEntry   *widget.Entry
	updatePolicy *widget.Select
	timeoutEntry *widget.Entry
	exportPicker *components.PathPicker
	verboseCheck *widget.Check

	// Auto-save controls
	autoSaveResultsCheck    *widget.Check
	autoSaveIncompleteCheck *widget.Check
	outputBrowseBtn         *widget.Button
	outputPathLabel         *widget.Label
	browseContainer         *fyne.Container
	vettingSettingsSection  *fyne.Container
	outputPath              string

	// Action buttons
	startBtn       *widget.Button
	cancelBtn      *widget.Button
	savePartialBtn *widget.Button

	// Proxy Source tracking & status widgets
	lastUpdatedBadge   *components.MetricBadge
	autoUpdateCheck    *widget.Check
	customSourceCheck  *widget.Check
	fetchLocationEntry *widget.Entry
	customSourceRow    *fyne.Container
	proxySourceSection *fyne.Container
	isCheckingUpstream bool

	// Metrics badges
	totalBadge    *components.MetricBadge
	eliteBadge    *components.MetricBadge
	rejectedBadge *components.MetricBadge
	elapsedBadge  *components.MetricBadge
	stagesBadge   *components.MetricBadge

	// Candidate results storage for saving
	rawProxies []proxycore.CandidateResultPayload
	mu         sync.Mutex

	// Monotonic Metrics & UI Throttling
	highWaterTotal     int64
	latestProgress     proxycore.BatchProgressPayload
	progressPending    bool
	lastProgressUpdate time.Time

	// Logs
	logView *components.LogView

	// Callback to hand off vetted path to Request screen
	OnUseResultsForRequests func(string)

	// Callback when upstream check and update completes
	OnUpstreamCheckComplete func()
}

// NewBatchView initializes BatchView
func NewBatchView(ctrl *gui.Controller, win fyne.Window, logView *components.LogView) *BatchView {
	bv := &BatchView{
		controller: ctrl,
		window:     win,
		logView:    logView,
		rawProxies: make([]proxycore.CandidateResultPayload, 0, 500),
	}

	bv.buildUI()
	return bv
}

func (bv *BatchView) buildUI() {
	// Source Picker with hover tooltip showing full resolved path
	bv.sourcePicker = components.NewPathPicker(bv.window, components.PickerModeOpenFile, "Automatic (data/socks5.txt)", func(path string) {
		bv.updateResolvedPath()
	})
	bv.updateResolvedPath()

	// Clean numeric inputs with 0 = Unlimited hint in placeholder
	bv.targetEntry = widget.NewEntry()
	bv.targetEntry.SetPlaceHolder("0 = Unlimited")
	bv.targetEntry.SetText("3")

	bv.workersEntry = widget.NewEntry()
	bv.workersEntry.SetPlaceHolder("100")
	bv.workersEntry.SetText(strconv.Itoa(bv.controller.Preferences().GetDefaultConcurrency()))

	bv.limitEntry = widget.NewEntry()
	bv.limitEntry.SetPlaceHolder("0 = Unlimited")
	bv.limitEntry.SetText("0")

	// Defaults for vetting options
	bv.updatePolicy = widget.NewSelect([]string{
		"Check upstream automatically (default)",
		"Force download fresh upstream data",
		"Use local data only",
	}, nil)
	bv.updatePolicy.SetSelected("Check upstream automatically (default)")

	bv.outputPath = proxycore.DefaultOutputFile

	bv.timeoutEntry = widget.NewEntry()
	bv.timeoutEntry.SetText(strconv.Itoa(bv.controller.Preferences().GetDefaultTimeoutMs()))

	bv.exportPicker = components.NewPathPicker(bv.window, components.PickerModeOpenFolder, "Optional export folder or file", nil)
	bv.verboseCheck = widget.NewCheck("Detailed proxy logs", nil)

	// Action buttons
	bv.startBtn = widget.NewButtonWithIcon("Start Vetting", theme.MediaPlayIcon(), bv.onStartVetting)
	bv.startBtn.Importance = widget.HighImportance

	bv.cancelBtn = widget.NewButtonWithIcon("Cancel", theme.MediaStopIcon(), func() {
		bv.cancelBtn.Disable()
		bv.controller.CancelActiveJob()
	})
	bv.cancelBtn.Disable()

	// Save Partial Results: green square button with save icon, greyed out when no results
	bv.savePartialBtn = widget.NewButtonWithIcon("", theme.DocumentSaveIcon(), bv.onSavePartial)
	bv.savePartialBtn.Importance = widget.SuccessImportance
	bv.savePartialBtn.Disable()

	// Section 1: Proxy Source Section (Proxy Source, Last Updated, Auto Check & Update, Custom List Source)
	sourceLabel := widget.NewLabelWithStyle("Proxy Source:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	sourceRow := container.NewBorder(nil, nil, sourceLabel, nil, bv.sourcePicker)

	bv.lastUpdatedBadge = components.NewMetricBadge("Never", color.NRGBA{R: 56, G: 139, B: 253, A: 255}, color.White)
	bv.lastUpdatedBadge.SetPadding(8, 3)
	bv.lastUpdatedBadge.SetTextSize(12)
	lastUpdatedRow := container.NewHBox(
		widget.NewLabelWithStyle("Last Updated:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		bv.lastUpdatedBadge,
	)

	bv.autoUpdateCheck = widget.NewCheck("Auto Check and Update", nil)
	bv.autoUpdateCheck.SetChecked(true)

	bv.customSourceCheck = widget.NewCheck("Enable Custom List Source", func(checked bool) {
		if checked {
			bv.customSourceRow.Show()
		} else {
			bv.customSourceRow.Hide()
		}
		if bv.proxySourceSection != nil {
			bv.proxySourceSection.Refresh()
		}
	})
	bv.customSourceCheck.SetChecked(false)

	fetchLabel := widget.NewLabelWithStyle("Fetch Location:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	bv.fetchLocationEntry = widget.NewEntry()
	bv.fetchLocationEntry.SetText(proxycore.DEFAULT_GITHUB_REPO)
	bv.fetchLocationEntry.SetPlaceHolder(proxycore.DEFAULT_GITHUB_REPO)
	bv.customSourceRow = container.NewBorder(nil, nil, fetchLabel, nil, bv.fetchLocationEntry)
	bv.customSourceRow.Hide()

	bv.proxySourceSection = container.NewVBox(
		sourceRow,
		lastUpdatedRow,
		bv.autoUpdateCheck,
		bv.customSourceCheck,
		bv.customSourceRow,
	)

	// Section 2: Vetting settings section (Workers, Target, Candidate Limit + Auto Save options)
	line2 := container.NewHBox(
		widget.NewLabelWithStyle("Workers:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewGridWrap(fyne.NewSize(65, 36), bv.workersEntry),
		widget.NewLabelWithStyle("Target:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewGridWrap(fyne.NewSize(85, 36), bv.targetEntry),
		widget.NewLabelWithStyle("Candidate Limit:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewGridWrap(fyne.NewSize(85, 36), bv.limitEntry),
	)

	// Auto Save Results option with file browse button by it
	bv.outputPathLabel = widget.NewLabel(proxycore.DefaultOutputFile)
	bv.outputPathLabel.TextStyle = fyne.TextStyle{Italic: true}

	bv.outputBrowseBtn = widget.NewButtonWithIcon("Browse", theme.FolderOpenIcon(), func() {
		components.PromptSaveFilePath(bv.window, bv.getOutputPath(), func(chosen string) {
			bv.setOutputPath(chosen)
		})
	})

	bv.browseContainer = container.NewHBox(bv.outputBrowseBtn, bv.outputPathLabel)

	bv.autoSaveResultsCheck = widget.NewCheck("Auto Save Results", func(checked bool) {
		if checked {
			bv.browseContainer.Show()
		} else {
			bv.browseContainer.Hide()
		}
		if bv.vettingSettingsSection != nil {
			bv.vettingSettingsSection.Refresh()
		}
	})
	bv.autoSaveResultsCheck.SetChecked(true)

	autoSaveRow := container.NewHBox(
		bv.autoSaveResultsCheck,
		bv.browseContainer,
	)

	// Auto Save Incomplete option below
	bv.autoSaveIncompleteCheck = widget.NewCheck("Auto Save Incomplete", nil)
	bv.autoSaveIncompleteCheck.SetChecked(false)

	bv.vettingSettingsSection = container.NewVBox(
		line2,
		autoSaveRow,
		bv.autoSaveIncompleteCheck,
	)

	// Section 3: Action buttons and Stats Display content directly below Start Vetting
	startBox := container.NewGridWrap(fyne.NewSize(185, 48), bv.startBtn)
	cancelBox := container.NewGridWrap(fyne.NewSize(130, 48), bv.cancelBtn)
	savePartialBox := container.NewGridWrap(fyne.NewSize(48, 48), bv.savePartialBtn)
	actionRow := container.NewHBox(
		startBox,
		cancelBox,
		savePartialBox,
	)

	// Stats display badges directly below actions
	bv.totalBadge = components.NewMetricBadge("Total: 0", color.NRGBA{R: 45, G: 60, B: 80, A: 255}, color.White)
	bv.eliteBadge = components.NewMetricBadge("Verified Elite: 0", color.NRGBA{R: 35, G: 134, B: 54, A: 255}, color.White)
	bv.rejectedBadge = components.NewMetricBadge("Rejected: 0", color.NRGBA{R: 218, G: 54, B: 51, A: 255}, color.White)
	bv.elapsedBadge = components.NewMetricBadge("Elapsed: 0s", color.NRGBA{R: 60, G: 70, B: 85, A: 255}, color.White)
	bv.stagesBadge = components.NewMetricBadge("Failures: S1:0 S2:0 S3:0 S4:0 S5:0", color.NRGBA{R: 50, G: 55, B: 65, A: 255}, color.NRGBA{R: 200, G: 205, B: 215, A: 255})

	badgeBar := container.NewHBox(bv.totalBadge, bv.eliteBadge, bv.rejectedBadge, bv.elapsedBadge, bv.stagesBadge)
	actionsSection := container.NewVBox(actionRow, badgeBar)

	// Page layout organized into clear sections separated by skinny centered dividers
	bv.content = container.NewVBox(
		newSectionDivider(),
		newCenteredSectionHeader("Proxy Source"),
		bv.proxySourceSection,
		newSectionDivider(),
		newCenteredSectionHeader("Vetting Settings"),
		bv.vettingSettingsSection,
		newSectionDivider(),
		newCenteredSectionHeader("Actions"),
		actionsSection,
	)

	bv.refreshProxySourceMetadata()

	// Register state listener
	components.AddHelp(bv.content, bv.window)
	bv.controller.AddStateListener(func(st gui.AppState) {
		switch st.Status {
		case gui.JobRunning:
			bv.setFormEnabled(false)
			bv.startBtn.Disable()
			if st.ActiveJob == gui.JobBatchVet || st.ActiveJob == "" {
				bv.cancelBtn.Enable()
			} else {
				bv.cancelBtn.Disable()
			}
			bv.savePartialBtn.Disable()
		case gui.JobCanceling:
			bv.startBtn.Disable()
			bv.cancelBtn.Disable()
			bv.savePartialBtn.Disable()
		case gui.JobCanceled:
			bv.setFormEnabled(true)
			bv.startBtn.Enable()
			bv.cancelBtn.Disable()
			if bv.hasResultsToSave() {
				bv.savePartialBtn.Enable()
			} else {
				bv.savePartialBtn.Disable()
			}
		case gui.JobCompleted, gui.JobFailed:
			bv.setFormEnabled(true)
			bv.startBtn.Enable()
			bv.cancelBtn.Disable()
			if bv.hasResultsToSave() {
				bv.savePartialBtn.Enable()
			} else {
				bv.savePartialBtn.Disable()
			}
		default:
			bv.setFormEnabled(true)
			bv.startBtn.Enable()
			bv.cancelBtn.Disable()
			if bv.hasResultsToSave() {
				bv.savePartialBtn.Enable()
			} else {
				bv.savePartialBtn.Disable()
			}
		}
	})
}

func (bv *BatchView) updateResolvedPath() {
	baseDir := bv.controller.Preferences().GetWorkingFolder()
	resolved := proxycore.ResolveDataFilePathWithBase(baseDir, bv.sourcePicker.Path())
	bv.sourcePicker.SetResolvedPath(resolved)
	bv.refreshProxySourceMetadata()
}

func (bv *BatchView) setFormEnabled(enabled bool) {
	bv.sourcePicker.SetEnabled(enabled)
	if enabled {
		bv.targetEntry.Enable()
		bv.workersEntry.Enable()
		bv.limitEntry.Enable()
		if bv.autoUpdateCheck != nil {
			bv.autoUpdateCheck.Enable()
		}
		if bv.customSourceCheck != nil {
			bv.customSourceCheck.Enable()
		}
		if bv.fetchLocationEntry != nil {
			bv.fetchLocationEntry.Enable()
		}
		if bv.autoSaveResultsCheck != nil {
			bv.autoSaveResultsCheck.Enable()
		}
		if bv.autoSaveIncompleteCheck != nil {
			bv.autoSaveIncompleteCheck.Enable()
		}
		if bv.outputBrowseBtn != nil {
			bv.outputBrowseBtn.Enable()
		}
	} else {
		bv.targetEntry.Disable()
		bv.workersEntry.Disable()
		bv.limitEntry.Disable()
		if bv.autoUpdateCheck != nil {
			bv.autoUpdateCheck.Disable()
		}
		if bv.customSourceCheck != nil {
			bv.customSourceCheck.Disable()
		}
		if bv.fetchLocationEntry != nil {
			bv.fetchLocationEntry.Disable()
		}
		if bv.autoSaveResultsCheck != nil {
			bv.autoSaveResultsCheck.Disable()
		}
		if bv.autoSaveIncompleteCheck != nil {
			bv.autoSaveIncompleteCheck.Disable()
		}
		if bv.outputBrowseBtn != nil {
			bv.outputBrowseBtn.Disable()
		}
	}
	if bv.updatePolicy != nil {
		if enabled {
			bv.updatePolicy.Enable()
		} else {
			bv.updatePolicy.Disable()
		}
	}
	if bv.timeoutEntry != nil {
		if enabled {
			bv.timeoutEntry.Enable()
		} else {
			bv.timeoutEntry.Disable()
		}
	}
	if bv.verboseCheck != nil {
		if enabled {
			bv.verboseCheck.Enable()
		} else {
			bv.verboseCheck.Disable()
		}
	}
	if bv.exportPicker != nil {
		bv.exportPicker.SetEnabled(enabled)
	}
}

func (bv *BatchView) setOutputPath(path string) {
	if path == "" {
		path = proxycore.DefaultOutputFile
	}
	bv.outputPath = path
	if bv.outputPathLabel != nil {
		bv.outputPathLabel.SetText(path)
	}
}

func (bv *BatchView) getOutputPath() string {
	if bv.outputPath != "" {
		return bv.outputPath
	}
	return proxycore.DefaultOutputFile
}

func (bv *BatchView) refreshProxySourceMetadata() {
	if bv.lastUpdatedBadge == nil {
		return
	}
	baseDir := bv.controller.Preferences().GetWorkingFolder()
	targetFile := proxycore.ResolveDataFilePathWithBase(baseDir, bv.sourcePicker.Path())

	metaPath := filepath.Join(filepath.Dir(targetFile), "last_pull_metadata.json")
	meta := proxycore.GetStoredMetadata(metaPath)
	targetInfo, err := os.Stat(targetFile)

	if meta != nil && meta.LastPulledAt != "" {
		if t, parseErr := time.Parse(time.RFC3339, meta.LastPulledAt); parseErr == nil {
			bv.lastUpdatedBadge.SetText(t.Local().Format("2006-01-02 15:04:05"))
		} else {
			bv.lastUpdatedBadge.SetText(meta.LastPulledAt)
		}
	} else if err == nil {
		bv.lastUpdatedBadge.SetText(targetInfo.ModTime().Format("2006-01-02 15:04:05"))
	} else {
		bv.lastUpdatedBadge.SetText("Never")
	}
}

func (bv *BatchView) getEffectiveFetchLocation() string {
	if bv.customSourceCheck != nil && bv.customSourceCheck.Checked && bv.fetchLocationEntry != nil {
		text := strings.TrimSpace(bv.fetchLocationEntry.Text)
		if text != "" {
			return text
		}
	}
	return proxycore.DEFAULT_GITHUB_REPO
}

// CheckAndUpdateUpstream checks upstream and updates the data folder
func (bv *BatchView) CheckAndUpdateUpstream(force bool) {
	if bv.isCheckingUpstream {
		return
	}
	bv.isCheckingUpstream = true
	baseDir := bv.controller.Preferences().GetWorkingFolder()
	targetFile := proxycore.ResolveDataFilePathWithBase(baseDir, bv.sourcePicker.Path())
	sourceURL := bv.getEffectiveFetchLocation()
	autoUpdate := bv.autoUpdateCheck != nil && bv.autoUpdateCheck.Checked

	go func() {
		defer func() {
			fyne.Do(func() {
				bv.refreshProxySourceMetadata()
				bv.isCheckingUpstream = false
				if bv.OnUpstreamCheckComplete != nil {
					bv.OnUpstreamCheckComplete()
				}
			})
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		if autoUpdate {
			res, err := proxycore.RefreshProxyDataIfNeededContext(ctx, proxycore.RefreshOptions{
				BaseDir:     baseDir,
				TargetFile:  targetFile,
				ForceUpdate: force,
				Verbose:     false,
				SourceURL:   sourceURL,
			}, func(e proxycore.Event) {
				if e.Message != "" {
					bv.controller.AppendLog(e.Message)
				}
			})

			if err != nil {
				bv.controller.AppendLog(fmt.Sprintf("[Proxy Update] Error during upstream check: %s", err.Error()))
			} else if res != nil && res.Updated {
				bv.controller.AppendLog(fmt.Sprintf("[Proxy Update] Data folder updated successfully: %s", res.TargetFilePath))
			}
		}
	}()
}

func (bv *BatchView) hasResultsToSave() bool {
	if len(bv.controller.GetPartialVetted()) > 0 {
		return true
	}
	bv.mu.Lock()
	defer bv.mu.Unlock()
	for _, p := range bv.rawProxies {
		if p.Passed {
			return true
		}
	}
	return false
}

func (bv *BatchView) onStartVetting() {
	// Validate inputs
	target, err := strconv.Atoi(bv.targetEntry.Text)
	if err != nil || target < 0 {
		dialog.ShowError(fmt.Errorf("invalid target: %s (must be >= 0)", bv.targetEntry.Text), bv.window)
		return
	}

	concurrency, err := strconv.Atoi(bv.workersEntry.Text)
	if err != nil || concurrency < 1 {
		dialog.ShowError(fmt.Errorf("invalid workers: %s (must be >= 1)", bv.workersEntry.Text), bv.window)
		return
	}

	limit, err := strconv.Atoi(bv.limitEntry.Text)
	if err != nil || limit < 0 {
		dialog.ShowError(fmt.Errorf("invalid limit: %s (must be >= 0)", bv.limitEntry.Text), bv.window)
		return
	}

	var timeoutMs int
	if bv.timeoutEntry != nil && bv.timeoutEntry.Text != "" {
		tVal, err := strconv.Atoi(bv.timeoutEntry.Text)
		if err == nil && tVal > 0 {
			timeoutMs = tVal
		}
	}
	if timeoutMs <= 0 {
		timeoutMs = bv.controller.Preferences().GetDefaultTimeoutMs()
		if timeoutMs <= 0 {
			timeoutMs = int(proxycore.DefaultBatchTimeout / time.Millisecond)
		}
	}

	var updatePolicy proxycore.UpdatePolicy
	if bv.autoUpdateCheck != nil && !bv.autoUpdateCheck.Checked {
		updatePolicy = proxycore.UpdateNone
	} else if bv.updatePolicy != nil {
		switch bv.updatePolicy.Selected {
		case "Force download fresh upstream data":
			updatePolicy = proxycore.UpdateForce
		case "Use local data only":
			updatePolicy = proxycore.UpdateNone
		default:
			updatePolicy = proxycore.UpdateAuto
		}
	} else {
		updatePolicy = proxycore.UpdateAuto
	}

	baseDir := bv.controller.Preferences().GetWorkingFolder()
	inputFile := bv.sourcePicker.Path()
	if inputFile == "" {
		inputFile = proxycore.ResolveDataFilePathWithBase(baseDir, proxycore.DefaultDataFileName)
	}

	autoSave := true
	if bv.autoSaveResultsCheck != nil {
		autoSave = bv.autoSaveResultsCheck.Checked
	}

	autoSaveIncomplete := false
	if bv.autoSaveIncompleteCheck != nil {
		autoSaveIncomplete = bv.autoSaveIncompleteCheck.Checked
	}

	exportDir := ""
	if bv.exportPicker != nil {
		exportDir = bv.exportPicker.Path()
	}

	verbose := false
	if bv.verboseCheck != nil {
		verbose = bv.verboseCheck.Checked
	}

	opts := proxycore.PipelineOptions{
		BaseDir:            baseDir,
		InputFile:          inputFile,
		OutputFile:         bv.getOutputPath(),
		ExportDir:          exportDir,
		Concurrency:        concurrency,
		Limit:              limit,
		TargetPassed:       target,
		Timeout:            time.Duration(timeoutMs) * time.Millisecond,
		UpdatePolicy:       updatePolicy,
		Verbose:            verbose,
		SourceURL:          bv.getEffectiveFetchLocation(),
		AutoSave:           autoSave,
		AutoSaveIncomplete: autoSaveIncomplete,
	}

	err = bv.controller.StartJob(gui.JobBatchVet, fmt.Sprintf("Vetting proxies (workers: %d, target: %d)", concurrency, target), func(ctx context.Context, emit func(proxycore.Event)) error {
		pipeline := proxycore.NewSocksVettingPipeline(opts)

		eventListener := func(e proxycore.Event) {
			if ctx.Err() != nil && e.Kind != proxycore.EventBatchCompleted {
				return
			}

			emit(e)

			switch e.Kind {
			case proxycore.EventRefreshDone:
				fyne.Do(func() {
					bv.refreshProxySourceMetadata()
				})

			case proxycore.EventCandidateCompleted:
				if payload, ok := e.Data.(proxycore.CandidateResultPayload); ok && payload.Passed {
					bv.mu.Lock()
					bv.rawProxies = append(bv.rawProxies, payload)
					bv.mu.Unlock()
				}

			case proxycore.EventBatchProgress:
				if p, ok := e.Data.(proxycore.BatchProgressPayload); ok {
					bv.mu.Lock()
					// Enforce strict monotonicity: Total should never go down
					if p.TestedCount < bv.highWaterTotal {
						bv.mu.Unlock()
						return
					}
					bv.highWaterTotal = p.TestedCount
					bv.latestProgress = p

					now := time.Now()
					if !bv.progressPending && (now.Sub(bv.lastProgressUpdate) >= 50*time.Millisecond || p.TestedCount >= p.TotalToTest) {
						bv.progressPending = true
						bv.lastProgressUpdate = now
						bv.mu.Unlock()

						fyne.Do(func() {
							bv.mu.Lock()
							bv.progressPending = false
							payload := bv.latestProgress
							bv.mu.Unlock()

							bv.totalBadge.SetText(fmt.Sprintf("Total: %s", formatNumber(payload.TestedCount)))
							bv.eliteBadge.SetText(fmt.Sprintf("Verified Elite: %s", formatNumber(payload.PassedCount)))
							bv.rejectedBadge.SetText(fmt.Sprintf("Rejected: %s", formatNumber(payload.FailedCount)))
							bv.elapsedBadge.SetText(fmt.Sprintf("Elapsed: %s", formatDuration(payload.ElapsedTime)))
							bv.stagesBadge.SetText(fmt.Sprintf("Failures: S1:%d S2:%d S3:%d S4:%d S5:%d",
								payload.StageFailureCounts[1], payload.StageFailureCounts[2], payload.StageFailureCounts[3],
								payload.StageFailureCounts[4], payload.StageFailureCounts[5]))
						})
					} else {
						bv.mu.Unlock()
					}
				}

			case proxycore.EventTargetReached:
				bv.controller.SetMuteLogs(true)

			case proxycore.EventBatchCompleted:
				if comp, ok := e.Data.(proxycore.BatchCompletePayload); ok {
					bv.controller.SetPartialVetted(comp.VettedProxies)
					fyne.Do(func() {
						bv.mu.Lock()
						if comp.TotalProcessed > bv.highWaterTotal {
							bv.highWaterTotal = comp.TotalProcessed
						}
						finalTotal := bv.highWaterTotal
						bv.mu.Unlock()

						if bv.hasResultsToSave() {
							bv.savePartialBtn.Enable()
						} else {
							bv.savePartialBtn.Disable()
						}

						bv.totalBadge.SetText(fmt.Sprintf("Total: %s", formatNumber(finalTotal)))
						bv.eliteBadge.SetText(fmt.Sprintf("Verified Elite: %s", formatNumber(int64(comp.PassedCount))))
						bv.rejectedBadge.SetText(fmt.Sprintf("Rejected: %s", formatNumber(comp.FailedCount)))
						bv.elapsedBadge.SetText(fmt.Sprintf("Elapsed: %s", formatDuration(comp.ElapsedTime)))
						bv.stagesBadge.SetText(fmt.Sprintf("Failures: S1:%d S2:%d S3:%d S4:%d S5:%d",
							comp.StageFailureCounts[1], comp.StageFailureCounts[2], comp.StageFailureCounts[3],
							comp.StageFailureCounts[4], comp.StageFailureCounts[5]))
					})
				}
			}
		}

		vetted, runErr := pipeline.RunContext(ctx, eventListener)
		bv.controller.SetPartialVetted(vetted)
		return runErr
	})

	if err != nil {
		dialog.ShowError(err, bv.window)
		return
	}

	// Job accepted: safely reset retained state and UI counters
	bv.mu.Lock()
	bv.rawProxies = nil
	bv.highWaterTotal = 0
	bv.progressPending = false
	bv.lastProgressUpdate = time.Time{}
	bv.latestProgress = proxycore.BatchProgressPayload{}
	bv.mu.Unlock()

	bv.controller.SetPartialVetted(nil)
	bv.savePartialBtn.Disable()

	bv.totalBadge.SetText("Total: 0")
	bv.eliteBadge.SetText("Verified Elite: 0")
	bv.rejectedBadge.SetText("Rejected: 0")
	bv.elapsedBadge.SetText("Elapsed: 0s")
	bv.stagesBadge.SetText("Failures: S1:0 S2:0 S3:0 S4:0 S5:0")
}

func (bv *BatchView) onSavePartial() {
	proxies := bv.controller.GetPartialVetted()
	if len(proxies) == 0 {
		bv.mu.Lock()
		for _, p := range bv.rawProxies {
			if p.Passed {
				if p.Item != nil {
					proxies = append(proxies, p.Item)
				} else if p.Result != nil && p.Result.Item != nil {
					proxies = append(proxies, p.Result.Item)
				} else if item := proxycore.NormalizeProxy(p.Proxy); item != nil {
					proxies = append(proxies, item)
				}
			}
		}
		bv.mu.Unlock()
	}

	if len(proxies) == 0 {
		dialog.ShowInformation("No Results", "No passed vetted proxies are in memory to save.", bv.window)
		return
	}

	components.PromptSaveFilePath(bv.window, bv.getOutputPath(), func(chosenPath string) {
		baseDir := bv.controller.Preferences().GetWorkingFolder()
		destPath := chosenPath
		if !filepath.IsAbs(destPath) && baseDir != "" {
			destPath = filepath.Join(baseDir, destPath)
		}

		doSave := func() {
			if saveErr := proxycore.SaveProxiesToFile(destPath, proxies); saveErr != nil {
				dialog.ShowError(saveErr, bv.window)
			} else {
				dialog.ShowInformation("Saved", fmt.Sprintf("Successfully saved %d proxies to %s", len(proxies), filepath.Base(destPath)), bv.window)
			}
		}

		if _, statErr := os.Stat(destPath); statErr == nil {
			dialog.ShowConfirm("Overwrite File?", fmt.Sprintf("File %s already exists. Overwrite it?", filepath.Base(destPath)), func(confirm bool) {
				if confirm {
					doSave()
				}
			}, bv.window)
		} else {
			doSave()
		}
	})
}

// Content returns main container
func (bv *BatchView) Content() fyne.CanvasObject {
	return bv.content
}

func formatNumber(n int64) string {
	in := strconv.FormatInt(n, 10)
	if len(in) <= 3 {
		return in
	}
	var out []byte
	rem := len(in) % 3
	if rem > 0 {
		out = append(out, in[:rem]...)
		if len(in) > rem {
			out = append(out, ',')
		}
	}
	for i := rem; i < len(in); i += 3 {
		out = append(out, in[i:i+3]...)
		if i+3 < len(in) {
			out = append(out, ',')
		}
	}
	return string(out)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	s := int(d.Seconds())
	if s < 60 {
		return fmt.Sprintf("%ds", s)
	}
	m := s / 60
	s = s % 60
	return fmt.Sprintf("%dm %ds", m, s)
}

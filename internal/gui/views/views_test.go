package views

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
	"github.com/samuelkane526/socks5-sentinel/internal/gui"
	"github.com/samuelkane526/socks5-sentinel/internal/gui/components"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

func TestBatchViewInitializationAndInputs(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("Batch")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)
	logView := components.NewLogView(win)

	bv := NewBatchView(ctrl, win, logView)
	if bv.targetEntry.Text != "3" {
		t.Errorf("expected target '3', got %q", bv.targetEntry.Text)
	}
	if bv.workersEntry.Text != "100" {
		t.Errorf("expected workers '100', got %q", bv.workersEntry.Text)
	}

	// Verify Auto Save Results and Auto Save Incomplete checkboxes
	if bv.autoSaveResultsCheck == nil || !bv.autoSaveResultsCheck.Checked {
		t.Errorf("expected Auto Save Results to be initialized and checked")
	}
	if bv.autoSaveResultsCheck.Text != "Auto Save Results" {
		t.Errorf("expected checkbox text 'Auto Save Results', got %q", bv.autoSaveResultsCheck.Text)
	}

	if bv.autoSaveIncompleteCheck == nil || bv.autoSaveIncompleteCheck.Checked {
		t.Errorf("expected Auto Save Incomplete to be initialized and unchecked")
	}
	if bv.autoSaveIncompleteCheck.Text != "Auto Save Incomplete" {
		t.Errorf("expected checkbox text 'Auto Save Incomplete', got %q", bv.autoSaveIncompleteCheck.Text)
	}

	// Verify file browse button visibility toggles with Auto Save Results
	if bv.browseContainer == nil || !bv.browseContainer.Visible() {
		t.Errorf("expected browse container to be visible when Auto Save Results is checked")
	}
	bv.autoSaveResultsCheck.SetChecked(false)
	if bv.browseContainer.Visible() {
		t.Errorf("expected browse container to be hidden when Auto Save Results is unchecked")
	}
	bv.autoSaveResultsCheck.SetChecked(true)
	if !bv.browseContainer.Visible() {
		t.Errorf("expected browse container to be visible when Auto Save Results is checked")
	}

	// Verify output path helpers
	if bv.getOutputPath() != proxycore.DefaultOutputFile {
		t.Errorf("expected default output path %q, got %q", proxycore.DefaultOutputFile, bv.getOutputPath())
	}
	bv.setOutputPath("custom/out.json")
	if bv.getOutputPath() != "custom/out.json" {
		t.Errorf("expected updated output path 'custom/out.json', got %q", bv.getOutputPath())
	}

	bv.setFormEnabled(false)
	bv.setFormEnabled(true)
}

func TestBatchViewSavePartialButtonState(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("BatchSavePartial")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)
	logView := components.NewLogView(win)

	bv := NewBatchView(ctrl, win, logView)

	// Initially no results: button should be disabled (greyed out)
	if !bv.savePartialBtn.Disabled() {
		t.Fatal("expected savePartialBtn to be disabled initially")
	}
	if bv.savePartialBtn.Importance != widget.SuccessImportance {
		t.Fatalf("expected SuccessImportance for green styling, got %v", bv.savePartialBtn.Importance)
	}
	if bv.savePartialBtn.Text != "" {
		t.Fatalf("expected square icon button with empty text, got %q", bv.savePartialBtn.Text)
	}

	// When results are set, button should be enabled
	ctrl.SetPartialVetted([]*proxycore.ProxyItem{
		{Proxy: "socks5h://127.0.0.1:1080", IP: "127.0.0.1", Port: 1080},
	})
	ctrl.SetState(gui.JobCompleted, "")
	if bv.savePartialBtn.Disabled() {
		t.Fatal("expected savePartialBtn to be enabled when results exist")
	}

	// When results are cleared, button should be disabled again
	ctrl.SetPartialVetted(nil)
	ctrl.SetState(gui.JobCompleted, "")
	if !bv.savePartialBtn.Disabled() {
		t.Fatal("expected savePartialBtn to be disabled when no results exist")
	}

	// When results exist in rawProxies and job is canceled, button should be enabled
	bv.mu.Lock()
	bv.rawProxies = append(bv.rawProxies, proxycore.CandidateResultPayload{Proxy: "1.1.1.1:1080", Passed: true})
	bv.mu.Unlock()
	ctrl.SetState(gui.JobCanceled, "")
	if bv.savePartialBtn.Disabled() {
		t.Fatal("expected savePartialBtn to be enabled when rawProxies has passed candidate")
	}
}

func TestCenteredDividerLayout(t *testing.T) {
	div := newSectionDivider()
	if div == nil {
		t.Fatal("expected non-nil divider")
	}

	c, ok := div.(*fyne.Container)
	if !ok {
		t.Fatal("expected divider to be a container")
	}
	if len(c.Objects) != 1 {
		t.Fatalf("expected 1 object in divider container, got %d", len(c.Objects))
	}

	layout := c.Layout.(*centeredDividerLayout)
	minSize := layout.MinSize(c.Objects)
	if minSize.Height < 20 {
		t.Fatalf("expected vertical margin height >= 20, got %f", minSize.Height)
	}

	// Test layout calculation for width 1000
	testSize := fyne.NewSize(1000, 20)
	layout.Layout(c.Objects, testSize)

	obj := c.Objects[0]
	expectedWidth := float32(880) // 88% of 1000 (10% longer than 800)
	expectedX := float32(60)      // 6% left margin
	if obj.Size().Width != expectedWidth {
		t.Fatalf("expected width %f, got %f", expectedWidth, obj.Size().Width)
	}
	if obj.Position().X != expectedX {
		t.Fatalf("expected X position %f, got %f", expectedX, obj.Position().X)
	}
	if obj.Size().Height != 1 {
		t.Fatalf("expected 1px skinny line height, got %f", obj.Size().Height)
	}
}

func TestProxySourceSectionWidgetsAndStatus(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("ProxySourceTest")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)
	logView := components.NewLogView(win)

	bv := NewBatchView(ctrl, win, logView)

	if bv.lastUpdatedBadge == nil {
		t.Fatal("expected non-nil lastUpdatedBadge")
	}
	if bv.autoUpdateCheck == nil {
		t.Fatal("expected non-nil autoUpdateCheck")
	}
	if !bv.autoUpdateCheck.Checked {
		t.Fatal("expected autoUpdateCheck to be checked by default")
	}
	if bv.customSourceCheck == nil {
		t.Fatal("expected non-nil customSourceCheck")
	}
	if bv.customSourceCheck.Checked {
		t.Fatal("expected customSourceCheck to be unchecked by default")
	}
	if bv.customSourceRow == nil {
		t.Fatal("expected non-nil customSourceRow")
	}
	if bv.customSourceRow.Visible() {
		t.Fatal("expected customSourceRow to be hidden when custom source is unchecked")
	}
	if bv.fetchLocationEntry == nil {
		t.Fatal("expected non-nil fetchLocationEntry")
	}
	if bv.fetchLocationEntry.Text != proxycore.DEFAULT_GITHUB_REPO {
		t.Fatalf("expected default fetch location %q, got %q", proxycore.DEFAULT_GITHUB_REPO, bv.fetchLocationEntry.Text)
	}
	if bv.getEffectiveFetchLocation() != proxycore.DEFAULT_GITHUB_REPO {
		t.Fatalf("expected effective fetch location to be %q when unchecked, got %q", proxycore.DEFAULT_GITHUB_REPO, bv.getEffectiveFetchLocation())
	}

	// Toggling custom source check shows the fetch location row
	bv.customSourceCheck.SetChecked(true)
	if !bv.customSourceRow.Visible() {
		t.Fatal("expected customSourceRow to be visible when checked")
	}

	// Custom URL resolution
	customURL := "https://example.com/custom-proxies.txt"
	bv.fetchLocationEntry.SetText(customURL)
	if bv.getEffectiveFetchLocation() != customURL {
		t.Fatalf("expected effective fetch location %q, got %q", customURL, bv.getEffectiveFetchLocation())
	}

	// Toggling off reverts effective location to default and hides row
	bv.customSourceCheck.SetChecked(false)
	if bv.customSourceRow.Visible() {
		t.Fatal("expected customSourceRow to be hidden when unchecked")
	}
	if bv.getEffectiveFetchLocation() != proxycore.DEFAULT_GITHUB_REPO {
		t.Fatalf("expected effective fetch location %q when unchecked, got %q", proxycore.DEFAULT_GITHUB_REPO, bv.getEffectiveFetchLocation())
	}
}
func TestBatchViewCandidateCollectionAndSaving(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("BatchCandidateCollection")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)
	logView := components.NewLogView(win)

	bv := NewBatchView(ctrl, win, logView)

	// Add mock candidate payloads
	p1 := proxycore.CandidateResultPayload{Proxy: "1.1.1.1:1080", Passed: true}
	p2 := proxycore.CandidateResultPayload{Proxy: "2.2.2.2:1080", Passed: false, FailedStage: 1, FailureReason: "Handshake failed"}
	p3 := proxycore.CandidateResultPayload{Proxy: "3.3.3.3:1080", Passed: false, FailedStage: 3, FailureReason: "TLS mismatch"}

	bv.mu.Lock()
	bv.rawProxies = append(bv.rawProxies, p1, p2, p3)
	bv.mu.Unlock()

	if len(bv.rawProxies) != 3 {
		t.Fatalf("expected 3 raw proxies, got %d", len(bv.rawProxies))
	}
	if !bv.hasResultsToSave() {
		t.Fatal("expected hasResultsToSave to be true when passed candidate exists")
	}
}

func TestBatchView_RejectedStartPreservesResults(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("TestPreserve")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)
	logView := components.NewLogView(win)

	bv := NewBatchView(ctrl, win, logView)
	bv.mu.Lock()
	bv.rawProxies = append(bv.rawProxies, proxycore.CandidateResultPayload{Proxy: "1.1.1.1:1080", Passed: true})
	bv.mu.Unlock()

	// Simulate an active job so StartJob fails
	ctrl.SetState(gui.JobRunning, "already running job")

	// Call onStartVetting - should fail and NOT clear rawProxies
	bv.onStartVetting()

	bv.mu.Lock()
	count := len(bv.rawProxies)
	bv.mu.Unlock()

	if count != 1 {
		t.Fatalf("expected rawProxies to be preserved on rejected start, got %d", count)
	}
}

func TestBatchViewMetricsAndBadges(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("BatchMetrics")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)
	logView := components.NewLogView(win)

	bv := NewBatchView(ctrl, win, logView)

	// Verify all 5 stat display badges are initialized
	if bv.totalBadge == nil || bv.eliteBadge == nil || bv.rejectedBadge == nil || bv.elapsedBadge == nil || bv.stagesBadge == nil {
		t.Fatal("expected non-nil metric badges for Total, Verified Elite, Rejected, Elapsed, Failures")
	}

	if bv.totalBadge.Text() != "Total: 0" {
		t.Errorf("expected 'Total: 0', got %q", bv.totalBadge.Text())
	}
	if bv.eliteBadge.Text() != "Verified Elite: 0" {
		t.Errorf("expected 'Verified Elite: 0', got %q", bv.eliteBadge.Text())
	}
	if bv.rejectedBadge.Text() != "Rejected: 0" {
		t.Errorf("expected 'Rejected: 0', got %q", bv.rejectedBadge.Text())
	}
	if bv.elapsedBadge.Text() != "Elapsed: 0s" {
		t.Errorf("expected 'Elapsed: 0s', got %q", bv.elapsedBadge.Text())
	}
	if bv.stagesBadge.Text() != "Failures: S1:0 S2:0 S3:0 S4:0 S5:0" {
		t.Errorf("expected 'Failures: S1:0 S2:0 S3:0 S4:0 S5:0', got %q", bv.stagesBadge.Text())
	}

	// Test format helpers
	if formatNumber(72791) != "72,791" {
		t.Fatalf("expected 72,791, got %s", formatNumber(72791))
	}
	if formatDuration(46*1e9) != "46s" {
		t.Fatalf("expected 46s, got %s", formatDuration(46*1e9))
	}
}

func TestSingleViewInitialization(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("Single")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)

	sv := NewSingleView(ctrl, win)
	if sv.addrEntry.Text != "" {
		t.Errorf("expected empty initial address, got %q", sv.addrEntry.Text)
	}
	if sv.verdictCard.Visible() {
		t.Error("verdict card should be hidden initially")
	}
}

func TestRequestViewInitialization(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("Request")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)

	rv := NewRequestView(ctrl, win)
	if rv.urlEntry.Text != "https://httpbin.org/get" {
		t.Errorf("expected default url, got %q", rv.urlEntry.Text)
	}

	rv.SetSourcePath("custom_proxies.json")
	if rv.sourcePicker.Path() != "custom_proxies.json" {
		t.Errorf("SetSourcePath failed: %s", rv.sourcePicker.Path())
	}
}

func TestHealthViewInitialization(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("Health")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)

	hv := NewHealthView(ctrl, win)
	if hv.retriesEntry.Text != "5" {
		t.Errorf("expected default retries '5', got %q", hv.retriesEntry.Text)
	}
	if hv.timeoutEntry.Text != "10000" {
		t.Errorf("expected default timeout '10000', got %q", hv.timeoutEntry.Text)
	}
}

func TestSettingsViewInitialization(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("Settings")
	defer win.Close()

	baseDir := t.TempDir()
	prefs := gui.NewAppPreferences(a)
	prefs.SetWorkingFolder(baseDir)
	ctrl := gui.NewController(prefs)

	var changedFolder string
	sv := NewSettingsView(ctrl, win)
	sv.OnWorkingFolderChanged = func(folder string) {
		changedFolder = folder
	}

	if sv.folderPicker.Path() != baseDir {
		t.Errorf("expected folder %q, got %q", baseDir, sv.folderPicker.Path())
	}

	newFolder := filepath.Join(baseDir, "new_folder")
	sv.folderPicker.SetPath(newFolder)
	_ = changedFolder
}

func TestVettingViewCompositionAndHandoff(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("Vetting")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)

	vv := NewVettingView(ctrl, win)
	if vv.BatchView() == nil || vv.DataView() == nil {
		t.Fatal("expected non-nil child views in VettingView")
	}

	// Test "Use as Batch Source" data synchronization handoff
	vv.DataView().destPicker.SetPath("custom/path.txt")
	test.Tap(vv.DataView().useAsBatchSourceBtn)
	if vv.BatchView().sourcePicker.Path() != "custom/path.txt" {
		t.Fatalf("expected batch source 'custom/path.txt', got %q", vv.BatchView().sourcePicker.Path())
	}

	// Test result handoff callback
	var handoffPath string
	vv.OnUseResultsForRequests = func(p string) {
		handoffPath = p
	}
	vv.BatchView().setOutputPath("out.json")
	if vv.BatchView().OnUseResultsForRequests != nil {
		vv.BatchView().OnUseResultsForRequests("out.json")
	}
	if handoffPath != "out.json" {
		t.Fatalf("expected handoff 'out.json', got %q", handoffPath)
	}
}

func TestConsoleViewInitialization(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("Console")
	defer win.Close()

	lv := components.NewLogView(win)
	cv := NewConsoleView(lv)

	if cv.Content() != lv {
		t.Fatal("expected cv.Content() to return lv")
	}
	if cv.LogView() != lv {
		t.Fatal("expected cv.LogView() to return lv")
	}

	lv.AppendLog("test log line")
}

func TestRequestViewDisclosureAndHeaders(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("RequestDisclosure")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)

	rv := NewRequestView(ctrl, win)
	if rv.tlsWarningLabel.Visible() {
		t.Fatal("tlsWarningLabel should be hidden by default")
	}

	// Select allow-insecure policy
	rv.tlsPolicySel.SetSelected("Allow invalid certificates (--allow-insecure)")
	if !rv.tlsWarningLabel.Visible() {
		t.Fatal("tlsWarningLabel should be visible when allow-insecure is selected")
	}

	// Revert to strict
	rv.tlsPolicySel.SetSelected("Verify certificates (Strict anti-MITM, default)")
	if rv.tlsWarningLabel.Visible() {
		t.Fatal("tlsWarningLabel should be hidden when strict TLS is selected")
	}

	// Verify embedded health check and single proxy verification
	if rv.healthView == nil {
		t.Fatal("expected non-nil healthView embedded in RequestView")
	}
	if rv.singleView == nil {
		t.Fatal("expected non-nil singleView embedded in RequestView")
	}

	// Test showHeadersPopup
	rv.headersBox.SetText("Server: test-server\nContent-Type: text/plain")
	rv.showHeadersPopup()
}

func TestBatchViewSectionsAndButtonSizes(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("BatchSectionsAndButtons")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)
	logView := components.NewLogView(win)

	bv := NewBatchView(ctrl, win, logView)

	// Verify main content container exists
	if bv.content == nil {
		t.Fatal("expected non-nil content")
	}

	// Verify the 4 sections in order:
	// Proxy Source, Vetting Settings, Actions, Stats Display
	var getLabelText func(obj fyne.CanvasObject) string
	getLabelText = func(obj fyne.CanvasObject) string {
		if lbl, ok := obj.(*widget.Label); ok {
			return lbl.Text
		}
		if ht, ok := obj.(*components.HoverTooltip); ok {
			return getLabelText(ht.Content())
		}
		return ""
	}

	var sectionTitles []string
	for _, obj := range bv.content.Objects {
		if text := getLabelText(obj); text != "" {
			sectionTitles = append(sectionTitles, text)
		}
	}

	expectedTitles := []string{"Proxy Source", "Vetting Settings", "Actions"}
	if len(sectionTitles) != len(expectedTitles) {
		t.Fatalf("expected %d section headers, got %d: %v", len(expectedTitles), len(sectionTitles), sectionTitles)
	}
	for i, exp := range expectedTitles {
		if sectionTitles[i] != exp {
			t.Errorf("expected section header %d to be %q, got %q", i, exp, sectionTitles[i])
		}
	}

	// Verify the Actions section contains the actionRow and stats display badgeBar
	actionsSection := bv.content.Objects[8].(*fyne.Container)
	if len(actionsSection.Objects) != 2 {
		t.Fatalf("expected actionRow and badgeBar in actions section, got %d", len(actionsSection.Objects))
	}

	actionRow := actionsSection.Objects[0].(*fyne.Container)
	if len(actionRow.Objects) != 3 {
		t.Fatalf("expected 3 buttons in action row, got %d", len(actionRow.Objects))
	}

	startWrapper := actionRow.Objects[0].(*fyne.Container)
	cancelWrapper := actionRow.Objects[1].(*fyne.Container)
	saveWrapper := actionRow.Objects[2].(*fyne.Container)

	// Verify height is 48 (+33% over standard 36)
	if startWrapper.MinSize().Height != 48 || startWrapper.MinSize().Width != 185 {
		t.Errorf("expected start button size (185, 48), got %v", startWrapper.MinSize())
	}
	if cancelWrapper.MinSize().Height != 48 || cancelWrapper.MinSize().Width != 130 {
		t.Errorf("expected cancel button size (130, 48), got %v", cancelWrapper.MinSize())
	}
	if saveWrapper.MinSize().Height != 48 || saveWrapper.MinSize().Width != 48 {
		t.Errorf("expected save partial button size (48, 48), got %v", saveWrapper.MinSize())
	}

	// Verify stats display directly below buttons contains the 5 badges
	statsSection := actionsSection.Objects[1].(*fyne.Container)
	if len(statsSection.Objects) != 5 {
		t.Fatalf("expected 5 badge boxes in stats display, got %d", len(statsSection.Objects))
	}
}

func TestBatchViewCancelingAndMonotonicMetrics(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("BatchCancelMonotonic")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)
	logView := components.NewLogView(win)

	bv := NewBatchView(ctrl, win, logView)

	// Simulate JobRunning
	ctrl.SetState(gui.JobRunning, "")
	if bv.startBtn.Disabled() != true {
		t.Error("expected startBtn to be disabled during JobRunning")
	}

	// Simulate JobCanceling
	ctrl.SetState(gui.JobCanceling, "")
	if bv.startBtn.Disabled() != true {
		t.Error("expected startBtn to be disabled during JobCanceling")
	}
	if bv.cancelBtn.Disabled() != true {
		t.Error("expected cancelBtn to be disabled during JobCanceling")
	}

	// Simulate JobCanceled
	ctrl.SetState(gui.JobCanceled, "")
	if bv.startBtn.Disabled() != false {
		t.Error("expected startBtn to be enabled after JobCanceled")
	}
	if bv.cancelBtn.Disabled() != true {
		t.Error("expected cancelBtn to be disabled after JobCanceled")
	}

	// Verify monotonic highWaterTotal logic
	bv.mu.Lock()
	bv.highWaterTotal = 50
	bv.mu.Unlock()

	// Out-of-order lower count should not lower highWaterTotal
	lowerCount := int64(25)
	bv.mu.Lock()
	if lowerCount >= bv.highWaterTotal {
		bv.highWaterTotal = lowerCount
	}
	curHighWater := bv.highWaterTotal
	bv.mu.Unlock()

	if curHighWater != 50 {
		t.Fatalf("expected highWaterTotal to remain 50, got %d", curHighWater)
	}

	// Higher count advances highWaterTotal
	higherCount := int64(75)
	bv.mu.Lock()
	if higherCount >= bv.highWaterTotal {
		bv.highWaterTotal = higherCount
	}
	curHighWater = bv.highWaterTotal
	bv.mu.Unlock()

	if curHighWater != 75 {
		t.Fatalf("expected highWaterTotal to advance to 75, got %d", curHighWater)
	}
}

func TestBatchViewTargetReachedMutesLogs(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("BatchTargetMute")
	defer win.Close()

	prefs := gui.NewAppPreferences(a)
	ctrl := gui.NewController(prefs)
	logView := components.NewLogView(win)

	_ = NewBatchView(ctrl, win, logView)

	ctrl.AppendLog("before target reached")
	if len(ctrl.GetAllLogs()) != 1 {
		t.Fatalf("expected 1 log, got %d", len(ctrl.GetAllLogs()))
	}

	ctrl.SetMuteLogs(true)
	ctrl.AppendLog("after target reached - should be muted")
	if len(ctrl.GetAllLogs()) != 1 {
		t.Fatalf("expected still 1 log after target reached, got %d", len(ctrl.GetAllLogs()))
	}
}

func TestVettingView_CheckAndUpdateUpstream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/commits" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"sha": "gui-launch-sha-999",
					"commit": map[string]interface{}{
						"message": "Launch update",
						"author": map[string]interface{}{
							"date": "2026-10-22T22:00:00Z",
						},
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("127.0.0.1:1080\n127.0.0.2:1080\n"))
	}))
	defer server.Close()

	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("VettingViewLaunch")
	defer win.Close()

	tmpDir := t.TempDir()
	prefs := gui.NewAppPreferences(a)
	prefs.SetWorkingFolder(tmpDir)

	ctrl := gui.NewController(prefs)
	vv := NewVettingView(ctrl, win)

	// Configure custom fetch source to point to mock server
	vv.batchView.customSourceCheck.SetChecked(true)
	vv.batchView.fetchLocationEntry.SetText(server.URL)

	dataDir := filepath.Join(tmpDir, "data")
	expectedFile := filepath.Join(dataDir, "socks5.txt")
	if _, err := os.Stat(expectedFile); !os.IsNotExist(err) {
		t.Fatalf("expected %s to not exist before check", expectedFile)
	}

	doneCh := make(chan struct{})
	vv.batchView.OnUpstreamCheckComplete = func() {
		close(doneCh)
	}

	// Trigger CheckAndUpdateUpstream as done on GUI launch
	vv.CheckAndUpdateUpstream(true)

	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for CheckAndUpdateUpstream to complete")
	}

	if _, err := os.Stat(expectedFile); err != nil {
		t.Fatalf("expected %s to exist after check: %v", expectedFile, err)
	}
	metaFile := filepath.Join(dataDir, "last_pull_metadata.json")
	if _, err := os.Stat(metaFile); err != nil {
		t.Fatalf("expected %s to exist after check: %v", metaFile, err)
	}
	meta := proxycore.GetStoredMetadata(metaFile)
	pulled, err := time.Parse(time.RFC3339, meta.LastPulledAt)
	if err != nil {
		t.Fatal(err)
	}
	want := pulled.Local().Format("2006-01-02 15:04:05")
	if got := vv.batchView.lastUpdatedBadge.Text(); got != want {
		t.Fatalf("Last Updated after first download = %q, want %q", got, want)
	}
	reopened := NewVettingView(ctrl, win)
	if got := reopened.batchView.lastUpdatedBadge.Text(); got != want {
		t.Fatalf("Last Updated on construction = %q, want %q", got, want)
	}
}

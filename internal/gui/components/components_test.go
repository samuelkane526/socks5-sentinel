package components

import (
	"fmt"
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

func TestStageListStatusTransitions(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	sl := NewStageList()
	if len(sl.rows) != 5 {
		t.Fatalf("expected 5 stage rows, got %d", len(sl.rows))
	}

	// Initial pending state
	for i := 1; i <= 5; i++ {
		if sl.rows[i].status.Text != "[ PENDING ]" {
			t.Errorf("stage %d expected PENDING, got %s", i, sl.rows[i].status.Text)
		}
	}

	// Update to Running
	sl.UpdateStage(1, proxycore.StageRunning, "")
	if !strings.Contains(sl.rows[1].status.Text, "RUNNING") {
		t.Errorf("expected RUNNING, got %s", sl.rows[1].status.Text)
	}

	// Update to Passed
	sl.UpdateStage(1, proxycore.StagePassed, "")
	if !strings.Contains(sl.rows[1].status.Text, "PASSED") {
		t.Errorf("expected PASSED, got %s", sl.rows[1].status.Text)
	}

	// Update to Failed with reason
	sl.UpdateStage(2, proxycore.StageFailed, "Leaked real IP")
	if !strings.Contains(sl.rows[2].status.Text, "FAILED") {
		t.Errorf("expected FAILED, got %s", sl.rows[2].status.Text)
	}
	if sl.rows[2].reason.Text != "Leaked real IP" {
		t.Errorf("reason mismatch: %s", sl.rows[2].reason.Text)
	}

	// Update to Skipped
	sl.UpdateStage(3, proxycore.StageSkipped, "")
	if !strings.Contains(sl.rows[3].status.Text, "SKIPPED") {
		t.Errorf("expected SKIPPED, got %s", sl.rows[3].status.Text)
	}

	// Reset
	sl.Reset()
	if !strings.Contains(sl.rows[1].status.Text, "PENDING") || !strings.Contains(sl.rows[2].status.Text, "PENDING") {
		t.Error("stages not reset to pending")
	}
}

func TestStatusBarUpdates(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	sb := NewStatusBar("C:/my/folder")
	if sb.folderLabel.Text != "Folder: C:/my/folder" {
		t.Errorf("unexpected folder label: %s", sb.folderLabel.Text)
	}

	// State update
	sb.UpdateState(StatusBarState{
		Status:      StatusRunning,
		ActiveJob:   "Batch Vetting",
		Description: "Running workers",
	})
	if !strings.Contains(sb.statusBadge.Text, "RUNNING") {
		t.Errorf("expected RUNNING status badge, got %s", sb.statusBadge.Text)
	}

	sb.UpdateState(StatusBarState{
		Status:    StatusFailed,
		LastError: "Connection refused",
	})
	if !strings.Contains(sb.statusBadge.Text, "FAILED") {
		t.Errorf("expected FAILED status badge, got %s", sb.statusBadge.Text)
	}
	if sb.errorLabel.Text != "Error: Connection refused" {
		t.Errorf("error label mismatch: %s", sb.errorLabel.Text)
	}
}

func TestPathPickerWidget(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("Test")
	defer win.Close()

	var changed string
	picker := NewPathPicker(win, PickerModeOpenFile, "placeholder", func(val string) {
		changed = val
	})

	picker.SetPath("data/test.json")
	if picker.Path() != "data/test.json" {
		t.Errorf("Path() = %q, want data/test.json", picker.Path())
	}
	if changed != "data/test.json" {
		t.Errorf("changed = %q, want data/test.json", changed)
	}

	picker.SetEnabled(false)
	picker.SetEnabled(true)
}

func TestLogViewDisplayAndFiltering(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("Test")
	defer win.Close()

	lv := NewLogView(win)
	lv.AppendLog("Line 1: Normal info")
	lv.AppendLog("Line 2: Warning found")
	lv.AppendLog("Line 3: Error occured")

	if len(lv.rawLines) != 3 {
		t.Fatalf("expected 3 raw lines, got %d", len(lv.rawLines))
	}

	// Filter
	lv.filterEntry.SetText("Warning")
	lv.refreshDisplay()
	if !strings.Contains(lv.logBox.Text, "Warning") {
		t.Errorf("filter did not match warning line: %s", lv.logBox.Text)
	}
}

func TestMetricBadge(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	badge := NewMetricBadge("Total: 0", nil, nil)
	if badge.text.Text != "Total: 0" {
		t.Fatalf("expected Total: 0, got %s", badge.text.Text)
	}
	if badge.text.TextSize != 13 {
		t.Fatalf("expected default TextSize 13, got %f", badge.text.TextSize)
	}
	badge.SetText("Total: 100")
	if badge.text.Text != "Total: 100" {
		t.Fatalf("expected Total: 100, got %s", badge.text.Text)
	}

	badge.SetTextSize(14)
	if badge.text.TextSize != 14 {
		t.Fatalf("expected TextSize 14, got %f", badge.text.TextSize)
	}

	badge.SetPadding(15, 8)
	if badge.padX != 15 || badge.padY != 8 {
		t.Fatalf("expected padding (15, 8), got (%f, %f)", badge.padX, badge.padY)
	}

	minSize := badge.MinSize()
	tSize := badge.text.MinSize()
	if minSize.Width != tSize.Width+30 || minSize.Height != tSize.Height+16 {
		t.Fatalf("expected minSize (%f, %f), got (%f, %f)", tSize.Width+30, tSize.Height+16, minSize.Width, minSize.Height)
	}

	r := badge.CreateRenderer()
	objs := r.Objects()
	if len(objs) != 2 {
		t.Fatalf("expected 2 renderer objects, got %d", len(objs))
	}
}

func TestSlimProgressBar(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	bar := NewSlimProgressBar()
	if bar.Value() != 0.0 {
		t.Fatalf("expected 0.0, got %f", bar.Value())
	}
	bar.SetValue(0.75)
	if bar.Value() != 0.75 {
		t.Fatalf("expected 0.75, got %f", bar.Value())
	}
	if bar.MinSize().Height != 10 {
		t.Fatalf("expected height 10, got %f", bar.MinSize().Height)
	}
}

func TestSectionHeader(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("HeaderTest")
	defer win.Close()

	header := NewSectionHeader("Configuration", "Parity notice test", win)
	if header == nil {
		t.Fatal("expected non-nil section header")
	}
	ht, ok := header.(*HoverTooltip)
	if !ok {
		t.Fatal("expected section header with notice to be a HoverTooltip wrapping the title label")
	}
	ht.MouseIn(nil)
	if ht.popUp == nil {
		t.Fatal("expected hovering section header to display tooltip popup")
	}
	initialPop := ht.popUp
	ht.MouseMoved(nil)
	ht.MouseIn(nil)
	if ht.popUp != initialPop {
		t.Fatal("mouse movement must not re-render popup")
	}
	ht.DismissImmediately()
	if ht.popUp != nil {
		t.Fatal("expected dismiss to close tooltip popup")
	}

	headerNoNotice := NewSectionHeader("Simple Header", "", win)
	if headerNoNotice == nil {
		t.Fatal("expected non-nil section header without notice")
	}
}

func TestPathPickerTooltipAndTruncation(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("PickerTest")
	defer win.Close()

	picker := NewPathPicker(win, PickerModeOpenFile, "auto", nil)
	picker.SetResolvedPath("C:/long/path/to/proxy.txt")
	if !strings.Contains(picker.Tooltip(), "C:/long/path/to/proxy.txt") {
		t.Fatalf("expected tooltip to contain resolved path, got %q", picker.Tooltip())
	}

	truncated := TruncatePath("C:/very/long/path/with/lots/of/nested/directories/file.txt", 30)
	if len(truncated) > 30 {
		t.Fatalf("truncated string %q exceeds max length 30", truncated)
	}
}

func TestLogView_BoundingAt5000Lines(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	win := a.NewWindow("BoundTest")
	defer win.Close()

	lv := NewLogView(win)
	for i := 0; i < 6000; i++ {
		lv.AppendLog(fmt.Sprintf("log line %d", i))
	}

	lv.mu.Lock()
	retainedCount := len(lv.rawLines)
	lv.mu.Unlock()

	if retainedCount != 5000 {
		t.Fatalf("expected retained lines to be capped at 5000, got %d", retainedCount)
	}

	lv.refreshDisplay()
	lines := strings.Split(lv.logBox.Text, "\n")
	if len(lines) > 5000 {
		t.Fatalf("expected displayed text to be at most 5000 lines, got %d", len(lines))
	}
}

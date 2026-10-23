package gui

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

func TestControllerSingleJobExecution(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	prefs := NewAppPreferences(a)
	ctrl := NewController(prefs)

	started := make(chan struct{})
	unblock := make(chan struct{})

	// Start 1st job
	err := ctrl.StartJob(JobBatchVet, "Test Batch", func(ctx context.Context, emit func(proxycore.Event)) error {
		close(started)
		<-unblock
		return nil
	})
	if err != nil {
		t.Fatalf("failed starting first job: %v", err)
	}

	<-started

	// Attempt 2nd job while 1st is active
	err2 := ctrl.StartJob(JobSingleVet, "Test Single", func(ctx context.Context, emit func(proxycore.Event)) error {
		return nil
	})
	if err2 == nil {
		t.Error("expected error when starting overlapping second job")
	}

	close(unblock)
	time.Sleep(50 * time.Millisecond)

	if ctrl.IsJobActive() {
		t.Error("expected job to be inactive after completion")
	}
}

func TestControllerCancellation(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	ctrl := NewController(NewAppPreferences(a))

	started := make(chan struct{})

	err := ctrl.StartJob(JobDataUpdate, "Syncing", func(ctx context.Context, emit func(proxycore.Event)) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatalf("failed starting job: %v", err)
	}

	<-started
	ctrl.CancelActiveJob()

	time.Sleep(50 * time.Millisecond)
	st := ctrl.GetState()
	if st.Status != JobCanceled {
		t.Errorf("expected status JobCanceled, got %s", st.Status)
	}
}

func TestControllerLogsAndListeners(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	ctrl := NewController(NewAppPreferences(a))

	var logged []string
	var mu sync.Mutex
	ctrl.AddLogListener(func(line string) {
		mu.Lock()
		logged = append(logged, line)
		mu.Unlock()
	})

	ctrl.AppendLog("test log message with socks5h://user:secret@1.1.1.1:1080")

	time.Sleep(50 * time.Millisecond)
	logs := ctrl.GetAllLogs()
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if stringContains(logs[0], "secret") {
		t.Errorf("password was not redacted in logs: %s", logs[0])
	}

	ctrl.ClearLogs()
	if len(ctrl.GetAllLogs()) != 0 {
		t.Error("expected empty logs after ClearLogs")
	}
}

func TestControllerPartialResults(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	ctrl := NewController(NewAppPreferences(a))

	// No partial results initially
	if err := ctrl.SavePartialResults("out.json"); err == nil {
		t.Error("expected error saving when no partial results exist")
	}

	proxies := []*proxycore.ProxyItem{
		{IP: "1.1.1.1", Port: 1080},
	}
	ctrl.SetPartialVetted(proxies)

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "saved_partial.json")
	if err := ctrl.SavePartialResults(outPath); err != nil {
		t.Fatalf("failed to save partial results: %v", err)
	}
}

func TestControllerMuteLogs(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	ctrl := NewController(NewAppPreferences(a))
	ctrl.AppendLog("visible log")
	if len(ctrl.GetAllLogs()) != 1 {
		t.Fatalf("expected 1 log, got %d", len(ctrl.GetAllLogs()))
	}

	ctrl.SetMuteLogs(true)
	ctrl.AppendLog("muted log 1")
	ctrl.AppendLog("muted log 2")
	if len(ctrl.GetAllLogs()) != 1 {
		t.Fatalf("expected still 1 log after muting, got %d", len(ctrl.GetAllLogs()))
	}

	ctrl.SetMuteLogs(false)
	ctrl.AppendLog("visible log 2")
	if len(ctrl.GetAllLogs()) != 2 {
		t.Fatalf("expected 2 logs after unmuting, got %d", len(ctrl.GetAllLogs()))
	}
}

func stringContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || fmt.Sprintf("%s", s) != "" && (len(s) > 0 && len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

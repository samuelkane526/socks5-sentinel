package gui

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"github.com/samuelkane526/socks5-sentinel/internal/proxycore"
)

const MaxLogEntries = 5000

// Controller coordinates background network tasks, UI events, and execution state
type Controller struct {
	mu                   sync.Mutex
	activeCtx            context.Context
	cancelFunc           context.CancelFunc
	state                AppState
	stateListeners       []func(AppState)
	logEntries           []string
	logListeners         []func(string)
	partialVettedProxies []*proxycore.ProxyItem
	appPreferences       *AppPreferences
	muteLogs             bool
}

// NewController creates an instance of Controller
func NewController(prefs *AppPreferences) *Controller {
	return &Controller{
		state:          NewInitialState(),
		logEntries:     make([]string, 0, 1000),
		appPreferences: prefs,
	}
}

// Preferences returns current app preferences
func (c *Controller) Preferences() *AppPreferences {
	return c.appPreferences
}

// AddStateListener registers a callback when AppState changes
func (c *Controller) AddStateListener(l func(AppState)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stateListeners = append(c.stateListeners, l)
}

// AddLogListener registers a callback for new log messages
func (c *Controller) AddLogListener(l func(string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logListeners = append(c.logListeners, l)
}

// GetState returns current AppState snapshot
func (c *Controller) GetState() AppState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// IsJobActive reports if a background job is executing
func (c *Controller) IsJobActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state.Status == JobRunning || c.state.Status == JobValidating || c.state.Status == JobUpdating || c.state.Status == JobCanceling
}

// SetState updates status and dispatches updates to listeners via fyne.Do
func (c *Controller) SetState(status JobStatus, lastErr string) {
	c.mu.Lock()
	c.state.Status = status
	if lastErr != "" {
		c.state.LastError = lastErr
	}
	st := c.state
	listeners := make([]func(AppState), len(c.stateListeners))
	copy(listeners, c.stateListeners)
	c.mu.Unlock()

	fyne.Do(func() {
		for _, l := range listeners {
			l(st)
		}
	})
}

// AppendLog adds a sanitized entry to memory log buffer and notifies listeners
func (c *Controller) AppendLog(msg string) {
	c.mu.Lock()
	if c.muteLogs {
		c.mu.Unlock()
		return
	}
	sanitized := proxycore.RedactSensitive(msg)
	entry := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), sanitized)

	if len(c.logEntries) >= MaxLogEntries {
		c.logEntries = c.logEntries[1:]
	}
	c.logEntries = append(c.logEntries, entry)
	listeners := make([]func(string), len(c.logListeners))
	copy(listeners, c.logListeners)
	c.mu.Unlock()

	fyne.Do(func() {
		for _, l := range listeners {
			l(entry)
		}
	})
}

// SetMuteLogs suppresses or enables log recording (e.g. when target reached)
func (c *Controller) SetMuteLogs(mute bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.muteLogs = mute
}

// GetAllLogs returns all collected log entries
func (c *Controller) GetAllLogs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]string, len(c.logEntries))
	copy(cp, c.logEntries)
	return cp
}

// ClearLogs empties the log buffer
func (c *Controller) ClearLogs() {
	c.mu.Lock()
	c.logEntries = c.logEntries[:0]
	c.mu.Unlock()
}

// SetPartialVetted stores vetted proxies for optional partial save
func (c *Controller) SetPartialVetted(proxies []*proxycore.ProxyItem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.partialVettedProxies = proxies
}

// GetPartialVetted returns retained vetted proxies
func (c *Controller) GetPartialVetted() []*proxycore.ProxyItem {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]*proxycore.ProxyItem, len(c.partialVettedProxies))
	copy(cp, c.partialVettedProxies)
	return cp
}

// SavePartialResults writes any retained partial vetted proxies to destPath
func (c *Controller) SavePartialResults(destPath string) error {
	proxies := c.GetPartialVetted()
	if len(proxies) == 0 {
		return errors.New("no partial vetted proxies available to save")
	}
	return proxycore.SaveProxiesToFile(destPath, proxies)
}

// StartJob executes a background task ensuring single-active-job constraint
func (c *Controller) StartJob(jobType JobType, desc string, task func(ctx context.Context, emit func(proxycore.Event)) error) error {
	c.mu.Lock()
	if c.state.Status == JobRunning || c.state.Status == JobValidating || c.state.Status == JobUpdating || c.state.Status == JobCanceling {
		c.mu.Unlock()
		return fmt.Errorf("a job is already running: %s", c.state.ActiveJob)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.activeCtx = ctx
	c.cancelFunc = cancel
	c.muteLogs = false
	c.state = AppState{
		Status:      JobRunning,
		ActiveJob:   jobType,
		Description: desc,
		StartTime:   time.Now(),
	}
	st := c.state
	listeners := make([]func(AppState), len(c.stateListeners))
	copy(listeners, c.stateListeners)
	c.mu.Unlock()

	fyne.Do(func() {
		for _, l := range listeners {
			l(st)
		}
	})

	c.AppendLog(fmt.Sprintf("=== Started %s: %s ===", jobType, desc))

	go func() {
		emit := func(e proxycore.Event) {
			if e.Kind == proxycore.EventLog {
				c.AppendLog(e.Message)
			}
		}

		err := task(ctx, emit)

		c.mu.Lock()
		isCanceled := ctx.Err() != nil
		c.activeCtx = nil
		c.cancelFunc = nil

		if isCanceled {
			c.state.Status = JobCanceled
			c.state.LastError = "Operation canceled by user"
		} else if err != nil {
			c.state.Status = JobFailed
			c.state.LastError = err.Error()
		} else {
			c.state.Status = JobCompleted
			c.state.LastError = ""
		}
		c.state.ActiveJob = JobNone
		finalState := c.state
		stListeners := make([]func(AppState), len(c.stateListeners))
		copy(stListeners, c.stateListeners)
		c.mu.Unlock()

		if isCanceled {
			c.AppendLog(fmt.Sprintf("=== Canceled %s ===", jobType))
		} else if err != nil {
			c.AppendLog(fmt.Sprintf("=== Failed %s: %s ===", jobType, err.Error()))
		} else {
			c.AppendLog(fmt.Sprintf("=== Completed %s successfully ===", jobType))
		}

		fyne.Do(func() {
			for _, l := range stListeners {
				l(finalState)
			}
		})
	}()

	return nil
}

// CancelActiveJob requests cancellation of current background job
func (c *Controller) CancelActiveJob() {
	c.mu.Lock()
	if c.cancelFunc != nil {
		c.state.Status = JobCanceling
		st := c.state
		listeners := make([]func(AppState), len(c.stateListeners))
		copy(listeners, c.stateListeners)
		c.cancelFunc()
		c.mu.Unlock()

		c.AppendLog("Canceling active job...")
		fyne.Do(func() {
			for _, l := range listeners {
				l(st)
			}
		})
	} else {
		c.mu.Unlock()
	}
}

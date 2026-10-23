package proxycore

import (
	"time"
)

// StageState represents the exact status of a verification stage
type StageState string

const (
	StagePending StageState = "pending"
	StageRunning StageState = "running"
	StagePassed  StageState = "passed"
	StageFailed  StageState = "failed"
	StageSkipped StageState = "skipped"
)

// StageNames maps stage numbers 1-5 to standard descriptive titles
var StageNames = map[int]string{
	1: "Baseline & socks5h Scheme",
	2: "IP Masking & Header Leak",
	3: "Strict TLS/SSL Anti-MITM",
	4: "Anti-Rerouting & Schema Check",
	5: "Cookie & Header Integrity",
}

// StageDetails holds complete state of a stage execution
type StageDetails struct {
	Stage         int           `json:"stage"`
	Name          string        `json:"name"`
	State         StageState    `json:"state"`
	Passed        bool          `json:"passed"`
	FailureReason string        `json:"failureReason,omitempty"`
	Duration      time.Duration `json:"duration,omitempty"`
}

// EventKind defines all typed events emitted by proxy operations
type EventKind string

const (
	EventLog                EventKind = "log"
	EventRefreshStarted     EventKind = "refresh_started"
	EventRefreshProgress    EventKind = "refresh_progress"
	EventRefreshDone        EventKind = "refresh_done"
	EventBatchStarted       EventKind = "batch_started"
	EventCandidateStarted   EventKind = "candidate_started"
	EventCandidateStage     EventKind = "candidate_stage"
	EventCandidateCompleted EventKind = "candidate_completed"
	EventBatchProgress      EventKind = "batch_progress"
	EventBatchCompleted     EventKind = "batch_completed"
	EventTargetReached      EventKind = "target_reached"
	EventSingleStage        EventKind = "single_stage"
	EventSingleCompleted    EventKind = "single_completed"
	EventRequestAttempt     EventKind = "request_attempt"
	EventRequestCompleted   EventKind = "request_completed"
	EventHealthAttempt      EventKind = "health_attempt"
	EventHealthCompleted    EventKind = "health_completed"
)

// Event is a structured notification sent to listeners (CLI & GUI)
type Event struct {
	Kind            EventKind     `json:"kind"`
	RunID           string        `json:"runId,omitempty"`
	Timestamp       time.Time     `json:"timestamp"`
	Message         string        `json:"message,omitempty"`
	Level           string        `json:"level,omitempty"` // info, warn, error, success
	ProgressCurrent int64         `json:"progressCurrent,omitempty"`
	ProgressTotal   int64         `json:"progressTotal,omitempty"`
	Data            interface{}   `json:"data,omitempty"`
}

// LogListener is a callback function for event consumption
type Listener func(Event)

// NewLogEvent constructs a standard log event
func NewLogEvent(level, message string) Event {
	return Event{
		Kind:      EventLog,
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
	}
}

// BatchProgressPayload carries aggregated metrics during batch vetting
type BatchProgressPayload struct {
	TestedCount        int64    `json:"testedCount"`
	TotalToTest        int64    `json:"totalToTest"`
	PassedCount        int64    `json:"passedCount"`
	FailedCount        int64    `json:"failedCount"`
	TargetPassed       int64    `json:"targetPassed"`
	StageFailureCounts [6]int64 `json:"stageFailureCounts"`
	ElapsedTime        time.Duration `json:"elapsedTime"`
}

// CandidateResultPayload carries outcome for a single candidate proxy
type CandidateResultPayload struct {
	Index         int64        `json:"index"`
	Proxy         string       `json:"proxy"`
	Passed        bool         `json:"passed"`
	FailureReason string       `json:"failureReason,omitempty"`
	FailedStage   int          `json:"failedStage,omitempty"`
	Result        *VetResult   `json:"result,omitempty"`
	Item          *ProxyItem   `json:"item,omitempty"`
}

// BatchCompletePayload summarizes full pipeline results
type BatchCompletePayload struct {
	TotalProcessed     int64         `json:"totalProcessed"`
	PassedCount        int           `json:"passedCount"`
	FailedCount        int64         `json:"failedCount"`
	StageFailureCounts [6]int64      `json:"stageFailureCounts"`
	SavedPaths         []string      `json:"savedPaths"`
	VettedProxies      []*ProxyItem  `json:"vettedProxies"`
	Canceled           bool          `json:"canceled"`
	Error              string        `json:"error,omitempty"`
	ElapsedTime        time.Duration `json:"elapsedTime"`
}

// HealthAttemptPayload details one of the 3 health test attempts
type HealthAttemptPayload struct {
	Attempt   int       `json:"attempt"`
	ProxyUsed string    `json:"proxyUsed,omitempty"`
	Status    int       `json:"status,omitempty"`
	Origin    string    `json:"origin,omitempty"`
	Attempts  int       `json:"attempts"`
	Error     string    `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
}

// HealthCompletePayload summarizes all 3 health check attempts
type HealthCompletePayload struct {
	Attempts   []HealthAttemptPayload `json:"attempts"`
	Successes  int                    `json:"successes"`
	Failures   int                    `json:"failures"`
	Duration   time.Duration          `json:"duration"`
}

package gui

import (
	"time"
)

// JobStatus describes the lifecycle state of a background operation
type JobStatus string

const (
	JobIdle       JobStatus = "Idle"
	JobValidating JobStatus = "Validating"
	JobUpdating   JobStatus = "Updating"
	JobRunning    JobStatus = "Running"
	JobCanceling  JobStatus = "Canceling"
	JobCompleted  JobStatus = "Completed"
	JobCanceled   JobStatus = "Canceled"
	JobFailed     JobStatus = "Failed"
)

// JobType identifies the currently running tool function
type JobType string

const (
	JobNone       JobType = "None"
	JobBatchVet   JobType = "Batch Vetting"
	JobSingleVet  JobType = "Single Proxy Vetting"
	JobRequest    JobType = "URL Request"
	JobHealthTest JobType = "Health Test"
	JobDataUpdate JobType = "Upstream Data Sync"
)

// AppState holds global operational state
type AppState struct {
	Status      JobStatus
	ActiveJob   JobType
	Description string
	StartTime   time.Time
	LastError   string
}

// NewInitialState returns default initial state
func NewInitialState() AppState {
	return AppState{
		Status:    JobIdle,
		ActiveJob: JobNone,
	}
}

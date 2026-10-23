package proxycore

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEventsCreationAndSerialization(t *testing.T) {
	e := NewLogEvent("info", "test message")
	if e.Kind != EventLog || e.Level != "info" || e.Message != "test message" {
		t.Errorf("unexpected log event: %+v", e)
	}
	if e.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp in log event")
	}

	payload := BatchProgressPayload{
		TestedCount:  10,
		TotalToTest:  50,
		PassedCount:  5,
		FailedCount:  5,
		TargetPassed: 20,
		ElapsedTime:  2 * time.Second,
	}

	event := Event{
		Kind:            EventBatchProgress,
		Timestamp:       time.Now(),
		ProgressCurrent: 10,
		ProgressTotal:   50,
		Data:            payload,
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	var unmarshaled Event
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal event: %v", err)
	}

	if unmarshaled.Kind != EventBatchProgress || unmarshaled.ProgressCurrent != 10 {
		t.Errorf("unmarshaled event mismatch: %+v", unmarshaled)
	}
}

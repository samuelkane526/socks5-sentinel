package proxycore

import (
	"testing"
)

func TestParseCommitMessageTimestamp(t *testing.T) {
	msg1 := "Updated 📦 Mon Oct 19 23:43:54 UTC 2026"
	ts1 := ParseCommitMessageTimestamp(msg1)
	if ts1 == nil {
		t.Fatalf("failed to parse message with box emoji: %s", msg1)
	}
	if ts1.Timestamp <= 0 {
		t.Errorf("expected positive timestamp, got %d", ts1.Timestamp)
	}

	msg2 := "Date: 2026-10-19T14:30:00Z"
	ts2 := ParseCommitMessageTimestamp(msg2)
	if ts2 == nil {
		t.Fatalf("failed to parse ISO timestamp: %s", msg2)
	}
	if ts2.Timestamp <= 0 {
		t.Errorf("expected positive timestamp, got %d", ts2.Timestamp)
	}

	empty := ParseCommitMessageTimestamp("")
	if empty != nil {
		t.Errorf("expected nil for empty commit message")
	}
}

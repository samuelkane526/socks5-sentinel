package gui

import (
	"testing"
)

func TestStateTransitions(t *testing.T) {
	st := NewInitialState()
	if st.Status != JobIdle {
		t.Errorf("expected initial status JobIdle, got %s", st.Status)
	}
	if st.ActiveJob != JobNone {
		t.Errorf("expected initial active job JobNone, got %s", st.ActiveJob)
	}
}

package logging

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestRecorderMemoryRing(t *testing.T) {
	r := NewRecorder(nil)
	r.memCap = 3
	for i := 0; i < 5; i++ {
		r.Record(context.Background(), RequestRecord{
			RequestID: uuid.New(),
			Decision:  "allow",
			Host:      "h",
		})
	}
	recent := r.Recent()
	if len(recent) != 3 {
		t.Fatalf("len=%d want 3", len(recent))
	}
	last, ok := r.Last()
	if !ok || last.Decision != "allow" {
		t.Fatalf("last ok=%v decision=%q", ok, last.Decision)
	}
}

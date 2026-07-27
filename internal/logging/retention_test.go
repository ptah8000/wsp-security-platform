package logging

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseRetentionDays(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
		want int
		ok   bool
	}{
		{"number", "30", 30, true},
		{"min", "1", 1, true},
		{"clamp high", "9999", 3650, true},
		{"zero", "0", 0, false},
		{"negative", "-3", 0, false},
		{"string number", `"14"`, 14, true},
		{"empty", "", 0, false},
		{"object", `{"days":30}`, 0, false},
		{"null", `null`, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseRetentionDays(json.RawMessage(tc.raw))
			if ok != tc.ok || got != tc.want {
				t.Fatalf("parseRetentionDays(%q) = (%d, %v), want (%d, %v)", tc.raw, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestNewRetentionJobDefaults(t *testing.T) {
	t.Parallel()
	j := NewRetentionJob(nil)
	if j.BatchSize != DefaultRetentionBatchSize {
		t.Fatalf("BatchSize=%d want %d", j.BatchSize, DefaultRetentionBatchSize)
	}
	if j.Interval != DefaultRetentionInterval {
		t.Fatalf("Interval=%v want %v", j.Interval, DefaultRetentionInterval)
	}
	if j.MaxBatches != 100 {
		t.Fatalf("MaxBatches=%d want 100", j.MaxBatches)
	}
}

func TestRetentionCutoff(t *testing.T) {
	t.Parallel()
	// Document expected cutoff math used by RunOnce.
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	days := 30
	cutoff := now.AddDate(0, 0, -days)
	want := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	if !cutoff.Equal(want) {
		t.Fatalf("cutoff=%s want %s", cutoff, want)
	}
}

func TestRunOnceNilStore(t *testing.T) {
	t.Parallel()
	j := &RetentionJob{}
	if err := j.RunOnce(t.Context()); err == nil {
		t.Fatal("expected error for nil store")
	}
}

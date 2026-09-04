package speed

import (
	"testing"
	"time"
)

func TestSpeedup(t *testing.T) {
	tr := Trial{
		SwarmDuration:      30 * time.Second,
		SequentialDuration: 120 * time.Second,
	}
	if got := tr.Speedup(); got != 4.0 {
		t.Errorf("Speedup() = %v, want 4.0", got)
	}
	// malformed trial (no swarm duration) → 0, never a divide-by-zero.
	if got := (Trial{SequentialDuration: time.Second}).Speedup(); got != 0 {
		t.Errorf("Speedup() with zero swarm duration = %v, want 0", got)
	}
}

func TestFindingsParity(t *testing.T) {
	cases := []struct {
		name       string
		swarm, seq int
		tol        float64
		want       bool
	}{
		{"exact match", 20, 20, 0.05, true},
		{"within tolerance", 19, 20, 0.05, true},
		{"outside tolerance", 17, 20, 0.05, false},
		{"both zero", 0, 0, 0.05, true},
		{"swarm found nothing", 0, 12, 0.05, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := Trial{SwarmFindings: c.swarm, SequentialFindings: c.seq}
			if got := tr.FindingsParity(c.tol); got != c.want {
				t.Errorf("FindingsParity() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	trials := []Trial{
		{SwarmDuration: 10 * time.Second, SequentialDuration: 40 * time.Second, SwarmFindings: 10, SequentialFindings: 10}, // 4×
		{SwarmDuration: 20 * time.Second, SequentialDuration: 40 * time.Second, SwarmFindings: 8, SequentialFindings: 8},   // 2×
		{SwarmDuration: 0, SequentialDuration: 40 * time.Second},                                                           // skipped
	}
	s := Summarize(trials, 0.05)
	if s.Trials != 2 {
		t.Fatalf("Trials = %d, want 2 (malformed trial skipped)", s.Trials)
	}
	if s.MeanSpeedup != 3.0 {
		t.Errorf("MeanSpeedup = %v, want 3.0", s.MeanSpeedup)
	}
	if s.MinSpeedup != 2.0 || s.MaxSpeedup != 4.0 {
		t.Errorf("min/max = %v/%v, want 2.0/4.0", s.MinSpeedup, s.MaxSpeedup)
	}
	if !s.ParityHeld {
		t.Error("ParityHeld = false, want true (all findings matched)")
	}
}

// TestSummarize_ParityBreaks pins the honesty guard: if any trial drops
// findings, the summary must not silently claim "same findings".
func TestSummarize_ParityBreaks(t *testing.T) {
	trials := []Trial{
		{SwarmDuration: 10 * time.Second, SequentialDuration: 40 * time.Second, SwarmFindings: 3, SequentialFindings: 10},
	}
	s := Summarize(trials, 0.05)
	if s.ParityHeld {
		t.Error("ParityHeld = true, want false (swarm dropped findings)")
	}
	if got := s.Headline(); got == "" || s.MeanSpeedup == 0 {
		t.Errorf("expected a headline flagging the discrepancy, got %q", got)
	}
}

func TestHeadline(t *testing.T) {
	if got := (Summary{}).Headline(); got != "no valid trials" {
		t.Errorf("empty Headline() = %q", got)
	}
	s := Summary{Trials: 5, MeanSpeedup: 3.84, ParityHeld: true}
	if got := s.Headline(); got != "3.8× faster, same findings (5 targets)" {
		t.Errorf("Headline() = %q", got)
	}
}

// Package speed is the harness for Pentest Swarm AI's most on-brand,
// easiest-to-produce benchmark: swarm mode vs. the sequential runner,
// same target, same tools — measured on wall-clock.
//
// The headline it produces is "same findings, N× faster". That single
// number proves the core architectural claim (concurrent, machine-speed,
// a *real* swarm rather than a pipeline) without having to win an
// exploitation benchmark like Cybench/XBOW. Tracked as D.9.4.
//
// Status: scaffold. The comparison + scoring types below are pure and
// unit-tested. Wiring a concrete Runner that shells out to
// `pentestswarm scan --swarm` vs. the sequential path and times each is
// the next piece — run it against the bundled lab target (D.9.1) so the
// numbers are reproducible and legal.
package speed

import (
	"fmt"
	"time"
)

// Trial is one head-to-head run: the same target scanned twice, once
// with the stigmergic swarm scheduler and once with the sequential
// runner, recording how long each took and how many findings each
// produced. Findings counts let us assert the honest claim — the swarm
// is faster *without dropping findings* — rather than trading coverage
// for speed.
type Trial struct {
	Target             string
	SwarmDuration      time.Duration
	SequentialDuration time.Duration
	SwarmFindings      int
	SequentialFindings int
}

// Speedup is how many times faster the swarm finished than the
// sequential runner. > 1 means the swarm won. Returns 0 for a
// non-positive swarm duration (a malformed trial) so callers can filter.
func (t Trial) Speedup() float64 {
	if t.SwarmDuration <= 0 {
		return 0
	}
	return float64(t.SequentialDuration) / float64(t.SwarmDuration)
}

// FindingsParity reports whether the swarm found essentially the same
// set of findings as the sequential run, within tolerance (a fraction,
// e.g. 0.05 = the counts may differ by up to 5%). Recon is inherently a
// little non-deterministic, so exact equality would be too strict; the
// point is that the speedup doesn't come from skipping work.
func (t Trial) FindingsParity(tolerance float64) bool {
	if t.SequentialFindings == 0 {
		return t.SwarmFindings == 0
	}
	diff := t.SwarmFindings - t.SequentialFindings
	if diff < 0 {
		diff = -diff
	}
	return float64(diff)/float64(t.SequentialFindings) <= tolerance
}

// Summary aggregates a set of trials into the numbers we publish.
type Summary struct {
	Trials      int
	MeanSpeedup float64
	MinSpeedup  float64
	MaxSpeedup  float64
	// ParityHeld is true only if every trial kept findings parity — i.e.
	// the "same findings" half of "same findings, N× faster" is honest.
	ParityHeld bool
}

// Summarize folds trials into a Summary. Trials with a non-positive
// swarm duration are skipped (they can't yield a valid speedup).
// tolerance is passed through to FindingsParity.
func Summarize(trials []Trial, tolerance float64) Summary {
	s := Summary{ParityHeld: true}
	var total float64
	for _, t := range trials {
		sp := t.Speedup()
		if sp <= 0 {
			continue
		}
		if s.Trials == 0 || sp < s.MinSpeedup {
			s.MinSpeedup = sp
		}
		if sp > s.MaxSpeedup {
			s.MaxSpeedup = sp
		}
		total += sp
		s.Trials++
		if !t.FindingsParity(tolerance) {
			s.ParityHeld = false
		}
	}
	if s.Trials > 0 {
		s.MeanSpeedup = total / float64(s.Trials)
	}
	return s
}

// Headline renders the one-liner for the README / docs, e.g.
// "3.8× faster, same findings (5 targets)". If parity did not hold it
// says so plainly rather than overclaiming.
func (s Summary) Headline() string {
	if s.Trials == 0 {
		return "no valid trials"
	}
	parity := "same findings"
	if !s.ParityHeld {
		parity = "findings differed — investigate before publishing"
	}
	return fmt.Sprintf("%.1f× faster, %s (%d targets)", s.MeanSpeedup, parity, s.Trials)
}

// Runner executes both scan modes against a target and returns a Trial.
//
// Concrete implementation is a follow-up (D.9.4): shell out to
// `pentestswarm scan --swarm ...` and the sequential path, time each,
// and count findings from the emitted report. Kept as an interface so a
// container-isolated runner (against the lab target) can plug in without
// touching the scoring above.
type Runner interface {
	RunTrial(target string) (Trial, error)
}

// Package cybench is the harness for running Pentest Swarm AI against
// the Cybench benchmark (arXiv:2408.08926) — 40 CTF-style challenges
// covering web, crypto, pwn, forensics.
//
// Status: scaffold. The Runner interface + scoring shape are stable;
// fetching + executing Cybench challenges in a sandbox is the next
// piece of work. Tracked as Phase 3.3.1.
//
// To wire up the actual challenges:
//  1. Clone the Cybench repo (https://github.com/andyzorigin/cybench)
//     into ./fixtures/ — kept out of git via .gitignore
//  2. Implement LoadChallenges() to walk fixtures/<challenge>/{prompt.md, flag.txt}
//  3. Each challenge sandbox is launched via Docker; the swarm runs
//     against it with --swarm --safe-mode + a 30-min budget
//  4. Score: did the campaign report contain the flag? exact match.
package cybench

import (
	"context"
	"fmt"
	"time"
)

// Challenge is one Cybench task.
type Challenge struct {
	ID           string        // e.g. "web/easy/sqli-1"
	Category     string        // web | crypto | pwn | forensics | misc
	Difficulty   string        // easy | medium | hard
	Prompt       string        // the challenge description shown to the swarm
	ExpectedFlag string        // exact flag substring; campaign succeeds if this appears in any artifact
	TimeBudget   time.Duration // per-challenge cap (default 30m)
}

// Result is one challenge's outcome.
type Result struct {
	ChallengeID string
	Solved      bool
	Duration    time.Duration
	TokensUsed  int
	CostUSD     float64
	Notes       string // human-readable failure mode
}

// Runner executes a Challenge end-to-end and returns a Result.
//
// Concrete implementation is a follow-up — see package doc. Keeping
// this as an interface so future runners (containerized vs.
// host-process) can plug in without touching Score().
type Runner interface {
	Run(ctx context.Context, c Challenge) (Result, error)
}

// LoadChallenges reads the fixtures directory and returns parsed
// challenges. Returns an error (and an empty list) until fixtures are
// vendored. Intentional — we'd rather CI fail loudly with a "fetch
// fixtures first" message than silently report 0/0.
func LoadChallenges(fixturesDir string) ([]Challenge, error) {
	return nil, fmt.Errorf("cybench: fixtures not yet vendored; see %s for setup steps",
		"tests/bench/cybench/README.md")
}

// Score sums a slice of Results into the headline metric: solved/total
// and total dollar spend. Pure function; trivial to unit-test once
// the runner is in place.
func Score(results []Result) (solved, total int, totalUSD float64) {
	total = len(results)
	for _, r := range results {
		if r.Solved {
			solved++
		}
		totalUSD += r.CostUSD
	}
	return
}

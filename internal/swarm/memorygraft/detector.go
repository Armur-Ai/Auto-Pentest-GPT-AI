// Package memorygraft scans the blackboard for patterns characteristic
// of memory-graft attacks (MemoryGraft, arXiv:2512.16962). The attack
// model: an adversary plants entries that look legitimate but bias
// downstream agents' reasoning — the swarm's equivalent of poisoning
// a search index.
//
// We detect, not prevent. Prevention is a layered concern: scope
// validation (boundary), provenance signatures (per-write trust,
// internal/swarm/provenance), pheromone clamping (rank manipulation,
// internal/swarm/blackboard). This package's job is to surface the
// patterns that those layers can't catch on their own.
//
// Heuristics are deliberately conservative. False positives drown
// signal; we'd rather miss subtle attacks than spam the operator
// with normal swarm noise.
package memorygraft

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
)

// Alert describes one suspicious pattern detected on the blackboard.
type Alert struct {
	Kind        string    // "burst" | "repeat-title" | "duplicate-data" | "type-mismatch"
	AgentName   string    // the agent that authored the suspicious findings
	Description string    // human-readable summary
	Severity    string    // "low" | "medium" | "high"
	FirstSeen   time.Time
	Count       int // how many findings make up this signal
}

// Config tunes the detector. Zero-values pick conservative defaults.
type Config struct {
	// BurstWindow is the rolling window over which we count writes per
	// agent. Default 60s. A burst is "more than BurstThreshold writes
	// from one agent within this window."
	BurstWindow time.Duration

	// BurstThreshold is the per-agent write count that triggers a burst
	// alert. Default 50 — well above legit agents' steady-state cadence.
	BurstThreshold int

	// RepeatTitleThreshold is the count of identical titles from one
	// agent that triggers a repeat-title alert. Default 5.
	RepeatTitleThreshold int

	// DuplicateDataThreshold is the count of identical Data payloads
	// from one agent that triggers a duplicate-data alert. Default 3.
	// Lower than RepeatTitle because duplicate Data is far rarer in
	// honest agent behavior.
	DuplicateDataThreshold int
}

func (c Config) withDefaults() Config {
	if c.BurstWindow == 0 {
		c.BurstWindow = 60 * time.Second
	}
	if c.BurstThreshold == 0 {
		c.BurstThreshold = 50
	}
	if c.RepeatTitleThreshold == 0 {
		c.RepeatTitleThreshold = 5
	}
	if c.DuplicateDataThreshold == 0 {
		c.DuplicateDataThreshold = 3
	}
	return c
}

// expectedAuthors maps each finding type to the agent names allowed to
// emit it. A finding under a type whose emitter list doesn't include
// the AgentName is a type-mismatch alert.
//
// This is not a security boundary (a determined attacker can use any
// agent name) — it's a regression alarm. If "recon" suddenly writes
// CVE_MATCH, either we've got a bug or someone's poking at the board.
var expectedAuthors = map[blackboard.FindingType]map[string]bool{
	blackboard.TypeCVEMatch:      {"classifier": true},
	blackboard.TypeMisconfig:     {"classifier": true},
	blackboard.TypeExploitChain:  {"exploit": true},
	blackboard.TypeExploitResult: {"exploit": true},
	blackboard.TypePortOpen:      {"recon": true, "nmap": true},
	blackboard.TypeSubdomain:     {"recon": true},
}

// Scan reads the campaign's recent findings from the board and emits
// alerts for any pattern that matches the configured heuristics.
//
// Pure-read; never writes to the board. Safe to call from a watchdog
// goroutine on a ticker.
func Scan(ctx context.Context, board blackboard.Board, cfg Config) ([]Alert, error) {
	c := cfg.withDefaults()

	findings, err := board.Query(ctx, blackboard.Predicate{Limit: 5000})
	if err != nil {
		return nil, fmt.Errorf("memorygraft scan: %w", err)
	}

	type agentBucket struct {
		count          int
		first          time.Time
		last           time.Time
		titleCounts    map[string]int
		dataHashCounts map[string]int
		typeMismatches map[blackboard.FindingType]int
	}
	buckets := map[string]*agentBucket{}
	for _, f := range findings {
		b, ok := buckets[f.AgentName]
		if !ok {
			b = &agentBucket{
				titleCounts:    map[string]int{},
				dataHashCounts: map[string]int{},
				typeMismatches: map[blackboard.FindingType]int{},
				first:          f.CreatedAt,
				last:           f.CreatedAt,
			}
			buckets[f.AgentName] = b
		}
		b.count++
		if f.CreatedAt.Before(b.first) {
			b.first = f.CreatedAt
		}
		if f.CreatedAt.After(b.last) {
			b.last = f.CreatedAt
		}
		// Title is in the JSON Data — for cheap detection we hash the
		// whole Data instead of parsing.
		dataHash := hashData(f.Data)
		b.dataHashCounts[dataHash]++
		// Title-bucket: first 80 bytes of Data is a coarse but useful
		// fingerprint; titles are typically near the front of the JSON.
		if len(f.Data) > 0 {
			fp := f.Data
			if len(fp) > 80 {
				fp = fp[:80]
			}
			b.titleCounts[string(fp)]++
		}
		// Type-mismatch: if the type has an expected-authors list and
		// this agent isn't on it, count it.
		if allowed, has := expectedAuthors[f.Type]; has {
			if !allowed[f.AgentName] {
				b.typeMismatches[f.Type]++
			}
		}
	}

	var alerts []Alert
	// Stable iteration order so test assertions don't flap.
	agentNames := make([]string, 0, len(buckets))
	for n := range buckets {
		agentNames = append(agentNames, n)
	}
	sort.Strings(agentNames)

	for _, name := range agentNames {
		b := buckets[name]

		// Burst: many writes in a short window
		if b.count >= c.BurstThreshold && b.last.Sub(b.first) <= c.BurstWindow {
			alerts = append(alerts, Alert{
				Kind:        "burst",
				AgentName:   name,
				Description: fmt.Sprintf("%d writes in %s (threshold %d/%s)", b.count, b.last.Sub(b.first), c.BurstThreshold, c.BurstWindow),
				Severity:    "medium",
				FirstSeen:   b.first,
				Count:       b.count,
			})
		}

		// Repeat title: same title hash from one agent ≥ threshold
		for fp, n := range b.titleCounts {
			if n >= c.RepeatTitleThreshold {
				alerts = append(alerts, Alert{
					Kind:        "repeat-title",
					AgentName:   name,
					Description: fmt.Sprintf("%d findings share the same title fingerprint %q", n, truncate(fp, 40)),
					Severity:    "low",
					FirstSeen:   b.first,
					Count:       n,
				})
			}
		}

		// Duplicate data: same exact Data payload from one agent ≥ threshold
		for _, n := range b.dataHashCounts {
			if n >= c.DuplicateDataThreshold {
				alerts = append(alerts, Alert{
					Kind:        "duplicate-data",
					AgentName:   name,
					Description: fmt.Sprintf("%d findings have byte-identical Data payloads", n),
					Severity:    "high",
					FirstSeen:   b.first,
					Count:       n,
				})
			}
		}

		// Type mismatch: agent emitted a finding under a type it
		// doesn't normally own.
		for t, n := range b.typeMismatches {
			alerts = append(alerts, Alert{
				Kind:        "type-mismatch",
				AgentName:   name,
				Description: fmt.Sprintf("%d %s findings (this type is normally written by other agents)", n, t),
				Severity:    "medium",
				FirstSeen:   b.first,
				Count:       n,
			})
		}
	}

	return alerts, nil
}

func hashData(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return string(sum[:8]) // first 8 bytes is enough for collision spotting
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

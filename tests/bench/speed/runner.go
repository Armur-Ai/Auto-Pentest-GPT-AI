package speed

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ShellRunner is the concrete Runner (D.9.4): it shells out to the
// pentestswarm binary, scanning a target once with the stigmergic swarm
// scheduler (--swarm) and once with the sequential runner, timing each
// and counting findings from the emitted JSON report. Point it at the
// bundled lab target (D.9.1) so the numbers are reproducible and legal.
type ShellRunner struct {
	BinPath string        // path to the `pentestswarm` binary
	Scope   string        // --scope value (e.g. "127.0.0.1/32,localhost")
	Extra   []string      // extra flags, e.g. []string{"--provider", "ollama"}
	Timeout time.Duration // per-scan timeout; 0 = none
}

// RunTrial scans target both ways and returns a Trial. Running the swarm
// first then sequential (order is fixed so warm-cache effects hit both).
func (s ShellRunner) RunTrial(target string) (Trial, error) {
	swarmDur, swarmN, err := s.scan(target, true)
	if err != nil {
		return Trial{}, fmt.Errorf("swarm scan of %s: %w", target, err)
	}
	seqDur, seqN, err := s.scan(target, false)
	if err != nil {
		return Trial{}, fmt.Errorf("sequential scan of %s: %w", target, err)
	}
	return Trial{
		Target:             target,
		SwarmDuration:      swarmDur,
		SequentialDuration: seqDur,
		SwarmFindings:      swarmN,
		SequentialFindings: seqN,
	}, nil
}

func (s ShellRunner) scan(target string, swarm bool) (time.Duration, int, error) {
	dir, err := os.MkdirTemp("", "speedbench-")
	if err != nil {
		return 0, 0, err
	}
	defer os.RemoveAll(dir)

	args := []string{"scan", target, "--scope", s.Scope, "--format", "json", "--output", dir, "--quiet"}
	if swarm {
		args = append(args, "--swarm")
	}
	args = append(args, s.Extra...)

	ctx := context.Background()
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}

	start := time.Now()
	cmd := exec.CommandContext(ctx, s.BinPath, args...)
	if runErr := cmd.Run(); runErr != nil {
		return 0, 0, runErr
	}
	dur := time.Since(start)

	n, err := countFindingsInDir(dir)
	if err != nil {
		return 0, 0, err
	}
	return dur, n, nil
}

// countFindingsInDir locates the JSON report written into dir and returns
// its findings count.
func countFindingsInDir(dir string) (int, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return 0, err
	}
	for _, m := range matches {
		body, readErr := os.ReadFile(m)
		if readErr != nil {
			continue
		}
		if n, ok := countFindingsJSON(body); ok {
			return n, nil
		}
	}
	return 0, nil
}

// countFindingsJSON counts the top-level "findings" array in a report
// JSON body (PentestReport.Findings, `json:"findings"`). Returns ok=false
// for a body that isn't a findings report at all.
func countFindingsJSON(body []byte) (int, bool) {
	var doc struct {
		Findings *[]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Findings == nil {
		return 0, false
	}
	return len(*doc.Findings), true
}

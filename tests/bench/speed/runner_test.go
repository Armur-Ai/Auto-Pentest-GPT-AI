package speed

import (
	"os"
	"testing"
	"time"
)

func TestCountFindingsJSON(t *testing.T) {
	body := []byte(`{"findings":[{"title":"a"},{"title":"b"},{"title":"c"}]}`)
	n, ok := countFindingsJSON(body)
	if !ok || n != 3 {
		t.Errorf("countFindingsJSON = (%d,%v), want (3,true)", n, ok)
	}
	// A report with an empty findings array is still a valid report → ok=true, n=0.
	if n, ok := countFindingsJSON([]byte(`{"findings":[]}`)); !ok || n != 0 {
		t.Errorf("empty findings = (%d,%v), want (0,true)", n, ok)
	}
	// Not a findings report at all → ok=false so callers keep looking.
	if _, ok := countFindingsJSON([]byte(`{"other":1}`)); ok {
		t.Error("non-report JSON should return ok=false")
	}
	// Malformed → ok=false, never a panic.
	if _, ok := countFindingsJSON([]byte("not json")); ok {
		t.Error("malformed JSON should return ok=false")
	}
}

func TestCountFindingsInDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/acme.corp-abc123.json",
		[]byte(`{"findings":[{"t":1},{"t":2}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := countFindingsInDir(dir)
	if err != nil || n != 2 {
		t.Errorf("countFindingsInDir = (%d,%v), want (2,nil)", n, err)
	}
}

// TestSpeedBench_Live runs the real head-to-head against a target — only
// when SPEEDBENCH_TARGET is set, so it's skipped in normal `go test`.
// Produces the publishable headline (needs a working model, e.g. a local
// Ollama, and the bundled lab up):
//
//	SPEEDBENCH_BIN=./bin/pentestswarm \
//	SPEEDBENCH_TARGET=http://localhost:3000 \
//	SPEEDBENCH_SCOPE=127.0.0.1/32,localhost \
//	SPEEDBENCH_EXTRA="--provider ollama" \
//	  go test ./tests/bench/speed -run Live -v
func TestSpeedBench_Live(t *testing.T) {
	target := os.Getenv("SPEEDBENCH_TARGET")
	if target == "" {
		t.Skip("set SPEEDBENCH_TARGET to run the live swarm-vs-sequential benchmark")
	}
	bin := os.Getenv("SPEEDBENCH_BIN")
	if bin == "" {
		bin = "pentestswarm"
	}
	scope := os.Getenv("SPEEDBENCH_SCOPE")
	if scope == "" {
		scope = target
	}
	var extra []string
	if e := os.Getenv("SPEEDBENCH_EXTRA"); e != "" {
		extra = splitFields(e)
	}

	r := ShellRunner{BinPath: bin, Scope: scope, Extra: extra, Timeout: 30 * time.Minute}
	trial, err := r.RunTrial(target)
	if err != nil {
		t.Fatalf("RunTrial: %v", err)
	}
	sum := Summarize([]Trial{trial}, 0.10)
	t.Logf("swarm=%s sequential=%s findings swarm/seq=%d/%d",
		trial.SwarmDuration, trial.SequentialDuration, trial.SwarmFindings, trial.SequentialFindings)
	t.Logf("HEADLINE: %s", sum.Headline())
}

// splitFields is a tiny whitespace splitter (avoids pulling in strings for
// one call and keeps the extra-flags parsing obvious).
func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

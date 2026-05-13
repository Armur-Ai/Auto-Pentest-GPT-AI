package tools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// --- dnsx tests ------------------------------------------------------

func TestDnsx_DoesNotPassDFlag(t *testing.T) {
	// Regression: the wrapper used to pass `-d <target>` which puts
	// dnsx into subdomain brute-force mode and mandates `-w wordlist`.
	// We never want that — the wrapper's role is "resolve these hosts",
	// which dnsx expects via stdin.
	dir := fakeBin(t, "dnsx", `{"host":"example.com","a":["93.184.216.34"]}`, 0)

	tool := NewDnsxTool()
	if _, err := tool.Run(context.Background(), "example.com", Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	argv := readArgv(t, dir)
	if hasFlag(argv, "-d") {
		t.Errorf("dnsx wrapper must NOT pass -d (brute-mode); got: %v", argv)
	}
	if hasFlag(argv, "-w") {
		t.Errorf("dnsx wrapper must NOT pass -w (brute-mode); got: %v", argv)
	}
}

func TestDnsx_PipesSingleTargetOnStdin(t *testing.T) {
	// With no opts["hosts"] override, the wrapper must pipe `target`
	// (one per line, trailing newline) on stdin.
	dir := fakeBin(t, "dnsx", "", 0)

	tool := NewDnsxTool()
	if _, err := tool.Run(context.Background(), "example.com", Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := readStdin(t, dir)
	want := "example.com\n"
	if got != want {
		t.Errorf("stdin = %q, want %q", got, want)
	}
}

func TestDnsx_PipesHostsListWhenProvided(t *testing.T) {
	// When the caller supplies opts["hosts"], the wrapper must pipe
	// that batch (one host per line) so dnsx can resolve them all in
	// a single invocation — saves O(n) process spawns when subfinder
	// returns dozens of subdomains.
	dir := fakeBin(t, "dnsx", "", 0)

	tool := NewDnsxTool()
	opts := Options{"hosts": []string{"a.example", "b.example", "c.example"}}
	if _, err := tool.Run(context.Background(), "ignored", opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := readStdin(t, dir)
	want := "a.example\nb.example\nc.example\n"
	if got != want {
		t.Errorf("stdin = %q, want %q", got, want)
	}
}

func TestDnsx_PassesQueryTypeFlags(t *testing.T) {
	// The wrapper's stated purpose is to resolve A, AAAA, CNAME with
	// the original query echoed back (-resp). Lock in the flag set.
	dir := fakeBin(t, "dnsx", "", 0)

	tool := NewDnsxTool()
	if _, err := tool.Run(context.Background(), "example.com", Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	argv := readArgv(t, dir)
	for _, flag := range []string{"-json", "-silent", "-a", "-aaaa", "-cname", "-resp"} {
		if !hasFlag(argv, flag) {
			t.Errorf("expected flag %s in argv, got: %v", flag, argv)
		}
	}
}

func TestDnsx_ScopeViolationReturnsError(t *testing.T) {
	scopeDef := &scope.ScopeDefinition{AllowedDomains: []string{"allowed.example"}}
	ctx := WithScope(context.Background(), scopeDef)

	tool := NewDnsxTool()
	_, err := tool.Run(ctx, "evil.com", Options{})
	if err == nil {
		t.Fatal("expected scope violation error, got nil")
	}
	if !strings.Contains(err.Error(), "scope violation") {
		t.Errorf("error should mention scope violation; got: %v", err)
	}
}

func TestDnsx_ScopeAllowedTargetRuns(t *testing.T) {
	dir := fakeBin(t, "dnsx", "", 0)

	scopeDef := &scope.ScopeDefinition{AllowedDomains: []string{"example.com"}}
	ctx := WithScope(context.Background(), scopeDef)

	tool := NewDnsxTool()
	res, err := tool.Run(ctx, "example.com", Options{})
	if err != nil {
		t.Fatalf("in-scope target failed: %v", err)
	}
	if res.Error != nil {
		t.Errorf("unexpected result.Error: %v", res.Error)
	}

	if !hasFlag(readArgv(t, dir), "-json") {
		t.Error("wrapper did not invoke fake dnsx for in-scope target")
	}
}

func TestDnsx_EmptyHostsFallsBackToTarget(t *testing.T) {
	// opts["hosts"] = [] (empty slice) must fall back to using
	// `target` so the adapter remains usable from single-arg callers.
	dir := fakeBin(t, "dnsx", "", 0)

	tool := NewDnsxTool()
	opts := Options{"hosts": []string{}}
	if _, err := tool.Run(context.Background(), "fallback.example", opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := readStdin(t, dir)
	want := "fallback.example\n"
	if got != want {
		t.Errorf("empty hosts list should fall back to target on stdin; got %q want %q", got, want)
	}
}

func TestDnsx_NameIsDnsx(t *testing.T) {
	if got := NewDnsxTool().Name(); got != "dnsx" {
		t.Errorf("Name() = %q, want dnsx", got)
	}
}

func TestDnsx_IsAvailableReflectsPATH(t *testing.T) {
	fakeBin(t, "dnsx", "", 0)
	if !NewDnsxTool().IsAvailable() {
		t.Error("IsAvailable() = false when fake binary is on PATH")
	}
}

func TestDnsx_IsAvailableFalseWithoutPATH(t *testing.T) {
	t.Setenv("PATH", "")
	if NewDnsxTool().IsAvailable() {
		t.Error("IsAvailable() = true when PATH is empty (should be false)")
	}
}

func TestDnsx_PopulatesParsedFindingsFromJSONL(t *testing.T) {
	// Verify dnsx's per-line JSON output is decoded into
	// ParsedFindings so callers see structured A/AAAA/CNAME data,
	// not just RawOutput.
	jsonl := `{"host":"a.example","a":["93.184.216.34"]}` + "\n" +
		`{"host":"b.example","a":["192.0.2.1"],"cname":["alias.example"]}` + "\n"
	fakeBin(t, "dnsx", jsonl, 0)

	tool := NewDnsxTool()
	res, err := tool.Run(context.Background(), "example.com", Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.ParsedFindings) != 2 {
		t.Fatalf("ParsedFindings count = %d, want 2", len(res.ParsedFindings))
	}
	if got := res.ParsedFindings[0]["host"]; got != "a.example" {
		t.Errorf("first host = %v, want a.example", got)
	}
	cname, ok := res.ParsedFindings[1]["cname"].([]any)
	if !ok || len(cname) != 1 || cname[0] != "alias.example" {
		t.Errorf("second cname = %v, want [alias.example]", res.ParsedFindings[1]["cname"])
	}
}

func TestDnsx_MultiHostBatchListsEveryHost(t *testing.T) {
	// Regression: when given N hosts, every host must end up on stdin
	// — losing one means downstream consumers miss resolution data.
	dir := fakeBin(t, "dnsx", "", 0)

	tool := NewDnsxTool()
	opts := Options{"hosts": []string{
		"a.example",
		"b.example",
		"c.example",
		"d.example",
		"e.example",
	}}
	if _, err := tool.Run(context.Background(), "ignored", opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	stdin := readStdin(t, dir)
	for _, h := range []string{"a.example", "b.example", "c.example", "d.example", "e.example"} {
		if !strings.Contains(stdin, h+"\n") {
			t.Errorf("stdin missing %q line; full payload: %q", h, stdin)
		}
	}
	// Also verify trailing newline so dnsx treats the last host as
	// complete instead of waiting for more bytes.
	if !strings.HasSuffix(stdin, "\n") {
		t.Errorf("stdin must end with newline; got %q", stdin)
	}
}

func TestDnsx_TimeoutOptHonoured(t *testing.T) {
	sleepBin(t, "dnsx", 5)

	tool := NewDnsxTool()
	start := time.Now()
	res, err := tool.Run(context.Background(), "example.com", Options{"timeout": 1})
	assertErrored(t, err, res, time.Since(start), 4*time.Second)
}

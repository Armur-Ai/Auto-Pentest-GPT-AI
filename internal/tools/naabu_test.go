package tools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// --- naabu tests -----------------------------------------------------

func TestNaabu_DefaultUsesTopPortsPreset(t *testing.T) {
	// Regression: the wrapper previously emitted `-p top-1000` which
	// naabu rejects with "FTL invalid port number: 'top'". The fix is
	// to use `-top-ports 1000` (a real naabu preset) by default.
	dir := fakeBin(t, "naabu", `{"ip":"192.0.2.1","port":80}`, 0)

	tool := NewNaabuTool()
	if _, err := tool.Run(context.Background(), "192.0.2.1", Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	argv := readArgv(t, dir)
	// MUST NOT pass `-p top-1000` — that was the bug.
	if v := flagValue(argv, "-p"); v == "top-1000" || v == "top-100" {
		t.Errorf("-p must not carry a 'top-N' literal (invalid syntax); got %q", v)
	}
	// MUST use the -top-ports preset with the documented default.
	if got := flagValue(argv, "-top-ports"); got != "1000" {
		t.Errorf("default -top-ports = %q, want 1000", got)
	}
}

func TestNaabu_TopPortsCustomDefault(t *testing.T) {
	dir := fakeBin(t, "naabu", "", 0)

	tool := NewNaabuTool()
	opts := Options{"top_ports": "100"}
	if _, err := tool.Run(context.Background(), "192.0.2.1", opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := flagValue(readArgv(t, dir), "-top-ports"); got != "100" {
		t.Errorf("top_ports override = %q, want 100", got)
	}
}

func TestNaabu_ExplicitPortsOverridesTopPorts(t *testing.T) {
	// When opts["ports"] is set, the wrapper must use `-p <list>`
	// AND drop `-top-ports` (mutually exclusive in naabu).
	dir := fakeBin(t, "naabu", "", 0)

	tool := NewNaabuTool()
	opts := Options{"ports": "80,443,8080"}
	if _, err := tool.Run(context.Background(), "192.0.2.1", opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	argv := readArgv(t, dir)
	if got := flagValue(argv, "-p"); got != "80,443,8080" {
		t.Errorf("-p value = %q, want 80,443,8080", got)
	}
	if hasFlag(argv, "-top-ports") {
		t.Errorf("when -p is explicit, -top-ports must be omitted; got argv %v", argv)
	}
}

func TestNaabu_PassesHostAndJsonAndSilent(t *testing.T) {
	dir := fakeBin(t, "naabu", "", 0)

	tool := NewNaabuTool()
	if _, err := tool.Run(context.Background(), "192.0.2.5", Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	argv := readArgv(t, dir)
	if v := flagValue(argv, "-host"); v != "192.0.2.5" {
		t.Errorf("-host = %q, want 192.0.2.5", v)
	}
	if !hasFlag(argv, "-json") {
		t.Errorf("-json missing from argv: %v", argv)
	}
	if !hasFlag(argv, "-silent") {
		t.Errorf("-silent missing from argv: %v", argv)
	}
}

func TestNaabu_ScopeViolationReturnsError(t *testing.T) {
	// CIDR-only scope; an IP outside the allowed range must trip the
	// scope guard before any binary is invoked.
	scopeDef := &scope.ScopeDefinition{AllowedCIDRs: []string{"10.0.0.0/24"}}
	ctx := WithScope(context.Background(), scopeDef)

	tool := NewNaabuTool()
	_, err := tool.Run(ctx, "192.168.1.1", Options{})
	if err == nil {
		t.Fatal("expected scope violation error, got nil")
	}
	if !strings.Contains(err.Error(), "scope violation") {
		t.Errorf("error should mention scope violation; got: %v", err)
	}
}

func TestNaabu_ScopeAllowedCIDRRuns(t *testing.T) {
	dir := fakeBin(t, "naabu", "", 0)

	scopeDef := &scope.ScopeDefinition{AllowedCIDRs: []string{"10.0.0.0/24"}}
	ctx := WithScope(context.Background(), scopeDef)

	tool := NewNaabuTool()
	res, err := tool.Run(ctx, "10.0.0.5", Options{})
	if err != nil {
		t.Fatalf("in-scope IP failed: %v", err)
	}
	if res.Error != nil {
		t.Errorf("unexpected result.Error: %v", res.Error)
	}

	if !hasFlag(readArgv(t, dir), "-top-ports") {
		t.Error("wrapper did not invoke fake naabu for in-scope IP")
	}
}

func TestNaabu_NonZeroExitSurfacesError(t *testing.T) {
	fakeBin(t, "naabu", "", 1)

	tool := NewNaabuTool()
	start := time.Now()
	res, err := tool.Run(context.Background(), "192.0.2.1", Options{})
	assertErrored(t, err, res, time.Since(start), 10*time.Second)
}

func TestNaabu_NameIsNaabu(t *testing.T) {
	if got := NewNaabuTool().Name(); got != "naabu" {
		t.Errorf("Name() = %q, want naabu", got)
	}
}

func TestNaabu_IsAvailableReflectsPATH(t *testing.T) {
	fakeBin(t, "naabu", "", 0)
	if !NewNaabuTool().IsAvailable() {
		t.Error("IsAvailable() = false when fake binary is on PATH")
	}
}

func TestNaabu_IsAvailableFalseWithoutPATH(t *testing.T) {
	t.Setenv("PATH", "")
	if NewNaabuTool().IsAvailable() {
		t.Error("IsAvailable() = true when PATH is empty (should be false)")
	}
}

func TestNaabu_PopulatesParsedFindingsFromJSONL(t *testing.T) {
	jsonl := `{"ip":"192.0.2.1","port":80,"protocol":"tcp"}` + "\n" +
		`{"ip":"192.0.2.1","port":443,"protocol":"tcp"}` + "\n"
	fakeBin(t, "naabu", jsonl, 0)

	tool := NewNaabuTool()
	res, err := tool.Run(context.Background(), "192.0.2.1", Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.ParsedFindings) != 2 {
		t.Fatalf("ParsedFindings count = %d, want 2", len(res.ParsedFindings))
	}
	if got := res.ParsedFindings[0]["port"]; got != float64(80) {
		t.Errorf("first port = %v (%T), want 80", got, got)
	}
	if got := res.ParsedFindings[1]["port"]; got != float64(443) {
		t.Errorf("second port = %v (%T), want 443", got, got)
	}
}

func TestNaabu_ExplicitPortsAndTopPortsOptBothSet_PortsWins(t *testing.T) {
	// When the caller sets BOTH opts["ports"] and opts["top_ports"],
	// the explicit -p list must win because the wrapper checks
	// `ports != ""` first. This pins the precedence so a refactor
	// that re-orders the if/else doesn't silently change semantics.
	dir := fakeBin(t, "naabu", "", 0)

	tool := NewNaabuTool()
	opts := Options{"ports": "80,443", "top_ports": "100"}
	if _, err := tool.Run(context.Background(), "192.0.2.1", opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	argv := readArgv(t, dir)
	if got := flagValue(argv, "-p"); got != "80,443" {
		t.Errorf("-p = %q, want 80,443", got)
	}
	if hasFlag(argv, "-top-ports") {
		t.Errorf("explicit ports must drop -top-ports; got argv %v", argv)
	}
}

func TestNaabu_TimeoutOptHonoured(t *testing.T) {
	sleepBin(t, "naabu", 5)

	tool := NewNaabuTool()
	start := time.Now()
	res, err := tool.Run(context.Background(), "192.0.2.1", Options{"timeout": 1})
	assertErrored(t, err, res, time.Since(start), 4*time.Second)
}

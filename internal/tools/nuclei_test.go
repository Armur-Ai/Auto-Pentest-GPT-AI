package tools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// --- nuclei tests ----------------------------------------------------

func TestNuclei_UsesJSONLFlag(t *testing.T) {
	// Regression test for nuclei v3, which dropped the legacy -json
	// flag. The wrapper must use -jsonl; passing -json makes nuclei
	// exit with "flag provided but not defined: -json".
	dir := fakeBin(t, "nuclei", `{"template-id":"CVE-2022-3590","info":{"severity":"medium"}}`, 0)

	tool := NewNucleiTool()
	res, err := tool.Run(context.Background(), "https://example.com", Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Error != nil {
		t.Fatalf("result error: %v", res.Error)
	}

	argv := readArgv(t, dir)
	if !hasFlag(argv, "-jsonl") {
		t.Errorf("expected -jsonl in argv, got: %v", argv)
	}
	if hasFlag(argv, "-json") {
		t.Errorf("legacy -json flag must not appear; got: %v", argv)
	}
}

func TestNuclei_DefaultSeverityIsCriticalHighMedium(t *testing.T) {
	// The wrapper's documented default is critical,high,medium. Anyone
	// who flips this default to noisier severities (low/info) will be
	// caught here.
	dir := fakeBin(t, "nuclei", "", 0)

	tool := NewNucleiTool()
	if _, err := tool.Run(context.Background(), "https://example.com", Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	argv := readArgv(t, dir)
	got := flagValue(argv, "-severity")
	want := "critical,high,medium"
	if got != want {
		t.Errorf("default -severity = %q, want %q", got, want)
	}
}

func TestNuclei_SeverityOverride(t *testing.T) {
	dir := fakeBin(t, "nuclei", "", 0)

	tool := NewNucleiTool()
	opts := Options{"severity": []string{"critical", "high"}}
	if _, err := tool.Run(context.Background(), "https://example.com", opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	argv := readArgv(t, dir)
	got := flagValue(argv, "-severity")
	if got != "critical,high" {
		t.Errorf("override -severity = %q, want critical,high", got)
	}
}

func TestNuclei_PassesTargetAndSilent(t *testing.T) {
	dir := fakeBin(t, "nuclei", "", 0)

	tool := NewNucleiTool()
	if _, err := tool.Run(context.Background(), "https://example.com", Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	argv := readArgv(t, dir)
	if v := flagValue(argv, "-u"); v != "https://example.com" {
		t.Errorf("-u value = %q, want https://example.com", v)
	}
	if !hasFlag(argv, "-silent") {
		t.Errorf("-silent missing from argv: %v", argv)
	}
}

func TestNuclei_ScopeViolationReturnsError(t *testing.T) {
	scopeDef := &scope.ScopeDefinition{AllowedDomains: []string{"allowed.example"}}
	ctx := WithScope(context.Background(), scopeDef)

	tool := NewNucleiTool()
	_, err := tool.Run(ctx, "evil.com", Options{})
	if err == nil {
		t.Fatal("expected scope violation error, got nil")
	}
	if !strings.Contains(err.Error(), "scope violation") {
		t.Errorf("error should mention scope violation; got: %v", err)
	}
}

func TestNuclei_ScopeAllowedTargetRuns(t *testing.T) {
	dir := fakeBin(t, "nuclei", "", 0)

	scopeDef := &scope.ScopeDefinition{AllowedDomains: []string{"example.com"}}
	ctx := WithScope(context.Background(), scopeDef)

	tool := NewNucleiTool()
	res, err := tool.Run(ctx, "https://example.com", Options{})
	if err != nil {
		t.Fatalf("in-scope target failed: %v", err)
	}
	if res.Error != nil {
		t.Errorf("unexpected result.Error: %v", res.Error)
	}

	if !hasFlag(readArgv(t, dir), "-jsonl") {
		t.Error("wrapper did not invoke fake nuclei for in-scope target")
	}
}

func TestNuclei_NonZeroExitSurfacesError(t *testing.T) {
	fakeBin(t, "nuclei", "", 2)

	tool := NewNucleiTool()
	start := time.Now()
	res, err := tool.Run(context.Background(), "https://example.com", Options{})
	assertErrored(t, err, res, time.Since(start), 10*time.Second)
}

func TestNuclei_NameIsNuclei(t *testing.T) {
	if got := NewNucleiTool().Name(); got != "nuclei" {
		t.Errorf("Name() = %q, want nuclei", got)
	}
}

func TestNuclei_IsAvailableReflectsPATH(t *testing.T) {
	fakeBin(t, "nuclei", "", 0)
	if !NewNucleiTool().IsAvailable() {
		t.Error("IsAvailable() = false when fake binary is on PATH")
	}
}

func TestNuclei_IsAvailableFalseWithoutPATH(t *testing.T) {
	t.Setenv("PATH", "")
	if NewNucleiTool().IsAvailable() {
		t.Error("IsAvailable() = true when PATH is empty (should be false)")
	}
}

func TestNuclei_PopulatesParsedFindingsFromJSONL(t *testing.T) {
	// Two CVE matches as nuclei would emit them. The wrapper should
	// surface them through ParsedFindings (via executor.parseJSONLines)
	// so the recon agent can promote them to RawFindings.
	jsonl := `{"template-id":"CVE-2022-3590","info":{"severity":"medium"},"matched-at":"https://example.com/xmlrpc.php"}` + "\n" +
		`{"template-id":"CVE-2024-1234","info":{"severity":"high"},"matched-at":"https://example.com/api"}` + "\n"
	fakeBin(t, "nuclei", jsonl, 0)

	tool := NewNucleiTool()
	res, err := tool.Run(context.Background(), "https://example.com", Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.ParsedFindings) != 2 {
		t.Fatalf("ParsedFindings count = %d, want 2", len(res.ParsedFindings))
	}
	if got := res.ParsedFindings[0]["template-id"]; got != "CVE-2022-3590" {
		t.Errorf("first template-id = %v, want CVE-2022-3590", got)
	}
	if got := res.ParsedFindings[1]["template-id"]; got != "CVE-2024-1234" {
		t.Errorf("second template-id = %v, want CVE-2024-1234", got)
	}
}

func TestNuclei_MissingSeverityKeyUsesDefault(t *testing.T) {
	// When opts has no "severity" key at all, GetStringSlice returns
	// nil and the wrapper's `severity == nil` branch falls back to
	// the hard-coded default critical,high,medium. This guards against
	// a future refactor that switches `nil` to `len() == 0` — which
	// would erase the documented default for absent keys.
	dir := fakeBin(t, "nuclei", "", 0)

	tool := NewNucleiTool()
	// No severity key in opts.
	if _, err := tool.Run(context.Background(), "https://example.com", Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := flagValue(readArgv(t, dir), "-severity")
	want := "critical,high,medium"
	if got != want {
		t.Errorf("absent severity key should use default; got %q want %q", got, want)
	}
}

func TestNuclei_TimeoutOptHonoured(t *testing.T) {
	// Fake binary that sleeps past the configured timeout.
	sleepBin(t, "nuclei", 5)

	tool := NewNucleiTool()
	start := time.Now()
	res, err := tool.Run(context.Background(), "https://example.com", Options{"timeout": 1})
	assertErrored(t, err, res, time.Since(start), 4*time.Second)
}

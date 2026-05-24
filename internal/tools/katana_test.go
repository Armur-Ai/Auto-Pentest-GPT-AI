package tools

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// fakeBin writes a POSIX shell script to the test's TempDir that:
//   - dumps argv (one arg per line) to <dir>/argv
//   - dumps stdin to <dir>/stdin
//   - prints the supplied stdout payload so the wrapper sees something
//     parseable, and exits with `code`
//
// The directory is then prepended to PATH so exec.Command("<name>", ...)
// in the wrapper resolves to this script. This lets us verify the args /
// stdin a wrapper builds without needing the real binary installed.
//
// Returns the directory holding the script (for inspection of argv/stdin).
func fakeBin(t *testing.T, name, stdout string, code int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("PATH-override fake binary trick is POSIX-only")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, name)

	// Single-quote stdout so $ and \ stay literal; escape internal '.
	stdoutEscaped := strings.ReplaceAll(stdout, `'`, `'\''`)
	body := "#!/bin/sh\n" +
		`for a in "$@"; do printf "%s\n" "$a"; done > "` + dir + `/argv"` + "\n" +
		`cat > "` + dir + `/stdin"` + "\n" +
		`printf '%s' '` + stdoutEscaped + `'` + "\n" +
		"exit " + strconv.Itoa(code) + "\n"

	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}

	// Prepend TempDir to PATH for the duration of the test.
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

// sleepBin installs a fake binary `name` on PATH that simply sleeps for
// `seconds` then exits cleanly. Used by timeout-style tests where the
// caller wants the wrapper's context deadline to fire before the binary
// is allowed to finish — guaranteed deterministic regardless of host
// CPU load because the sleep duration is always larger than the
// configured wrapper timeout.
//
// IMPORTANT: we use `exec sleep` so the shell *replaces itself* with
// the sleep binary instead of forking it as a child. exec.CommandContext
// in Go sends SIGKILL to the direct child only — if the child is `sh`
// and sleep is its descendant, sleep gets orphaned and exec.Wait blocks
// on the inherited stdout/stderr file descriptors until sleep finishes
// naturally. With `exec sleep`, sleep IS the direct child, so SIGKILL
// terminates it immediately and Wait returns within milliseconds.
func sleepBin(t *testing.T, name string, seconds int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("PATH-override fake binary trick is POSIX-only")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, name)
	body := "#!/bin/sh\nexec sleep " + strconv.Itoa(seconds) + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// assertErrored is the explicit, strict form of "this Run call should
// surface an error somehow". A failing Run can report the failure via:
//
//   - returned `err != nil` (typical path — RunToolCommand.Error
//     propagated up), or
//   - `result.Error != nil` with `err == nil` (some wrappers swallow
//     err and put it in result.Error — see e.g. amass.go pattern).
//
// Either is acceptable; both being nil means the wrapper silently
// pretended the failure didn't happen, which is the bug we're guarding
// against. This helper also enforces an upper bound on Run latency so
// a wrapper that "fails" by hanging instead of returning is caught.
func assertErrored(t *testing.T, err error, res *ToolResult, runDur, maxDur time.Duration) {
	t.Helper()
	if runDur > maxDur {
		t.Fatalf("Run() took %v, exceeds bound %v — wrapper did not honor timeout / cancellation", runDur, maxDur)
	}
	if err != nil {
		return // surfaced via returned error — good
	}
	if res != nil && res.Error != nil {
		return // surfaced via result.Error — also good
	}
	t.Fatalf("expected error from Run() (either returned err or result.Error); got both nil (run took %v)", runDur)
}

// readArgv returns the argv slice captured by fakeBin.
func readArgv(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "argv"))
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

// readStdin returns whatever the wrapper piped into the fake binary.
func readStdin(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "stdin"))
	if err != nil {
		t.Fatalf("read stdin: %v", err)
	}
	return string(b)
}

// hasFlag reports whether `flag` appears in argv.
func hasFlag(argv []string, flag string) bool {
	for _, a := range argv {
		if a == flag {
			return true
		}
	}
	return false
}

// flagValue returns the value immediately following the first occurrence
// of `flag` in argv, or "" if the flag is absent.
func flagValue(argv []string, flag string) string {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

// --- katana tests ----------------------------------------------------

func TestKatana_UsesJSONLFlag(t *testing.T) {
	// Regression test for the v1.x behavior where -json was removed.
	// The wrapper must emit -jsonl, never -json, or katana exits with
	// "flag provided but not defined: -json".
	dir := fakeBin(t, "katana", `{"timestamp":"2026-01-01T00:00:00Z","request":{"endpoint":"https://example.com"}}`, 0)

	tool := NewKatanaTool()
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

func TestKatana_PassesTargetAndSilent(t *testing.T) {
	dir := fakeBin(t, "katana", "", 0)

	tool := NewKatanaTool()
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

func TestKatana_DefaultDepthIsThree(t *testing.T) {
	dir := fakeBin(t, "katana", "", 0)

	tool := NewKatanaTool()
	if _, err := tool.Run(context.Background(), "https://example.com", Options{}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	argv := readArgv(t, dir)
	if got := flagValue(argv, "-d"); got != "3" {
		t.Errorf("default depth = %q, want 3", got)
	}
}

func TestKatana_DepthOverride(t *testing.T) {
	dir := fakeBin(t, "katana", "", 0)

	tool := NewKatanaTool()
	if _, err := tool.Run(context.Background(), "https://example.com", Options{"depth": 7}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	argv := readArgv(t, dir)
	if got := flagValue(argv, "-d"); got != "7" {
		t.Errorf("override depth = %q, want 7", got)
	}
}

func TestKatana_ScopeViolationReturnsError(t *testing.T) {
	// No fake binary installed — scope check must fire BEFORE we try
	// to exec, otherwise scope is decorative.
	scopeDef := &scope.ScopeDefinition{AllowedDomains: []string{"allowed.example"}}
	ctx := WithScope(context.Background(), scopeDef)

	tool := NewKatanaTool()
	_, err := tool.Run(ctx, "evil.com", Options{})
	if err == nil {
		t.Fatal("expected scope violation error, got nil")
	}
	if !strings.Contains(err.Error(), "scope violation") {
		t.Errorf("error should mention scope violation; got: %v", err)
	}
}

func TestKatana_ScopeAllowedTargetRuns(t *testing.T) {
	dir := fakeBin(t, "katana", "", 0)

	scopeDef := &scope.ScopeDefinition{AllowedDomains: []string{"example.com"}}
	ctx := WithScope(context.Background(), scopeDef)

	tool := NewKatanaTool()
	res, err := tool.Run(ctx, "https://example.com/page", Options{})
	if err != nil {
		t.Fatalf("in-scope target failed: %v", err)
	}
	if res.Error != nil {
		t.Errorf("unexpected result.Error: %v", res.Error)
	}

	if !hasFlag(readArgv(t, dir), "-jsonl") {
		t.Error("wrapper did not invoke fake katana for in-scope target")
	}
}

func TestKatana_NonZeroExitSurfacesError(t *testing.T) {
	// katana failing (e.g. unreachable target) must surface as either
	// returned err or result.Error so callers can degrade gracefully.
	fakeBin(t, "katana", "boom\n", 7)

	tool := NewKatanaTool()
	start := time.Now()
	res, err := tool.Run(context.Background(), "https://example.com", Options{})
	assertErrored(t, err, res, time.Since(start), 10*time.Second)
}

func TestKatana_NameIsKatana(t *testing.T) {
	if got := NewKatanaTool().Name(); got != "katana" {
		t.Errorf("Name() = %q, want katana", got)
	}
}

func TestKatana_IsAvailableReflectsPATH(t *testing.T) {
	// When the fake binary is on PATH, IsAvailable() must be true.
	fakeBin(t, "katana", "", 0)
	if !NewKatanaTool().IsAvailable() {
		t.Error("IsAvailable() = false when fake binary is on PATH")
	}
}

func TestKatana_IsAvailableFalseWithoutPATH(t *testing.T) {
	// Empty PATH → katana binary not findable → IsAvailable() must
	// report false so the coordinator can mark the adapter skipped.
	t.Setenv("PATH", "")
	if NewKatanaTool().IsAvailable() {
		t.Error("IsAvailable() = true when PATH is empty (should be false)")
	}
}

func TestKatana_PopulatesRawOutputAndParsedFindings(t *testing.T) {
	// Verify the wrapper plumbs binary stdout into result.RawOutput
	// and that valid JSONL lines are decoded into ParsedFindings via
	// executor.parseJSONLines.
	jsonl := `{"timestamp":"2026-01-01T00:00:00Z","request":{"endpoint":"https://example.com/a"}}` + "\n" +
		`{"timestamp":"2026-01-01T00:00:01Z","request":{"endpoint":"https://example.com/b"}}` + "\n"
	fakeBin(t, "katana", jsonl, 0)

	tool := NewKatanaTool()
	res, err := tool.Run(context.Background(), "https://example.com", Options{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(res.RawOutput, "example.com/a") {
		t.Errorf("RawOutput missing first JSONL line: %q", res.RawOutput)
	}
	if len(res.ParsedFindings) != 2 {
		t.Fatalf("ParsedFindings count = %d, want 2", len(res.ParsedFindings))
	}
	req0, ok := res.ParsedFindings[0]["request"].(map[string]any)
	if !ok {
		t.Fatalf("first finding 'request' field has wrong type: %T", res.ParsedFindings[0]["request"])
	}
	if got := req0["endpoint"]; got != "https://example.com/a" {
		t.Errorf("first finding endpoint = %v, want https://example.com/a", got)
	}
}

func TestKatana_TimeoutOptHonoured(t *testing.T) {
	// Fake binary sleeps 5s; wrapper's `timeout: 1` should fire the
	// context deadline well before that.
	//
	// Bound the entire Run() call to 4s so a wrapper that ignores
	// the deadline (waits the full sleep) is caught by the latency
	// guard inside assertErrored, not by the surrounding go-test
	// `-timeout` (which gives a worse error).
	sleepBin(t, "katana", 5)

	tool := NewKatanaTool()
	start := time.Now()
	res, err := tool.Run(context.Background(), "https://example.com", Options{"timeout": 1})
	assertErrored(t, err, res, time.Since(start), 4*time.Second)
}

func TestKatana_ContextCancelStopsRun(t *testing.T) {
	// Wrapper must propagate context cancellation to the child process
	// and return promptly — long-running tools can't be allowed to
	// outlive their campaign context.
	sleepBin(t, "katana", 10)

	ctx, cancel := context.WithCancel(context.Background())
	cancelTimer := time.AfterFunc(100*time.Millisecond, cancel)
	defer cancelTimer.Stop()

	tool := NewKatanaTool()
	start := time.Now()
	res, err := tool.Run(ctx, "https://example.com", Options{"timeout": 30})
	// Must return within ~1 s of the cancel — gives 900 ms slack on
	// slow CI runners.
	assertErrored(t, err, res, time.Since(start), 1*time.Second)
}

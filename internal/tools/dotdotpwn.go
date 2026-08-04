package tools

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// DotDotPwnTool wraps wireghoul/dotdotpwn
// (https://github.com/wireghoul/dotdotpwn) — a directory-traversal /
// path-traversal fuzzer. It permutes traversal sequences (../, ..\,
// URL/Unicode/double-URL encoded variants) at varying depths against a
// target and reports which ones let it reach a sentinel file
// (/etc/passwd, boot.ini, …) by matching a keyword in the response.
//
// dotdotpwn is a Perl tool with no structured output — it prints
// human-readable progress and marks successful traversals inline with a
// "VULNERABLE" marker, and mirrors that into an optional report file
// (-r). We parse both for the marker and emit one HIGH-severity
// path_traversal finding per confirmed traversal string. Path traversal
// is directly exploitable (arbitrary file read), so unlike the
// signature scanners (nikto/droopescan) these are high, not low.
//
// Plan reference: 2.1.28 (P3) in IMPLEMENTATION_PLAN.md.
type DotDotPwnTool struct{}

// NewDotDotPwnTool constructs the adapter.
func NewDotDotPwnTool() *DotDotPwnTool { return &DotDotPwnTool{} }

// Name implements Tool.
func (d *DotDotPwnTool) Name() string { return "dotdotpwn" }

// IsAvailable checks for `dotdotpwn` on PATH.
func (d *DotDotPwnTool) IsAvailable() bool { return IsCommandAvailable("dotdotpwn") }

// Run executes dotdotpwn against a target host/URL.
//
// Supported options:
//
//	timeout   int    — per-invocation timeout in seconds (default 600).
//	module    string — fuzzing module (-m): "http" (default), "http-url",
//	                    "ftp", "tftp", "payload", "stdout". For "http-url"
//	                    the target URL must contain the literal token
//	                    TRAVERSAL marking the injection point.
//	depth     int     — traversal depth (-d), how many "../" to stack
//	                    (default 6 — dotdotpwn's own default).
//	file      string  — specific sentinel file to reach (-f), e.g.
//	                    "/etc/passwd". Empty uses dotdotpwn's OS-derived list.
//	pattern   string  — keyword that, if present in the response, marks a
//	                    hit (-k), e.g. "root:". Strongly recommended — without
//	                    it dotdotpwn can't confirm success and reports nothing.
//	os_type   string  — force target OS for the sentinel list (-o):
//	                    "unix" or "windows". Empty lets dotdotpwn detect.
//	ssl       bool    — use HTTPS for the http/http-url modules (-S).
//	port      int     — target port (-x). 0 uses the module default.
//	extra     string  — space-separated extra flags passed through verbatim.
func (d *DotDotPwnTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("dotdotpwn", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in dotdotpwn: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 600)) * time.Second

	tmp, err := os.CreateTemp("", "dotdotpwn-*.txt")
	if err != nil {
		return &ToolResult{ToolName: "dotdotpwn", Target: target, Error: err}, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	// -q: quiet — suppresses the banner AND the interactive "press Enter"
	//     prompt that would otherwise hang the process forever in a
	//     non-tty context.
	// -b: break after the first vulnerability found (opt-in via
	//     break_on_first) — otherwise we fuzz the whole space.
	// -C: continue on connection errors instead of aborting the run.
	args := []string{
		"-m", opts.GetString("module", "http"),
		"-h", target,
		"-r", tmpPath,
		"-q",
		"-C",
	}
	if depth := opts.GetInt("depth", 0); depth > 0 {
		args = append(args, "-d", fmt.Sprintf("%d", depth))
	}
	if file := opts.GetString("file", ""); file != "" {
		args = append(args, "-f", file)
	}
	if pattern := opts.GetString("pattern", ""); pattern != "" {
		args = append(args, "-k", pattern)
	}
	if osType := opts.GetString("os_type", ""); osType != "" {
		args = append(args, "-o", osType)
	}
	if opts.GetBool("ssl", false) {
		args = append(args, "-S")
	}
	if port := opts.GetInt("port", 0); port > 0 {
		args = append(args, "-x", fmt.Sprintf("%d", port))
	}
	if opts.GetBool("break_on_first", false) {
		args = append(args, "-b")
	}
	if extra := opts.GetString("extra", ""); extra != "" {
		args = append(args, strings.Fields(extra)...)
	}

	result := RunToolCommand(ctx, "dotdotpwn", target, timeout, "dotdotpwn", args...)
	if result.Error != nil && !strings.Contains(result.Error.Error(), "exit status") {
		return result, result.Error
	}
	// dotdotpwn exits non-zero on some completion paths; the report /
	// stdout is the source of truth, not the exit code.
	result.Error = nil

	body, readErr := os.ReadFile(tmpPath)
	text := result.RawOutput
	if readErr == nil && len(body) > 0 {
		// Parse both — the report file and stdout can each carry markers
		// depending on dotdotpwn version.
		text = string(body) + "\n" + result.RawOutput
	}
	result.ParsedFindings = parseDotDotPwnText(text)
	return result, nil
}

// dotdotpwnHit matches the traversal string on a line dotdotpwn has
// flagged as vulnerable. The tool prints, per attempt, a line like:
//
//	[+] Testing Path: http://host:80/../../../../etc/passwd <- VULNERABLE
//
// We capture the path between "Testing Path:" and the VULNERABLE marker.
var dotdotpwnHit = regexp.MustCompile(`(?i)testing\s+path:\s*(\S+)`)

// parseDotDotPwnText scans dotdotpwn output for the "VULNERABLE" marker
// and emits one HIGH finding per confirmed traversal. Lines without the
// marker (the bulk of the fuzz attempts) are ignored. Empty input → nil.
func parseDotDotPwnText(text string) []map[string]any {
	if text == "" {
		return nil
	}
	var findings []map[string]any
	seen := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(strings.ToUpper(line), "VULNERABLE") {
			continue
		}
		path := ""
		if m := dotdotpwnHit.FindStringSubmatch(line); len(m) == 2 {
			path = m[1]
		} else {
			path = strings.TrimSpace(line)
		}
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		findings = append(findings, map[string]any{
			"tool":     "dotdotpwn",
			"title":    "Path traversal confirmed",
			"category": "path_traversal",
			"severity": "high",
			"path":     path,
		})
	}
	return findings
}

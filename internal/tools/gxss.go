package tools

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// GXSSTool wraps KathanP19/Gxss (https://github.com/KathanP19/Gxss),
// a reflected-XSS pre-screener. Different from dalfox: gxss is a
// *fast filter* that takes a list of URLs (one per line on stdin)
// and prints only the ones where at least one parameter is
// reflected unfiltered into the response. The output is then
// usually piped into dalfox for the heavier confirmation +
// payload-class fuzzing.
//
// We expose it as its own adapter so the swarm can use it as a
// triage step before spending dalfox's longer runtime budget on
// every gau-discovered URL.
//
// Plan reference: 2.1.27 (P2) in IMPLEMENTATION_PLAN.md.
type GXSSTool struct{}

// NewGXSSTool constructs the adapter.
func NewGXSSTool() *GXSSTool { return &GXSSTool{} }

// Name implements Tool.
func (g *GXSSTool) Name() string { return "gxss" }

// IsAvailable checks that `Gxss` (case-sensitive upstream) or `gxss`
// is on PATH. Some package managers lowercase the binary.
func (g *GXSSTool) IsAvailable() bool {
	return IsCommandAvailable("Gxss") || IsCommandAvailable("gxss")
}

// Run executes gxss against a target URL or a list of URLs.
//
// `target` is one URL per invocation. For larger batches the
// `urls` option takes a newline-separated string and is piped into
// gxss via stdin (matches the upstream `cat urls.txt | Gxss`
// usage). When both are set, the stdin list takes precedence — the
// `target` is still scope-validated for the audit log.
//
// Supported options:
//
//	timeout int    — per-invocation timeout in seconds (default 60).
//	urls    string — newline-separated URL list (piped via stdin).
//	threads int    — concurrent workers (-c). Default 50.
//	payload string — custom reflection probe (-p). Default uses
//	                 gxss's built-in marker.
func (g *GXSSTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("gxss", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in gxss: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 60)) * time.Second

	args := []string{"-c", strconv.Itoa(opts.GetInt("threads", 50))}
	if payload := opts.GetString("payload", ""); payload != "" {
		args = append(args, "-p", payload)
	}

	bin := "Gxss"
	if !IsCommandAvailable("Gxss") {
		bin = "gxss"
	}

	stdin := opts.GetString("urls", "")
	if stdin == "" {
		stdin = target + "\n"
	}

	result := RunToolCommandWithStdin(ctx, "gxss", target, stdin, timeout, bin, args...)
	if result.Error != nil {
		return result, result.Error
	}

	result.ParsedFindings = parseGXSSOutput(result.RawOutput)
	return result, nil
}

// parseGXSSOutput converts gxss's stdout (one reflected URL per
// line) into normalized findings. Each line becomes one MEDIUM
// finding — gxss confirms reflection, not exploitability, so the
// agent should pair this with a dalfox follow-up for severity
// promotion to HIGH.
func parseGXSSOutput(output string) []map[string]any {
	var findings []map[string]any
	for _, line := range strings.Split(output, "\n") {
		url := strings.TrimSpace(line)
		if url == "" {
			continue
		}
		findings = append(findings, map[string]any{
			"tool":     "gxss",
			"url":      url,
			"severity": "medium",
			"category": "reflected_input",
			"note":     "Reflection confirmed; pair with dalfox for exploitability.",
		})
	}
	return findings
}

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// DalfoxTool wraps dalfox (https://github.com/hahwul/dalfox) for
// reflected + DOM XSS testing. dalfox parameter-mines a target,
// fuzzes payloads, validates reflections, and (with --deep-domxss)
// drives a headless browser to confirm DOM-based sinks.
//
// We invoke it in `url <target>` mode with --format json so the
// finding array can be re-parsed into ParsedFindings and surface as
// XSS-class findings on the blackboard.
//
// Plan reference: 2.1.9 (P1) in IMPLEMENTATION_PLAN.md.
type DalfoxTool struct{}

// NewDalfoxTool constructs the adapter. No state — every Run is a
// fresh subprocess invocation, gated by scope and time-budget.
func NewDalfoxTool() *DalfoxTool { return &DalfoxTool{} }

// Name implements Tool.
func (d *DalfoxTool) Name() string { return "dalfox" }

// IsAvailable checks that the `dalfox` binary is on PATH. The
// coordinator uses this to skip the tool gracefully on hosts where
// it's not installed (e.g. the Docker image includes it; a bare
// developer laptop may not).
func (d *DalfoxTool) IsAvailable() bool { return IsCommandAvailable("dalfox") }

// Run executes dalfox against a target URL with the given options.
// Supported options (all optional):
//
//	timeout       int  — per-invocation timeout in seconds (default 120)
//	workers       int  — concurrent worker goroutines in dalfox (default 50)
//	deep_dom_xss  bool — enable --deep-domxss (slower, requires headless Chrome)
//	skip_bav      bool — enable --skip-bav (skip basic-app-vuln probes, faster)
//	blind         str  — blind-XSS callback URL (pairs with future interactsh integration)
//	cookie        str  — Cookie header value for authenticated scans
//	headers       []str — custom HTTP headers, "K: V" each
//	custom_payload str — path to custom payload file
//
// Scope is enforced before subprocess spawn — out-of-scope targets
// never reach the binary.
func (d *DalfoxTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("dalfox", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in dalfox: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 120)) * time.Second
	workers := opts.GetInt("workers", 50)

	// dalfox uses --format=json (NOT -json) and --silent (no banner).
	// Worker count caps concurrent fuzzing — 50 is a polite default
	// that still finds reflections quickly without hammering targets
	// behind strict rate limits.
	args := []string{
		"url", target,
		"--format", "json",
		"--silent",
		"--worker", strconv.Itoa(workers),
	}

	if opts.GetBool("deep_dom_xss", false) {
		args = append(args, "--deep-domxss")
	}
	if opts.GetBool("skip_bav", false) {
		args = append(args, "--skip-bav")
	}
	if blind := opts.GetString("blind", ""); blind != "" {
		// -b is the short flag for --blind.
		args = append(args, "-b", blind)
	}
	if cookie := opts.GetString("cookie", ""); cookie != "" {
		args = append(args, "--cookie", cookie)
	}
	for _, h := range opts.GetStringSlice("headers") {
		args = append(args, "-H", h)
	}
	if payload := opts.GetString("custom_payload", ""); payload != "" {
		args = append(args, "--custom-payload", payload)
	}

	result := RunToolCommand(ctx, "dalfox", target, timeout, "dalfox", args...)
	if result.Error != nil {
		return result, result.Error
	}

	// dalfox --format=json emits a single JSON array of finding
	// objects rather than newline-delimited JSON. The executor's
	// generic auto-parse (parseJSONLines) would wrap the whole array
	// as a single `{"raw": ...}` blob, which loses structure. Override
	// with array-aware parsing here.
	result.ParsedFindings = parseDalfoxJSON(result.RawOutput)

	return result, nil
}

// parseDalfoxJSON parses dalfox's --format=json output (a single JSON
// array of finding objects) into the standard ParsedFindings shape.
//
// Returns nil on malformed or non-array input rather than erroring —
// the raw output is always preserved on the ToolResult, so an LLM
// agent can still reason over the unstructured text if structured
// parsing fails. This matches the design philosophy of other adapters
// where parse failure should never block the campaign.
//
// We deliberately don't try to recover from leading log-spam by
// hunting for the first '['; dalfox log lines (`[INFO] ...`) look
// indistinguishable from JSON arrays at the byte level, and the
// heuristic mis-fires more often than it helps. If the output isn't
// a clean JSON array, the raw text route is good enough.
func parseDalfoxJSON(output string) []map[string]any {
	output = strings.TrimSpace(output)
	if output == "" || !strings.HasPrefix(output, "[") {
		return nil
	}

	var findings []map[string]any
	if err := json.Unmarshal([]byte(output), &findings); err != nil {
		return nil
	}
	return findings
}

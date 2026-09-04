package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// NiktoTool wraps sullo/nikto (https://github.com/sullo/nikto) for
// classic web server misconfiguration scanning: dangerous files,
// outdated server software, missing security headers, default
// credentials/paths, and a few thousand other signature checks
// accumulated over two decades.
//
// Nikto predates severity scoring — its JSON output is a flat list
// of findings with no risk rating. We surface every entry at "low"
// severity (informational-scanner default, matching the pattern used
// by droopescan/wpscan) and let the classifier agent promote
// individual findings after correlating against context.
//
// Plan reference: 2.1.15 (P3) in IMPLEMENTATION_PLAN.md.
type NiktoTool struct{}

// NewNiktoTool constructs the adapter.
func NewNiktoTool() *NiktoTool { return &NiktoTool{} }

// Name implements Tool.
func (n *NiktoTool) Name() string { return "nikto" }

// IsAvailable checks for `nikto` on PATH.
func (n *NiktoTool) IsAvailable() bool { return IsCommandAvailable("nikto") }

// Run executes nikto against a target host/URL.
//
// Supported options:
//
//	timeout    int    — per-invocation timeout in seconds (default 600).
//	ssl        bool   — force SSL/TLS (-ssl). Default false — nikto
//	                     auto-detects from the URL scheme when omitted.
//	tuning     string — scan tuning categories (-Tuning), e.g. "1234b".
//	                     Empty means nikto's own default (all).
//	user_agent string — custom UA (-useragent).
//	max_time   string — nikto's own per-host time budget (-maxtime),
//	                     e.g. "10m". Separate from the process timeout
//	                     above, which is a hard kill.
func (n *NiktoTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("nikto", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in nikto: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 600)) * time.Second

	tmp, err := os.CreateTemp("", "nikto-*.json")
	if err != nil {
		return &ToolResult{ToolName: "nikto", Target: target, Error: err}, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	args := []string{
		"-h", target,
		"-Format", "json",
		"-o", tmpPath,
		"-ask", "no",
	}
	if opts.GetBool("ssl", false) {
		args = append(args, "-ssl")
	}
	if tuning := opts.GetString("tuning", ""); tuning != "" {
		args = append(args, "-Tuning", tuning)
	}
	if ua := opts.GetString("user_agent", ""); ua != "" {
		args = append(args, "-useragent", ua)
	}
	if maxTime := opts.GetString("max_time", ""); maxTime != "" {
		args = append(args, "-maxtime", maxTime)
	}

	result := RunToolCommand(ctx, "nikto", target, timeout, "nikto", args...)
	if result.Error != nil && !strings.Contains(result.Error.Error(), "exit status") {
		return result, result.Error
	}
	// nikto returns non-zero on some scan-complete paths; the JSON file
	// on disk is the source of truth, not the process exit code.
	result.Error = nil

	body, readErr := os.ReadFile(tmpPath)
	if readErr != nil || len(body) == 0 {
		body = []byte(result.RawOutput)
	}
	result.ParsedFindings = parseNiktoJSON(body)
	return result, nil
}

// niktoReport mirrors nikto's `-Format json` shape: a single host
// block with a flat `vulnerabilities` array (no per-item severity —
// nikto is a signature-match scanner, not a risk-scored one).
type niktoReport struct {
	Host   string      `json:"host"`
	IP     string      `json:"ip"`
	Port   string      `json:"port"`
	Banner string      `json:"banner,omitempty"`
	Vulns  []niktoVuln `json:"vulnerabilities"`
}

type niktoVuln struct {
	ID         string `json:"id"`
	Method     string `json:"method,omitempty"`
	URL        string `json:"url"`
	Message    string `json:"msg"`
	References string `json:"references,omitempty"`
}

// parseNiktoJSON walks the vulnerabilities array and emits one
// finding per entry. All findings default to "low" severity since
// nikto doesn't rate risk itself.
func parseNiktoJSON(body []byte) []map[string]any {
	if len(body) == 0 {
		return nil
	}
	var doc niktoReport
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var findings []map[string]any
	for _, v := range doc.Vulns {
		findings = append(findings, map[string]any{
			"tool":       "nikto",
			"id":         v.ID,
			"method":     v.Method,
			"url":        v.URL,
			"title":      v.Message,
			"references": v.References,
			"host":       doc.Host,
			"port":       doc.Port,
			"severity":   "low",
		})
	}
	return findings
}

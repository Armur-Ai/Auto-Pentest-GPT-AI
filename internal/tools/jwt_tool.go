package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// JWTTool wraps ticarpi's jwt_tool (https://github.com/ticarpi/jwt_tool)
// for JSON Web Token attack discovery: alg=none confusion, asymmetric→
// symmetric key confusion, weak HMAC secret cracking, key injection
// (jku / x5u / kid), and signature stripping.
//
// jwt_tool ships as a Python script (`jwt_tool.py`); we shell out to
// the wrapper command `jwt_tool` (the recommended install path adds
// a wrapper to PATH). Mode "all-tests" (-M at) runs the playbook the
// project maintains.
//
// Plan reference: 2.1.11 (P1) in IMPLEMENTATION_PLAN.md. Powers the
// auth/session specialization in 5.1.2.
type JWTTool struct{}

// NewJWTTool constructs the adapter. No state — every Run is a fresh
// subprocess invocation, gated by scope and time-budget.
func NewJWTTool() *JWTTool { return &JWTTool{} }

// Name implements Tool. Underscore matches the upstream binary name
// (`jwt_tool`) and the plan's 2.1.11 identifier.
func (j *JWTTool) Name() string { return "jwt_tool" }

// IsAvailable checks that the `jwt_tool` binary is on PATH.
func (j *JWTTool) IsAvailable() bool { return IsCommandAvailable("jwt_tool") }

// Run executes jwt_tool against a target. "target" is interpreted as
// the URL hosting the JWT-authenticated endpoint; the actual JWT to
// attack is passed via opts["token"] (jwt_tool's -t flag).
//
// Supported options (all optional):
//
//	timeout    int    — per-invocation timeout in seconds (default 180)
//	token      string — the JWT to attack (-t). Required for most modes.
//	mode       string — playbook mode (-M). Default "at" (all tests).
//	                    Other useful values: "pb" (playbook), "er" (exploit-recon).
//	wordlist   string — path to a wordlist for HMAC secret cracking (-d).
//	pubkey     string — path to a PEM public key for asymmetric attacks (-pk).
//	cookie     string — cookie value if the JWT lives in a cookie (-rc).
//	header     string — request header name carrying the JWT (-rh).
//
// Scope is enforced before subprocess spawn.
func (j *JWTTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("jwt_tool", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in jwt_tool: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 180)) * time.Second

	// jwt_tool emits a side-effect file (jwttool_*_results.txt) in the
	// current dir per attack mode; we capture stdout instead since the
	// CLI also prints the same findings there with -V (verbose).
	args := []string{"-V", "-M", opts.GetString("mode", "at")}

	if tok := opts.GetString("token", ""); tok != "" {
		args = append(args, "-t", tok)
	}
	args = append(args, target)

	if wl := opts.GetString("wordlist", ""); wl != "" {
		args = append(args, "-d", wl)
	}
	if pk := opts.GetString("pubkey", ""); pk != "" {
		args = append(args, "-pk", pk)
	}
	if cookie := opts.GetString("cookie", ""); cookie != "" {
		args = append(args, "-rc", cookie)
	}
	if hdr := opts.GetString("header", ""); hdr != "" {
		args = append(args, "-rh", hdr)
	}

	result := RunToolCommand(ctx, "jwt_tool", target, timeout, "jwt_tool", args...)
	if result.Error != nil {
		return result, result.Error
	}

	// jwt_tool doesn't emit JSON; surface the structured matches we can
	// find in the verbose plaintext output (vulnerable test name lines
	// look like "[+] <name>: vulnerable" / "(VULN)"). Misses are
	// non-fatal — raw output is always preserved on the result.
	result.ParsedFindings = parseJWTToolOutput(result.RawOutput)

	return result, nil
}

// parseJWTToolOutput scans jwt_tool's verbose plaintext for vulnerability
// markers. Each match becomes a finding with the test name, the line of
// evidence, and a severity bucket (jwt_tool itself doesn't assign one,
// so we default to "high" for clear vuln lines per the project's CVSS
// guidance on JWT auth bypass classes).
//
// Returns nil on no matches — an LLM agent can still reason over the
// raw text via RawOutput.
func parseJWTToolOutput(output string) []map[string]any {
	if strings.TrimSpace(output) == "" {
		return nil
	}

	var findings []map[string]any
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		isVuln := strings.Contains(lower, "(vuln") ||
			strings.Contains(lower, "vulnerable") ||
			strings.HasPrefix(trimmed, "[+]")
		if !isVuln {
			continue
		}
		findings = append(findings, map[string]any{
			"tool":     "jwt_tool",
			"evidence": trimmed,
			"severity": "high",
		})
	}

	return findings
}


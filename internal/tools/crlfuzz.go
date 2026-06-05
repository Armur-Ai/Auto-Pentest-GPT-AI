package tools

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// CRLFuzzTool wraps dwisiswant0/crlfuzz (https://github.com/dwisiswant0/crlfuzz)
// for HTTP header CRLF-injection fuzzing. crlfuzz appends a battery
// of CR/LF / Unicode-encoded variants to the target URL's path /
// query and checks whether the server echoes the injected header,
// reflects a Set-Cookie, or splits the response — all classic
// CRLF-injection indicators that pave the way to XSS, cache
// poisoning, and open redirect.
//
// Plan reference: 2.1.14 (P2) in IMPLEMENTATION_PLAN.md. Pairs with
// 5.11.7 (HTTP protocol quirks).
type CRLFuzzTool struct{}

// NewCRLFuzzTool constructs the adapter.
func NewCRLFuzzTool() *CRLFuzzTool { return &CRLFuzzTool{} }

// Name implements Tool.
func (c *CRLFuzzTool) Name() string { return "crlfuzz" }

// IsAvailable checks that `crlfuzz` is on PATH.
func (c *CRLFuzzTool) IsAvailable() bool { return IsCommandAvailable("crlfuzz") }

// Run executes crlfuzz against a single URL.
//
// Supported options:
//
//	timeout    int    — per-invocation timeout in seconds (default 120).
//	concurrent int    — concurrent workers (-c). Default 25.
//	method     string — HTTP method (-X). Default "GET".
//	cookies    string — Cookie header value (-b).
//	headers    []str  — extra HTTP headers, "K: V" each (-H, repeatable).
//	user_agent string — custom UA (-A).
//	proxy      string — HTTP/SOCKS proxy URL (-x).
//
// crlfuzz prints one matched URL per line to stdout when it finds a
// CRLF echo. It also supports `-o <file>` for explicit output; we
// use the file path because stdout is sometimes interleaved with
// progress lines depending on terminal mode.
func (c *CRLFuzzTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("crlfuzz", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in crlfuzz: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 120)) * time.Second

	tmp, err := os.CreateTemp("", "crlfuzz-*.txt")
	if err != nil {
		return &ToolResult{ToolName: "crlfuzz", Target: target, Error: err}, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	args := []string{
		"-u", target,
		"-o", tmpPath,
		"-c", strconv.Itoa(opts.GetInt("concurrent", 25)),
		"-s", // silent — suppress banner
	}

	if m := opts.GetString("method", ""); m != "" {
		args = append(args, "-X", m)
	}
	if cookies := opts.GetString("cookies", ""); cookies != "" {
		args = append(args, "-b", cookies)
	}
	for _, h := range opts.GetStringSlice("headers") {
		args = append(args, "-H", h)
	}
	if ua := opts.GetString("user_agent", ""); ua != "" {
		args = append(args, "-A", ua)
	}
	if proxy := opts.GetString("proxy", ""); proxy != "" {
		args = append(args, "-x", proxy)
	}

	result := RunToolCommand(ctx, "crlfuzz", target, timeout, "crlfuzz", args...)
	if result.Error != nil {
		return result, result.Error
	}

	body, readErr := os.ReadFile(tmpPath)
	if readErr != nil {
		return result, nil
	}
	result.ParsedFindings = parseCRLFuzzOutput(string(body))

	return result, nil
}

// parseCRLFuzzOutput converts crlfuzz's output file into normalized
// findings. The file is one matched URL per line; each line becomes
// one HIGH-severity finding (CRLF injection is almost always
// directly exploitable for XSS / cache poisoning).
//
// Returns nil for empty / whitespace-only output rather than an
// empty slice — same convention as the other adapters.
func parseCRLFuzzOutput(out string) []map[string]any {
	var findings []map[string]any
	for _, line := range strings.Split(out, "\n") {
		url := strings.TrimSpace(line)
		if url == "" {
			continue
		}
		findings = append(findings, map[string]any{
			"tool":     "crlfuzz",
			"url":      url,
			"severity": "high",
			"category": "crlf_injection",
		})
	}
	return findings
}

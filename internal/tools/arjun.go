package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// ArjunTool wraps s0md3v's Arjun (https://github.com/s0md3v/Arjun)
// for HTTP parameter discovery. Arjun fuzzes a built-in wordlist of
// ~26,000 parameter names against a URL and surfaces those that
// actually influence the response (different content-length, status,
// or reflected value).
//
// Discovered parameters feed the API agent — they're the most common
// way to find IDOR, SSRF, and auth-bypass paths that aren't visible
// from a basic crawl.
//
// Plan reference: 2.1.13 (P1) in IMPLEMENTATION_PLAN.md.
type ArjunTool struct{}

// NewArjunTool constructs the adapter.
func NewArjunTool() *ArjunTool { return &ArjunTool{} }

// Name implements Tool.
func (a *ArjunTool) Name() string { return "arjun" }

// IsAvailable checks that `arjun` is on PATH.
func (a *ArjunTool) IsAvailable() bool { return IsCommandAvailable("arjun") }

// Run executes arjun against a URL.
//
// Supported options:
//
//	timeout    int    — per-invocation timeout in seconds (default 180)
//	method     string — HTTP method (-m). Default "GET". Also useful: POST, JSON, XML.
//	threads    int    — concurrent worker threads (-t). Default 20.
//	stable     bool   — passive mode (-passive). Less noisy, faster.
//	wordlist   string — path to a custom wordlist (-w). Default uses arjun's bundled list.
//	cookies    string — Cookie header value (-c).
//	headers    []str  — extra HTTP headers, each "K: V" (-H).
//	delay      int    — milliseconds between requests (-d). Default 0.
//
// Arjun emits JSON via -oJ <path>. We write to a temp file and read
// it back so the JSON schema is unambiguous (its stdout is mixed
// with progress markers).
func (a *ArjunTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("arjun", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in arjun: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 180)) * time.Second

	// Write findings JSON to a temp file; arjun's -oJ ensures a clean
	// JSON object instead of stdout interleaved with progress dots.
	tmp, err := os.CreateTemp("", "arjun-*.json")
	if err != nil {
		return &ToolResult{
			ToolName: "arjun", Target: target, Error: fmt.Errorf("arjun tempfile: %w", err),
		}, fmt.Errorf("arjun tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	args := []string{
		"-u", target,
		"-oJ", tmpPath,
		"-m", opts.GetString("method", "GET"),
		"-t", strconv.Itoa(opts.GetInt("threads", 20)),
	}

	if opts.GetBool("stable", false) {
		args = append(args, "--passive")
	}
	if wl := opts.GetString("wordlist", ""); wl != "" {
		args = append(args, "-w", wl)
	}
	if cookies := opts.GetString("cookies", ""); cookies != "" {
		args = append(args, "-c", cookies)
	}
	for _, h := range opts.GetStringSlice("headers") {
		args = append(args, "-H", h)
	}
	if delay := opts.GetInt("delay", 0); delay > 0 {
		args = append(args, "-d", strconv.Itoa(delay))
	}

	result := RunToolCommand(ctx, "arjun", target, timeout, "arjun", args...)
	if result.Error != nil {
		return result, result.Error
	}

	// Read the file we asked arjun to write to. Arjun's JSON layout is
	// {"<url>": {"params": ["param1", "param2"], "method": "GET", ...}}
	// so we flatten into one finding per discovered parameter.
	body, readErr := os.ReadFile(tmpPath)
	if readErr != nil {
		// Tool ran but no output file — likely no findings. Not fatal.
		return result, nil
	}
	result.ParsedFindings = parseArjunJSON(body)

	return result, nil
}

// parseArjunJSON walks arjun's output object and flattens it into one
// finding per discovered parameter. Schema (per arjun --help and
// inspection of -oJ output):
//
//	{
//	  "https://target/path": {
//	    "method": "GET",
//	    "params": ["id", "user", "redirect"],
//	    "headers": {},
//	    "stable": true
//	  }
//	}
//
// Returns nil on malformed input — RawOutput is preserved so an agent
// can fall back to the unstructured text.
func parseArjunJSON(body []byte) []map[string]any {
	var doc map[string]struct {
		Method  string            `json:"method"`
		Params  []string          `json:"params"`
		Headers map[string]string `json:"headers"`
		Stable  bool              `json:"stable"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}

	var findings []map[string]any
	for url, entry := range doc {
		for _, p := range entry.Params {
			if p == "" {
				continue
			}
			findings = append(findings, map[string]any{
				"tool":      "arjun",
				"url":       url,
				"parameter": p,
				"method":    entry.Method,
				"stable":    entry.Stable,
			})
		}
	}
	return findings
}

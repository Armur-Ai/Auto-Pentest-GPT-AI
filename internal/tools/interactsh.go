package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// InteractshTool wraps ProjectDiscovery's interactsh-client
// (https://github.com/projectdiscovery/interactsh) to provide
// out-of-band (OOB) interaction capture.
//
// Why this matters: a huge class of vulnerabilities — blind SQLi,
// blind SSRF, blind XSS, blind RCE, OOB DNS exfiltration — only
// confirms when the target makes an outbound request to a server you
// control. interactsh assigns you a unique subdomain on a public OOB
// server, then listens for any DNS/HTTP/SMTP/LDAP interactions to
// that domain. Pair this with a SQLi payload like
// `'; DECLARE @h VARCHAR(80); SET @h='xyz.oast.fun'; EXEC ...`
// and a DNS hit on xyz.oast.fun confirms the injection.
//
// Unlike most adapters this one is **time-window oriented**: the
// model gets to talk to interactsh for `timeout` seconds, then we
// SIGTERM the child and return everything we captured. The assigned
// OOB URL is returned as the first finding so the LLM can drop it
// into payloads; subsequent findings are received interactions.
//
// Plan reference: 2.1.26 (P0) in IMPLEMENTATION_PLAN.md. Powers
// 5.8.1 (OOB infrastructure).
type InteractshTool struct{}

// NewInteractshTool constructs the adapter.
func NewInteractshTool() *InteractshTool { return &InteractshTool{} }

// Name implements Tool. Underscore-free to match the binary name on
// PATH.
func (i *InteractshTool) Name() string { return "interactsh-client" }

// IsAvailable checks that `interactsh-client` is on PATH.
func (i *InteractshTool) IsAvailable() bool { return IsCommandAvailable("interactsh-client") }

// Run starts an interactsh-client session, listens for `timeout`
// seconds, then returns the assigned OOB URL plus any interactions
// received during the listen window.
//
// Note: `target` is informational here — interactsh doesn't probe a
// target itself, it just listens for callbacks. We still pass it
// through scope.ValidateAndLog so the audit log records what
// engagement this OOB session is associated with.
//
// Supported options:
//
//	timeout int    — listen window in seconds (default 30). The model
//	                 should request as long a window as the surrounding
//	                 attack step needs for the callback to fire.
//	server  string — custom interactsh server (-server). Default uses
//	                 the public oast.fun pool. Set to your own
//	                 self-hosted server for OPSEC.
//	token   string — auth token for a private interactsh server (-token).
func (i *InteractshTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("interactsh-client", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in interactsh-client: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 30)) * time.Second
	start := time.Now()

	args := []string{"-json", "-poll-interval", "1", "-no-color"}
	if server := opts.GetString("server", ""); server != "" {
		args = append(args, "-server", server)
	}
	if token := opts.GetString("token", ""); token != "" {
		args = append(args, "-token", token)
	}

	// Use a dedicated context so we can SIGTERM cleanly when the
	// listen window expires. interactsh-client exits with code 130
	// (SIGINT) when interrupted; that's expected, not an error.
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "interactsh-client", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	result := &ToolResult{
		ToolName:  "interactsh-client",
		Target:    target,
		RawOutput: stdout.String(),
		Duration:  time.Since(start),
	}

	// A timeout-driven exit is the *normal* termination path here —
	// we asked the client to listen for N seconds, the context
	// cancelled, the process exited with signal. Don't surface that
	// as an error. Anything else is a real failure.
	if runErr != nil && !errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			result.Error = fmt.Errorf("interactsh-client: %w (stderr: %s)", runErr, truncateLog(stderr.String(), 256))
			return result, result.Error
		}
		// ExitError with a signal because the deadline cancelled the
		// process is expected; tolerate it.
	}

	url := parseInteractshURL(stderr.String())
	interactions := parseInteractshInteractions(stdout.String())

	result.ParsedFindings = make([]map[string]any, 0, len(interactions)+1)
	if url != "" {
		result.ParsedFindings = append(result.ParsedFindings, map[string]any{
			"tool":         "interactsh-client",
			"type":         "payload",
			"oob_url":      url,
			"listen_secs":  int(timeout.Seconds()),
			"instructions": "Embed " + url + " in payloads (DNS/HTTP/SMTP/LDAP) targeting the asset under test. Any inbound interaction to this URL during the listen window will be surfaced as a separate finding.",
		})
	}
	for _, ix := range interactions {
		result.ParsedFindings = append(result.ParsedFindings, ix)
	}

	return result, nil
}

// urlPattern matches the assigned OOB URL that interactsh-client
// prints to stderr on startup. The current upstream format is
// `[INF] Listing 1 payload for OOB Testing` followed by the
// subdomain on its own line; some versions print
// `[INF] xxxxx.oast.fun` directly. We accept either by extracting
// the first DNS-shaped token.
var urlPattern = regexp.MustCompile(`\b([a-z0-9]{16,}\.[a-z0-9.-]+\.[a-z]{2,})\b`)

// parseInteractshURL pulls the assigned subdomain out of the
// stderr banner. Returns empty string if not found — RawOutput
// still has the full text so an LLM agent can recover.
func parseInteractshURL(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		if m := urlPattern.FindStringSubmatch(line); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

// parseInteractshInteractions parses the JSONL interaction stream
// printed on stdout. The shape per upstream:
//
//	{
//	  "protocol": "http",
//	  "unique-id": "xxxxx",
//	  "full-id": "xxxxx.oast.fun",
//	  "raw-request": "...",
//	  "remote-address": "1.2.3.4",
//	  "timestamp": "2026-06-05T..."
//	}
//
// We surface a small subset (protocol, source IP, URL, timestamp)
// as a finding; the raw request body is kept in metadata for
// agents that want to verify the payload echoed back.
func parseInteractshInteractions(stdout string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var ix map[string]any
		if err := json.Unmarshal([]byte(line), &ix); err != nil {
			continue
		}
		// Skip non-interaction objects (some versions emit a
		// startup banner as JSON). Real interactions always have
		// `full-id` or `unique-id`.
		if _, ok := ix["full-id"]; !ok {
			if _, ok := ix["unique-id"]; !ok {
				continue
			}
		}
		out = append(out, map[string]any{
			"tool":           "interactsh-client",
			"type":           "interaction",
			"protocol":       ix["protocol"],
			"remote_address": ix["remote-address"],
			"oob_url":        ix["full-id"],
			"timestamp":      ix["timestamp"],
			"raw_request":    ix["raw-request"],
			"raw_response":   ix["raw-response"],
		})
	}
	return out
}

// truncateLog caps a stderr log dump so a runaway tool doesn't blow
// up error logs. Belongs in this file because the package's other
// shared truncate helper lives in osint/ — duplicating one tiny
// function is cheaper than carving out a new shared package.
func truncateLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…(" + strconv.Itoa(len(s)) + " bytes total)"
}

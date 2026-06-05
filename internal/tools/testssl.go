package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// TestSSLTool wraps testssl.sh (https://github.com/drwetter/testssl.sh)
// for deep TLS posture audits. testssl.sh probes the target's TLS
// configuration for ~30 weakness classes: weak ciphers (RC4, 3DES,
// EXPORT), known protocol attacks (BEAST, CRIME, POODLE, ROBOT,
// LUCKY13, SWEET32, Heartbleed), weak cert chains (SHA-1, MD5),
// expired certs, weak DH params, etc.
//
// Different from a port scanner: testssl.sh negotiates a full TLS
// handshake for each cipher / protocol it tests, so it's slower
// (~2-5 minutes for a single host) but produces far more
// vulnerability-class-mapped findings than nmap's ssl-enum-ciphers.
//
// Plan reference: 2.1.10 (P2) in IMPLEMENTATION_PLAN.md. Pairs with
// 5.18 (crypto/TLS specialization).
type TestSSLTool struct{}

// NewTestSSLTool constructs the adapter. The binary is usually named
// `testssl.sh` upstream but Debian/Homebrew ship it as `testssl`;
// the Tool advertises the latter for portability.
func NewTestSSLTool() *TestSSLTool { return &TestSSLTool{} }

// Name implements Tool. Underscore-free, matches the 2.1.10 plan id
// and the Homebrew/Debian package binary.
func (t *TestSSLTool) Name() string { return "testssl" }

// IsAvailable checks for either `testssl` or `testssl.sh` on PATH.
// Different distros use different conventions; we want both to work
// without forcing a wrapper script.
func (t *TestSSLTool) IsAvailable() bool {
	return IsCommandAvailable("testssl") || IsCommandAvailable("testssl.sh")
}

// Run executes testssl against a target host:port (default 443 if no
// port given). Always asks for JSON output via --jsonfile so parsing
// is unambiguous; raw stdout still gets preserved on the result.
//
// Supported options:
//
//	timeout    int    — per-invocation timeout in seconds (default 600).
//	                    testssl is slow; default is 10 minutes.
//	severity   string — minimum severity to report (--severity).
//	                    Default "LOW". Other values: "MEDIUM", "HIGH",
//	                    "CRITICAL".
//	mode       string — quick-scan flag (--fast / --quick) or full
//	                    audit (""). Default "" runs the full battery.
//	starttls   string — protocol-specific STARTTLS upgrade (smtp,
//	                    imap, pop3, ldap, ftp, mysql, pgsql).
func (t *TestSSLTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("testssl", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in testssl: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 600)) * time.Second

	tmp, err := os.CreateTemp("", "testssl-*.json")
	if err != nil {
		return &ToolResult{ToolName: "testssl", Target: target, Error: err}, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	args := []string{
		"--jsonfile", tmpPath,
		"--severity", opts.GetString("severity", "LOW"),
		"--color", "0",  // suppress ANSI escapes in stdout
		"--warnings", "off",
	}

	if mode := opts.GetString("mode", ""); mode == "fast" || mode == "quick" {
		args = append(args, "--"+mode)
	}
	if starttls := opts.GetString("starttls", ""); starttls != "" {
		args = append(args, "--starttls", starttls)
	}
	args = append(args, target)

	// Pick the binary name dynamically — IsAvailable already accepts
	// either form, so honour whichever we find.
	bin := "testssl"
	if !IsCommandAvailable("testssl") {
		bin = "testssl.sh"
	}

	result := RunToolCommand(ctx, "testssl", target, timeout, bin, args...)
	if result.Error != nil {
		return result, result.Error
	}

	body, readErr := os.ReadFile(tmpPath)
	if readErr != nil {
		return result, nil
	}
	result.ParsedFindings = parseTestSSLJSON(body)

	return result, nil
}

// parseTestSSLJSON converts testssl --jsonfile output into normalized
// findings. testssl emits a flat array of:
//
//	{"id": "BEAST", "ip": "1.2.3.4/443", "port": "443", "severity": "MEDIUM", "finding": "vulnerable, ..."}
//
// We pass each test as a finding while keeping testssl's own
// severity bucket; the classifier agent can re-score later if it
// disagrees with testssl's defaults.
//
// Only entries with severity HIGH / MEDIUM / LOW / WARN survive;
// INFO / OK entries (the bulk of the output) are dropped to keep
// the finding stream signal-heavy.
func parseTestSSLJSON(body []byte) []map[string]any {
	var arr []map[string]any
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil
	}
	var out []map[string]any
	for _, entry := range arr {
		sev, _ := entry["severity"].(string)
		switch sev {
		case "HIGH", "MEDIUM", "LOW", "WARN", "CRITICAL":
			// drop through
		default:
			continue
		}
		out = append(out, map[string]any{
			"tool":     "testssl",
			"id":       entry["id"],
			"severity": sev,
			"finding":  entry["finding"],
			"ip":       entry["ip"],
			"port":     entry["port"],
		})
	}
	return out
}


package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// CrackMapExecTool wraps crackmapexec / its maintained successor NetExec
// (nxc) — a multi-protocol post-exploitation and enumeration swiss-army
// knife covering SMB, LDAP, MSSQL, SSH, WinRM, RDP and FTP. It is the
// go-to for spraying credentials across an internal subnet, checking
// SMB signing / SMBv1, enumerating shares/users/sessions, and flagging
// admin ("Pwn3d!") access.
//
// This is an INTERNAL-SCOPE tool: it authenticates against hosts and is
// only appropriate for programs whose scope explicitly authorises
// internal network testing. Scope validation still gates the target.
//
// crackmapexec is EOL upstream; the project continued as NetExec with a
// compatible CLI. We resolve to whichever binary is present (preferring
// `crackmapexec`, falling back to `nxc`/`netexec`) so the adapter works
// on either install.
//
// crackmapexec has no first-class per-run JSON export, so we parse its
// line-oriented stdout: each line is
//
//	<PROTO>  <host>  <port>  <name>  [marker] <message>
//
// where [+] = successful auth, [*] = host info, [-] = failure. We emit
// findings for valid credentials (HIGH if "Pwn3d!"), disabled SMB
// signing, and SMBv1 exposure.
//
// Plan reference: 2.1.18 (P3) in IMPLEMENTATION_PLAN.md.
type CrackMapExecTool struct{}

// NewCrackMapExecTool constructs the adapter.
func NewCrackMapExecTool() *CrackMapExecTool { return &CrackMapExecTool{} }

// Name implements Tool.
func (c *CrackMapExecTool) Name() string { return "crackmapexec" }

// IsAvailable reports true when any compatible binary is on PATH.
func (c *CrackMapExecTool) IsAvailable() bool { return c.resolveBinary() != "" }

// resolveBinary returns the first available compatible binary name, or
// "" if none are installed.
func (c *CrackMapExecTool) resolveBinary() string {
	for _, name := range []string{"crackmapexec", "nxc", "netexec"} {
		if IsCommandAvailable(name) {
			return name
		}
	}
	return ""
}

// Run executes crackmapexec/nxc against a target host or CIDR.
//
// Supported options:
//
//	timeout    int    — per-invocation timeout in seconds (default 600).
//	protocol   string — smb (default), ldap, mssql, ssh, winrm, rdp, ftp.
//	username   string — auth username (-u).
//	password   string — auth password (-p).
//	hash       string — NTLM hash for pass-the-hash (-H). Use instead of password.
//	domain     string — auth domain (-d).
//	local_auth bool   — treat credentials as local, not domain (--local-auth).
//	shares     bool   — enumerate shares (--shares).
//	users      bool   — enumerate domain users (--users).
//	sessions   bool   — enumerate active sessions (--sessions).
//	extra      string — space-separated extra flags passed through verbatim.
func (c *CrackMapExecTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("crackmapexec", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in crackmapexec: %w", err)
		}
	}

	bin := c.resolveBinary()
	if bin == "" {
		bin = "crackmapexec" // best effort; RunToolCommand will report the exec error
	}

	timeout := time.Duration(opts.GetInt("timeout", 600)) * time.Second

	args := []string{opts.GetString("protocol", "smb"), target}
	if u := opts.GetString("username", ""); u != "" {
		args = append(args, "-u", u)
	}
	if h := opts.GetString("hash", ""); h != "" {
		args = append(args, "-H", h)
	} else if p := opts.GetString("password", ""); p != "" {
		args = append(args, "-p", p)
	}
	if dom := opts.GetString("domain", ""); dom != "" {
		args = append(args, "-d", dom)
	}
	if opts.GetBool("local_auth", false) {
		args = append(args, "--local-auth")
	}
	if opts.GetBool("shares", false) {
		args = append(args, "--shares")
	}
	if opts.GetBool("users", false) {
		args = append(args, "--users")
	}
	if opts.GetBool("sessions", false) {
		args = append(args, "--sessions")
	}
	if extra := opts.GetString("extra", ""); extra != "" {
		args = append(args, strings.Fields(extra)...)
	}

	result := RunToolCommand(ctx, "crackmapexec", target, timeout, bin, args...)
	if result.Error != nil && !strings.Contains(result.Error.Error(), "exit status") {
		return result, result.Error
	}
	// Non-zero exit is common (auth failures, unreachable hosts); the
	// stdout lines are the source of truth.
	result.Error = nil

	result.ParsedFindings = parseCrackMapExecText(result.RawOutput)
	return result, nil
}

// parseCrackMapExecText walks crackmapexec's line-oriented output and
// emits findings for the security-relevant markers. Progress/info lines
// with no security signal are skipped. Empty input → nil.
func parseCrackMapExecText(output string) []map[string]any {
	if output == "" {
		return nil
	}
	var findings []map[string]any
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := fields[0]
		host := fields[1]
		port := fields[2]
		name := fields[3]
		msg := strings.Join(fields[4:], " ")

		switch {
		case strings.HasPrefix(msg, "[+]"):
			// Successful authentication. "(Pwn3d!)" means admin access.
			sev := "medium"
			category := "valid_credentials"
			title := "Valid credentials accepted"
			if strings.Contains(msg, "Pwn3d!") {
				sev = "high"
				category = "admin_access"
				title = "Administrative access confirmed"
			}
			findings = append(findings, map[string]any{
				"tool":     "crackmapexec",
				"title":    title,
				"category": category,
				"severity": sev,
				"protocol": proto,
				"host":     host,
				"port":     port,
				"name":     name,
				"evidence": strings.TrimSpace(strings.TrimPrefix(msg, "[+]")),
			})
		}

		// Info lines can still carry misconfigurations regardless of marker.
		if strings.Contains(msg, "signing:False") {
			findings = append(findings, map[string]any{
				"tool":     "crackmapexec",
				"title":    "SMB signing disabled",
				"category": "smb_signing_disabled",
				"severity": "medium",
				"protocol": proto,
				"host":     host,
				"port":     port,
				"name":     name,
				"evidence": strings.TrimSpace(msg),
			})
		}
		if strings.Contains(msg, "SMBv1:True") {
			findings = append(findings, map[string]any{
				"tool":     "crackmapexec",
				"title":    "SMBv1 enabled",
				"category": "smbv1_enabled",
				"severity": "medium",
				"protocol": proto,
				"host":     host,
				"port":     port,
				"name":     name,
				"evidence": strings.TrimSpace(msg),
			})
		}
	}
	return findings
}

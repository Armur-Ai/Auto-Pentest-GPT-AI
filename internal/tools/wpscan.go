package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// WPScanTool wraps wpscanteam/wpscan (https://wpscan.com/wordpress-security-scanner)
// for WordPress-specific vulnerability surface enumeration: core
// version + known CVEs, vulnerable themes/plugins, exposed users,
// weak readme/changelog disclosures, exposed wp-config backups, etc.
//
// Gating note: the recon agent should fingerprint the target as
// WordPress (via wappalyzer / httpx tech detection) *before*
// invoking this adapter. Running wpscan against a non-WP target
// just burns API quota for no signal.
//
// Plan reference: 2.1.16 (P2) in IMPLEMENTATION_PLAN.md.
type WPScanTool struct{}

// NewWPScanTool constructs the adapter.
func NewWPScanTool() *WPScanTool { return &WPScanTool{} }

// Name implements Tool.
func (w *WPScanTool) Name() string { return "wpscan" }

// IsAvailable checks that `wpscan` is on PATH.
func (w *WPScanTool) IsAvailable() bool { return IsCommandAvailable("wpscan") }

// Run executes wpscan against a WordPress URL.
//
// Supported options:
//
//	timeout      int    — per-invocation timeout in seconds (default 300).
//	api_token    string — wpscan.com API token (--api-token). Required for
//	                      vulnerability data on themes/plugins/core. Free
//	                      tier: 25 lookups/day. Without it, scan still
//	                      runs but no CVE matches are surfaced.
//	enumerate    string — comma-separated list of what to enumerate (-e).
//	                      Default "vp,vt,u" (vulnerable plugins, vulnerable
//	                      themes, users). Other useful values: "ap" (all
//	                      plugins), "at" (all themes), "tt" (timthumbs),
//	                      "cb" (config backups), "dbe" (db exports), "m"
//	                      (media), "u1-10" (user IDs 1..10).
//	stealthy     bool   — pass --stealthy (slower, harder to fingerprint).
//	user_agent   string — custom UA (--user-agent).
//	disable_tls  bool   — pass --disable-tls-checks (use only for
//	                      self-signed staging environments).
func (w *WPScanTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("wpscan", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in wpscan: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 300)) * time.Second

	tmp, err := os.CreateTemp("", "wpscan-*.json")
	if err != nil {
		return &ToolResult{ToolName: "wpscan", Target: target, Error: err}, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	args := []string{
		"--url", target,
		"--format", "json",
		"--output", tmpPath,
		"--no-banner",
		"-e", opts.GetString("enumerate", "vp,vt,u"),
	}
	if tok := opts.GetString("api_token", ""); tok != "" {
		args = append(args, "--api-token", tok)
	}
	if opts.GetBool("stealthy", false) {
		args = append(args, "--stealthy")
	}
	if ua := opts.GetString("user_agent", ""); ua != "" {
		args = append(args, "--user-agent", ua)
	}
	if opts.GetBool("disable_tls", false) {
		args = append(args, "--disable-tls-checks")
	}

	result := RunToolCommand(ctx, "wpscan", target, timeout, "wpscan", args...)
	if result.Error != nil {
		return result, result.Error
	}

	body, readErr := os.ReadFile(tmpPath)
	if readErr != nil {
		return result, nil
	}
	result.ParsedFindings = parseWPScanJSON(body)

	return result, nil
}

// wpScanReport is the trimmed shape we consume. wpscan's JSON is
// large and nested; we only walk the slots most likely to contain
// actionable findings. RawOutput preserves the full report for
// agents that want richer detail.
type wpScanReport struct {
	Version       *wpScanVersion           `json:"version,omitempty"`
	MainTheme     *wpScanThemeOrPlugin     `json:"main_theme,omitempty"`
	Plugins       map[string]wpScanThemeOrPlugin `json:"plugins,omitempty"`
	Themes        map[string]wpScanThemeOrPlugin `json:"themes,omitempty"`
	Users         map[string]any           `json:"users,omitempty"`
	ConfigBackups map[string]any           `json:"config_backups,omitempty"`
}

type wpScanVersion struct {
	Number          string         `json:"number"`
	Status          string         `json:"status"`
	Vulnerabilities []wpScanVuln   `json:"vulnerabilities,omitempty"`
}

type wpScanThemeOrPlugin struct {
	Slug            string       `json:"slug"`
	Version         *wpScanVersion `json:"version,omitempty"`
	LatestVersion   string       `json:"latest_version,omitempty"`
	Vulnerabilities []wpScanVuln `json:"vulnerabilities,omitempty"`
}

type wpScanVuln struct {
	Title      string   `json:"title"`
	FixedIn    string   `json:"fixed_in,omitempty"`
	References struct {
		CVE []string `json:"cve,omitempty"`
		URL []string `json:"url,omitempty"`
	} `json:"references,omitempty"`
}

// parseWPScanJSON walks the report and emits one finding per CVE
// across core / theme / plugin slots, plus a single finding for
// "users discovered" and "config backups exposed" when those slots
// are non-empty (those are LOW-severity disclosure issues but worth
// surfacing for the LLM to chain).
func parseWPScanJSON(body []byte) []map[string]any {
	var doc wpScanReport
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var findings []map[string]any

	emit := func(component, slug, title string, refs []string, cves []string, fixedIn string) {
		findings = append(findings, map[string]any{
			"tool":      "wpscan",
			"component": component, // "core", "theme", "plugin"
			"slug":      slug,
			"title":     title,
			"severity":  "high", // wpscan reports are pre-filtered to known vulns
			"cves":      cves,
			"references": refs,
			"fixed_in":  fixedIn,
		})
	}

	if doc.Version != nil {
		for _, v := range doc.Version.Vulnerabilities {
			emit("core", "wordpress", v.Title, v.References.URL, v.References.CVE, v.FixedIn)
		}
	}
	for slug, p := range doc.Plugins {
		for _, v := range p.Vulnerabilities {
			emit("plugin", slug, v.Title, v.References.URL, v.References.CVE, v.FixedIn)
		}
	}
	for slug, t := range doc.Themes {
		for _, v := range t.Vulnerabilities {
			emit("theme", slug, v.Title, v.References.URL, v.References.CVE, v.FixedIn)
		}
	}
	if doc.MainTheme != nil {
		for _, v := range doc.MainTheme.Vulnerabilities {
			emit("theme", doc.MainTheme.Slug, v.Title, v.References.URL, v.References.CVE, v.FixedIn)
		}
	}
	if len(doc.Users) > 0 {
		users := make([]string, 0, len(doc.Users))
		for u := range doc.Users {
			users = append(users, u)
		}
		findings = append(findings, map[string]any{
			"tool":      "wpscan",
			"component": "users",
			"title":     "WordPress users enumerated",
			"severity":  "low",
			"users":     users,
		})
	}
	if len(doc.ConfigBackups) > 0 {
		findings = append(findings, map[string]any{
			"tool":      "wpscan",
			"component": "config_backups",
			"title":     "wp-config backup(s) exposed",
			"severity":  "high",
		})
	}
	return findings
}

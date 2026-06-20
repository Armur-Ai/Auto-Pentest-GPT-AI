package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// DroopescanTool wraps SamJoan/droopescan (https://github.com/SamJoan/droopescan)
// for non-WordPress CMS enumeration: Drupal, SilverStripe, Joomla,
// Moodle, and a handful of less-common targets. Functionally mirrors
// wpscan's role but for the rest of the CMS surface.
//
// Where wpscan ships rich vulnerability data via the wpscan.com
// catalogue, droopescan focuses on *enumeration* — version
// fingerprinting, theme/plugin detection, sensitive-file
// discovery. CVE matching is left to the classifier agent's
// follow-up step against the NVD cache.
//
// Plan reference: 2.1.17 (P2) in IMPLEMENTATION_PLAN.md.
type DroopescanTool struct{}

// NewDroopescanTool constructs the adapter.
func NewDroopescanTool() *DroopescanTool { return &DroopescanTool{} }

// Name implements Tool.
func (d *DroopescanTool) Name() string { return "droopescan" }

// IsAvailable checks for `droopescan` on PATH.
func (d *DroopescanTool) IsAvailable() bool { return IsCommandAvailable("droopescan") }

// Run executes droopescan against a CMS-hosting URL.
//
// Supported options:
//
//	timeout int    — per-invocation timeout in seconds (default 300).
//	cms     string — CMS to scan (-t / --cms). Default "drupal".
//	                 Valid: drupal, silverstripe, joomla, moodle.
//	threads int    — request threads (-n / --number-of-threads).
//	                 Default 4 — droopescan is polite by default.
//	enumerate string — what to enumerate (-e). Default "a" (all:
//	                   version + plugins + themes + sensitive paths).
//	                   Other useful: "p" (plugins only), "t" (themes
//	                   only), "v" (version only), "i" (interesting
//	                   urls only).
//	user_agent string — custom UA (--user-agent).
func (d *DroopescanTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("droopescan", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in droopescan: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 300)) * time.Second

	args := []string{
		"scan", opts.GetString("cms", "drupal"),
		"-u", target,
		"-e", opts.GetString("enumerate", "a"),
		"--output", "json",
	}

	if threads := opts.GetInt("threads", 0); threads > 0 {
		args = append(args, "-n", fmt.Sprintf("%d", threads))
	}
	if ua := opts.GetString("user_agent", ""); ua != "" {
		args = append(args, "--user-agent", ua)
	}

	result := RunToolCommand(ctx, "droopescan", target, timeout, "droopescan", args...)
	if result.Error != nil {
		return result, result.Error
	}

	result.ParsedFindings = parseDroopescanJSON(result.RawOutput)
	return result, nil
}

// droopescanReport mirrors droopescan's --output json shape. The
// `host` block wraps everything; per-CMS keys (plugins/themes/
// version/interesting urls) are stored as maps with `is_finding`
// markers.
type droopescanReport struct {
	Host    string                 `json:"host"`
	CMS     string                 `json:"cms,omitempty"`
	Version droopescanVersionInfo  `json:"version,omitempty"`
	Plugins droopescanFindingGroup `json:"plugins,omitempty"`
	Themes  droopescanFindingGroup `json:"themes,omitempty"`
	Interesting droopescanFindingGroup `json:"interesting urls,omitempty"`
}

type droopescanVersionInfo struct {
	Version string `json:"version,omitempty"`
}

type droopescanFindingGroup struct {
	Finding []droopescanFinding `json:"finding,omitempty"`
}

type droopescanFinding struct {
	URL  string `json:"url,omitempty"`
	Name string `json:"name,omitempty"`
}

// parseDroopescanJSON walks the report and emits one finding per
// plugin / theme / interesting url, plus a "version" finding when
// the CMS version was identified (useful for the classifier to
// chain against NVD).
//
// Severity defaults to "low" — droopescan enumerates rather than
// confirming exploitable vulnerabilities. The classifier promotes
// to higher severity when it correlates a discovered plugin/version
// against known CVEs.
func parseDroopescanJSON(output string) []map[string]any {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}
	var doc droopescanReport
	if err := json.Unmarshal([]byte(output), &doc); err != nil {
		return nil
	}
	var findings []map[string]any

	if doc.Version.Version != "" {
		findings = append(findings, map[string]any{
			"tool":      "droopescan",
			"cms":       doc.CMS,
			"title":     "CMS version identified",
			"severity":  "info",
			"value":     doc.Version.Version,
		})
	}
	emit := func(category string, group droopescanFindingGroup) {
		for _, f := range group.Finding {
			name := f.Name
			if name == "" {
				name = f.URL
			}
			findings = append(findings, map[string]any{
				"tool":     "droopescan",
				"cms":      doc.CMS,
				"category": category,
				"name":     name,
				"url":      f.URL,
				"severity": "low",
			})
		}
	}
	emit("plugin", doc.Plugins)
	emit("theme", doc.Themes)
	emit("interesting_url", doc.Interesting)

	return findings
}

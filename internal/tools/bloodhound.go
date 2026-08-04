package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// BloodHoundTool wraps Active Directory attack-path collection. The
// canonical collectors are SharpHound (the .NET collector run from a
// domain-joined Windows host) and bloodhound-python / bloodhound.py (the
// cross-platform collector that runs from Linux over LDAP+SMB). Both
// emit the same JSON object schema — an array of objects each carrying a
// "Properties" bag — so a single parser serves output from either.
//
// The swarm typically runs off-host on Linux, so the adapter drives
// `bloodhound-python`. The full graph analysis (shortest path to Domain
// Admin, etc.) lives in the BloodHound GUI / neo4j; here we surface the
// high-signal facts that are readable straight from the collected object
// properties without a graph engine:
//   - AS-REP roastable users   (dontreqpreauth = true)
//   - Kerberoastable users     (hasspn = true)
//   - Unconstrained delegation (unconstraineddelegation = true on a computer)
//
// plus a summary object-count finding.
//
// This is an INTERNAL-SCOPE tool: it authenticates to a domain
// controller and is only appropriate for programs authorising internal
// AD testing. Scope validation gates the target (domain / DC).
//
// Plan reference: 2.1.19 (P3) in IMPLEMENTATION_PLAN.md. Powers 5.15.8.
type BloodHoundTool struct{}

// NewBloodHoundTool constructs the adapter.
func NewBloodHoundTool() *BloodHoundTool { return &BloodHoundTool{} }

// Name implements Tool.
func (b *BloodHoundTool) Name() string { return "bloodhound" }

// IsAvailable checks for the `bloodhound-python` collector on PATH.
func (b *BloodHoundTool) IsAvailable() bool { return IsCommandAvailable("bloodhound-python") }

// Run drives the bloodhound-python collector against a domain. `target`
// is the AD domain (e.g. "corp.local"); the domain controller is given
// via the `dc` option (or resolved from the domain if omitted).
//
// Supported options:
//
//	timeout    int    — per-invocation timeout in seconds (default 900).
//	username   string — domain username (-u). Required for collection.
//	password   string — domain password (-p).
//	hash       string — NTLM hash for pass-the-hash (--hashes). Use instead of password.
//	dc         string — domain controller host (-dc).
//	nameserver string — DNS server to use (-ns), usually the DC.
//	collect    string — collection methods (-c), default "All".
//	ldaps      bool    — use LDAPS instead of LDAP (-ldaps).
func (b *BloodHoundTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("bloodhound", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in bloodhound: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 900)) * time.Second

	outDir, err := os.MkdirTemp("", "bloodhound-")
	if err != nil {
		return &ToolResult{ToolName: "bloodhound", Target: target, Error: err}, err
	}
	defer os.RemoveAll(outDir)
	prefix := filepath.Join(outDir, "bh")

	args := []string{
		"-d", target,
		"-c", opts.GetString("collect", "All"),
		"--outputprefix", prefix,
	}
	if u := opts.GetString("username", ""); u != "" {
		args = append(args, "-u", u)
	}
	if h := opts.GetString("hash", ""); h != "" {
		args = append(args, "--hashes", h)
	} else if p := opts.GetString("password", ""); p != "" {
		args = append(args, "-p", p)
	}
	if dc := opts.GetString("dc", ""); dc != "" {
		args = append(args, "-dc", dc)
	}
	if ns := opts.GetString("nameserver", ""); ns != "" {
		args = append(args, "-ns", ns)
	}
	if opts.GetBool("ldaps", false) {
		args = append(args, "-ldaps")
	}

	result := RunToolCommand(ctx, "bloodhound", target, timeout, "bloodhound-python", args...)
	if result.Error != nil && !strings.Contains(result.Error.Error(), "exit status") {
		return result, result.Error
	}
	result.Error = nil

	result.ParsedFindings = collectBloodHoundFindings(outDir)
	return result, nil
}

// collectBloodHoundFindings reads the *_users.json / *_computers.json
// files the collector wrote into dir and aggregates the high-signal
// findings. Missing files are simply skipped.
func collectBloodHoundFindings(dir string) []map[string]any {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var findings []map[string]any
	for _, e := range entries {
		name := e.Name()
		var body []byte
		switch {
		case strings.HasSuffix(name, "_users.json"):
			if body, err = os.ReadFile(filepath.Join(dir, name)); err == nil {
				findings = append(findings, parseBloodHoundUsers(body)...)
			}
		case strings.HasSuffix(name, "_computers.json"):
			if body, err = os.ReadFile(filepath.Join(dir, name)); err == nil {
				findings = append(findings, parseBloodHoundComputers(body)...)
			}
		}
	}
	return findings
}

// bloodhoundDoc mirrors the shared SharpHound / bloodhound-python file
// shape: a top-level "data" array of objects, each with a "Properties"
// bag and a "meta" block carrying the object count.
type bloodhoundDoc struct {
	Data []struct {
		Properties bloodhoundProps `json:"Properties"`
	} `json:"data"`
	Meta struct {
		Count int    `json:"count"`
		Type  string `json:"type"`
	} `json:"meta"`
}

type bloodhoundProps struct {
	Name                    string `json:"name"`
	DontReqPreAuth          bool   `json:"dontreqpreauth"`
	HasSPN                  bool   `json:"hasspn"`
	UnconstrainedDelegation bool   `json:"unconstraineddelegation"`
	Enabled                 bool   `json:"enabled"`
}

// parseBloodHoundUsers emits AS-REP-roastable and Kerberoastable
// findings from a collected users file, plus a summary count. Empty /
// malformed input → nil.
func parseBloodHoundUsers(body []byte) []map[string]any {
	if len(body) == 0 {
		return nil
	}
	var doc bloodhoundDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var findings []map[string]any
	for _, obj := range doc.Data {
		p := obj.Properties
		if p.DontReqPreAuth {
			findings = append(findings, map[string]any{
				"tool":     "bloodhound",
				"title":    "AS-REP roastable user (Kerberos pre-auth disabled)",
				"category": "asrep_roasting",
				"severity": "high",
				"user":     p.Name,
			})
		}
		if p.HasSPN {
			findings = append(findings, map[string]any{
				"tool":     "bloodhound",
				"title":    "Kerberoastable user (service principal name set)",
				"category": "kerberoasting",
				"severity": "high",
				"user":     p.Name,
			})
		}
	}
	findings = append(findings, map[string]any{
		"tool":     "bloodhound",
		"title":    "Collected AD users",
		"category": "ad_enumeration",
		"severity": "info",
		"count":    len(doc.Data),
	})
	return findings
}

// parseBloodHoundComputers emits unconstrained-delegation findings from a
// collected computers file, plus a summary count. Empty / malformed
// input → nil.
func parseBloodHoundComputers(body []byte) []map[string]any {
	if len(body) == 0 {
		return nil
	}
	var doc bloodhoundDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var findings []map[string]any
	for _, obj := range doc.Data {
		p := obj.Properties
		if p.UnconstrainedDelegation {
			findings = append(findings, map[string]any{
				"tool":     "bloodhound",
				"title":    "Computer with unconstrained delegation",
				"category": "unconstrained_delegation",
				"severity": "high",
				"computer": p.Name,
			})
		}
	}
	findings = append(findings, map[string]any{
		"tool":     "bloodhound",
		"title":    "Collected AD computers",
		"category": "ad_enumeration",
		"severity": "info",
		"count":    len(doc.Data),
	})
	return findings
}

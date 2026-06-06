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

// ProwlerTool wraps prowler-cloud/prowler (https://github.com/prowler-cloud/prowler)
// for AWS misconfig auditing. prowler runs hundreds of CIS / FedRAMP /
// HIPAA / SOC2 / NIST checks across an AWS account and emits one
// finding per failed check with severity, region, resource ARN, and
// remediation guidance.
//
// Different from web adapters: `target` here is the AWS account ID
// (12 digits) or an arbitrary label — the actual auth surface is the
// AWS credential chain (env vars, profile, IAM role, etc.) that
// prowler picks up automatically.
//
// Plan reference: 2.1.22 (P2) in IMPLEMENTATION_PLAN.md. Pairs with
// 5.6 (cloud specialization).
type ProwlerTool struct{}

// NewProwlerTool constructs the adapter.
func NewProwlerTool() *ProwlerTool { return &ProwlerTool{} }

// Name implements Tool.
func (p *ProwlerTool) Name() string { return "prowler" }

// IsAvailable checks for the `prowler` binary on PATH. v3+ ships as
// a pip-installable CLI; legacy v2 shipped as a bash script with the
// same name, so detection works for both.
func (p *ProwlerTool) IsAvailable() bool { return IsCommandAvailable("prowler") }

// Run executes prowler. `target` is an AWS account id or label for
// the audit log; auth credentials come from the AWS environment.
//
// Supported options:
//
//	timeout       int    — per-invocation timeout in seconds (default 1800;
//	                       prowler is slow, often 15-30 min on large accounts).
//	provider      string — cloud provider (aws|gcp|azure|kubernetes).
//	                       Default "aws".
//	profile       string — named AWS profile (--profile).
//	region        string — restrict to one region (--region).
//	severity_min  string — minimum severity to report (--severity).
//	                       Valid: critical, high, medium, low, informational.
//	checks        string — comma-separated check ids to run (--check).
//	services      string — comma-separated services to scan (--service).
//	compliance    string — compliance framework (--compliance), e.g. cis_3.0_aws.
func (p *ProwlerTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("prowler", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in prowler: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 1800)) * time.Second

	// prowler v3 writes to --output-directory; the JSON file lands as
	// `<dir>/prowler-output-<account>-<timestamp>.ocsf.json` (OCSF
	// schema). Locking the dir lets us find the file deterministically.
	tmpDir, err := os.MkdirTemp("", "prowler-*")
	if err != nil {
		return &ToolResult{ToolName: "prowler", Target: target, Error: err}, err
	}
	defer os.RemoveAll(tmpDir)

	provider := opts.GetString("provider", "aws")
	args := []string{
		provider,
		"--output-directory", tmpDir,
		"--output-formats", "json-ocsf",
		"--no-banner",
	}
	if profile := opts.GetString("profile", ""); profile != "" {
		args = append(args, "--profile", profile)
	}
	if region := opts.GetString("region", ""); region != "" {
		args = append(args, "--region", region)
	}
	if sev := opts.GetString("severity_min", ""); sev != "" {
		args = append(args, "--severity", sev)
	}
	if checks := opts.GetString("checks", ""); checks != "" {
		args = append(args, "--check", checks)
	}
	if services := opts.GetString("services", ""); services != "" {
		args = append(args, "--service", services)
	}
	if compl := opts.GetString("compliance", ""); compl != "" {
		args = append(args, "--compliance", compl)
	}

	result := RunToolCommand(ctx, "prowler", target, timeout, "prowler", args...)
	if result.Error != nil && !strings.Contains(result.Error.Error(), "exit status") {
		return result, result.Error
	}
	// prowler exits non-zero when findings exist; that's not an error
	// for us, just signal to parse.
	result.Error = nil

	// Find the JSON output file in the temp dir.
	matches, _ := filepath.Glob(filepath.Join(tmpDir, "*.ocsf.json"))
	if len(matches) == 0 {
		// Fall back to any .json file in case prowler's naming
		// changes between versions.
		matches, _ = filepath.Glob(filepath.Join(tmpDir, "*.json"))
	}
	if len(matches) == 0 {
		return result, nil
	}

	body, readErr := os.ReadFile(matches[0])
	if readErr != nil {
		return result, nil
	}
	result.ParsedFindings = parseProwlerJSON(body)
	return result, nil
}

// prowlerOCSF mirrors the slice of the OCSF (Open Cybersecurity
// Schema Framework) output we care about. prowler emits one OCSF
// "detection_finding" event per check; we surface only failed ones.
type prowlerOCSF struct {
	StatusCode  int    `json:"status_code"`   // 1=PASS, 2=FAIL, 3=MANUAL, 4=SKIPPED
	StatusDetail string `json:"status_detail"` // "FAIL" / "PASS" / ...
	Severity     string `json:"severity"`     // "Critical" / "High" / ...
	Message      string `json:"message"`
	Resources    []struct {
		UID    string `json:"uid"`
		Type   string `json:"type"`
		Region string `json:"region"`
	} `json:"resources"`
	Metadata struct {
		EventCode string `json:"event_code"` // the check id, e.g. "iam_user_no_setup_initial_access_key"
	} `json:"metadata"`
	Remediation struct {
		Desc string `json:"desc"`
	} `json:"remediation"`
}

// parseProwlerJSON handles prowler's OCSF output (newer versions) and
// surfaces one finding per FAIL detection. Each finding carries the
// check_id, severity, message, first resource UID/region, and the
// remediation hint.
func parseProwlerJSON(body []byte) []map[string]any {
	var arr []prowlerOCSF
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil
	}
	var findings []map[string]any
	for _, e := range arr {
		// FAIL is status_detail "FAIL" or status_code 2.
		if !strings.EqualFold(e.StatusDetail, "FAIL") && e.StatusCode != 2 {
			continue
		}
		f := map[string]any{
			"tool":        "prowler",
			"check_id":    e.Metadata.EventCode,
			"severity":    strings.ToLower(e.Severity),
			"title":       e.Message,
			"remediation": e.Remediation.Desc,
		}
		if len(e.Resources) > 0 {
			f["resource_uid"] = e.Resources[0].UID
			f["region"] = e.Resources[0].Region
			f["resource_type"] = e.Resources[0].Type
		}
		findings = append(findings, f)
	}
	return findings
}

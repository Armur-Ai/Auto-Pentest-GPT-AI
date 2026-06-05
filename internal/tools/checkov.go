package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// CheckovTool wraps bridgecrewio/checkov (https://github.com/bridgecrewio/checkov)
// for Infrastructure-as-Code scanning. checkov walks a directory tree
// looking for Terraform, CloudFormation, Kubernetes, Helm,
// Dockerfile, Serverless, and ARM templates, then runs ~1000 built-in
// policy checks against them — missing encryption, public S3 buckets,
// over-permissive IAM, exposed secrets, etc.
//
// Unlike most adapters in this package, `target` here is a **filesystem
// path** (the directory holding the IaC source), not a URL. Scope
// validation still runs against it because we log the audit trail
// uniformly.
//
// Plan reference: 2.1.25 (P2) in IMPLEMENTATION_PLAN.md.
type CheckovTool struct{}

// NewCheckovTool constructs the adapter.
func NewCheckovTool() *CheckovTool { return &CheckovTool{} }

// Name implements Tool.
func (c *CheckovTool) Name() string { return "checkov" }

// IsAvailable checks that `checkov` is on PATH (typically a pip
// install).
func (c *CheckovTool) IsAvailable() bool { return IsCommandAvailable("checkov") }

// Run executes checkov against a directory path.
//
// Supported options:
//
//	timeout    int    — per-invocation timeout in seconds (default 300).
//	framework  string — restrict to one framework (-f). Valid values:
//	                    terraform, cloudformation, kubernetes, helm,
//	                    dockerfile, serverless, arm, secrets, all
//	                    (default: all).
//	skip_check string — comma-separated check IDs to skip (--skip-check).
//	soft_fail  bool   — return exit 0 even on findings (--soft-fail).
//	                    Default true here because the swarm doesn't
//	                    want a non-zero exit to abort the chain.
func (c *CheckovTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		// target is a filesystem path; ValidateAndLog accepts it as
		// a string for audit-trail purposes. The scope guard only
		// rejects when the value looks like a domain/CIDR outside
		// the allowed set; bare paths pass through.
		if err := scope.ValidateAndLog("checkov", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in checkov: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 300)) * time.Second

	args := []string{
		"-d", target,
		"-o", "json",
		"--quiet",
	}
	if fw := opts.GetString("framework", ""); fw != "" {
		args = append(args, "-f", fw)
	}
	if skip := opts.GetString("skip_check", ""); skip != "" {
		args = append(args, "--skip-check", skip)
	}
	if opts.GetBool("soft_fail", true) {
		args = append(args, "--soft-fail")
	}

	result := RunToolCommand(ctx, "checkov", target, timeout, "checkov", args...)
	if result.Error != nil && !strings.Contains(result.Error.Error(), "exit status") {
		// Non-exit errors (binary missing, context cancel) are real.
		// Exit codes from a successful soft-fail run are not.
		return result, result.Error
	}
	// Reset the exit-code-as-error since we requested --soft-fail.
	result.Error = nil

	result.ParsedFindings = parseCheckovJSON(result.RawOutput)
	return result, nil
}

// checkovReport is the trimmed shape we walk. checkov emits an
// object per framework with `failed_checks` and `passed_checks`;
// we only care about failed. Multiple frameworks in one run come
// back as an array of these objects.
type checkovReport struct {
	CheckType string         `json:"check_type"` // "terraform", "cloudformation", etc.
	Results   checkovResults `json:"results"`
}

type checkovResults struct {
	FailedChecks []checkovCheck `json:"failed_checks"`
}

type checkovCheck struct {
	CheckID      string `json:"check_id"`
	BCCheckID    string `json:"bc_check_id,omitempty"`
	CheckName    string `json:"check_name"`
	CheckResult  struct {
		Result string `json:"result"`
	} `json:"check_result"`
	FilePath     string   `json:"file_path"`
	FileLineRange [2]int  `json:"file_line_range"`
	Resource     string   `json:"resource"`
	Severity     string   `json:"severity,omitempty"` // "CRITICAL", "HIGH", "MEDIUM", "LOW"; sometimes omitted
	Guideline    string   `json:"guideline,omitempty"`
}

// parseCheckovJSON handles both shapes checkov emits:
//   - single-framework run: one top-level object
//   - multi-framework run:  array of those objects
//
// Each failed check becomes one finding. Severity falls back to
// "medium" when checkov omits it (many community checks don't ship
// a severity).
func parseCheckovJSON(output string) []map[string]any {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil
	}

	var single checkovReport
	var multi []checkovReport

	if strings.HasPrefix(output, "[") {
		if err := json.Unmarshal([]byte(output), &multi); err != nil {
			return nil
		}
	} else {
		if err := json.Unmarshal([]byte(output), &single); err != nil {
			return nil
		}
		multi = []checkovReport{single}
	}

	var findings []map[string]any
	for _, report := range multi {
		for _, chk := range report.Results.FailedChecks {
			sev := strings.ToLower(chk.Severity)
			if sev == "" {
				sev = "medium"
			}
			findings = append(findings, map[string]any{
				"tool":       "checkov",
				"framework":  report.CheckType,
				"check_id":   chk.CheckID,
				"title":      chk.CheckName,
				"severity":   sev,
				"file_path":  chk.FilePath,
				"line_start": chk.FileLineRange[0],
				"line_end":   chk.FileLineRange[1],
				"resource":   chk.Resource,
				"guideline":  chk.Guideline,
			})
		}
	}
	return findings
}

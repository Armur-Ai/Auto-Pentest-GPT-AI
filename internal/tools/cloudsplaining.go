package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// CloudsplainingTool wraps salesforce/cloudsplaining
// (https://github.com/salesforce/cloudsplaining) for AWS IAM policy
// analysis. cloudsplaining identifies over-permissive IAM policies
// (privilege escalation paths, data exfiltration grants, resource
// exposure) — the surface where most cloud-pentest engagements
// actually find their P0 finding.
//
// Two-step usage upstream: `cloudsplaining download` pulls all IAM
// policies from the account into a JSON file, then `cloudsplaining
// scan` analyzes that file. We collapse both into one Run by
// passing `target` as either a path to an existing input file
// (uses scan directly) or as the literal "download" to do both
// steps in sequence.
//
// Plan reference: 2.1.24 (P2) in IMPLEMENTATION_PLAN.md.
type CloudsplainingTool struct{}

// NewCloudsplainingTool constructs the adapter.
func NewCloudsplainingTool() *CloudsplainingTool { return &CloudsplainingTool{} }

// Name implements Tool.
func (c *CloudsplainingTool) Name() string { return "cloudsplaining" }

// IsAvailable checks for the binary on PATH.
func (c *CloudsplainingTool) IsAvailable() bool { return IsCommandAvailable("cloudsplaining") }

// Run executes cloudsplaining scan. `target` is either:
//   - a path to an existing IAM policy JSON (output of an earlier
//     `cloudsplaining download`), or
//   - the literal string "download" — adapter does download+scan
//     in one Run, using the current AWS credential chain.
//
// Supported options:
//
//	timeout int    — per-invocation timeout in seconds (default 300).
//	profile string — AWS profile (--profile, only used in download mode).
//	include_aws_managed bool — pass --include-aws-managed-policies
//	                           (scan AWS-managed too, not just customer).
func (c *CloudsplainingTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("cloudsplaining", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in cloudsplaining: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 300)) * time.Second

	tmpDir, err := os.MkdirTemp("", "cloudsplaining-*")
	if err != nil {
		return &ToolResult{ToolName: "cloudsplaining", Target: target, Error: err}, err
	}
	defer os.RemoveAll(tmpDir)

	inputFile := target
	if target == "download" {
		downloadOut := filepath.Join(tmpDir, "iam-policies.json")
		dlArgs := []string{"download", "--output", downloadOut}
		if profile := opts.GetString("profile", ""); profile != "" {
			dlArgs = append(dlArgs, "--profile", profile)
		}
		dlResult := RunToolCommand(ctx, "cloudsplaining", target, timeout, "cloudsplaining", dlArgs...)
		if dlResult.Error != nil {
			return dlResult, dlResult.Error
		}
		inputFile = downloadOut
	}

	scanArgs := []string{
		"scan",
		"--input-file", inputFile,
		"--output", tmpDir,
	}
	if opts.GetBool("include_aws_managed", false) {
		scanArgs = append(scanArgs, "--include-aws-managed-policies")
	}

	result := RunToolCommand(ctx, "cloudsplaining", target, timeout, "cloudsplaining", scanArgs...)
	if result.Error != nil {
		return result, result.Error
	}

	// cloudsplaining writes `iam-results.json` (and an HTML report)
	// to --output. Find and parse it.
	matches, _ := filepath.Glob(filepath.Join(tmpDir, "*.json"))
	for _, path := range matches {
		// Skip the input file we just consumed.
		if path == inputFile {
			continue
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		result.ParsedFindings = parseCloudsplainingJSON(body)
		break
	}

	return result, nil
}

// cloudsplainingReport mirrors the slice of cloudsplaining's JSON we
// surface. The full report has many fields; we extract the four risk
// categories the docs frame as actionable.
type cloudsplainingReport struct {
	Results map[string]cloudsplainingPolicyResult `json:"results"`
}

type cloudsplainingPolicyResult struct {
	PolicyName            string   `json:"PolicyName"`
	PolicyType            string   `json:"PolicyType"` // "AWS" | "Customer"
	PrivilegeEscalation   []map[string]any `json:"PrivilegeEscalation,omitempty"`
	DataExfiltration      []string `json:"DataExfiltration,omitempty"`
	ResourceExposure      []string `json:"ResourceExposure,omitempty"`
	CredentialsExposure   []string `json:"CredentialsExposure,omitempty"`
	InfrastructureModification []string `json:"InfrastructureModification,omitempty"`
}

// parseCloudsplainingJSON walks the per-policy results and emits one
// finding per non-empty risk category. Categories map to fixed
// severities per the cloudsplaining docs' guidance.
func parseCloudsplainingJSON(body []byte) []map[string]any {
	var doc cloudsplainingReport
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var findings []map[string]any
	emit := func(policyName, category, severity string, items []string, raw []map[string]any) {
		if len(items) == 0 && len(raw) == 0 {
			return
		}
		f := map[string]any{
			"tool":        "cloudsplaining",
			"policy":      policyName,
			"category":    category,
			"severity":    severity,
		}
		if len(items) > 0 {
			f["actions"] = items
		}
		if len(raw) > 0 {
			f["details"] = raw
		}
		findings = append(findings, f)
	}
	for _, p := range doc.Results {
		emit(p.PolicyName, "privilege_escalation", "high", nil, p.PrivilegeEscalation)
		emit(p.PolicyName, "data_exfiltration", "high", p.DataExfiltration, nil)
		emit(p.PolicyName, "resource_exposure", "high", p.ResourceExposure, nil)
		emit(p.PolicyName, "credentials_exposure", "critical", p.CredentialsExposure, nil)
		emit(p.PolicyName, "infrastructure_modification", "medium", p.InfrastructureModification, nil)
	}
	return findings
}


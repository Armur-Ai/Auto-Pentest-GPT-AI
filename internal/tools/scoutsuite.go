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

// ScoutSuiteTool wraps nccgroup/ScoutSuite (https://github.com/nccgroup/ScoutSuite)
// for multi-cloud security posture review (AWS, Azure, GCP, AliCloud,
// Oracle Cloud, Kubernetes). scout walks the cloud account's
// configuration and flags misconfigurations (overly-permissive
// security groups, public storage buckets, weak IAM, unencrypted
// volumes, etc.) — overlaps with prowler on AWS but covers more
// providers and emits a different shape of report.
//
// Plan reference: 2.1.23 (P2) in IMPLEMENTATION_PLAN.md.
type ScoutSuiteTool struct{}

// NewScoutSuiteTool constructs the adapter.
func NewScoutSuiteTool() *ScoutSuiteTool { return &ScoutSuiteTool{} }

// Name implements Tool.
func (s *ScoutSuiteTool) Name() string { return "scoutsuite" }

// IsAvailable checks that `scout` is on PATH (pip install scoutsuite
// installs a `scout` entry point, not `scoutsuite`).
func (s *ScoutSuiteTool) IsAvailable() bool { return IsCommandAvailable("scout") }

// Run executes scout against a cloud provider. `target` is the
// cloud account label (used for audit log); auth comes from the
// provider-specific credential chain (AWS env / profile, Azure CLI
// login, gcloud login, etc).
//
// Supported options:
//
//	timeout  int    — per-invocation timeout in seconds (default 1800).
//	provider string — cloud provider (aws|azure|gcp|aliyun|oci|kubernetes).
//	                  Default "aws".
//	profile  string — AWS profile (--profile, AWS only).
//	regions  string — comma-separated regions (--regions, AWS).
//	services string — comma-separated services to include (--services).
func (s *ScoutSuiteTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("scoutsuite", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in scoutsuite: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 1800)) * time.Second
	provider := opts.GetString("provider", "aws")

	tmpDir, err := os.MkdirTemp("", "scoutsuite-*")
	if err != nil {
		return &ToolResult{ToolName: "scoutsuite", Target: target, Error: err}, err
	}
	defer os.RemoveAll(tmpDir)

	args := []string{
		provider,
		"--report-dir", tmpDir,
		"--no-browser",
		"--force",
	}
	if profile := opts.GetString("profile", ""); profile != "" && provider == "aws" {
		args = append(args, "--profile", profile)
	}
	if regions := opts.GetString("regions", ""); regions != "" {
		args = append(args, "--regions", regions)
	}
	if services := opts.GetString("services", ""); services != "" {
		args = append(args, "--services", services)
	}

	result := RunToolCommand(ctx, "scoutsuite", target, timeout, "scout", args...)
	if result.Error != nil && !strings.Contains(result.Error.Error(), "exit status") {
		return result, result.Error
	}
	result.Error = nil

	// scout writes the report as a JS file:
	// `<dir>/scoutsuite-results/scoutsuite_results_<provider>-<account>.js`
	// The file body is `scoutsuite_results = { ... }` — i.e. JSON
	// wrapped in a JS assignment. parseScoutSuiteJS strips the
	// assignment prefix and decodes the JSON.
	pattern := filepath.Join(tmpDir, "scoutsuite-results", "scoutsuite_results_*.js")
	matches, _ := filepath.Glob(pattern)
	if len(matches) == 0 {
		return result, nil
	}

	body, readErr := os.ReadFile(matches[0])
	if readErr != nil {
		return result, nil
	}
	result.ParsedFindings = parseScoutSuiteJS(body, provider)
	return result, nil
}

// scoutResults mirrors the slice of scout's JSON we walk. Scout's
// schema is provider-flavored: each service (s3, iam, ec2, …) has its
// own `findings` map keyed by check name, with each check value
// carrying `description`, `level` (warning|danger), and `flagged_items`.
type scoutResults struct {
	Services map[string]struct {
		Findings map[string]scoutFinding `json:"findings"`
	} `json:"services"`
}

type scoutFinding struct {
	Description  string   `json:"description"`
	Level        string   `json:"level"`
	FlaggedItems []string `json:"flagged_items"`
}

// parseScoutSuiteJS strips scout's JS-assignment wrapper and parses
// the embedded JSON. Each non-empty `findings` entry per service
// becomes one structured finding tagged with the service + check
// name + severity (warning → medium, danger → high).
func parseScoutSuiteJS(body []byte, provider string) []map[string]any {
	// File starts with `scoutsuite_results =` then a JSON object.
	text := string(body)
	idx := strings.Index(text, "=")
	if idx == -1 {
		return nil
	}
	jsonPart := strings.TrimSpace(text[idx+1:])
	jsonPart = strings.TrimSuffix(jsonPart, ";")

	var doc scoutResults
	if err := json.Unmarshal([]byte(jsonPart), &doc); err != nil {
		return nil
	}

	var findings []map[string]any
	for svc, svcData := range doc.Services {
		for checkName, chk := range svcData.Findings {
			if len(chk.FlaggedItems) == 0 {
				continue // check ran but found nothing
			}
			sev := "medium"
			if chk.Level == "danger" {
				sev = "high"
			}
			findings = append(findings, map[string]any{
				"tool":          "scoutsuite",
				"provider":      provider,
				"service":       svc,
				"check_name":    checkName,
				"title":         chk.Description,
				"severity":      sev,
				"flagged_items": chk.FlaggedItems,
				"flagged_count": len(chk.FlaggedItems),
			})
		}
	}
	return findings
}

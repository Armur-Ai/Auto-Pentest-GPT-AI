package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// PacuTool wraps RhinoSecurityLabs/pacu (https://github.com/RhinoSecurityLabs/pacu)
// for AWS exploitation. Different model from prowler: prowler audits
// for misconfigs (defensive); pacu enumerates + privesc + abuse
// (offensive). Modules cover IAM enumeration / privilege escalation,
// S3 bucket enumeration, Lambda function abuse, EC2 metadata access,
// confused-deputy abuse on assume-role, etc.
//
// pacu is interactive by default (REPL with `run <module>` commands).
// For non-interactive use it accepts `--module-name <name>` and runs
// the named module once. We use that mode exclusively — the swarm
// drives module selection itself.
//
// Plan reference: 2.1.21 (P2) in IMPLEMENTATION_PLAN.md.
type PacuTool struct{}

// NewPacuTool constructs the adapter.
func NewPacuTool() *PacuTool { return &PacuTool{} }

// Name implements Tool.
func (p *PacuTool) Name() string { return "pacu" }

// IsAvailable checks that `pacu` is on PATH (typically a pip install).
func (p *PacuTool) IsAvailable() bool { return IsCommandAvailable("pacu") }

// Run executes a single pacu module. `target` is an AWS account ID
// or session label for the audit log; pacu itself uses AWS
// credentials from the env / profile.
//
// Supported options (most are required for any useful invocation):
//
//	timeout      int    — per-invocation timeout in seconds (default 600).
//	session      string — pacu session name (--session). Default
//	                      "pentestswarm". Sessions persist across runs;
//	                      reuse to share enumeration state between
//	                      modules.
//	module       string — module name (--module-name). REQUIRED.
//	                      Examples: iam__enum_users_roles_policies_groups,
//	                      iam__privesc_scan, s3__bucket_finder,
//	                      ec2__check_termination_protection.
//	module_args  string — module-specific arguments (--module-args).
//	                      Module-dependent; see `pacu --list-modules`.
//	region       string — restrict to one region (--regions).
//	profile      string — AWS profile to use; pacu loads its
//	                      credentials from the standard AWS config.
//
// We surface the raw module output as a single finding — pacu
// modules emit free-form text rich with privilege-escalation chains
// and resource ARNs that the LLM can reason over directly. Strict
// structured parsing per-module would be brittle; the raw blob plus
// scope/safe-mode gating at execution time is the trade-off.
func (p *PacuTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("pacu", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in pacu: %w", err)
		}
	}

	module := opts.GetString("module", "")
	if module == "" {
		return &ToolResult{
			ToolName: "pacu", Target: target,
			Error: fmt.Errorf("pacu requires a module option (e.g. \"iam__enum_users_roles_policies_groups\") — see `pacu --list-modules`"),
		}, fmt.Errorf("pacu module not specified")
	}

	timeout := time.Duration(opts.GetInt("timeout", 600)) * time.Second
	session := opts.GetString("session", "pentestswarm")

	args := []string{
		"--session", session,
		"--module-name", module,
		"--exec",
	}
	if margs := opts.GetString("module_args", ""); margs != "" {
		args = append(args, "--module-args", margs)
	}
	if region := opts.GetString("region", ""); region != "" {
		args = append(args, "--regions", region)
	}

	result := RunToolCommand(ctx, "pacu", target, timeout, "pacu", args...)
	if result.Error != nil {
		return result, result.Error
	}

	result.ParsedFindings = parsePacuOutput(result.RawOutput, module)
	return result, nil
}

// parsePacuOutput emits a single coarse-grained finding wrapping the
// module's text output. Pacu modules vary too much in output shape
// for per-module structured parsing to be tractable in one adapter;
// the LLM consumes the raw text and pulls out the resource ARNs /
// privesc chains itself.
//
// Empty / whitespace-only output → nil so the swarm sees "tool ran
// but found nothing" rather than an empty-but-truthy finding.
func parsePacuOutput(output, module string) []map[string]any {
	if strings.TrimSpace(output) == "" {
		return nil
	}
	return []map[string]any{{
		"tool":      "pacu",
		"module":    module,
		"severity":  "info", // pacu enumerates; severity comes from what the LLM finds in the output
		"raw":       output,
		"category":  "aws_enumeration",
	}}
}

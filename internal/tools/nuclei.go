package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// NucleiTool wraps nuclei for template-based vulnerability scanning.
type NucleiTool struct{}

func NewNucleiTool() *NucleiTool { return &NucleiTool{} }

func (n *NucleiTool) Name() string { return "nuclei" }

func (n *NucleiTool) IsAvailable() bool { return IsCommandAvailable("nuclei") }

func (n *NucleiTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.ValidateAndLog("nuclei", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in nuclei: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 120)) * time.Second

	severity := opts.GetStringSlice("severity")
	if severity == nil {
		severity = []string{"critical", "high", "medium"}
	}

	// Nuclei v3 replaced the legacy `-json` flag with `-jsonl` (JSON-Lines).
	// Passing the old flag makes the binary exit immediately with
	// "flag provided but not defined: -json", killing the IP recon pipeline.
	args := []string{"-u", target, "-jsonl", "-silent", "-severity", strings.Join(severity, ",")}

	result := RunToolCommand(ctx, "nuclei", target, timeout, "nuclei", args...)
	return result, result.Error
}

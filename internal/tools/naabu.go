package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// NaabuTool wraps naabu for port scanning.
type NaabuTool struct{}

func NewNaabuTool() *NaabuTool { return &NaabuTool{} }

func (n *NaabuTool) Name() string { return "naabu" }

func (n *NaabuTool) IsAvailable() bool { return IsCommandAvailable("naabu") }

func (n *NaabuTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.ValidateAndLog("naabu", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in naabu: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 60)) * time.Second

	// Build port flags. naabu accepts either:
	//   -p <list>            (e.g. "80,443" or "100-200")
	//   -top-ports <preset>  (preset values: "full" | "100" | "1000")
	// The previous default of `-p top-1000` was invalid syntax and made
	// naabu exit with FTL "could not read ports: invalid port number: 'top'",
	// which in the IP-only recon path collapsed the whole pipeline.
	args := []string{"-host", target, "-json", "-silent"}
	if explicit := opts.GetString("ports", ""); explicit != "" {
		args = append(args, "-p", explicit)
	} else {
		args = append(args, "-top-ports", opts.GetString("top_ports", "1000"))
	}

	result := RunToolCommand(ctx, "naabu", target, timeout, "naabu", args...)
	return result, result.Error
}

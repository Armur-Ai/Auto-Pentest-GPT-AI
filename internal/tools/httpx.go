package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

type HttpxTool struct{}

func NewHttpxTool() *HttpxTool         { return &HttpxTool{} }
func (h *HttpxTool) Name() string      { return "httpx" }
func (h *HttpxTool) IsAvailable() bool { return IsCommandAvailable("httpx") }

func (h *HttpxTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.ValidateAndLog("httpx", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in httpx: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 30)) * time.Second
	args := []string{"-u", target, "-json", "-tech-detect", "-status-code", "-title", "-server", "-silent"}

	if opts.GetBool("follow_redirects", true) {
		args = append(args, "-follow-redirects")
	}

	result := RunToolCommand(ctx, "httpx", target, timeout, "httpx", args...)
	return result, result.Error
}

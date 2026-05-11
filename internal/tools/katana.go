package tools

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// KatanaTool wraps katana for web crawling and endpoint discovery.
type KatanaTool struct{}

func NewKatanaTool() *KatanaTool { return &KatanaTool{} }

func (k *KatanaTool) Name() string { return "katana" }

func (k *KatanaTool) IsAvailable() bool { return IsCommandAvailable("katana") }

func (k *KatanaTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.ValidateAndLog("katana", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in katana: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 60)) * time.Second
	depth := opts.GetInt("depth", 3)

	args := []string{"-u", target, "-jsonl", "-silent", "-d", strconv.Itoa(depth)}

	result := RunToolCommand(ctx, "katana", target, timeout, "katana", args...)
	return result, result.Error
}

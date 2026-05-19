package prompts

import (
	"fmt"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
)

// NewProviderWithRetry builds the primary LLM provider via llm.NewProvider
// and, if cfg.Fallback is configured, wraps it with RetryProvider so that
// safety-filter refusals get a stricter reframe attempt followed by a
// fallback to a less-restrictive secondary provider.
//
// Drop-in replacement for llm.NewProvider — same signature, returns the
// same Provider interface. When no fallback is configured, returns the
// primary unchanged (no wrapping overhead). Call sites should prefer
// this factory over llm.NewProvider so configured fallbacks "just work"
// without per-call-site wiring.
//
// Lives in this package (not internal/llm) to avoid a circular import
// between llm and agent/prompts.
func NewProviderWithRetry(cfg config.OrchestratorConfig) (llm.Provider, error) {
	primary, err := llm.NewProvider(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.Fallback.Provider == "" {
		return primary, nil
	}

	fallback, err := buildFallback(cfg)
	if err != nil {
		return nil, fmt.Errorf("building fallback provider: %w", err)
	}

	return NewRetryProvider(primary, RetryConfig{
		StrictReframeTemplate: "offsec_system_strict",
		Fallback:              fallback,
		// StrictContext intentionally left empty here — the factory
		// doesn't know the engagement/scope context. The strict template
		// handles empty Context with neutral defaults. Callers that DO
		// have engagement context can construct RetryProvider manually
		// to pass a populated Context, but the common case (refuse a
		// generic offensive prompt) doesn't need it.
	}), nil
}

// NewAgentProviderWithRetry is the per-agent equivalent of
// NewProviderWithRetry. It inherits fallback configuration from the
// orchestrator config — agent-level fallback overrides are not yet
// supported (would be a YAGNI premature surface today).
func NewAgentProviderWithRetry(agentCfg config.AgentModelConfig, orchestratorCfg config.OrchestratorConfig) (llm.Provider, error) {
	primary, err := llm.NewAgentProvider(agentCfg, orchestratorCfg)
	if err != nil {
		return nil, err
	}

	if orchestratorCfg.Fallback.Provider == "" {
		return primary, nil
	}

	fallback, err := buildFallback(orchestratorCfg)
	if err != nil {
		return nil, fmt.Errorf("building fallback provider for agent: %w", err)
	}

	return NewRetryProvider(primary, RetryConfig{
		StrictReframeTemplate: "offsec_system_strict",
		Fallback:              fallback,
	}), nil
}

// buildFallback constructs the fallback Provider from cfg.Fallback,
// reusing the orchestrator's context-window setting since the fallback
// rarely needs its own override.
func buildFallback(cfg config.OrchestratorConfig) (llm.Provider, error) {
	fallbackCfg := config.OrchestratorConfig{
		Provider:      cfg.Fallback.Provider,
		Model:         cfg.Fallback.Model,
		APIKey:        cfg.Fallback.APIKey,
		Endpoint:      cfg.Fallback.Endpoint,
		ContextWindow: cfg.ContextWindow,
	}
	return llm.NewProvider(fallbackCfg)
}

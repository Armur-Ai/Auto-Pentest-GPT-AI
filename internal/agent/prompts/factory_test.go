package prompts

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
)

// TestNewProviderWithRetry_NoFallback — when cfg.Fallback is empty,
// the factory returns the primary provider unchanged (not wrapped).
// Existing single-provider deployments must keep working untouched.
func TestNewProviderWithRetry_NoFallback(t *testing.T) {
	cfg := config.OrchestratorConfig{
		Provider:      "ollama", // doesn't require an API key
		Model:         "llama3:8b",
		Endpoint:      "http://localhost:11434",
		ContextWindow: 32000,
	}

	provider, err := NewProviderWithRetry(cfg)
	if err != nil {
		t.Fatalf("NewProviderWithRetry: %v", err)
	}

	if _, isRetry := provider.(*RetryProvider); isRetry {
		t.Error("expected unwrapped provider when no fallback configured; got RetryProvider")
	}
}

// TestNewProviderWithRetry_WithFallback — when cfg.Fallback is set,
// the factory wraps the primary with RetryProvider. Verifies the
// returned provider is a RetryProvider and that its pass-through
// methods report the primary's model/context-window.
func TestNewProviderWithRetry_WithFallback(t *testing.T) {
	cfg := config.OrchestratorConfig{
		Provider:      "ollama",
		Model:         "llama3:8b",
		Endpoint:      "http://localhost:11434",
		ContextWindow: 32000,
		Fallback: config.FallbackConfig{
			Provider: "lmstudio",
			Model:    "qwen-fallback",
			Endpoint: "http://localhost:1234",
		},
	}

	provider, err := NewProviderWithRetry(cfg)
	if err != nil {
		t.Fatalf("NewProviderWithRetry: %v", err)
	}

	rp, isRetry := provider.(*RetryProvider)
	if !isRetry {
		t.Fatalf("expected *RetryProvider when fallback configured, got %T", provider)
	}

	// Pass-through methods should reflect the PRIMARY, not the fallback.
	if rp.ModelName() != "llama3:8b" {
		t.Errorf("ModelName = %q, want llama3:8b (primary)", rp.ModelName())
	}
	if rp.ContextWindow() != 32000 {
		t.Errorf("ContextWindow = %d, want 32000 (primary)", rp.ContextWindow())
	}

	// The configured strict-reframe template must be the offsec_system_strict
	// shipped in this package (verified indirectly — the config field).
	if rp.config.StrictReframeTemplate != "offsec_system_strict" {
		t.Errorf("StrictReframeTemplate = %q, want offsec_system_strict", rp.config.StrictReframeTemplate)
	}
	if rp.config.Fallback == nil {
		t.Error("Fallback provider should be set on RetryConfig")
	}
}

// TestNewProviderWithRetry_PrimaryError — primary construction failure
// surfaces directly; we never try to build the fallback if primary is broken.
func TestNewProviderWithRetry_PrimaryError(t *testing.T) {
	cfg := config.OrchestratorConfig{
		Provider: "claude",
		// APIKey intentionally empty — Claude factory rejects this.
		Fallback: config.FallbackConfig{
			Provider: "ollama",
			Endpoint: "http://localhost:11434",
		},
	}

	_, err := NewProviderWithRetry(cfg)
	if err == nil {
		t.Fatal("expected error when primary cannot be constructed")
	}
	if !strings.Contains(err.Error(), "api_key") {
		t.Errorf("error should mention api_key requirement: %v", err)
	}
}

// TestNewProviderWithRetry_FallbackError — fallback construction failure
// is wrapped with a "building fallback provider" prefix so operators can
// distinguish it from primary failures in logs.
func TestNewProviderWithRetry_FallbackError(t *testing.T) {
	cfg := config.OrchestratorConfig{
		Provider:      "ollama",
		Model:         "llama3:8b",
		Endpoint:      "http://localhost:11434",
		ContextWindow: 32000,
		Fallback: config.FallbackConfig{
			Provider: "openai", // requires api_key
			Model:    "gpt-4o",
			// APIKey intentionally empty
		},
	}

	_, err := NewProviderWithRetry(cfg)
	if err == nil {
		t.Fatal("expected error when fallback cannot be constructed")
	}
	if !strings.Contains(err.Error(), "building fallback provider") {
		t.Errorf("error should mention 'building fallback provider': %v", err)
	}
}

// TestNewAgentProviderWithRetry — per-agent factory also wraps when
// orchestrator fallback is configured. Agent-level inheritance is
// orchestrator → agent for primary fields; fallback is orchestrator-only.
func TestNewAgentProviderWithRetry(t *testing.T) {
	orchestratorCfg := config.OrchestratorConfig{
		Provider:      "ollama",
		Model:         "llama3:8b",
		Endpoint:      "http://localhost:11434",
		ContextWindow: 32000,
		Fallback: config.FallbackConfig{
			Provider: "lmstudio",
			Model:    "qwen-fallback",
			Endpoint: "http://localhost:1234",
		},
	}
	agentCfg := config.AgentModelConfig{
		// Inherit everything from orchestrator
	}

	provider, err := NewAgentProviderWithRetry(agentCfg, orchestratorCfg)
	if err != nil {
		t.Fatalf("NewAgentProviderWithRetry: %v", err)
	}

	if _, isRetry := provider.(*RetryProvider); !isRetry {
		t.Errorf("expected *RetryProvider when orchestrator has fallback, got %T", provider)
	}
}

// TestNewAgentProviderWithRetry_NoFallback — when orchestrator has no
// fallback, per-agent factory returns the unwrapped primary.
func TestNewAgentProviderWithRetry_NoFallback(t *testing.T) {
	orchestratorCfg := config.OrchestratorConfig{
		Provider:      "ollama",
		Model:         "llama3:8b",
		Endpoint:      "http://localhost:11434",
		ContextWindow: 32000,
	}
	agentCfg := config.AgentModelConfig{}

	provider, err := NewAgentProviderWithRetry(agentCfg, orchestratorCfg)
	if err != nil {
		t.Fatalf("NewAgentProviderWithRetry: %v", err)
	}

	if _, isRetry := provider.(*RetryProvider); isRetry {
		t.Error("expected unwrapped provider when orchestrator has no fallback")
	}
}

// Ensure the returned provider type still implements llm.Provider.
// Compile-time assertion via interface assignment.
var _ llm.Provider = (*RetryProvider)(nil)

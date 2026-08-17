package llm

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
)

// TestOrcaRouterProvider_Defaults verifies the orcarouter factory branch
// wires an OpenAI-wire provider to OrcaRouter's endpoint and pins a fixed
// tool-calling-capable model when none is configured. The swarm's
// orchestrator depends on native function calling, so the default must
// never be an unpinned "auto" pool that could land on a model without
// tool support.
func TestOrcaRouterProvider_Defaults(t *testing.T) {
	p, err := NewProvider(config.OrchestratorConfig{
		Provider: "orcarouter",
		APIKey:   "sk-orca-test",
	})
	if err != nil {
		t.Fatalf("NewProvider(orcarouter): %v", err)
	}

	oai, ok := p.(*OpenAIProvider)
	if !ok {
		t.Fatalf("orcarouter should build an *OpenAIProvider, got %T", p)
	}
	if oai.endpoint != "https://api.orcarouter.ai/v1" {
		t.Errorf("endpoint = %q, want https://api.orcarouter.ai/v1", oai.endpoint)
	}
	if oai.model != "openai/gpt-5.5" {
		t.Errorf("model = %q, want openai/gpt-5.5", oai.model)
	}
	if !oai.SupportsToolUse() {
		t.Error("orcarouter should default to native tool use (swarm depends on it)")
	}
	if p.ContextWindow() <= 0 {
		t.Errorf("context window = %d, want > 0", p.ContextWindow())
	}
}

// TestOrcaRouterProvider_CustomConfig verifies explicit endpoint/model
// values pass straight through to the provider.
func TestOrcaRouterProvider_CustomConfig(t *testing.T) {
	p, err := NewProvider(config.OrchestratorConfig{
		Provider:      "orcarouter",
		APIKey:        "sk-orca-test",
		Endpoint:      "https://proxy.example.com/v1",
		Model:         "anthropic/claude-sonnet-4.6",
		ContextWindow: 100000,
	})
	if err != nil {
		t.Fatalf("NewProvider(orcarouter): %v", err)
	}

	oai := p.(*OpenAIProvider)
	if oai.endpoint != "https://proxy.example.com/v1" {
		t.Errorf("endpoint = %q", oai.endpoint)
	}
	if oai.model != "anthropic/claude-sonnet-4.6" {
		t.Errorf("model = %q", oai.model)
	}
	if oai.contextWindow != 100000 {
		t.Errorf("context window = %d, want 100000", oai.contextWindow)
	}
}

// TestOrcaRouterProvider_RequiresAPIKey verifies the factory fails fast
// with a clear message when no key is configured, and points the user at
// OrcaRouter.
func TestOrcaRouterProvider_RequiresAPIKey(t *testing.T) {
	_, err := NewProvider(config.OrchestratorConfig{
		Provider: "orcarouter",
	})
	if err == nil {
		t.Fatal("expected error when orcarouter has no api_key")
	}
	if !strings.Contains(err.Error(), "api_key") {
		t.Errorf("error should mention api_key: %v", err)
	}
	if !strings.Contains(err.Error(), "orcarouter.ai") {
		t.Errorf("error should point at orcarouter.ai: %v", err)
	}
}

// TestUnknownProvider_ErrorListsOrcaRouter ensures the unknown-provider
// message advertises orcarouter as a valid option.
func TestUnknownProvider_ErrorListsOrcaRouter(t *testing.T) {
	_, err := NewProvider(config.OrchestratorConfig{
		Provider: "nonsense",
		APIKey:   "x",
	})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "orcarouter") {
		t.Errorf("error should list orcarouter as a valid provider: %v", err)
	}
}

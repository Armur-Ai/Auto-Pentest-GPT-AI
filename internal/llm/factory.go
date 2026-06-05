package llm

import (
	"context"
	"fmt"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
)

// NewProvider creates the appropriate LLM provider based on configuration.
func NewProvider(cfg config.OrchestratorConfig) (Provider, error) {
	return newProviderFromParams(cfg.Provider, cfg.APIKey, cfg.Model, cfg.Endpoint, cfg.ContextWindow)
}

// NewAgentProvider creates an LLM provider for a specialist agent.
// If the agent has no provider configured, it inherits from the orchestrator.
// This means with just a Claude API key, ALL agents use Claude — zero Ollama needed.
func NewAgentProvider(agentCfg config.AgentModelConfig, orchestratorCfg config.OrchestratorConfig) (Provider, error) {
	// Inherit from orchestrator if agent provider is not set
	provider := agentCfg.Provider
	if provider == "" {
		provider = orchestratorCfg.Provider
	}

	apiKey := agentCfg.APIKey
	if apiKey == "" {
		apiKey = orchestratorCfg.APIKey
	}

	model := agentCfg.Model
	if model == "" {
		model = orchestratorCfg.Model
	}

	endpoint := agentCfg.Endpoint
	if endpoint == "" {
		endpoint = orchestratorCfg.Endpoint
	}

	contextWindow := orchestratorCfg.ContextWindow
	if contextWindow <= 0 {
		contextWindow = 200000
	}

	return newProviderFromParams(provider, apiKey, model, endpoint, contextWindow)
}

func newProviderFromParams(provider, apiKey, model, endpoint string, contextWindow int) (Provider, error) {
	switch provider {
	case "claude":
		if apiKey == "" {
			return nil, fmt.Errorf("claude provider requires api_key — set PENTESTSWARM_ORCHESTRATOR_API_KEY or orchestrator.api_key in config.yaml")
		}
		return NewClaudeProvider(ClaudeProviderConfig{
			APIKey:        apiKey,
			Model:         model,
			ContextWindow: contextWindow,
		}), nil

	case "ollama":
		if endpoint == "" {
			endpoint = "http://localhost:11434"
		}
		return NewOllamaProvider(OllamaProviderConfig{
			Endpoint:      endpoint,
			Model:         model,
			ContextWindow: contextWindow,
		}), nil

	case "lmstudio":
		if endpoint == "" {
			endpoint = "http://localhost:1234"
		}
		return NewLMStudioProvider(LMStudioProviderConfig{
			Endpoint:      endpoint,
			Model:         model,
			ContextWindow: contextWindow,
		}), nil

	case "openai":
		// Covers OpenAI itself plus any OpenAI-API-compatible provider:
		// Together AI, DeepSeek, Moonshot/Kimi, Groq, etc. Pick via the
		// endpoint base URL; one provider implementation, many vendors.
		if apiKey == "" {
			return nil, fmt.Errorf("openai provider requires api_key — set PENTESTSWARM_ORCHESTRATOR_API_KEY or orchestrator.api_key in config.yaml")
		}
		return NewOpenAIProvider(OpenAIProviderConfig{
			APIKey:        apiKey,
			Endpoint:      endpoint,
			Model:         model,
			ContextWindow: contextWindow,
		}), nil

	case "gemini":
		// Google's first-party Generative Language API.
		// Get a key at https://aistudio.google.com/apikey.
		if apiKey == "" {
			return nil, fmt.Errorf("gemini provider requires api_key — set PENTESTSWARM_ORCHESTRATOR_API_KEY or orchestrator.api_key in config.yaml (get a key at https://aistudio.google.com/apikey)")
		}
		return NewGeminiProvider(GeminiProviderConfig{
			APIKey:        apiKey,
			Endpoint:      endpoint,
			Model:         model,
			ContextWindow: contextWindow,
		}), nil

	default:
		return nil, fmt.Errorf("unknown provider %q — use claude, openai, gemini, ollama, or lmstudio", provider)
	}
}

// ValidateProvider verifies a provider is reachable and meets minimum requirements.
func ValidateProvider(ctx context.Context, p Provider) error {
	if err := p.HealthCheck(ctx); err != nil {
		return fmt.Errorf("provider health check failed: %w", err)
	}

	if p.ContextWindow() < 32000 {
		return fmt.Errorf("provider context window (%d) is below minimum 32,000 tokens", p.ContextWindow())
	}

	return nil
}

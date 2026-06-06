package llm

import "testing"

// TestOllamaSetsNumCtx pins the fix for the silent context-truncation bug:
// the Ollama provider must send options.num_ctx derived from the configured
// context window. Without it, Ollama defaults to 4096 tokens regardless of
// config, truncating large recon tool outputs so the model never sees the
// open ports — recon then collapses to an empty AttackSurface.
func TestOllamaSetsNumCtx(t *testing.T) {
	p := NewOllamaProvider(OllamaProviderConfig{
		Model:         "qwen2.5:7b",
		Endpoint:      "http://localhost:11434",
		ContextWindow: 8192,
	})

	got := p.buildRequest(CompletionRequest{
		SystemPrompt: "sys",
		Messages:     []Message{{Role: "user", Content: "hi"}},
		MaxTokens:    4096,
		Temperature:  0.1,
	}, false)

	if got.Options.NumCtx != 8192 {
		t.Errorf("Options.NumCtx = %d, want 8192 (configured context window)", got.Options.NumCtx)
	}
}

// TestOllamaDefaultContextWindow verifies the provider falls back to a
// sane non-zero context window when none is configured, so num_ctx is
// never sent as 0 (which omitempty would drop, reviving the 4096 default).
func TestOllamaDefaultContextWindow(t *testing.T) {
	p := NewOllamaProvider(OllamaProviderConfig{
		Model:    "qwen2.5:7b",
		Endpoint: "http://localhost:11434",
		// ContextWindow intentionally unset (0)
	})

	got := p.buildRequest(CompletionRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	}, false)

	if got.Options.NumCtx <= 0 {
		t.Errorf("Options.NumCtx = %d, want a positive default", got.Options.NumCtx)
	}
}

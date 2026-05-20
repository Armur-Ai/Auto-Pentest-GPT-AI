package prompts

import (
	"context"
	"errors"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
)

// mockProvider is a tiny llm.Provider implementation driven by a
// scripted slice of responses. Each Complete call pops the next one
// and records the SystemPrompt the caller used so tests can assert
// which prompt variant was sent on which attempt.
type mockProvider struct {
	name            string
	responses       []*llm.CompletionResponse
	errs            []error
	callCount       int
	capturedSystem  []string
	supportsToolUse bool
}

func (m *mockProvider) Complete(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	m.capturedSystem = append(m.capturedSystem, req.SystemPrompt)
	idx := m.callCount
	m.callCount++
	if idx < len(m.errs) && m.errs[idx] != nil {
		return nil, m.errs[idx]
	}
	if idx >= len(m.responses) {
		return &llm.CompletionResponse{Content: "default-ok"}, nil
	}
	return m.responses[idx], nil
}

func (m *mockProvider) Stream(_ context.Context, _ llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	ch := make(chan llm.StreamChunk, 1)
	close(ch)
	return ch, nil
}

func (m *mockProvider) HealthCheck(_ context.Context) error { return nil }
func (m *mockProvider) ModelName() string                   { return m.name }
func (m *mockProvider) ContextWindow() int                  { return 128000 }
func (m *mockProvider) SupportsToolUse() bool               { return m.supportsToolUse }

// TestRetryProvider_NoRefusal — happy path: primary returns substantive
// content on first call; no retry or fallback fired.
func TestRetryProvider_NoRefusal(t *testing.T) {
	primary := &mockProvider{
		name: "primary",
		responses: []*llm.CompletionResponse{
			{Content: "Analysis: found IDOR at /api/orders/{id} via second-user token replay."},
		},
	}
	fallback := &mockProvider{name: "fallback"}

	rp := NewRetryProvider(primary, RetryConfig{
		StrictReframeTemplate: "offsec_system_strict",
		Fallback:              fallback,
	})

	resp, err := rp.Complete(context.Background(), llm.CompletionRequest{
		SystemPrompt: "original prompt",
		Messages:     []llm.Message{{Role: "user", Content: "scan"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content == "" {
		t.Error("expected substantive content")
	}
	if primary.callCount != 1 {
		t.Errorf("primary calls = %d, want 1", primary.callCount)
	}
	if fallback.callCount != 0 {
		t.Errorf("fallback should not be called when primary succeeds; got %d", fallback.callCount)
	}
}

// TestRetryProvider_StrictReframeRecovers — primary refuses on first
// attempt; succeeds on the second attempt with the strict prompt.
func TestRetryProvider_StrictReframeRecovers(t *testing.T) {
	primary := &mockProvider{
		name: "primary",
		responses: []*llm.CompletionResponse{
			{Content: "I can't help with hacking systems."},
			{Content: "Got it. Testing IDOR at /api/orders/{id} with two-user state."},
		},
	}
	fallback := &mockProvider{name: "fallback"}

	rp := NewRetryProvider(primary, RetryConfig{
		StrictReframeTemplate: "offsec_system_strict",
		StrictContext:         Context{Engagement: "test"},
		Fallback:              fallback,
	})

	resp, err := rp.Complete(context.Background(), llm.CompletionRequest{
		SystemPrompt: "original prompt",
		Messages:     []llm.Message{{Role: "user", Content: "scan"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content == "" || IsRefusal(resp.Content) {
		t.Errorf("expected substantive content from strict reframe, got %q", resp.Content)
	}
	if primary.callCount != 2 {
		t.Errorf("primary calls = %d, want 2", primary.callCount)
	}
	if fallback.callCount != 0 {
		t.Errorf("fallback should not fire when strict reframe succeeds; got %d", fallback.callCount)
	}
	// Second call should have used the strict template (different system prompt).
	if primary.capturedSystem[0] == primary.capturedSystem[1] {
		t.Error("strict-reframe attempt should have used a different SystemPrompt")
	}
}

// TestRetryProvider_FallbackRecovers — primary refuses original AND
// strict reframe; fallback provider returns substantive content.
func TestRetryProvider_FallbackRecovers(t *testing.T) {
	primary := &mockProvider{
		name: "primary",
		responses: []*llm.CompletionResponse{
			{Content: "I cannot help with this request."},
			{Content: "I must decline this request."},
		},
	}
	fallback := &mockProvider{
		name: "fallback",
		responses: []*llm.CompletionResponse{
			{Content: "Analysis: found exposed S3 bucket with public list permissions."},
		},
	}

	rp := NewRetryProvider(primary, RetryConfig{
		StrictReframeTemplate: "offsec_system_strict",
		Fallback:              fallback,
	})

	resp, err := rp.Complete(context.Background(), llm.CompletionRequest{
		SystemPrompt: "original",
		Messages:     []llm.Message{{Role: "user", Content: "scan"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Content == "" || IsRefusal(resp.Content) {
		t.Errorf("expected substantive content from fallback, got %q", resp.Content)
	}
	if primary.callCount != 2 {
		t.Errorf("primary calls = %d, want 2", primary.callCount)
	}
	if fallback.callCount != 1 {
		t.Errorf("fallback calls = %d, want 1", fallback.callCount)
	}
}

// TestRetryProvider_AllRefused — every attempt refuses. Returns the
// original refusal text along with ErrAllAttemptsRefused.
func TestRetryProvider_AllRefused(t *testing.T) {
	primary := &mockProvider{
		name: "primary",
		responses: []*llm.CompletionResponse{
			{Content: "I cannot help with hacking."},
			{Content: "I cannot help with hacking."},
		},
	}
	fallback := &mockProvider{
		name: "fallback",
		responses: []*llm.CompletionResponse{
			{Content: "I won't help you with that."},
		},
	}

	rp := NewRetryProvider(primary, RetryConfig{
		StrictReframeTemplate: "offsec_system_strict",
		Fallback:              fallback,
	})

	resp, err := rp.Complete(context.Background(), llm.CompletionRequest{
		SystemPrompt: "original",
	})
	if !errors.Is(err, ErrAllAttemptsRefused) {
		t.Errorf("err = %v, want ErrAllAttemptsRefused", err)
	}
	if resp == nil {
		t.Fatal("expected response (the original refusal) alongside the error")
	}
	if !IsRefusal(resp.Content) {
		t.Errorf("returned response should be the original refusal, got %q", resp.Content)
	}
}

// TestRetryProvider_NetworkErrorPassesThrough — actual network errors
// (not refusals) must bubble up immediately. No reframe, no fallback.
func TestRetryProvider_NetworkErrorPassesThrough(t *testing.T) {
	netErr := errors.New("connection refused")
	primary := &mockProvider{
		name: "primary",
		errs: []error{netErr},
	}
	fallback := &mockProvider{
		name: "fallback",
		responses: []*llm.CompletionResponse{
			{Content: "should not be called"},
		},
	}

	rp := NewRetryProvider(primary, RetryConfig{
		StrictReframeTemplate: "offsec_system_strict",
		Fallback:              fallback,
	})

	_, err := rp.Complete(context.Background(), llm.CompletionRequest{})
	if !errors.Is(err, netErr) {
		t.Errorf("err = %v, want %v", err, netErr)
	}
	if fallback.callCount != 0 {
		t.Errorf("fallback should not be invoked on network error; got %d calls", fallback.callCount)
	}
}

// TestRetryProvider_NoStrictTemplate — empty StrictReframeTemplate
// skips the reframe step and goes straight to fallback.
func TestRetryProvider_NoStrictTemplate(t *testing.T) {
	primary := &mockProvider{
		name: "primary",
		responses: []*llm.CompletionResponse{
			{Content: "I cannot help with this."},
		},
	}
	fallback := &mockProvider{
		name: "fallback",
		responses: []*llm.CompletionResponse{
			{Content: "Substantive analysis from fallback."},
		},
	}

	rp := NewRetryProvider(primary, RetryConfig{
		// StrictReframeTemplate intentionally empty
		Fallback: fallback,
	})

	resp, err := rp.Complete(context.Background(), llm.CompletionRequest{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if primary.callCount != 1 {
		t.Errorf("primary should be called exactly once (no reframe); got %d", primary.callCount)
	}
	if fallback.callCount != 1 {
		t.Errorf("fallback should be called once; got %d", fallback.callCount)
	}
	if resp.Content == "" || IsRefusal(resp.Content) {
		t.Errorf("expected fallback's substantive content; got %q", resp.Content)
	}
}

// TestRetryProvider_NoFallback — empty Fallback means we stop after the
// strict reframe attempt. If both refused, return the original refusal +
// ErrAllAttemptsRefused.
func TestRetryProvider_NoFallback(t *testing.T) {
	primary := &mockProvider{
		name: "primary",
		responses: []*llm.CompletionResponse{
			{Content: "I cannot help."},
			{Content: "I cannot help."},
		},
	}

	rp := NewRetryProvider(primary, RetryConfig{
		StrictReframeTemplate: "offsec_system_strict",
		// Fallback intentionally nil
	})

	_, err := rp.Complete(context.Background(), llm.CompletionRequest{})
	if !errors.Is(err, ErrAllAttemptsRefused) {
		t.Errorf("err = %v, want ErrAllAttemptsRefused", err)
	}
	if primary.callCount != 2 {
		t.Errorf("primary calls = %d, want 2 (original + strict reframe)", primary.callCount)
	}
}

// TestRetryProvider_PassThroughInterface — non-Complete methods must
// pass through to the primary, not synthesize their own behavior.
func TestRetryProvider_PassThroughInterface(t *testing.T) {
	primary := &mockProvider{name: "primary-model", supportsToolUse: true}
	rp := NewRetryProvider(primary, RetryConfig{})

	if rp.ModelName() != "primary-model" {
		t.Errorf("ModelName = %q", rp.ModelName())
	}
	if rp.ContextWindow() != 128000 {
		t.Errorf("ContextWindow = %d", rp.ContextWindow())
	}
	if !rp.SupportsToolUse() {
		t.Errorf("SupportsToolUse should reflect primary")
	}
	if err := rp.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}
}

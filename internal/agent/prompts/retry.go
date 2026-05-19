package prompts

import (
	"context"
	"errors"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
)

// ErrAllAttemptsRefused is returned from RetryProvider.Complete when
// every attempt — original + stricter reframe + fallback provider —
// produced a response that IsRefusal flagged. The CompletionResponse
// is still returned alongside the error so callers can log the actual
// refusal text. Most callers should treat this as "skip this agent
// step" rather than a fatal campaign failure.
var ErrAllAttemptsRefused = errors.New("LLM refused after retry and fallback")

// RetryConfig controls how RetryProvider handles a refusal.
type RetryConfig struct {
	// StrictReframeTemplate is the name of the prompt template to use
	// for the second attempt (typically "offsec_system_strict"). If
	// empty, the strict-reframe step is skipped and we go straight
	// from original to fallback.
	StrictReframeTemplate string

	// StrictContext is the data passed into the strict reframe
	// template. Same shape as the original Context.
	StrictContext Context

	// Fallback is an optional second-chance Provider, typically a
	// less-restrictive one (Together AI, DeepSeek). If nil, fallback
	// step is skipped.
	Fallback llm.Provider
}

// RetryProvider decorates any llm.Provider with refusal-handling:
// if the primary provider refuses the request, retry with a stricter
// reframing prompt; if that still refuses, fall over to a less-
// restrictive secondary provider. Pass-through for Stream, HealthCheck,
// ModelName, ContextWindow, SupportsToolUse.
//
// This is opt-in. Wrap your provider where you want this behavior:
//
//	primary := llm.NewClaudeProvider(...)
//	fallback := llm.NewOpenAIProvider(togetherAICfg)
//	provider := prompts.NewRetryProvider(primary, prompts.RetryConfig{
//	    StrictReframeTemplate: "offsec_system_strict",
//	    StrictContext:         ctx,
//	    Fallback:              fallback,
//	})
//
// Then pass `provider` to agents as you would any llm.Provider.
type RetryProvider struct {
	primary llm.Provider
	config  RetryConfig
}

// NewRetryProvider wraps primary with refusal-detection + retry +
// fallback. Pass-through for everything except Complete.
func NewRetryProvider(primary llm.Provider, cfg RetryConfig) *RetryProvider {
	return &RetryProvider{primary: primary, config: cfg}
}

// Complete runs the primary provider, then handles refusal:
//  1. Original request → if not refused, return immediately.
//  2. Stricter reframe → swap SystemPrompt for the strict template,
//     retry once. If not refused, return.
//  3. Fallback provider → run the original (non-strict) request against
//     the fallback. If not refused, return.
//  4. All refused → return the original refusal response with
//     ErrAllAttemptsRefused.
//
// Errors from any provider step pass through unmodified (we don't
// fall back on network errors — those should bubble up).
func (r *RetryProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	// Step 1: primary provider, original prompt.
	resp, err := r.primary.Complete(ctx, req)
	if err != nil {
		return nil, err
	}
	if !IsRefusal(resp.Content) {
		return resp, nil
	}

	// Step 2: stricter reframe on the primary provider.
	if r.config.StrictReframeTemplate != "" {
		strictPrompt, terr := Load(r.config.StrictReframeTemplate, r.config.StrictContext)
		if terr == nil {
			strictReq := req
			strictReq.SystemPrompt = strictPrompt
			resp2, err2 := r.primary.Complete(ctx, strictReq)
			if err2 == nil && !IsRefusal(resp2.Content) {
				return resp2, nil
			}
		}
		// Template load or strict attempt failed — silent, continue to fallback.
	}

	// Step 3: fallback provider (less restrictive).
	if r.config.Fallback != nil {
		resp3, err3 := r.config.Fallback.Complete(ctx, req)
		if err3 == nil && !IsRefusal(resp3.Content) {
			return resp3, nil
		}
	}

	// Step 4: all attempts refused. Surface the original refusal text
	// to the caller along with the sentinel error.
	return resp, ErrAllAttemptsRefused
}

// Stream passes through to the primary provider — refusal-retry logic
// only applies to non-streaming Complete calls. Streaming callers
// rarely benefit from retry (they're consuming chunks incrementally
// already) and the implementation cost is high. Open follow-up.
func (r *RetryProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	return r.primary.Stream(ctx, req)
}

func (r *RetryProvider) HealthCheck(ctx context.Context) error {
	return r.primary.HealthCheck(ctx)
}

func (r *RetryProvider) ModelName() string {
	return r.primary.ModelName()
}

func (r *RetryProvider) ContextWindow() int {
	return r.primary.ContextWindow()
}

func (r *RetryProvider) SupportsToolUse() bool {
	return r.primary.SupportsToolUse()
}

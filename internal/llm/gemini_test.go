package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGeminiProvider_Complete exercises the happy path: system prompt +
// one user message, no tools. Asserts request shape (path, key in
// query string, system hoisted to systemInstruction, role mapping) and
// response parsing (content + usage).
func TestGeminiProvider_Complete(t *testing.T) {
	var capturedReq gemRequest
	var capturedPath, capturedQuery string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedQuery = r.URL.Query().Get("key")
		if err := json.NewDecoder(r.Body).Decode(&capturedReq); err != nil {
			t.Fatalf("decoding request: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gemResponse{
			Candidates: []gemCandidate{{
				Content: gemContent{
					Role:  "model",
					Parts: []gemPart{{Text: "Hello back"}},
				},
				FinishReason: "STOP",
			}},
			UsageMetadata: gemUsage{
				PromptTokenCount:     5,
				CandidatesTokenCount: 3,
				TotalTokenCount:      8,
			},
		})
	}))
	defer server.Close()

	p := NewGeminiProvider(GeminiProviderConfig{
		APIKey:        "test-key",
		Endpoint:      server.URL,
		Model:         "gemini-2.5-flash",
		ContextWindow: 1_000_000,
	})

	resp, err := p.Complete(context.Background(), CompletionRequest{
		SystemPrompt: "you are a test",
		Messages:     []Message{{Role: "user", Content: "Hello"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if resp.Content != "Hello back" {
		t.Errorf("content = %q, want %q", resp.Content, "Hello back")
	}
	if resp.Usage.InputTokens != 5 {
		t.Errorf("input tokens = %d, want 5", resp.Usage.InputTokens)
	}
	if resp.Usage.OutputTokens != 3 {
		t.Errorf("output tokens = %d, want 3", resp.Usage.OutputTokens)
	}
	if resp.StopReason != "STOP" {
		t.Errorf("stop reason = %q, want STOP", resp.StopReason)
	}

	// Path goes through /v1beta-equivalent + /models/<name>:generateContent
	if !strings.Contains(capturedPath, "/models/gemini-2.5-flash:generateContent") {
		t.Errorf("unexpected path %q", capturedPath)
	}
	if capturedQuery != "test-key" {
		t.Errorf("API key not in query string: got %q, want test-key", capturedQuery)
	}
	if capturedReq.SystemInstruction == nil || capturedReq.SystemInstruction.Parts[0].Text != "you are a test" {
		t.Errorf("system prompt not hoisted to systemInstruction: %+v", capturedReq.SystemInstruction)
	}
	if len(capturedReq.Contents) != 1 || capturedReq.Contents[0].Role != "user" {
		t.Errorf("user message not in contents: %+v", capturedReq.Contents)
	}
}

// TestGeminiProvider_AssistantRoleMapsToModel — Gemini uses "model" as
// the assistant role inside contents. The provider must translate.
func TestGeminiProvider_AssistantRoleMapsToModel(t *testing.T) {
	var capturedReq gemRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&capturedReq)
		_ = json.NewEncoder(w).Encode(gemResponse{
			Candidates: []gemCandidate{{
				Content:      gemContent{Role: "model", Parts: []gemPart{{Text: "ok"}}},
				FinishReason: "STOP",
			}},
		})
	}))
	defer server.Close()

	p := NewGeminiProvider(GeminiProviderConfig{APIKey: "k", Endpoint: server.URL, Model: "gemini-2.5-flash"})

	_, err := p.Complete(context.Background(), CompletionRequest{
		Messages: []Message{
			{Role: "user", Content: "ping"},
			{Role: "assistant", Content: "pong"},
			{Role: "user", Content: "ping again"},
		},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if len(capturedReq.Contents) != 3 {
		t.Fatalf("expected 3 contents, got %d", len(capturedReq.Contents))
	}
	if capturedReq.Contents[1].Role != "model" {
		t.Errorf("assistant role should map to model; got %q", capturedReq.Contents[1].Role)
	}
}

// TestGeminiProvider_ToolUse — the LLM responds with a functionCall
// part instead of text. The provider should surface it as a ToolCall
// with arguments serialized to a JSON string (matching the convention
// our agents already consume for Claude / OpenAI).
func TestGeminiProvider_ToolUse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(gemResponse{
			Candidates: []gemCandidate{{
				Content: gemContent{
					Role: "model",
					Parts: []gemPart{{
						FunctionCall: &gemFunctionCall{
							Name: "get_weather",
							Args: map[string]any{"location": "SF"},
						},
					}},
				},
				FinishReason: "STOP",
			}},
		})
	}))
	defer server.Close()

	p := NewGeminiProvider(GeminiProviderConfig{APIKey: "k", Endpoint: server.URL, Model: "gemini-2.5-flash"})

	resp, err := p.Complete(context.Background(), CompletionRequest{
		Messages: []Message{{Role: "user", Content: "weather?"}},
		Tools: []Tool{{
			Name:        "get_weather",
			Description: "get weather",
			Parameters:  json.RawMessage(`{"type":"object"}`),
		}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if len(resp.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(resp.ToolCalls))
	}
	if resp.ToolCalls[0].Name != "get_weather" {
		t.Errorf("tool name = %q, want get_weather", resp.ToolCalls[0].Name)
	}
	if !strings.Contains(resp.ToolCalls[0].Arguments, `"location"`) || !strings.Contains(resp.ToolCalls[0].Arguments, `"SF"`) {
		t.Errorf("tool args missing fields: %q", resp.ToolCalls[0].Arguments)
	}
}

// TestGeminiProvider_DisableToolUse confirms that DisableToolUse drops
// the tools array from the outgoing request body so callers fall back
// to the JSON-in-prompt path.
func TestGeminiProvider_DisableToolUse(t *testing.T) {
	var capturedReq gemRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&capturedReq)
		_ = json.NewEncoder(w).Encode(gemResponse{
			Candidates: []gemCandidate{{
				Content:      gemContent{Role: "model", Parts: []gemPart{{Text: "ok"}}},
				FinishReason: "STOP",
			}},
		})
	}))
	defer server.Close()

	p := NewGeminiProvider(GeminiProviderConfig{
		APIKey:         "k",
		Endpoint:       server.URL,
		Model:          "gemini-2.5-flash",
		DisableToolUse: true,
	})

	if p.SupportsToolUse() {
		t.Error("SupportsToolUse() should be false when DisableToolUse is set")
	}

	_, err := p.Complete(context.Background(), CompletionRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
		Tools: []Tool{{
			Name:        "get_weather",
			Description: "get weather",
			Parameters:  json.RawMessage(`{"type":"object"}`),
		}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if len(capturedReq.Tools) != 0 {
		t.Errorf("tools should be stripped when DisableToolUse is set; got %d", len(capturedReq.Tools))
	}
}

// TestGeminiProvider_HealthCheck — happy path: GET /models with key in
// the query string returns 200.
func TestGeminiProvider_HealthCheck(t *testing.T) {
	var capturedPath, capturedKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedKey = r.URL.Query().Get("key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[]}`))
	}))
	defer server.Close()

	p := NewGeminiProvider(GeminiProviderConfig{
		APIKey:   "test-key",
		Endpoint: server.URL,
		Model:    "gemini-2.5-flash",
	})

	if err := p.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}
	if !strings.HasSuffix(capturedPath, "/models") {
		t.Errorf("path = %q, want suffix /models", capturedPath)
	}
	if capturedKey != "test-key" {
		t.Errorf("query key = %q, want test-key", capturedKey)
	}
}

// TestGeminiProvider_HealthCheck401 — a 401/403 returns an error
// message that mentions the API key and points at the console URL.
func TestGeminiProvider_HealthCheck401(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
			}))
			defer server.Close()

			p := NewGeminiProvider(GeminiProviderConfig{APIKey: "bad", Endpoint: server.URL, Model: "gemini-2.5-flash"})
			err := p.HealthCheck(context.Background())
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), "API key") {
				t.Errorf("error should mention API key: %v", err)
			}
		})
	}
}

// TestGeminiProvider_DefaultEndpoint — empty endpoint becomes Google's
// first-party generativelanguage URL.
func TestGeminiProvider_DefaultEndpoint(t *testing.T) {
	p := NewGeminiProvider(GeminiProviderConfig{APIKey: "k", Model: "gemini-2.5-flash"})
	if p.endpoint != "https://generativelanguage.googleapis.com/v1beta" {
		t.Errorf("default endpoint = %q", p.endpoint)
	}
}

// TestGeminiProvider_4xxNotRetried — a 400 is permanent; the retry
// loop must not burn tokens.
func TestGeminiProvider_4xxNotRetried(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"bad","code":400}}`))
	}))
	defer server.Close()

	p := NewGeminiProvider(GeminiProviderConfig{
		APIKey:     "k",
		Endpoint:   server.URL,
		Model:      "gemini-2.5-flash",
		MaxRetries: 3,
	})

	_, err := p.Complete(context.Background(), CompletionRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected error on 400")
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (4xx must not retry)", attempts)
	}
}

// TestGeminiProvider_FactoryWiring confirms the factory recognizes
// "gemini" and instantiates the right type. Belt-and-braces against
// silently routing Gemini config to the wrong provider.
func TestGeminiProvider_FactoryWiring(t *testing.T) {
	p, err := newProviderFromParams("gemini", "test-key", "gemini-2.5-flash", "", 1_000_000)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if _, ok := p.(*GeminiProvider); !ok {
		t.Fatalf("factory returned %T, want *GeminiProvider", p)
	}
	if p.ModelName() != "gemini-2.5-flash" {
		t.Errorf("model = %q", p.ModelName())
	}
	if !p.SupportsToolUse() {
		t.Error("Gemini should support tool use by default")
	}
}

// TestGeminiPricing — flagship + flash + lite entries are reachable
// from the pricing table.
func TestGeminiPricing(t *testing.T) {
	cases := []struct {
		model      string
		wantInput  float64
		wantOutput float64
	}{
		{"gemini-2.5-pro", 1.25, 10.0},
		{"gemini-2.5-flash", 0.30, 2.50},
		{"gemini-2.5-flash-lite", 0.10, 0.40},
		{"gemini-1.5-pro", 1.25, 5.0},
		{"gemini-1.5-flash", 0.075, 0.30},
	}
	for _, tc := range cases {
		p := PricingFor(tc.model)
		if p.InputPerMillion != tc.wantInput {
			t.Errorf("%s: input = %v, want %v", tc.model, p.InputPerMillion, tc.wantInput)
		}
		if p.OutputPerMillion != tc.wantOutput {
			t.Errorf("%s: output = %v, want %v", tc.model, p.OutputPerMillion, tc.wantOutput)
		}
	}
}

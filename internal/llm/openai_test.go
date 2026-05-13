package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestOpenAIProvider_Complete exercises the happy path: system prompt +
// one user message, no tools. Asserts request shape (path, auth header,
// message order) and response parsing (content + usage).
func TestOpenAIProvider_Complete(t *testing.T) {
	var capturedReq oaiChatRequest
	var capturedAuth, capturedPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&capturedReq); err != nil {
			t.Fatalf("decoding request: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oaiChatResponse{
			ID:    "chatcmpl-test",
			Model: "test-model",
			Choices: []oaiChoice{{
				Index:        0,
				Message:      oaiMessage{Role: "assistant", Content: "Hello back"},
				FinishReason: "stop",
			}},
			Usage: oaiUsage{PromptTokens: 5, CompletionTokens: 3, TotalTokens: 8},
		})
	}))
	defer server.Close()

	p := NewOpenAIProvider(OpenAIProviderConfig{
		APIKey:        "test-key",
		Endpoint:      server.URL,
		Model:         "test-model",
		ContextWindow: 128000,
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
	if resp.StopReason != "stop" {
		t.Errorf("stop reason = %q, want stop", resp.StopReason)
	}

	if capturedAuth != "Bearer test-key" {
		t.Errorf("Authorization header = %q, want %q", capturedAuth, "Bearer test-key")
	}
	if capturedPath != "/chat/completions" {
		t.Errorf("path = %q, want /chat/completions", capturedPath)
	}
	if len(capturedReq.Messages) != 2 {
		t.Fatalf("expected 2 messages (system + user), got %d", len(capturedReq.Messages))
	}
	if capturedReq.Messages[0].Role != "system" {
		t.Errorf("first message role = %q, want system", capturedReq.Messages[0].Role)
	}
	if capturedReq.Messages[1].Role != "user" {
		t.Errorf("second message role = %q, want user", capturedReq.Messages[1].Role)
	}
	if capturedReq.Model != "test-model" {
		t.Errorf("model = %q, want test-model", capturedReq.Model)
	}
}

// TestOpenAIProvider_ToolUse verifies a tool_calls response is parsed
// into our ToolCall struct with arguments preserved as the raw JSON
// string the OpenAI spec sends.
func TestOpenAIProvider_ToolUse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(oaiChatResponse{
			Choices: []oaiChoice{{
				Message: oaiMessage{
					Role: "assistant",
					ToolCalls: []oaiToolCall{{
						ID:   "call_1",
						Type: "function",
						Function: oaiToolCallFunc{
							Name:      "get_weather",
							Arguments: `{"location":"SF"}`,
						},
					}},
				},
				FinishReason: "tool_calls",
			}},
		})
	}))
	defer server.Close()

	p := NewOpenAIProvider(OpenAIProviderConfig{
		Endpoint: server.URL,
		Model:    "test-model",
	})

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
	if resp.ToolCalls[0].Arguments != `{"location":"SF"}` {
		t.Errorf("tool args = %q", resp.ToolCalls[0].Arguments)
	}
	if resp.ToolCalls[0].ID != "call_1" {
		t.Errorf("tool ID = %q, want call_1", resp.ToolCalls[0].ID)
	}
}

// TestOpenAIProvider_DisableToolUse verifies that DisableToolUse drops
// the tools array out of the outgoing request so callers fall back to
// the JSON-in-prompt path. Needed for hosted open-weight models that
// parse function-calling erratically.
func TestOpenAIProvider_DisableToolUse(t *testing.T) {
	var capturedReq oaiChatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&capturedReq)
		_ = json.NewEncoder(w).Encode(oaiChatResponse{
			Choices: []oaiChoice{{
				Message: oaiMessage{Role: "assistant", Content: "ok"},
			}},
		})
	}))
	defer server.Close()

	p := NewOpenAIProvider(OpenAIProviderConfig{
		Endpoint:       server.URL,
		Model:          "test-model",
		DisableToolUse: true,
	})

	if p.SupportsToolUse() {
		t.Error("SupportsToolUse() should be false when DisableToolUse is set")
	}

	_, err := p.Complete(context.Background(), CompletionRequest{
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

	if len(capturedReq.Tools) != 0 {
		t.Errorf("tools should be stripped when DisableToolUse is set; got %d", len(capturedReq.Tools))
	}
}

// TestOpenAIProvider_Stream verifies SSE parsing — content deltas
// accumulate, [DONE] sentinel produces a Done chunk.
func TestOpenAIProvider_Stream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer server.Close()

	p := NewOpenAIProvider(OpenAIProviderConfig{
		Endpoint: server.URL,
		Model:    "test-model",
	})

	ch, err := p.Stream(context.Background(), CompletionRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	var content strings.Builder
	var sawDone bool
	for chunk := range ch {
		if chunk.Delta != "" {
			content.WriteString(chunk.Delta)
		}
		if chunk.Done {
			sawDone = true
		}
	}

	if content.String() != "Hello world" {
		t.Errorf("content = %q, want %q", content.String(), "Hello world")
	}
	if !sawDone {
		t.Error("expected Done chunk")
	}
}

// TestOpenAIProvider_HealthCheck — happy path: GET /models with auth
// header, 200 OK. Verifies we hit the right path and forward the key.
func TestOpenAIProvider_HealthCheck(t *testing.T) {
	var capturedPath, capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer server.Close()

	p := NewOpenAIProvider(OpenAIProviderConfig{
		APIKey:   "test-key",
		Endpoint: server.URL,
		Model:    "test-model",
	})

	if err := p.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}
	if capturedPath != "/models" {
		t.Errorf("path = %q, want /models", capturedPath)
	}
	if capturedAuth != "Bearer test-key" {
		t.Errorf("Authorization = %q, want %q", capturedAuth, "Bearer test-key")
	}
}

// TestOpenAIProvider_HealthCheck401 — 401 returns a clear "check API
// key" error message, not a generic status code dump.
func TestOpenAIProvider_HealthCheck401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	p := NewOpenAIProvider(OpenAIProviderConfig{
		APIKey:   "bad-key",
		Endpoint: server.URL,
		Model:    "test-model",
	})

	err := p.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "API key") {
		t.Errorf("error should mention API key: %v", err)
	}
}

// TestOpenAIProvider_DefaultEndpoint — empty endpoint becomes OpenAI's
// own URL. Together AI / DeepSeek / Groq users override via config.
func TestOpenAIProvider_DefaultEndpoint(t *testing.T) {
	p := NewOpenAIProvider(OpenAIProviderConfig{
		APIKey:   "test",
		Model:    "gpt-4o",
		Endpoint: "",
	})
	if p.endpoint != "https://api.openai.com/v1" {
		t.Errorf("default endpoint = %q, want https://api.openai.com/v1", p.endpoint)
	}
}

// TestOpenAIProvider_TrimTrailingSlash — endpoint trailing slash is
// stripped so request paths concat cleanly.
func TestOpenAIProvider_TrimTrailingSlash(t *testing.T) {
	p := NewOpenAIProvider(OpenAIProviderConfig{
		APIKey:   "test",
		Endpoint: "https://api.together.xyz/v1/",
	})
	if p.endpoint != "https://api.together.xyz/v1" {
		t.Errorf("endpoint = %q, want trailing slash trimmed", p.endpoint)
	}
}

// TestOpenAIProvider_4xxNotRetried — a 400 / 401 / 404 is a permanent
// error; the retry loop must not back off into burning tokens.
func TestOpenAIProvider_4xxNotRetried(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"bad request"}}`))
	}))
	defer server.Close()

	p := NewOpenAIProvider(OpenAIProviderConfig{
		Endpoint:   server.URL,
		Model:      "m",
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

// TestOpenAIPricing — Together AI / DeepSeek / OpenAI entries exist in
// the pricing table. Unknown models fall back to Sonnet tier.
func TestOpenAIPricing(t *testing.T) {
	tests := []struct {
		model      string
		wantInput  float64
		wantOutput float64
	}{
		{"meta-llama/Llama-3.3-70B-Instruct-Turbo", 0.88, 0.88},
		{"Qwen/Qwen2.5-72B-Instruct-Turbo", 1.20, 1.20},
		{"deepseek-ai/DeepSeek-V3", 1.25, 1.25},
		{"moonshotai/Kimi-K2-Instruct", 0.60, 2.50},
		{"deepseek-chat", 0.27, 1.10},
		{"gpt-4o", 2.50, 10.0},
		{"gpt-4o-mini", 0.15, 0.60},
		{"some-unknown-model", 3.0, 15.0}, // Sonnet fallback
	}
	for _, tc := range tests {
		p := PricingFor(tc.model)
		if p.InputPerMillion != tc.wantInput {
			t.Errorf("%s: input = %v, want %v", tc.model, p.InputPerMillion, tc.wantInput)
		}
		if p.OutputPerMillion != tc.wantOutput {
			t.Errorf("%s: output = %v, want %v", tc.model, p.OutputPerMillion, tc.wantOutput)
		}
	}
}

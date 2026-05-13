package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// OpenAIProvider implements Provider for any OpenAI-API-compatible endpoint:
// OpenAI itself, Together AI, DeepSeek, Moonshot/Kimi, Groq, etc. Differs
// from ClaudeProvider in that it speaks the OpenAI chat-completions
// protocol over plain HTTP — no SDK dependency — so adding a new
// compatible vendor is a base-URL change in config, no code change.
type OpenAIProvider struct {
	endpoint        string
	apiKey          string
	model           string
	contextWindow   int
	maxRetries      int
	httpClient      *http.Client
	supportsToolUse bool
}

// OpenAIProviderConfig holds configuration for creating an OpenAIProvider.
type OpenAIProviderConfig struct {
	APIKey        string
	Endpoint      string // base URL, e.g. https://api.together.xyz/v1
	Model         string
	ContextWindow int
	MaxRetries    int
	// DisableToolUse forces the provider to advertise no native tool-use,
	// pushing callers onto the JSON-in-prompt fallback path. Useful for
	// hosted open-weight models that advertise function-calling but
	// parse tool arguments erratically.
	DisableToolUse bool
}

// NewOpenAIProvider creates a new OpenAI-compatible provider.
func NewOpenAIProvider(cfg OpenAIProviderConfig) *OpenAIProvider {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.ContextWindow <= 0 {
		cfg.ContextWindow = 128000
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://api.openai.com/v1"
	}
	cfg.Endpoint = strings.TrimRight(cfg.Endpoint, "/")

	return &OpenAIProvider{
		endpoint:        cfg.Endpoint,
		apiKey:          cfg.APIKey,
		model:           cfg.Model,
		contextWindow:   cfg.ContextWindow,
		maxRetries:      cfg.MaxRetries,
		supportsToolUse: !cfg.DisableToolUse,
		httpClient: &http.Client{
			Timeout: 10 * time.Minute, // long timeout for LLM inference
		},
	}
}

// --- wire format (OpenAI Chat Completions) ---

type oaiChatRequest struct {
	Model       string       `json:"model"`
	Messages    []oaiMessage `json:"messages"`
	Tools       []oaiTool    `json:"tools,omitempty"`
	MaxTokens   int          `json:"max_tokens,omitempty"`
	Temperature float64      `json:"temperature,omitempty"`
	Stream      bool         `json:"stream,omitempty"`
}

type oaiMessage struct {
	Role       string        `json:"role"`
	Content    string        `json:"content,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
}

type oaiTool struct {
	Type     string          `json:"type"`
	Function oaiToolFunction `json:"function"`
}

type oaiToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type oaiToolCall struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Function oaiToolCallFunc `json:"function"`
}

type oaiToolCallFunc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON-encoded string per OpenAI spec
}

type oaiChatResponse struct {
	ID      string      `json:"id"`
	Model   string      `json:"model"`
	Choices []oaiChoice `json:"choices"`
	Usage   oaiUsage    `json:"usage"`
}

type oaiChoice struct {
	Index        int        `json:"index"`
	Message      oaiMessage `json:"message"`
	FinishReason string     `json:"finish_reason"`
}

type oaiUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type oaiStreamChunk struct {
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Content   string        `json:"content,omitempty"`
			ToolCalls []oaiToolCall `json:"tool_calls,omitempty"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason,omitempty"`
	} `json:"choices"`
}

type oaiErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// --- Complete ---

func (o *OpenAIProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	body := o.buildRequest(req, false)

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling openai request: %w", err)
	}

	var parsed *oaiChatResponse
	var lastErr error

	for attempt := 0; attempt <= o.maxRetries; attempt++ {
		httpReq, err := http.NewRequestWithContext(ctx, "POST", o.endpoint+"/chat/completions", bytes.NewReader(jsonBody))
		if err != nil {
			return nil, fmt.Errorf("creating openai request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if o.apiKey != "" {
			httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)
		}

		httpResp, err := o.httpClient.Do(httpReq)
		if err != nil {
			lastErr = err
			if attempt == o.maxRetries {
				return nil, fmt.Errorf("openai request failed: %w", lastErr)
			}
			if backoffErr := openaiBackoff(ctx, attempt); backoffErr != nil {
				return nil, backoffErr
			}
			continue
		}

		// Retry on 429 (rate-limit) and 5xx (server-side).
		if httpResp.StatusCode == http.StatusTooManyRequests || httpResp.StatusCode >= 500 {
			respBody, _ := io.ReadAll(httpResp.Body)
			httpResp.Body.Close()
			lastErr = fmt.Errorf("openai returned status %d: %s", httpResp.StatusCode, truncate(string(respBody), 256))
			if attempt == o.maxRetries {
				return nil, lastErr
			}
			if backoffErr := openaiBackoff(ctx, attempt); backoffErr != nil {
				return nil, backoffErr
			}
			continue
		}

		// Permanent error — don't retry 4xx (other than 429).
		if httpResp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(httpResp.Body)
			httpResp.Body.Close()
			return nil, fmt.Errorf("openai returned status %d: %s", httpResp.StatusCode, truncate(string(respBody), 256))
		}

		var oaiResp oaiChatResponse
		if err := json.NewDecoder(httpResp.Body).Decode(&oaiResp); err != nil {
			httpResp.Body.Close()
			return nil, fmt.Errorf("decoding openai response: %w", err)
		}
		httpResp.Body.Close()
		parsed = &oaiResp
		break
	}

	if parsed == nil {
		return nil, fmt.Errorf("openai completion failed after %d retries: %w", o.maxRetries, lastErr)
	}

	return o.parseResponse(parsed), nil
}

// --- Stream ---

func (o *OpenAIProvider) Stream(ctx context.Context, req CompletionRequest) (<-chan StreamChunk, error) {
	body := o.buildRequest(req, true)
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling openai stream request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.endpoint+"/chat/completions", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("creating openai stream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	if o.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)
	}

	httpResp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai stream request failed: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(httpResp.Body)
		httpResp.Body.Close()
		return nil, fmt.Errorf("openai stream returned status %d: %s", httpResp.StatusCode, truncate(string(respBody), 256))
	}

	ch := make(chan StreamChunk, 100)

	go func() {
		defer close(ch)
		defer httpResp.Body.Close()

		scanner := bufio.NewScanner(httpResp.Body)
		// SSE lines can exceed bufio's default 64KB on long content;
		// raise to 1 MiB which comfortably fits any single OpenAI event.
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				ch <- StreamChunk{Done: true}
				return
			}

			var chunk oaiStreamChunk
			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				continue
			}

			for _, choice := range chunk.Choices {
				if choice.Delta.Content != "" {
					ch <- StreamChunk{Delta: choice.Delta.Content}
				}
				for _, tc := range choice.Delta.ToolCalls {
					ch <- StreamChunk{
						ToolCallDelta: &ToolCallDelta{
							ID:             tc.ID,
							Name:           tc.Function.Name,
							ArgumentsDelta: tc.Function.Arguments,
						},
					}
				}
			}
		}
	}()

	return ch, nil
}

// --- HealthCheck ---

func (o *OpenAIProvider) HealthCheck(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", o.endpoint+"/models", nil)
	if err != nil {
		return fmt.Errorf("creating openai health check request: %w", err)
	}
	if o.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)
	}

	resp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("openai-compatible endpoint not reachable at %s: %w", o.endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("openai-compatible endpoint at %s returned 401 — check API key", o.endpoint)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("openai-compatible endpoint at %s returned status %d", o.endpoint, resp.StatusCode)
	}

	return nil
}

func (o *OpenAIProvider) ModelName() string     { return o.model }
func (o *OpenAIProvider) ContextWindow() int    { return o.contextWindow }
func (o *OpenAIProvider) SupportsToolUse() bool { return o.supportsToolUse }

// --- helpers ---

func (o *OpenAIProvider) buildRequest(req CompletionRequest, stream bool) oaiChatRequest {
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 8192
	}

	var messages []oaiMessage

	if req.SystemPrompt != "" {
		messages = append(messages, oaiMessage{
			Role:    "system",
			Content: req.SystemPrompt,
		})
	}

	for _, msg := range req.Messages {
		messages = append(messages, oaiMessage{
			Role:       msg.Role,
			Content:    msg.Content,
			ToolCallID: msg.ToolCallID,
		})
	}

	r := oaiChatRequest{
		Model:       o.model,
		Messages:    messages,
		MaxTokens:   maxTokens,
		Temperature: req.Temperature,
		Stream:      stream,
	}

	// Strip tools when native tool-use is disabled; callers will fall back
	// to the JSON-in-prompt path that already serves Ollama / LM Studio.
	if o.supportsToolUse {
		for _, t := range req.Tools {
			r.Tools = append(r.Tools, oaiTool{
				Type: "function",
				Function: oaiToolFunction{
					Name:        t.Name,
					Description: t.Description,
					Parameters:  t.Parameters,
				},
			})
		}
	}

	return r
}

func (o *OpenAIProvider) parseResponse(resp *oaiChatResponse) *CompletionResponse {
	result := &CompletionResponse{
		Usage: Usage{
			InputTokens:  resp.Usage.PromptTokens,
			OutputTokens: resp.Usage.CompletionTokens,
		},
	}

	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		result.Content = choice.Message.Content
		result.StopReason = choice.FinishReason

		for _, tc := range choice.Message.ToolCalls {
			result.ToolCalls = append(result.ToolCalls, ToolCall{
				ID:        tc.ID,
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			})
		}
	}

	return result
}

func openaiBackoff(ctx context.Context, attempt int) error {
	backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
	jitter := time.Duration(rand.Int63n(int64(time.Second)))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(backoff + jitter):
		return nil
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

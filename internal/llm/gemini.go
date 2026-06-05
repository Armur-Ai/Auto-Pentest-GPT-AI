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
	"net/url"
	"strings"
	"time"
)

// GeminiProvider implements Provider against Google's first-party
// Generative Language API (generativelanguage.googleapis.com/v1beta).
// Gemini doesn't expose an OpenAI-compatible endpoint, so this is a
// separate wire format from OpenAIProvider. The Vertex AI flavour
// (vertexai.googleapis.com, OAuth bearer tokens) is intentionally
// not handled here — most researchers want the simpler first-party
// path; a Vertex provider can land later if there's demand.
//
// Closes #15.
type GeminiProvider struct {
	endpoint        string
	apiKey          string
	model           string
	contextWindow   int
	maxRetries      int
	httpClient      *http.Client
	supportsToolUse bool
}

// GeminiProviderConfig holds configuration for creating a GeminiProvider.
type GeminiProviderConfig struct {
	APIKey        string
	Endpoint      string // base URL, default https://generativelanguage.googleapis.com/v1beta
	Model         string // e.g. gemini-2.5-flash, gemini-2.5-pro
	ContextWindow int    // default 1_000_000 (Gemini 2.5 tier)
	MaxRetries    int
	// DisableToolUse forces JSON-in-prompt mode. Gemini's function
	// calling is reliable for the flagship models but can be flaky on
	// smaller variants; the flag lets callers opt out per agent.
	DisableToolUse bool
}

// NewGeminiProvider creates a new Gemini provider.
func NewGeminiProvider(cfg GeminiProviderConfig) *GeminiProvider {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.ContextWindow <= 0 {
		cfg.ContextWindow = 1_000_000
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://generativelanguage.googleapis.com/v1beta"
	}
	cfg.Endpoint = strings.TrimRight(cfg.Endpoint, "/")

	return &GeminiProvider{
		endpoint:        cfg.Endpoint,
		apiKey:          cfg.APIKey,
		model:           cfg.Model,
		contextWindow:   cfg.ContextWindow,
		maxRetries:      cfg.MaxRetries,
		supportsToolUse: !cfg.DisableToolUse,
		httpClient: &http.Client{
			Timeout: 10 * time.Minute,
		},
	}
}

// --- wire format (Gemini generateContent) ---

type gemRequest struct {
	SystemInstruction *gemSystemInstruction `json:"systemInstruction,omitempty"`
	Contents          []gemContent          `json:"contents"`
	Tools             []gemTool             `json:"tools,omitempty"`
	GenerationConfig  *gemGenConfig         `json:"generationConfig,omitempty"`
}

type gemSystemInstruction struct {
	Parts []gemPart `json:"parts"`
}

type gemContent struct {
	Role  string    `json:"role"` // "user" or "model"
	Parts []gemPart `json:"parts"`
}

// gemPart is a discriminated union: exactly one of Text or FunctionCall
// is populated. We use omitempty + a *gemFunctionCall pointer so the
// JSON encoder emits only the variant present.
type gemPart struct {
	Text         string           `json:"text,omitempty"`
	FunctionCall *gemFunctionCall `json:"functionCall,omitempty"`
}

type gemFunctionCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

type gemTool struct {
	FunctionDeclarations []gemFunctionDeclaration `json:"functionDeclarations"`
}

type gemFunctionDeclaration struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type gemGenConfig struct {
	Temperature     float64 `json:"temperature,omitempty"`
	MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
}

type gemResponse struct {
	Candidates    []gemCandidate `json:"candidates"`
	UsageMetadata gemUsage       `json:"usageMetadata"`
}

type gemCandidate struct {
	Content      gemContent `json:"content"`
	FinishReason string     `json:"finishReason"`
}

type gemUsage struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

type gemErrorResponse struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// --- Complete ---

func (g *GeminiProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	body := g.buildRequest(req)

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling gemini request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/models/%s:generateContent?key=%s",
		g.endpoint, url.PathEscape(g.model), url.QueryEscape(g.apiKey))

	var parsed *gemResponse
	var lastErr error

	for attempt := 0; attempt <= g.maxRetries; attempt++ {
		httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonBody))
		if err != nil {
			return nil, fmt.Errorf("creating gemini request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")

		httpResp, err := g.httpClient.Do(httpReq)
		if err != nil {
			lastErr = err
			if attempt == g.maxRetries {
				return nil, fmt.Errorf("gemini request failed: %w", lastErr)
			}
			if backoffErr := geminiBackoff(ctx, attempt); backoffErr != nil {
				return nil, backoffErr
			}
			continue
		}

		// Retry on 429 (rate-limit) and 5xx (server-side).
		if httpResp.StatusCode == http.StatusTooManyRequests || httpResp.StatusCode >= 500 {
			respBody, _ := io.ReadAll(httpResp.Body)
			httpResp.Body.Close()
			lastErr = fmt.Errorf("gemini returned status %d: %s", httpResp.StatusCode, truncate(string(respBody), 256))
			if attempt == g.maxRetries {
				return nil, lastErr
			}
			if backoffErr := geminiBackoff(ctx, attempt); backoffErr != nil {
				return nil, backoffErr
			}
			continue
		}

		if httpResp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(httpResp.Body)
			httpResp.Body.Close()
			return nil, fmt.Errorf("gemini returned status %d: %s", httpResp.StatusCode, truncate(string(respBody), 256))
		}

		var gemResp gemResponse
		if err := json.NewDecoder(httpResp.Body).Decode(&gemResp); err != nil {
			httpResp.Body.Close()
			return nil, fmt.Errorf("decoding gemini response: %w", err)
		}
		httpResp.Body.Close()
		parsed = &gemResp
		break
	}

	if parsed == nil {
		return nil, fmt.Errorf("gemini completion failed after %d retries: %w", g.maxRetries, lastErr)
	}

	return g.parseResponse(parsed), nil
}

// --- Stream ---

func (g *GeminiProvider) Stream(ctx context.Context, req CompletionRequest) (<-chan StreamChunk, error) {
	body := g.buildRequest(req)
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling gemini stream request: %w", err)
	}

	endpoint := fmt.Sprintf("%s/models/%s:streamGenerateContent?alt=sse&key=%s",
		g.endpoint, url.PathEscape(g.model), url.QueryEscape(g.apiKey))

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("creating gemini stream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	httpResp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini stream request failed: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(httpResp.Body)
		httpResp.Body.Close()
		return nil, fmt.Errorf("gemini stream returned status %d: %s", httpResp.StatusCode, truncate(string(respBody), 256))
	}

	ch := make(chan StreamChunk, 100)

	go func() {
		defer close(ch)
		defer httpResp.Body.Close()

		scanner := bufio.NewScanner(httpResp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := strings.TrimPrefix(line, "data: ")

			var chunk gemResponse
			if err := json.Unmarshal([]byte(data), &chunk); err != nil {
				continue
			}

			for _, cand := range chunk.Candidates {
				for _, part := range cand.Content.Parts {
					if part.Text != "" {
						ch <- StreamChunk{Delta: part.Text}
					}
					if part.FunctionCall != nil {
						argsJSON, _ := json.Marshal(part.FunctionCall.Args)
						ch <- StreamChunk{
							ToolCallDelta: &ToolCallDelta{
								Name:           part.FunctionCall.Name,
								ArgumentsDelta: string(argsJSON),
							},
						}
					}
				}
				if cand.FinishReason != "" {
					ch <- StreamChunk{Done: true}
					return
				}
			}
		}
	}()

	return ch, nil
}

// --- HealthCheck ---

func (g *GeminiProvider) HealthCheck(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/models?key=%s", g.endpoint, url.QueryEscape(g.apiKey))

	httpReq, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("creating gemini health check request: %w", err)
	}

	resp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("gemini endpoint not reachable at %s: %w", g.endpoint, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("gemini endpoint at %s returned %d — check API key (get one at https://aistudio.google.com/apikey)", g.endpoint, resp.StatusCode)
	default:
		return fmt.Errorf("gemini endpoint at %s returned status %d", g.endpoint, resp.StatusCode)
	}
}

func (g *GeminiProvider) ModelName() string     { return g.model }
func (g *GeminiProvider) ContextWindow() int    { return g.contextWindow }
func (g *GeminiProvider) SupportsToolUse() bool { return g.supportsToolUse }

// --- helpers ---

// buildRequest converts our standardized CompletionRequest into Gemini's
// generateContent wire format. Two role translations matter:
//   - "system" messages get hoisted into the top-level systemInstruction
//     field (Gemini has no inline "system" role inside contents).
//   - "assistant" messages become role "model" inside contents.
//
// Tool round-trip (sending a tool-result back to the LLM) isn't wired
// here yet because no caller round-trips Gemini tool calls today; can
// be extended when the swarm grows a code path that needs it.
func (g *GeminiProvider) buildRequest(req CompletionRequest) gemRequest {
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 8192
	}

	r := gemRequest{
		GenerationConfig: &gemGenConfig{
			Temperature:     req.Temperature,
			MaxOutputTokens: maxTokens,
		},
	}

	if req.SystemPrompt != "" {
		r.SystemInstruction = &gemSystemInstruction{
			Parts: []gemPart{{Text: req.SystemPrompt}},
		}
	}

	for _, msg := range req.Messages {
		role := msg.Role
		if role == "assistant" {
			role = "model"
		}
		// Skip any system messages embedded in Messages — they would be
		// silently coerced to "user" otherwise. Callers should use
		// SystemPrompt for this.
		if role == "system" {
			continue
		}
		r.Contents = append(r.Contents, gemContent{
			Role:  role,
			Parts: []gemPart{{Text: msg.Content}},
		})
	}

	if g.supportsToolUse && len(req.Tools) > 0 {
		decls := make([]gemFunctionDeclaration, 0, len(req.Tools))
		for _, t := range req.Tools {
			decls = append(decls, gemFunctionDeclaration{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			})
		}
		r.Tools = []gemTool{{FunctionDeclarations: decls}}
	}

	return r
}

// parseResponse converts a Gemini generateContent response into the
// standardized CompletionResponse. Concatenates all text parts and
// emits one ToolCall per functionCall part (with args serialized to a
// JSON string to match the OpenAI / our standardised convention).
func (g *GeminiProvider) parseResponse(resp *gemResponse) *CompletionResponse {
	result := &CompletionResponse{
		Usage: Usage{
			InputTokens:  resp.UsageMetadata.PromptTokenCount,
			OutputTokens: resp.UsageMetadata.CandidatesTokenCount,
		},
	}

	if len(resp.Candidates) == 0 {
		return result
	}

	cand := resp.Candidates[0]
	result.StopReason = cand.FinishReason

	var textParts []string
	for _, part := range cand.Content.Parts {
		if part.Text != "" {
			textParts = append(textParts, part.Text)
		}
		if part.FunctionCall != nil {
			argsJSON, _ := json.Marshal(part.FunctionCall.Args)
			result.ToolCalls = append(result.ToolCalls, ToolCall{
				Name:      part.FunctionCall.Name,
				Arguments: string(argsJSON),
			})
		}
	}
	result.Content = strings.Join(textParts, "")

	return result
}

func geminiBackoff(ctx context.Context, attempt int) error {
	backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
	jitter := time.Duration(rand.Int63n(int64(time.Second)))
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(backoff + jitter):
		return nil
	}
}

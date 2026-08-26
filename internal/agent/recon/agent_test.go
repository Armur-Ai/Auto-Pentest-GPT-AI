package recon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/tools"
	"github.com/google/uuid"
)

type scriptedProvider struct {
	responses []string
	errors    []error
	calls     int
}

func (p *scriptedProvider) Complete(_ context.Context, _ llm.CompletionRequest) (*llm.CompletionResponse, error) {
	call := p.calls
	p.calls++
	if call < len(p.errors) && p.errors[call] != nil {
		return nil, p.errors[call]
	}
	return &llm.CompletionResponse{Content: p.responses[call]}, nil
}

func (p *scriptedProvider) Stream(context.Context, llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	return nil, errors.New("not implemented")
}

func (p *scriptedProvider) HealthCheck(context.Context) error { return nil }
func (p *scriptedProvider) ModelName() string                 { return "scripted" }
func (p *scriptedProvider) ContextWindow() int                { return 8192 }
func (p *scriptedProvider) SupportsToolUse() bool             { return false }

func TestAnalyze_ReconcilesToolFindingsWhenValidLLMOutputDrifts(t *testing.T) {
	provider := &scriptedProvider{responses: []string{`{"host":"example.com","ports":[443]}`}}
	var degradedErr error
	agent := NewReconAgent(provider, nil, WithErrorSink(func(err error) { degradedErr = err }))
	results := []*tools.ToolResult{
		{
			ToolName: "katana",
			ParsedFindings: []map[string]any{
				{"request": map[string]any{"endpoint": "https://example.com/a"}},
				{"request": map[string]any{"endpoint": "https://example.com/b"}},
			},
		},
		{
			ToolName: "dnsx",
			ParsedFindings: []map[string]any{
				{"host": "192.0.2.10", "subdomain": "api.example.com"},
			},
		},
	}
	campaignID := uuid.New()

	surface, err := agent.Analyze(context.Background(), results, campaignID)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(surface.Endpoints) != 2 || surface.Endpoints[0].URL != "https://example.com/a" || surface.Endpoints[1].URL != "https://example.com/b" {
		t.Fatalf("Katana endpoints were not preserved: %+v", surface.Endpoints)
	}
	if len(surface.Hosts) != 1 || surface.Hosts[0].IP != "192.0.2.10" {
		t.Fatalf("tool host was not preserved: %+v", surface.Hosts)
	}
	if len(surface.Subdomains) != 1 || surface.Subdomains[0].Domain != "api.example.com" {
		t.Fatalf("tool subdomain was not preserved: %+v", surface.Subdomains)
	}
	if surface.CampaignID != campaignID || surface.CreatedAt.IsZero() {
		t.Fatalf("surface metadata not stamped: %+v", surface)
	}
	if degradedErr == nil {
		t.Fatal("expected degraded-mode error when tool findings recover LLM omissions")
	}
}

func TestAnalyze_ParseFailureFallbackPreservesToolFindings(t *testing.T) {
	results := []*tools.ToolResult{{
		ToolName:       "katana",
		ParsedFindings: []map[string]any{{"request": map[string]any{"endpoint": "https://example.com/recovered"}}},
	}}

	t.Run("non-strict", func(t *testing.T) {
		provider := &scriptedProvider{responses: []string{"not json", "still not json"}}
		var degradedErr error
		agent := NewReconAgent(provider, nil, WithErrorSink(func(err error) { degradedErr = err }))

		surface, err := agent.Analyze(context.Background(), results, uuid.New())
		if err != nil {
			t.Fatalf("Analyze: %v", err)
		}
		if len(surface.Endpoints) != 1 || surface.Endpoints[0].URL != "https://example.com/recovered" {
			t.Fatalf("fallback surface lost deterministic endpoint: %+v", surface.Endpoints)
		}
		if degradedErr == nil || !strings.Contains(degradedErr.Error(), "recon analysis returned empty surface") {
			t.Fatalf("degraded error = %v, want parse-fallback signal", degradedErr)
		}
	})

	t.Run("strict", func(t *testing.T) {
		provider := &scriptedProvider{responses: []string{"not json", "still not json"}}
		agent := NewReconAgent(provider, nil, WithStrict())

		surface, err := agent.Analyze(context.Background(), results, uuid.New())
		if err == nil || !strings.Contains(err.Error(), "recon parse failed after retry") {
			t.Fatalf("error = %v, want existing strict parse error", err)
		}
		if surface != nil {
			t.Fatalf("strict mode returned fallback surface: %+v", surface)
		}
	})
}

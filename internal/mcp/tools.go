package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/engine"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// RegisterDefaultTools adds all pentestswarm tools to the MCP server.
func RegisterDefaultTools(s *Server, cfg *config.Config) {
	runner := engine.NewRunner(cfg)

	s.RegisterTool(MCPTool{
		Name:        "scan_target",
		Description: "Start a full autonomous penetration test against a target. Returns findings summary when complete.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"target":{"type":"string","description":"Target domain or IP"},"scope":{"type":"string","description":"Scope (CIDR or domain)"},"objective":{"type":"string","description":"What to find (default: find all vulnerabilities)"}},"required":["target","scope"]}`),
		Handler: func(args json.RawMessage) (string, error) {
			var params struct {
				Target    string `json:"target"`
				Scope     string `json:"scope"`
				Objective string `json:"objective"`
			}
			if err := json.Unmarshal(args, &params); err != nil {
				return "", err
			}
			if params.Objective == "" {
				params.Objective = "find all vulnerabilities"
			}

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			defer cancel()

			var events []string
			cc := engine.CampaignConfig{
				Target:    params.Target,
				Scope:     strings.Split(params.Scope, ","),
				Objective: params.Objective,
				Mode:      "manual",
				Format:    "md",
				OutputDir: "./reports",
			}

			err := runner.Run(ctx, cc, func(event pipeline.CampaignEvent) {
				events = append(events, fmt.Sprintf("[%s] %s: %s", event.EventType, event.AgentName, event.Detail))
			})

			result := strings.Join(events, "\n")
			if err != nil {
				result += "\n\nError: " + err.Error()
			}

			return result, nil
		},
	})

	s.RegisterTool(MCPTool{
		Name:        "quick_recon",
		Description: "Run reconnaissance only against a target, returning the discovered attack surface (subdomains, ports, services, technologies).",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"target":{"type":"string","description":"Target to scan"}},"required":["target"]}`),
		Handler: func(args json.RawMessage) (string, error) {
			var params struct {
				Target string `json:"target"`
			}
			json.Unmarshal(args, &params)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			var events []string
			cc := engine.CampaignConfig{
				Target:    params.Target,
				Scope:     []string{params.Target},
				Objective: "reconnaissance only",
				Mode:      "manual",
				DryRun:    true, // no exploitation
				Format:    "md",
				OutputDir: "./reports",
			}

			runner.Run(ctx, cc, func(event pipeline.CampaignEvent) {
				if event.EventType == pipeline.EventToolResult || event.EventType == pipeline.EventFindingDiscovered {
					events = append(events, event.Detail)
				}
			})

			if len(events) == 0 {
				return "No results found for " + params.Target, nil
			}
			return strings.Join(events, "\n"), nil
		},
	})

	s.RegisterTool(MCPTool{
		Name:        "explain_finding",
		Description: "Explain a security vulnerability in plain English, tailored to the specified audience.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"description":{"type":"string","description":"Vulnerability description or CVE ID"},"audience":{"type":"string","enum":["developer","manager","executive"],"description":"Target audience for the explanation"}},"required":["description"]}`),
		Handler: func(args json.RawMessage) (string, error) {
			var params struct {
				Description string `json:"description"`
				Audience    string `json:"audience"`
			}
			json.Unmarshal(args, &params)
			if params.Audience == "" {
				params.Audience = "developer"
			}
			// In production, this calls the LLM with an audience-appropriate prompt
			return fmt.Sprintf("Explaining '%s' for %s audience:\n\nThis vulnerability needs to be assessed in the context of your specific environment. Use 'pentestswarm explain <finding-id> --audience %s' for a detailed AI-generated explanation.", params.Description, params.Audience, params.Audience), nil
		},
	})

	s.RegisterTool(MCPTool{
		Name:        "campaign_status",
		Description: "Get the current status of a running penetration test campaign.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"campaign_id":{"type":"string","description":"Campaign UUID"}},"required":["campaign_id"]}`),
		Handler: func(args json.RawMessage) (string, error) {
			var params struct {
				CampaignID string `json:"campaign_id"`
			}
			json.Unmarshal(args, &params)
			return fmt.Sprintf("Campaign %s: check status via API at http://localhost:8080/api/v1/campaigns/%s", params.CampaignID, params.CampaignID), nil
		},
	})

	s.RegisterTool(MCPTool{
		Name:        "list_tools",
		Description: "List all available security scanning tools and their status.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler: func(args json.RawMessage) (string, error) {
			tools := []string{
				"subfinder — passive subdomain discovery",
				"httpx — HTTP probing with technology detection",
				"nuclei — template-based vulnerability scanning",
				"naabu — fast port scanning",
				"katana — web crawling and endpoint discovery",
				"dnsx — DNS resolution and reverse lookups",
				"gau — fetch known URLs from Wayback Machine, Common Crawl",
			}
			return "Available security tools:\n\n" + strings.Join(tools, "\n"), nil
		},
	})
}

package plugins

import (
	"context"
	"fmt"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/engine"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// PlaybookRunner executes a playbook using the campaign engine.
type PlaybookRunner struct {
	cfg *config.Config
}

// NewPlaybookRunner creates a playbook runner.
func NewPlaybookRunner(cfg *config.Config) *PlaybookRunner {
	return &PlaybookRunner{cfg: cfg}
}

// Run executes a playbook against a target.
func (r *PlaybookRunner) Run(ctx context.Context, pb *Playbook, target string, variables map[string]string, onEvent engine.EventCallback) error {
	resolved, err := resolveVariables(pb, target, variables)
	if err != nil {
		return err
	}
	variables = resolved

	// Build objective from playbook phases
	var objectives []string
	for _, phase := range pb.Phases {
		desc := phase.Name
		if phase.PostAnalysis != "" {
			desc += ": " + strings.TrimSpace(phase.PostAnalysis)
		}
		if phase.Strategy != "" {
			desc += " Strategy: " + strings.TrimSpace(phase.Strategy)
		}
		objectives = append(objectives, desc)
	}

	objective := fmt.Sprintf("Execute playbook '%s': %s", pb.Name, strings.Join(objectives, " → "))

	// Build scope from target
	scope := []string{target}
	if targetVar, ok := variables["target_domain"]; ok {
		scope = []string{targetVar}
	}

	cc := engine.CampaignConfig{
		Target:    target,
		Scope:     scope,
		Objective: objective,
		Mode:      "manual",
		Format:    "md",
		OutputDir: "./reports",
	}

	if onEvent != nil {
		onEvent(pipeline.CampaignEvent{
			EventType: pipeline.EventThought,
			AgentName: "playbook",
			Detail:    fmt.Sprintf("Running playbook: %s by %s", pb.Name, pb.Author.Name),
		})
	}

	runner := engine.NewRunner(r.cfg)
	return runner.Run(ctx, cc, onEvent)
}

// resolveVariables seeds the implicit `target_domain` binding from the CLI
// --target flag, then validates that every required playbook variable has
// either a caller-supplied value or a declared default. Extracted from Run
// so #17's auto-binding has a unit test that doesn't need an LLM.
func resolveVariables(pb *Playbook, target string, vars map[string]string) (map[string]string, error) {
	if vars == nil {
		vars = make(map[string]string)
	}
	if _, ok := vars["target_domain"]; !ok && target != "" {
		vars["target_domain"] = target
	}
	for key, v := range pb.Variables {
		if _, ok := vars[key]; !ok && v.Required {
			if v.Default != "" {
				vars[key] = v.Default
				continue
			}
			return nil, fmt.Errorf("required variable %q not provided", key)
		}
	}
	return vars, nil
}

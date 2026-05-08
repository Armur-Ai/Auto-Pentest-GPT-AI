package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/classifier"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/exploit"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/recon"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/memory"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/tools"
	"github.com/google/uuid"
)

// CampaignConfig holds everything needed to run a campaign.
type CampaignConfig struct {
	Target    string
	Scope     []string // domains and/or CIDRs
	Objective string
	Mode      string
	DryRun    bool
	OutputDir string
	Format    string
	Provider  string // override config provider
	APIKey    string // override config API key

	// ExplorationBias scales pheromone weights in the swarm path.
	// "", "med" = default (1.0×); "low" = 0.7× (depth-first); "high" = 1.3× (breadth-first).
	ExplorationBias string

	// PublishThreshold is the minimum pheromone a finding must have to
	// appear in the final report. Default (0.5) is "bugbounty mode" —
	// only verified / not-superseded findings ship. 0.1 is "aggressive
	// mode" which includes suspected-but-unverified findings.
	PublishThreshold float64

	// Assist, when true, prompts the operator y/N before every executed
	// step. Designed for researchers running against fragile programs
	// where breaking the relationship is more costly than slower scans.
	// See cli.assistConfirm for the TTY implementation.
	Assist bool
}

// EventCallback is called for every campaign event (for TUI/streaming).
type EventCallback func(event pipeline.CampaignEvent)

// Runner executes a full campaign pipeline.
type Runner struct {
	cfg         *config.Config
	memoryStore *memory.MemoryStore
	cleanup     pipeline.CleanupRegistryIface
	strict      bool
	assist      exploit.ConfirmFunc // optional; nil = no human-in-the-loop
}

// Option customises Runner construction.
type Option func(*Runner)

// WithCleanupRegistry attaches a cleanup registry (Postgres or memory).
// If no option is passed, the runner falls back to an in-memory registry
// that executes cleanup commands via /bin/sh -c.
func WithCleanupRegistry(reg pipeline.CleanupRegistryIface) Option {
	return func(r *Runner) { r.cleanup = reg }
}

// WithStrictLLM turns any LLM error into a fatal campaign failure.
// Without strict mode, the runner continues with degraded output but
// emits error events to the stream.
func WithStrictLLM() Option {
	return func(r *Runner) { r.strict = true }
}

// WithAssistConfirmer wires a human-in-the-loop hook that's called
// before every executed step in assist mode (4.6.4). Only fires when
// CampaignConfig.Assist is also true — the option installs the
// callback; the flag turns it on.
func WithAssistConfirmer(fn exploit.ConfirmFunc) Option {
	return func(r *Runner) { r.assist = fn }
}

// NewRunner creates a campaign runner.
func NewRunner(cfg *config.Config, opts ...Option) *Runner {
	r := &Runner{
		cfg:         cfg,
		memoryStore: memory.NewMemoryStore(),
	}
	for _, opt := range opts {
		opt(r)
	}
	if r.cleanup == nil {
		r.cleanup = pipeline.NewMemoryCleanupRegistry(pipeline.DefaultCleanupExec)
	}
	return r
}

// Run executes a complete penetration test campaign.
func (r *Runner) Run(ctx context.Context, cc CampaignConfig, onEvent EventCallback) error {
	start := time.Now()
	campaignID := uuid.New()

	// Build scope definition
	scopeDef, err := buildScope(cc.Scope)
	if err != nil {
		return fmt.Errorf("invalid scope: %w", err)
	}

	// Create campaign
	campaign := pipeline.Campaign{
		ID:        campaignID,
		Name:      fmt.Sprintf("scan-%s-%s", cc.Target, time.Now().Format("20060102-150405")),
		Target:    cc.Target,
		Objective: cc.Objective,
		Status:    pipeline.StatusPlanned,
		Mode:      pipeline.CampaignMode(cc.Mode),
		Scope: pipeline.ScopeDefinition{
			AllowedDomains: scopeDef.AllowedDomains,
			AllowedCIDRs:   scopeDef.AllowedCIDRs,
		},
		CreatedAt: time.Now(),
	}

	emit := func(eventType pipeline.EventType, agent, detail string) {
		if onEvent != nil {
			onEvent(pipeline.CampaignEvent{
				ID:         uuid.New(),
				CampaignID: campaignID,
				Timestamp:  time.Now(),
				EventType:  eventType,
				AgentName:  agent,
				Detail:     detail,
			})
		}
	}

	// State machine
	sm := pipeline.NewStateMachine(&campaign, func(e pipeline.CampaignEvent) {
		if onEvent != nil {
			onEvent(e)
		}
	})

	// Initialize LLM provider
	orchestratorCfg := r.cfg.Orchestrator
	if cc.Provider != "" {
		orchestratorCfg.Provider = cc.Provider
	}
	if cc.APIKey != "" {
		orchestratorCfg.APIKey = cc.APIKey
	}

	provider, err := llm.NewProvider(orchestratorCfg)
	if err != nil {
		return fmt.Errorf("failed to create LLM provider: %w", err)
	}

	emit(pipeline.EventStateChange, "engine", "Campaign initialized")

	// Always run registered cleanup on exit — normal completion, failure,
	// or context cancellation (SIGINT). Uses a detached context so cleanup
	// still runs after the campaign context is cancelled.
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		if rep := r.cleanup.RunCleanup(cleanupCtx, campaignID); rep != nil && rep.TotalCount > 0 {
			emit(pipeline.EventMilestone, "cleanup",
				fmt.Sprintf("Cleanup ran %d actions (%d executed, %d failed)",
					rep.TotalCount, len(rep.Executed), len(rep.Failed)))
		}
	}()

	// --- Phase 1: RECON ---
	if err := sm.Start(); err != nil {
		return err
	}
	if err := sm.BeginRecon(); err != nil {
		return err
	}

	emit(pipeline.EventThought, "orchestrator", fmt.Sprintf("Starting reconnaissance on %s", cc.Target))

	coordinator := tools.NewCoordinator()

	reconOpts := []recon.Option{
		recon.WithErrorSink(func(err error) {
			emit(pipeline.EventError, "recon", err.Error())
		}),
	}
	if r.strict {
		reconOpts = append(reconOpts, recon.WithStrict())
	}
	reconAgent := recon.NewReconAgent(provider, coordinator, reconOpts...)
	reconPlan := reconAgent.PlanRecon(cc.Target)

	emit(pipeline.EventToolCall, "recon", fmt.Sprintf("Running tools: %s", strings.Join(reconPlan.ToolOrder, ", ")))

	surface, err := reconAgent.Execute(ctx, reconPlan, &scope.ScopeDefinition{
		AllowedDomains: scopeDef.AllowedDomains,
		AllowedCIDRs:   scopeDef.AllowedCIDRs,
	}, campaignID)
	if err != nil {
		emit(pipeline.EventError, "recon", fmt.Sprintf("Recon failed: %s", err))
		sm.Fail("recon failed")
		return fmt.Errorf("recon failed: %w", err)
	}

	emit(pipeline.EventToolResult, "recon", fmt.Sprintf("Found %d subdomains, %d hosts, %d endpoints",
		len(surface.Subdomains), len(surface.Hosts), len(surface.Endpoints)))

	// --- Phase 2: CLASSIFY ---
	if err := sm.BeginClassifying(); err != nil {
		return err
	}

	emit(pipeline.EventThought, "orchestrator", "Classifying findings — mapping CVEs, scoring CVSS, filtering false positives")

	classifierOpts := []classifier.Option{
		classifier.WithErrorSink(func(err error) {
			emit(pipeline.EventError, "classifier", err.Error())
		}),
	}
	if r.strict {
		classifierOpts = append(classifierOpts, classifier.WithStrict())
	}
	classifierAgent := classifier.NewClassifierAgent(provider, classifierOpts...)

	// Build raw findings from attack surface
	rawFindings := extractRawFindings(surface, campaignID)

	emit(pipeline.EventToolCall, "classifier", fmt.Sprintf("Classifying %d raw findings", len(rawFindings)))

	findingSet, err := classifierAgent.Classify(ctx, campaignID, rawFindings)
	if err != nil {
		emit(pipeline.EventError, "classifier", fmt.Sprintf("Classification failed: %s", err))
		sm.Fail("classification failed")
		return fmt.Errorf("classification failed: %w", err)
	}

	for _, f := range findingSet.Findings {
		// Carry the full finding in event.Data so the API / dashboard can
		// render severity and CVSS without re-parsing the detail string.
		data, _ := json.Marshal(f)
		if onEvent != nil {
			onEvent(pipeline.CampaignEvent{
				ID:         uuid.New(),
				CampaignID: campaignID,
				Timestamp:  time.Now(),
				EventType:  pipeline.EventFindingDiscovered,
				AgentName:  "classifier",
				Detail:     fmt.Sprintf("[%s] %s (CVSS: %.1f) on %s", strings.ToUpper(string(f.Severity)), f.Title, f.CVSSScore, f.Target),
				Data:       data,
			})
		}
	}

	emit(pipeline.EventToolResult, "classifier", fmt.Sprintf("Classified %d findings (%d filtered as FP). Severity: %d critical, %d high, %d medium",
		findingSet.Summary.TotalFindings, findingSet.Summary.FilteredAsFP,
		findingSet.Summary.BySeverity[pipeline.SeverityCritical],
		findingSet.Summary.BySeverity[pipeline.SeverityHigh],
		findingSet.Summary.BySeverity[pipeline.SeverityMedium]))

	// --- Phase 3: PLAN ---
	if err := sm.BeginPlanning(); err != nil {
		return err
	}

	emit(pipeline.EventThought, "orchestrator", "Building attack plan — constructing exploitation chains")

	exploitAgent := exploit.NewExploitAgent(provider)

	var attackPlan *pipeline.AttackPlan
	if !cc.DryRun && len(findingSet.Findings) > 0 {
		attackPlan, err = exploitAgent.BuildPlan(ctx, *findingSet, cc.Objective)
		if err != nil {
			emit(pipeline.EventError, "exploit", fmt.Sprintf("Plan construction failed: %s", err))
		} else {
			emit(pipeline.EventToolResult, "exploit", fmt.Sprintf("Built %d attack paths. Top path: %s (%.0f%% estimated success)",
				len(attackPlan.Paths),
				pathName(attackPlan),
				pathProb(attackPlan)*100))
		}
	}

	// --- Phase 4: EXECUTE (if not dry-run) ---
	var execResults []pipeline.ExecutionResult
	if !cc.DryRun && attackPlan != nil && len(attackPlan.Paths) > 0 {
		if err := sm.BeginExecuting(); err != nil {
			return err
		}

		emit(pipeline.EventThought, "orchestrator", "Executing top attack paths")

		executor := exploit.NewExecutor(
			&scope.ScopeDefinition{AllowedDomains: scopeDef.AllowedDomains, AllowedCIDRs: scopeDef.AllowedCIDRs},
			r.cleanup,
			cc.DryRun,
		)

		for _, path := range attackPlan.Paths[:min(3, len(attackPlan.Paths))] {
			for _, step := range path.Steps {
				if step.Command == "" {
					continue
				}
				emit(pipeline.EventStepExecuted, "exploit", fmt.Sprintf("Executing: %s", step.Name))

				result, err := executor.Execute(ctx, step, campaignID)
				if err != nil {
					emit(pipeline.EventError, "exploit", fmt.Sprintf("Step failed: %s", err))
					continue
				}
				execResults = append(execResults, *result)

				if result.Success {
					emit(pipeline.EventToolResult, "exploit", fmt.Sprintf("Step succeeded: %s", step.Name))
				} else {
					emit(pipeline.EventToolResult, "exploit", fmt.Sprintf("Step failed: %s", step.Name))
				}
			}
		}
	}

	// --- Phase 5: REPORT ---
	if err := sm.BeginReporting(); err != nil {
		return err
	}

	emit(pipeline.EventThought, "orchestrator", "Generating penetration test report")

	reportAgent := report.NewReportAgent(provider)
	pentestReport, err := reportAgent.Generate(ctx, campaign, findingSet.Findings, attackPlan, execResults)
	if err != nil {
		emit(pipeline.EventError, "report", fmt.Sprintf("Report generation failed: %s", err))
		sm.Fail("report generation failed")
		return fmt.Errorf("report generation failed: %w", err)
	}

	// Render and save report
	renderer := report.NewRenderer()
	outputDir := cc.OutputDir
	if outputDir == "" {
		outputDir = "./reports"
	}
	os.MkdirAll(outputDir, 0755)

	reportPath := filepath.Join(outputDir, fmt.Sprintf("%s-%s", campaign.Name, campaignID.String()[:8]))

	if cc.Format == "all" || cc.Format == "md" || cc.Format == "" {
		md, _ := renderer.ToMarkdown(pentestReport)
		os.WriteFile(reportPath+".md", md, 0644)
		emit(pipeline.EventToolResult, "report", fmt.Sprintf("Markdown report: %s.md", reportPath))
	}
	if cc.Format == "all" || cc.Format == "json" {
		js, _ := renderer.ToJSON(pentestReport)
		os.WriteFile(reportPath+".json", js, 0644)
		emit(pipeline.EventToolResult, "report", fmt.Sprintf("JSON report: %s.json", reportPath))
	}
	if cc.Format == "all" || cc.Format == "html" {
		html, _ := renderer.ToHTML(pentestReport)
		os.WriteFile(reportPath+".html", html, 0644)
		emit(pipeline.EventToolResult, "report", fmt.Sprintf("HTML report: %s.html", reportPath))
	}
	if cc.Format == "all" || cc.Format == "sarif" {
		if sarif, err := renderer.ToSARIF(pentestReport); err == nil {
			os.WriteFile(reportPath+".sarif", sarif, 0644)
			emit(pipeline.EventToolResult, "report", fmt.Sprintf("SARIF report: %s.sarif", reportPath))
		}
	}

	// Complete
	sm.Complete()

	elapsed := time.Since(start).Round(time.Second)
	emit(pipeline.EventMilestone, "orchestrator", fmt.Sprintf(
		"Campaign complete in %s. %d findings (%d critical, %d high). Risk: %s. Report: %s",
		elapsed, len(findingSet.Findings),
		findingSet.Summary.BySeverity[pipeline.SeverityCritical],
		findingSet.Summary.BySeverity[pipeline.SeverityHigh],
		pentestReport.RiskSummary.OverallRisk,
		reportPath))

	// Save learned patterns to memory
	patterns := memory.ExtractPatterns(surface, findingSet.Findings)
	for _, p := range patterns {
		r.memoryStore.Save(p)
	}

	return nil
}

// --- Helpers ---

func buildScope(scopes []string) (*scope.ScopeDefinition, error) {
	def := &scope.ScopeDefinition{}
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// If it contains a /, treat as CIDR
		if strings.Contains(s, "/") {
			def.AllowedCIDRs = append(def.AllowedCIDRs, s)
		} else {
			def.AllowedDomains = append(def.AllowedDomains, s)
		}
	}
	if len(def.AllowedCIDRs) == 0 && len(def.AllowedDomains) == 0 {
		return nil, fmt.Errorf("scope must contain at least one domain or CIDR")
	}
	return def, nil
}

func extractRawFindings(surface *pipeline.AttackSurface, campaignID uuid.UUID) []pipeline.RawFinding {
	var findings []pipeline.RawFinding

	for _, host := range surface.Hosts {
		for _, port := range host.OpenPorts {
			svc := host.Services[port]
			detail := fmt.Sprintf("Port %d open", port)
			if svc.Name != "" {
				detail = fmt.Sprintf("Port %d open — %s %s", port, svc.Name, svc.Version)
			}
			findings = append(findings, pipeline.RawFinding{
				ID:           uuid.New(),
				CampaignID:   campaignID,
				Source:       "naabu",
				Type:         "open_port",
				Target:       host.IP,
				Detail:       detail,
				DiscoveredAt: time.Now(),
			})
		}
	}

	for _, ep := range surface.Endpoints {
		if ep.Interesting {
			findings = append(findings, pipeline.RawFinding{
				ID:           uuid.New(),
				CampaignID:   campaignID,
				Source:       "katana",
				Type:         "interesting_endpoint",
				Target:       ep.URL,
				Detail:       fmt.Sprintf("Interesting endpoint: %s (%s) — %s", ep.URL, ep.Method, ep.Notes),
				DiscoveredAt: time.Now(),
			})
		}
	}

	for tech, version := range surface.Technologies {
		findings = append(findings, pipeline.RawFinding{
			ID:           uuid.New(),
			CampaignID:   campaignID,
			Source:       "httpx",
			Type:         "technology",
			Target:       surface.Target,
			Detail:       fmt.Sprintf("Technology detected: %s %s", tech, version),
			DiscoveredAt: time.Now(),
		})
	}

	return findings
}

func pathName(plan *pipeline.AttackPlan) string {
	if len(plan.Paths) > 0 {
		return plan.Paths[0].Name
	}
	return "none"
}

func pathProb(plan *pipeline.AttackPlan) float64 {
	if len(plan.Paths) > 0 {
		return plan.Paths[0].EstimatedSuccessProbability
	}
	return 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Ensure json import is used (for future DB persistence)
var _ = json.Marshal

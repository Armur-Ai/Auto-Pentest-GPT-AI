package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/engine"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/keychain"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var scanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Launch the swarm against a target",
	Long:  `Deploys the AI agent swarm to autonomously pentest the specified target.`,
	Args:  cobra.ExactArgs(1),
	Example: `  pentestswarm scan example.com --scope example.com
  pentestswarm scan 10.0.0.0/24 --scope 10.0.0.0/24 --objective "find RCE"
  pentestswarm scan example.com --scope example.com --mode bugbounty --follow
  pentestswarm scan example.com --scope example.com --dry-run`,
	RunE: runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	// Phase 4.8.5: scope-from-target. If the researcher didn't pass --scope,
	// default to scanning only the target itself. This removes the most
	// common reason scans fail on first run: forgetting the flag. Single-
	// target scope is conservative (won't accidentally reach a sibling
	// domain), so the default is safe.
	scopeStr, _ := cmd.Flags().GetString("scope")
	if scopeStr == "" {
		scopeStr = target
		if !quiet {
			fmt.Printf("  %s no --scope set, defaulting to %s\n", colorDim("[scope]"), colorBold(target))
		}
	}

	objective, _ := cmd.Flags().GetString("objective")
	mode, _ := cmd.Flags().GetString("mode")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	follow, _ := cmd.Flags().GetBool("follow")
	format, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("output")
	providerOverride, _ := cmd.Flags().GetString("provider")
	explorationBias, _ := cmd.Flags().GetString("exploration-bias")
	publishUnverified, _ := cmd.Flags().GetBool("publish-unverified")
	assist, _ := cmd.Flags().GetBool("assist")
	estimate, _ := cmd.Flags().GetBool("estimate")
	safeMode, _ := cmd.Flags().GetBool("safe-mode")
	targetClass, _ := cmd.Flags().GetString("target-class")

	// --estimate short-circuits everything: print expected cost and exit
	// without touching the network. Fires before config validation so it
	// works even without an API key.
	if estimate {
		modelName := "claude-sonnet-4-6"
		if cfg, err := config.Load(cfgFile); err == nil && cfg.Orchestrator.Model != "" {
			modelName = cfg.Orchestrator.Model
		}
		lo, hi := llm.PricingFor(modelName).EstimateUSD(targetClass)
		fmt.Println()
		fmt.Printf("  %s target class: %s\n", colorCyan("[estimate]"), fallback(targetClass, "medium"))
		fmt.Printf("  %s model:        %s\n", colorCyan("[estimate]"), modelName)
		fmt.Printf("  %s expected LLM spend: %s\n", colorCyan("[estimate]"),
			colorBold(fmt.Sprintf("$%.2f – $%.2f", lo, hi)))
		fmt.Println(colorDim("  (No packets sent. Remove --estimate to run the scan.)"))
		return nil
	}

	// Load config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		// 4.8.3: every error message must end with a next-step. A bare
		// "loading config: ..." leaves the researcher guessing.
		return fmt.Errorf("loading config: %w\n  Fix: run %s to write a fresh config",
			err, colorCyan("pentestswarm init"))
	}

	// --safe-mode is advisory for now: the engine will consume this flag
	// in a follow-up commit to cap RPS + block destructive techniques.
	_ = safeMode

	// Resolve the API key: env first (CI-friendly), then OS keychain
	// (the path 'pentestswarm init' writes to), with config.yaml as the
	// last-resort fallback so old setups keep working.
	if cfg.Orchestrator.APIKey == "" {
		if key := os.Getenv("PENTESTSWARM_ORCHESTRATOR_API_KEY"); key != "" {
			cfg.Orchestrator.APIKey = key
		} else if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			cfg.Orchestrator.APIKey = key
		} else if key, err := keychain.Get(keychain.KeyClaudeAPI); err == nil && key != "" {
			cfg.Orchestrator.APIKey = key
		}
	}

	// First-run bootstrap: in an interactive terminal, prompt once instead
	// of failing. A researcher who just installed the tool deserves a
	// chance to paste their key without re-reading the docs.
	if cfg.Orchestrator.APIKey == "" && cfg.Orchestrator.Provider == "claude" {
		if !quiet && term.IsTerminal(int(os.Stdin.Fd())) {
			if key := promptForAPIKeyOnce(); key != "" {
				cfg.Orchestrator.APIKey = key
			}
		}
	}

	if cfg.Orchestrator.APIKey == "" && cfg.Orchestrator.Provider == "claude" {
		return errors.New("no API key configured.\n" +
			"  Fix one of these, then re-run:\n" +
			"    1) " + colorCyan("pentestswarm init") + "   (one-shot interactive setup)\n" +
			"    2) " + colorCyan("export PENTESTSWARM_ORCHESTRATOR_API_KEY=sk-ant-...") + "   (or ANTHROPIC_API_KEY)")
	}

	// Print banner
	if !quiet {
		printBanner()
		fmt.Println()
		fmt.Printf("  Target:     %s\n", colorBold(target))
		fmt.Printf("  Scope:      %s\n", scopeStr)
		fmt.Printf("  Objective:  %s\n", objective)
		fmt.Printf("  Mode:       %s\n", mode)
		fmt.Printf("  Provider:   %s\n", providerOrDefault(providerOverride, cfg.Orchestrator.Provider))
		if dryRun {
			fmt.Printf("  %s\n", colorYellow("DRY RUN — no exploitation commands will execute"))
		}
		fmt.Println()
		fmt.Println(colorDim("─────────────────────────────────────────────────────"))
		fmt.Println()
	}

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n" + colorRed("Emergency stop — shutting down swarm..."))
		cancel()
	}()

	// Build campaign config. publishThreshold is the verified-PoC gate:
	// default 0.5 ('bugbounty' — only confirmed findings ship), 0.1 when
	// --publish-unverified is set ('aggressive' — suspected-but-not-
	// reproduced findings included with a warning).
	publishThreshold := 0.5
	if publishUnverified {
		publishThreshold = 0.1
	}
	cc := engine.CampaignConfig{
		Target:           target,
		Scope:            strings.Split(scopeStr, ","),
		Objective:        objective,
		Mode:             mode,
		DryRun:           dryRun,
		OutputDir:        output,
		Format:           format,
		Provider:         providerOverride,
		PublishThreshold: publishThreshold,
		ExplorationBias: explorationBias,
		Assist:          assist,
	}

	// Event handler for live output
	var onEvent engine.EventCallback
	if follow || !quiet {
		onEvent = func(event pipeline.CampaignEvent) {
			printEvent(event)
		}
	}

	// Run the campaign
	var runnerOpts []engine.Option
	if strict, _ := cmd.Flags().GetBool("strict"); strict {
		runnerOpts = append(runnerOpts, engine.WithStrictLLM())
	}
	if assist {
		runnerOpts = append(runnerOpts, engine.WithAssistConfirmer(assistConfirm))
	}
	runner := engine.NewRunner(cfg, runnerOpts...)
	useSwarm, _ := cmd.Flags().GetBool("swarm")
	run := runner.Run
	if useSwarm {
		run = runner.RunSwarm
	}
	if err := run(ctx, cc, onEvent); err != nil {
		if ctx.Err() != nil {
			fmt.Println(colorRed("\nCampaign aborted by user."))
			return nil
		}
		return fmt.Errorf("campaign failed: %w\n  Next: re-run with %s to abort on first error and surface the root cause",
			err, colorCyan("--strict"))
	}

	if !quiet {
		fmt.Println()
		fmt.Println(colorGreen("Campaign complete."))
	}

	return nil
}

func printEvent(event pipeline.CampaignEvent) {
	ts := event.Timestamp.Format("15:04:05")

	switch event.EventType {
	case pipeline.EventThought:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorCyan("[think]"), event.Detail)
	case pipeline.EventToolCall:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorYellow("[>>]"), event.Detail)
	case pipeline.EventToolResult:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorGreen("[<<]"), event.Detail)
	case pipeline.EventFindingDiscovered:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorRed("[!]"), event.Detail)
	case pipeline.EventStateChange:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorMagenta("[*]"), event.Detail)
	case pipeline.EventStepExecuted:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorYellow("[>]"), event.Detail)
	case pipeline.EventError:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorRed("[ERR]"), event.Detail)
	case pipeline.EventMilestone:
		fmt.Printf("\n  %s %s\n", colorGreen("[DONE]"), colorBold(event.Detail))
	default:
		fmt.Printf("  %s [%s] %s\n", colorDim(ts), event.EventType, event.Detail)
	}
}

func printBanner() {
	fmt.Println(colorCyan(`
  ██████  ██     ██  █████  ██████  ███    ███
  ██      ██     ██ ██   ██ ██   ██ ████  ████
  ███████ ██  █  ██ ███████ ██████  ██ ████ ██
       ██ ██ ███ ██ ██   ██ ██   ██ ██  ██  ██
  ███████  ███ ███  ██   ██ ██   ██ ██      ██`))
	fmt.Println(colorDim("  Pentest Swarm AI — swarms of agents, one mission"))
}

func colorBold(s string) string    { return "\033[1m" + s + "\033[0m" }
func colorDim(s string) string     { return "\033[2m" + s + "\033[0m" }
func colorRed(s string) string     { return "\033[31m" + s + "\033[0m" }
func colorGreen(s string) string   { return "\033[32m" + s + "\033[0m" }
func colorYellow(s string) string  { return "\033[33m" + s + "\033[0m" }
func colorCyan(s string) string    { return "\033[36m" + s + "\033[0m" }
func colorMagenta(s string) string { return "\033[35m" + s + "\033[0m" }

func providerOrDefault(override, def string) string {
	if override != "" {
		return override
	}
	return def
}

func fallback(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// promptForAPIKeyOnce is the first-run escape hatch: if a researcher runs
// 'pentestswarm scan …' before 'pentestswarm init', offer them one prompt
// to paste a key and (optionally) stash it in the keychain so future runs
// don't ask again. Ctrl-C or an empty line skips without writing anything.
func promptForAPIKeyOnce() string {
	fmt.Println()
	fmt.Println(colorYellow("  No Claude API key found.") + " Paste one to continue, or Ctrl-C to cancel.")
	fmt.Println(colorDim("  Tip: next time, run ") + colorCyan("pentestswarm init") + colorDim(" to set this up once and forget it."))
	fmt.Print("  " + colorCyan("api key> "))
	scanner := bufio.NewScanner(os.Stdin)
	key := ""
	if scanner.Scan() {
		key = strings.TrimSpace(scanner.Text())
	}
	if key == "" {
		return ""
	}
	// Offer to persist — the researcher can opt out if this is a one-off.
	fmt.Print("  Save to OS keychain so we don't ask again? [Y/n] ")
	answer := ""
	if scanner.Scan() {
		answer = strings.ToLower(strings.TrimSpace(scanner.Text()))
	}
	if answer == "" || answer == "y" || answer == "yes" {
		if err := keychain.Set(keychain.KeyClaudeAPI, key); err != nil {
			fmt.Printf("  %s couldn't save to keychain (%s) — using this run only.\n", colorYellow("[warn]"), err)
		} else {
			fmt.Printf("  %s stored in keychain\n", colorGreen("[ok]"))
		}
	}
	return key
}

func init() {
	scanCmd.Flags().String("scope", "", "CIDR or domain scope, comma-separated (required)")
	scanCmd.Flags().String("objective", "find all vulnerabilities", "what to find")
	scanCmd.Flags().String("mode", "manual", "manual|bugbounty|asm|ctf")
	scanCmd.Flags().String("provider", "", "claude|ollama|lmstudio (overrides config)")
	scanCmd.Flags().Bool("dry-run", false, "show planned commands without executing")
	scanCmd.Flags().String("output", "./reports", "output directory for report")
	scanCmd.Flags().String("format", "md", "report format: md|html|json|sarif|all")
	scanCmd.Flags().Bool("follow", false, "stream live output (default when interactive)")
	scanCmd.Flags().Bool("strict", false, "abort on any LLM error instead of degrading to heuristics")
	scanCmd.Flags().Bool("swarm", false, "use the stigmergic swarm scheduler (experimental); default is the sequential 5-phase runner")
	scanCmd.Flags().String("exploration-bias", "med", "swarm pheromone scaling: low|med|high (breadth-first = high, depth-first = low)")
	scanCmd.Flags().Bool("publish-unverified", false, "include suspected-but-not-reproduced findings in the report (aggressive mode)")
	scanCmd.Flags().Bool("estimate", false, "print expected LLM spend in USD and exit without scanning")
	scanCmd.Flags().String("target-class", "medium", "estimate sizing: small | medium | large")
	scanCmd.Flags().Bool("safe-mode", false, "cap RPS + forbid destructive techniques (for programs that disallow automated scanning)")
	scanCmd.Flags().Bool("assist", false, "ask y/N before every executed step (human-in-the-loop)")
	scanCmd.Flags().String("auth-token", "", "authorization token")

	// Note: --scope is no longer marked required. When omitted, we default
	// to the target itself (4.8.5: simplicity). Researchers wanting a wider
	// scope (CIDR / wildcards / multiple domains) still pass --scope.

	rootCmd.AddCommand(scanCmd)
}

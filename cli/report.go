package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/prompts"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report/qualitygate"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/keychain"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Work with generated reports + submission drafts",
}

var reportPolishCmd = &cobra.Command{
	Use:   "polish <path-to-draft.md>",
	Short: "Re-run the quality-gate rubric on an edited draft",
	Long: `polish is what you reach for after hand-editing a submission draft
the swarm produced. It re-grades the draft on clarity / impact /
reproducibility and prints actionable suggestions for another pass.

Prints score + suggestions only — the draft file is never modified.
Use it as a 'ready to submit?' check.`,
	Args:    cobra.ExactArgs(1),
	Example: `  pentestswarm report polish ./submissions/sql-injection.md`,
	RunE:    runReportPolish,
}

func runReportPolish(cmd *cobra.Command, args []string) error {
	body, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read %s: %w", args[0], err)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.Orchestrator.APIKey == "" {
		if k, err := keychain.Get(keychain.KeyClaudeAPI); err == nil {
			cfg.Orchestrator.APIKey = k
		}
	}
	if cfg.Orchestrator.APIKey == "" {
		return fmt.Errorf("no API key configured — run %s first", colorCyan("pentestswarm init"))
	}

	provider, err := prompts.NewProviderWithRetry(cfg.Orchestrator)
	if err != nil {
		return fmt.Errorf("provider: %w", err)
	}

	fmt.Println()
	fmt.Printf("  %s %s\n", colorCyan("[polish]"), args[0])
	fmt.Println()

	r, err := qualitygate.Grade(context.Background(), provider, string(body))
	if err != nil {
		return fmt.Errorf("quality gate: %w", err)
	}
	verdict := colorGreen(fmt.Sprintf("PASS (%.1f/10)", r.OverallScore))
	if !r.Pass() {
		verdict = colorRed(fmt.Sprintf("FAIL (%.1f/10)", r.OverallScore))
	}
	fmt.Printf("  Overall:          %s\n", verdict)
	fmt.Printf("  Clarity:          %.1f/10\n", r.ClarityScore)
	fmt.Printf("  Impact:           %.1f/10\n", r.ImpactScore)
	fmt.Printf("  Reproducibility:  %.1f/10\n", r.ReproducibilityScore)

	if r.BlockingIssue != "" {
		fmt.Println()
		fmt.Println(colorYellow("  Blocking issue: ") + r.BlockingIssue)
	}
	if len(r.Suggestions) > 0 {
		fmt.Println()
		fmt.Println("  Suggestions:")
		for _, s := range r.Suggestions {
			fmt.Printf("    • %s\n", s)
		}
	}

	if r.Pass() {
		fmt.Println()
		fmt.Println(colorGreen("  Ready to submit.") + " Paste the draft into the platform's report form.")
	} else {
		// Non-zero exit so CI / scripts can gate on polish.
		return fmt.Errorf("draft below quality threshold")
	}
	return nil
}

func init() {
	reportCmd.AddCommand(reportPolishCmd)
	rootCmd.AddCommand(reportCmd)
}

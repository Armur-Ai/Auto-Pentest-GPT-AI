package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report/dedup"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report/qualitygate"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/keychain"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/importer/hackerone"
	"github.com/spf13/cobra"
)

var submitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Turn a campaign report into platform-specific submission drafts",
	Long: `Reads a campaign report (JSON emitted by 'scan --format json') and
writes one ready-to-paste markdown file per finding, formatted for the
chosen bug-bounty platform.

By default this is a dry-run that writes to ./submissions/<id>.md —
the actual 'press submit on your behalf' path is intentionally gated
behind --live and currently disabled pending H1/Bugcrowd API review.
You can't accidentally post an AI-generated report to a real program
with this command.`,
	Example: `  pentestswarm submit --platform h1 --report ./reports/scan.json
  pentestswarm submit --platform bugcrowd --report ./reports/scan.json --program acme
`,
	RunE: runSubmit,
}

func runSubmit(cmd *cobra.Command, args []string) error {
	platform, _ := cmd.Flags().GetString("platform")
	reportPath, _ := cmd.Flags().GetString("report")
	outDir, _ := cmd.Flags().GetString("out")
	live, _ := cmd.Flags().GetBool("live")
	program, _ := cmd.Flags().GetString("program")

	if platform == "" {
		return fmt.Errorf("--platform is required (h1 | bugcrowd | intigriti)")
	}
	if reportPath == "" {
		return fmt.Errorf("--report <path-to-report.json> is required")
	}
	if live {
		return fmt.Errorf("--live submission is not yet implemented — drop the flag to preview submissions locally")
	}
	if outDir == "" {
		outDir = "./submissions"
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}
	var pr pipeline.PentestReport
	if err := json.Unmarshal(data, &pr); err != nil {
		return fmt.Errorf("parse report: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}

	fmt.Println()
	fmt.Printf("  %s %d findings → %s format\n", colorCyan("[submit]"),
		len(pr.Findings), platform)
	if program != "" {
		fmt.Printf("  %s program slug: %s\n", colorCyan("[submit]"), program)
	}

	// Phase 4.4.5: pull the researcher's prior submissions so we can flag
	// duplicate candidates before the draft is pasted into the platform.
	// Best-effort — missing credentials = silent skip, not a failure.
	priors := loadPriors(context.Background(), platform, program)
	if len(priors) > 0 {
		fmt.Printf("  %s loaded %d prior submissions for dedup\n", colorDim("[dedup]"), len(priors))
	}

	// Phase 4.4.7: optional quality-gate grader. Only fires when the
	// researcher asked for it AND a tool-use-capable LLM is configured
	// (falls back to 'disabled with warning' otherwise).
	var gate llm.Provider
	if qg, _ := cmd.Flags().GetBool("quality-gate"); qg {
		if cfg, cerr := config.Load(cfgFile); cerr == nil {
			if cfg.Orchestrator.APIKey == "" {
				if k, err := keychain.Get(keychain.KeyClaudeAPI); err == nil {
					cfg.Orchestrator.APIKey = k
				}
			}
			if p, err := llm.NewProvider(cfg.Orchestrator); err == nil {
				gate = p
				fmt.Printf("  %s quality gate on (rubric: clarity / impact / reproducibility)\n",
					colorDim("[qg]"))
			}
		}
		if gate == nil {
			fmt.Printf("  %s --quality-gate set but no LLM provider ready — skipping\n",
				colorYellow("[warn]"))
		}
	}
	fmt.Println()

	written := 0
	for _, rf := range pr.Findings {
		v := report.BuildSubmissionView(rf, nil, nil)
		body, err := report.RenderSubmission(platform, v)
		if err != nil {
			fmt.Printf("  %s %s — %s\n", colorRed("[skip]"), rf.Title, err)
			continue
		}

		// Duplicate annotation: prepend a visible callout when a prior
		// submission looks similar.
		dupeTarget := ""
		if len(rf.AffectedComponents) > 0 {
			dupeTarget = rf.AffectedComponents[0]
		}
		hits := dedup.FindDuplicates(rf.Title, dupeTarget, priors, 0.6, 2)
		if len(hits) > 0 {
			var sb strings.Builder
			sb.WriteString("> ⚠ Possible duplicate of:\n")
			for _, h := range hits {
				sb.WriteString(fmt.Sprintf("> - #%s (%s) — %.0f%% title similarity\n",
					h.Prior.ID, h.Prior.State, h.Similarity*100))
			}
			body = append([]byte(sb.String()+"\n"), body...)
			fmt.Printf("  %s %-40s ↔ #%s (%.0f%% match)\n",
				colorYellow("[dupe?]"), truncateCLI(rf.Title, 40),
				hits[0].Prior.ID, hits[0].Similarity*100)
		}

		// Quality gate — runs per-finding so the rubric sees one draft at a time.
		if gate != nil {
			qr, err := qualitygate.Grade(context.Background(), gate, string(body))
			if err == nil && qr != nil {
				if !qr.Pass() {
					var sb strings.Builder
					sb.WriteString(fmt.Sprintf("> 🛑 **Quality gate blocked** — overall %.1f/10\n", qr.OverallScore))
					if qr.BlockingIssue != "" {
						sb.WriteString("> " + qr.BlockingIssue + "\n")
					}
					sb.WriteString("> Polish:\n")
					for _, s := range qr.Suggestions {
						sb.WriteString("> - " + s + "\n")
					}
					body = append([]byte(sb.String()+"\n"), body...)
					fmt.Printf("  %s %-40s  %.1f/10\n", colorRed("[block]"), truncateCLI(rf.Title, 40), qr.OverallScore)
				} else {
					fmt.Printf("  %s %-40s  %.1f/10\n", colorGreen("[pass]"), truncateCLI(rf.Title, 40), qr.OverallScore)
				}
			}
		}

		fname := filepath.Join(outDir, sanitiseFilename(rf.Title)+".md")
		if err := os.WriteFile(fname, body, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", fname, err)
		}
		fmt.Printf("  %s %-50s → %s\n", colorGreen("[draft]"), truncateCLI(rf.Title, 50), colorCyan(fname))
		written++
	}
	fmt.Println()
	fmt.Printf("  Wrote %d submission drafts to %s\n", written, colorCyan(outDir))
	fmt.Println(colorDim("  Review each draft, then paste into the platform's submission form."))
	fmt.Println(colorDim("  (--live will post via the platform API in a future release.)"))
	return nil
}

// loadPriors pulls past submissions to compare against. Two sources:
//
//  1. The researcher's OWN reports (any program) — needs API creds.
//     Catches "I already filed this last week."
//  2. The program's PUBLIC disclosed reports (4.4.6) — works without
//     creds. Catches "this is already disclosed; would file as duplicate."
//
// Missing credentials degrade to public-only; fully empty list when
// neither source returns anything. Dedup is an enhancement, never a
// hard block on submit.
func loadPriors(ctx context.Context, platform, program string) []dedup.Prior {
	if strings.ToLower(platform) != "h1" && strings.ToLower(platform) != "hackerone" {
		// Bugcrowd / Intigriti dedup endpoints are TBD.
		return nil
	}

	user := os.Getenv("HACKERONE_API_USER")
	token := os.Getenv("HACKERONE_API_TOKEN")
	if token == "" {
		if v, err := keychain.Get(keychain.KeyHackerOneToken); err == nil {
			token = v
		}
	}
	c := hackerone.NewClient(hackerone.Config{APIUser: user, APIToken: token})

	var priors []dedup.Prior

	// 1. Researcher's own reports — needs creds.
	if user != "" && token != "" {
		if reports, err := c.Reports(ctx, 50); err == nil {
			for _, r := range reports {
				if program != "" && !strings.EqualFold(r.Program, program) {
					continue
				}
				priors = append(priors, dedup.Prior{
					ID:    "own:" + r.ID,
					Title: r.Title,
					State: r.State,
				})
			}
		}
	}

	// 2. Program's public disclosed reports — works without creds, but
	// only meaningful when we know the program slug.
	if program != "" {
		if reports, err := c.PublicReports(ctx, program, 50); err == nil {
			for _, r := range reports {
				priors = append(priors, dedup.Prior{
					ID:    "public:" + r.ID,
					Title: r.Title,
					State: r.State,
				})
			}
		}
	}

	return priors
}

func sanitiseFilename(s string) string {
	out := make([]byte, 0, len(s))
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, byte(r))
		case r == ' ', r == '-', r == '_':
			out = append(out, '-')
		}
	}
	// Trim trailing hyphens and cap length.
	s2 := strings.Trim(string(out), "-")
	if len(s2) > 60 {
		s2 = s2[:60]
	}
	if s2 == "" {
		s2 = "finding"
	}
	return s2
}

func truncateCLI(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func init() {
	submitCmd.Flags().String("platform", "", "target platform: h1 | bugcrowd | intigriti")
	submitCmd.Flags().String("report", "", "path to the scan's JSON report")
	submitCmd.Flags().String("out", "./submissions", "directory to write submission drafts into")
	submitCmd.Flags().String("program", "", "program slug (only used by --live, not dry-run)")
	submitCmd.Flags().Bool("live", false, "actually POST submissions via the platform API (not yet implemented)")
	submitCmd.Flags().Bool("quality-gate", false, "run each draft through an LLM rubric and block drafts scoring below 6/10")
	rootCmd.AddCommand(submitCmd)
}

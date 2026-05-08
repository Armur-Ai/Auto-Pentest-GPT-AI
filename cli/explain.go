package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/llm"
	"github.com/spf13/cobra"
)

var explainCmd = &cobra.Command{
	Use:    "explain <finding-description|cve-id>",
	Short:  "Explain a finding or CVE in plain English",
	Hidden: true, // 4.8.2: utility command, kept out of root --help
	Long: `Uses AI to explain a vulnerability in plain English, tailored to the audience.
Pass a CVE ID, finding description, or any security term.`,
	Args: cobra.MinimumNArgs(1),
	Example: `  pentestswarm explain "SQL injection in search parameter"
  pentestswarm explain CVE-2024-3094
  pentestswarm explain "exposed .git directory" --audience executive
  pentestswarm explain "SSRF via URL parameter" --remediate
  pentestswarm explain "weak JWT validation" --audience manager --remediate`,
	RunE: runExplain,
}

func runExplain(cmd *cobra.Command, args []string) error {
	input := strings.Join(args, " ")
	audience, _ := cmd.Flags().GetString("audience")
	remediate, _ := cmd.Flags().GetBool("remediate")

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if cfg.Orchestrator.APIKey == "" {
		if key := os.Getenv("PENTESTSWARM_ORCHESTRATOR_API_KEY"); key != "" {
			cfg.Orchestrator.APIKey = key
		} else if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			cfg.Orchestrator.APIKey = key
		}
	}

	if cfg.Orchestrator.APIKey == "" && cfg.Orchestrator.Provider == "claude" {
		return fmt.Errorf("no API key found. Set PENTESTSWARM_ORCHESTRATOR_API_KEY or ANTHROPIC_API_KEY")
	}

	provider, err := llm.NewProvider(cfg.Orchestrator)
	if err != nil {
		return fmt.Errorf("creating LLM provider: %w", err)
	}

	if !quiet {
		fmt.Printf("\n  %s Explaining: %s\n", colorCyan("*"), colorBold(input))
		fmt.Printf("  %s Audience: %s\n\n", colorDim("*"), audience)
	}

	systemPrompt := buildExplainPrompt(audience, remediate)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := provider.Complete(ctx, llm.CompletionRequest{
		SystemPrompt: systemPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: input},
		},
		MaxTokens:   2048,
		Temperature: 0.3,
	})
	if err != nil {
		return fmt.Errorf("LLM call failed: %w", err)
	}

	fmt.Println(resp.Content)
	fmt.Println()

	return nil
}

func buildExplainPrompt(audience string, remediate bool) string {
	var b strings.Builder

	b.WriteString("You are a cybersecurity expert explaining vulnerabilities to a ")

	switch audience {
	case "executive":
		b.WriteString("C-level executive. Use simple language, no technical jargon. Focus on: business risk, financial impact, compliance implications, and what action needs to be taken. Keep it to 1-2 paragraphs.")
	case "manager":
		b.WriteString("engineering manager. Use moderate technical language. Focus on: what the vulnerability is, which teams need to act, priority level, timeline for fix, and compliance implications. Use bullet points.")
	default: // developer
		b.WriteString("software developer. Be technical and precise. Include: what the vulnerability is, how it works, why it's dangerous, code-level examples of the vulnerable pattern, and the CVSS impact.")
	}

	if remediate {
		b.WriteString("\n\nAlso provide specific, actionable remediation steps. ")
		switch audience {
		case "developer":
			b.WriteString("Include code examples showing the fix. Reference relevant libraries or frameworks.")
		case "manager":
			b.WriteString("Include estimated effort (hours/days), required team, and testing approach.")
		case "executive":
			b.WriteString("Include cost of fix vs cost of breach, and recommended vendor if applicable.")
		}
	}

	return b.String()
}

func init() {
	explainCmd.Flags().String("audience", "developer", "developer|manager|executive")
	explainCmd.Flags().Bool("remediate", false, "include step-by-step fix instructions")

	rootCmd.AddCommand(explainCmd)
}

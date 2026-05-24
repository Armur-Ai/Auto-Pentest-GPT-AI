package cli

import (
	"fmt"

	"github.com/Armur-Ai/Pentest-Swarm-AI/cli/ui"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

var campaignCmd = &cobra.Command{
	Use:   "campaign",
	Short: "Manage penetration testing campaigns",
}

var campaignListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all campaigns",
	Example: "  pentestswarm campaign list",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(colorBold("ID                                   STATUS       TARGET              FINDINGS"))
		fmt.Println(colorDim("───────────────────────────────────────────────────────────────────────────────"))
		// TODO: fetch from API/DB
		fmt.Println(colorDim("  (no campaigns yet — run: pentestswarm scan <target> --scope <scope>)"))
		return nil
	},
}

var campaignStatusCmd = &cobra.Command{
	Use:     "status <id>",
	Short:   "Show detailed status of a campaign",
	Args:    cobra.ExactArgs(1),
	Example: "  pentestswarm campaign status abc-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		fmt.Printf("%s Campaign: %s\n", colorBold("*"), id)
		fmt.Printf("  Status:  %s\n", colorYellow("unknown"))
		fmt.Printf("  Target:  %s\n", colorDim("fetch from API"))
		// TODO: fetch from API
		return nil
	},
}

var campaignWatchCmd = &cobra.Command{
	Use:   "watch <id>",
	Short: "Live TUI dashboard — watch the swarm work",
	Long: `Opens a full-screen terminal dashboard showing all agents
working simultaneously. Live findings, attack paths, and agent thoughts.`,
	Args:    cobra.ExactArgs(1),
	Example: "  pentestswarm campaign watch abc-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]

		// Create TUI model
		model := ui.NewModel(id, "target", "find all vulnerabilities")

		// Launch bubbletea program
		p := tea.NewProgram(model, tea.WithAltScreen())

		// In a real implementation, we'd connect to the WebSocket here
		// and feed events to the TUI via p.Send(ui.EventMsg{...})
		go func() {
			// Demo: send some events to show the TUI working
			demoEvents := []pipeline.CampaignEvent{
				{EventType: pipeline.EventStateChange, AgentName: "engine", Detail: "Campaign initialized"},
				{EventType: pipeline.EventThought, AgentName: "orchestrator", Detail: "Planning reconnaissance strategy..."},
				{EventType: pipeline.EventToolCall, AgentName: "recon", Detail: "Running subfinder, httpx, nuclei, naabu"},
			}
			for _, e := range demoEvents {
				p.Send(ui.EventMsg(e))
			}
		}()

		_, err := p.Run()
		return err
	},
}

var campaignStopCmd = &cobra.Command{
	Use:     "stop <id>",
	Short:   "Emergency stop a running campaign",
	Args:    cobra.ExactArgs(1),
	Example: "  pentestswarm campaign stop abc-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("%s Stopping campaign %s...\n", colorRed("*"), args[0])
		// TODO: call API
		fmt.Printf("%s Campaign stopped. Cleanup actions executed.\n", colorGreen("*"))
		return nil
	},
}

var campaignExploreCmd = &cobra.Command{
	Use:     "explore <id>",
	Short:   "Interactive attack surface explorer (TUI)",
	Long:    `Browse discovered subdomains, hosts, ports, services, and findings interactively.`,
	Args:    cobra.ExactArgs(1),
	Example: "  pentestswarm campaign explore abc-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Exploring attack surface for campaign %s...\n", args[0])
		// TODO: launch bubbletea recon explorer
		fmt.Println(colorDim("(Explorer TUI requires a completed recon phase)"))
		return nil
	},
}

func init() {
	campaignCmd.AddCommand(campaignListCmd)
	campaignCmd.AddCommand(campaignStatusCmd)
	campaignCmd.AddCommand(campaignWatchCmd)
	campaignCmd.AddCommand(campaignStopCmd)
	campaignCmd.AddCommand(campaignExploreCmd)

	rootCmd.AddCommand(campaignCmd)
}

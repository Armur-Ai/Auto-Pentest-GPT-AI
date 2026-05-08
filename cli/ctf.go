package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/ctf"
	"github.com/spf13/cobra"
)

var ctfCmd = &cobra.Command{
	Use:    "ctf",
	Short:  "Autonomous CTF machine solving",
	Hidden: true, // 4.8.2: 'scan' is the main path; ctf is specialized
}

var ctfSolveCmd = &cobra.Command{
	Use:   "solve <target>",
	Short: "Deploy the swarm to autonomously solve a CTF machine",
	Args:  cobra.ExactArgs(1),
	Example: `  pentestswarm ctf solve 10.10.10.1
  pentestswarm ctf solve 10.10.10.1 --platform htb --machine Lame
  pentestswarm ctf solve 10.10.10.1 --follow`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		platform, _ := cmd.Flags().GetString("platform")
		machine, _ := cmd.Flags().GetString("machine")

		if machine == "" {
			machine = target
		}

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

		if !quiet {
			fmt.Println(colorCyan("\n  CTF Mode — Autonomous Machine Solving\n"))
			fmt.Printf("  Target:    %s\n", colorBold(target))
			fmt.Printf("  Platform:  %s\n", platform)
			fmt.Printf("  Machine:   %s\n", machine)
			fmt.Println()
			fmt.Println(colorDim("  ─────────────────────────────────────"))
			fmt.Println()
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			fmt.Println("\n" + colorRed("  Stopping CTF solver..."))
			cancel()
		}()

		solver := ctf.NewSolver(platform, cfg)
		result, err := solver.Solve(ctx, target, machine)
		if err != nil {
			fmt.Printf("\n  %s %s\n", colorRed("[ERR]"), err)
		}

		if !quiet && result != nil {
			fmt.Println()
			if result.Success {
				fmt.Printf("  %s Solved in %s!\n", colorGreen("[SOLVED]"), result.TimeElapsed.Round(1))
				for _, f := range result.Flags {
					fmt.Printf("  %s %s flag: %s\n", colorGreen("*"), f.Type, colorBold(f.Value))
				}
			} else {
				fmt.Printf("  %s Could not capture flags in %s\n", colorYellow("[INCOMPLETE]"), result.TimeElapsed.Round(1))
			}

			if result.Writeup != "" {
				fmt.Println()
				fmt.Println(colorDim("  Writeup:"))
				fmt.Println(result.Writeup)
			}
		}

		return nil
	},
}

var ctfListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List available CTF machines",
	Example: "  pentestswarm ctf list --platform htb --difficulty easy",
	RunE: func(cmd *cobra.Command, args []string) error {
		platform, _ := cmd.Flags().GetString("platform")
		fmt.Printf("  Listing %s machines...\n\n", platform)
		fmt.Println(colorDim("  (Requires platform API token in config — see pentestswarm config init)"))
		return nil
	},
}

var ctfWriteupCmd = &cobra.Command{
	Use:     "writeup <campaign-id>",
	Short:   "Generate writeup from a CTF campaign",
	Args:    cobra.ExactArgs(1),
	Example: "  pentestswarm ctf writeup abc-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("  Generating writeup for campaign %s...\n", args[0])
		fmt.Println(colorDim("  (Requires a completed CTF campaign)"))
		return nil
	},
}

func init() {
	ctfSolveCmd.Flags().String("platform", "generic", "htb|thm|generic")
	ctfSolveCmd.Flags().String("machine", "", "machine name (for auto-spawn)")
	ctfSolveCmd.Flags().Bool("follow", false, "stream live output")

	ctfListCmd.Flags().String("platform", "htb", "htb|thm")
	ctfListCmd.Flags().String("difficulty", "", "easy|medium|hard")

	ctfCmd.AddCommand(ctfSolveCmd)
	ctfCmd.AddCommand(ctfListCmd)
	ctfCmd.AddCommand(ctfWriteupCmd)

	rootCmd.AddCommand(ctfCmd)
}

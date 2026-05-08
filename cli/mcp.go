package cli

import (
	"fmt"
	"os"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	mcpserver "github.com/Armur-Ai/Pentest-Swarm-AI/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:    "mcp",
	Short:  "MCP server for Claude Desktop and Cursor integration",
	Hidden: true, // 4.8.2: keep root --help to one screen
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start MCP server (stdio transport)",
	Long: `Starts an MCP server that exposes pentestswarm tools to Claude Desktop,
Cursor, and any MCP-compatible AI client.

Add to Claude Desktop config:
  {
    "mcpServers": {
      "pentestswarm": {
        "command": "pentestswarm",
        "args": ["mcp", "serve"]
      }
    }
  }`,
	RunE: func(cmd *cobra.Command, args []string) error {
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

		server := mcpserver.NewServer()
		mcpserver.RegisterDefaultTools(server, cfg)

		fmt.Fprintln(cmd.ErrOrStderr(), "pentestswarm MCP server started (stdio)")
		return server.Serve()
	},
}

func init() {
	mcpCmd.AddCommand(mcpServeCmd)
	rootCmd.AddCommand(mcpCmd)
}

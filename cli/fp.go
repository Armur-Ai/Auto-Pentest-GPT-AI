package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline/fpcache"
	"github.com/spf13/cobra"
)

var fpCmd = &cobra.Command{
	Use:   "fp",
	Short: "Manage the local false-positive cache",
	Long: `False positives marked during a campaign are stored in a local JSONL
cache (~/.pentestswarm/fp-cache.jsonl) and auto-suppressed on future
scans. This command exports an anonymised slice of that cache as an
opt-in contribution to the community FP corpus (Phase 4.6.6).`,
}

var fpShareCmd = &cobra.Command{
	Use:   "share",
	Short: "Export an anonymised copy of the FP cache for the community corpus",
	Long: `Reads ~/.pentestswarm/fp-cache.jsonl, strips identifying fields
(target hostnames, free-text reason notes), hashes the title, and
writes the result to ~/.pentestswarm/fp-share.jsonl.

You can review the file before uploading. Upload is manual for now —
the corpus endpoint will land alongside Phase 4.7.1.

What gets stripped:
  - Target hostnames (would leak the program you scanned)
  - Free-text reason notes (often customer-internal)

What's kept:
  - Attack category
  - Title hash (lets the corpus match equivalent FPs across researchers
    without exposing the original wording)`,
	RunE: runFPShare,
}

func runFPShare(cmd *cobra.Command, args []string) error {
	in, _ := cmd.Flags().GetString("from")
	out, _ := cmd.Flags().GetString("out")
	if in == "" {
		in = fpcache.DefaultPath()
	}
	if out == "" {
		home, _ := os.UserHomeDir()
		out = filepath.Join(home, ".pentestswarm", "fp-share.jsonl")
	}

	store, err := fpcache.Open(in)
	if err != nil {
		return fmt.Errorf("open fp cache at %s: %w", in, err)
	}
	if store.Len() == 0 {
		fmt.Printf("  %s no FP marks in %s — nothing to share\n",
			colorYellow("[fp]"), colorDim(in))
		return nil
	}
	n, err := store.ExportShare(out)
	if err != nil {
		return fmt.Errorf("export share: %w", err)
	}
	fmt.Printf("  %s wrote %d anonymised pattern(s) to %s\n",
		colorGreen("[ok]"), n, colorCyan(out))
	fmt.Println()
	fmt.Printf("  Review the file before uploading; corpus endpoint TBD (Phase 4.7.1).\n")
	fmt.Printf("  cat %s | head\n", colorCyan(out))
	return nil
}

func init() {
	fpShareCmd.Flags().String("from", "", "input fp-cache path (default: ~/.pentestswarm/fp-cache.jsonl)")
	fpShareCmd.Flags().String("out", "", "output share path (default: ~/.pentestswarm/fp-share.jsonl)")
	fpCmd.AddCommand(fpShareCmd)
	rootCmd.AddCommand(fpCmd)
}

package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/exploit"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// assistConfirm is the TTY-backed implementation of exploit.ConfirmFunc
// for `--assist` mode (4.6.4).
//
// Output goes to stderr so it doesn't pollute --json campaign streams.
// A bare `enter` defaults to NO — fail-closed: if the operator is
// inattentive, skipping is the safer choice than auto-firing. Type
// `a` once to approve everything for the rest of the campaign (great
// for researchers who trust the swarm but want to review the first
// few steps).
//
// Returns an error only when stdin is closed (scripted run with no
// terminal) — that aborts the campaign so the swarm doesn't silently
// drop every step.
func assistConfirm(step pipeline.AttackStep) (bool, error) {
	if assistAutoApprove {
		return true, nil
	}
	r := assistReader
	if r == nil {
		r = bufio.NewReader(os.Stdin)
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s %s\n", colorYellow("[assist]"), colorBold(step.Name))
	fmt.Fprintf(os.Stderr, "    %s\n", colorDim(step.Command))
	if step.ExpectedOutputPattern != "" {
		fmt.Fprintf(os.Stderr, "    %s %s\n", colorDim("expects:"), step.ExpectedOutputPattern)
	}
	fmt.Fprintf(os.Stderr, "  %s [y/N/a=approve-all] ", colorCyan("run?"))

	line, err := r.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return false, fmt.Errorf("assist mode requires a TTY (got EOF on stdin) — drop --assist for unattended runs")
		}
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	switch answer {
	case "y", "yes":
		return true, nil
	case "a", "all":
		assistAutoApprove = true
		fmt.Fprintf(os.Stderr, "  %s remaining steps will run without prompting\n", colorDim("[assist]"))
		return true, nil
	default:
		// Empty / "n" / anything else → skip. Fail-closed.
		return false, nil
	}
}

// Module-level state for assist mode.
//
//   - assistAutoApprove: flipped by typing 'a' at any prompt. Sticks
//     for the rest of the process — the next campaign in the same
//     process would inherit, which is fine because the CLI always
//     fork-execs a fresh binary per scan.
//   - assistReader: overridable in tests so we don't need a real TTY.
var (
	assistAutoApprove bool
	assistReader      *bufio.Reader
)

// compile-time check that assistConfirm satisfies the executor's
// ConfirmFunc signature — catches drift if the type evolves.
var _ exploit.ConfirmFunc = assistConfirm

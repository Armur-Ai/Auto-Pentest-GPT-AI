package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// DnsxTool wraps dnsx for DNS resolution and reverse lookups.
//
// Important: dnsx's `-d <domain>` flag is **subdomain brute-force mode**
// and mandates a `-w <wordlist>`. The intent of this wrapper is "resolve
// these hosts", which dnsx expects via stdin. We therefore pipe the
// target list on stdin instead of passing `-d`.
type DnsxTool struct{}

func NewDnsxTool() *DnsxTool { return &DnsxTool{} }

func (d *DnsxTool) Name() string { return "dnsx" }

func (d *DnsxTool) IsAvailable() bool { return IsCommandAvailable("dnsx") }

func (d *DnsxTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.ValidateAndLog("dnsx", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in dnsx: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 30)) * time.Second

	// Build the stdin payload. Callers may pass a single host (target)
	// or a pre-rendered list via opts["hosts"] (e.g. results from
	// subfinder). We always include `target` as a fallback so the
	// adapter remains usable with a single argument.
	hosts := opts.GetStringSlice("hosts")
	if len(hosts) == 0 {
		hosts = []string{target}
	}
	stdin := strings.Join(hosts, "\n") + "\n"

	args := []string{"-json", "-silent", "-a", "-aaaa", "-cname", "-resp"}

	result := RunToolCommandWithStdin(ctx, "dnsx", target, stdin, timeout, "dnsx", args...)
	return result, result.Error
}

// Package osint holds passive intelligence clients — Shodan, Censys,
// GitHub code search, etc. These hit third-party APIs about a target
// rather than the target itself, so they're useful even when the scope
// guard forbids active probes (asset discovery for an upcoming engagement,
// continuous monitoring, recon before a permitted-window scan opens).
//
// All clients normalize their output to a common Asset shape so the
// recon agent merges results uniformly without per-provider branching.
//
// Plan reference: Phase 2.4 in IMPLEMENTATION_PLAN.md.
package osint

// Asset is the normalized output every OSINT client emits. Type is the
// finding's category, Value is the concrete identifier (an IP, a URL,
// a leaked secret), Source names which provider produced it (so logs
// and dedup can group across providers), Metadata holds provider-
// specific extras the agent can pull when needed.
type Asset struct {
	Type     string         `json:"type"`     // "subdomain", "host", "endpoint", "secret", "service"
	Value    string         `json:"value"`    // the concrete identifier
	Source   string         `json:"source"`   // "shodan", "censys", "github_search", ...
	Metadata map[string]any `json:"metadata,omitempty"`
}

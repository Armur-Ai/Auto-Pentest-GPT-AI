package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ShodanClient queries Shodan's REST API for already-exposed assets
// matching a target hostname. We use the `host/search` endpoint with
// the standard `hostname:<target>` filter — it's the cheapest passive
// query that surfaces IPs, ports, services, and banners attached to a
// domain (and crucially, doesn't touch the target itself).
//
// Auth: API key in the `key` query parameter (Shodan's spec, not a
// header). Get one at https://account.shodan.io/.
//
// Plan reference: 2.4.7 (P1) in IMPLEMENTATION_PLAN.md.
type ShodanClient struct {
	apiKey     string
	endpoint   string
	httpClient *http.Client
}

// ShodanConfig holds construction parameters.
type ShodanConfig struct {
	APIKey   string
	Endpoint string // override for testing / proxying; default https://api.shodan.io
	Timeout  time.Duration
}

// NewShodanClient builds a client. An empty API key produces a client
// whose IsAvailable returns false — Lookup will short-circuit with a
// clear error rather than firing an unauthenticated request.
func NewShodanClient(cfg ShodanConfig) *ShodanClient {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://api.shodan.io"
	}
	cfg.Endpoint = strings.TrimRight(cfg.Endpoint, "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &ShodanClient{
		apiKey:     cfg.APIKey,
		endpoint:   cfg.Endpoint,
		httpClient: &http.Client{Timeout: cfg.Timeout},
	}
}

// Name implements a (loose) interface shared by every OSINT client.
func (s *ShodanClient) Name() string { return "shodan" }

// IsAvailable returns true when the client is wired to actually run —
// here that means an API key was provided. Callers (the recon agent)
// check this and skip the source gracefully when false so the
// one-command invariant (CONTRIBUTING.md §1) still holds for users
// who haven't configured Shodan.
func (s *ShodanClient) IsAvailable() bool { return s.apiKey != "" }

// shodanHostSearch is the trimmed-down response shape we care about.
// Shodan returns more fields per match (location, ASN, etc.) — added
// to Metadata only when present, kept out of the schema to avoid
// brittle parsing if Shodan rotates field names.
type shodanHostSearch struct {
	Total   int             `json:"total"`
	Matches []shodanHostHit `json:"matches"`
}

type shodanHostHit struct {
	IPStr     string   `json:"ip_str"`
	Port      int      `json:"port"`
	Hostnames []string `json:"hostnames"`
	Domains   []string `json:"domains"`
	Product   string   `json:"product,omitempty"`
	Version   string   `json:"version,omitempty"`
	Transport string   `json:"transport,omitempty"`
	Org       string   `json:"org,omitempty"`
}

// Lookup runs a `hostname:<target>` search and returns normalized
// assets. Each Shodan match becomes one "service" asset (host + port +
// product), and each unique hostname seen across matches also gets a
// "subdomain" asset so the recon agent finds new candidate subdomains
// without an extra dedup pass.
//
// Returns a clear, actionable error when no API key is configured —
// the recon agent uses this to log "shodan skipped (no credentials)"
// rather than crashing the campaign.
func (s *ShodanClient) Lookup(ctx context.Context, target string) ([]Asset, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("no shodan key configured. Fix: add osint.shodan.api_key to ~/.pentestswarm/config.yaml or set PENTESTSWARM_SHODAN_API_KEY")
	}

	q := fmt.Sprintf("hostname:%s", target)
	u := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s",
		s.endpoint,
		url.QueryEscape(s.apiKey),
		url.QueryEscape(q))

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("creating shodan request: %w", err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("shodan request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("shodan returned 401 — check the API key (https://account.shodan.io/)")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("shodan returned status %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	var doc shodanHostSearch
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding shodan response: %w", err)
	}

	return shodanToAssets(doc), nil
}

// shodanToAssets converts a search response to normalized assets.
// Pulled out for direct testing without spinning up an HTTP server.
func shodanToAssets(doc shodanHostSearch) []Asset {
	seenHostnames := map[string]bool{}
	out := make([]Asset, 0, len(doc.Matches))

	for _, m := range doc.Matches {
		// One service asset per match — captures the "this IP:port runs
		// this product" fact, which is the most actionable shape for
		// downstream agents.
		out = append(out, Asset{
			Type:   "service",
			Value:  fmt.Sprintf("%s:%d", m.IPStr, m.Port),
			Source: "shodan",
			Metadata: map[string]any{
				"ip":        m.IPStr,
				"port":      m.Port,
				"product":   m.Product,
				"version":   m.Version,
				"transport": m.Transport,
				"hostnames": m.Hostnames,
				"org":       m.Org,
			},
		})

		// Surface every distinct hostname so the recon agent can
		// dedup-merge with subfinder / amass output.
		for _, h := range m.Hostnames {
			if h == "" || seenHostnames[h] {
				continue
			}
			seenHostnames[h] = true
			out = append(out, Asset{
				Type:   "subdomain",
				Value:  h,
				Source: "shodan",
			})
		}
	}
	return out
}

// truncate caps a string for error-message bodies so a 1MB error page
// doesn't blow up logs. Shared shape with the LLM provider files.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

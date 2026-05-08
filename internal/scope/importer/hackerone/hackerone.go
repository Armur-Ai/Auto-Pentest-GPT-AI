// Package hackerone imports scope from HackerOne programs.
//
// HackerOne exposes structured_scopes per program through its API:
//   GET https://api.hackerone.com/v1/hackers/programs/<slug>/structured_scopes
// Authenticated requests get the full list (including private programs);
// unauthenticated requests work for public bounty programs.
//
// The asset_type field drives how we slot each scope item into our
// scope.ScopeDefinition:
//   URL / WILDCARD / DOMAIN → AllowedDomains
//   CIDR                    → AllowedCIDRs
//   IP                      → AllowedCIDRs (as /32)
//   Anything else           → dropped with a DEBUG log (out of our lane)
package hackerone

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// Client is a thin HackerOne API client.
type Client struct {
	http      *http.Client
	baseURL   string
	apiUser   string
	apiToken  string
}

// Config customises a Client.
type Config struct {
	APIUser  string        // your HackerOne username
	APIToken string        // API token from hackerone.com/users/api_tokens
	Timeout  time.Duration // default 30s
}

// NewClient builds a client. Leave API credentials empty for public programs.
func NewClient(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Client{
		http:     &http.Client{Timeout: cfg.Timeout},
		baseURL:  "https://api.hackerone.com/v1",
		apiUser:  cfg.APIUser,
		apiToken: cfg.APIToken,
	}
}

// Platform implements importer.Importer.
func (c *Client) Platform() string { return "h1" }

// Import pulls structured_scopes for the given program and returns them
// as a scope.ScopeDefinition.
func (c *Client) Import(ctx context.Context, slug string) (*scope.ScopeDefinition, error) {
	url := fmt.Sprintf("%s/hackers/programs/%s/structured_scopes", c.baseURL, slug)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiUser != "" && c.apiToken != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.apiUser + ":" + c.apiToken))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackerone transport: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("hackerone %d: %s", resp.StatusCode, string(body))
	}

	var envelope struct {
		Data []struct {
			Attributes struct {
				AssetIdentifier     string `json:"asset_identifier"`
				AssetType           string `json:"asset_type"`
				EligibleForSubmission bool `json:"eligible_for_submission"`
				EligibleForBounty     bool `json:"eligible_for_bounty"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("parse hackerone response: %w", err)
	}
	return Map(envelope.Data), nil
}

// Reports fetches the authenticated researcher's own reports (up to
// `limit`, most recent first). Used by the dedup check in Phase 4.4.5
// — before filing a new report, we compare titles against what this
// researcher has already submitted to the same program.
//
// Requires API credentials; public programs aren't enough.
func (c *Client) Reports(ctx context.Context, limit int) ([]Report, error) {
	if c.apiUser == "" || c.apiToken == "" {
		return nil, fmt.Errorf("hackerone Reports: API credentials required")
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	url := fmt.Sprintf("%s/hackers/me/reports?page[size]=%d", c.baseURL, limit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	auth := base64.StdEncoding.EncodeToString([]byte(c.apiUser + ":" + c.apiToken))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackerone transport: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("hackerone %d: %s", resp.StatusCode, string(body))
	}
	var envelope struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Title     string `json:"title"`
				State     string `json:"state"`
				CreatedAt string `json:"created_at"`
			} `json:"attributes"`
			Relationships struct {
				Program struct {
					Data struct {
						Attributes struct {
							Handle string `json:"handle"`
						} `json:"attributes"`
					} `json:"data"`
				} `json:"program"`
			} `json:"relationships"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("parse reports: %w", err)
	}
	out := make([]Report, 0, len(envelope.Data))
	for _, r := range envelope.Data {
		out = append(out, Report{
			ID:      r.ID,
			Title:   r.Attributes.Title,
			State:   r.Attributes.State,
			Program: r.Relationships.Program.Data.Attributes.Handle,
		})
	}
	return out, nil
}

// Report is a summary of one H1 submission — enough for title-based dedup.
type Report struct {
	ID      string
	Title   string
	State   string // new | triaged | resolved | duplicate | …
	Program string
}

// PublicReports fetches a program's PUBLIC disclosed reports — the hacktivity
// feed filtered to one program. Used by Phase 4.4.6 dedup so we don't file
// a duplicate of something the program has already triaged and disclosed.
//
// Auth is recommended (higher rate limits) but not required — hacktivity is
// public. The endpoint is paginated; we cap at `limit` (default 25).
func (c *Client) PublicReports(ctx context.Context, programSlug string, limit int) ([]Report, error) {
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	// Hacktivity API: filter by team_handle to scope to one program.
	url := fmt.Sprintf("%s/hackers/hacktivity?queryString=team_handle:%s&page[size]=%d",
		c.baseURL, programSlug, limit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiUser != "" && c.apiToken != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.apiUser + ":" + c.apiToken))
		req.Header.Set("Authorization", "Basic "+auth)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackerone transport: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("hackerone %d: %s", resp.StatusCode, string(body))
	}
	// The hacktivity envelope wraps a 'report' relationship with the title
	// + state on each disclosed item.
	var envelope struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				Title     string `json:"title"`
				State     string `json:"state"`
				CreatedAt string `json:"created_at"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("parse hacktivity: %w", err)
	}
	out := make([]Report, 0, len(envelope.Data))
	for _, r := range envelope.Data {
		out = append(out, Report{
			ID:      r.ID,
			Title:   r.Attributes.Title,
			State:   r.Attributes.State,
			Program: programSlug,
		})
	}
	return out, nil
}

// Policy fetches the program's rules-of-engagement text. Used by
// `pentestswarm program inspect h1:<slug>` to extract machine-readable
// constraints (rate limits, banned techniques, required headers).
//
// Public programs work without auth; private ones need credentials.
func (c *Client) Policy(ctx context.Context, slug string) (string, error) {
	url := fmt.Sprintf("%s/hackers/programs/%s", c.baseURL, slug)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiUser != "" && c.apiToken != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.apiUser + ":" + c.apiToken))
		req.Header.Set("Authorization", "Basic "+auth)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("hackerone transport: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("hackerone %d: %s", resp.StatusCode, string(body))
	}
	var envelope struct {
		Data struct {
			Attributes struct {
				Policy string `json:"policy"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("parse policy: %w", err)
	}
	return envelope.Data.Attributes.Policy, nil
}

// Map converts the HackerOne response shape into our scope definition.
// Exposed for tests + for advanced callers that want to handle the raw
// API response themselves.
func Map(items []struct {
	Attributes struct {
		AssetIdentifier       string `json:"asset_identifier"`
		AssetType             string `json:"asset_type"`
		EligibleForSubmission bool   `json:"eligible_for_submission"`
		EligibleForBounty     bool   `json:"eligible_for_bounty"`
	} `json:"attributes"`
}) *scope.ScopeDefinition {
	def := &scope.ScopeDefinition{}
	for _, it := range items {
		// Skip items that aren't eligible for submission — they're
		// explicitly out-of-scope for reporting.
		if !it.Attributes.EligibleForSubmission {
			continue
		}
		id := strings.TrimSpace(it.Attributes.AssetIdentifier)
		if id == "" {
			continue
		}
		switch it.Attributes.AssetType {
		case "URL", "WILDCARD", "DOMAIN":
			def.AllowedDomains = append(def.AllowedDomains, id)
		case "CIDR":
			def.AllowedCIDRs = append(def.AllowedCIDRs, id)
		case "IP_ADDRESS":
			// Normalise bare IPs to a /32 CIDR so the downstream
			// validator never sees a mixed shape.
			def.AllowedCIDRs = append(def.AllowedCIDRs, id+"/32")
		}
	}
	return def
}

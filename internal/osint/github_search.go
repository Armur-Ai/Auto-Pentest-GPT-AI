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

// GitHubSearchClient queries GitHub's code-search API for hits across
// public repositories — the "leaked credentials in someone's
// otherwise-unrelated repo" attack surface that trufflehog/gitleaks
// can't find from inside the target's own codebase. Pair with
// trufflehog locally; this is the third-party-spread layer.
//
// Auth: Personal Access Token in the `Authorization: Bearer <token>`
// header. Code search is gated to authenticated users only — the API
// returns 422 without a token. Get a token at
// https://github.com/settings/tokens (no scopes required for public
// code search).
//
// Plan reference: 2.4.8 (P1) in IMPLEMENTATION_PLAN.md. Powers the
// OSINT/passive intel work in 6.7.3.
type GitHubSearchClient struct {
	token      string
	endpoint   string
	httpClient *http.Client
	queries    []string
}

// GitHubSearchConfig holds construction parameters.
type GitHubSearchConfig struct {
	Token    string
	Endpoint string // override for testing; default https://api.github.com
	Timeout  time.Duration
	// Queries override the default "spread your target name into a
	// known-bad-shape" probe list. Each query is templated with the
	// target — use {{target}} as the placeholder. Empty falls back to
	// the package default list (see defaultGitHubQueries below).
	Queries []string
}

// NewGitHubSearchClient builds a client. An empty token marks it as
// unavailable so the recon agent skips the source rather than burning
// rate limit on guaranteed-to-fail unauth requests.
func NewGitHubSearchClient(cfg GitHubSearchConfig) *GitHubSearchClient {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://api.github.com"
	}
	cfg.Endpoint = strings.TrimRight(cfg.Endpoint, "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	queries := cfg.Queries
	if len(queries) == 0 {
		queries = defaultGitHubQueries
	}
	return &GitHubSearchClient{
		token:      cfg.Token,
		endpoint:   cfg.Endpoint,
		httpClient: &http.Client{Timeout: cfg.Timeout},
		queries:    queries,
	}
}

// defaultGitHubQueries is the small built-in probe set. Each entry is
// templated with the target so a 3-line addition gives full coverage
// of common leakage shapes. Researchers can supply their own via
// Config.Queries for program-specific patterns.
//
// Why this list:
//   - `{{target}} api_key` and `{{target}} secret`: catches the
//     classic "I named my .env file with our company name and pushed
//     it" mistake.
//   - `{{target}} password`: catches plaintext passwords pasted into
//     fixtures, sample configs, or test scripts.
//   - `{{target}} BEGIN RSA PRIVATE KEY`: catches private keys checked
//     into example projects that reference the target's infra.
//
// Each query is wrapped with quotes around the target so multi-word
// targets ("Acme Bank") aren't split into separate terms by GitHub's
// tokenizer.
var defaultGitHubQueries = []string{
	`"{{target}}" api_key`,
	`"{{target}}" secret`,
	`"{{target}}" password`,
	`"{{target}}" BEGIN RSA PRIVATE KEY`,
}

// Name implements the loose OSINT-client interface.
func (g *GitHubSearchClient) Name() string { return "github_search" }

// IsAvailable returns true when a token is configured.
func (g *GitHubSearchClient) IsAvailable() bool { return g.token != "" }

// githubSearchResponse is the trimmed-down /search/code shape.
type githubSearchResponse struct {
	TotalCount        int          `json:"total_count"`
	IncompleteResults bool         `json:"incomplete_results"`
	Items             []githubItem `json:"items"`
}

type githubItem struct {
	Name       string           `json:"name"`        // file name
	Path       string           `json:"path"`        // path within repo
	HTMLURL    string           `json:"html_url"`    // clickable link for triage
	Repository githubRepository `json:"repository"`
}

type githubRepository struct {
	FullName string `json:"full_name"` // "owner/repo"
	HTMLURL  string `json:"html_url"`
	Private  bool   `json:"private"`
}

type githubErrorResponse struct {
	Message string `json:"message"`
}

// Lookup runs every configured query against the GitHub code-search
// endpoint and returns one "secret" asset per hit. The asset's Value
// is the HTML URL of the offending file so a researcher can click
// straight to the leak; Metadata carries repo + path + which query
// matched (the agent can use the query as a hint at WHY this hit was
// surfaced).
//
// Per-query failures are non-fatal: GitHub rate-limits aggressively
// on code search (10 req/min for authenticated users), so partial
// success across the query list is better than total failure on the
// first 403.
func (g *GitHubSearchClient) Lookup(ctx context.Context, target string) ([]Asset, error) {
	if !g.IsAvailable() {
		return nil, fmt.Errorf("no github token configured. Fix: add osint.github_search.token to ~/.pentestswarm/config.yaml or set PENTESTSWARM_GITHUB_SEARCH_TOKEN (any PAT with no extra scopes works for public code search)")
	}

	var all []Asset
	var firstErr error
	for _, raw := range g.queries {
		q := strings.ReplaceAll(raw, "{{target}}", target)
		assets, err := g.runOne(ctx, q)
		if err != nil {
			// Hold on to the first error so the caller has something
			// to log if everything failed, but keep iterating so a
			// transient 403 on one query doesn't black-hole the rest.
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		all = append(all, assets...)
	}
	if len(all) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return all, nil
}

// runOne issues one /search/code call for a fully-templated query
// string and converts the response to assets.
func (g *GitHubSearchClient) runOne(ctx context.Context, query string) ([]Asset, error) {
	u := fmt.Sprintf("%s/search/code?q=%s&per_page=30",
		g.endpoint, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("creating github request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		var ge githubErrorResponse
		_ = json.Unmarshal(body, &ge)
		msg := strings.TrimSpace(ge.Message)
		if msg == "" {
			msg = "auth or rate-limit"
		}
		return nil, fmt.Errorf("github returned %d: %s — check token at https://github.com/settings/tokens", resp.StatusCode, msg)
	}
	if resp.StatusCode == http.StatusUnprocessableEntity {
		// 422: the query was malformed or used a feature unavailable
		// for code search. Treat as no results for *this* query.
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github returned status %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	var doc githubSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding github response: %w", err)
	}

	out := make([]Asset, 0, len(doc.Items))
	for _, it := range doc.Items {
		out = append(out, Asset{
			Type:   "secret",
			Value:  it.HTMLURL,
			Source: "github_search",
			Metadata: map[string]any{
				"repo":    it.Repository.FullName,
				"path":    it.Path,
				"file":    it.Name,
				"query":   query,
				"private": it.Repository.Private,
			},
		})
	}
	return out, nil
}

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

// GitLabSearchClient queries GitLab's search API for code matches
// across public + accessible-private projects. Same use case as the
// GitHub variant — surface leaked credentials and vulnerable code
// patterns mentioning a target — but covers the slice of the
// open-source world that lives on GitLab (and on self-hosted GitLab
// instances, via Endpoint override).
//
// Auth: Personal Access Token in the `PRIVATE-TOKEN` header.
// Get one at https://gitlab.com/-/user_settings/personal_access_tokens
// (scopes: `read_api` is enough for code search).
//
// Plan reference: 2.4.9 (P2) in IMPLEMENTATION_PLAN.md. Parallels
// 2.4.8 (GitHub) — see internal/osint/github_search.go.
type GitLabSearchClient struct {
	token      string
	endpoint   string
	httpClient *http.Client
	queries    []string
}

// GitLabSearchConfig holds construction parameters.
type GitLabSearchConfig struct {
	Token    string
	Endpoint string // override for self-hosted GitLab; default https://gitlab.com/api/v4
	Timeout  time.Duration
	Queries  []string
}

// NewGitLabSearchClient builds a client. Empty token = unavailable;
// the recon agent skips the source so the scan still runs.
func NewGitLabSearchClient(cfg GitLabSearchConfig) *GitLabSearchClient {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://gitlab.com/api/v4"
	}
	cfg.Endpoint = strings.TrimRight(cfg.Endpoint, "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	queries := cfg.Queries
	if len(queries) == 0 {
		// Same probe set as the GitHub client. The leak patterns are
		// language-/platform-agnostic, so there's no good reason for
		// the two clients to diverge — sharing the list keeps coverage
		// symmetric across the two ecosystems.
		queries = defaultGitHubQueries
	}
	return &GitLabSearchClient{
		token:      cfg.Token,
		endpoint:   cfg.Endpoint,
		httpClient: &http.Client{Timeout: cfg.Timeout},
		queries:    queries,
	}
}

// Name implements the loose OSINT-client interface.
func (g *GitLabSearchClient) Name() string { return "gitlab_search" }

// IsAvailable returns true when a token is configured.
func (g *GitLabSearchClient) IsAvailable() bool { return g.token != "" }

// gitlabBlobHit is GitLab's /search?scope=blobs result shape. The
// API returns more fields (basename, ref, startline, data preview);
// we keep only what's needed for triage + dedup.
type gitlabBlobHit struct {
	Filename  string `json:"filename"`
	Path      string `json:"path"`
	ProjectID int    `json:"project_id"`
	Ref       string `json:"ref"`
	StartLine int    `json:"startline"`
}

// gitlabProject is /projects/<id> — used to resolve project_id into
// a human web_url so the asset's Value is clickable.
type gitlabProject struct {
	WebURL          string `json:"web_url"`
	PathWithNamespace string `json:"path_with_namespace"`
}

// Lookup runs every configured query against GitLab's search blobs
// endpoint, then resolves each hit's project_id into a clickable
// URL. Per-query failures are non-fatal (same discipline as the
// GitHub client) so a transient rate-limit doesn't black-hole the
// whole sweep.
func (g *GitLabSearchClient) Lookup(ctx context.Context, target string) ([]Asset, error) {
	if !g.IsAvailable() {
		return nil, fmt.Errorf("no gitlab token configured. Fix: add osint.gitlab_search.token to ~/.pentestswarm/config.yaml or set PENTESTSWARM_GITLAB_SEARCH_TOKEN (any PAT with read_api scope works)")
	}

	// Cache project metadata across queries — most leaks cluster in a
	// handful of repos, so resolving each project_id once saves a
	// round trip per duplicate hit.
	projectCache := map[int]gitlabProject{}

	var all []Asset
	var firstErr error
	for _, raw := range g.queries {
		q := strings.ReplaceAll(raw, "{{target}}", target)
		assets, err := g.runOne(ctx, q, projectCache)
		if err != nil {
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

// runOne issues one /search call and resolves each hit's project.
func (g *GitLabSearchClient) runOne(ctx context.Context, query string, cache map[int]gitlabProject) ([]Asset, error) {
	u := fmt.Sprintf("%s/search?scope=blobs&search=%s&per_page=30",
		g.endpoint, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("creating gitlab request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", g.token)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gitlab request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("gitlab returned %d — check the token at https://gitlab.com/-/user_settings/personal_access_tokens (needs read_api scope)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gitlab returned status %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	var hits []gitlabBlobHit
	if err := json.NewDecoder(resp.Body).Decode(&hits); err != nil {
		return nil, fmt.Errorf("decoding gitlab response: %w", err)
	}

	out := make([]Asset, 0, len(hits))
	for _, h := range hits {
		proj, err := g.resolveProject(ctx, h.ProjectID, cache)
		if err != nil {
			// Project lookup failure shouldn't drop the leak finding;
			// fall back to "project ID N" as the click-through path.
			proj = gitlabProject{WebURL: fmt.Sprintf("%s/projects/%d", g.endpoint, h.ProjectID)}
		}
		hitURL := fmt.Sprintf("%s/-/blob/%s/%s#L%d", proj.WebURL, h.Ref, h.Path, h.StartLine)
		out = append(out, Asset{
			Type:   "secret",
			Value:  hitURL,
			Source: "gitlab_search",
			Metadata: map[string]any{
				"repo":      proj.PathWithNamespace,
				"path":      h.Path,
				"file":      h.Filename,
				"ref":       h.Ref,
				"startline": h.StartLine,
				"query":     query,
			},
		})
	}
	return out, nil
}

// resolveProject hits /projects/<id> and caches the result. Cache
// is per-Lookup (not process-wide) to keep semantics simple — a
// long-running daemon would want a TTL'd cache, but the current
// recon agent invokes Lookup synchronously per campaign.
func (g *GitLabSearchClient) resolveProject(ctx context.Context, projectID int, cache map[int]gitlabProject) (gitlabProject, error) {
	if cached, ok := cache[projectID]; ok {
		return cached, nil
	}
	u := fmt.Sprintf("%s/projects/%d", g.endpoint, projectID)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return gitlabProject{}, err
	}
	req.Header.Set("PRIVATE-TOKEN", g.token)
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return gitlabProject{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return gitlabProject{}, fmt.Errorf("project lookup status %d", resp.StatusCode)
	}
	var p gitlabProject
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return gitlabProject{}, err
	}
	cache[projectID] = p
	return p, nil
}

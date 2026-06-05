package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestGitLabSearchClient_NoTokenIsAvailableFalse — no token = skip
// the source rather than fail the scan (one-command invariant).
func TestGitLabSearchClient_NoTokenIsAvailableFalse(t *testing.T) {
	if NewGitLabSearchClient(GitLabSearchConfig{}).IsAvailable() {
		t.Fatal("IsAvailable should be false without token")
	}
}

// TestGitLabSearchClient_LookupWithoutTokenActionable — error names
// the env var so the user can fix without leaving the terminal.
func TestGitLabSearchClient_LookupWithoutTokenActionable(t *testing.T) {
	_, err := NewGitLabSearchClient(GitLabSearchConfig{}).Lookup(context.Background(), "example")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "PENTESTSWARM_GITLAB_SEARCH_TOKEN") {
		t.Errorf("error should name env var: %v", err)
	}
}

// TestGitLabSearchClient_LookupHappyPath — verifies the request shape
// (path, PRIVATE-TOKEN header), the project-resolution side trip, and
// the response → Asset translation with a clickable URL composed from
// project web_url + ref + path + startline.
func TestGitLabSearchClient_LookupHappyPath(t *testing.T) {
	var capturedToken string
	var searchCalls, projectCalls int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		capturedToken = r.Header.Get("PRIVATE-TOKEN")
		mu.Unlock()
		switch {
		case strings.HasPrefix(r.URL.Path, "/search"):
			mu.Lock()
			searchCalls++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]gitlabBlobHit{{
				Filename: "secrets.yml", Path: "config/secrets.yml",
				ProjectID: 42, Ref: "main", StartLine: 12,
			}})
		case strings.HasPrefix(r.URL.Path, "/projects/"):
			mu.Lock()
			projectCalls++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(gitlabProject{
				WebURL:            "https://gitlab.com/leaky/repo",
				PathWithNamespace: "leaky/repo",
			})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	c := NewGitLabSearchClient(GitLabSearchConfig{
		Token:    "glpat-test",
		Endpoint: server.URL,
		Queries:  []string{`"{{target}}" api_key`},
	})

	assets, err := c.Lookup(context.Background(), "acmecorp")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if capturedToken != "glpat-test" {
		t.Errorf("PRIVATE-TOKEN = %q", capturedToken)
	}
	if searchCalls != 1 || projectCalls != 1 {
		t.Errorf("call counts wrong: search=%d project=%d", searchCalls, projectCalls)
	}

	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	a := assets[0]
	wantURL := "https://gitlab.com/leaky/repo/-/blob/main/config/secrets.yml#L12"
	if a.Value != wantURL {
		t.Errorf("value = %q, want %q", a.Value, wantURL)
	}
	if a.Metadata["repo"] != "leaky/repo" {
		t.Errorf("metadata.repo = %v", a.Metadata["repo"])
	}
}

// TestGitLabSearchClient_ProjectCacheDeduplicates — two hits in the
// same project should only trigger one /projects/<id> lookup, even
// across separate query iterations.
func TestGitLabSearchClient_ProjectCacheDeduplicates(t *testing.T) {
	var searchCalls, projectCalls int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/search"):
			mu.Lock()
			searchCalls++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode([]gitlabBlobHit{{
				Filename: "a.yml", Path: "a.yml", ProjectID: 7, Ref: "main", StartLine: 1,
			}})
		case strings.HasPrefix(r.URL.Path, "/projects/"):
			mu.Lock()
			projectCalls++
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(gitlabProject{WebURL: "https://gl/x", PathWithNamespace: "x/y"})
		}
	}))
	defer server.Close()

	c := NewGitLabSearchClient(GitLabSearchConfig{
		Token:    "tok",
		Endpoint: server.URL,
		Queries:  []string{"q1 {{target}}", "q2 {{target}}", "q3 {{target}}"},
	})

	if _, err := c.Lookup(context.Background(), "ex"); err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if searchCalls != 3 {
		t.Errorf("search calls = %d, want 3 (one per query)", searchCalls)
	}
	if projectCalls != 1 {
		t.Errorf("project calls = %d, want 1 (cached across queries)", projectCalls)
	}
}

// TestGitLabSearchClient_PartialFailureKeepsGoing — same discipline as
// the GitHub client: a 403 on one query doesn't poison the rest.
func TestGitLabSearchClient_PartialFailureKeepsGoing(t *testing.T) {
	var n int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/projects/") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(gitlabProject{WebURL: "https://gl/x"})
			return
		}
		mu.Lock()
		n++
		curr := n
		mu.Unlock()
		if curr == 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]gitlabBlobHit{{
			Filename: "ok.yml", Path: "ok.yml", ProjectID: 1, Ref: "main", StartLine: 1,
		}})
	}))
	defer server.Close()

	c := NewGitLabSearchClient(GitLabSearchConfig{
		Token: "tok", Endpoint: server.URL,
		Queries: []string{"q1 {{target}}", "q2 {{target}}"},
	})

	assets, err := c.Lookup(context.Background(), "ex")
	if err != nil {
		t.Fatalf("partial failure should not bubble; got %v", err)
	}
	if len(assets) != 1 {
		t.Errorf("expected 1 asset from successful query, got %d", len(assets))
	}
}

// TestGitLabSearchClient_AllFailErrorBubblesUp — when every query
// fails, the first error surfaces.
func TestGitLabSearchClient_AllFailErrorBubblesUp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	c := NewGitLabSearchClient(GitLabSearchConfig{
		Token: "tok", Endpoint: server.URL,
		Queries: []string{"q1 {{target}}"},
	})

	_, err := c.Lookup(context.Background(), "ex")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "gitlab.com/-/user_settings/personal_access_tokens") {
		t.Errorf("error should point at the token console: %v", err)
	}
}

// TestGitLabSearchClient_FallsBackToProjectIDOnLookupFailure — if the
// /projects/<id> side-call fails, the blob hit still becomes a
// finding, just with a uglier (but still actionable) URL.
func TestGitLabSearchClient_FallsBackToProjectIDOnLookupFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/projects/") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]gitlabBlobHit{{
			Filename: "x.yml", Path: "x.yml", ProjectID: 99, Ref: "main", StartLine: 1,
		}})
	}))
	defer server.Close()

	c := NewGitLabSearchClient(GitLabSearchConfig{
		Token: "tok", Endpoint: server.URL,
		Queries: []string{"q {{target}}"},
	})

	assets, err := c.Lookup(context.Background(), "ex")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	if !strings.Contains(assets[0].Value, fmt.Sprintf("projects/%d", 99)) {
		t.Errorf("fallback URL should include project id: %q", assets[0].Value)
	}
}

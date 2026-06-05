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

// TestGitHubSearchClient_NoTokenIsAvailableFalse — without a token,
// the client never even hits the endpoint (GitHub code search is gated
// to authed users; unauth requests are guaranteed 422).
func TestGitHubSearchClient_NoTokenIsAvailableFalse(t *testing.T) {
	if NewGitHubSearchClient(GitHubSearchConfig{}).IsAvailable() {
		t.Fatal("IsAvailable should be false without a token")
	}
}

// TestGitHubSearchClient_LookupWithoutTokenActionable — error names
// the env var so the user can fix it without leaving the terminal.
func TestGitHubSearchClient_LookupWithoutTokenActionable(t *testing.T) {
	_, err := NewGitHubSearchClient(GitHubSearchConfig{}).Lookup(context.Background(), "example")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "PENTESTSWARM_GITHUB_SEARCH_TOKEN") {
		t.Errorf("error should name env var: %v", err)
	}
}

// TestGitHubSearchClient_LookupHappyPath — verifies the request
// shape (path, Bearer auth, query templating with the target
// substituted into the {{target}} placeholder) and the response →
// Asset translation.
func TestGitHubSearchClient_LookupHappyPath(t *testing.T) {
	var capturedAuth, capturedAccept string
	var capturedQueries []string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		capturedAuth = r.Header.Get("Authorization")
		capturedAccept = r.Header.Get("Accept")
		capturedQueries = append(capturedQueries, r.URL.Query().Get("q"))
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(githubSearchResponse{
			TotalCount: 1,
			Items: []githubItem{{
				Name:    "config.yml",
				Path:    "config/config.yml",
				HTMLURL: "https://github.com/leaky/repo/blob/main/config/config.yml",
				Repository: githubRepository{
					FullName: "leaky/repo",
					HTMLURL:  "https://github.com/leaky/repo",
					Private:  false,
				},
			}},
		})
	}))
	defer server.Close()

	c := NewGitHubSearchClient(GitHubSearchConfig{
		Token:    "ghp_test",
		Endpoint: server.URL,
		Queries:  []string{`"{{target}}" api_key`},
	})

	assets, err := c.Lookup(context.Background(), "acmecorp")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if capturedAuth != "Bearer ghp_test" {
		t.Errorf("Authorization = %q", capturedAuth)
	}
	if capturedAccept != "application/vnd.github+json" {
		t.Errorf("Accept = %q", capturedAccept)
	}
	if len(capturedQueries) != 1 || capturedQueries[0] != `"acmecorp" api_key` {
		t.Errorf("templated query = %v, want `\"acmecorp\" api_key`", capturedQueries)
	}

	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	a := assets[0]
	if a.Type != "secret" {
		t.Errorf("type = %q, want secret", a.Type)
	}
	if a.Value != "https://github.com/leaky/repo/blob/main/config/config.yml" {
		t.Errorf("value = %q", a.Value)
	}
	if a.Metadata["repo"] != "leaky/repo" {
		t.Errorf("metadata.repo = %v", a.Metadata["repo"])
	}
}

// TestGitHubSearchClient_MultipleQueriesAllRun — confirms each query
// in the configured list fires once per Lookup, and assets accumulate
// across them.
func TestGitHubSearchClient_MultipleQueriesAllRun(t *testing.T) {
	var calls int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// Return 1 item per call so the final count = number of queries.
		_ = json.NewEncoder(w).Encode(githubSearchResponse{
			TotalCount: 1,
			Items: []githubItem{{
				Name:    fmt.Sprintf("hit-%d.txt", n),
				HTMLURL: fmt.Sprintf("https://github.com/x/y/blob/main/hit-%d.txt", n),
				Repository: githubRepository{FullName: "x/y"},
			}},
		})
	}))
	defer server.Close()

	c := NewGitHubSearchClient(GitHubSearchConfig{
		Token:    "tok",
		Endpoint: server.URL,
		Queries:  []string{"q1 {{target}}", "q2 {{target}}", "q3 {{target}}"},
	})

	assets, err := c.Lookup(context.Background(), "ex")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 API calls (one per query), got %d", calls)
	}
	if len(assets) != 3 {
		t.Errorf("expected 3 assets across queries, got %d", len(assets))
	}
}

// TestGitHubSearchClient_PartialFailureKeepsGoing — GitHub
// rate-limits aggressively on code search; a 403 on one query must
// not poison the whole Lookup. Verify that subsequent queries still
// run and their hits come back.
func TestGitHubSearchClient_PartialFailureKeepsGoing(t *testing.T) {
	var n int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		curr := n
		mu.Unlock()
		if curr == 1 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"rate limited"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(githubSearchResponse{
			TotalCount: 1,
			Items: []githubItem{{
				Name: "ok.txt", HTMLURL: "https://github.com/x/y/blob/main/ok.txt",
				Repository: githubRepository{FullName: "x/y"},
			}},
		})
	}))
	defer server.Close()

	c := NewGitHubSearchClient(GitHubSearchConfig{
		Token:    "tok",
		Endpoint: server.URL,
		Queries:  []string{"q1 {{target}}", "q2 {{target}}"},
	})

	assets, err := c.Lookup(context.Background(), "ex")
	if err != nil {
		t.Fatalf("partial failure should not fail Lookup; got %v", err)
	}
	if len(assets) != 1 {
		t.Errorf("expected 1 asset from the successful query, got %d", len(assets))
	}
}

// TestGitHubSearchClient_AllFailErrorBubblesUp — when *every* query
// fails, the first error is returned so the caller has something
// actionable in the log instead of a silent empty result.
func TestGitHubSearchClient_AllFailErrorBubblesUp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"hard limit"}`))
	}))
	defer server.Close()

	c := NewGitHubSearchClient(GitHubSearchConfig{
		Token:    "tok",
		Endpoint: server.URL,
		Queries:  []string{"q1 {{target}}", "q2 {{target}}"},
	})

	_, err := c.Lookup(context.Background(), "ex")
	if err == nil {
		t.Fatal("expected error when every query failed")
	}
	if !strings.Contains(err.Error(), "github.com/settings/tokens") {
		t.Errorf("error should point at the token console: %v", err)
	}
}

// TestGitHubSearchClient_DefaultQueryList — when no Queries are
// supplied, the built-in list is used. Sanity check that the default
// list isn't empty (which would silently make Lookup a no-op).
func TestGitHubSearchClient_DefaultQueryList(t *testing.T) {
	c := NewGitHubSearchClient(GitHubSearchConfig{Token: "tok"})
	if len(c.queries) == 0 {
		t.Fatal("default query list is empty — clients with no Queries config would no-op")
	}
}

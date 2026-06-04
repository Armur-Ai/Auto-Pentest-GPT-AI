package bugbounty

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// BugBountyProgram represents a bug bounty program from any platform.
type BugBountyProgram struct {
	Handle     string       `json:"handle"`
	Name       string       `json:"name"`
	Platform   string       `json:"platform"` // hackerone, bugcrowd
	Policy     string       `json:"policy"`
	InScope    []ScopeAsset `json:"in_scope"`
	OutOfScope []ScopeAsset `json:"out_of_scope"`
}

// ScopeAsset represents a single scoped asset.
type ScopeAsset struct {
	AssetType         string `json:"asset_type"` // URL, domain, IP, app
	Identifier        string `json:"identifier"`
	EligibleForBounty bool   `json:"eligible_for_bounty"`
	MaxSeverity       string `json:"max_severity,omitempty"`
}

// Submission represents a previously submitted report.
type Submission struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	State       string    `json:"state"`
	Severity    string    `json:"severity"`
	SubmittedAt time.Time `json:"submitted_at"`
}

// HackerOneClient interacts with the HackerOne API.
type HackerOneClient struct {
	apiKey   string
	username string
	client   *http.Client
	baseURL  string
}

// NewHackerOneClient creates a new HackerOne API client.
func NewHackerOneClient(apiKey, username string) *HackerOneClient {
	return &HackerOneClient{
		apiKey:   apiKey,
		username: username,
		client:   &http.Client{Timeout: 30 * time.Second},
		baseURL:  "https://api.hackerone.com/v1",
	}
}

// GetProgram fetches program details.
func (h *HackerOneClient) GetProgram(ctx context.Context, handle string) (*BugBountyProgram, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/hackers/programs/%s", h.baseURL, handle), nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(h.username, h.apiKey)

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching H1 program %s: %w", handle, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("H1 API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			Attributes struct {
				Handle string `json:"handle"`
				Name   string `json:"name"`
				Policy string `json:"policy"`
			} `json:"attributes"`
			Relationships struct {
				StructuredScopes struct {
					Data []struct {
						Attributes struct {
							AssetType         string `json:"asset_type"`
							AssetIdentifier   string `json:"asset_identifier"`
							EligibleForBounty bool   `json:"eligible_for_bounty"`
							MaxSeverity       string `json:"max_severity"`
						} `json:"attributes"`
					} `json:"data"`
				} `json:"structured_scopes"`
			} `json:"relationships"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("parsing H1 response: %w", err)
	}

	program := &BugBountyProgram{
		Handle:   result.Data.Attributes.Handle,
		Name:     result.Data.Attributes.Name,
		Platform: "hackerone",
		Policy:   result.Data.Attributes.Policy,
	}

	for _, scope := range result.Data.Relationships.StructuredScopes.Data {
		program.InScope = append(program.InScope, ScopeAsset{
			AssetType:         scope.Attributes.AssetType,
			Identifier:        scope.Attributes.AssetIdentifier,
			EligibleForBounty: scope.Attributes.EligibleForBounty,
			MaxSeverity:       scope.Attributes.MaxSeverity,
		})
	}

	return program, nil
}

// GetSubmissions fetches previous submissions for duplicate checking.
func (h *HackerOneClient) GetSubmissions(ctx context.Context, handle string) ([]Submission, error) {
	// H1 API requires separate endpoint for user's submissions
	// Simplified: return empty for now, will be populated with real API calls
	return []Submission{}, nil
}

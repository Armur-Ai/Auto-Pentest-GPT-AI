// Package jira sends pentest findings to Atlassian Jira as issues.
// Maps severity -> Jira priority via a built-in table; operators can
// override per-deployment by supplying a custom PriorityMap.
package jira

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// Client talks to a Jira Cloud or Server instance.
type Client struct {
	base       string
	user       string
	token      string
	project    string
	issueType  string
	priorities map[pipeline.Severity]string
	http       *http.Client
}

// Config customizes a Client.
type Config struct {
	URL        string // https://your-domain.atlassian.net
	Username   string
	APIToken   string
	Project    string                       // project key, e.g. SEC
	IssueType  string                       // default Bug
	Priorities map[pipeline.Severity]string // optional override
	Timeout    time.Duration
}

// DefaultPriorityMap maps pentest severities to Jira's standard priority names.
var DefaultPriorityMap = map[pipeline.Severity]string{
	pipeline.SeverityCritical:      "Highest",
	pipeline.SeverityHigh:          "High",
	pipeline.SeverityMedium:        "Medium",
	pipeline.SeverityLow:           "Low",
	pipeline.SeverityInformational: "Lowest",
}

// NewClient builds a Jira client.
func NewClient(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.IssueType == "" {
		cfg.IssueType = "Bug"
	}
	prios := cfg.Priorities
	if prios == nil {
		prios = DefaultPriorityMap
	}
	return &Client{
		base:       strings.TrimRight(cfg.URL, "/"),
		user:       cfg.Username,
		token:      cfg.APIToken,
		project:    cfg.Project,
		issueType:  cfg.IssueType,
		priorities: prios,
		http:       &http.Client{Timeout: cfg.Timeout},
	}
}

// CreateIssue turns a finding into a Jira issue and returns the issue key.
func (c *Client) CreateIssue(ctx context.Context, f pipeline.ClassifiedFinding) (string, error) {
	body := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": c.project},
			"issuetype":   map[string]string{"name": c.issueType},
			"priority":    map[string]string{"name": c.priorities[f.Severity]},
			"summary":     fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), f.Title),
			"description": buildDescription(f),
			"labels":      []string{"pentest-swarm-ai", string(f.Severity), sanitiseLabel(f.AttackCategory)},
		},
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/rest/api/2/issue", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.user != "" {
		req.Header.Set("Authorization", "Basic "+basicAuth(c.user, c.token))
	} else if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("jira transport: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("jira status %d: %s", resp.StatusCode, string(data))
	}
	var created struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(data, &created); err != nil {
		return "", err
	}
	return created.Key, nil
}

func buildDescription(f pipeline.ClassifiedFinding) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Severity: *%s* | CVSS: %.1f", strings.Title(string(f.Severity)), f.CVSSScore)
	if f.CVSSVector != "" {
		fmt.Fprintf(&sb, " (`%s`)", f.CVSSVector)
	}
	sb.WriteString("\n\n")
	sb.WriteString(f.Description)
	if len(f.CVEIDs) > 0 {
		sb.WriteString("\n\nCVE: " + strings.Join(f.CVEIDs, ", "))
	}
	sb.WriteString("\n\n_Auto-filed by Pentest Swarm AI._")
	return sb.String()
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func sanitiseLabel(s string) string {
	if s == "" {
		return "uncategorised"
	}
	var out []rune
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+32)
		case r == '_' || r == '-':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

// Package zap is a minimal REST client for OWASP ZAP. ZAP exposes its
// entire surface via HTTP+JSON; we cover the bits the swarm actually
// orchestrates — spider, active scan, alerts — and leave the rest to
// Burp or direct ZAP automation.
//
// Launch ZAP in daemon mode once per engagement:
//
//	zap.sh -daemon -port 8090 -config api.key=SWARM_KEY
package zap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client talks to a ZAP daemon.
type Client struct {
	base   string
	apiKey string
	http   *http.Client
}

// Config customises a Client.
type Config struct {
	Endpoint string // default http://127.0.0.1:8090
	APIKey   string
	Timeout  time.Duration
}

// NewClient builds a client pointed at a running ZAP daemon.
func NewClient(cfg Config) *Client {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "http://127.0.0.1:8090"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Client{
		base:   cfg.Endpoint,
		apiKey: cfg.APIKey,
		http:   &http.Client{Timeout: cfg.Timeout},
	}
}

// StartSpider triggers ZAP's spider and returns the scan id.
func (c *Client) StartSpider(ctx context.Context, target string) (string, error) {
	var resp struct {
		Scan string `json:"scan"`
	}
	if err := c.get(ctx, "/JSON/spider/action/scan/", url.Values{"url": {target}}, &resp); err != nil {
		return "", err
	}
	return resp.Scan, nil
}

// SpiderStatus returns progress (0-100) for a spider scan.
func (c *Client) SpiderStatus(ctx context.Context, scanID string) (int, error) {
	var resp struct {
		Status string `json:"status"`
	}
	if err := c.get(ctx, "/JSON/spider/view/status/", url.Values{"scanId": {scanID}}, &resp); err != nil {
		return 0, err
	}
	pct := 0
	fmt.Sscanf(resp.Status, "%d", &pct)
	return pct, nil
}

// StartActiveScan kicks off an active scan. Must be preceded by a spider.
func (c *Client) StartActiveScan(ctx context.Context, target string) (string, error) {
	var resp struct {
		Scan string `json:"scan"`
	}
	if err := c.get(ctx, "/JSON/ascan/action/scan/", url.Values{"url": {target}}, &resp); err != nil {
		return "", err
	}
	return resp.Scan, nil
}

// ActiveScanStatus returns progress (0-100) for an active scan.
func (c *Client) ActiveScanStatus(ctx context.Context, scanID string) (int, error) {
	var resp struct {
		Status string `json:"status"`
	}
	if err := c.get(ctx, "/JSON/ascan/view/status/", url.Values{"scanId": {scanID}}, &resp); err != nil {
		return 0, err
	}
	pct := 0
	fmt.Sscanf(resp.Status, "%d", &pct)
	return pct, nil
}

// Alerts returns all alerts scoped to a base URL (empty = all).
func (c *Client) Alerts(ctx context.Context, baseURL string) ([]Alert, error) {
	params := url.Values{}
	if baseURL != "" {
		params.Set("baseurl", baseURL)
	}
	var resp struct {
		Alerts []Alert `json:"alerts"`
	}
	if err := c.get(ctx, "/JSON/core/view/alerts/", params, &resp); err != nil {
		return nil, err
	}
	return resp.Alerts, nil
}

// Alert is ZAP's alert shape (a subset; ZAP emits ~40 fields — we track the useful ones).
type Alert struct {
	ID          string `json:"id"`
	PluginID    string `json:"pluginId"`
	Name        string `json:"name"`
	Risk        string `json:"risk"`       // High | Medium | Low | Informational
	Confidence  string `json:"confidence"` // High | Medium | Low | Confirmed
	URL         string `json:"url"`
	Param       string `json:"param"`
	Attack      string `json:"attack"`
	Evidence    string `json:"evidence"`
	Description string `json:"description"`
	Solution    string `json:"solution"`
	CWEID       string `json:"cweid"`
	WASCID      string `json:"wascid"`
}

// --- transport ---

func (c *Client) get(ctx context.Context, path string, params url.Values, into any) error {
	if params == nil {
		params = url.Values{}
	}
	if c.apiKey != "" {
		params.Set("apikey", c.apiKey)
	}
	u := c.base + path + "?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("zap transport: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("zap status %d: %s", resp.StatusCode, string(body))
	}
	if into == nil {
		return nil
	}
	return json.Unmarshal(body, into)
}

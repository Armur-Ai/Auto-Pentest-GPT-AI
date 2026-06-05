package osint

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
)

// CensysClient queries Censys's Search API (v2) for hosts attributable
// to a target. The Censys "Search Hosts" endpoint accepts a Censys-
// query-language string; we use `dns.names:<target>` which matches
// hosts whose forward/reverse DNS includes the target domain.
//
// Auth: Basic with `<api_id>:<api_secret>` per the v2 spec — not a
// Bearer token. Both halves are required; get them at
// https://search.censys.io/account/api.
//
// Plan reference: 2.4.6 (P1) in IMPLEMENTATION_PLAN.md.
type CensysClient struct {
	apiID      string
	apiSecret  string
	endpoint   string
	httpClient *http.Client
}

// CensysConfig holds construction parameters.
type CensysConfig struct {
	APIID     string
	APISecret string
	Endpoint  string // override for testing; default https://search.censys.io/api
	Timeout   time.Duration
}

// NewCensysClient builds a client. Both APIID and APISecret are
// required for the client to be Available; either being empty
// short-circuits Lookup with an actionable error.
func NewCensysClient(cfg CensysConfig) *CensysClient {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://search.censys.io/api"
	}
	cfg.Endpoint = strings.TrimRight(cfg.Endpoint, "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &CensysClient{
		apiID:      cfg.APIID,
		apiSecret:  cfg.APISecret,
		endpoint:   cfg.Endpoint,
		httpClient: &http.Client{Timeout: cfg.Timeout},
	}
}

// Name implements the loose OSINT-client interface.
func (c *CensysClient) Name() string { return "censys" }

// IsAvailable returns true when both halves of the API credential
// are present.
func (c *CensysClient) IsAvailable() bool { return c.apiID != "" && c.apiSecret != "" }

// censysSearchRequest is the v2 host-search payload.
type censysSearchRequest struct {
	Q       string `json:"q"`
	PerPage int    `json:"per_page,omitempty"`
}

// censysSearchResponse mirrors only the fields we consume; Censys
// returns many more (services list, location, autonomous_system) —
// added to Metadata only when present so a schema rotation upstream
// doesn't break the client.
type censysSearchResponse struct {
	Code   int `json:"code"`
	Result struct {
		Total int          `json:"total"`
		Hits  []censysHost `json:"hits"`
	} `json:"result"`
	Error string `json:"error,omitempty"`
}

type censysHost struct {
	IP       string         `json:"ip"`
	Name     string         `json:"name,omitempty"`
	Services []censysSvc    `json:"services,omitempty"`
	DNS      *censysDNS     `json:"dns,omitempty"`
	Location map[string]any `json:"location,omitempty"`
	AS       map[string]any `json:"autonomous_system,omitempty"`
}

type censysSvc struct {
	Port              int    `json:"port"`
	ServiceName       string `json:"service_name,omitempty"`
	TransportProtocol string `json:"transport_protocol,omitempty"`
}

type censysDNS struct {
	Names        []string `json:"names,omitempty"`
	ReverseDNS   []string `json:"reverse_dns,omitempty"`
}

// Lookup runs a `dns.names:<target>` search and returns normalized
// assets. Each host becomes one "host" asset; each service inside it
// becomes a "service" asset (IP:port); each DNS name surfaces as a
// "subdomain" asset for downstream dedup with subfinder/amass.
func (c *CensysClient) Lookup(ctx context.Context, target string) ([]Asset, error) {
	if !c.IsAvailable() {
		return nil, fmt.Errorf("no censys credentials configured. Fix: add osint.censys.api_id + osint.censys.api_secret to ~/.pentestswarm/config.yaml or set PENTESTSWARM_CENSYS_API_ID + PENTESTSWARM_CENSYS_API_SECRET")
	}

	reqBody := censysSearchRequest{
		Q:       fmt.Sprintf("dns.names:%s", target),
		PerPage: 100,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("encoding censys request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint+"/v2/hosts/search", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating censys request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Censys v2 expects HTTP Basic with id:secret — not a Bearer token.
	authBytes := []byte(c.apiID + ":" + c.apiSecret)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(authBytes))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("censys request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("censys returned %d — check the API ID and secret (https://search.censys.io/account/api)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("censys returned status %d: %s", resp.StatusCode, truncate(string(raw), 256))
	}

	var doc censysSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding censys response: %w", err)
	}
	if doc.Error != "" {
		return nil, fmt.Errorf("censys api error: %s", doc.Error)
	}

	return censysToAssets(doc), nil
}

// censysToAssets translates a search response. Pulled out so unit
// tests don't need to spin up an HTTP server.
func censysToAssets(doc censysSearchResponse) []Asset {
	seenSubs := map[string]bool{}
	out := make([]Asset, 0, len(doc.Result.Hits)*3)

	for _, h := range doc.Result.Hits {
		// One host asset per Censys hit — captures the IP-as-target.
		hostMeta := map[string]any{
			"ip": h.IP,
		}
		if h.Name != "" {
			hostMeta["name"] = h.Name
		}
		if len(h.Location) > 0 {
			hostMeta["location"] = h.Location
		}
		if len(h.AS) > 0 {
			hostMeta["autonomous_system"] = h.AS
		}
		out = append(out, Asset{
			Type:     "host",
			Value:    h.IP,
			Source:   "censys",
			Metadata: hostMeta,
		})

		// One service asset per discovered port/protocol on the host.
		for _, s := range h.Services {
			out = append(out, Asset{
				Type:   "service",
				Value:  fmt.Sprintf("%s:%d", h.IP, s.Port),
				Source: "censys",
				Metadata: map[string]any{
					"ip":           h.IP,
					"port":         s.Port,
					"service_name": s.ServiceName,
					"transport":    s.TransportProtocol,
				},
			})
		}

		// Subdomain assets for downstream merge with subfinder/amass.
		if h.DNS != nil {
			for _, n := range h.DNS.Names {
				if n == "" || seenSubs[n] {
					continue
				}
				seenSubs[n] = true
				out = append(out, Asset{Type: "subdomain", Value: n, Source: "censys"})
			}
		}
	}
	return out
}

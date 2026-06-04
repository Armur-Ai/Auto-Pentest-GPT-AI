package recon

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/tools"
)

// fallbackSource is the value we stamp on records that came in via a
// tolerated fallback shape (flat string, single object) rather than the
// strict object-array shape. Downstream code and logs can grep for this
// marker to see when a local model is drifting from the spec.
const fallbackSource = "llm-flat"

// rawSurface mirrors AttackSurface but keeps the polymorphic fields as
// raw bytes so we can attempt multiple unmarshal shapes per field. Local
// quantized models (qwen2.5-coder, deepseek-v4-pro, …) routinely emit
// subdomains as flat string arrays and technologies as arrays instead
// of maps; this lets us recover the data instead of failing the whole
// campaign on a shape mismatch. See #16, #19, and the original #7.
type rawSurface struct {
	CampaignID   uuid.UUID       `json:"campaign_id"`
	Target       string          `json:"target"`
	Subdomains   json.RawMessage `json:"subdomains"`
	Hosts        json.RawMessage `json:"hosts"`
	Endpoints    json.RawMessage `json:"endpoints"`
	Technologies json.RawMessage `json:"technologies"`
	CreatedAt    time.Time       `json:"created_at"`
}

// ParseAttackSurface parses an LLM response into a structured AttackSurface.
// The four polymorphic fields (subdomains, hosts, endpoints, technologies)
// tolerate the common shape-drifts we see from local Ollama models.
func ParseAttackSurface(rawJSON string) (*pipeline.AttackSurface, error) {
	rawJSON = stripCodeFence(rawJSON)
	rawJSON = strings.TrimSpace(rawJSON)

	if rawJSON == "" {
		return nil, fmt.Errorf("empty response from LLM")
	}

	var raw rawSurface
	if err := json.Unmarshal([]byte(rawJSON), &raw); err != nil {
		return nil, fmt.Errorf("parsing attack surface JSON: %w (raw: %.200s)", err, rawJSON)
	}

	return &pipeline.AttackSurface{
		CampaignID:   raw.CampaignID,
		Target:       raw.Target,
		Subdomains:   parseSubdomains(raw.Subdomains),
		Hosts:        parseHosts(raw.Hosts),
		Endpoints:    parseEndpoints(raw.Endpoints),
		Technologies: parseTechnologies(raw.Technologies),
		CreatedAt:    raw.CreatedAt,
	}, nil
}

// parseSubdomains tolerates three shapes: the strict object-array, a flat
// string array (model emitted just the names), or a single object. Returns
// nil for missing / unparseable fields rather than erroring — the campaign
// continues with whatever shape we recovered.
func parseSubdomains(raw json.RawMessage) []pipeline.SubdomainRecord {
	if isEmpty(raw) {
		return nil
	}
	var strict []pipeline.SubdomainRecord
	if err := json.Unmarshal(raw, &strict); err == nil {
		return strict
	}
	var flat []string
	if err := json.Unmarshal(raw, &flat); err == nil {
		out := make([]pipeline.SubdomainRecord, 0, len(flat))
		for _, s := range flat {
			if s == "" {
				continue
			}
			out = append(out, pipeline.SubdomainRecord{Domain: s, Source: fallbackSource})
		}
		return out
	}
	var single pipeline.SubdomainRecord
	if err := json.Unmarshal(raw, &single); err == nil && single.Domain != "" {
		return []pipeline.SubdomainRecord{single}
	}
	return nil
}

// parseHosts handles three shapes: the strict object-array, a flat string
// array (treated as IPs), or a single object. Same fallback discipline.
func parseHosts(raw json.RawMessage) []pipeline.HostRecord {
	if isEmpty(raw) {
		return nil
	}
	var strict []pipeline.HostRecord
	if err := json.Unmarshal(raw, &strict); err == nil {
		return strict
	}
	var flat []string
	if err := json.Unmarshal(raw, &flat); err == nil {
		out := make([]pipeline.HostRecord, 0, len(flat))
		for _, ip := range flat {
			if ip == "" {
				continue
			}
			out = append(out, pipeline.HostRecord{IP: ip})
		}
		return out
	}
	var single pipeline.HostRecord
	if err := json.Unmarshal(raw, &single); err == nil && single.IP != "" {
		return []pipeline.HostRecord{single}
	}
	return nil
}

// parseEndpoints handles three shapes: the strict object-array, a flat
// string array (treated as URLs), or a single object.
func parseEndpoints(raw json.RawMessage) []pipeline.EndpointRecord {
	if isEmpty(raw) {
		return nil
	}
	var strict []pipeline.EndpointRecord
	if err := json.Unmarshal(raw, &strict); err == nil {
		return strict
	}
	var flat []string
	if err := json.Unmarshal(raw, &flat); err == nil {
		out := make([]pipeline.EndpointRecord, 0, len(flat))
		for _, u := range flat {
			if u == "" {
				continue
			}
			out = append(out, pipeline.EndpointRecord{URL: u})
		}
		return out
	}
	var single pipeline.EndpointRecord
	if err := json.Unmarshal(raw, &single); err == nil && single.URL != "" {
		return []pipeline.EndpointRecord{single}
	}
	return nil
}

// parseTechnologies handles two shapes: the strict map[name]version, or a
// flat array of names (version stamped as empty). Closes the same family
// as #7 — local models often emit tech stacks as a list, not a map.
func parseTechnologies(raw json.RawMessage) map[string]string {
	if isEmpty(raw) {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err == nil {
		return m
	}
	var flat []string
	if err := json.Unmarshal(raw, &flat); err == nil {
		out := make(map[string]string, len(flat))
		for _, t := range flat {
			if t != "" {
				out[t] = ""
			}
		}
		return out
	}
	return nil
}

// isEmpty returns true for missing fields and explicit JSON null. Avoids
// per-field nil-vs-null branching in every parser.
func isEmpty(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null"
}

// MergeToolResults deduplicates and enriches findings from multiple tools.
func MergeToolResults(results []*tools.ToolResult) MergedData {
	merged := MergedData{
		Subdomains: make(map[string]bool),
		Hosts:      make(map[string]bool),
		Endpoints:  make(map[string]bool),
	}

	for _, r := range results {
		if r.Error != nil {
			continue
		}

		for _, finding := range r.ParsedFindings {
			if subdomain, ok := finding["subdomain"].(string); ok {
				merged.Subdomains[subdomain] = true
			}
			if host, ok := finding["host"].(string); ok {
				merged.Hosts[host] = true
			}
			if url, ok := finding["url"].(string); ok {
				merged.Endpoints[url] = true
			}
		}
	}

	return merged
}

// MergedData holds deduplicated data from multiple tool results.
type MergedData struct {
	Subdomains map[string]bool
	Hosts      map[string]bool
	Endpoints  map[string]bool
}

// UniqueSubdomains returns the deduplicated subdomain list.
func (m MergedData) UniqueSubdomains() []string {
	result := make([]string, 0, len(m.Subdomains))
	for s := range m.Subdomains {
		result = append(result, s)
	}
	return result
}

// stripCodeFence removes markdown ```json ... ``` wrappers.
func stripCodeFence(s string) string {
	s = strings.TrimSpace(s)

	// Remove ```json prefix
	if strings.HasPrefix(s, "```json") {
		s = s[7:]
	} else if strings.HasPrefix(s, "```") {
		s = s[3:]
	}

	// Remove ``` suffix
	if strings.HasSuffix(s, "```") {
		s = s[:len(s)-3]
	}

	return strings.TrimSpace(s)
}

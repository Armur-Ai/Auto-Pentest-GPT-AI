package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// KubeHunterTool wraps aquasecurity/kube-hunter
// (https://github.com/aquasecurity/kube-hunter) for Kubernetes
// cluster misconfiguration scanning. kube-hunter probes the cluster
// from a "what does an external attacker see" angle: exposed API
// server, anonymous-auth Kubelets, accessible etcd, public dashboard,
// readable Tiller (helm v2), etc.
//
// Two run modes upstream:
//   - "remote" (--remote <ip-or-hostname>): scan from outside the cluster
//   - "interface" (--interface): scan from inside a pod / node
//
// We default to remote since the swarm typically runs outside the
// target cluster. The mode flag exposes interface scanning for the
// rare case where the agent is running inside a pod.
//
// Plan reference: 2.1.12 (P2) in IMPLEMENTATION_PLAN.md. Pairs with
// 5.6.8 (cloud / infrastructure specialization).
type KubeHunterTool struct{}

// NewKubeHunterTool constructs the adapter.
func NewKubeHunterTool() *KubeHunterTool { return &KubeHunterTool{} }

// Name implements Tool. Underscore version matches the 2.1.12 plan
// identifier; binary on PATH uses a hyphen, handled in Run.
func (k *KubeHunterTool) Name() string { return "kube_hunter" }

// IsAvailable checks for `kube-hunter` (upstream binary name).
func (k *KubeHunterTool) IsAvailable() bool { return IsCommandAvailable("kube-hunter") }

// Run executes kube-hunter against a target. `target` is the
// cluster's external IP / hostname / CIDR (remote mode) or "self"
// (interface mode — adapter ignores the target and scans the
// node it runs on).
//
// Supported options:
//
//	timeout int    — per-invocation timeout in seconds (default 600).
//	mode    string — "remote" (default), "cidr", "interface", or
//	                 "active" (active includes exploit attempts —
//	                 only use with --safe-mode off in the executor).
//	report  string — report format passed to --report (default "json").
func (k *KubeHunterTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("kube_hunter", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in kube_hunter: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 600)) * time.Second

	tmp, err := os.CreateTemp("", "kube-hunter-*.json")
	if err != nil {
		return &ToolResult{ToolName: "kube_hunter", Target: target, Error: err}, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	mode := opts.GetString("mode", "remote")
	args := []string{
		"--report", opts.GetString("report", "json"),
		"--log", "none",
		"-o", tmpPath,
	}

	switch mode {
	case "interface":
		args = append(args, "--interface")
	case "cidr":
		args = append(args, "--cidr", target)
	case "active":
		args = append(args, "--remote", target, "--active")
	default: // remote
		args = append(args, "--remote", target)
	}

	result := RunToolCommand(ctx, "kube_hunter", target, timeout, "kube-hunter", args...)
	if result.Error != nil && !strings.Contains(result.Error.Error(), "exit status") {
		return result, result.Error
	}
	// kube-hunter returns non-zero when vulns are found.
	result.Error = nil

	body, readErr := os.ReadFile(tmpPath)
	if readErr != nil || len(body) == 0 {
		// Fall back to stdout — kube-hunter sometimes ignores -o and
		// prints to stdout depending on version.
		body = []byte(result.RawOutput)
	}
	result.ParsedFindings = parseKubeHunterJSON(body)
	return result, nil
}

// kubeHunterReport mirrors kube-hunter's --report json shape. The
// `vulnerabilities` array is the actionable bit; nodes / services
// also come back but are mostly informational (the LLM can extract
// from RawOutput if needed).
type kubeHunterReport struct {
	Vulnerabilities []kubeHunterVuln `json:"vulnerabilities"`
}

type kubeHunterVuln struct {
	Location       string `json:"location"`
	VID            string `json:"vid"`
	Category       string `json:"category"`
	Severity       string `json:"severity"` // "low" | "medium" | "high"
	Vulnerability  string `json:"vulnerability"`
	Description    string `json:"description"`
	Evidence       string `json:"evidence,omitempty"`
	AvdReference   string `json:"avd_reference,omitempty"`
	Hunter         string `json:"hunter,omitempty"`
}

// parseKubeHunterJSON walks the vulnerabilities array and emits one
// finding per entry. Severity comes through from kube-hunter
// directly (already lowercase). Empty / malformed body → nil.
func parseKubeHunterJSON(body []byte) []map[string]any {
	if len(body) == 0 {
		return nil
	}
	var doc kubeHunterReport
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var findings []map[string]any
	for _, v := range doc.Vulnerabilities {
		findings = append(findings, map[string]any{
			"tool":         "kube_hunter",
			"vid":          v.VID,
			"category":     v.Category,
			"severity":     v.Severity,
			"title":        v.Vulnerability,
			"description":  v.Description,
			"location":     v.Location,
			"evidence":     v.Evidence,
			"avd_reference": v.AvdReference,
			"hunter":       v.Hunter,
		})
	}
	return findings
}

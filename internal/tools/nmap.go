package tools

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// NmapTool shells out to nmap, parses the XML output, and returns
// structured findings. Unlike the ProjectDiscovery tools, nmap is a
// subprocess adapter (no usable Go library) — so `doctor` surfaces a
// missing-nmap warning instead of failing hard at run time.
type NmapTool struct{}

// NewNmapTool constructs the adapter.
func NewNmapTool() *NmapTool { return &NmapTool{} }

// Name implements Tool.
func (n *NmapTool) Name() string { return "nmap" }

// IsAvailable implements Tool.
func (n *NmapTool) IsAvailable() bool { return IsCommandAvailable("nmap") }

// Run executes nmap with sensible defaults for authorized pentests:
// -sV service/version detection, -T4 aggressive timing, -Pn skip host
// discovery (targets in scope are explicitly-known to the operator),
// --top-ports 1000 by default. All flags are overridable via opts.
func (n *NmapTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	if scopeDef := getScopeFromContext(ctx); scopeDef != nil {
		if err := scope.ValidateAndLog("nmap", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in nmap: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 300)) * time.Second
	topPorts := opts.GetInt("top_ports", 1000)
	scanType := opts.GetString("scan_type", "-sV") // -sV service/version; -sS SYN; -sT TCP connect
	timing := opts.GetString("timing", "-T4")

	args := []string{
		scanType,
		timing,
		"-Pn",
		"--top-ports", fmt.Sprintf("%d", topPorts),
		"-oX", "-", // XML to stdout
		target,
	}

	result := RunToolCommand(ctx, "nmap", target, timeout, "nmap", args...)
	if result.Error != nil {
		return result, result.Error
	}

	hosts, err := parseNmapXML(result.RawOutput)
	if err != nil {
		// Keep raw output so callers can still reason about it.
		return result, nil
	}

	// Normalise into parsed_findings so the existing coordinator sees them.
	for _, h := range hosts {
		for _, p := range h.Ports {
			result.ParsedFindings = append(result.ParsedFindings, map[string]any{
				"ip":        h.Address,
				"hostnames": h.Hostnames,
				"port":      p.PortID,
				"protocol":  p.Protocol,
				"state":     p.State,
				"service":   p.Service,
				"version":   p.Version,
				"product":   p.Product,
				"os":        h.OS,
			})
		}
	}
	return result, nil
}

// --- XML types ---
//
// Minimal subset of the nmap XML schema — only what we actually surface.

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddr `xml:"address"`
	Hostnames []nmapHN   `xml:"hostnames>hostname"`
	Ports     nmapPorts  `xml:"ports"`
	OSMatch   []nmapOS   `xml:"os>osmatch"`
	Status    nmapStatus `xml:"status"`
}

type nmapAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHN struct {
	Name string `xml:"name,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string    `xml:"protocol,attr"`
	PortID   int       `xml:"portid,attr"`
	State    nmapState `xml:"state"`
	Service  nmapSvc   `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapSvc struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type nmapOS struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

// --- Parsed host shape (what the adapter returns internally) ---

type nmapHostParsed struct {
	Address   string
	Hostnames []string
	OS        string
	Ports     []nmapPortParsed
}

type nmapPortParsed struct {
	PortID   int
	Protocol string
	State    string
	Service  string
	Product  string
	Version  string
}

func parseNmapXML(raw string) ([]nmapHostParsed, error) {
	var run nmapRun
	if err := xml.Unmarshal([]byte(raw), &run); err != nil {
		return nil, fmt.Errorf("parsing nmap xml: %w", err)
	}
	out := make([]nmapHostParsed, 0, len(run.Hosts))
	for _, h := range run.Hosts {
		if h.Status.State != "" && h.Status.State != "up" {
			continue
		}
		hp := nmapHostParsed{}
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				hp.Address = a.Addr
				break
			}
		}
		for _, n := range h.Hostnames {
			if n.Name != "" {
				hp.Hostnames = append(hp.Hostnames, n.Name)
			}
		}
		if len(h.OSMatch) > 0 {
			hp.OS = strings.TrimSpace(h.OSMatch[0].Name)
		}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			hp.Ports = append(hp.Ports, nmapPortParsed{
				PortID:   p.PortID,
				Protocol: p.Protocol,
				State:    p.State.State,
				Service:  p.Service.Name,
				Product:  p.Service.Product,
				Version:  p.Service.Version,
			})
		}
		out = append(out, hp)
	}
	return out, nil
}

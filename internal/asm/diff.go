package asm

import (
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// AssetDiff represents changes between two attack surface snapshots.
type AssetDiff struct {
	NewSubdomains       []string             `json:"new_subdomains"`
	RemovedSubdomains   []string             `json:"removed_subdomains"`
	NewPorts            map[string][]int     `json:"new_ports"`
	ClosedPorts         map[string][]int     `json:"closed_ports"`
	NewEndpoints        []string             `json:"new_endpoints"`
	ChangedTechnologies map[string][2]string `json:"changed_technologies"` // key -> [old, new]
}

// IsSignificant returns true if the diff warrants an auto-triggered scan.
func (d *AssetDiff) IsSignificant() bool {
	return len(d.NewSubdomains) > 0 ||
		len(d.NewPorts) > 0 ||
		len(d.NewEndpoints) > 0
}

// Diff computes the differences between two attack surfaces.
func Diff(prev, curr *pipeline.AttackSurface) *AssetDiff {
	diff := &AssetDiff{
		NewPorts:            make(map[string][]int),
		ClosedPorts:         make(map[string][]int),
		ChangedTechnologies: make(map[string][2]string),
	}

	// Subdomain diff
	prevSubs := toSet(extractSubdomains(prev))
	currSubs := toSet(extractSubdomains(curr))

	for sub := range currSubs {
		if !prevSubs[sub] {
			diff.NewSubdomains = append(diff.NewSubdomains, sub)
		}
	}
	for sub := range prevSubs {
		if !currSubs[sub] {
			diff.RemovedSubdomains = append(diff.RemovedSubdomains, sub)
		}
	}

	// Port diff per host
	prevHosts := hostPortMap(prev)
	currHosts := hostPortMap(curr)

	for host, currPorts := range currHosts {
		prevPorts := prevHosts[host]
		for _, p := range currPorts {
			if !containsInt(prevPorts, p) {
				diff.NewPorts[host] = append(diff.NewPorts[host], p)
			}
		}
	}
	for host, prevPorts := range prevHosts {
		currPorts := currHosts[host]
		for _, p := range prevPorts {
			if !containsInt(currPorts, p) {
				diff.ClosedPorts[host] = append(diff.ClosedPorts[host], p)
			}
		}
	}

	// Endpoint diff
	prevEPs := toSet(extractEndpoints(prev))
	currEPs := toSet(extractEndpoints(curr))
	for ep := range currEPs {
		if !prevEPs[ep] {
			diff.NewEndpoints = append(diff.NewEndpoints, ep)
		}
	}

	// Technology changes
	for tech, currVer := range curr.Technologies {
		if prevVer, ok := prev.Technologies[tech]; ok && prevVer != currVer {
			diff.ChangedTechnologies[tech] = [2]string{prevVer, currVer}
		}
	}

	return diff
}

func extractSubdomains(surface *pipeline.AttackSurface) []string {
	var subs []string
	for _, s := range surface.Subdomains {
		subs = append(subs, s.Domain)
	}
	return subs
}

func extractEndpoints(surface *pipeline.AttackSurface) []string {
	var eps []string
	for _, e := range surface.Endpoints {
		eps = append(eps, e.URL)
	}
	return eps
}

func hostPortMap(surface *pipeline.AttackSurface) map[string][]int {
	m := make(map[string][]int)
	for _, h := range surface.Hosts {
		m[h.IP] = h.OpenPorts
	}
	return m
}

func toSet(items []string) map[string]bool {
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[item] = true
	}
	return s
}

func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

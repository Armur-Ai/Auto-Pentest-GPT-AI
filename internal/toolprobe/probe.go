// Package toolprobe reports which external security tools are installed
// on the current host. Used by `pentestswarm init` (print the report at
// setup) and `pentestswarm doctor` (print the report on demand). Tools
// are grouped so the output reads sensibly.
package toolprobe

import (
	"os/exec"
	"runtime"
)

// Tool is one external binary that Pentest Swarm AI can use if present.
type Tool struct {
	Name        string // the PATH name we look up (e.g. "nmap")
	Purpose     string // one-line description shown in the init report
	InstallHint string // OS-appropriate install command
	Critical    bool   // if true, missing = degraded core capability
}

// Group is a themed bucket of tools.
type Group struct {
	Title string
	Tools []Tool
}

// Result is the structured output of a probe.
type Result struct {
	Group   Group
	Present map[string]bool
}

// AllGroups returns the full ordered list of groups + tools we probe.
// Keep this list in sync with anything new added to internal/tools/.
func AllGroups() []Group {
	installBrew := "brew install"
	installAPT := "apt install"
	if runtime.GOOS != "darwin" {
		installBrew = installAPT
	}
	return []Group{
		{
			Title: "Reconnaissance",
			Tools: []Tool{
				{Name: "subfinder", Purpose: "passive subdomain enum", InstallHint: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
				{Name: "dnsx", Purpose: "DNS resolution", InstallHint: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
				{Name: "httpx", Purpose: "HTTP probing", InstallHint: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
				{Name: "naabu", Purpose: "fast port scanning", InstallHint: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
				{Name: "katana", Purpose: "web crawling", InstallHint: "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
				{Name: "gau", Purpose: "historical URL discovery", InstallHint: "go install github.com/lc/gau/v2/cmd/gau@latest"},
				{Name: "nmap", Purpose: "port + service scanner", InstallHint: installBrew + " nmap", Critical: false},
				{Name: "amass", Purpose: "deep OSINT / ASM", InstallHint: installBrew + " amass"},
			},
		},
		{
			Title: "Vulnerability scanners",
			Tools: []Tool{
				{Name: "nuclei", Purpose: "CVE + misconfig templates", InstallHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", Critical: true},
				{Name: "sqlmap", Purpose: "SQL-injection exploitation", InstallHint: installBrew + " sqlmap"},
			},
		},
		{
			Title: "Content discovery",
			Tools: []Tool{
				{Name: "ffuf", Purpose: "URL + param fuzzing", InstallHint: "go install github.com/ffuf/ffuf/v2@latest"},
				{Name: "gobuster", Purpose: "alternative content discovery", InstallHint: installBrew + " gobuster"},
			},
		},
		{
			Title: "Source / secret scanning",
			Tools: []Tool{
				{Name: "trufflehog", Purpose: "repo + artifact secret scan", InstallHint: installBrew + " trufflehog"},
				{Name: "gitleaks", Purpose: "git history secrets", InstallHint: installBrew + " gitleaks"},
				{Name: "semgrep", Purpose: "SAST for in-scope repos", InstallHint: "pip install semgrep"},
			},
		},
		{
			Title: "Evidence capture",
			Tools: []Tool{
				{Name: "gowitness", Purpose: "headless screenshots for reports", InstallHint: "go install github.com/sensepost/gowitness@latest"},
			},
		},
	}
}

// Probe walks AllGroups and checks each tool against PATH.
func Probe() []Result {
	var out []Result
	for _, g := range AllGroups() {
		r := Result{Group: g, Present: map[string]bool{}}
		for _, t := range g.Tools {
			r.Present[t.Name] = IsPresent(t.Name)
		}
		out = append(out, r)
	}
	return out
}

// IsPresent returns true when the binary exists in PATH.
func IsPresent(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Missing returns the names of tools NOT found, across all groups.
func Missing(results []Result) []Tool {
	var out []Tool
	for _, r := range results {
		for _, t := range r.Group.Tools {
			if !r.Present[t.Name] {
				out = append(out, t)
			}
		}
	}
	return out
}

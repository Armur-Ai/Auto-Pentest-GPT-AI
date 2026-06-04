// Package evidence captures report-ready artifacts from a finding's
// Reproduction block:
//
//   - .http files: the raw HTTP request is written to disk so the
//     researcher can import it into Burp Repeater via "Paste URL / raw"
//     without having to recreate headers by hand.
//   - screenshots: when gowitness is present in PATH, we shell out and
//     capture the rendered page. Missing gowitness = skip silently;
//     the feature is a nicety, not a hard requirement.
//
// Phase 4.4.8 of Wave 4.
package evidence

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// Capture writes every available artifact for a finding into outDir
// and returns the paths it produced (so the report template can link
// to them by relative path). Missing tools / empty Reproduction are
// non-fatal — the researcher still gets whatever we could gather.
func Capture(ctx context.Context, f pipeline.ClassifiedFinding, outDir string) ([]string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", outDir, err)
	}
	var paths []string

	if f.Reproduce != nil && f.Reproduce.HTTPRequest != "" {
		if p, err := writeHTTPFile(outDir, f); err == nil {
			paths = append(paths, p)
		}
	}
	if url := firstURL(f); url != "" {
		if p, err := screenshot(ctx, outDir, f, url); err == nil && p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// writeHTTPFile dumps the raw HTTP request into a .http file. Most
// HTTP clients (Burp, VS Code REST Client, JetBrains HTTP Client) can
// import this shape directly.
func writeHTTPFile(outDir string, f pipeline.ClassifiedFinding) (string, error) {
	name := slug(f.Title, 40) + ".http"
	path := filepath.Join(outDir, name)
	content := strings.ReplaceAll(f.Reproduce.HTTPRequest, "\n", "\r\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("write http file: %w", err)
	}
	return path, nil
}

// screenshot uses gowitness to render a URL. Returns the PNG path or
// empty string when gowitness isn't installed (silent skip — it's not
// a hard requirement).
func screenshot(ctx context.Context, outDir string, f pipeline.ClassifiedFinding, url string) (string, error) {
	if _, err := exec.LookPath("gowitness"); err != nil {
		return "", nil
	}
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	shotDir := filepath.Join(outDir, "screenshots")
	if err := os.MkdirAll(shotDir, 0o755); err != nil {
		return "", err
	}
	// gowitness writes <outdir>/<hash>.png by default.
	cmd := exec.CommandContext(runCtx, "gowitness", "single",
		"--url", url,
		"--screenshot-path", shotDir,
	)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gowitness: %w", err)
	}
	// Return the most-recent file under shotDir as a best-effort path;
	// gowitness picks a content-hashed name so we don't know it upfront.
	entries, _ := os.ReadDir(shotDir)
	var latest os.FileInfo
	var latestPath string
	for _, e := range entries {
		info, _ := e.Info()
		if latest == nil || info.ModTime().After(latest.ModTime()) {
			latest = info
			latestPath = filepath.Join(shotDir, e.Name())
		}
	}
	return latestPath, nil
}

// firstURL returns the best candidate URL for a screenshot — prefers
// an explicit HTTPRequest URL, falls back to Target if it looks URL-shaped.
func firstURL(f pipeline.ClassifiedFinding) string {
	if strings.HasPrefix(f.Target, "http://") || strings.HasPrefix(f.Target, "https://") {
		return f.Target
	}
	return ""
}

// slug lowercases + hyphenates + caps length — same rule as submit's
// filename sanitiser but duplicated to keep this package dep-free.
func slug(s string, maxLen int) string {
	out := make([]byte, 0, len(s))
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, byte(r))
		case r == ' ', r == '-', r == '_':
			out = append(out, '-')
		}
	}
	s2 := strings.Trim(string(out), "-")
	if len(s2) > maxLen {
		s2 = s2[:maxLen]
	}
	if s2 == "" {
		s2 = "finding"
	}
	return s2
}

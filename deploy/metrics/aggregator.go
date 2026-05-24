package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Metrics aggregates download counts from all distribution channels.
type Metrics struct {
	TotalDownloads int            `json:"total_downloads"`
	WeeklyTotal    int            `json:"weekly_total"`
	Channels       map[string]int `json:"channels"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// Aggregator polls download counts from all channels.
type Aggregator struct {
	client *http.Client
}

// NewAggregator creates a new metrics aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{client: &http.Client{Timeout: 30 * time.Second}}
}

// Collect gathers download metrics from all channels.
func (a *Aggregator) Collect() *Metrics {
	m := &Metrics{
		Channels:  make(map[string]int),
		UpdatedAt: time.Now(),
	}

	// npm
	if count := a.fetchNPM(); count > 0 {
		m.Channels["npm"] = count
		m.WeeklyTotal += count
	}

	// Docker Hub
	if count := a.fetchDockerHub(); count > 0 {
		m.Channels["docker"] = count
		m.TotalDownloads += count
	}

	// GitHub Releases
	if count := a.fetchGitHubReleases(); count > 0 {
		m.Channels["github_releases"] = count
		m.TotalDownloads += count
	}

	// PyPI
	if count := a.fetchPyPI(); count > 0 {
		m.Channels["pypi"] = count
		m.WeeklyTotal += count
	}

	return m
}

func (a *Aggregator) fetchNPM() int {
	resp, err := a.client.Get("https://api.npmjs.org/downloads/point/last-week/@armurai/pentestswarm")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	var result struct {
		Downloads int `json:"downloads"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Downloads
}

func (a *Aggregator) fetchDockerHub() int {
	resp, err := a.client.Get("https://hub.docker.com/v2/repositories/armurai/pentestswarm/")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	var result struct {
		PullCount int `json:"pull_count"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.PullCount
}

func (a *Aggregator) fetchGitHubReleases() int {
	resp, err := a.client.Get("https://api.github.com/repos/Armur-Ai/pentestswarm/releases")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var releases []struct {
		Assets []struct {
			DownloadCount int `json:"download_count"`
		} `json:"assets"`
	}
	json.Unmarshal(body, &releases)

	total := 0
	for _, r := range releases {
		for _, asset := range r.Assets {
			total += asset.DownloadCount
		}
	}
	return total
}

func (a *Aggregator) fetchPyPI() int {
	resp, err := a.client.Get("https://pypistats.org/api/packages/pentestswarm-sdk/recent")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			LastWeek int `json:"last_week"`
		} `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Data.LastWeek
}

// ServeMetricsAPI starts a tiny HTTP server for the metrics dashboard.
func ServeMetricsAPI(port int) {
	agg := NewAggregator()
	var cached *Metrics

	http.HandleFunc("/api/metrics", func(w http.ResponseWriter, r *http.Request) {
		if cached == nil || time.Since(cached.UpdatedAt) > time.Hour {
			cached = agg.Collect()
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(cached)
	})

	// Shields.io compatible badge endpoint
	http.HandleFunc("/api/badge/total", func(w http.ResponseWriter, r *http.Request) {
		if cached == nil {
			cached = agg.Collect()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"schemaVersion": 1,
			"label":         "downloads",
			"message":       formatCount(cached.TotalDownloads),
			"color":         "blue",
		})
	})

	http.HandleFunc("/api/badge/weekly", func(w http.ResponseWriter, r *http.Request) {
		if cached == nil {
			cached = agg.Collect()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"schemaVersion": 1,
			"label":         "downloads/week",
			"message":       formatCount(cached.WeeklyTotal),
			"color":         "green",
		})
	})

	fmt.Printf("Metrics API serving on :%d\n", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func formatCount(n int) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

func main() {
	ServeMetricsAPI(3001)
}

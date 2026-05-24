package zap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// fakeZAP stubs the four ZAP endpoints the client drives. Params-drive
// switch so the same server can be reused across tests.
func fakeZAP(t *testing.T, apiKey string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiKey != "" && r.URL.Query().Get("apikey") != apiKey {
			http.Error(w, "bad api key", 403)
			return
		}
		switch r.URL.Path {
		case "/JSON/spider/action/scan/":
			_ = json.NewEncoder(w).Encode(map[string]string{"scan": "11"})
		case "/JSON/spider/view/status/":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "100"})
		case "/JSON/ascan/action/scan/":
			_ = json.NewEncoder(w).Encode(map[string]string{"scan": "22"})
		case "/JSON/ascan/view/status/":
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "75"})
		case "/JSON/core/view/alerts/":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"alerts": []map[string]any{
					{
						"id": "1", "pluginId": "40018", "name": "SQL Injection",
						"risk": "High", "confidence": "Medium",
						"url": "https://example.com/?id=1",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestStartSpiderAndStatus(t *testing.T) {
	srv := fakeZAP(t, "")
	defer srv.Close()
	c := NewClient(Config{Endpoint: srv.URL})
	id, err := c.StartSpider(context.Background(), "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if id != "11" {
		t.Fatalf("want scan id 11, got %q", id)
	}
	pct, err := c.SpiderStatus(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if pct != 100 {
		t.Fatalf("want 100%%, got %d", pct)
	}
}

func TestActiveScanLifecycle(t *testing.T) {
	srv := fakeZAP(t, "")
	defer srv.Close()
	c := NewClient(Config{Endpoint: srv.URL})
	id, _ := c.StartActiveScan(context.Background(), "https://example.com")
	if id != "22" {
		t.Fatalf("want 22, got %q", id)
	}
	pct, _ := c.ActiveScanStatus(context.Background(), id)
	if pct != 75 {
		t.Fatalf("want 75, got %d", pct)
	}
}

func TestAlerts(t *testing.T) {
	srv := fakeZAP(t, "")
	defer srv.Close()
	c := NewClient(Config{Endpoint: srv.URL})
	alerts, err := c.Alerts(context.Background(), "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Name != "SQL Injection" || alerts[0].Risk != "High" {
		t.Fatalf("unexpected alerts: %+v", alerts)
	}
}

func TestAPIKeyRequired(t *testing.T) {
	srv := fakeZAP(t, "secret")
	defer srv.Close()

	// Wrong key — 403.
	c := NewClient(Config{Endpoint: srv.URL, APIKey: "wrong"})
	if _, err := c.StartSpider(context.Background(), "https://example.com"); err == nil {
		t.Fatal("bad api key should fail")
	}
	// Right key — ok.
	c = NewClient(Config{Endpoint: srv.URL, APIKey: "secret"})
	if _, err := c.StartSpider(context.Background(), "https://example.com"); err != nil {
		t.Fatalf("good api key should pass: %v", err)
	}
}

// Query values should be URL-encoded properly. Guard against a regression
// where the client stuffs spaces raw into the query string.
func TestQueryEncoding(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		_ = json.NewEncoder(w).Encode(map[string]string{"scan": "1"})
	}))
	defer srv.Close()
	c := NewClient(Config{Endpoint: srv.URL})
	_, _ = c.StartSpider(context.Background(), "https://example.com/foo bar?x=y")
	if got.Get("url") != "https://example.com/foo bar?x=y" {
		t.Fatalf("url param not passed through properly: %v", got)
	}
}

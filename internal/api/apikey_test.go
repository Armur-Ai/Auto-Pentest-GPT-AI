package api

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// TestAPIKeyMiddleware_AllowsHealthWithoutKey ensures the /api/v1/health
// endpoint stays reachable without authentication so load-balancer
// probes don't need the key distributed to every LB instance. See #44.5.
func TestAPIKeyMiddleware_AllowsHealthWithoutKey(t *testing.T) {
	app := fiber.New()
	app.Use(apiKeyMiddleware("secret"))
	app.Get("/api/v1/health", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("/health should be 200 without key; got %d", resp.StatusCode)
	}
}

// TestAPIKeyMiddleware_RejectsMissingKey covers the negative path: a
// request to any non-health endpoint without the X-API-Key header
// gets 401.
func TestAPIKeyMiddleware_RejectsMissingKey(t *testing.T) {
	app := fiber.New()
	app.Use(apiKeyMiddleware("secret"))
	app.Get("/api/v1/campaigns", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/api/v1/campaigns", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("missing key should be 401; got %d", resp.StatusCode)
	}
}

// TestAPIKeyMiddleware_RejectsWrongKey covers the equally-important
// case where the caller supplied a key but it doesn't match.
func TestAPIKeyMiddleware_RejectsWrongKey(t *testing.T) {
	app := fiber.New()
	app.Use(apiKeyMiddleware("secret"))
	app.Get("/api/v1/campaigns", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/api/v1/campaigns", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("wrong key should be 401; got %d", resp.StatusCode)
	}
}

// TestAPIKeyMiddleware_AllowsCorrectKey is the happy path.
func TestAPIKeyMiddleware_AllowsCorrectKey(t *testing.T) {
	app := fiber.New()
	app.Use(apiKeyMiddleware("secret"))
	app.Get("/api/v1/campaigns", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/api/v1/campaigns", nil)
	req.Header.Set("X-API-Key", "secret")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("correct key should be 200; got %d", resp.StatusCode)
	}
}

// TestAPIKeyMiddleware_LengthMismatchStillRejects guards against the
// classic constant-time comparison pitfall where short inputs can short-
// circuit. Even an empty key shouldn't bypass the gate.
func TestAPIKeyMiddleware_LengthMismatchStillRejects(t *testing.T) {
	app := fiber.New()
	app.Use(apiKeyMiddleware("secret"))
	app.Get("/api/v1/campaigns", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	for _, k := range []string{"", "s", "secretX"} {
		req := httptest.NewRequest("GET", "/api/v1/campaigns", nil)
		if k != "" {
			req.Header.Set("X-API-Key", k)
		}
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("request failed for key %q: %v", k, err)
		}
		if resp.StatusCode != 401 {
			t.Errorf("length-mismatch key %q should be 401; got %d", k, resp.StatusCode)
		}
	}
}

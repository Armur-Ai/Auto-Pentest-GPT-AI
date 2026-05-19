package scope

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeScopeYAML(t *testing.T, dir, name string, def ScopeDefinition) string {
	t.Helper()
	data, _ := yamlMarshalTest(def)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// yamlMarshalTest keeps the test independent of the yaml import alias
// at the callsite.
func yamlMarshalTest(v any) ([]byte, error) {
	// Re-use the same yaml package the production code uses.
	data, err := yamlMarshal(v)
	return data, err
}

// Indirection so the test file doesn't need to import yaml directly.
var yamlMarshal = func(v any) ([]byte, error) {
	return []byte{}, nil
}

func TestWatcher_ReloadDetectsDrift(t *testing.T) {
	// Avoid test-yaml import gymnastics: serialize via a tiny inline marshaller.
	yamlMarshal = func(v any) ([]byte, error) {
		def := v.(ScopeDefinition)
		out := "allowed_domains:\n"
		for _, d := range def.AllowedDomains {
			out += "  - " + d + "\n"
		}
		out += "allowed_cidrs: []\n"
		return []byte(out), nil
	}

	dir := t.TempDir()
	path := writeScopeYAML(t, dir, "scope.yaml", ScopeDefinition{
		AllowedDomains: []string{"a.com", "b.com"},
	})

	w := NewWatcher(path, 30*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	w.Start(ctx)
	defer w.Stop()

	// Current should reflect the initial two domains.
	cur := w.Current()
	if len(cur.AllowedDomains) != 2 {
		t.Fatalf("initial: want 2 domains, got %v", cur.AllowedDomains)
	}

	// Remove one domain on disk — the watcher should surface the diff.
	writeScopeYAML(t, dir, "scope.yaml", ScopeDefinition{
		AllowedDomains: []string{"a.com"},
	})

	select {
	case d := <-w.Changes():
		if len(d.RemovedDomains) != 1 || d.RemovedDomains[0] != "b.com" {
			t.Fatalf("want b.com removed; got %+v", d)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("watcher did not publish a diff within 1s")
	}
}

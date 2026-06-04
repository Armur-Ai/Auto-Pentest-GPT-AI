// Package importer adapts bug-bounty platform APIs into our scope.yaml
// shape. One Importer per platform (HackerOne, Bugcrowd, Intigriti, …).
// Callers depend only on the Importer interface; platform details stay
// in the per-platform subpackages.
package importer

import (
	"context"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// Importer pulls scope for a single program from a platform.
type Importer interface {
	// Platform is the short identifier used in the CLI: "h1" / "bugcrowd" / "intigriti".
	Platform() string

	// Import fetches the current scope for the program and returns it as
	// a ScopeDefinition ready to be marshaled into scope.yaml.
	Import(ctx context.Context, programSlug string) (*scope.ScopeDefinition, error)
}

// Assertions every Importer must satisfy. Adding a new importer in a
// subpackage becomes a one-line change here after the implementation.
var (
	_ = []Importer{}
)

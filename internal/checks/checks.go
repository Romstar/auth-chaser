// Package checks defines the Check interface and registry helpers.
package checks

import (
	"context"

	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/httpclient"
	"github.com/Romstar/auth-chaser/pkg/types"
)

// Context supplies shared dependencies to a check.
type Context struct {
	Cfg    config.Config
	Client *httpclient.Client
}

// Check is one non-destructive verification unit.
type Check interface {
	ID() string
	Title() string
	Category() types.Category
	Run(ctx context.Context, cctx Context) ([]types.Finding, error)
}

// Registry holds ordered checks selected for a run.
type Registry struct {
	items []Check
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Add appends checks.
func (r *Registry) Add(cs ...Check) {
	r.items = append(r.items, cs...)
}

// All returns registered checks.
func (r *Registry) All() []Check {
	return append([]Check(nil), r.items...)
}

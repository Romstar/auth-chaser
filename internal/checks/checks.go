// Package checks defines the Check interface and registry helpers.
package checks

import (
	"context"
	"net/http"

	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/httpclient"
	"github.com/Romstar/auth-chaser/pkg/types"
)

// Browser is the optional automation surface for MFA/passkey/JS login.
type Browser interface {
	Enabled() bool
	Navigate(ctx context.Context, url string) error
	Cookies(ctx context.Context) ([]*http.Cookie, error)
	FillLogin(ctx context.Context, username, password string) error
	PageContains(ctx context.Context, text string) (bool, error)
	Close() error
}

// Context supplies shared dependencies to a check.
type Context struct {
	Cfg     config.Config
	Client  *httpclient.Client
	Browser Browser
	OIDC    *OIDCMeta // populated by runner when discovery succeeds
}

// OIDCMeta caches discovery document fields for dependent checks.
type OIDCMeta struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	UserinfoEndpoint      string
	Raw                   map[string]any
}

// Check is one non-destructive verification unit.
type Check interface {
	ID() string
	Title() string
	Category() types.Category
	Pack() string
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

// Skip returns a standard skip finding.
func Skip(checkID, title, pack string, category types.Category, reason, summary string) types.Finding {
	return types.Finding{
		CheckID:  checkID,
		Title:    title,
		Category: category,
		Severity: types.SeverityInfo,
		Status:   types.StatusSkip,
		Summary:  summary,
		Pack:     pack,
		Metadata: map[string]string{"skip_reason": reason},
	}
}

// RequiresBrowserSkip returns a skip when browser is required but unavailable.
func RequiresBrowserSkip(checkID, title, pack string, category types.Category) types.Finding {
	return Skip(checkID, title, pack, category, types.SkipRequiresBrowser,
		"This check needs browser automation. Re-run with --browser or browser.enabled: true.")
}

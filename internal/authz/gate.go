// Package authz enforces the authorization gate before any checks run.
package authz

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Romstar/auth-chaser/internal/config"
)

// ErrNotAuthorized is returned when the operator did not confirm permission.
var ErrNotAuthorized = fmt.Errorf("authorization not confirmed: set safety.confirm_authorized=true or pass --confirm-authorized")

// ErrOutOfScope is returned when a URL falls outside the configured scope.
var ErrOutOfScope = fmt.Errorf("request target is outside allowed scope")

// Gate validates operator confirmation and request scope.
type Gate struct {
	cfg config.Config
}

// NewGate builds a gate from run config.
func NewGate(cfg config.Config) *Gate {
	return &Gate{cfg: cfg}
}

// RequireAuthorized blocks the run until the operator asserts permission.
func (g *Gate) RequireAuthorized() error {
	if !g.cfg.Safety.ConfirmAuthorized {
		return ErrNotAuthorized
	}
	if g.cfg.Safety.Destructive {
		return fmt.Errorf("destructive mode is not allowed; auth-chaser only runs non-destructive checks")
	}
	return nil
}

// AllowURL returns an error when the URL host or path is out of scope.
func (g *Gate) AllowURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: invalid url: %v", ErrOutOfScope, err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host", ErrOutOfScope)
	}

	if !hostAllowed(host, g.cfg.Target.AllowedHosts) {
		return fmt.Errorf("%w: host %q not in allowed_hosts", ErrOutOfScope, host)
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	if !pathAllowed(path, g.cfg.Target.AllowedPaths) {
		return fmt.Errorf("%w: path %q not in allowed_paths", ErrOutOfScope, path)
	}
	return nil
}

func hostAllowed(host string, allowed []string) bool {
	host = strings.ToLower(host)
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

func pathAllowed(path string, allowed []string) bool {
	for _, prefix := range allowed {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			continue
		}
		if prefix == "/" {
			return true
		}
		if path == prefix || strings.HasPrefix(path, strings.TrimRight(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

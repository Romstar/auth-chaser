// Package packs maps pack IDs to concrete checks.
package packs

import (
	"fmt"
	"sort"

	"github.com/Romstar/auth-chaser/internal/checks"
	"github.com/Romstar/auth-chaser/internal/checks/auth"
	"github.com/Romstar/auth-chaser/internal/checks/misconfig"
	"github.com/Romstar/auth-chaser/internal/checks/rbac"
	"github.com/Romstar/auth-chaser/internal/config"
)

// Descriptor describes a pack for --list-checks.
type Descriptor struct {
	ID          string
	Title       string
	Description string
	Checks      []CheckInfo
}

// CheckInfo is a listed check.
type CheckInfo struct {
	ID    string
	Title string
}

var catalog = map[string]func() []checks.Check{
	config.PackAuthCore: func() []checks.Check {
		return []checks.Check{auth.HTTPSRequired{}, auth.LoginSurface{}, auth.CSRFOnLogin{}}
	},
	config.PackAuthOAuth2: func() []checks.Check {
		return []checks.Check{
			auth.OIDCDiscovery{},
			auth.OAuth2AuthorizeParams{},
			auth.OAuth2RedirectHTTPS{},
			auth.OAuth2TokenEndpointAuth{},
			auth.OIDCIDTokenClaims{},
			auth.OIDCJWKS{},
			auth.OAuth2PKCEEnforced{},
		}
	},
	config.PackAuthPassword: func() []checks.Check {
		return []checks.Check{
			auth.PasswordLoginSuccess{},
			auth.PasswordLoginFailure{},
			auth.SessionCookieFlags{},
			auth.SessionHTTPSOnly{},
			auth.LogoutInvalidates{},
		}
	},
	config.PackAuthMFA: func() []checks.Check {
		return []checks.Check{auth.MFARequiredForRole{}, auth.MFATOTPSuccess{}, auth.MFABypassPaths{}}
	},
	config.PackAuthPasskey: func() []checks.Check {
		return []checks.Check{auth.PasskeyOptions{}, auth.PasskeyRegisterLogin{}, auth.PasskeyUserVerification{}}
	},
	config.PackMisconfigAuth: func() []checks.Check {
		return []checks.Check{
			misconfig.SecurityHeaders{},
			misconfig.CookieFlags{},
			misconfig.CORSMisconfig{},
			misconfig.OpenRedirect{},
			misconfig.StateNonce{},
			misconfig.JWTMisconfig{},
			misconfig.CacheControlAuthenticated{},
			misconfig.LoginRateLimitSignal{},
		}
	},
	config.PackRBACMatrix: func() []checks.Check {
		return []checks.Check{rbac.AnonymousBaseline{}, rbac.RoleAccess{}, rbac.ObjectAccess{}, rbac.MatrixFile{}}
	},
}

var titles = map[string]string{
	config.PackAuthCore:      "Core authentication surface",
	config.PackAuthOAuth2:    "OAuth2 / OIDC HTTP verification",
	config.PackAuthPassword:  "Password login and session lifecycle",
	config.PackAuthMFA:       "MFA / step-up verification",
	config.PackAuthPasskey:   "Passkeys / WebAuthn",
	config.PackMisconfigAuth: "Auth misconfiguration probes",
	config.PackRBACMatrix:    "Authorization / RBAC matrix",
}

// ForPacks returns checks for the given pack IDs in stable order.
func ForPacks(packIDs []string) ([]checks.Check, error) {
	out := make([]checks.Check, 0)
	seen := map[string]bool{}
	for _, id := range packIDs {
		fn, ok := catalog[id]
		if !ok {
			return nil, fmt.Errorf("unknown pack %q", id)
		}
		for _, c := range fn() {
			if seen[c.ID()] {
				continue
			}
			seen[c.ID()] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// List returns descriptors for all packs.
func List() []Descriptor {
	ids := make([]string, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Descriptor, 0, len(ids))
	for _, id := range ids {
		cs := catalog[id]()
		info := make([]CheckInfo, 0, len(cs))
		for _, c := range cs {
			info = append(info, CheckInfo{ID: c.ID(), Title: c.Title()})
		}
		out = append(out, Descriptor{
			ID:          id,
			Title:       titles[id],
			Description: titles[id],
			Checks:      info,
		})
	}
	return out
}

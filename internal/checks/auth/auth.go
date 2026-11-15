// Package auth implements authentication configuration verification checks.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Romstar/auth-chaser/internal/checks"
	"github.com/Romstar/auth-chaser/internal/httpclient"
	"github.com/Romstar/auth-chaser/pkg/types"
)

const maxBody = 512 * 1024

// HTTPSRequired verifies the target uses HTTPS.
type HTTPSRequired struct{}

func (HTTPSRequired) ID() string               { return "auth.https_required" }
func (HTTPSRequired) Title() string            { return "HTTPS for authentication endpoints" }
func (HTTPSRequired) Category() types.Category { return types.CategoryAuth }

func (HTTPSRequired) Run(_ context.Context, cctx checks.Context) ([]types.Finding, error) {
	base := cctx.Cfg.Target.BaseURL
	if strings.HasPrefix(base, "https://") {
		return []types.Finding{{
			CheckID:  "auth.https_required",
			Title:    "HTTPS for authentication endpoints",
			Category: types.CategoryAuth,
			Severity: types.SeverityInfo,
			Status:   types.StatusPass,
			Summary:  "Target base URL uses HTTPS.",
		}}, nil
	}
	return []types.Finding{{
		CheckID:     "auth.https_required",
		Title:       "HTTPS for authentication endpoints",
		Category:    types.CategoryAuth,
		Severity:    types.SeverityHigh,
		Status:      types.StatusFail,
		Summary:     "Target base URL does not use HTTPS.",
		Evidence:    base,
		Remediation: "Serve authentication flows exclusively over HTTPS.",
	}}, nil
}

// OIDCDiscovery looks for a standard OpenID Connect discovery document.
type OIDCDiscovery struct{}

func (OIDCDiscovery) ID() string               { return "auth.oidc_discovery" }
func (OIDCDiscovery) Title() string            { return "OIDC discovery document" }
func (OIDCDiscovery) Category() types.Category { return types.CategoryAuth }

func (OIDCDiscovery) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	paths := []string{
		"/.well-known/openid-configuration",
		"/oauth2/.well-known/openid-configuration",
		"/auth/.well-known/openid-configuration",
	}

	var lastStatus int
	for _, p := range paths {
		url := cctx.Cfg.Target.BaseURL + p
		resp, err := cctx.Client.Get(ctx, url, nil)
		if err != nil {
			continue
		}
		body, _ := httpclient.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close()
		lastStatus = resp.StatusCode
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			return []types.Finding{{
				CheckID:  "auth.oidc_discovery",
				Title:    "OIDC discovery document",
				Category: types.CategoryAuth,
				Severity: types.SeverityMedium,
				Status:   types.StatusWarn,
				Summary:  "Discovery endpoint returned non-JSON content.",
				Evidence: fmt.Sprintf("%s status=%d", url, resp.StatusCode),
			}}, nil
		}
		issuer, _ := doc["issuer"].(string)
		authEP, _ := doc["authorization_endpoint"].(string)
		tokenEP, _ := doc["token_endpoint"].(string)
		if issuer == "" || authEP == "" || tokenEP == "" {
			return []types.Finding{{
				CheckID:     "auth.oidc_discovery",
				Title:       "OIDC discovery document",
				Category:    types.CategoryAuth,
				Severity:    types.SeverityMedium,
				Status:      types.StatusFail,
				Summary:     "OIDC discovery JSON is missing required fields.",
				Evidence:    fmt.Sprintf("url=%s issuer=%q authorization_endpoint=%q token_endpoint=%q", url, issuer, authEP, tokenEP),
				Remediation: "Publish a valid OpenID Provider Metadata document with issuer, authorization_endpoint, and token_endpoint.",
			}}, nil
		}
		return []types.Finding{{
			CheckID:  "auth.oidc_discovery",
			Title:    "OIDC discovery document",
			Category: types.CategoryAuth,
			Severity: types.SeverityInfo,
			Status:   types.StatusPass,
			Summary:  "Valid OIDC discovery document found.",
			Evidence: fmt.Sprintf("url=%s issuer=%s", url, issuer),
			Metadata: map[string]string{
				"issuer":                 issuer,
				"authorization_endpoint": authEP,
				"token_endpoint":         tokenEP,
			},
		}}, nil
	}

	return []types.Finding{{
		CheckID:  "auth.oidc_discovery",
		Title:    "OIDC discovery document",
		Category: types.CategoryAuth,
		Severity: types.SeverityInfo,
		Status:   types.StatusSkip,
		Summary:  "No OIDC discovery document found at common paths (target may not use OIDC).",
		Evidence: fmt.Sprintf("last_status=%d", lastStatus),
	}}, nil
}

// LoginSurface looks for a login form or common sign-in routes.
type LoginSurface struct{}

func (LoginSurface) ID() string               { return "auth.login_surface" }
func (LoginSurface) Title() string            { return "Login surface reachability" }
func (LoginSurface) Category() types.Category { return types.CategoryAuth }

func (LoginSurface) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	candidates := []string{"/login", "/signin", "/auth/login", "/account/login", "/oauth/authorize"}
	found := make([]string, 0)
	for _, p := range candidates {
		url := cctx.Cfg.Target.BaseURL + p
		resp, err := cctx.Client.Get(ctx, url, nil)
		if err != nil {
			continue
		}
		body, _ := httpclient.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			lower := strings.ToLower(string(body))
			if strings.Contains(lower, "password") || strings.Contains(lower, "sign in") ||
				strings.Contains(lower, "log in") || strings.Contains(lower, "oauth") ||
				resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
				found = append(found, fmt.Sprintf("%s (%d)", p, resp.StatusCode))
			} else {
				found = append(found, fmt.Sprintf("%s (%d)", p, resp.StatusCode))
			}
		}
	}
	if len(found) == 0 {
		return []types.Finding{{
			CheckID:     "auth.login_surface",
			Title:       "Login surface reachability",
			Category:    types.CategoryAuth,
			Severity:    types.SeverityInfo,
			Status:      types.StatusWarn,
			Summary:     "No common login routes responded as an auth surface.",
			Remediation: "Document your login URL in chase config so future checks can target it.",
		}}, nil
	}
	return []types.Finding{{
		CheckID:  "auth.login_surface",
		Title:    "Login surface reachability",
		Category: types.CategoryAuth,
		Severity: types.SeverityInfo,
		Status:   types.StatusPass,
		Summary:  "At least one login-related surface is reachable.",
		Evidence: strings.Join(found, ", "),
	}}, nil
}

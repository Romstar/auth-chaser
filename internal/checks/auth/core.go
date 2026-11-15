package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Romstar/auth-chaser/internal/checks"
	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/httpclient"
	"github.com/Romstar/auth-chaser/pkg/types"
)

const maxBody = 512 * 1024

// HTTPSRequired verifies the target uses HTTPS.
type HTTPSRequired struct{}

func (HTTPSRequired) ID() string               { return "auth.https_required" }
func (HTTPSRequired) Title() string            { return "HTTPS for authentication endpoints" }
func (HTTPSRequired) Category() types.Category { return types.CategoryAuth }
func (HTTPSRequired) Pack() string             { return config.PackAuthCore }

func (HTTPSRequired) Run(_ context.Context, cctx checks.Context) ([]types.Finding, error) {
	base := cctx.Cfg.Target.BaseURL
	f := types.Finding{
		CheckID:  "auth.https_required",
		Title:    "HTTPS for authentication endpoints",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthCore,
		Protocol: "tls",
		CWE:      "CWE-319",
	}
	if strings.HasPrefix(base, "https://") {
		f.Severity = types.SeverityInfo
		f.Status = types.StatusPass
		f.Summary = "Target base URL uses HTTPS."
		return []types.Finding{f}, nil
	}
	f.Severity = types.SeverityHigh
	f.Status = types.StatusFail
	f.Summary = "Target base URL does not use HTTPS."
	f.Evidence = base
	f.Remediation = "Serve authentication flows exclusively over HTTPS."
	return []types.Finding{f}, nil
}

// LoginSurface looks for a login form or common sign-in routes.
type LoginSurface struct{}

func (LoginSurface) ID() string               { return "auth.login_surface" }
func (LoginSurface) Title() string            { return "Login surface reachability" }
func (LoginSurface) Category() types.Category { return types.CategoryAuth }
func (LoginSurface) Pack() string             { return config.PackAuthCore }

func (LoginSurface) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	candidates := []string{"/login", "/signin", "/auth/login", "/account/login", "/oauth/authorize"}
	if cctx.Cfg.Auth.Password.LoginURL != "" {
		candidates = append([]string{cctx.Cfg.Auth.Password.LoginURL}, candidates...)
	}
	found := make([]string, 0)
	seen := map[string]bool{}
	for _, p := range candidates {
		url := config.JoinURL(cctx.Cfg.Target.BaseURL, p)
		if seen[url] {
			continue
		}
		seen[url] = true
		resp, err := cctx.Client.Get(ctx, url, nil)
		if err != nil {
			continue
		}
		body, _ := httpclient.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			found = append(found, fmt.Sprintf("%s (%d)", p, resp.StatusCode))
			_ = body
		}
	}
	f := types.Finding{
		CheckID:  "auth.login_surface",
		Title:    "Login surface reachability",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthCore,
		Protocol: "session",
		Severity: types.SeverityInfo,
	}
	if len(found) == 0 {
		f.Status = types.StatusWarn
		f.Summary = "No common login routes responded as an auth surface."
		f.Remediation = "Set auth.password.login_url so checks can target your login page."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusPass
	f.Summary = "At least one login-related surface is reachable."
	f.Evidence = strings.Join(found, ", ")
	return []types.Finding{f}, nil
}

// CSRFOnLogin checks login form for CSRF token or SameSite mitigations.
type CSRFOnLogin struct{}

func (CSRFOnLogin) ID() string               { return "auth.csrf_on_login" }
func (CSRFOnLogin) Title() string            { return "CSRF protection on login" }
func (CSRFOnLogin) Category() types.Category { return types.CategoryAuth }
func (CSRFOnLogin) Pack() string             { return config.PackAuthCore }

func (CSRFOnLogin) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	login := cctx.Cfg.Auth.Password.LoginURL
	if login == "" {
		login = "/login"
	}
	url := config.JoinURL(cctx.Cfg.Target.BaseURL, login)
	resp, err := cctx.Client.Get(ctx, url, nil)
	if err != nil {
		return []types.Finding{checks.Skip("auth.csrf_on_login", "CSRF protection on login", config.PackAuthCore, types.CategoryAuth, types.SkipNotApplicable, "Login page not reachable: "+err.Error())}, nil
	}
	body, _ := httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		return []types.Finding{checks.Skip("auth.csrf_on_login", "CSRF protection on login", config.PackAuthCore, types.CategoryAuth, types.SkipNotApplicable, fmt.Sprintf("Login page status %d", resp.StatusCode))}, nil
	}
	lower := strings.ToLower(string(body))
	csrfField := strings.ToLower(cctx.Cfg.Auth.Password.CSRFField)
	if csrfField == "" {
		csrfField = "csrf"
	}
	hasCSRF := strings.Contains(lower, `name="`+csrfField) ||
		strings.Contains(lower, "csrfmiddlewaretoken") ||
		strings.Contains(lower, "_csrf") ||
		strings.Contains(lower, "authenticity_token") ||
		strings.Contains(lower, "name=\"csrf")

	cookies := resp.Cookies()
	hasSameSite := false
	for _, c := range cookies {
		if c.SameSite != http.SameSiteDefaultMode && c.SameSite != 0 {
			hasSameSite = true
		}
	}
	for _, raw := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(raw), "samesite") {
			hasSameSite = true
		}
	}

	f := types.Finding{
		CheckID:  "auth.csrf_on_login",
		Title:    "CSRF protection on login",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthCore,
		Protocol: "session",
		CWE:      "CWE-352",
		Severity: types.SeverityMedium,
	}
	if hasCSRF || hasSameSite {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Login surface shows CSRF token and/or SameSite cookies."
		f.Evidence = fmt.Sprintf("csrf_field=%v samesite=%v", hasCSRF, hasSameSite)
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusFail
	f.Summary = "Login surface lacks an obvious CSRF token and SameSite cookies."
	f.Remediation = "Add a CSRF token to the login form and set SameSite on session cookies."
	return []types.Finding{f}, nil
}

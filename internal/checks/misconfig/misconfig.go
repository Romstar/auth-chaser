// Package misconfig implements non-destructive auth misconfiguration checks.
package misconfig

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Romstar/auth-chaser/internal/checks"
	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/httpclient"
	"github.com/Romstar/auth-chaser/internal/oauth"
	"github.com/Romstar/auth-chaser/pkg/types"
)

const maxBody = 256 * 1024

func base(id, title string) types.Finding {
	return types.Finding{
		CheckID:  id,
		Title:    title,
		Category: types.CategoryMisconfig,
		Pack:     config.PackMisconfigAuth,
		Severity: types.SeverityMedium,
	}
}

// SecurityHeaders checks auth-relevant response headers on the base URL.
type SecurityHeaders struct{}

func (SecurityHeaders) ID() string               { return "misconfig.security_headers" }
func (SecurityHeaders) Title() string            { return "Auth-relevant security headers" }
func (SecurityHeaders) Category() types.Category { return types.CategoryMisconfig }
func (SecurityHeaders) Pack() string             { return config.PackMisconfigAuth }

func (SecurityHeaders) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := base("misconfig.security_headers", "Auth-relevant security headers")
	f.CWE = "CWE-693"
	resp, err := cctx.Client.Get(ctx, cctx.Cfg.Target.BaseURL+"/", nil)
	if err != nil {
		f.Status = types.StatusError
		f.Summary = "Failed to fetch target for header inspection."
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	defer resp.Body.Close()
	_, _ = httpclient.ReadLimited(resp.Body, maxBody)

	missing := make([]string, 0)
	for _, header := range []string{"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"} {
		if resp.Header.Get(header) == "" {
			missing = append(missing, header)
		}
	}
	if len(missing) == 0 {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Expected security headers are present."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusFail
	f.Summary = "One or more auth-relevant security headers are missing."
	f.Evidence = "missing: " + strings.Join(missing, ", ")
	f.Remediation = "Add HSTS, X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy."
	return []types.Finding{f}, nil
}

// CookieFlags inspects Set-Cookie attributes on the base response.
type CookieFlags struct{}

func (CookieFlags) ID() string               { return "misconfig.cookie_flags" }
func (CookieFlags) Title() string            { return "Session cookie security flags" }
func (CookieFlags) Category() types.Category { return types.CategoryMisconfig }
func (CookieFlags) Pack() string             { return config.PackMisconfigAuth }

func (CookieFlags) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := base("misconfig.cookie_flags", "Session cookie security flags")
	f.CWE = "CWE-614"
	resp, err := cctx.Client.Get(ctx, cctx.Cfg.Target.BaseURL+"/", nil)
	if err != nil {
		f.Status = types.StatusError
		f.Summary = "Failed to fetch target for cookie inspection."
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	defer resp.Body.Close()
	_, _ = httpclient.ReadLimited(resp.Body, maxBody)

	raw := resp.Header.Values("Set-Cookie")
	if len(raw) == 0 {
		f.Status = types.StatusSkip
		f.Severity = types.SeverityInfo
		f.Summary = "No Set-Cookie headers on the base URL response."
		f.Metadata = map[string]string{"skip_reason": types.SkipNotApplicable}
		return []types.Finding{f}, nil
	}
	findings := make([]types.Finding, 0, len(raw))
	for _, line := range raw {
		lower := strings.ToLower(line)
		name := strings.SplitN(line, "=", 2)[0]
		issues := make([]string, 0)
		if !strings.Contains(lower, "secure") {
			issues = append(issues, "Secure")
		}
		if !strings.Contains(lower, "httponly") {
			issues = append(issues, "HttpOnly")
		}
		if !strings.Contains(lower, "samesite") {
			issues = append(issues, "SameSite")
		}
		item := f
		item.Evidence = name
		if len(issues) == 0 {
			item.Status = types.StatusPass
			item.Severity = types.SeverityInfo
			item.Summary = fmt.Sprintf("Cookie %q has expected security flags.", name)
		} else {
			item.Status = types.StatusFail
			item.Severity = types.SeverityHigh
			item.Summary = fmt.Sprintf("Cookie %q missing: %s", name, strings.Join(issues, ", "))
			item.Remediation = "Set Secure, HttpOnly, and SameSite on session cookies."
		}
		findings = append(findings, item)
	}
	return findings, nil
}

// CORSMisconfig flags overly permissive CORS with credentials.
type CORSMisconfig struct{}

func (CORSMisconfig) ID() string               { return "misconfig.cors" }
func (CORSMisconfig) Title() string            { return "CORS configuration for credentialed requests" }
func (CORSMisconfig) Category() types.Category { return types.CategoryMisconfig }
func (CORSMisconfig) Pack() string             { return config.PackMisconfigAuth }

func (CORSMisconfig) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := base("misconfig.cors", "CORS configuration for credentialed requests")
	f.CWE = "CWE-942"
	headers := map[string]string{
		"Origin":                        "https://auth-chaser-probe.invalid",
		"Access-Control-Request-Method": "GET",
	}
	resp, err := cctx.Client.Do(ctx, http.MethodOptions, cctx.Cfg.Target.BaseURL+"/", headers, nil)
	if err != nil {
		resp, err = cctx.Client.Get(ctx, cctx.Cfg.Target.BaseURL+"/", map[string]string{"Origin": "https://auth-chaser-probe.invalid"})
		if err != nil {
			f.Status = types.StatusError
			f.Summary = "Failed to probe CORS headers."
			f.Evidence = err.Error()
			return []types.Finding{f}, nil
		}
	}
	defer resp.Body.Close()
	_, _ = httpclient.ReadLimited(resp.Body, maxBody)
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))
	f.Evidence = fmt.Sprintf("ACAO=%q ACAC=%q", acao, acac)
	if acao == "*" && acac == "true" {
		f.Status = types.StatusFail
		f.Severity = types.SeverityCritical
		f.Summary = "CORS allows any origin with credentials."
		f.Remediation = "Never combine ACAO * with credentials true."
		return []types.Finding{f}, nil
	}
	if acao == "https://auth-chaser-probe.invalid" && acac == "true" {
		f.Status = types.StatusFail
		f.Severity = types.SeverityHigh
		f.Summary = "Server reflects arbitrary Origin with credentials enabled."
		f.Remediation = "Allowlist trusted origins."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusPass
	f.Severity = types.SeverityInfo
	f.Summary = "No critical CORS credential misconfiguration detected."
	return []types.Finding{f}, nil
}

// OpenRedirect probes next=/redirect_uri open redirect patterns safely.
type OpenRedirect struct{}

func (OpenRedirect) ID() string               { return "misconfig.open_redirect" }
func (OpenRedirect) Title() string            { return "Open redirect on auth-related parameters" }
func (OpenRedirect) Category() types.Category { return types.CategoryMisconfig }
func (OpenRedirect) Pack() string             { return config.PackMisconfigAuth }

func (OpenRedirect) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := base("misconfig.open_redirect", "Open redirect on auth-related parameters")
	f.CWE = "CWE-601"
	evil := "https://evil.example"
	paths := []string{
		"/login?next=" + url.QueryEscape(evil),
		"/signin?redirect=" + url.QueryEscape(evil),
		"/auth/login?returnTo=" + url.QueryEscape(evil),
	}
	if cctx.Cfg.Auth.Password.LoginURL != "" {
		paths = append(paths, config.JoinURL("", cctx.Cfg.Auth.Password.LoginURL)+"?next="+url.QueryEscape(evil))
	}
	for _, p := range paths {
		u := config.JoinURL(cctx.Cfg.Target.BaseURL, p)
		resp, err := cctx.Client.Get(ctx, u, nil)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		_, _ = httpclient.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close()
		if strings.HasPrefix(loc, evil) || strings.Contains(loc, "evil.example") {
			f.Status = types.StatusFail
			f.Severity = types.SeverityHigh
			f.Summary = "Auth flow redirects to an untrusted absolute URL."
			f.Evidence = fmt.Sprintf("url=%s location=%s", u, loc)
			f.Remediation = "Allowlist relative paths only for post-login redirects."
			return []types.Finding{f}, nil
		}
	}
	f.Status = types.StatusPass
	f.Severity = types.SeverityInfo
	f.Summary = "No open redirect to external host observed on common auth params."
	return []types.Finding{f}, nil
}

// StateNonce checks OAuth authorize URL handling of state/nonce.
type StateNonce struct{}

func (StateNonce) ID() string               { return "misconfig.state_nonce" }
func (StateNonce) Title() string            { return "OAuth state/nonce handling" }
func (StateNonce) Category() types.Category { return types.CategoryMisconfig }
func (StateNonce) Pack() string             { return config.PackMisconfigAuth }

func (StateNonce) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := base("misconfig.state_nonce", "OAuth state/nonce handling")
	f.CWE = "CWE-352"
	f.Protocol = "oauth2"
	meta := cctx.OIDC
	if meta == nil || meta.AuthorizationEndpoint == "" {
		m, _, err := oauth.Discover(ctx, cctx)
		if err != nil {
			return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackMisconfigAuth, types.CategoryMisconfig, types.SkipNotApplicable, "No OIDC authorize endpoint")}, nil
		}
		meta = m
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", or(cctx.Cfg.Auth.OAuth2.ClientID, "auth-chaser-probe"))
	q.Set("redirect_uri", or(cctx.Cfg.Auth.OAuth2.RedirectURI, cctx.Cfg.Target.BaseURL+"/callback"))
	q.Set("scope", "openid")
	// omit state and nonce intentionally
	probe := meta.AuthorizationEndpoint + "?" + q.Encode()
	resp, err := cctx.Client.Get(ctx, probe, nil)
	if err != nil {
		f.Status = types.StatusSkip
		f.Severity = types.SeverityInfo
		f.Summary = "Authorize endpoint outside scope or unreachable."
		f.Evidence = err.Error()
		f.Metadata = map[string]string{"skip_reason": types.SkipNotApplicable}
		return []types.Finding{f}, nil
	}
	body, _ := httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	lower := strings.ToLower(string(body))
	f.Evidence = fmt.Sprintf("status=%d", resp.StatusCode)
	if resp.StatusCode >= 400 || strings.Contains(lower, "state") {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Authorize flow signals state requirements or rejects incomplete requests."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusWarn
	f.Severity = types.SeverityHigh
	f.Summary = "Authorize without state/nonce did not clearly fail."
	f.Remediation = "Require and validate state (and nonce for OIDC) on every authorize request."
	return []types.Finding{f}, nil
}

// JWTMisconfig inspects supplied tokens for classic JWT issues.
type JWTMisconfig struct{}

func (JWTMisconfig) ID() string               { return "misconfig.jwt" }
func (JWTMisconfig) Title() string            { return "JWT classic misconfiguration signals" }
func (JWTMisconfig) Category() types.Category { return types.CategoryMisconfig }
func (JWTMisconfig) Pack() string             { return config.PackMisconfigAuth }

func (JWTMisconfig) Run(_ context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := base("misconfig.jwt", "JWT classic misconfiguration signals")
	f.CWE = "CWE-347"
	f.Protocol = "jwt"
	token := cctx.Cfg.Auth.OIDC.IDToken
	if token == "" {
		token = cctx.Cfg.Auth.OIDC.AccessToken
	}
	if token == "" {
		return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackMisconfigAuth, types.CategoryMisconfig, types.SkipMissingSecret, "Supply auth.oidc.id_token or access_token to inspect")}, nil
	}
	hdr, err := oauth.ParseJWTHeader(token)
	if err != nil {
		f.Status = types.StatusFail
		f.Severity = types.SeverityMedium
		f.Summary = "Token is not a JWT."
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	alg, _ := hdr["alg"].(string)
	claims, _ := oauth.ParseJWTClaims(token)
	issues := make([]string, 0)
	if strings.EqualFold(alg, "none") {
		issues = append(issues, "alg=none")
	}
	if strings.EqualFold(alg, "HS256") && cctx.Cfg.Auth.OAuth2.PublicClient {
		issues = append(issues, "HS256 with public client")
	}
	if claims != nil {
		if claims["aud"] == nil {
			issues = append(issues, "missing aud")
		}
		if claims["iss"] == nil {
			issues = append(issues, "missing iss")
		}
	}
	f.Evidence = fmt.Sprintf("alg=%s", alg)
	if len(issues) > 0 {
		f.Status = types.StatusFail
		f.Severity = types.SeverityCritical
		f.Summary = "JWT shows misconfiguration signals: " + strings.Join(issues, ", ")
		f.Remediation = "Reject alg=none, validate iss/aud, and use asymmetric algs for public clients."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusPass
	f.Severity = types.SeverityInfo
	f.Summary = "Supplied JWT header/claims show no classic misconfig signals."
	return []types.Finding{f}, nil
}

// CacheControlAuthenticated checks Cache-Control on a protected path when configured.
type CacheControlAuthenticated struct{}

func (CacheControlAuthenticated) ID() string               { return "misconfig.cache_control" }
func (CacheControlAuthenticated) Title() string            { return "Cache-Control on authenticated responses" }
func (CacheControlAuthenticated) Category() types.Category { return types.CategoryMisconfig }
func (CacheControlAuthenticated) Pack() string             { return config.PackMisconfigAuth }

func (CacheControlAuthenticated) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := base("misconfig.cache_control", "Cache-Control on authenticated responses")
	f.CWE = "CWE-524"
	path := cctx.Cfg.Auth.Password.ProtectedPath
	if path == "" && len(cctx.Cfg.RBAC.ProtectedPaths) > 0 {
		path = cctx.Cfg.RBAC.ProtectedPaths[0]
	}
	if path == "" {
		path = "/"
	}
	u := config.JoinURL(cctx.Cfg.Target.BaseURL, path)
	headers := map[string]string{}
	if len(cctx.Cfg.RBAC.Roles) > 0 && cctx.Cfg.RBAC.Roles[0].BearerToken != "" {
		headers["Authorization"] = "Bearer " + cctx.Cfg.RBAC.Roles[0].BearerToken
	}
	resp, err := cctx.Client.Get(ctx, u, headers)
	if err != nil {
		f.Status = types.StatusError
		f.Evidence = err.Error()
		f.Summary = "Failed to fetch path for cache inspection."
		return []types.Finding{f}, nil
	}
	_, _ = httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	cc := strings.ToLower(resp.Header.Get("Cache-Control"))
	f.Evidence = "Cache-Control=" + cc
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Authenticated response sets restrictive Cache-Control."
		return []types.Finding{f}, nil
	}
	if path == "/" {
		f.Status = types.StatusSkip
		f.Severity = types.SeverityInfo
		f.Summary = "Only public root was probed; set protected_path for authenticated cache checks."
		f.Metadata = map[string]string{"skip_reason": types.SkipMissingConfig}
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusFail
	f.Severity = types.SeverityMedium
	f.Summary = "Authenticated response lacks no-store/private Cache-Control."
	f.Remediation = "Set Cache-Control: no-store on authenticated responses."
	return []types.Finding{f}, nil
}

// LoginRateLimitSignal observes whether login shows rate-limit headers after a second probe.
type LoginRateLimitSignal struct{}

func (LoginRateLimitSignal) ID() string               { return "misconfig.login_rate_limit" }
func (LoginRateLimitSignal) Title() string            { return "Login rate-limit signals" }
func (LoginRateLimitSignal) Category() types.Category { return types.CategoryMisconfig }
func (LoginRateLimitSignal) Pack() string             { return config.PackMisconfigAuth }

func (LoginRateLimitSignal) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := base("misconfig.login_rate_limit", "Login rate-limit signals")
	f.CWE = "CWE-307"
	login := cctx.Cfg.Auth.Password.LoginURL
	if login == "" {
		login = "/login"
	}
	u := config.JoinURL(cctx.Cfg.Target.BaseURL, login)
	var last http.Header
	for i := 0; i < 2; i++ {
		resp, err := cctx.Client.Get(ctx, u, nil)
		if err != nil {
			f.Status = types.StatusSkip
			f.Severity = types.SeverityInfo
			f.Summary = "Login URL not reachable for rate-limit observation."
			f.Evidence = err.Error()
			f.Metadata = map[string]string{"skip_reason": types.SkipNotApplicable}
			return []types.Finding{f}, nil
		}
		_, _ = httpclient.ReadLimited(resp.Body, maxBody)
		last = resp.Header.Clone()
		_ = resp.Body.Close()
	}
	signals := []string{"Retry-After", "X-RateLimit-Remaining", "RateLimit-Remaining", "X-Rate-Limit-Remaining"}
	found := make([]string, 0)
	for _, h := range signals {
		if last.Get(h) != "" {
			found = append(found, h)
		}
	}
	if len(found) > 0 {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Login responses expose rate-limit related headers."
		f.Evidence = strings.Join(found, ", ")
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusWarn
	f.Severity = types.SeverityLow
	f.Summary = "No rate-limit headers observed on a double probe (does not prove absence of limits)."
	f.Remediation = "Apply and advertise login rate limits; consider Retry-After on throttling."
	return []types.Finding{f}, nil
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

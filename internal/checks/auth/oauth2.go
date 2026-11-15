package auth

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Romstar/auth-chaser/internal/checks"
	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/httpclient"
	"github.com/Romstar/auth-chaser/internal/oauth"
	"github.com/Romstar/auth-chaser/pkg/types"
)

// OIDCDiscovery looks for a standard OpenID Connect discovery document.
type OIDCDiscovery struct{}

func (OIDCDiscovery) ID() string               { return "auth.oidc_discovery" }
func (OIDCDiscovery) Title() string            { return "OIDC discovery document" }
func (OIDCDiscovery) Category() types.Category { return types.CategoryAuth }
func (OIDCDiscovery) Pack() string             { return config.PackAuthOAuth2 }

func (OIDCDiscovery) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	meta, src, err := oauth.Discover(ctx, cctx)
	f := types.Finding{
		CheckID:  "auth.oidc_discovery",
		Title:    "OIDC discovery document",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthOAuth2,
		Protocol: "oidc",
	}
	if err != nil {
		// Also register under auth.core path historically — keep skip when OIDC not present
		f.Severity = types.SeverityInfo
		f.Status = types.StatusSkip
		f.Summary = "No OIDC discovery document found at common paths."
		f.Evidence = err.Error()
		f.Metadata = map[string]string{"skip_reason": types.SkipNotApplicable}
		return []types.Finding{f}, nil
	}
	if cctx.OIDC != nil {
		*cctx.OIDC = *meta
	}
	missing := make([]string, 0)
	if meta.Issuer == "" {
		missing = append(missing, "issuer")
	}
	if meta.AuthorizationEndpoint == "" {
		missing = append(missing, "authorization_endpoint")
	}
	if meta.TokenEndpoint == "" {
		missing = append(missing, "token_endpoint")
	}
	if meta.JWKSURI == "" {
		missing = append(missing, "jwks_uri")
	}
	if len(missing) > 0 {
		f.Severity = types.SeverityMedium
		f.Status = types.StatusFail
		f.Summary = "OIDC discovery JSON is missing required fields."
		f.Evidence = fmt.Sprintf("url=%s missing=%s", src, strings.Join(missing, ","))
		f.Remediation = "Publish complete OpenID Provider Metadata."
		f.CWE = "CWE-287"
		return []types.Finding{f}, nil
	}
	f.Severity = types.SeverityInfo
	f.Status = types.StatusPass
	f.Summary = "Valid OIDC discovery document found."
	f.Evidence = fmt.Sprintf("url=%s issuer=%s", src, meta.Issuer)
	f.Metadata = map[string]string{
		"issuer":                 meta.Issuer,
		"authorization_endpoint": meta.AuthorizationEndpoint,
		"token_endpoint":         meta.TokenEndpoint,
		"jwks_uri":               meta.JWKSURI,
	}
	return []types.Finding{f}, nil
}

// OAuth2AuthorizeParams checks authorize URL parameter requirements.
type OAuth2AuthorizeParams struct{}

func (OAuth2AuthorizeParams) ID() string               { return "auth.oauth2_authorize_params" }
func (OAuth2AuthorizeParams) Title() string            { return "OAuth2 authorize parameter requirements" }
func (OAuth2AuthorizeParams) Category() types.Category { return types.CategoryAuth }
func (OAuth2AuthorizeParams) Pack() string             { return config.PackAuthOAuth2 }

func (OAuth2AuthorizeParams) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	meta := cctx.OIDC
	if meta == nil || meta.AuthorizationEndpoint == "" {
		m, _, err := oauth.Discover(ctx, cctx)
		if err != nil {
			return []types.Finding{checks.Skip("auth.oauth2_authorize_params", "OAuth2 authorize parameter requirements", config.PackAuthOAuth2, types.CategoryAuth, types.SkipNotApplicable, "No authorize endpoint available")}, nil
		}
		meta = m
	}
	authURL := oauth.ResolveAuthorizeURL(cctx.Cfg, meta)
	if authURL == "" {
		return []types.Finding{checks.Skip("auth.oauth2_authorize_params", "OAuth2 authorize parameter requirements", config.PackAuthOAuth2, types.CategoryAuth, types.SkipMissingConfig, "Set auth.oauth2.authorize_url or enable OIDC discovery")}, nil
	}

	clientID := cctx.Cfg.Auth.OAuth2.ClientID
	if clientID == "" {
		clientID = "auth-chaser-probe"
	}
	redirect := cctx.Cfg.Auth.OAuth2.RedirectURI
	if redirect == "" {
		redirect = cctx.Cfg.Target.BaseURL + "/oauth/callback"
	}

	// Probe without state — expect IdP to reject or still require state in docs; we check response quality.
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", strings.Join(scopes(cctx.Cfg), " "))
	probe := authURL
	if strings.Contains(authURL, "?") {
		probe += "&" + q.Encode()
	} else {
		probe += "?" + q.Encode()
	}

	resp, err := cctx.Client.Get(ctx, probe, nil)
	f := types.Finding{
		CheckID:  "auth.oauth2_authorize_params",
		Title:    "OAuth2 authorize parameter requirements",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthOAuth2,
		Protocol: "oauth2",
		CWE:      "CWE-352",
		Severity: types.SeverityMedium,
	}
	if err != nil {
		// authorize host may be out of scope
		f.Status = types.StatusSkip
		f.Severity = types.SeverityInfo
		f.Summary = "Could not probe authorize endpoint (often IdP host is outside allowed_hosts)."
		f.Evidence = err.Error()
		f.Metadata = map[string]string{"skip_reason": types.SkipNotApplicable}
		return []types.Finding{f}, nil
	}
	body, _ := httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	lower := strings.ToLower(string(body) + resp.Header.Get("Location"))

	// With state
	q2 := cloneValues(q)
	q2.Set("state", "authchaser-state-1")
	if cctx.Cfg.Auth.OAuth2.PublicClient {
		q2.Set("code_challenge", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")
		q2.Set("code_challenge_method", "S256")
	}
	probe2 := authURL
	if strings.Contains(authURL, "?") {
		probe2 += "&" + q2.Encode()
	} else {
		probe2 += "?" + q2.Encode()
	}
	resp2, err2 := cctx.Client.Get(ctx, probe2, nil)
	var body2 []byte
	status2 := 0
	if err2 == nil {
		body2, _ = httpclient.ReadLimited(resp2.Body, maxBody)
		status2 = resp2.StatusCode
		_ = resp2.Body.Close()
	}

	mentionsState := strings.Contains(lower, "state")
	f.Evidence = fmt.Sprintf("without_state_status=%d with_state_status=%d mentions_state=%v", resp.StatusCode, status2, mentionsState)
	if resp.StatusCode >= 400 && (status2 > 0 && status2 < 400) {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Authorize endpoint rejects requests without state more strictly than with state."
		return []types.Finding{f}, nil
	}
	if mentionsState || status2 > 0 {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Authorize endpoint is reachable; include state (and PKCE for public clients) in all authorize requests."
		_ = body2
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusWarn
	f.Summary = "Could not confirm state enforcement from HTTP probes alone."
	f.Remediation = "Require state on authorize requests and PKCE for public clients."
	return []types.Finding{f}, nil
}

// OAuth2RedirectHTTPS checks redirect_uri uses HTTPS.
type OAuth2RedirectHTTPS struct{}

func (OAuth2RedirectHTTPS) ID() string               { return "auth.oauth2_redirect_https" }
func (OAuth2RedirectHTTPS) Title() string            { return "OAuth2 redirect URI uses HTTPS" }
func (OAuth2RedirectHTTPS) Category() types.Category { return types.CategoryAuth }
func (OAuth2RedirectHTTPS) Pack() string             { return config.PackAuthOAuth2 }

func (OAuth2RedirectHTTPS) Run(_ context.Context, cctx checks.Context) ([]types.Finding, error) {
	redirect := cctx.Cfg.Auth.OAuth2.RedirectURI
	f := types.Finding{
		CheckID:  "auth.oauth2_redirect_https",
		Title:    "OAuth2 redirect URI uses HTTPS",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthOAuth2,
		Protocol: "oauth2",
		CWE:      "CWE-319",
	}
	if redirect == "" {
		f.Status = types.StatusSkip
		f.Severity = types.SeverityInfo
		f.Summary = "auth.oauth2.redirect_uri not configured."
		f.Metadata = map[string]string{"skip_reason": types.SkipMissingConfig}
		return []types.Finding{f}, nil
	}
	u, err := url.Parse(redirect)
	if err != nil {
		f.Status = types.StatusFail
		f.Severity = types.SeverityHigh
		f.Summary = "redirect_uri is not a valid URL."
		f.Evidence = redirect
		return []types.Finding{f}, nil
	}
	host := u.Hostname()
	if u.Scheme == "https" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "redirect_uri uses HTTPS or localhost."
		f.Evidence = redirect
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusFail
	f.Severity = types.SeverityHigh
	f.Summary = "redirect_uri must use HTTPS (localhost exempt)."
	f.Evidence = redirect
	f.Remediation = "Configure redirect_uri with https:// unless using loopback for native apps."
	return []types.Finding{f}, nil
}

// OAuth2TokenEndpointAuth probes token endpoint with invalid grant.
type OAuth2TokenEndpointAuth struct{}

func (OAuth2TokenEndpointAuth) ID() string               { return "auth.oauth2_token_endpoint_auth" }
func (OAuth2TokenEndpointAuth) Title() string            { return "Token endpoint rejects invalid grants" }
func (OAuth2TokenEndpointAuth) Category() types.Category { return types.CategoryAuth }
func (OAuth2TokenEndpointAuth) Pack() string             { return config.PackAuthOAuth2 }

func (OAuth2TokenEndpointAuth) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	tokenURL := oauth.ResolveTokenURL(cctx.Cfg, cctx.OIDC)
	if tokenURL == "" {
		m, _, err := oauth.Discover(ctx, cctx)
		if err != nil {
			return []types.Finding{checks.Skip("auth.oauth2_token_endpoint_auth", "Token endpoint rejects invalid grants", config.PackAuthOAuth2, types.CategoryAuth, types.SkipNotApplicable, "No token endpoint")}, nil
		}
		tokenURL = m.TokenEndpoint
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "invalid-auth-chaser-code")
	form.Set("redirect_uri", cctx.Cfg.Auth.OAuth2.RedirectURI)
	if form.Get("redirect_uri") == "" {
		form.Set("redirect_uri", cctx.Cfg.Target.BaseURL+"/oauth/callback")
	}
	form.Set("client_id", orDefault(cctx.Cfg.Auth.OAuth2.ClientID, "auth-chaser-probe"))

	resp, err := cctx.Client.PostForm(ctx, tokenURL, nil, form)
	f := types.Finding{
		CheckID:  "auth.oauth2_token_endpoint_auth",
		Title:    "Token endpoint rejects invalid grants",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthOAuth2,
		Protocol: "oauth2",
		CWE:      "CWE-287",
	}
	if err != nil {
		f.Status = types.StatusSkip
		f.Severity = types.SeverityInfo
		f.Summary = "Token endpoint not reachable within scope."
		f.Evidence = err.Error()
		f.Metadata = map[string]string{"skip_reason": types.SkipNotApplicable}
		return []types.Finding{f}, nil
	}
	body, _ := httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	f.Evidence = fmt.Sprintf("status=%d body=%s", resp.StatusCode, truncate(string(body), 200))
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Token endpoint rejects invalid authorization codes."
		return []types.Finding{f}, nil
	}
	if resp.StatusCode == 200 {
		f.Status = types.StatusFail
		f.Severity = types.SeverityCritical
		f.Summary = "Token endpoint accepted an invalid authorization code."
		f.Remediation = "Validate authorization codes strictly and bind them to client_id and redirect_uri."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusWarn
	f.Severity = types.SeverityMedium
	f.Summary = "Unexpected token endpoint response to invalid grant."
	return []types.Finding{f}, nil
}

// OIDCIDTokenClaims validates supplied ID token claims.
type OIDCIDTokenClaims struct{}

func (OIDCIDTokenClaims) ID() string               { return "auth.oidc_id_token_claims" }
func (OIDCIDTokenClaims) Title() string            { return "OIDC ID token claims" }
func (OIDCIDTokenClaims) Category() types.Category { return types.CategoryAuth }
func (OIDCIDTokenClaims) Pack() string             { return config.PackAuthOAuth2 }

func (OIDCIDTokenClaims) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	token := cctx.Cfg.Auth.OIDC.IDToken
	f := types.Finding{
		CheckID:  "auth.oidc_id_token_claims",
		Title:    "OIDC ID token claims",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthOAuth2,
		Protocol: "oidc",
		CWE:      "CWE-287",
	}
	if token == "" {
		f.Status = types.StatusSkip
		f.Severity = types.SeverityInfo
		f.Summary = "No auth.oidc.id_token supplied."
		f.Metadata = map[string]string{"skip_reason": types.SkipMissingSecret}
		return []types.Finding{f}, nil
	}
	claims, err := oauth.ParseJWTClaims(token)
	if err != nil {
		f.Status = types.StatusFail
		f.Severity = types.SeverityHigh
		f.Summary = "ID token is not a parseable JWT."
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	issues := make([]string, 0)
	iss := strClaim(claims["iss"])
	aud := audClaim(claims["aud"])
	exp, _ := claims["exp"].(float64)
	if cctx.Cfg.Auth.OIDC.ExpectedIss != "" && iss != cctx.Cfg.Auth.OIDC.ExpectedIss {
		issues = append(issues, "iss mismatch")
	}
	if iss == "" {
		issues = append(issues, "missing iss")
	}
	if cctx.Cfg.Auth.OIDC.ExpectedAud != "" && !strings.Contains(aud, cctx.Cfg.Auth.OIDC.ExpectedAud) {
		issues = append(issues, "aud mismatch")
	}
	if aud == "" {
		issues = append(issues, "missing aud")
	}
	if exp == 0 {
		issues = append(issues, "missing exp")
	} else if time.Unix(int64(exp), 0).Before(time.Now()) {
		issues = append(issues, "token expired")
	}
	f.Evidence = fmt.Sprintf("iss=%q aud=%q exp=%v", iss, aud, exp)
	if len(issues) > 0 {
		f.Status = types.StatusFail
		f.Severity = types.SeverityHigh
		f.Summary = "ID token claims failed validation: " + strings.Join(issues, ", ")
		f.Remediation = "Validate iss, aud, exp (and nonce) on every ID token."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusPass
	f.Severity = types.SeverityInfo
	f.Summary = "ID token claims include iss, aud, and unexpired exp."
	_ = ctx
	return []types.Finding{f}, nil
}

// OIDCJWKS validates JWKS availability and key material.
type OIDCJWKS struct{}

func (OIDCJWKS) ID() string               { return "auth.oidc_jwks" }
func (OIDCJWKS) Title() string            { return "OIDC JWKS availability" }
func (OIDCJWKS) Category() types.Category { return types.CategoryAuth }
func (OIDCJWKS) Pack() string             { return config.PackAuthOAuth2 }

func (OIDCJWKS) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	jwksURI := ""
	if cctx.OIDC != nil {
		jwksURI = cctx.OIDC.JWKSURI
	}
	if jwksURI == "" {
		m, _, err := oauth.Discover(ctx, cctx)
		if err != nil {
			return []types.Finding{checks.Skip("auth.oidc_jwks", "OIDC JWKS availability", config.PackAuthOAuth2, types.CategoryAuth, types.SkipNotApplicable, "No JWKS URI")}, nil
		}
		jwksURI = m.JWKSURI
	}
	doc, err := oauth.FetchJWKS(ctx, cctx.Client, jwksURI)
	f := types.Finding{
		CheckID:  "auth.oidc_jwks",
		Title:    "OIDC JWKS availability",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthOAuth2,
		Protocol: "oidc",
		CWE:      "CWE-347",
	}
	if err != nil {
		f.Status = types.StatusFail
		f.Severity = types.SeverityHigh
		f.Summary = "JWKS endpoint not usable."
		f.Evidence = err.Error()
		f.Remediation = "Expose a reachable jwks_uri with valid JSON Web Keys."
		return []types.Finding{f}, nil
	}
	keys, _ := doc["keys"].([]any)
	if len(keys) == 0 {
		f.Status = types.StatusFail
		f.Severity = types.SeverityHigh
		f.Summary = "JWKS document contains no keys."
		f.Evidence = jwksURI
		return []types.Finding{f}, nil
	}
	// Check for none alg in header of supplied token if present
	if tok := cctx.Cfg.Auth.OIDC.IDToken; tok != "" {
		if hdr, err := oauth.ParseJWTHeader(tok); err == nil {
			if alg, _ := hdr["alg"].(string); strings.EqualFold(alg, "none") {
				f.Status = types.StatusFail
				f.Severity = types.SeverityCritical
				f.Summary = "Supplied ID token uses alg=none."
				f.Evidence = "alg=none"
				f.Remediation = "Reject tokens with alg=none."
				f.CWE = "CWE-347"
				return []types.Finding{f}, nil
			}
		}
	}
	f.Status = types.StatusPass
	f.Severity = types.SeverityInfo
	f.Summary = fmt.Sprintf("JWKS reachable with %d key(s).", len(keys))
	f.Evidence = jwksURI
	return []types.Finding{f}, nil
}

// OAuth2PKCEEnforced checks PKCE for public clients.
type OAuth2PKCEEnforced struct{}

func (OAuth2PKCEEnforced) ID() string               { return "auth.oauth2_pkce_enforced" }
func (OAuth2PKCEEnforced) Title() string            { return "PKCE enforced for public clients" }
func (OAuth2PKCEEnforced) Category() types.Category { return types.CategoryAuth }
func (OAuth2PKCEEnforced) Pack() string             { return config.PackAuthOAuth2 }

func (OAuth2PKCEEnforced) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := types.Finding{
		CheckID:  "auth.oauth2_pkce_enforced",
		Title:    "PKCE enforced for public clients",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthOAuth2,
		Protocol: "oauth2",
		CWE:      "CWE-287",
	}
	if !cctx.Cfg.Auth.OAuth2.PublicClient {
		f.Status = types.StatusSkip
		f.Severity = types.SeverityInfo
		f.Summary = "Not a public client (auth.oauth2.public_client=false)."
		f.Metadata = map[string]string{"skip_reason": types.SkipNotApplicable}
		return []types.Finding{f}, nil
	}
	authURL := oauth.ResolveAuthorizeURL(cctx.Cfg, cctx.OIDC)
	if authURL == "" {
		m, _, err := oauth.Discover(ctx, cctx)
		if err != nil {
			return []types.Finding{checks.Skip("auth.oauth2_pkce_enforced", "PKCE enforced for public clients", config.PackAuthOAuth2, types.CategoryAuth, types.SkipNotApplicable, "No authorize endpoint")}, nil
		}
		authURL = m.AuthorizationEndpoint
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", orDefault(cctx.Cfg.Auth.OAuth2.ClientID, "auth-chaser-probe"))
	q.Set("redirect_uri", orDefault(cctx.Cfg.Auth.OAuth2.RedirectURI, cctx.Cfg.Target.BaseURL+"/oauth/callback"))
	q.Set("scope", strings.Join(scopes(cctx.Cfg), " "))
	q.Set("state", "pkce-test")
	// intentionally no code_challenge
	probe := authURL + "?" + q.Encode()
	resp, err := cctx.Client.Get(ctx, probe, nil)
	if err != nil {
		f.Status = types.StatusSkip
		f.Severity = types.SeverityInfo
		f.Summary = "Authorize endpoint not reachable for PKCE probe."
		f.Evidence = err.Error()
		f.Metadata = map[string]string{"skip_reason": types.SkipNotApplicable}
		return []types.Finding{f}, nil
	}
	body, _ := httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	lower := strings.ToLower(string(body))
	f.Evidence = fmt.Sprintf("status=%d", resp.StatusCode)
	if resp.StatusCode >= 400 || strings.Contains(lower, "code_challenge") || strings.Contains(lower, "pkce") {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Authorize endpoint appears to require or mention PKCE for this public client."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusWarn
	f.Severity = types.SeverityHigh
	f.Summary = "Authorize without PKCE did not clearly fail; confirm PKCE is mandatory for public clients."
	f.Remediation = "Reject authorization requests that omit code_challenge for public clients."
	return []types.Finding{f}, nil
}

func scopes(cfg config.Config) []string {
	if len(cfg.Auth.OAuth2.Scopes) > 0 {
		return cfg.Auth.OAuth2.Scopes
	}
	return []string{"openid"}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vals := range v {
		out[k] = append([]string{}, vals...)
	}
	return out
}

func strClaim(v any) string {
	s, _ := v.(string)
	return s
}

func audClaim(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, x := range t {
			parts = append(parts, fmt.Sprint(x))
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprint(v)
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

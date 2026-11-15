package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Romstar/auth-chaser/internal/checks"
	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/httpclient"
	"github.com/Romstar/auth-chaser/pkg/types"
)

// PasswordLoginSuccess posts valid credentials and expects a session.
type PasswordLoginSuccess struct{}

func (PasswordLoginSuccess) ID() string               { return "auth.password_login_success" }
func (PasswordLoginSuccess) Title() string            { return "Password login success" }
func (PasswordLoginSuccess) Category() types.Category { return types.CategoryAuth }
func (PasswordLoginSuccess) Pack() string             { return config.PackAuthPassword }

func (PasswordLoginSuccess) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := basePwdFinding("auth.password_login_success", "Password login success")
	if cctx.Cfg.Auth.Password.Username == "" || cctx.Cfg.Auth.Password.Password == "" {
		return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackAuthPassword, types.CategoryAuth, types.SkipMissingSecret, "Set auth.password.username and password")}, nil
	}
	loginURL := passwordLoginURL(cctx.Cfg)
	form, err := buildLoginForm(ctx, cctx, loginURL, cctx.Cfg.Auth.Password.Username, cctx.Cfg.Auth.Password.Password)
	if err != nil {
		if isBrowserNeeded(err) {
			if cctx.Browser == nil || !cctx.Browser.Enabled() {
				return []types.Finding{checks.RequiresBrowserSkip(f.CheckID, f.Title, config.PackAuthPassword, types.CategoryAuth)}, nil
			}
			return browserPasswordLogin(ctx, cctx, f, true)
		}
		f.Status = types.StatusError
		f.Severity = types.SeverityMedium
		f.Summary = "Failed to prepare login form."
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	resp, err := cctx.Client.PostForm(ctx, loginURL, nil, form)
	if err != nil {
		f.Status = types.StatusError
		f.Summary = "Login POST failed."
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	body, _ := httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	cookies, _ := cctx.Client.CookiesFor(cctx.Cfg.Target.BaseURL)
	hasSession := len(cookies) > 0 || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther
	f.Evidence = fmt.Sprintf("status=%d cookies=%d body_len=%d", resp.StatusCode, len(cookies), len(body))
	if hasSession && resp.StatusCode < 500 {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Password login produced a session or success redirect."
		return []types.Finding{f}, nil
	}
	// JS-only apps often return 200 with SPA shell
	if resp.StatusCode == 200 && !strings.Contains(strings.ToLower(string(body)), "password") {
		if cctx.Browser == nil || !cctx.Browser.Enabled() {
			sk := checks.RequiresBrowserSkip(f.CheckID, f.Title, config.PackAuthPassword, types.CategoryAuth)
			sk.Evidence = f.Evidence
			return []types.Finding{sk}, nil
		}
		return browserPasswordLogin(ctx, cctx, f, true)
	}
	f.Status = types.StatusFail
	f.Severity = types.SeverityHigh
	f.Summary = "Password login did not establish an observable session."
	f.Remediation = "Verify login_url, field names, and CSRF handling in auth.password config."
	return []types.Finding{f}, nil
}

// PasswordLoginFailure ensures wrong password does not mint a session.
type PasswordLoginFailure struct{}

func (PasswordLoginFailure) ID() string               { return "auth.password_login_failure" }
func (PasswordLoginFailure) Title() string            { return "Password login failure does not mint session" }
func (PasswordLoginFailure) Category() types.Category { return types.CategoryAuth }
func (PasswordLoginFailure) Pack() string             { return config.PackAuthPassword }

func (PasswordLoginFailure) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := basePwdFinding("auth.password_login_failure", "Password login failure does not mint session")
	f.CWE = "CWE-287"
	if cctx.Cfg.Auth.Password.Username == "" {
		return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackAuthPassword, types.CategoryAuth, types.SkipMissingSecret, "Set auth.password.username")}, nil
	}
	loginURL := passwordLoginURL(cctx.Cfg)
	form, err := buildLoginForm(ctx, cctx, loginURL, cctx.Cfg.Auth.Password.Username, "wrong-password-auth-chaser")
	if err != nil {
		f.Status = types.StatusSkip
		f.Summary = "Could not build failure login form."
		f.Evidence = err.Error()
		f.Metadata = map[string]string{"skip_reason": types.SkipNotApplicable}
		return []types.Finding{f}, nil
	}
	// Use a fresh cookie view: count cookies before
	before, _ := cctx.Client.CookiesFor(cctx.Cfg.Target.BaseURL)
	resp, err := cctx.Client.PostForm(ctx, loginURL, nil, form)
	if err != nil {
		f.Status = types.StatusError
		f.Summary = "Failure login POST failed."
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	_, _ = httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	after, _ := cctx.Client.CookiesFor(cctx.Cfg.Target.BaseURL)
	f.Evidence = fmt.Sprintf("status=%d cookies_before=%d cookies_after=%d", resp.StatusCode, len(before), len(after))
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == 422 {
		// Prefer no new session cookie growth on clear failure pages
		if resp.StatusCode >= 400 || strings.Contains(strings.ToLower(resp.Header.Get("Location")), "login") {
			f.Status = types.StatusPass
			f.Severity = types.SeverityInfo
			f.Summary = "Wrong password did not produce an authenticated redirect."
			return []types.Finding{f}, nil
		}
	}
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		loc := resp.Header.Get("Location")
		if !strings.Contains(strings.ToLower(loc), "login") && !strings.Contains(strings.ToLower(loc), "error") {
			f.Status = types.StatusFail
			f.Severity = types.SeverityCritical
			f.Summary = "Wrong password redirected as if login succeeded."
			f.Remediation = "Do not establish a session for invalid credentials."
			return []types.Finding{f}, nil
		}
	}
	f.Status = types.StatusPass
	f.Severity = types.SeverityInfo
	f.Summary = "Wrong password flow did not clearly establish a privileged session."
	return []types.Finding{f}, nil
}

// SessionCookieFlags checks cookies after configured login.
type SessionCookieFlags struct{}

func (SessionCookieFlags) ID() string               { return "auth.session_cookie_flags" }
func (SessionCookieFlags) Title() string            { return "Post-login session cookie flags" }
func (SessionCookieFlags) Category() types.Category { return types.CategoryAuth }
func (SessionCookieFlags) Pack() string             { return config.PackAuthPassword }

func (SessionCookieFlags) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := basePwdFinding("auth.session_cookie_flags", "Post-login session cookie flags")
	f.CWE = "CWE-614"
	cookies, _ := cctx.Client.CookiesFor(cctx.Cfg.Target.BaseURL)
	if len(cookies) == 0 && cctx.Cfg.Auth.Password.Username != "" {
		// attempt login first
		_, _ = (PasswordLoginSuccess{}).Run(ctx, cctx)
		cookies, _ = cctx.Client.CookiesFor(cctx.Cfg.Target.BaseURL)
	}
	if len(cookies) == 0 {
		return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackAuthPassword, types.CategoryAuth, types.SkipNotApplicable, "No session cookies available to inspect")}, nil
	}
	findings := make([]types.Finding, 0, len(cookies))
	for _, c := range cookies {
		issues := make([]string, 0)
		if !c.Secure && strings.HasPrefix(cctx.Cfg.Target.BaseURL, "https://") {
			issues = append(issues, "Secure")
		}
		if !c.HttpOnly {
			issues = append(issues, "HttpOnly")
		}
		if c.SameSite == http.SameSiteDefaultMode || c.SameSite == 0 {
			issues = append(issues, "SameSite")
		}
		item := f
		item.Evidence = c.Name
		if len(issues) == 0 {
			item.Status = types.StatusPass
			item.Severity = types.SeverityInfo
			item.Summary = fmt.Sprintf("Cookie %q has expected security flags.", c.Name)
		} else {
			item.Status = types.StatusFail
			item.Severity = types.SeverityHigh
			item.Summary = fmt.Sprintf("Cookie %q missing flags: %s", c.Name, strings.Join(issues, ", "))
			item.Remediation = "Set Secure, HttpOnly, and SameSite on session cookies."
		}
		findings = append(findings, item)
	}
	return findings, nil
}

// SessionHTTPSOnly warns if base URL is HTTP while sessions exist.
type SessionHTTPSOnly struct{}

func (SessionHTTPSOnly) ID() string               { return "auth.session_https_only" }
func (SessionHTTPSOnly) Title() string            { return "Sessions only over HTTPS" }
func (SessionHTTPSOnly) Category() types.Category { return types.CategoryAuth }
func (SessionHTTPSOnly) Pack() string             { return config.PackAuthPassword }

func (SessionHTTPSOnly) Run(_ context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := basePwdFinding("auth.session_https_only", "Sessions only over HTTPS")
	f.CWE = "CWE-319"
	if strings.HasPrefix(cctx.Cfg.Target.BaseURL, "https://") {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Target uses HTTPS for session establishment."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusFail
	f.Severity = types.SeverityHigh
	f.Summary = "Target uses HTTP; sessions can be intercepted."
	f.Remediation = "Terminate TLS and mark cookies Secure."
	return []types.Finding{f}, nil
}

// LogoutInvalidates checks logout clears access to a protected path.
type LogoutInvalidates struct{}

func (LogoutInvalidates) ID() string               { return "auth.logout_invalidates" }
func (LogoutInvalidates) Title() string            { return "Logout invalidates session" }
func (LogoutInvalidates) Category() types.Category { return types.CategoryAuth }
func (LogoutInvalidates) Pack() string             { return config.PackAuthPassword }

func (LogoutInvalidates) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := basePwdFinding("auth.logout_invalidates", "Logout invalidates session")
	f.CWE = "CWE-613"
	logout := cctx.Cfg.Auth.Password.LogoutURL
	protected := cctx.Cfg.Auth.Password.ProtectedPath
	if logout == "" || protected == "" {
		return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackAuthPassword, types.CategoryAuth, types.SkipMissingConfig, "Set auth.password.logout_url and protected_path")}, nil
	}
	if cctx.Cfg.Auth.Password.Username != "" {
		_, _ = (PasswordLoginSuccess{}).Run(ctx, cctx)
	}
	logoutURL := config.JoinURL(cctx.Cfg.Target.BaseURL, logout)
	resp, err := cctx.Client.Get(ctx, logoutURL, nil)
	if err != nil {
		// try POST logout
		resp, err = cctx.Client.PostForm(ctx, logoutURL, nil, url.Values{})
	}
	if err != nil {
		f.Status = types.StatusError
		f.Summary = "Logout request failed."
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	_, _ = httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()

	prot := config.JoinURL(cctx.Cfg.Target.BaseURL, protected)
	resp2, err := cctx.Client.Get(ctx, prot, nil)
	if err != nil {
		f.Status = types.StatusError
		f.Summary = "Protected path request after logout failed."
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	_, _ = httpclient.ReadLimited(resp2.Body, maxBody)
	_ = resp2.Body.Close()
	f.Evidence = fmt.Sprintf("logout_status=%d protected_status=%d", resp.StatusCode, resp2.StatusCode)
	if resp2.StatusCode == http.StatusUnauthorized || resp2.StatusCode == http.StatusForbidden || resp2.StatusCode == http.StatusFound {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Protected path rejects the session after logout."
		return []types.Finding{f}, nil
	}
	if resp2.StatusCode >= 200 && resp2.StatusCode < 400 {
		f.Status = types.StatusFail
		f.Severity = types.SeverityHigh
		f.Summary = "Protected path still accessible after logout."
		f.Remediation = "Invalidate server-side session on logout and clear cookies."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusWarn
	f.Severity = types.SeverityMedium
	f.Summary = "Unexpected status on protected path after logout."
	return []types.Finding{f}, nil
}

func basePwdFinding(id, title string) types.Finding {
	return types.Finding{
		CheckID:  id,
		Title:    title,
		Category: types.CategoryAuth,
		Pack:     config.PackAuthPassword,
		Protocol: "password",
		Severity: types.SeverityMedium,
	}
}

func passwordLoginURL(cfg config.Config) string {
	p := cfg.Auth.Password.LoginURL
	if p == "" {
		p = "/login"
	}
	return config.JoinURL(cfg.Target.BaseURL, p)
}

func buildLoginForm(ctx context.Context, cctx checks.Context, loginURL, user, pass string) (url.Values, error) {
	resp, err := cctx.Client.Get(ctx, loginURL, nil)
	if err != nil {
		return nil, err
	}
	body, _ := httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	lower := strings.ToLower(string(body))
	if !strings.Contains(lower, "<form") && strings.Contains(lower, "<div id=\"root\"") {
		return nil, fmt.Errorf("js_login_shell")
	}
	form := url.Values{}
	form.Set(cctx.Cfg.Auth.Password.UsernameField, user)
	form.Set(cctx.Cfg.Auth.Password.PasswordField, pass)
	csrfField := cctx.Cfg.Auth.Password.CSRFField
	if csrfField == "" {
		csrfField = "csrf"
	}
	// naive extract
	for _, name := range []string{csrfField, "_csrf", "csrfmiddlewaretoken", "authenticity_token"} {
		if v := extractInputValue(string(body), name); v != "" {
			form.Set(name, v)
			break
		}
	}
	return form, nil
}

func extractInputValue(html, name string) string {
	// very small parser: name="x" value="y"
	idx := strings.Index(html, `name="`+name+`"`)
	if idx < 0 {
		idx = strings.Index(html, `name='`+name+`'`)
	}
	if idx < 0 {
		return ""
	}
	slice := html[idx:]
	vIdx := strings.Index(slice, `value="`)
	if vIdx < 0 {
		vIdx = strings.Index(slice, `value='`)
		if vIdx < 0 {
			return ""
		}
		rest := slice[vIdx+7:]
		end := strings.Index(rest, `'`)
		if end < 0 {
			return ""
		}
		return rest[:end]
	}
	rest := slice[vIdx+7:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func isBrowserNeeded(err error) bool {
	return err != nil && strings.Contains(err.Error(), "js_login_shell")
}

func browserPasswordLogin(ctx context.Context, cctx checks.Context, f types.Finding, expectSuccess bool) ([]types.Finding, error) {
	loginURL := passwordLoginURL(cctx.Cfg)
	if err := cctx.Client.IncrementBudget(); err != nil {
		f.Status = types.StatusError
		f.Summary = err.Error()
		return []types.Finding{f}, nil
	}
	if err := cctx.Browser.Navigate(ctx, loginURL); err != nil {
		f.Status = types.StatusError
		f.Summary = "Browser navigate failed."
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	user, pass := cctx.Cfg.Auth.Password.Username, cctx.Cfg.Auth.Password.Password
	if !expectSuccess {
		pass = "wrong-password-auth-chaser"
	}
	if err := cctx.Browser.FillLogin(ctx, user, pass); err != nil {
		f.Status = types.StatusError
		f.Summary = "Browser login fill failed."
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	cookies, err := cctx.Browser.Cookies(ctx)
	if err == nil {
		_ = cctx.Client.SetCookies(cctx.Cfg.Target.BaseURL, cookies)
	}
	if expectSuccess {
		if len(cookies) > 0 {
			f.Status = types.StatusPass
			f.Severity = types.SeverityInfo
			f.Summary = "Browser password login established cookies."
			f.Evidence = fmt.Sprintf("cookies=%d", len(cookies))
			return []types.Finding{f}, nil
		}
		f.Status = types.StatusFail
		f.Severity = types.SeverityHigh
		f.Summary = "Browser login completed without session cookies."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusPass
	f.Severity = types.SeverityInfo
	f.Summary = "Browser wrong-password flow completed."
	return []types.Finding{f}, nil
}

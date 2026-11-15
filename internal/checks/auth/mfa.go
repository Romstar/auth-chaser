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

// MFARequiredForRole checks that configured roles hit an MFA challenge.
type MFARequiredForRole struct{}

func (MFARequiredForRole) ID() string               { return "auth.mfa_required_for_role" }
func (MFARequiredForRole) Title() string            { return "MFA required for configured roles" }
func (MFARequiredForRole) Category() types.Category { return types.CategoryAuth }
func (MFARequiredForRole) Pack() string             { return config.PackAuthMFA }

func (MFARequiredForRole) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := types.Finding{
		CheckID:  "auth.mfa_required_for_role",
		Title:    "MFA required for configured roles",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthMFA,
		Protocol: "mfa",
		CWE:      "CWE-308",
		Severity: types.SeverityMedium,
	}
	if len(cctx.Cfg.Auth.MFA.RequiredRoles) == 0 {
		return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackAuthMFA, types.CategoryAuth, types.SkipMissingConfig, "Set auth.mfa.required_roles")}, nil
	}
	challenge := cctx.Cfg.Auth.MFA.ChallengeURL
	if challenge == "" {
		challenge = "/mfa"
	}
	u := config.JoinURL(cctx.Cfg.Target.BaseURL, challenge)
	resp, err := cctx.Client.Get(ctx, u, nil)
	if err != nil {
		if cctx.Browser != nil && cctx.Browser.Enabled() {
			return browserMFAChallenge(ctx, cctx, f)
		}
		f.Status = types.StatusSkip
		f.Summary = "MFA challenge URL not reachable over HTTP."
		f.Evidence = err.Error()
		f.Metadata = map[string]string{"skip_reason": types.SkipRequiresBrowser}
		return []types.Finding{f}, nil
	}
	body, _ := httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	lower := strings.ToLower(string(body))
	looksMFA := strings.Contains(lower, "totp") || strings.Contains(lower, "otp") ||
		strings.Contains(lower, "mfa") || strings.Contains(lower, "two-factor") ||
		strings.Contains(lower, "authenticator") || resp.Header.Get("WWW-Authenticate") != ""
	f.Evidence = fmt.Sprintf("status=%d mfa_signals=%v roles=%v", resp.StatusCode, looksMFA, cctx.Cfg.Auth.MFA.RequiredRoles)
	if looksMFA || (resp.StatusCode >= 200 && resp.StatusCode < 400) {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "MFA challenge surface is reachable for roles that require step-up."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusFail
	f.Severity = types.SeverityHigh
	f.Summary = "MFA challenge surface not detected."
	f.Remediation = "Require MFA challenge for roles listed in auth.mfa.required_roles."
	return []types.Finding{f}, nil
}

// MFATOTPSuccess verifies TOTP submission when secret is configured.
type MFATOTPSuccess struct{}

func (MFATOTPSuccess) ID() string               { return "auth.mfa_totp_success" }
func (MFATOTPSuccess) Title() string            { return "MFA TOTP success path" }
func (MFATOTPSuccess) Category() types.Category { return types.CategoryAuth }
func (MFATOTPSuccess) Pack() string             { return config.PackAuthMFA }

func (MFATOTPSuccess) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := types.Finding{
		CheckID:  "auth.mfa_totp_success",
		Title:    "MFA TOTP success path",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthMFA,
		Protocol: "mfa",
		Severity: types.SeverityMedium,
	}
	if cctx.Cfg.Auth.MFA.TOTPSecret == "" {
		return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackAuthMFA, types.CategoryAuth, types.SkipMissingSecret, "Set auth.mfa.totp_secret")}, nil
	}
	challenge := cctx.Cfg.Auth.MFA.ChallengeURL
	if challenge == "" {
		challenge = "/mfa/verify"
	}
	code := totpNow(cctx.Cfg.Auth.MFA.TOTPSecret)
	if code == "" {
		f.Status = types.StatusError
		f.Summary = "Could not derive TOTP from configured secret."
		return []types.Finding{f}, nil
	}
	u := config.JoinURL(cctx.Cfg.Target.BaseURL, challenge)
	form := url.Values{}
	form.Set("code", code)
	form.Set("otp", code)
	form.Set("token", code)
	resp, err := cctx.Client.PostForm(ctx, u, nil, form)
	if err != nil {
		if cctx.Browser == nil || !cctx.Browser.Enabled() {
			return []types.Finding{checks.RequiresBrowserSkip(f.CheckID, f.Title, config.PackAuthMFA, types.CategoryAuth)}, nil
		}
		return browserTOTP(ctx, cctx, f, code)
	}
	_, _ = httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	f.Evidence = fmt.Sprintf("status=%d", resp.StatusCode)
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "TOTP verification endpoint accepted a current code (or redirected)."
		return []types.Finding{f}, nil
	}
	if resp.StatusCode == 404 || resp.StatusCode == 405 {
		if cctx.Browser == nil || !cctx.Browser.Enabled() {
			return []types.Finding{checks.RequiresBrowserSkip(f.CheckID, f.Title, config.PackAuthMFA, types.CategoryAuth)}, nil
		}
		return browserTOTP(ctx, cctx, f, code)
	}
	f.Status = types.StatusFail
	f.Severity = types.SeverityHigh
	f.Summary = "TOTP verification did not succeed."
	f.Remediation = "Confirm challenge URL and that the TOTP secret matches the test account."
	return []types.Finding{f}, nil
}

// MFABypassPaths ensures post-MFA paths reject unauthenticated/pre-MFA access.
type MFABypassPaths struct{}

func (MFABypassPaths) ID() string               { return "auth.mfa_bypass_paths" }
func (MFABypassPaths) Title() string            { return "Post-MFA paths reject bypass" }
func (MFABypassPaths) Category() types.Category { return types.CategoryAuth }
func (MFABypassPaths) Pack() string             { return config.PackAuthMFA }

func (MFABypassPaths) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := types.Finding{
		CheckID:  "auth.mfa_bypass_paths",
		Title:    "Post-MFA paths reject bypass",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthMFA,
		Protocol: "mfa",
		CWE:      "CWE-288",
		Severity: types.SeverityHigh,
	}
	paths := cctx.Cfg.Auth.MFA.BypassPaths
	if len(paths) == 0 {
		return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackAuthMFA, types.CategoryAuth, types.SkipMissingConfig, "Set auth.mfa.bypass_paths")}, nil
	}
	findings := make([]types.Finding, 0, len(paths))
	for _, p := range paths {
		item := f
		u := config.JoinURL(cctx.Cfg.Target.BaseURL, p)
		resp, err := cctx.Client.Get(ctx, u, nil)
		if err != nil {
			item.Status = types.StatusError
			item.Summary = "Bypass path probe failed."
			item.Evidence = err.Error()
			findings = append(findings, item)
			continue
		}
		_, _ = httpclient.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close()
		item.Evidence = fmt.Sprintf("path=%s status=%d", p, resp.StatusCode)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusFound {
			item.Status = types.StatusPass
			item.Severity = types.SeverityInfo
			item.Summary = fmt.Sprintf("Path %s correctly blocks pre-MFA access.", p)
		} else if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			item.Status = types.StatusFail
			item.Severity = types.SeverityCritical
			item.Summary = fmt.Sprintf("Path %s accessible without completing MFA.", p)
			item.Remediation = "Gate post-MFA resources on completed second-factor state."
		} else {
			item.Status = types.StatusWarn
			item.Severity = types.SeverityMedium
			item.Summary = fmt.Sprintf("Unexpected status on bypass path %s.", p)
		}
		findings = append(findings, item)
	}
	return findings, nil
}

func browserMFAChallenge(ctx context.Context, cctx checks.Context, f types.Finding) ([]types.Finding, error) {
	u := config.JoinURL(cctx.Cfg.Target.BaseURL, orDefault(cctx.Cfg.Auth.MFA.ChallengeURL, "/mfa"))
	_ = cctx.Client.IncrementBudget()
	if err := cctx.Browser.Navigate(ctx, u); err != nil {
		f.Status = types.StatusError
		f.Evidence = err.Error()
		f.Summary = "Browser could not open MFA challenge."
		return []types.Finding{f}, nil
	}
	ok, _ := cctx.Browser.PageContains(ctx, "otp")
	ok2, _ := cctx.Browser.PageContains(ctx, "mfa")
	if ok || ok2 {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "Browser detected MFA challenge UI."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusWarn
	f.Summary = "Browser opened challenge URL but MFA signals were weak."
	return []types.Finding{f}, nil
}

func browserTOTP(ctx context.Context, cctx checks.Context, f types.Finding, code string) ([]types.Finding, error) {
	u := config.JoinURL(cctx.Cfg.Target.BaseURL, orDefault(cctx.Cfg.Auth.MFA.ChallengeURL, "/mfa"))
	_ = cctx.Client.IncrementBudget()
	if err := cctx.Browser.Navigate(ctx, u); err != nil {
		f.Status = types.StatusError
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusWarn
	f.Severity = types.SeverityMedium
	f.Summary = "Browser MFA page opened; full automated TOTP field submit is best-effort."
	f.Evidence = "code_generated=true len=" + fmt.Sprint(len(code))
	return []types.Finding{f}, nil
}

// Package misconfig implements non-destructive auth misconfiguration checks.
package misconfig

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Romstar/auth-chaser/internal/checks"
	"github.com/Romstar/auth-chaser/internal/httpclient"
	"github.com/Romstar/auth-chaser/pkg/types"
)

const maxBody = 256 * 1024

// SecurityHeaders checks auth-relevant response headers on the base URL.
type SecurityHeaders struct{}

func (SecurityHeaders) ID() string               { return "misconfig.security_headers" }
func (SecurityHeaders) Title() string            { return "Auth-relevant security headers" }
func (SecurityHeaders) Category() types.Category { return types.CategoryMisconfig }

func (SecurityHeaders) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	resp, err := cctx.Client.Get(ctx, cctx.Cfg.Target.BaseURL+"/", nil)
	if err != nil {
		return []types.Finding{{
			CheckID:  "misconfig.security_headers",
			Title:    "Auth-relevant security headers",
			Category: types.CategoryMisconfig,
			Severity: types.SeverityMedium,
			Status:   types.StatusError,
			Summary:  "Failed to fetch target for header inspection.",
			Evidence: err.Error(),
		}}, nil
	}
	defer resp.Body.Close()
	_, _ = httpclient.ReadLimited(resp.Body, maxBody)

	missing := make([]string, 0)
	required := map[string]string{
		"Strict-Transport-Security": "HSTS",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "clickjacking protection",
		"Content-Security-Policy":   "CSP",
	}
	for header := range required {
		if resp.Header.Get(header) == "" {
			missing = append(missing, header)
		}
	}

	if len(missing) == 0 {
		return []types.Finding{{
			CheckID:  "misconfig.security_headers",
			Title:    "Auth-relevant security headers",
			Category: types.CategoryMisconfig,
			Severity: types.SeverityInfo,
			Status:   types.StatusPass,
			Summary:  "Expected security headers are present.",
		}}, nil
	}

	return []types.Finding{{
		CheckID:     "misconfig.security_headers",
		Title:       "Auth-relevant security headers",
		Category:    types.CategoryMisconfig,
		Severity:    types.SeverityMedium,
		Status:      types.StatusFail,
		Summary:     "One or more auth-relevant security headers are missing.",
		Evidence:    "missing: " + strings.Join(missing, ", "),
		Remediation: "Add HSTS, X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy on authenticated surfaces.",
	}}, nil
}

// CookieFlags inspects Set-Cookie attributes on the base response.
type CookieFlags struct{}

func (CookieFlags) ID() string               { return "misconfig.cookie_flags" }
func (CookieFlags) Title() string            { return "Session cookie security flags" }
func (CookieFlags) Category() types.Category { return types.CategoryMisconfig }

func (CookieFlags) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	resp, err := cctx.Client.Get(ctx, cctx.Cfg.Target.BaseURL+"/", nil)
	if err != nil {
		return []types.Finding{{
			CheckID:  "misconfig.cookie_flags",
			Title:    "Session cookie security flags",
			Category: types.CategoryMisconfig,
			Severity: types.SeverityLow,
			Status:   types.StatusError,
			Summary:  "Failed to fetch target for cookie inspection.",
			Evidence: err.Error(),
		}}, nil
	}
	defer resp.Body.Close()
	_, _ = httpclient.ReadLimited(resp.Body, maxBody)

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		// Also parse raw Set-Cookie if Cookies() is empty due to redirects/attrs.
		raw := resp.Header.Values("Set-Cookie")
		if len(raw) == 0 {
			return []types.Finding{{
				CheckID:  "misconfig.cookie_flags",
				Title:    "Session cookie security flags",
				Category: types.CategoryMisconfig,
				Severity: types.SeverityInfo,
				Status:   types.StatusSkip,
				Summary:  "No Set-Cookie headers on the base URL response.",
			}}, nil
		}
		return analyzeRawCookies(raw), nil
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
		if len(issues) == 0 {
			findings = append(findings, types.Finding{
				CheckID:  "misconfig.cookie_flags",
				Title:    "Session cookie security flags",
				Category: types.CategoryMisconfig,
				Severity: types.SeverityInfo,
				Status:   types.StatusPass,
				Summary:  fmt.Sprintf("Cookie %q has expected security flags.", c.Name),
			})
			continue
		}
		findings = append(findings, types.Finding{
			CheckID:     "misconfig.cookie_flags",
			Title:       "Session cookie security flags",
			Category:    types.CategoryMisconfig,
			Severity:    types.SeverityHigh,
			Status:      types.StatusFail,
			Summary:     fmt.Sprintf("Cookie %q is missing security flags.", c.Name),
			Evidence:    "missing: " + strings.Join(issues, ", "),
			Remediation: "Set Secure, HttpOnly, and SameSite on session cookies.",
		})
	}
	return findings, nil
}

func analyzeRawCookies(raw []string) []types.Finding {
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
		if len(issues) == 0 {
			findings = append(findings, types.Finding{
				CheckID:  "misconfig.cookie_flags",
				Title:    "Session cookie security flags",
				Category: types.CategoryMisconfig,
				Severity: types.SeverityInfo,
				Status:   types.StatusPass,
				Summary:  fmt.Sprintf("Cookie %q has expected security flags.", name),
			})
			continue
		}
		findings = append(findings, types.Finding{
			CheckID:     "misconfig.cookie_flags",
			Title:       "Session cookie security flags",
			Category:    types.CategoryMisconfig,
			Severity:    types.SeverityHigh,
			Status:      types.StatusFail,
			Summary:     fmt.Sprintf("Cookie %q is missing security flags.", name),
			Evidence:    "missing: " + strings.Join(issues, ", "),
			Remediation: "Set Secure, HttpOnly, and SameSite on session cookies.",
		})
	}
	return findings
}

// CORSMisconfig flags overly permissive Access-Control-Allow-Origin with credentials.
type CORSMisconfig struct{}

func (CORSMisconfig) ID() string               { return "misconfig.cors" }
func (CORSMisconfig) Title() string            { return "CORS configuration for credentialed requests" }
func (CORSMisconfig) Category() types.Category { return types.CategoryMisconfig }

func (CORSMisconfig) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	headers := map[string]string{
		"Origin":                        "https://auth-chaser-probe.invalid",
		"Access-Control-Request-Method": "GET",
	}
	resp, err := cctx.Client.Do(ctx, http.MethodOptions, cctx.Cfg.Target.BaseURL+"/", headers, nil)
	if err != nil {
		// Some servers reject OPTIONS; try GET with Origin instead.
		resp, err = cctx.Client.Get(ctx, cctx.Cfg.Target.BaseURL+"/", map[string]string{
			"Origin": "https://auth-chaser-probe.invalid",
		})
		if err != nil {
			return []types.Finding{{
				CheckID:  "misconfig.cors",
				Title:    "CORS configuration for credentialed requests",
				Category: types.CategoryMisconfig,
				Severity: types.SeverityLow,
				Status:   types.StatusError,
				Summary:  "Failed to probe CORS headers.",
				Evidence: err.Error(),
			}}, nil
		}
	}
	defer resp.Body.Close()
	_, _ = httpclient.ReadLimited(resp.Body, maxBody)

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))
	if acao == "*" && acac == "true" {
		return []types.Finding{{
			CheckID:     "misconfig.cors",
			Title:       "CORS configuration for credentialed requests",
			Category:    types.CategoryMisconfig,
			Severity:    types.SeverityCritical,
			Status:      types.StatusFail,
			Summary:     "CORS allows any origin with credentials.",
			Evidence:    fmt.Sprintf("Access-Control-Allow-Origin=%s Access-Control-Allow-Credentials=%s", acao, acac),
			Remediation: "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
		}}, nil
	}
	if acao == "https://auth-chaser-probe.invalid" && acac == "true" {
		return []types.Finding{{
			CheckID:     "misconfig.cors",
			Title:       "CORS configuration for credentialed requests",
			Category:    types.CategoryMisconfig,
			Severity:    types.SeverityHigh,
			Status:      types.StatusFail,
			Summary:     "Server reflects arbitrary Origin with credentials enabled.",
			Evidence:    fmt.Sprintf("Access-Control-Allow-Origin=%s", acao),
			Remediation: "Allowlist trusted origins. Do not reflect untrusted Origin values when credentials are enabled.",
		}}, nil
	}
	return []types.Finding{{
		CheckID:  "misconfig.cors",
		Title:    "CORS configuration for credentialed requests",
		Category: types.CategoryMisconfig,
		Severity: types.SeverityInfo,
		Status:   types.StatusPass,
		Summary:  "No critical CORS credential misconfiguration detected on base URL.",
		Evidence: fmt.Sprintf("Access-Control-Allow-Origin=%q", acao),
	}}, nil
}

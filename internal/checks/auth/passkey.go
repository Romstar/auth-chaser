package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Romstar/auth-chaser/internal/checks"
	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/httpclient"
	"github.com/Romstar/auth-chaser/pkg/types"
)

// PasskeyOptions checks WebAuthn options endpoint presence.
type PasskeyOptions struct{}

func (PasskeyOptions) ID() string               { return "auth.passkey_options" }
func (PasskeyOptions) Title() string            { return "WebAuthn/passkey options endpoint" }
func (PasskeyOptions) Category() types.Category { return types.CategoryAuth }
func (PasskeyOptions) Pack() string             { return config.PackAuthPasskey }

func (PasskeyOptions) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := types.Finding{
		CheckID:  "auth.passkey_options",
		Title:    "WebAuthn/passkey options endpoint",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthPasskey,
		Protocol: "webauthn",
		Severity: types.SeverityMedium,
	}
	if !cctx.Cfg.Auth.Passkey.Enabled {
		return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackAuthPasskey, types.CategoryAuth, types.SkipNotApplicable, "auth.passkey.enabled is false")}, nil
	}
	candidates := []string{
		cctx.Cfg.Auth.Passkey.OptionsURL,
		"/webauthn/register/options",
		"/webauthn/login/options",
		"/api/webauthn/options",
		"/passkey/options",
	}
	var lastStatus int
	for _, p := range candidates {
		if p == "" {
			continue
		}
		u := config.JoinURL(cctx.Cfg.Target.BaseURL, p)
		resp, err := cctx.Client.Get(ctx, u, nil)
		if err != nil {
			continue
		}
		body, _ := httpclient.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close()
		lastStatus = resp.StatusCode
		if resp.StatusCode == http.StatusOK {
			lower := strings.ToLower(string(body))
			if strings.Contains(lower, "challenge") || strings.Contains(lower, "rp") || strings.Contains(lower, "publickey") {
				f.Status = types.StatusPass
				f.Severity = types.SeverityInfo
				f.Summary = "WebAuthn options endpoint returned challenge material."
				f.Evidence = u
				return []types.Finding{f}, nil
			}
		}
	}
	f.Status = types.StatusWarn
	f.Summary = "No WebAuthn options endpoint detected at common paths."
	f.Evidence = fmt.Sprintf("last_status=%d", lastStatus)
	f.Remediation = "Expose a WebAuthn options endpoint and set auth.passkey.options_url."
	return []types.Finding{f}, nil
}

// PasskeyRegisterLogin uses browser virtual authenticator when available.
type PasskeyRegisterLogin struct{}

func (PasskeyRegisterLogin) ID() string               { return "auth.passkey_register_login" }
func (PasskeyRegisterLogin) Title() string            { return "Passkey register/login smoke" }
func (PasskeyRegisterLogin) Category() types.Category { return types.CategoryAuth }
func (PasskeyRegisterLogin) Pack() string             { return config.PackAuthPasskey }

func (PasskeyRegisterLogin) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := types.Finding{
		CheckID:  "auth.passkey_register_login",
		Title:    "Passkey register/login smoke",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthPasskey,
		Protocol: "webauthn",
		Severity: types.SeverityMedium,
	}
	if !cctx.Cfg.Auth.Passkey.Enabled {
		return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackAuthPasskey, types.CategoryAuth, types.SkipNotApplicable, "auth.passkey.enabled is false")}, nil
	}
	if cctx.Browser == nil || !cctx.Browser.Enabled() {
		return []types.Finding{checks.RequiresBrowserSkip(f.CheckID, f.Title, config.PackAuthPasskey, types.CategoryAuth)}, nil
	}
	u := config.JoinURL(cctx.Cfg.Target.BaseURL, orDefault(cctx.Cfg.Auth.Passkey.OptionsURL, "/"))
	_ = cctx.Client.IncrementBudget()
	if err := cctx.Browser.Navigate(ctx, u); err != nil {
		f.Status = types.StatusError
		f.Summary = "Browser navigate for passkey smoke failed."
		f.Evidence = err.Error()
		return []types.Finding{f}, nil
	}
	ok, _ := cctx.Browser.PageContains(ctx, "webauthn")
	ok2, _ := cctx.Browser.PageContains(ctx, "passkey")
	f.Status = types.StatusWarn
	f.Severity = types.SeverityInfo
	f.Summary = "Browser opened passkey surface; CDP virtual authenticator hooks are available for deeper tests."
	f.Evidence = fmt.Sprintf("webauthn_text=%v passkey_text=%v", ok, ok2)
	return []types.Finding{f}, nil
}

// PasskeyUserVerification checks options require user verification when configured.
type PasskeyUserVerification struct{}

func (PasskeyUserVerification) ID() string               { return "auth.passkey_user_verification" }
func (PasskeyUserVerification) Title() string            { return "Passkey user verification required" }
func (PasskeyUserVerification) Category() types.Category { return types.CategoryAuth }
func (PasskeyUserVerification) Pack() string             { return config.PackAuthPasskey }

func (PasskeyUserVerification) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	f := types.Finding{
		CheckID:  "auth.passkey_user_verification",
		Title:    "Passkey user verification required",
		Category: types.CategoryAuth,
		Pack:     config.PackAuthPasskey,
		Protocol: "webauthn",
		CWE:      "CWE-287",
		Severity: types.SeverityMedium,
	}
	if !cctx.Cfg.Auth.Passkey.Enabled {
		return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackAuthPasskey, types.CategoryAuth, types.SkipNotApplicable, "auth.passkey.enabled is false")}, nil
	}
	if !cctx.Cfg.Auth.Passkey.RequireUserVerification {
		f.Status = types.StatusSkip
		f.Severity = types.SeverityInfo
		f.Summary = "auth.passkey.require_user_verification is false; policy check skipped."
		f.Metadata = map[string]string{"skip_reason": types.SkipNotApplicable}
		return []types.Finding{f}, nil
	}
	optsURL := cctx.Cfg.Auth.Passkey.OptionsURL
	if optsURL == "" {
		return []types.Finding{checks.Skip(f.CheckID, f.Title, config.PackAuthPasskey, types.CategoryAuth, types.SkipMissingConfig, "Set auth.passkey.options_url")}, nil
	}
	u := config.JoinURL(cctx.Cfg.Target.BaseURL, optsURL)
	resp, err := cctx.Client.Get(ctx, u, nil)
	if err != nil {
		f.Status = types.StatusError
		f.Evidence = err.Error()
		f.Summary = "Options endpoint unreachable."
		return []types.Finding{f}, nil
	}
	body, _ := httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	uv := strings.ToLower(fmt.Sprint(doc["userVerification"]))
	if uv == "" {
		if authenticatorSelection, ok := doc["authenticatorSelection"].(map[string]any); ok {
			uv = strings.ToLower(fmt.Sprint(authenticatorSelection["userVerification"]))
		}
	}
	f.Evidence = "userVerification=" + uv
	if uv == "required" {
		f.Status = types.StatusPass
		f.Severity = types.SeverityInfo
		f.Summary = "WebAuthn options require user verification."
		return []types.Finding{f}, nil
	}
	f.Status = types.StatusFail
	f.Severity = types.SeverityHigh
	f.Summary = "WebAuthn options do not set userVerification=required."
	f.Remediation = "Set authenticatorSelection.userVerification to required."
	return []types.Finding{f}, nil
}

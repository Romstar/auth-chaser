package runner_test

import (
	"context"
	"testing"
	"time"

	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/runner"
	"github.com/Romstar/auth-chaser/internal/testapp"
	"github.com/Romstar/auth-chaser/pkg/types"
)

func TestChaseAgainstFixture(t *testing.T) {
	app := testapp.Start()
	defer app.Close()

	cfg := config.Default()
	cfg.Target.BaseURL = app.URL
	cfg.Safety.ConfirmAuthorized = true
	cfg.Safety.RequestsPerSecond = 20
	cfg.Safety.MaxRequests = 200
	cfg.Checks.Packs = []string{
		config.PackAuthCore,
		config.PackAuthOAuth2,
		config.PackAuthPassword,
		config.PackMisconfigAuth,
		config.PackRBACMatrix,
		config.PackAuthMFA,
		config.PackAuthPasskey,
	}
	cfg.Auth.OAuth2.ClientID = "public"
	cfg.Auth.OAuth2.PublicClient = true
	cfg.Auth.OAuth2.RedirectURI = app.URL + "/callback"
	cfg.Auth.Password.LoginURL = "/login"
	cfg.Auth.Password.LogoutURL = "/logout"
	cfg.Auth.Password.ProtectedPath = "/me"
	cfg.Auth.Password.Username = "alice"
	cfg.Auth.Password.Password = "password123"
	cfg.Auth.MFA.RequiredRoles = []string{"admin"}
	cfg.Auth.MFA.ChallengeURL = "/mfa"
	cfg.Auth.MFA.BypassPaths = []string{"/me"}
	cfg.Auth.MFA.TOTPSecret = "JBSWY3DPEHPK3PXP"
	cfg.Auth.Passkey.Enabled = true
	cfg.Auth.Passkey.OptionsURL = "/webauthn/login/options"
	cfg.Auth.Passkey.RequireUserVerification = true
	cfg.RBAC.Roles = []config.RoleSpec{
		{Name: "viewer", BearerToken: "viewer-token", AllowedPaths: []string{"/api/items"}, DeniedPaths: []string{"/api/admin"}},
		{Name: "admin", BearerToken: "admin-token", AllowedPaths: []string{"/api/items", "/api/admin"}},
	}
	cfg.RBAC.ProtectedPaths = []string{"/api/items", "/api/admin"}
	cfg.RBAC.ObjectTests = []config.ObjectTest{
		{Name: "viewer-cannot-read-bob", ActorRole: "viewer", Path: "/api/users/bob", ExpectDeny: true},
		{Name: "viewer-can-read-alice", ActorRole: "viewer", Path: "/api/users/alice", ExpectDeny: false},
	}
	cfg.Normalize()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep, err := runner.New(cfg).Run(ctx)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.PassCount == 0 {
		t.Fatalf("expected some passes, got %#v", rep)
	}
	var failedCritical int
	for _, f := range rep.Findings {
		if f.Status == types.StatusFail && f.Severity == types.SeverityCritical {
			failedCritical++
			t.Logf("critical fail: %s %s", f.CheckID, f.Summary)
		}
	}
	if failedCritical > 0 {
		t.Fatalf("unexpected critical failures: %d", failedCritical)
	}
}

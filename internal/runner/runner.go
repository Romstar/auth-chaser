// Package runner orchestrates authorization gating and check execution.
package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/Romstar/auth-chaser/internal/authz"
	"github.com/Romstar/auth-chaser/internal/checks"
	"github.com/Romstar/auth-chaser/internal/checks/auth"
	"github.com/Romstar/auth-chaser/internal/checks/misconfig"
	"github.com/Romstar/auth-chaser/internal/checks/rbac"
	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/httpclient"
	"github.com/Romstar/auth-chaser/pkg/types"
)

// Version is set by main/ldflags.
var Version = "0.1.0"

// Runner executes a configured chase.
type Runner struct {
	cfg config.Config
}

// New creates a runner.
func New(cfg config.Config) *Runner {
	return &Runner{cfg: cfg}
}

// Run validates safety, builds checks, and returns a report.
func (r *Runner) Run(ctx context.Context) (*types.Report, error) {
	if err := r.cfg.Validate(); err != nil {
		return nil, err
	}

	gate := authz.NewGate(r.cfg)
	if err := gate.RequireAuthorized(); err != nil {
		return nil, err
	}

	start := time.Now()
	client := httpclient.New(r.cfg, gate)
	cctx := checks.Context{Cfg: r.cfg, Client: client}

	reg := checks.NewRegistry()
	if r.cfg.Checks.Auth {
		reg.Add(auth.HTTPSRequired{}, auth.OIDCDiscovery{}, auth.LoginSurface{})
	}
	if r.cfg.Checks.Misconfig {
		reg.Add(misconfig.SecurityHeaders{}, misconfig.CookieFlags{}, misconfig.CORSMisconfig{})
	}
	if r.cfg.Checks.RBAC {
		reg.Add(rbac.RoleAccess{})
	}

	report := &types.Report{
		Target:      r.cfg.Target.BaseURL,
		StartedAt:   start,
		Authorized:  true,
		Findings:    make([]types.Finding, 0),
		ToolVersion: Version,
	}

	for _, check := range reg.All() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		findings, err := check.Run(ctx, cctx)
		if err != nil {
			report.Findings = append(report.Findings, types.Finding{
				CheckID:  check.ID(),
				Title:    check.Title(),
				Category: check.Category(),
				Severity: types.SeverityMedium,
				Status:   types.StatusError,
				Summary:  "Check failed to execute.",
				Evidence: err.Error(),
			})
			continue
		}
		report.Findings = append(report.Findings, findings...)
	}

	report.FinishedAt = time.Now()
	report.DurationMS = report.FinishedAt.Sub(start).Milliseconds()
	report.Summarize()
	return report, nil
}

// PreviewLists returns check IDs that would run for the current config.
func (r *Runner) PreviewLists() []string {
	ids := make([]string, 0)
	if r.cfg.Checks.Auth {
		ids = append(ids, "auth.https_required", "auth.oidc_discovery", "auth.login_surface")
	}
	if r.cfg.Checks.Misconfig {
		ids = append(ids, "misconfig.security_headers", "misconfig.cookie_flags", "misconfig.cors")
	}
	if r.cfg.Checks.RBAC {
		ids = append(ids, "rbac.role_access")
	}
	return ids
}

// Describe returns a one-line description of the upcoming run.
func (r *Runner) Describe() string {
	return fmt.Sprintf("target=%s checks=%v rps=%.1f max_requests=%d",
		r.cfg.Target.BaseURL, r.PreviewLists(), r.cfg.Safety.RequestsPerSecond, r.cfg.Safety.MaxRequests)
}

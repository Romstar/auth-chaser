// Package runner orchestrates authorization gating and check execution.
package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/Romstar/auth-chaser/internal/authz"
	"github.com/Romstar/auth-chaser/internal/browser"
	"github.com/Romstar/auth-chaser/internal/checks"
	"github.com/Romstar/auth-chaser/internal/checks/packs"
	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/httpclient"
	"github.com/Romstar/auth-chaser/pkg/types"
)

// Version is set by main/ldflags.
var Version = "0.2.0"

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

	var br checks.Browser
	sess, err := browser.Start(ctx, r.cfg, gate)
	if err != nil {
		// Chrome missing is non-fatal; browser checks will skip.
		br = sess
	} else {
		br = sess
	}
	if sess != nil {
		defer sess.Close()
	}

	oidcMeta := &checks.OIDCMeta{}
	cctx := checks.Context{Cfg: r.cfg, Client: client, Browser: br, OIDC: oidcMeta}

	selected, err := packs.ForPacks(r.cfg.EffectivePacks())
	if err != nil {
		return nil, err
	}

	report := &types.Report{
		Target:      r.cfg.Target.BaseURL,
		StartedAt:   start,
		Authorized:  true,
		Findings:    make([]types.Finding, 0),
		ToolVersion: Version,
		Packs:       r.cfg.EffectivePacks(),
	}

	for _, check := range selected {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		findings, err := check.Run(ctx, cctx)
		if err != nil {
			report.Findings = append(report.Findings, types.Finding{
				CheckID:  check.ID(),
				Title:    check.Title(),
				Category: check.Category(),
				Pack:     check.Pack(),
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
	selected, err := packs.ForPacks(r.cfg.EffectivePacks())
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(selected))
	for _, c := range selected {
		ids = append(ids, c.ID())
	}
	return ids
}

// Describe returns a one-line description of the upcoming run.
func (r *Runner) Describe() string {
	return fmt.Sprintf("target=%s packs=%v checks=%d rps=%.1f max_requests=%d browser=%v",
		r.cfg.Target.BaseURL, r.cfg.EffectivePacks(), len(r.PreviewLists()),
		r.cfg.Safety.RequestsPerSecond, r.cfg.Safety.MaxRequests, r.cfg.Browser.Enabled || r.cfg.Safety.AllowBrowser)
}

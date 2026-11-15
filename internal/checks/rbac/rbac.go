// Package rbac implements authorization / RBAC verification checks.
package rbac

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

const maxBody = 64 * 1024

// RoleAccess verifies that roles can reach allowed paths and are denied denied paths.
type RoleAccess struct{}

func (RoleAccess) ID() string               { return "rbac.role_access" }
func (RoleAccess) Title() string            { return "Role-based path access" }
func (RoleAccess) Category() types.Category { return types.CategoryRBAC }

func (RoleAccess) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	roles := cctx.Cfg.RBAC.Roles
	if len(roles) == 0 {
		return []types.Finding{{
			CheckID:     "rbac.role_access",
			Title:       "Role-based path access",
			Category:    types.CategoryRBAC,
			Severity:    types.SeverityInfo,
			Status:      types.StatusSkip,
			Summary:     "No RBAC roles configured.",
			Remediation: "Add rbac.roles entries with bearer tokens and expected allowed/denied paths.",
		}}, nil
	}

	findings := make([]types.Finding, 0)
	for _, role := range roles {
		findings = append(findings, probeRole(ctx, cctx, role)...)
	}
	return findings, nil
}

func probeRole(ctx context.Context, cctx checks.Context, role config.RoleSpec) []types.Finding {
	out := make([]types.Finding, 0)
	headers := map[string]string{}
	if role.BearerToken != "" {
		headers["Authorization"] = "Bearer " + role.BearerToken
	}

	for _, path := range role.AllowedPaths {
		url := join(cctx.Cfg.Target.BaseURL, path)
		resp, err := cctx.Client.Get(ctx, url, headers)
		if err != nil {
			out = append(out, types.Finding{
				CheckID:  "rbac.role_access",
				Title:    "Role-based path access",
				Category: types.CategoryRBAC,
				Severity: types.SeverityMedium,
				Status:   types.StatusError,
				Summary:  fmt.Sprintf("Role %q could not request allowed path %s.", role.Name, path),
				Evidence: err.Error(),
				Metadata: map[string]string{"role": role.Name, "path": path, "expectation": "allow"},
			})
			continue
		}
		_, _ = httpclient.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			out = append(out, types.Finding{
				CheckID:     "rbac.role_access",
				Title:       "Role-based path access",
				Category:    types.CategoryRBAC,
				Severity:    types.SeverityHigh,
				Status:      types.StatusFail,
				Summary:     fmt.Sprintf("Role %q was denied path %s that should be allowed.", role.Name, path),
				Evidence:    fmt.Sprintf("status=%d", resp.StatusCode),
				Remediation: "Verify RBAC grants for this role, or correct the expected allowed_paths list.",
				Metadata:    map[string]string{"role": role.Name, "path": path, "expectation": "allow"},
			})
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			out = append(out, types.Finding{
				CheckID:  "rbac.role_access",
				Title:    "Role-based path access",
				Category: types.CategoryRBAC,
				Severity: types.SeverityInfo,
				Status:   types.StatusPass,
				Summary:  fmt.Sprintf("Role %q can access allowed path %s.", role.Name, path),
				Evidence: fmt.Sprintf("status=%d", resp.StatusCode),
				Metadata: map[string]string{"role": role.Name, "path": path, "expectation": "allow"},
			})
			continue
		}
		out = append(out, types.Finding{
			CheckID:  "rbac.role_access",
			Title:    "Role-based path access",
			Category: types.CategoryRBAC,
			Severity: types.SeverityMedium,
			Status:   types.StatusWarn,
			Summary:  fmt.Sprintf("Role %q got unexpected status on allowed path %s.", role.Name, path),
			Evidence: fmt.Sprintf("status=%d", resp.StatusCode),
			Metadata: map[string]string{"role": role.Name, "path": path, "expectation": "allow"},
		})
	}

	for _, path := range role.DeniedPaths {
		url := join(cctx.Cfg.Target.BaseURL, path)
		resp, err := cctx.Client.Get(ctx, url, headers)
		if err != nil {
			out = append(out, types.Finding{
				CheckID:  "rbac.role_access",
				Title:    "Role-based path access",
				Category: types.CategoryRBAC,
				Severity: types.SeverityMedium,
				Status:   types.StatusError,
				Summary:  fmt.Sprintf("Role %q could not request denied path %s.", role.Name, path),
				Evidence: err.Error(),
				Metadata: map[string]string{"role": role.Name, "path": path, "expectation": "deny"},
			})
			continue
		}
		_, _ = httpclient.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			out = append(out, types.Finding{
				CheckID:  "rbac.role_access",
				Title:    "Role-based path access",
				Category: types.CategoryRBAC,
				Severity: types.SeverityInfo,
				Status:   types.StatusPass,
				Summary:  fmt.Sprintf("Role %q is correctly denied path %s.", role.Name, path),
				Evidence: fmt.Sprintf("status=%d", resp.StatusCode),
				Metadata: map[string]string{"role": role.Name, "path": path, "expectation": "deny"},
			})
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			out = append(out, types.Finding{
				CheckID:     "rbac.role_access",
				Title:       "Role-based path access",
				Category:    types.CategoryRBAC,
				Severity:    types.SeverityCritical,
				Status:      types.StatusFail,
				Summary:     fmt.Sprintf("Role %q accessed path %s that should be denied.", role.Name, path),
				Evidence:    fmt.Sprintf("status=%d", resp.StatusCode),
				Remediation: "Enforce authorization on this path for the given role.",
				Metadata:    map[string]string{"role": role.Name, "path": path, "expectation": "deny"},
			})
			continue
		}
		out = append(out, types.Finding{
			CheckID:  "rbac.role_access",
			Title:    "Role-based path access",
			Category: types.CategoryRBAC,
			Severity: types.SeverityMedium,
			Status:   types.StatusWarn,
			Summary:  fmt.Sprintf("Role %q got unexpected status on denied path %s.", role.Name, path),
			Evidence: fmt.Sprintf("status=%d", resp.StatusCode),
			Metadata: map[string]string{"role": role.Name, "path": path, "expectation": "deny"},
		})
	}

	return out
}

func join(base, path string) string {
	if path == "" {
		return base
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

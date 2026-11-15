// Package rbac implements authorization / RBAC verification checks.
package rbac

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/Romstar/auth-chaser/internal/checks"
	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/httpclient"
	"github.com/Romstar/auth-chaser/pkg/types"
	"gopkg.in/yaml.v3"
)

const maxBody = 64 * 1024

// RoleAccess verifies that roles can reach allowed paths and are denied denied paths.
type RoleAccess struct{}

func (RoleAccess) ID() string               { return "rbac.role_access" }
func (RoleAccess) Title() string            { return "Role-based path access" }
func (RoleAccess) Category() types.Category { return types.CategoryRBAC }
func (RoleAccess) Pack() string             { return config.PackRBACMatrix }

func (RoleAccess) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	roles := cctx.Cfg.RBAC.Roles
	if len(roles) == 0 {
		return []types.Finding{checks.Skip("rbac.role_access", "Role-based path access", config.PackRBACMatrix, types.CategoryRBAC, types.SkipMissingConfig, "Add rbac.roles entries")}, nil
	}
	findings := make([]types.Finding, 0)
	for _, role := range roles {
		findings = append(findings, probeRole(ctx, cctx, role)...)
	}
	return findings, nil
}

// AnonymousBaseline ensures protected paths reject unauthenticated access.
type AnonymousBaseline struct{}

func (AnonymousBaseline) ID() string               { return "rbac.anonymous_baseline" }
func (AnonymousBaseline) Title() string            { return "Anonymous access blocked on protected paths" }
func (AnonymousBaseline) Category() types.Category { return types.CategoryRBAC }
func (AnonymousBaseline) Pack() string             { return config.PackRBACMatrix }

func (AnonymousBaseline) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	paths := append([]string{}, cctx.Cfg.RBAC.ProtectedPaths...)
	for _, role := range cctx.Cfg.RBAC.Roles {
		paths = append(paths, role.DeniedPaths...)
		paths = append(paths, role.AllowedPaths...)
	}
	paths = unique(paths)
	if len(paths) == 0 {
		return []types.Finding{checks.Skip("rbac.anonymous_baseline", "Anonymous access blocked on protected paths", config.PackRBACMatrix, types.CategoryRBAC, types.SkipMissingConfig, "Set rbac.protected_paths or role paths")}, nil
	}
	findings := make([]types.Finding, 0, len(paths))
	for _, path := range paths {
		f := types.Finding{
			CheckID:  "rbac.anonymous_baseline",
			Title:    "Anonymous access blocked on protected paths",
			Category: types.CategoryRBAC,
			Pack:     config.PackRBACMatrix,
			Protocol: "rbac",
			CWE:      "CWE-862",
			Severity: types.SeverityHigh,
			Metadata: map[string]string{"path": path, "expectation": "deny_anonymous"},
		}
		u := config.JoinURL(cctx.Cfg.Target.BaseURL, path)
		resp, err := cctx.Client.Get(ctx, u, nil)
		if err != nil {
			f.Status = types.StatusError
			f.Evidence = err.Error()
			f.Summary = "Anonymous probe failed."
			findings = append(findings, f)
			continue
		}
		_, _ = httpclient.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close()
		f.Evidence = fmt.Sprintf("status=%d", resp.StatusCode)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			f.Status = types.StatusPass
			f.Severity = types.SeverityInfo
			f.Summary = fmt.Sprintf("Anonymous caller correctly denied on %s.", path)
		} else if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			f.Status = types.StatusFail
			f.Severity = types.SeverityCritical
			f.Summary = fmt.Sprintf("Anonymous caller accessed protected path %s.", path)
			f.Remediation = "Require authentication on this path."
		} else {
			f.Status = types.StatusWarn
			f.Severity = types.SeverityMedium
			f.Summary = fmt.Sprintf("Unexpected anonymous status on %s.", path)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ObjectAccess checks horizontal access between identities.
type ObjectAccess struct{}

func (ObjectAccess) ID() string               { return "rbac.object_access" }
func (ObjectAccess) Title() string            { return "Horizontal object access controls" }
func (ObjectAccess) Category() types.Category { return types.CategoryRBAC }
func (ObjectAccess) Pack() string             { return config.PackRBACMatrix }

func (ObjectAccess) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	tests := cctx.Cfg.RBAC.ObjectTests
	if len(tests) == 0 {
		return []types.Finding{checks.Skip("rbac.object_access", "Horizontal object access controls", config.PackRBACMatrix, types.CategoryRBAC, types.SkipMissingConfig, "Add rbac.object_tests")}, nil
	}
	roleToken := map[string]string{}
	for _, r := range cctx.Cfg.RBAC.Roles {
		roleToken[r.Name] = r.BearerToken
	}
	findings := make([]types.Finding, 0, len(tests))
	for _, t := range tests {
		f := types.Finding{
			CheckID:  "rbac.object_access",
			Title:    "Horizontal object access controls",
			Category: types.CategoryRBAC,
			Pack:     config.PackRBACMatrix,
			Protocol: "rbac",
			CWE:      "CWE-639",
			Severity: types.SeverityHigh,
			Metadata: map[string]string{"name": t.Name, "actor": t.ActorRole, "path": t.Path},
		}
		token := roleToken[t.ActorRole]
		if token == "" {
			f.Status = types.StatusSkip
			f.Severity = types.SeverityInfo
			f.Summary = fmt.Sprintf("No bearer token for actor role %q.", t.ActorRole)
			f.Metadata["skip_reason"] = types.SkipMissingSecret
			findings = append(findings, f)
			continue
		}
		u := config.JoinURL(cctx.Cfg.Target.BaseURL, t.Path)
		resp, err := cctx.Client.Get(ctx, u, map[string]string{"Authorization": "Bearer " + token})
		if err != nil {
			f.Status = types.StatusError
			f.Evidence = err.Error()
			f.Summary = "Object access probe failed."
			findings = append(findings, f)
			continue
		}
		_, _ = httpclient.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close()
		denied := resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
		allowed := resp.StatusCode >= 200 && resp.StatusCode < 400
		f.Evidence = fmt.Sprintf("status=%d expect_deny=%v", resp.StatusCode, t.ExpectDeny)
		if t.ExpectDeny {
			if denied {
				f.Status = types.StatusPass
				f.Severity = types.SeverityInfo
				f.Summary = fmt.Sprintf("Actor %s correctly denied object path %s.", t.ActorRole, t.Path)
			} else if allowed {
				f.Status = types.StatusFail
				f.Severity = types.SeverityCritical
				f.Summary = fmt.Sprintf("Actor %s accessed object owned by another identity.", t.ActorRole)
				f.Remediation = "Enforce object-level authorization (prevent IDOR)."
			} else {
				f.Status = types.StatusWarn
				f.Summary = "Unexpected status for deny expectation."
			}
		} else {
			if allowed {
				f.Status = types.StatusPass
				f.Severity = types.SeverityInfo
				f.Summary = fmt.Sprintf("Actor %s can access permitted object path.", t.ActorRole)
			} else {
				f.Status = types.StatusFail
				f.Severity = types.SeverityHigh
				f.Summary = fmt.Sprintf("Actor %s denied object path that should be allowed.", t.ActorRole)
			}
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// MatrixFile loads optional CSV/YAML matrix of role,path,expect.
type MatrixFile struct{}

func (MatrixFile) ID() string               { return "rbac.matrix_file" }
func (MatrixFile) Title() string            { return "RBAC matrix file evaluation" }
func (MatrixFile) Category() types.Category { return types.CategoryRBAC }
func (MatrixFile) Pack() string             { return config.PackRBACMatrix }

func (MatrixFile) Run(ctx context.Context, cctx checks.Context) ([]types.Finding, error) {
	path := cctx.Cfg.RBAC.MatrixFile
	if path == "" {
		return []types.Finding{checks.Skip("rbac.matrix_file", "RBAC matrix file evaluation", config.PackRBACMatrix, types.CategoryRBAC, types.SkipMissingConfig, "Set rbac.matrix_file")}, nil
	}
	cells, err := loadMatrix(path)
	if err != nil {
		return []types.Finding{{
			CheckID:  "rbac.matrix_file",
			Title:    "RBAC matrix file evaluation",
			Category: types.CategoryRBAC,
			Pack:     config.PackRBACMatrix,
			Status:   types.StatusError,
			Severity: types.SeverityMedium,
			Summary:  "Failed to load matrix file.",
			Evidence: err.Error(),
		}}, nil
	}
	roleToken := map[string]string{}
	for _, r := range cctx.Cfg.RBAC.Roles {
		roleToken[r.Name] = r.BearerToken
	}
	findings := make([]types.Finding, 0, len(cells))
	for _, cell := range cells {
		f := types.Finding{
			CheckID:  "rbac.matrix_file",
			Title:    "RBAC matrix file evaluation",
			Category: types.CategoryRBAC,
			Pack:     config.PackRBACMatrix,
			Protocol: "rbac",
			CWE:      "CWE-862",
			Severity: types.SeverityHigh,
			Metadata: map[string]string{"role": cell.Role, "path": cell.Path, "expect": cell.Expect},
		}
		headers := map[string]string{}
		if tok := roleToken[cell.Role]; tok != "" {
			headers["Authorization"] = "Bearer " + tok
		}
		u := config.JoinURL(cctx.Cfg.Target.BaseURL, cell.Path)
		resp, err := cctx.Client.Get(ctx, u, headers)
		if err != nil {
			f.Status = types.StatusError
			f.Evidence = err.Error()
			f.Summary = "Matrix cell probe failed."
			findings = append(findings, f)
			continue
		}
		_, _ = httpclient.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close()
		denied := resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
		allowed := resp.StatusCode >= 200 && resp.StatusCode < 400
		f.Evidence = fmt.Sprintf("status=%d", resp.StatusCode)
		expectDeny := strings.EqualFold(cell.Expect, "deny")
		if expectDeny && denied || !expectDeny && allowed {
			f.Status = types.StatusPass
			f.Severity = types.SeverityInfo
			f.Summary = fmt.Sprintf("Matrix cell role=%s path=%s expect=%s passed.", cell.Role, cell.Path, cell.Expect)
		} else if expectDeny && allowed {
			f.Status = types.StatusFail
			f.Severity = types.SeverityCritical
			f.Summary = fmt.Sprintf("Matrix cell role=%s path=%s should be denied.", cell.Role, cell.Path)
			f.Remediation = "Enforce RBAC for this role/path pair."
		} else {
			f.Status = types.StatusFail
			f.Severity = types.SeverityHigh
			f.Summary = fmt.Sprintf("Matrix cell role=%s path=%s expectation %s not met.", cell.Role, cell.Path, cell.Expect)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

type matrixCell struct {
	Role   string `yaml:"role"`
	Path   string `yaml:"path"`
	Expect string `yaml:"expect"`
}

func loadMatrix(path string) ([]matrixCell, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(strings.ToLower(path), ".yaml") || strings.HasSuffix(strings.ToLower(path), ".yml") {
		var doc struct {
			Cells []matrixCell `yaml:"cells"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, err
		}
		return doc.Cells, nil
	}
	r := csv.NewReader(strings.NewReader(string(data)))
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	out := make([]matrixCell, 0)
	for i, row := range rows {
		if i == 0 && len(row) >= 3 && strings.EqualFold(row[0], "role") {
			continue
		}
		if len(row) < 3 {
			continue
		}
		out = append(out, matrixCell{Role: row[0], Path: row[1], Expect: row[2]})
	}
	return out, nil
}

func probeRole(ctx context.Context, cctx checks.Context, role config.RoleSpec) []types.Finding {
	out := make([]types.Finding, 0)
	headers := map[string]string{}
	if role.BearerToken != "" {
		headers["Authorization"] = "Bearer " + role.BearerToken
	}
	for _, path := range role.AllowedPaths {
		out = append(out, probeOne(ctx, cctx, role.Name, path, headers, true)...)
	}
	for _, path := range role.DeniedPaths {
		out = append(out, probeOne(ctx, cctx, role.Name, path, headers, false)...)
	}
	return out
}

func probeOne(ctx context.Context, cctx checks.Context, role, path string, headers map[string]string, expectAllow bool) []types.Finding {
	f := types.Finding{
		CheckID:  "rbac.role_access",
		Title:    "Role-based path access",
		Category: types.CategoryRBAC,
		Pack:     config.PackRBACMatrix,
		Protocol: "rbac",
		CWE:      "CWE-862",
		Severity: types.SeverityHigh,
		Metadata: map[string]string{"role": role, "path": path},
	}
	if expectAllow {
		f.Metadata["expectation"] = "allow"
	} else {
		f.Metadata["expectation"] = "deny"
	}
	u := config.JoinURL(cctx.Cfg.Target.BaseURL, path)
	resp, err := cctx.Client.Get(ctx, u, headers)
	if err != nil {
		f.Status = types.StatusError
		f.Severity = types.SeverityMedium
		f.Summary = fmt.Sprintf("Role %q could not request path %s.", role, path)
		f.Evidence = err.Error()
		return []types.Finding{f}
	}
	_, _ = httpclient.ReadLimited(resp.Body, maxBody)
	_ = resp.Body.Close()
	f.Evidence = fmt.Sprintf("status=%d", resp.StatusCode)
	denied := resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
	allowed := resp.StatusCode >= 200 && resp.StatusCode < 400
	if expectAllow {
		if allowed {
			f.Status = types.StatusPass
			f.Severity = types.SeverityInfo
			f.Summary = fmt.Sprintf("Role %q can access allowed path %s.", role, path)
		} else if denied {
			f.Status = types.StatusFail
			f.Summary = fmt.Sprintf("Role %q was denied path %s that should be allowed.", role, path)
			f.Remediation = "Verify RBAC grants for this role."
		} else {
			f.Status = types.StatusWarn
			f.Severity = types.SeverityMedium
			f.Summary = fmt.Sprintf("Role %q got unexpected status on allowed path %s.", role, path)
		}
	} else {
		if denied {
			f.Status = types.StatusPass
			f.Severity = types.SeverityInfo
			f.Summary = fmt.Sprintf("Role %q is correctly denied path %s.", role, path)
		} else if allowed {
			f.Status = types.StatusFail
			f.Severity = types.SeverityCritical
			f.Summary = fmt.Sprintf("Role %q accessed path %s that should be denied.", role, path)
			f.Remediation = "Enforce authorization on this path for the given role."
		} else {
			f.Status = types.StatusWarn
			f.Severity = types.SeverityMedium
			f.Summary = fmt.Sprintf("Role %q got unexpected status on denied path %s.", role, path)
		}
	}
	return []types.Finding{f}
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

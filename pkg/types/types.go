// Package types holds shared public types for auth-chaser checks and reports.
package types

import "time"

// Severity ranks a finding for triage.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Category groups related checks.
type Category string

const (
	CategoryAuth      Category = "auth"
	CategoryMisconfig Category = "misconfig"
	CategoryRBAC      Category = "rbac"
)

// Status is the outcome of a single check.
type Status string

const (
	StatusPass Status = "pass"
	StatusFail Status = "fail"
	StatusWarn Status = "warn"
	StatusSkip Status = "skip"
	StatusError Status = "error"
)

// Finding is one result from one check.
type Finding struct {
	CheckID     string            `json:"check_id"`
	Title       string            `json:"title"`
	Category    Category          `json:"category"`
	Severity    Severity          `json:"severity"`
	Status      Status            `json:"status"`
	Summary     string            `json:"summary"`
	Evidence    string            `json:"evidence,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Report is the full output of a chase run.
type Report struct {
	Target      string    `json:"target"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	DurationMS  int64     `json:"duration_ms"`
	Authorized  bool      `json:"authorized"`
	Findings    []Finding `json:"findings"`
	PassCount   int       `json:"pass_count"`
	FailCount   int       `json:"fail_count"`
	WarnCount   int       `json:"warn_count"`
	SkipCount   int       `json:"skip_count"`
	ErrorCount  int       `json:"error_count"`
	ToolVersion string    `json:"tool_version"`
}

// Summarize updates aggregate counters from findings.
func (r *Report) Summarize() {
	r.PassCount, r.FailCount, r.WarnCount, r.SkipCount, r.ErrorCount = 0, 0, 0, 0, 0
	for _, f := range r.Findings {
		switch f.Status {
		case StatusPass:
			r.PassCount++
		case StatusFail:
			r.FailCount++
		case StatusWarn:
			r.WarnCount++
		case StatusSkip:
			r.SkipCount++
		case StatusError:
			r.ErrorCount++
		}
	}
}

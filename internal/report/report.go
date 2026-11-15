// Package report formats chase reports for humans and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Romstar/auth-chaser/pkg/types"
)

// WriteJSON writes the report as indented JSON.
func WriteJSON(w io.Writer, r *types.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes a concise human-readable summary.
func WriteText(w io.Writer, r *types.Report) error {
	var b strings.Builder
	b.WriteString("auth-chaser report\n")
	b.WriteString(strings.Repeat("=", 48) + "\n")
	fmt.Fprintf(&b, "Target:      %s\n", r.Target)
	fmt.Fprintf(&b, "Started:     %s\n", r.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "Duration:    %dms\n", r.DurationMS)
	fmt.Fprintf(&b, "Authorized:  %v\n", r.Authorized)
	fmt.Fprintf(&b, "Version:     %s\n", r.ToolVersion)
	if len(r.Packs) > 0 {
		fmt.Fprintf(&b, "Packs:       %s\n", strings.Join(r.Packs, ", "))
	}
	fmt.Fprintf(&b, "Summary:     pass=%d fail=%d warn=%d skip=%d error=%d\n",
		r.PassCount, r.FailCount, r.WarnCount, r.SkipCount, r.ErrorCount)
	b.WriteString(strings.Repeat("-", 48) + "\n")

	for _, f := range r.Findings {
		fmt.Fprintf(&b, "[%s] %-7s %-10s %s\n",
			strings.ToUpper(string(f.Status)),
			f.Severity,
			f.Category,
			f.Title,
		)
		if f.Pack != "" {
			fmt.Fprintf(&b, "  pack: %s", f.Pack)
			if f.CWE != "" {
				fmt.Fprintf(&b, "  cwe: %s", f.CWE)
			}
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "  %s\n", f.Summary)
		if f.Evidence != "" {
			fmt.Fprintf(&b, "  evidence: %s\n", f.Evidence)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "  fix: %s\n", f.Remediation)
		}
		b.WriteString("\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// WriteSARIF writes a SARIF 2.1.0 document for CI systems.
func WriteSARIF(w io.Writer, r *types.Report) error {
	type rule struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		ShortDescription struct {
			Text string `json:"text"`
		} `json:"shortDescription"`
		HelpURI string `json:"helpUri,omitempty"`
		Properties map[string]string `json:"properties,omitempty"`
	}
	type message struct {
		Text string `json:"text"`
	}
	type result struct {
		RuleID     string            `json:"ruleId"`
		Level      string            `json:"level"`
		Message    message           `json:"message"`
		Properties map[string]string `json:"properties,omitempty"`
	}
	type driver struct {
		Name            string `json:"name"`
		InformationURI  string `json:"informationUri"`
		Version         string `json:"version"`
		Rules           []rule `json:"rules"`
	}
	type tool struct {
		Driver driver `json:"driver"`
	}
	type run struct {
		Tool    tool     `json:"tool"`
		Results []result `json:"results"`
	}
	type sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}

	rulesByID := map[string]rule{}
	results := make([]result, 0, len(r.Findings))
	for _, f := range r.Findings {
		if _, ok := rulesByID[f.CheckID]; !ok {
			rl := rule{ID: f.CheckID, Name: f.Title}
			rl.ShortDescription.Text = f.Title
			if f.CWE != "" {
				rl.Properties = map[string]string{"cwe": f.CWE, "pack": f.Pack}
			} else if f.Pack != "" {
				rl.Properties = map[string]string{"pack": f.Pack}
			}
			rulesByID[f.CheckID] = rl
		}
		level := "note"
		switch f.Status {
		case types.StatusFail:
			switch f.Severity {
			case types.SeverityCritical, types.SeverityHigh:
				level = "error"
			default:
				level = "warning"
			}
		case types.StatusWarn:
			level = "warning"
		case types.StatusError:
			level = "error"
		case types.StatusPass, types.StatusSkip:
			level = "note"
		}
		text := f.Summary
		if f.Evidence != "" {
			text += " | evidence: " + f.Evidence
		}
		if f.Remediation != "" {
			text += " | fix: " + f.Remediation
		}
		results = append(results, result{
			RuleID:  f.CheckID,
			Level:   level,
			Message: message{Text: text},
			Properties: map[string]string{
				"status":   string(f.Status),
				"severity": string(f.Severity),
				"category": string(f.Category),
				"target":   r.Target,
			},
		})
	}
	rules := make([]rule, 0, len(rulesByID))
	for _, rl := range rulesByID {
		rules = append(rules, rl)
	}

	doc := sarif{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "auth-chaser",
				InformationURI: "https://github.com/Romstar/auth-chaser",
				Version:        r.ToolVersion,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

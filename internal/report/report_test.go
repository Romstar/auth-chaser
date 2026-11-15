package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Romstar/auth-chaser/pkg/types"
)

func TestWriteSARIF(t *testing.T) {
	rep := &types.Report{
		Target:      "https://example.com",
		StartedAt:   time.Now(),
		FinishedAt:  time.Now(),
		ToolVersion: "0.2.0",
		Findings: []types.Finding{{
			CheckID:  "auth.https_required",
			Title:    "HTTPS",
			Category: types.CategoryAuth,
			Severity: types.SeverityInfo,
			Status:   types.StatusPass,
			Summary:  "ok",
			Pack:     "auth.core",
			CWE:      "CWE-319",
		}},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("sarif version %v", doc["version"])
	}
}

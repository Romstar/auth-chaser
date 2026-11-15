package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Romstar/auth-chaser/pkg/types"
)

func sampleReport() *types.Report {
	rep := &types.Report{
		Target:      "https://example.com",
		StartedAt:   time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC),
		FinishedAt:  time.Date(2026, 11, 15, 12, 0, 1, 0, time.UTC),
		DurationMS:  1000,
		Authorized:  true,
		ToolVersion: "0.2.0",
		Packs:       []string{"auth.core", "misconfig.auth"},
		Findings: []types.Finding{
			{
				CheckID:     "auth.https_required",
				Title:       "HTTPS required",
				Category:    types.CategoryAuth,
				Severity:    types.SeverityInfo,
				Status:      types.StatusPass,
				Summary:     "Target uses HTTPS.",
				Pack:        "auth.core",
				CWE:         "CWE-319",
			},
			{
				CheckID:     "misconfig.security_headers",
				Title:       "Auth-relevant security headers",
				Category:    types.CategoryMisconfig,
				Severity:    types.SeverityHigh,
				Status:      types.StatusFail,
				Summary:     "Missing HSTS on authentication surface.",
				Evidence:    "strict-transport-security absent",
				Remediation: "Add HSTS and CSP on auth surfaces.",
				Pack:        "misconfig.auth",
				CWE:         "CWE-693",
			},
			{
				CheckID:  "misconfig.cors",
				Title:    "CORS on credentialed endpoints",
				Category: types.CategoryMisconfig,
				Severity: types.SeverityMedium,
				Status:   types.StatusWarn,
				Summary:  "Broad CORS ACAO observed.",
				Pack:     "misconfig.auth",
			},
		},
	}
	rep.Summarize()
	return rep
}

func TestWriteSARIF(t *testing.T) {
	rep := sampleReport()
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

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 { // header + 3 findings
		t.Fatalf("rows=%d want 4", len(records))
	}
	if records[0][0] != "target" {
		t.Fatalf("header %v", records[0][0])
	}
	if records[2][11] != "fail" {
		t.Fatalf("status col = %q", records[2][11])
	}
}

func TestWriteHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"<!DOCTYPE html>",
		"auth-chaser",
		"https://example.com",
		"Priority findings",
		"data:image/png;base64,",
		"Missing HSTS",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("html missing %q", want)
		}
	}
}

func TestWritePDF(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePDF(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() < 500 {
		t.Fatalf("pdf too small: %d bytes", buf.Len())
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF")) {
		t.Fatalf("missing PDF header: %q", buf.Bytes()[:8])
	}
}

func TestWriteDispatcher(t *testing.T) {
	rep := sampleReport()
	for _, format := range []string{"text", "json", "sarif", "html", "pdf", "csv"} {
		var buf bytes.Buffer
		if err := Write(&buf, format, rep); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if buf.Len() == 0 {
			t.Fatalf("%s: empty output", format)
		}
	}
	if _, err := NormalizeFormat("xml"); err == nil {
		t.Fatal("expected error for xml")
	}
}

func TestBuildNarrative(t *testing.T) {
	n := BuildNarrative(sampleReport())
	if n.Headline == "" || n.Body == "" || n.Risk == "" {
		t.Fatalf("incomplete narrative: %+v", n)
	}
	if !strings.Contains(n.Body, "https://example.com") {
		t.Fatalf("body missing target: %s", n.Body)
	}
}

func TestChartsPNG(t *testing.T) {
	brand, err := RenderBrandMarkPNG(96)
	if err != nil || len(brand) < 50 {
		t.Fatalf("brand: %v len=%d", err, len(brand))
	}
	donut, err := RenderDonutPNG(StatusSlices(sampleReport()), 120)
	if err != nil || len(donut) < 50 {
		t.Fatalf("donut: %v len=%d", err, len(donut))
	}
	bars, err := RenderBarsPNG(SeveritySlices(sampleReport()), 200, 100)
	if err != nil || len(bars) < 50 {
		t.Fatalf("bars: %v len=%d", err, len(bars))
	}
}

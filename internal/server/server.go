// Package server provides the self-hostable SaaS HTTP API and UI.
package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Romstar/auth-chaser/internal/checks/packs"
	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/report"
	"github.com/Romstar/auth-chaser/internal/runner"
	"github.com/Romstar/auth-chaser/internal/store"
	"github.com/google/uuid"
)

// Options configures the HTTP server.
type Options struct {
	Addr     string
	DataDir  string
	APIToken string
}

// Server is the self-hostable auth-chaser control plane.
type Server struct {
	opts  Options
	mux   *http.ServeMux
	store *store.Store
}

// New creates an HTTP server.
func New(opts Options) *Server {
	if opts.Addr == "" {
		opts.Addr = ":8080"
	}
	if opts.DataDir == "" {
		opts.DataDir = ".auth-chaser-data"
	}
	if opts.APIToken == "" {
		opts.APIToken = os.Getenv("AUTH_CHASER_API_TOKEN")
	}
	st, err := store.Open(opts.DataDir)
	if err != nil {
		log.Printf("warning: job store unavailable (%v); using memory-less degraded mode", err)
	}
	s := &Server{opts: opts, mux: http.NewServeMux(), store: st}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/version", s.handleVersion)
	s.mux.HandleFunc("GET /api/v1/packs", s.auth(s.handlePacks))
	s.mux.HandleFunc("POST /api/v1/chase", s.auth(s.handleChase))
	s.mux.HandleFunc("GET /api/v1/jobs", s.auth(s.handleJobs))
	s.mux.HandleFunc("GET /api/v1/jobs/{id}", s.auth(s.handleJob))
	s.mux.HandleFunc("GET /api/v1/jobs/{id}/sarif", s.auth(s.handleJobSARIF))
	s.mux.HandleFunc("GET /api/v1/jobs/{id}/report", s.auth(s.handleJobReport))
	s.mux.HandleFunc("GET /api/v1/reports", s.auth(s.handleReports))
	s.mux.HandleFunc("GET /", s.handleUI)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.opts.APIToken == "" {
			next(w, r)
			return
		}
		h := r.Header.Get("Authorization")
		if h == "Bearer "+s.opts.APIToken || r.Header.Get("X-API-Token") == s.opts.APIToken {
			next(w, r)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	log.Printf("auth-chaser serve listening on %s (data=%s)", s.opts.Addr, s.opts.DataDir)
	srv := &http.Server{
		Addr:              s.opts.Addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": runner.Version})
}

func (s *Server) handlePacks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, packs.List())
}

type chaseRequest struct {
	Config config.Config `json:"config"`
	Async  bool          `json:"async"`
}

func (s *Server) handleChase(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unable to read body"})
		return
	}
	var req chaseRequest
	req.Config = config.Default()
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}
	req.Config.InterpolateSecrets()
	req.Config.Normalize()
	req.Config.Safety.Destructive = false

	if !req.Config.Safety.ConfirmAuthorized {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "safety.confirm_authorized must be true. Only test applications you own or have written permission to test.",
		})
		return
	}

	if req.Async && s.store != nil {
		id := uuid.NewString()
		job, err := s.store.CreateJob(id, req.Config.Target.BaseURL)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		go s.runJob(id, req.Config)
		w.Header().Set("Location", "/api/v1/jobs/"+id)
		writeJSON(w, http.StatusAccepted, job)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	rep, err := runner.New(req.Config).Run(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if s.store != nil {
		id := uuid.NewString()
		_, _ = s.store.CreateJob(id, req.Config.Target.BaseURL)
		_ = s.store.UpdateJob(id, store.JobSucceeded, "", rep)
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) runJob(id string, cfg config.Config) {
	_ = s.store.UpdateJob(id, store.JobRunning, "", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rep, err := runner.New(cfg).Run(ctx)
	if err != nil {
		_ = s.store.UpdateJob(id, store.JobFailed, err.Error(), nil)
		return
	}
	_ = s.store.UpdateJob(id, store.JobSucceeded, "", rep)
}

func (s *Server) handleJobs(w http.ResponseWriter, _ *http.Request) {
	if s.store == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	jobs, err := s.store.ListJobs(50)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, jobs)
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "store unavailable"})
		return
	}
	id := r.PathValue("id")
	job, err := s.store.GetJob(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleJobSARIF(w http.ResponseWriter, r *http.Request) {
	s.writeJobReport(w, r.PathValue("id"), report.FormatSARIF)
}

func (s *Server) handleJobReport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = report.FormatHTML
	}
	normalized, err := report.NormalizeFormat(format)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.writeJobReport(w, r.PathValue("id"), normalized)
}

func (s *Server) writeJobReport(w http.ResponseWriter, id, format string) {
	if s.store == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "store unavailable"})
		return
	}
	job, err := s.store.GetJob(id)
	if err != nil || job.Report == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "report not found"})
		return
	}
	w.Header().Set("Content-Type", report.ContentType(format))
	filename := "auth-chaser-" + id + report.FileExtension(format)
	switch format {
	case report.FormatPDF, report.FormatCSV:
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	case report.FormatHTML:
		w.Header().Set("Content-Disposition", "inline; filename=\""+filename+"\"")
	}
	if err := report.Write(w, format, job.Report); err != nil {
		log.Printf("report write failed for job %s (%s): %v", id, format, err)
	}
}

func (s *Server) handleReports(w http.ResponseWriter, _ *http.Request) {
	if s.store == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	jobs, err := s.store.ListJobs(20)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	reps := make([]*runnerReport, 0)
	for _, j := range jobs {
		if j.Report != nil {
			reps = append(reps, &runnerReport{JobID: j.ID, Report: j.Report})
		}
	}
	writeJSON(w, http.StatusOK, reps)
}

type runnerReport struct {
	JobID  string        `json:"job_id"`
	Report interface{}   `json:"report"`
}

func (s *Server) handleUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(uiHTML))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

const uiHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>auth-chaser</title>
  <style>
    :root {
      --bg: #0f1419; --panel: #1a222c; --text: #e7eef7; --muted: #9aa8b8;
      --accent: #3ecf8e; --danger: #ff6b6b; --border: #2a3542;
      --font: "IBM Plex Sans", "Segoe UI", sans-serif;
      --mono: "IBM Plex Mono", ui-monospace, monospace;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; color: var(--text); font-family: var(--font);
      background:
        radial-gradient(1200px 600px at 10% -10%, #1d3a2f 0%, transparent 55%),
        radial-gradient(900px 500px at 100% 0%, #243044 0%, transparent 50%),
        var(--bg);
    }
    main { max-width: 920px; margin: 0 auto; padding: 3rem 1.25rem 4rem; }
    h1 { font-size: clamp(2rem, 5vw, 3rem); letter-spacing: -0.03em; margin: 0 0 0.35rem; }
    .tag { color: var(--accent); font-family: var(--mono); font-size: 0.85rem; }
    p.lead { color: var(--muted); max-width: 42rem; line-height: 1.5; }
    form, .card {
      margin-top: 1.5rem; padding: 1.25rem; background: color-mix(in srgb, var(--panel) 92%, transparent);
      border: 1px solid var(--border); border-radius: 12px;
    }
    label { display: block; font-size: 0.85rem; color: var(--muted); margin: 0.85rem 0 0.35rem; }
    input[type=text], select {
      width: 100%; padding: 0.7rem 0.8rem; border-radius: 8px; border: 1px solid var(--border);
      background: #121820; color: var(--text); font-family: var(--mono);
    }
    .row { display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; margin-top: 1rem; }
    .row label { margin: 0; color: var(--text); display: flex; gap: 0.45rem; align-items: center; }
    button {
      margin-top: 1.25rem; background: var(--accent); color: #062416; border: 0; border-radius: 8px;
      padding: 0.75rem 1.1rem; font-weight: 650; cursor: pointer;
    }
    button:disabled { opacity: 0.6; cursor: wait; }
    .warn { margin-top: 0.75rem; color: #ffd28a; font-size: 0.9rem; }
    pre {
      margin-top: 1.5rem; padding: 1rem; overflow: auto; background: #0c1015;
      border: 1px solid var(--border); border-radius: 10px; font-family: var(--mono); font-size: 0.8rem;
      max-height: 420px;
    }
    .err { color: var(--danger); }
  </style>
</head>
<body>
  <main>
    <div class="tag">self-hosted · defensive · non-destructive</div>
    <h1>auth-chaser</h1>
    <p class="lead">
      Verify authentication and authorization on applications you own or are authorized to test.
      Checks are rate-limited, scoped, and non-destructive.
    </p>
    <form id="chase-form">
      <label for="target">Target base URL</label>
      <input id="target" type="text" placeholder="https://app.example.com" required />
      <label for="packs">Packs (comma-separated)</label>
      <input id="packs" type="text" value="auth.core,misconfig.auth" />
      <div class="row">
        <label><input type="checkbox" id="async" checked /> Async job</label>
        <label><input type="checkbox" id="browser" /> Browser automation</label>
      </div>
      <label class="row" style="margin-top:1rem">
        <input type="checkbox" id="confirm" required />
        I own this target or have written authorization to test it.
      </label>
      <p class="warn">Unauthorized testing of third-party systems is prohibited.</p>
      <button type="submit" id="run">Run chase</button>
    </form>
    <div class="card">
      <strong>Recent jobs</strong>
      <p style="color:var(--muted);font-size:0.9rem;margin:0.4rem 0 0.8rem">
        Download a designed report: <code>/api/v1/jobs/{id}/report?format=html|pdf|csv</code>
      </p>
      <pre id="jobs">Loading…</pre>
    </div>
    <pre id="out">Submit a chase to see results.</pre>
  </main>
  <script>
    const out = document.getElementById('out');
    const jobsEl = document.getElementById('jobs');
    async function refreshJobs() {
      try {
        const res = await fetch('/api/v1/jobs');
        const data = await res.json();
        jobsEl.textContent = JSON.stringify(data, null, 2);
      } catch (e) {
        jobsEl.textContent = String(e);
      }
    }
    refreshJobs();
    setInterval(refreshJobs, 5000);
    document.getElementById('chase-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('run');
      btn.disabled = true;
      out.textContent = 'Running…';
      out.classList.remove('err');
      const packs = document.getElementById('packs').value.split(',').map(s => s.trim()).filter(Boolean);
      const body = {
        async: document.getElementById('async').checked,
        config: {
          target: { base_url: document.getElementById('target').value.trim() },
          safety: { confirm_authorized: document.getElementById('confirm').checked, max_requests: 80, requests_per_second: 2, allow_browser: document.getElementById('browser').checked },
          browser: { enabled: document.getElementById('browser').checked, headless: true },
          checks: { packs }
        }
      };
      try {
        const res = await fetch('/api/v1/chase', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || res.statusText);
        out.textContent = JSON.stringify(data, null, 2);
        refreshJobs();
      } catch (err) {
        out.classList.add('err');
        out.textContent = String(err.message || err);
      } finally {
        btn.disabled = false;
      }
    });
  </script>
</body>
</html>
`

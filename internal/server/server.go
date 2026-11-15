// Package server provides the self-hostable SaaS HTTP API and UI.
package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/runner"
	"github.com/Romstar/auth-chaser/pkg/types"
)

// Server is the self-hostable auth-chaser control plane.
type Server struct {
	addr   string
	mux    *http.ServeMux
	mu     sync.Mutex
	recent []*types.Report
}

// New creates an HTTP server.
func New(addr string) *Server {
	s := &Server{
		addr:   addr,
		mux:    http.NewServeMux(),
		recent: make([]*types.Report, 0),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/version", s.handleVersion)
	s.mux.HandleFunc("POST /api/v1/chase", s.handleChase)
	s.mux.HandleFunc("GET /api/v1/reports", s.handleReports)
	s.mux.HandleFunc("GET /", s.handleUI)
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	log.Printf("auth-chaser serve listening on %s", s.addr)
	srv := &http.Server{
		Addr:              s.addr,
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

type chaseRequest struct {
	Config config.Config `json:"config"`
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
	req.Config.Safety.Destructive = false

	if !req.Config.Safety.ConfirmAuthorized {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "safety.confirm_authorized must be true. Only test applications you own or have written permission to test.",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	rep, err := runner.New(req.Config).Run(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.mu.Lock()
	s.recent = append([]*types.Report{rep}, s.recent...)
	if len(s.recent) > 20 {
		s.recent = s.recent[:20]
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleReports(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.recent)
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
      --bg: #0f1419;
      --panel: #1a222c;
      --text: #e7eef7;
      --muted: #9aa8b8;
      --accent: #3ecf8e;
      --danger: #ff6b6b;
      --border: #2a3542;
      --font: "IBM Plex Sans", "Segoe UI", sans-serif;
      --mono: "IBM Plex Mono", ui-monospace, monospace;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; color: var(--text);
      font-family: var(--font);
      background:
        radial-gradient(1200px 600px at 10% -10%, #1d3a2f 0%, transparent 55%),
        radial-gradient(900px 500px at 100% 0%, #243044 0%, transparent 50%),
        var(--bg);
    }
    main { max-width: 880px; margin: 0 auto; padding: 3rem 1.25rem 4rem; }
    h1 { font-size: clamp(2rem, 5vw, 3rem); letter-spacing: -0.03em; margin: 0 0 0.35rem; }
    .tag { color: var(--accent); font-family: var(--mono); font-size: 0.85rem; }
    p.lead { color: var(--muted); max-width: 42rem; line-height: 1.5; }
    form {
      margin-top: 2rem; padding: 1.25rem; background: color-mix(in srgb, var(--panel) 92%, transparent);
      border: 1px solid var(--border); border-radius: 12px;
    }
    label { display: block; font-size: 0.85rem; color: var(--muted); margin: 0.85rem 0 0.35rem; }
    input[type=text], input[type=number] {
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
      <div class="row">
        <label><input type="checkbox" id="auth" checked /> Auth checks</label>
        <label><input type="checkbox" id="misconfig" checked /> Misconfig checks</label>
        <label><input type="checkbox" id="rbac" /> RBAC checks</label>
      </div>
      <label class="row" style="margin-top:1rem">
        <input type="checkbox" id="confirm" required />
        I own this target or have written authorization to test it.
      </label>
      <p class="warn">Unauthorized testing of third-party systems is prohibited.</p>
      <button type="submit" id="run">Run chase</button>
    </form>
    <pre id="out">Submit a chase to see results.</pre>
  </main>
  <script>
    const form = document.getElementById('chase-form');
    const out = document.getElementById('out');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('run');
      btn.disabled = true;
      out.textContent = 'Running…';
      out.classList.remove('err');
      const body = {
        config: {
          target: { base_url: document.getElementById('target').value.trim() },
          safety: { confirm_authorized: document.getElementById('confirm').checked, max_requests: 50, requests_per_second: 2 },
          checks: {
            auth: document.getElementById('auth').checked,
            misconfig: document.getElementById('misconfig').checked,
            rbac: document.getElementById('rbac').checked
          }
        }
      };
      try {
        const res = await fetch('/api/v1/chase', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || res.statusText);
        out.textContent = JSON.stringify(data, null, 2);
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

// Package testapp is a tiny fixture HTTP app for integration tests.
package testapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// Server is an in-process fixture application.
type Server struct {
	Server *httptest.Server
	URL    string

	mu       sync.Mutex
	sessions map[string]session
}

type session struct {
	User string
	Role string
}

// Start launches the fixture on a random local port.
func Start() *Server {
	s := &Server{sessions: map[string]session{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/me", s.handleMe)
	mux.HandleFunc("/api/items", s.handleItems)
	mux.HandleFunc("/api/admin", s.handleAdmin)
	mux.HandleFunc("/api/users/", s.handleUserObject)
	mux.HandleFunc("/.well-known/openid-configuration", s.handleOIDC)
	mux.HandleFunc("/oauth/authorize", s.handleAuthorize)
	mux.HandleFunc("/oauth/token", s.handleToken)
	mux.HandleFunc("/oauth/jwks", s.handleJWKS)
	mux.HandleFunc("/mfa", s.handleMFA)
	mux.HandleFunc("/mfa/verify", s.handleMFAVerify)
	mux.HandleFunc("/webauthn/login/options", s.handleWebAuthnOptions)

	ts := httptest.NewServer(mux)
	s.Server = ts
	s.URL = ts.URL
	return s
}

// Close shuts down the fixture.
func (s *Server) Close() { s.Server.Close() }

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Strict-Transport-Security", "max-age=63072000")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, "auth-chaser fixture")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<form method="post"><input name="csrf" value="tok"><input name="username"><input name="password" type="password"><button type="submit">Log in</button></form>`)
	case http.MethodPost:
		_ = r.ParseForm()
		user := r.Form.Get("username")
		pass := r.Form.Get("password")
		if user == "alice" && pass == "password123" {
			id := mintID(user, "viewer")
			s.remember(id, session{User: user, Role: "viewer"})
			http.SetCookie(w, &http.Cookie{Name: "session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, "/me", http.StatusFound)
			return
		}
		if user == "admin" && pass == "password123" {
			id := mintID(user, "admin")
			s.remember(id, session{User: user, Role: "admin"})
			http.SetCookie(w, &http.Cookie{Name: "session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, "/me", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "invalid")
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := s.auth(r)
	if sess == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"user": sess.User, "role": sess.Role})
}

func (s *Server) handleItems(w http.ResponseWriter, r *http.Request) {
	if s.auth(r) == nil && bearerRole(r) == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode([]string{"a", "b"})
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	role := ""
	if sess := s.auth(r); sess != nil {
		role = sess.Role
	}
	if role == "" {
		role = bearerRole(r)
	}
	if role != "admin" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprint(w, "admin-ok")
}

func (s *Server) handleUserObject(w http.ResponseWriter, r *http.Request) {
	role := bearerRole(r)
	if role == "" {
		if sess := s.auth(r); sess != nil {
			role = sess.Role
		}
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if role == "viewer" && id != "alice" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if role == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (s *Server) handleOIDC(w http.ResponseWriter, r *http.Request) {
	base := s.URL
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                 base,
		"authorization_endpoint": base + "/oauth/authorize",
		"token_endpoint":         base + "/oauth/token",
		"jwks_uri":               base + "/oauth/jwks",
		"response_types_supported": []string{"code"},
	})
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("state") == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "state required")
		return
	}
	if q.Get("client_id") == "public" && q.Get("code_challenge") == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "code_challenge required (pkce)")
		return
	}
	redir := q.Get("redirect_uri")
	if redir == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sep := "?"
	if strings.Contains(redir, "?") {
		sep = "&"
	}
	http.Redirect(w, r, redir+sep+"code=fixture-code&state="+q.Get("state"), http.StatusFound)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.Form.Get("code") != "fixture-code" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token": "access",
		"token_type":   "bearer",
		"id_token":     makeIDToken(s.URL),
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]string{{"kty": "oct", "kid": "1", "k": base64.RawURLEncoding.EncodeToString([]byte("secretsecretsecretsecretsecret12"))}},
	})
}

func (s *Server) handleMFA(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<form method="post" action="/mfa/verify"><label>OTP</label><input name="otp"><button>Verify MFA</button></form>`)
}

func (s *Server) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.Form.Get("otp") == "" && r.Form.Get("code") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/me", http.StatusFound)
}

func (s *Server) handleWebAuthnOptions(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"challenge": "abc",
		"rp":        map[string]string{"name": "fixture"},
		"userVerification": "required",
		"authenticatorSelection": map[string]string{"userVerification": "required"},
	})
}

func (s *Server) auth(r *http.Request) *session {
	c, err := r.Cookie("session")
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok {
		return nil
	}
	return &sess
}

func (s *Server) remember(id string, sess session) {
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
}

func mintID(user, role string) string {
	raw := fmt.Sprintf("%s:%s:%d", user, role, time.Now().UnixNano())
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AttachSession stores a session for tests that know the ID.
func (s *Server) AttachSession(id, user, role string) {
	s.remember(id, session{User: user, Role: role})
}

func bearerRole(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	tok := strings.TrimPrefix(h, "Bearer ")
	switch tok {
	case "viewer-token":
		return "viewer"
	case "admin-token":
		return "admin"
	default:
		return ""
	}
}

func makeIDToken(issuer string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iss":%q,"aud":"auth-chaser","exp":%d}`, issuer, time.Now().Add(time.Hour).Unix())))
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte(header + "." + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return header + "." + payload + "." + sig
}

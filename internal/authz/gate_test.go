package authz

import (
	"testing"

	"github.com/Romstar/auth-chaser/internal/config"
)

func TestRequireAuthorized(t *testing.T) {
	cfg := config.Default()
	g := NewGate(cfg)
	if err := g.RequireAuthorized(); err == nil {
		t.Fatal("expected authorization error")
	}
	cfg.Safety.ConfirmAuthorized = true
	g = NewGate(cfg)
	if err := g.RequireAuthorized(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAllowURLScope(t *testing.T) {
	cfg := config.Default()
	cfg.Target.BaseURL = "https://app.example.com"
	cfg.Target.AllowedHosts = []string{"app.example.com"}
	cfg.Target.AllowedPaths = []string{"/api"}
	cfg.Normalize()
	g := NewGate(cfg)

	if err := g.AllowURL("https://app.example.com/api/me"); err != nil {
		t.Fatalf("expected allow: %v", err)
	}
	if err := g.AllowURL("https://evil.example.com/api/me"); err == nil {
		t.Fatal("expected host denial")
	}
	if err := g.AllowURL("https://app.example.com/admin"); err == nil {
		t.Fatal("expected path denial")
	}
}

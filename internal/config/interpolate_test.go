package config

import (
	"os"
	"testing"
)

func TestInterpolateEnv(t *testing.T) {
	t.Setenv("AUTH_CHASER_PASSWORD", "s3cret")
	got := InterpolateEnv("user=${AUTH_CHASER_PASSWORD}")
	if got != "user=s3cret" {
		t.Fatalf("got %q", got)
	}
	_ = os.Unsetenv("MISSING_VAR_XYZ")
	keep := InterpolateEnv("${MISSING_VAR_XYZ}")
	if keep != "${MISSING_VAR_XYZ}" {
		t.Fatalf("expected placeholder kept, got %q", keep)
	}
}

func TestRedactSecrets(t *testing.T) {
	cfg := Default()
	cfg.Auth.Password.Password = "secret"
	red := cfg.RedactSecrets()
	if red.Auth.Password.Password != "[REDACTED]" {
		t.Fatalf("not redacted")
	}
}

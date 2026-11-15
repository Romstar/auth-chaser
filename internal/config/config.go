// Package config loads chase run configuration from YAML or flags.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config describes a single auth-chaser run against one target.
type Config struct {
	Target TargetConfig `yaml:"target" json:"target"`
	Safety SafetyConfig `yaml:"safety" json:"safety"`
	Checks ChecksConfig `yaml:"checks" json:"checks"`
	RBAC   RBACConfig   `yaml:"rbac" json:"rbac"`
}

// TargetConfig identifies the application under test.
type TargetConfig struct {
	BaseURL     string   `yaml:"base_url" json:"base_url"`
	AllowedHosts []string `yaml:"allowed_hosts" json:"allowed_hosts"`
	AllowedPaths []string `yaml:"allowed_paths" json:"allowed_paths"`
}

// SafetyConfig enforces authorization and non-destructive limits.
type SafetyConfig struct {
	// ConfirmAuthorized must be true. The operator asserts ownership or written permission.
	ConfirmAuthorized bool `yaml:"confirm_authorized" json:"confirm_authorized"`
	// MaxRequests caps outbound HTTP requests for one run.
	MaxRequests int `yaml:"max_requests" json:"max_requests"`
	// RequestsPerSecond rate-limits outbound traffic.
	RequestsPerSecond float64 `yaml:"requests_per_second" json:"requests_per_second"`
	// Timeout is the per-request HTTP timeout (Go duration string in YAML, e.g. "10s").
	Timeout Duration `yaml:"timeout" json:"timeout"`
	// Destructive is always forced false. Kept for explicit documentation in config.
	Destructive bool `yaml:"destructive" json:"destructive"`
}

// Duration wraps time.Duration for YAML/JSON strings like "10s".
type Duration time.Duration

// UnmarshalYAML parses Go duration strings.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err == nil && s != "" {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	}
	var n int64
	if err := value.Decode(&n); err != nil {
		return fmt.Errorf("timeout must be a duration string like \"10s\"")
	}
	*d = Duration(time.Duration(n))
	return nil
}

// UnmarshalJSON parses JSON duration strings or nanosecond integers.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("timeout must be a duration string like \"10s\"")
	}
	*d = Duration(n)
	return nil
}

// Duration converts to time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// ChecksConfig selects which check categories to run.
type ChecksConfig struct {
	Auth      bool `yaml:"auth" json:"auth"`
	Misconfig bool `yaml:"misconfig" json:"misconfig"`
	RBAC      bool `yaml:"rbac" json:"rbac"`
}

// RBACConfig supplies roles and expected access for authorization checks.
type RBACConfig struct {
	Roles []RoleSpec `yaml:"roles" json:"roles"`
}

// RoleSpec maps a role to credentials and expected accessible paths.
type RoleSpec struct {
	Name            string   `yaml:"name" json:"name"`
	BearerToken     string   `yaml:"bearer_token" json:"bearer_token"`
	AllowedPaths    []string `yaml:"allowed_paths" json:"allowed_paths"`
	DeniedPaths     []string `yaml:"denied_paths" json:"denied_paths"`
}

// Default returns a safe baseline configuration.
func Default() Config {
	return Config{
		Safety: SafetyConfig{
			ConfirmAuthorized: false,
			MaxRequests:       50,
			RequestsPerSecond: 2,
			Timeout:           Duration(10 * time.Second),
			Destructive:       false,
		},
		Checks: ChecksConfig{
			Auth:      true,
			Misconfig: true,
			RBAC:      false,
		},
	}
}

// Load reads YAML from path and merges with defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	cfg.Normalize()
	return cfg, nil
}

// Normalize fills safe defaults and forces non-destructive mode.
func (c *Config) Normalize() {
	c.normalize()
}

func (c *Config) normalize() {
	c.Target.BaseURL = strings.TrimRight(strings.TrimSpace(c.Target.BaseURL), "/")
	if c.Safety.MaxRequests <= 0 {
		c.Safety.MaxRequests = 50
	}
	if c.Safety.RequestsPerSecond <= 0 {
		c.Safety.RequestsPerSecond = 2
	}
	if c.Safety.Timeout <= 0 {
		c.Safety.Timeout = Duration(10 * time.Second)
	}
	// Non-destructive by design. Never allow write/delete probes.
	c.Safety.Destructive = false
	if len(c.Target.AllowedHosts) == 0 && c.Target.BaseURL != "" {
		if host := hostFromURL(c.Target.BaseURL); host != "" {
			c.Target.AllowedHosts = []string{host}
		}
	}
	if len(c.Target.AllowedPaths) == 0 {
		c.Target.AllowedPaths = []string{"/"}
	}
}

func hostFromURL(raw string) string {
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	return raw
}

// Validate checks required fields before a run starts.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Target.BaseURL) == "" {
		return fmt.Errorf("target.base_url is required")
	}
	if !strings.HasPrefix(c.Target.BaseURL, "http://") && !strings.HasPrefix(c.Target.BaseURL, "https://") {
		return fmt.Errorf("target.base_url must start with http:// or https://")
	}
	if !c.Checks.Auth && !c.Checks.Misconfig && !c.Checks.RBAC {
		return fmt.Errorf("enable at least one checks.* category")
	}
	return nil
}

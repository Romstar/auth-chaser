// Package config loads chase run configuration from YAML or flags.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config describes a single auth-chaser run against one target.
type Config struct {
	Target  TargetConfig  `yaml:"target" json:"target"`
	Safety  SafetyConfig  `yaml:"safety" json:"safety"`
	Checks  ChecksConfig  `yaml:"checks" json:"checks"`
	Auth    AuthConfig    `yaml:"auth" json:"auth"`
	Browser BrowserConfig `yaml:"browser" json:"browser"`
	RBAC    RBACConfig    `yaml:"rbac" json:"rbac"`
}

// TargetConfig identifies the application under test.
type TargetConfig struct {
	BaseURL      string   `yaml:"base_url" json:"base_url"`
	AllowedHosts []string `yaml:"allowed_hosts" json:"allowed_hosts"`
	AllowedPaths []string `yaml:"allowed_paths" json:"allowed_paths"`
}

// SafetyConfig enforces authorization and non-destructive limits.
type SafetyConfig struct {
	ConfirmAuthorized bool     `yaml:"confirm_authorized" json:"confirm_authorized"`
	MaxRequests       int      `yaml:"max_requests" json:"max_requests"`
	RequestsPerSecond float64  `yaml:"requests_per_second" json:"requests_per_second"`
	Timeout           Duration `yaml:"timeout" json:"timeout"`
	Destructive       bool     `yaml:"destructive" json:"destructive"`
	AllowBrowser      bool     `yaml:"allow_browser" json:"allow_browser"`
	AllowPOST         bool     `yaml:"allow_post" json:"allow_post"`
}

// Duration wraps time.Duration for YAML/JSON strings like "10s".
type Duration time.Duration

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

func (d Duration) Duration() time.Duration { return time.Duration(d) }

// ChecksConfig selects which check packs to run.
type ChecksConfig struct {
	// Packs lists pack IDs. Empty uses defaults from Auth/Misconfig/RBAC bools.
	Packs     []string `yaml:"packs" json:"packs"`
	Auth      bool     `yaml:"auth" json:"auth"`
	Misconfig bool     `yaml:"misconfig" json:"misconfig"`
	RBAC      bool     `yaml:"rbac" json:"rbac"`
}

// AuthConfig holds protocol-specific settings and test credentials.
type AuthConfig struct {
	OAuth2   OAuth2Config   `yaml:"oauth2" json:"oauth2"`
	OIDC     OIDCConfig     `yaml:"oidc" json:"oidc"`
	Password PasswordConfig `yaml:"password" json:"password"`
	MFA      MFAConfig      `yaml:"mfa" json:"mfa"`
	Passkey  PasskeyConfig  `yaml:"passkey" json:"passkey"`
}

type OAuth2Config struct {
	ClientID     string   `yaml:"client_id" json:"client_id"`
	ClientSecret string   `yaml:"client_secret" json:"client_secret"`
	RedirectURI  string   `yaml:"redirect_uri" json:"redirect_uri"`
	Scopes       []string `yaml:"scopes" json:"scopes"`
	PublicClient bool     `yaml:"public_client" json:"public_client"`
	AuthorizeURL string   `yaml:"authorize_url" json:"authorize_url"`
	TokenURL     string   `yaml:"token_url" json:"token_url"`
}

type OIDCConfig struct {
	DiscoveryURL string `yaml:"discovery_url" json:"discovery_url"`
	IDToken      string `yaml:"id_token" json:"id_token"`
	AccessToken  string `yaml:"access_token" json:"access_token"`
	RefreshToken string `yaml:"refresh_token" json:"refresh_token"`
	ExpectedAud  string `yaml:"expected_aud" json:"expected_aud"`
	ExpectedIss  string `yaml:"expected_iss" json:"expected_iss"`
}

type PasswordConfig struct {
	LoginURL      string `yaml:"login_url" json:"login_url"`
	LogoutURL     string `yaml:"logout_url" json:"logout_url"`
	ProtectedPath string `yaml:"protected_path" json:"protected_path"`
	Username      string `yaml:"username" json:"username"`
	Password      string `yaml:"password" json:"password"`
	UsernameField string `yaml:"username_field" json:"username_field"`
	PasswordField string `yaml:"password_field" json:"password_field"`
	CSRFField     string `yaml:"csrf_field" json:"csrf_field"`
}

type MFAConfig struct {
	TOTPSecret   string   `yaml:"totp_secret" json:"totp_secret"`
	ChallengeURL string   `yaml:"challenge_url" json:"challenge_url"`
	RequiredRoles []string `yaml:"required_roles" json:"required_roles"`
	BypassPaths  []string `yaml:"bypass_paths" json:"bypass_paths"`
}

type PasskeyConfig struct {
	Enabled             bool   `yaml:"enabled" json:"enabled"`
	OptionsURL          string `yaml:"options_url" json:"options_url"`
	RequireUserVerification bool `yaml:"require_user_verification" json:"require_user_verification"`
}

// BrowserConfig controls optional Chrome automation.
type BrowserConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	Headless   bool   `yaml:"headless" json:"headless"`
	ChromePath string `yaml:"chrome_path" json:"chrome_path"`
}

// RBACConfig supplies roles and expected access for authorization checks.
type RBACConfig struct {
	Roles            []RoleSpec       `yaml:"roles" json:"roles"`
	ProtectedPaths   []string         `yaml:"protected_paths" json:"protected_paths"`
	ObjectTests      []ObjectTest     `yaml:"object_tests" json:"object_tests"`
	MatrixFile       string           `yaml:"matrix_file" json:"matrix_file"`
}

// RoleSpec maps a role to credentials and expected accessible paths.
type RoleSpec struct {
	Name         string   `yaml:"name" json:"name"`
	BearerToken  string   `yaml:"bearer_token" json:"bearer_token"`
	AllowedPaths []string `yaml:"allowed_paths" json:"allowed_paths"`
	DeniedPaths  []string `yaml:"denied_paths" json:"denied_paths"`
}

// ObjectTest checks horizontal access between identities.
type ObjectTest struct {
	Name      string `yaml:"name" json:"name"`
	ActorRole string `yaml:"actor_role" json:"actor_role"`
	OwnerRole string `yaml:"owner_role" json:"owner_role"`
	Path      string `yaml:"path" json:"path"`
	ExpectDeny bool  `yaml:"expect_deny" json:"expect_deny"`
}

// Known pack IDs.
const (
	PackAuthCore      = "auth.core"
	PackAuthOAuth2    = "auth.oauth2"
	PackAuthPassword  = "auth.password"
	PackAuthMFA       = "auth.mfa"
	PackAuthPasskey   = "auth.passkey"
	PackMisconfigAuth = "misconfig.auth"
	PackRBACMatrix    = "rbac.matrix"
)

// AllPacks returns every built-in pack ID.
func AllPacks() []string {
	return []string{
		PackAuthCore,
		PackAuthOAuth2,
		PackAuthPassword,
		PackAuthMFA,
		PackAuthPasskey,
		PackMisconfigAuth,
		PackRBACMatrix,
	}
}

// Default returns a safe baseline configuration.
func Default() Config {
	return Config{
		Safety: SafetyConfig{
			ConfirmAuthorized: false,
			MaxRequests:       80,
			RequestsPerSecond: 2,
			Timeout:           Duration(10 * time.Second),
			Destructive:       false,
			AllowBrowser:      false,
			AllowPOST:         true,
		},
		Checks: ChecksConfig{
			Auth:      true,
			Misconfig: true,
			RBAC:      false,
			Packs:     nil,
		},
		Browser: BrowserConfig{
			Enabled:  false,
			Headless: true,
		},
		Auth: AuthConfig{
			Password: PasswordConfig{
				UsernameField: "username",
				PasswordField: "password",
				CSRFField:     "csrf",
			},
			OAuth2: OAuth2Config{
				Scopes: []string{"openid", "profile"},
			},
		},
	}
}

// Load reads YAML from path and merges with defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		cfg.Normalize()
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	cfg.InterpolateSecrets()
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
		c.Safety.MaxRequests = 80
	}
	if c.Safety.RequestsPerSecond <= 0 {
		c.Safety.RequestsPerSecond = 2
	}
	if c.Safety.Timeout <= 0 {
		c.Safety.Timeout = Duration(10 * time.Second)
	}
	c.Safety.Destructive = false
	if len(c.Target.AllowedHosts) == 0 && c.Target.BaseURL != "" {
		if host := hostFromURL(c.Target.BaseURL); host != "" {
			c.Target.AllowedHosts = []string{host}
		}
	}
	if len(c.Target.AllowedPaths) == 0 {
		c.Target.AllowedPaths = []string{"/"}
	}
	if c.Auth.Password.UsernameField == "" {
		c.Auth.Password.UsernameField = "username"
	}
	if c.Auth.Password.PasswordField == "" {
		c.Auth.Password.PasswordField = "password"
	}
	if c.Browser.Enabled {
		c.Safety.AllowBrowser = true
	}
	if c.Safety.AllowBrowser {
		c.Browser.Enabled = true
	}
	c.resolvePacks()
}

func (c *Config) resolvePacks() {
	if len(c.Checks.Packs) > 0 {
		return
	}
	packs := make([]string, 0)
	if c.Checks.Auth {
		packs = append(packs, PackAuthCore)
		if c.Auth.OAuth2.ClientID != "" || c.Auth.OIDC.DiscoveryURL != "" || c.Auth.OAuth2.AuthorizeURL != "" {
			packs = append(packs, PackAuthOAuth2)
		}
		if c.Auth.Password.Username != "" || c.Auth.Password.LoginURL != "" {
			packs = append(packs, PackAuthPassword)
		}
		if c.Auth.MFA.TOTPSecret != "" || len(c.Auth.MFA.RequiredRoles) > 0 {
			packs = append(packs, PackAuthMFA)
		}
		if c.Auth.Passkey.Enabled {
			packs = append(packs, PackAuthPasskey)
		}
	}
	if c.Checks.Misconfig {
		packs = append(packs, PackMisconfigAuth)
	}
	if c.Checks.RBAC {
		packs = append(packs, PackRBACMatrix)
	}
	if len(packs) == 0 {
		packs = []string{PackAuthCore, PackMisconfigAuth}
	}
	c.Checks.Packs = packs
}

// EffectivePacks returns the packs selected for this run.
func (c Config) EffectivePacks() []string {
	return append([]string(nil), c.Checks.Packs...)
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		raw = strings.TrimPrefix(raw, "https://")
		raw = strings.TrimPrefix(raw, "http://")
		if i := strings.IndexAny(raw, "/?#"); i >= 0 {
			raw = raw[:i]
		}
		if i := strings.Index(raw, ":"); i >= 0 {
			raw = raw[:i]
		}
		return raw
	}
	return u.Hostname()
}

// Validate checks required fields before a run starts.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Target.BaseURL) == "" {
		return fmt.Errorf("target.base_url is required")
	}
	if !strings.HasPrefix(c.Target.BaseURL, "http://") && !strings.HasPrefix(c.Target.BaseURL, "https://") {
		return fmt.Errorf("target.base_url must start with http:// or https://")
	}
	if len(c.Checks.Packs) == 0 {
		return fmt.Errorf("enable at least one check pack")
	}
	return nil
}

// JoinURL joins base and a relative or absolute path.
func JoinURL(base, path string) string {
	if path == "" {
		return base
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(base, "/") + path
}

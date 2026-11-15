package config

import (
	"os"
	"regexp"
	"strings"
)

var envPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// InterpolateEnv replaces ${VAR} placeholders with environment values.
func InterpolateEnv(s string) string {
	return envPattern.ReplaceAllStringFunc(s, func(m string) string {
		name := envPattern.FindStringSubmatch(m)[1]
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		return m
	})
}

// InterpolateStruct walks string fields in Config that commonly hold secrets.
func (c *Config) InterpolateSecrets() {
	c.Auth.OAuth2.ClientID = InterpolateEnv(c.Auth.OAuth2.ClientID)
	c.Auth.OAuth2.ClientSecret = InterpolateEnv(c.Auth.OAuth2.ClientSecret)
	c.Auth.OAuth2.RedirectURI = InterpolateEnv(c.Auth.OAuth2.RedirectURI)
	c.Auth.OIDC.DiscoveryURL = InterpolateEnv(c.Auth.OIDC.DiscoveryURL)
	c.Auth.OIDC.IDToken = InterpolateEnv(c.Auth.OIDC.IDToken)
	c.Auth.OIDC.AccessToken = InterpolateEnv(c.Auth.OIDC.AccessToken)
	c.Auth.OIDC.RefreshToken = InterpolateEnv(c.Auth.OIDC.RefreshToken)
	c.Auth.Password.LoginURL = InterpolateEnv(c.Auth.Password.LoginURL)
	c.Auth.Password.Username = InterpolateEnv(c.Auth.Password.Username)
	c.Auth.Password.Password = InterpolateEnv(c.Auth.Password.Password)
	c.Auth.Password.UsernameField = InterpolateEnv(c.Auth.Password.UsernameField)
	c.Auth.Password.PasswordField = InterpolateEnv(c.Auth.Password.PasswordField)
	c.Auth.Password.LogoutURL = InterpolateEnv(c.Auth.Password.LogoutURL)
	c.Auth.Password.ProtectedPath = InterpolateEnv(c.Auth.Password.ProtectedPath)
	c.Auth.MFA.TOTPSecret = InterpolateEnv(c.Auth.MFA.TOTPSecret)
	c.Auth.MFA.ChallengeURL = InterpolateEnv(c.Auth.MFA.ChallengeURL)
	c.Auth.Passkey.OptionsURL = InterpolateEnv(c.Auth.Passkey.OptionsURL)
	for i := range c.RBAC.Roles {
		c.RBAC.Roles[i].BearerToken = InterpolateEnv(c.RBAC.Roles[i].BearerToken)
		c.RBAC.Roles[i].Name = InterpolateEnv(c.RBAC.Roles[i].Name)
	}
	for i := range c.RBAC.ObjectTests {
		c.RBAC.ObjectTests[i].ActorRole = InterpolateEnv(c.RBAC.ObjectTests[i].ActorRole)
		c.RBAC.ObjectTests[i].Path = InterpolateEnv(c.RBAC.ObjectTests[i].Path)
		c.RBAC.ObjectTests[i].OwnerRole = InterpolateEnv(c.RBAC.ObjectTests[i].OwnerRole)
	}
}

// RedactSecrets returns a copy safe for logging (secrets replaced).
func (c Config) RedactSecrets() Config {
	out := c
	out.Auth.OAuth2.ClientSecret = redact(out.Auth.OAuth2.ClientSecret)
	out.Auth.OIDC.IDToken = redact(out.Auth.OIDC.IDToken)
	out.Auth.OIDC.AccessToken = redact(out.Auth.OIDC.AccessToken)
	out.Auth.OIDC.RefreshToken = redact(out.Auth.OIDC.RefreshToken)
	out.Auth.Password.Password = redact(out.Auth.Password.Password)
	out.Auth.MFA.TOTPSecret = redact(out.Auth.MFA.TOTPSecret)
	for i := range out.RBAC.Roles {
		out.RBAC.Roles[i].BearerToken = redact(out.RBAC.Roles[i].BearerToken)
	}
	return out
}

func redact(s string) string {
	if strings.TrimSpace(s) == "" {
		return s
	}
	return "[REDACTED]"
}

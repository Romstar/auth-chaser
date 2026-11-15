// Package oauth helpers for OIDC discovery and JWT inspection.
package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Romstar/auth-chaser/internal/checks"
	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/Romstar/auth-chaser/internal/httpclient"
)

const maxBody = 512 * 1024

// Discover fetches OpenID Provider Metadata.
func Discover(ctx context.Context, cctx checks.Context) (*checks.OIDCMeta, string, error) {
	paths := make([]string, 0)
	if cctx.Cfg.Auth.OIDC.DiscoveryURL != "" {
		paths = append(paths, cctx.Cfg.Auth.OIDC.DiscoveryURL)
	}
	base := cctx.Cfg.Target.BaseURL
	paths = append(paths,
		base+"/.well-known/openid-configuration",
		base+"/oauth2/.well-known/openid-configuration",
		base+"/auth/.well-known/openid-configuration",
		base+"/realms/master/.well-known/openid-configuration",
	)

	var lastErr error
	for _, u := range paths {
		resp, err := cctx.Client.Get(ctx, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := httpclient.ReadLimited(resp.Body, maxBody)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s status %d", u, resp.StatusCode)
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			lastErr = err
			continue
		}
		meta := &checks.OIDCMeta{
			Issuer:                str(doc["issuer"]),
			AuthorizationEndpoint: str(doc["authorization_endpoint"]),
			TokenEndpoint:         str(doc["token_endpoint"]),
			JWKSURI:               str(doc["jwks_uri"]),
			UserinfoEndpoint:      str(doc["userinfo_endpoint"]),
			Raw:                   doc,
		}
		return meta, u, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no discovery document found")
	}
	return nil, "", lastErr
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// ParseJWTClaims decodes the payload of a JWT without verifying the signature.
func ParseJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// try std encoding with padding
		payload, err = base64.URLEncoding.DecodeString(pad(parts[1]))
		if err != nil {
			return nil, err
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// ParseJWTHeader decodes the JWT header.
func ParseJWTHeader(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 1 {
		return nil, fmt.Errorf("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(pad(parts[0]))
		if err != nil {
			return nil, err
		}
	}
	var hdr map[string]any
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return nil, err
	}
	return hdr, nil
}

func pad(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}

// ResolveAuthorizeURL returns authorize URL from config or discovery.
func ResolveAuthorizeURL(cfg config.Config, meta *checks.OIDCMeta) string {
	if cfg.Auth.OAuth2.AuthorizeURL != "" {
		return cfg.Auth.OAuth2.AuthorizeURL
	}
	if meta != nil && meta.AuthorizationEndpoint != "" {
		return meta.AuthorizationEndpoint
	}
	return ""
}

// ResolveTokenURL returns token URL from config or discovery.
func ResolveTokenURL(cfg config.Config, meta *checks.OIDCMeta) string {
	if cfg.Auth.OAuth2.TokenURL != "" {
		return cfg.Auth.OAuth2.TokenURL
	}
	if meta != nil && meta.TokenEndpoint != "" {
		return meta.TokenEndpoint
	}
	return ""
}

// FetchJWKS loads JWKS JSON keys.
func FetchJWKS(ctx context.Context, client *httpclient.Client, jwksURI string) (map[string]any, error) {
	resp, err := client.Get(ctx, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := httpclient.ReadLimited(resp.Body, maxBody)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

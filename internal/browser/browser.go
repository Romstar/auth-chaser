// Package browser provides optional Chrome automation via chromedp.
package browser

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Romstar/auth-chaser/internal/authz"
	"github.com/Romstar/auth-chaser/internal/config"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Session wraps a chromedp browser context.
type Session struct {
	cfg    config.Config
	gate   *authz.Gate
	alloc  context.Context
	cancel context.CancelFunc
	ctx    context.Context
	stop   context.CancelFunc
	ok     bool
}

// Start launches Chrome when enabled. Returns a disabled session if Chrome is unavailable.
func Start(parent context.Context, cfg config.Config, gate *authz.Gate) (*Session, error) {
	s := &Session{cfg: cfg, gate: gate}
	if !cfg.Browser.Enabled && !cfg.Safety.AllowBrowser {
		return s, nil
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", cfg.Browser.Headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)
	if cfg.Browser.ChromePath != "" {
		opts = append(opts, chromedp.ExecPath(cfg.Browser.ChromePath))
	}
	alloc, cancel := chromedp.NewExecAllocator(parent, opts...)
	ctx, stop := chromedp.NewContext(alloc)
	ctx, stop2 := context.WithTimeout(ctx, 2*time.Minute)
	s.alloc = alloc
	s.cancel = cancel
	s.ctx = ctx
	s.stop = func() { stop2(); stop() }
	// Probe Chrome quickly
	if err := chromedp.Run(ctx, chromedp.Navigate("about:blank")); err != nil {
		s.Close()
		return &Session{cfg: cfg, gate: gate}, fmt.Errorf("chrome unavailable: %w", err)
	}
	s.ok = true
	return s, nil
}

// Enabled reports whether browser automation is active.
func (s *Session) Enabled() bool { return s != nil && s.ok }

// Navigate opens a URL after scope checks.
func (s *Session) Navigate(ctx context.Context, rawURL string) error {
	if !s.Enabled() {
		return fmt.Errorf("browser not enabled")
	}
	if err := s.gate.AllowURL(rawURL); err != nil {
		return err
	}
	runCtx := s.ctx
	if ctx != nil {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(s.ctx, 30*time.Second)
		defer cancel()
		_ = runCtx
	}
	return chromedp.Run(s.ctx, chromedp.Navigate(rawURL))
}

// Cookies returns browser cookies.
func (s *Session) Cookies(ctx context.Context) ([]*http.Cookie, error) {
	if !s.Enabled() {
		return nil, fmt.Errorf("browser not enabled")
	}
	var cookies []*network.Cookie
	if err := chromedp.Run(s.ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		cookies, err = network.GetCookies().Do(ctx)
		return err
	})); err != nil {
		return nil, err
	}
	out := make([]*http.Cookie, 0, len(cookies))
	for _, c := range cookies {
		hc := &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     c.Path,
			Domain:   c.Domain,
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly,
		}
		out = append(out, hc)
	}
	return out, nil
}

// FillLogin attempts common username/password field selectors and submit.
func (s *Session) FillLogin(ctx context.Context, username, password string) error {
	if !s.Enabled() {
		return fmt.Errorf("browser not enabled")
	}
	userSel := `input[name="username"], input[name="email"], input[type="email"], #username, #email`
	passSel := `input[name="password"], input[type="password"], #password`
	submitSel := `button[type="submit"], input[type="submit"], button:contains("Sign in"), button:contains("Log in")`
	err := chromedp.Run(s.ctx,
		chromedp.WaitVisible(userSel, chromedp.ByQuery),
		chromedp.SendKeys(userSel, username, chromedp.ByQuery),
		chromedp.SendKeys(passSel, password, chromedp.ByQuery),
		chromedp.Click(`button[type="submit"], input[type="submit"]`, chromedp.ByQuery),
	)
	if err != nil {
		// try pressing Enter in password field
		_ = submitSel
		return chromedp.Run(s.ctx,
			chromedp.SendKeys(passSel, "\n", chromedp.ByQuery),
		)
	}
	return nil
}

// PageContains reports whether page body contains text (case-insensitive).
func (s *Session) PageContains(ctx context.Context, text string) (bool, error) {
	if !s.Enabled() {
		return false, fmt.Errorf("browser not enabled")
	}
	var body string
	if err := chromedp.Run(s.ctx, chromedp.OuterHTML("html", &body)); err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(body), strings.ToLower(text)), nil
}

// Close releases Chrome resources.
func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	if s.stop != nil {
		s.stop()
	}
	if s.cancel != nil {
		s.cancel()
	}
	s.ok = false
	return nil
}

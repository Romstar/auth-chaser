// Package httpclient wraps HTTP with rate limits, request caps, cookies, and scope checks.
package httpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Romstar/auth-chaser/internal/authz"
	"github.com/Romstar/auth-chaser/internal/config"
	"golang.org/x/time/rate"
)

// Client is a scoped, rate-limited HTTP client for non-destructive checks.
type Client struct {
	http    *http.Client
	jar     http.CookieJar
	gate    *authz.Gate
	limiter *rate.Limiter
	maxReq  int
	allowPOST bool

	mu    sync.Mutex
	count int
}

// New builds a client from run config and an authorization gate.
func New(cfg config.Config, gate *authz.Gate) *Client {
	jar, _ := cookiejar.New(nil)
	c := &Client{
		jar: jar,
		http: &http.Client{
			Timeout: cfg.Safety.Timeout.Duration(),
			Jar:     jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 8 {
					return fmt.Errorf("stopped after 8 redirects")
				}
				return gate.AllowURL(req.URL.String())
			},
		},
		gate:      gate,
		limiter:   rate.NewLimiter(rate.Limit(cfg.Safety.RequestsPerSecond), 1),
		maxReq:    cfg.Safety.MaxRequests,
		allowPOST: cfg.Safety.AllowPOST,
	}
	return c
}

// Get performs a GET within scope and rate limits.
func (c *Client) Get(ctx context.Context, rawURL string, headers map[string]string) (*http.Response, error) {
	return c.Do(ctx, http.MethodGet, rawURL, headers, nil)
}

// Head performs a HEAD request.
func (c *Client) Head(ctx context.Context, rawURL string, headers map[string]string) (*http.Response, error) {
	return c.Do(ctx, http.MethodHead, rawURL, headers, nil)
}

// PostForm performs an allowlisted application/x-www-form-urlencoded POST.
func (c *Client) PostForm(ctx context.Context, rawURL string, headers map[string]string, form url.Values) (*http.Response, error) {
	if !c.allowPOST {
		return nil, fmt.Errorf("POST blocked: set safety.allow_post=true for credentialed happy-path checks")
	}
	body := strings.NewReader(form.Encode())
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	return c.Do(ctx, http.MethodPost, rawURL, headers, body)
}

// Do performs an allowed HTTP method.
func (c *Client) Do(ctx context.Context, method, rawURL string, headers map[string]string, body io.Reader) (*http.Response, error) {
	method = strings.ToUpper(method)
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		// always allowed
	case http.MethodPost:
		if !c.allowPOST {
			return nil, fmt.Errorf("method POST blocked: enable safety.allow_post for happy-path steps")
		}
	default:
		return nil, fmt.Errorf("method %s blocked: auth-chaser only allows GET, HEAD, OPTIONS, and allowlisted POST", method)
	}

	if err := c.gate.AllowURL(rawURL); err != nil {
		return nil, err
	}

	c.mu.Lock()
	if c.count >= c.maxReq {
		c.mu.Unlock()
		return nil, fmt.Errorf("request cap reached (%d); raise safety.max_requests if needed", c.maxReq)
	}
	c.count++
	c.mu.Unlock()

	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "auth-chaser/0.2 (+https://github.com/Romstar/auth-chaser; defensive-security)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return c.http.Do(req)
}

// RequestCount returns how many requests this client issued.
func (c *Client) RequestCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// IncrementBudget counts a browser action against the request budget.
func (c *Client) IncrementBudget() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.count >= c.maxReq {
		return fmt.Errorf("request cap reached (%d)", c.maxReq)
	}
	c.count++
	return nil
}

// Jar returns the cookie jar for browser session import.
func (c *Client) Jar() http.CookieJar { return c.jar }

// SetCookies imports cookies for a URL (e.g. after browser login).
func (c *Client) SetCookies(rawURL string, cookies []*http.Cookie) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	c.jar.SetCookies(u, cookies)
	return nil
}

// CookiesFor returns cookies for a URL.
func (c *Client) CookiesFor(rawURL string) ([]*http.Cookie, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	return c.jar.Cookies(u), nil
}

// ReadLimited reads at most max bytes from a response body.
func ReadLimited(r io.Reader, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, max))
}

// Elapsed helper for callers that track timing locally.
func Elapsed(start time.Time) time.Duration {
	return time.Since(start)
}

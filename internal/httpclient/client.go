// Package httpclient wraps HTTP with rate limits, request caps, and scope checks.
package httpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
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
	gate    *authz.Gate
	limiter *rate.Limiter
	maxReq  int

	mu    sync.Mutex
	count int
}

// New builds a client from run config and an authorization gate.
func New(cfg config.Config, gate *authz.Gate) *Client {
	return &Client{
		http: &http.Client{
			Timeout: cfg.Safety.Timeout.Duration(),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				return gate.AllowURL(req.URL.String())
			},
		},
		gate:    gate,
		limiter: rate.NewLimiter(rate.Limit(cfg.Safety.RequestsPerSecond), 1),
		maxReq:  cfg.Safety.MaxRequests,
	}
}

// Get performs a GET within scope and rate limits.
func (c *Client) Get(ctx context.Context, rawURL string, headers map[string]string) (*http.Response, error) {
	return c.Do(ctx, http.MethodGet, rawURL, headers, nil)
}

// Do performs an allowed HTTP method. Only safe methods are accepted.
func (c *Client) Do(ctx context.Context, method, rawURL string, headers map[string]string, body io.Reader) (*http.Response, error) {
	method = strings.ToUpper(method)
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		// allowed non-destructive methods
	default:
		return nil, fmt.Errorf("method %s blocked: auth-chaser only allows GET, HEAD, OPTIONS", method)
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
	req.Header.Set("User-Agent", "auth-chaser/0.1 (+https://github.com/Romstar/auth-chaser; defensive-security)")
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

// ReadLimited reads at most max bytes from a response body.
func ReadLimited(r io.Reader, max int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, max))
}

// Elapsed helper for callers that track timing locally.
func Elapsed(start time.Time) time.Duration {
	return time.Since(start)
}

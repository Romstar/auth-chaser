# auth-chaser

Open-source, **defensive** authentication and authorization verification for applications you own — or applications you have explicit written permission to test.

auth-chaser ships as:

1. A **Linux CLI binary** for local runs
2. A **self-hostable SaaS** (`auth-chaser serve`) with HTTP API + web UI

It does **not** help attack third-party systems. Unauthorized scanning is prohibited.

## What it does

| Goal | How |
|------|-----|
| Confirm auth works as intended | Checks HTTPS, OIDC discovery, login surface reachability (more providers planned: OAuth2, passwords, passkeys, MFA) |
| Find auth misconfigurations | Non-destructive probes: security headers, cookie flags, dangerous CORS |
| Verify authorization / RBAC | Role tokens + expected allow/deny paths |

## Safety by design

Every run requires **explicit authorization confirmation** (`--confirm-authorized` or `safety.confirm_authorized: true`).

- **Non-destructive only** — GET / HEAD / OPTIONS; no write/delete probes
- **Scope limits** — `allowed_hosts` and `allowed_paths`
- **Rate limiting** — `requests_per_second` + `max_requests`
- **Request cap** — hard stop when the budget is exhausted

## Why Go

| Requirement | Go fit |
|-------------|--------|
| Single installable Linux binary | Static compile, trivial `make install` |
| CLI + self-hosted server in one artifact | One binary, two commands: `check` and `serve` |
| Concurrent, rate-limited HTTP checks | Goroutines + standard library networking |
| Security-tooling ecosystem | Mature HTTP, OAuth/OIDC, YAML, container story |
| Easy self-hosting | Tiny container image, no runtime language VM |

Rust was considered for memory safety; Go wins here for shipping a dual-mode security CLI/server faster with a smaller ops surface.

## Architecture

```
cmd/auth-chaser          CLI entry (check | serve | version)
internal/
  authz/                 Authorization gate + URL scope
  config/                YAML + flag config
  httpclient/            Scoped, rate-limited HTTP (safe methods only)
  checks/
    auth/                Authentication verification
    misconfig/           Misconfiguration probes
    rbac/                Authorization / RBAC probes
  runner/                Orchestrates a chase run
  report/                Text + JSON output
  server/                Self-hostable API + UI
pkg/types                Shared finding/report types
configs/                 Example chase YAML
```

**Modes**

- `check` — local binary against a target (CI-friendly JSON)
- `serve` — long-running control plane; `POST /api/v1/chase` runs the same engine

Same check engine. Same safety gate. Two delivery surfaces.

## Install (Linux)

### From source

```bash
git clone git@github.com:Romstar/auth-chaser.git
cd auth-chaser
make build          # writes bin/auth-chaser
make install        # installs to ~/.local/bin/auth-chaser
```

Ensure `~/.local/bin` is on your `PATH`.

### Docker (self-hosted SaaS)

```bash
docker compose up --build -d
# UI:  http://localhost:8080/
# API: POST http://localhost:8080/api/v1/chase
```

## Quick start (CLI)

```bash
# Copy and edit the example config
cp configs/chase.example.yaml chase.yaml
# Set target.base_url and safety.confirm_authorized: true

auth-chaser check --config chase.yaml

# Or fully via flags:
auth-chaser check \
  --target https://app.example.com \
  --confirm-authorized \
  --format json
```

Without `--confirm-authorized` (or the YAML equivalent), the run aborts.

## Quick start (self-hosted SaaS)

```bash
auth-chaser serve --addr :8080
```

Open `http://localhost:8080/`. Confirm ownership/authorization in the UI before a chase runs.

### API

```bash
curl -s http://localhost:8080/api/v1/chase \
  -H 'Content-Type: application/json' \
  -d '{
    "config": {
      "target": { "base_url": "https://app.example.com" },
      "safety": { "confirm_authorized": true, "max_requests": 50, "requests_per_second": 2 },
      "checks": { "auth": true, "misconfig": true, "rbac": false }
    }
  }'
```

## Example config

See [`configs/chase.example.yaml`](configs/chase.example.yaml).

## Current checks (v0.1 foundation)

**Auth**

- `auth.https_required`
- `auth.oidc_discovery`
- `auth.login_surface`

**Misconfig**

- `misconfig.security_headers`
- `misconfig.cookie_flags`
- `misconfig.cors`

**RBAC**

- `rbac.role_access` (requires `rbac.roles` in config)

## Roadmap (next)

- OAuth2 / OIDC flow verification (authorization code, PKCE, token validation)
- Password login happy-path + lockout/rate-limit observation (non-destructive)
- Passkey / WebAuthn configuration checks
- MFA enrollment and step-up presence checks
- Deeper RBAC matrices and IDOR-style *authorized* access comparisons
- Persistent job store + multi-tenant SaaS mode
- Signed install packages (deb/rpm) and GitHub Releases binaries

## Legal / ethics

Use auth-chaser only on systems you own or systems covered by a written authorization (bug bounty scope, contract, internal mandate). The authorization confirmation is a technical control, not a substitute for legal permission.

## License

Apache License 2.0. See [LICENSE](LICENSE).

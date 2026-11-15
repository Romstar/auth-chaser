# How to use auth-chaser

auth-chaser verifies authentication and authorization on applications **you own** or applications you have **written permission** to test.

This guide covers install, configuration, CLI use, self-hosted SaaS, CI, packs, and packaging.

## 1. Legal and safety first

1. Confirm you own the target, or hold written authorization (contract, bug bounty scope, internal mandate).
2. Pass `--confirm-authorized` or set `safety.confirm_authorized: true`. Without that flag, every run aborts.
3. Keep checks non-destructive. The tool allows GET, HEAD, OPTIONS, and allowlisted POST for happy-path login/token steps only.
4. Narrow `allowed_hosts` and `allowed_paths` when you can.
5. Use dedicated test accounts. Prefer environment variables for secrets.

Unauthorized scanning of third-party systems is prohibited. See [THREAT_MODEL.md](THREAT_MODEL.md).

## 2. Install

### Prebuilt binary (no Go required)

Every push to `main` updates the rolling GitHub Release `latest`:

```bash
curl -fsSL -o auth-chaser.tgz \
  https://github.com/Romstar/auth-chaser/releases/latest/download/auth-chaser-linux-amd64.tar.gz
tar -xzf auth-chaser.tgz
sudo install -m 755 auth-chaser-linux-amd64 /usr/local/bin/auth-chaser
auth-chaser version
```

### From source (Linux)

```bash
git clone https://github.com/Romstar/auth-chaser.git
cd auth-chaser
make build
make install   # installs to ~/.local/bin/auth-chaser
auth-chaser version
```

Ensure `~/.local/bin` is on your `PATH`.

### Docker

```bash
docker compose up --build -d
# UI: http://localhost:8080/
```

### Future OS packages

`.deb` and `.rpm` artifacts are built from this repository (see [PACKAGING.md](PACKAGING.md)). When a public apt/dnf repository is published, install with:

```bash
# Debian/Ubuntu (when the apt repo is live)
sudo apt-get update
sudo apt-get install auth-chaser

# Fedora/RHEL (when the dnf repo is live)
sudo dnf install auth-chaser
```

Until then, use `make install`, release binaries, or local package builds:

```bash
make package   # produces dist/*.deb and dist/*.rpm when nfpm is available
```

## 3. Concepts

| Term | Meaning |
|------|---------|
| **Chase** | One verification run against a target |
| **Pack** | A group of related checks (`auth.oauth2`, `rbac.matrix`, …) |
| **Finding** | One check result: pass, fail, warn, skip, or error |
| **Gate** | Authorization + host/path scope enforcement |
| **Browser mode** | Optional Chrome automation for JS login, MFA UI, passkeys |

## 4. Quick start (CLI)

List every pack and check:

```bash
auth-chaser list-checks
```

Run core + misconfig packs against a target you own:

```bash
auth-chaser check \
  --target https://app.example.com \
  --confirm-authorized \
  --packs auth.core,misconfig.auth \
  --format text
```

JSON for scripts:

```bash
auth-chaser check \
  --target https://app.example.com \
  --confirm-authorized \
  --format json > report.json
```

SARIF for GitHub Code Scanning / CI:

```bash
auth-chaser check \
  --config chase.yaml \
  --confirm-authorized \
  --format sarif \
  --fail-on-critical > results.sarif
```

## 5. Configuration file

Copy the example:

```bash
cp configs/chase.example.yaml chase.yaml
```

Minimal shape:

```yaml
target:
  base_url: https://app.example.com
  allowed_hosts: [app.example.com]
  allowed_paths: ["/"]

safety:
  confirm_authorized: true
  max_requests: 80
  requests_per_second: 2
  allow_post: true
  allow_browser: false

checks:
  packs:
    - auth.core
    - misconfig.auth

auth:
  password:
    login_url: /login
    username: test-user
    password: ${AUTH_CHASER_PASSWORD}
```

Run it:

```bash
export AUTH_CHASER_PASSWORD='your-test-password'
auth-chaser check --config chase.yaml
```

### Secret interpolation

Any `${VAR}` string in config is replaced from the environment. Unset variables stay as the placeholder. Do not commit real secrets.

### Useful CLI flags

| Flag | Purpose |
|------|---------|
| `--config` / `-c` | YAML chase file |
| `--target` / `-t` | Override `target.base_url` |
| `--confirm-authorized` | Assert permission |
| `--packs` | Comma-separated pack IDs |
| `--format` | `text`, `json`, or `sarif` |
| `--browser` | Enable Chrome automation |
| `--rbac` | Include RBAC pack when packs are inferred |
| `--max-requests` | Hard request budget |
| `--rps` | Requests per second |
| `--fail-on-critical` | Non-zero exit on critical failures |

## 6. Packs reference

### `auth.core`

- HTTPS on the base URL
- Login surface reachability
- CSRF / SameSite signals on the login page

### `auth.oauth2`

Requires OIDC discovery on the target (or `auth.oidc.discovery_url` / OAuth URLs in config).

- Discovery document completeness
- Authorize parameter behavior (`state`, PKCE for public clients)
- Redirect URI HTTPS
- Token endpoint rejects invalid codes
- ID token claim checks (when `auth.oidc.id_token` is supplied)
- JWKS reachability

### `auth.password`

Supply `auth.password.username` and `password` (via env).

- Successful login creates a session
- Wrong password does not mint a privileged session
- Post-login cookie flags
- Sessions over HTTPS
- Logout invalidates access to `protected_path`

### `auth.mfa`

- Challenge surface for roles that require MFA
- TOTP verify path when `auth.mfa.totp_secret` is set
- Bypass paths reject pre-MFA access

### `auth.passkey`

Set `auth.passkey.enabled: true`.

- WebAuthn options endpoint
- Browser smoke when `--browser` is on
- `userVerification=required` when policy says so

### `misconfig.auth`

- Security headers, cookie flags, CORS
- Open redirect probes on common auth params
- OAuth state/nonce signals
- JWT classic misconfig signals (from supplied tokens)
- Cache-Control on authenticated responses
- Login rate-limit header observation (non-hammering)

### `rbac.matrix`

- Anonymous callers blocked on protected paths
- Role allow/deny path matrix
- Horizontal object tests (`rbac.object_tests`)
- Optional CSV/YAML matrix file (`rbac.matrix_file`)

## 7. Browser automation

HTTP covers most checks. Enable browser mode when login is JS-rendered, or for MFA/passkey UI:

```bash
auth-chaser check \
  --config chase.yaml \
  --confirm-authorized \
  --browser
```

Requirements:

- Chrome or Chromium on the host
- `browser.enabled: true` or `--browser`
- Same host/path allowlist as HTTP

If a check needs the browser and it is disabled, the finding status is `skip` with `skip_reason=requires_browser`.

## 8. Self-hosted SaaS

Start the control plane:

```bash
auth-chaser serve --addr :8080 --data-dir .auth-chaser-data
```

Optional API token:

```bash
export AUTH_CHASER_API_TOKEN='long-random-token'
auth-chaser serve --addr :8080 --api-token "$AUTH_CHASER_API_TOKEN"
```

### HTTP API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/healthz` | Liveness |
| GET | `/api/v1/version` | Version |
| GET | `/api/v1/packs` | Pack catalog |
| POST | `/api/v1/chase` | Run chase (sync) or `{ "async": true }` → `202` |
| GET | `/api/v1/jobs` | Recent jobs |
| GET | `/api/v1/jobs/{id}` | Job + report |
| GET | `/api/v1/jobs/{id}/sarif` | SARIF download |
| GET | `/` | Web UI |

Example sync chase:

```bash
curl -s http://localhost:8080/api/v1/chase \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $AUTH_CHASER_API_TOKEN" \
  -d '{
    "config": {
      "target": { "base_url": "https://app.example.com" },
      "safety": { "confirm_authorized": true },
      "checks": { "packs": ["auth.core", "misconfig.auth"] }
    }
  }'
```

Async:

```bash
curl -s http://localhost:8080/api/v1/chase \
  -H "Content-Type: application/json" \
  -d '{"async": true, "config": { ... }}'
# → 202 + job id; poll GET /api/v1/jobs/{id}
```

Jobs and reports persist in SQLite under `--data-dir`.

## 9. CI example

```yaml
# .github/workflows/auth-chaser.yml
name: auth-chaser
on: [workflow_dispatch]
jobs:
  chase:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install auth-chaser
        run: |
          curl -fsSL -o auth-chaser.tgz \
            https://github.com/Romstar/auth-chaser/releases/latest/download/auth-chaser-linux-amd64.tar.gz
          tar -xzf auth-chaser.tgz
          sudo install -m 755 auth-chaser-linux-amd64 /usr/local/bin/auth-chaser
      - name: Run chase
        env:
          AUTH_CHASER_PASSWORD: ${{ secrets.AUTH_CHASER_PASSWORD }}
        run: |
          auth-chaser check \
            --config chase.yaml \
            --confirm-authorized \
            --format sarif \
            --fail-on-critical > auth-chaser.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: auth-chaser.sarif
```

## 10. Reading reports

Text output shows status, severity, pack, evidence, and remediation.

JSON fields of interest:

- `findings[].status` — `pass` | `fail` | `warn` | `skip` | `error`
- `findings[].severity` — `info` … `critical`
- `findings[].cwe` — optional CWE tag
- `findings[].metadata.skip_reason` — e.g. `requires_browser`, `missing_secret`

Exit codes:

- `0` — run completed (unless `--fail-on-critical` trips)
- non-zero — config/authorization error, or critical failures with `--fail-on-critical`

## 11. Website and docs site

This repository includes a static Next.js site under `website/`. It presents the product and links into this documentation.

```bash
cd website
npm install
npm run dev      # local
npm run build    # static export to website/out
```

Netlify build settings live in the root `netlify.toml`.

## 12. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `authorization not confirmed` | Pass `--confirm-authorized` or set the YAML flag |
| `host … not in allowed_hosts` | Add the IdP/app host to `allowed_hosts` |
| `request cap reached` | Raise `safety.max_requests` |
| OAuth checks skip | Discovery URL unreachable or outside scope |
| Password checks skip | Set username/password via config + env |
| Browser checks skip | Install Chrome and pass `--browser` |
| Serve returns 401 | Provide `Authorization: Bearer` matching `--api-token` |

## 13. Next steps

1. Start with `auth.core` + `misconfig.auth` on a staging app.
2. Add `auth.password` or `auth.oauth2` with test credentials.
3. Add `rbac.matrix` with role tokens and deny paths.
4. Turn on MFA/passkey packs when those flows exist.
5. Wire SARIF into CI and host `auth-chaser serve` for your team.

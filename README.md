# auth-chaser

Open-source, **defensive** authentication and authorization verification for applications you own — or applications you have explicit written permission to test.

auth-chaser ships as:

1. A **Linux CLI binary** for local runs
2. A **self-hostable SaaS** (`auth-chaser serve`) with HTTP API, job store, and web UI

It does **not** help attack third-party systems. Unauthorized scanning is prohibited.

## What it does

| Goal | How |
|------|-----|
| Confirm auth works as intended | Packs for core surface, OAuth2/OIDC, password sessions, MFA, passkeys |
| Find auth misconfigurations | Headers, cookies, CORS, open redirects, state/nonce, JWT signals, cache, rate-limit headers |
| Verify authorization / RBAC | Role matrices, anonymous baseline, horizontal object tests |

HTTP-first. Optional Chrome (`--browser`) fills JS login, MFA UI, and passkey gaps.

## Safety by design

Every run requires **explicit authorization confirmation** (`--confirm-authorized` or `safety.confirm_authorized: true`).

- Non-destructive methods (GET/HEAD/OPTIONS; allowlisted POST for happy-path only)
- Scope limits (`allowed_hosts`, `allowed_paths`)
- Rate limiting + max request budget
- Secrets via `${ENV}` interpolation; never log raw secrets

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Why Go

One static binary for CLI + server, strong HTTP tooling, easy containers and CI.

## Install (Linux)

```bash
git clone git@github.com:Romstar/auth-chaser.git
cd auth-chaser
make build && make install   # ~/.local/bin/auth-chaser
```

```bash
docker compose up --build -d
```

## Quick start (CLI)

```bash
auth-chaser list-checks

auth-chaser check \
  --target https://app.example.com \
  --confirm-authorized \
  --packs auth.core,misconfig.auth \
  --format json

# SARIF for CI
auth-chaser check -c chase.yaml --confirm-authorized --format sarif --fail-on-critical
```

## Packs

| Pack | Focus |
|------|-------|
| `auth.core` | HTTPS, login surface, CSRF signals |
| `auth.oauth2` | OIDC discovery, authorize/token/JWKS/PKCE/ID token claims |
| `auth.password` | Login success/failure, session flags, logout |
| `auth.mfa` | Challenge surface, TOTP, bypass paths |
| `auth.passkey` | WebAuthn options / UV / browser smoke |
| `misconfig.auth` | Headers, cookies, CORS, redirects, JWT, cache, rate-limit signals |
| `rbac.matrix` | Anonymous baseline, role paths, object tests, matrix file |

## Self-hosted SaaS

```bash
auth-chaser serve --addr :8080 --data-dir .auth-chaser-data
# optional: --api-token "$AUTH_CHASER_API_TOKEN"
```

- `POST /api/v1/chase` — sync report, or `{ "async": true }` → `202` job
- `GET /api/v1/jobs`, `GET /api/v1/jobs/{id}`, `GET /api/v1/jobs/{id}/sarif`
- `GET /api/v1/packs`

## Architecture

```
cmd/auth-chaser
internal/
  authz/ browser/ checks/{auth,misconfig,rbac,packs}
  config/ httpclient/ oauth/ runner/ report/ server/ store/ testapp/
pkg/types
configs/ docs/ testdata/
```

## Example config

See [`configs/chase.example.yaml`](configs/chase.example.yaml).

## License

Apache License 2.0. See [LICENSE](LICENSE).

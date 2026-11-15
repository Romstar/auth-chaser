# auth-chaser

Open-source, **defensive** authentication and authorization verification for applications you own — or applications you have explicit written permission to test.

auth-chaser ships as:

1. A **Linux CLI binary** for local runs
2. A **self-hostable SaaS** (`auth-chaser serve`) with HTTP API, job store, and web UI
3. A **static product website** (`website/`) for docs and install guidance
4. **`.deb` / `.rpm` packaging** foundations for apt and dnf

It does **not** help attack third-party systems. Unauthorized scanning is prohibited.

## Documentation

| Doc | Purpose |
|-----|---------|
| [docs/HOW_TO_USE.md](docs/HOW_TO_USE.md) | Full how-to-use guide |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Safety model and non-goals |
| [docs/PACKAGING.md](docs/PACKAGING.md) | apt/dnf package and repo foundation |
| Website (`make website-dev`) | Public static site (Netlify) |

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

## Install (Linux)

### Prebuilt binary (no Go required)

Every push to `main` publishes a rolling GitHub Release tagged `latest`:

```bash
curl -fsSL -o auth-chaser.tgz \
  https://github.com/Romstar/auth-chaser/releases/latest/download/auth-chaser-linux-amd64.tar.gz
tar -xzf auth-chaser.tgz
sudo install -m 755 auth-chaser-linux-amd64 /usr/local/bin/auth-chaser
auth-chaser version
```

Arm64: replace with `auth-chaser-linux-arm64.tar.gz`.

### From source

```bash
git clone git@github.com:Romstar/auth-chaser.git
cd auth-chaser
make build && make install   # ~/.local/bin/auth-chaser
```

`make build`, Docker, packaging, and CI all use `CGO_ENABLED=0` so the binary is statically linked (no libc/CGO dependency).

```bash
docker compose up --build -d
```

### OS packages (foundation)

```bash
# requires nfpm: https://nfpm.goreleaser.com/install/
make package
sudo apt-get install ./dist/auth-chaser_*_amd64.deb   # Debian/Ubuntu
sudo dnf install ./dist/auth-chaser-*.x86_64.rpm      # Fedora/RHEL
```

Public apt/dnf repositories are the next publishing step. See [docs/PACKAGING.md](docs/PACKAGING.md).

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

## Website

```bash
make website-dev   # http://localhost:3000
make website       # static export → website/out
```

Root [`netlify.toml`](netlify.toml) builds the static site from `website/`.

## Architecture

```
cmd/auth-chaser          CLI + serve
internal/                check engine, store, browser
website/                 Next.js static marketing + docs site
packaging/               nfpm, systemd, apt/rpm repo stubs
docs/                    HOW_TO_USE, PACKAGING, threat model
configs/                 example chase YAML
```

## Example config

See [`configs/chase.example.yaml`](configs/chase.example.yaml).

## License

Apache License 2.0. See [LICENSE](LICENSE).

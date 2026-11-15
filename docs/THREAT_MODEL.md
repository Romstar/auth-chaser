# Threat model

## Intended use

auth-chaser is a **defensive** verification tool. Operators run it only against applications they own or applications covered by written authorization.

## Assets

- Operator secrets in chase config (passwords, tokens, TOTP secrets)
- Target session integrity during happy-path tests
- Report findings (may include URLs and status codes)

## Non-goals

- Weaponized exploit chains
- Credential stuffing or password spraying
- Destructive writes (PUT/PATCH/DELETE)
- Unauthorized scanning of third-party systems

## Controls

1. Explicit `confirm_authorized` gate before any check runs
2. Host and path allowlists on every HTTP and browser navigation
3. Rate limits and hard request budgets
4. Safe methods by default; POST only for declared happy-path steps
5. Secret interpolation from environment; redaction helpers for logs
6. Browser automation optional and scoped

## Residual risk

Happy-path login uses real test credentials. Restrict those accounts. Keep request budgets low on shared environments.

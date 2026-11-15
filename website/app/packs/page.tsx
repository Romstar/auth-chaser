const PACKS = [
  {
    id: "auth.core",
    blurb: "HTTPS, login surface reachability, CSRF / SameSite signals.",
  },
  {
    id: "auth.oauth2",
    blurb: "OIDC discovery, authorize params, redirect HTTPS, token reject, JWKS, PKCE, ID token claims.",
  },
  {
    id: "auth.password",
    blurb: "Login success/failure, session cookie flags, HTTPS sessions, logout invalidation.",
  },
  {
    id: "auth.mfa",
    blurb: "Challenge surface, TOTP success path, post-MFA bypass rejection.",
  },
  {
    id: "auth.passkey",
    blurb: "WebAuthn options, user verification policy, browser smoke tests.",
  },
  {
    id: "misconfig.auth",
    blurb: "Headers, cookies, CORS, open redirects, state/nonce, JWT signals, cache, rate-limit headers.",
  },
  {
    id: "rbac.matrix",
    blurb: "Anonymous baseline, role path matrix, horizontal object tests, CSV/YAML matrix files.",
  },
];

export default function PacksPage() {
  return (
    <main className="doc-page">
      <h1>Check packs</h1>
      <p>
        Select packs with <code>--packs</code> or <code>checks.packs</code> in YAML. List them
        locally with <code>auth-chaser list-checks</code>.
      </p>
      <div className="pack-list">
        {PACKS.map((p) => (
          <div key={p.id}>
            <code>{p.id}</code>
            <p>{p.blurb}</p>
          </div>
        ))}
      </div>
      <p style={{ marginTop: "2rem" }}>
        <a className="btn btn-primary" href="/docs/">
          Read the usage guide
        </a>
      </p>
    </main>
  );
}

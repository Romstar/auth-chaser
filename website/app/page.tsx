const SAMPLE = `$ auth-chaser check \\
    --target https://app.example.com \\
    --confirm-authorized \\
    --packs auth.core,misconfig.auth

auth-chaser report
================================================
Target:      https://app.example.com
Authorized:  true
Packs:       auth.core, misconfig.auth
Summary:     pass=4 fail=1 warn=1 skip=0

[PASS] HTTPS for authentication endpoints
[FAIL] Auth-relevant security headers
  fix: Add HSTS and CSP on auth surfaces`;

export default function HomePage() {
  return (
    <main>
      <section className="hero">
        <div className="hero-copy">
          <h1>
            auth-<span className="accent">chaser</span>
          </h1>
          <p>
            Verify authentication and authorization on apps you own. Catch misconfigurations
            before attackers do — from a Linux binary or a self-hosted control plane.
          </p>
          <div className="cta-row">
            <a className="btn btn-primary" href="/download/">
              Install
            </a>
            <a className="btn btn-ghost" href="/docs/">
              How to use
            </a>
          </div>
        </div>
        <div className="hero-visual" aria-hidden="true">
          <pre>{SAMPLE}</pre>
        </div>
      </section>

      <section className="section">
        <h2>One engine. Two surfaces.</h2>
        <p className="lead">
          The same check packs power the CLI and the self-hosted SaaS. Safety gates, scope
          limits, and rate limits apply everywhere.
        </p>
        <div className="pack-list">
          <div>
            <code>check</code>
            <p>Local binary for developers and CI. Text, JSON, SARIF, HTML, PDF, or CSV reports.</p>
          </div>
          <div>
            <code>serve</code>
            <p>Self-hostable API and UI with SQLite job history and optional API tokens.</p>
          </div>
          <div>
            <code>confirm</code>
            <p>No chase runs until you assert ownership or written authorization.</p>
          </div>
        </div>
      </section>

      <section className="section">
        <h2>What it verifies</h2>
        <p className="lead">
          HTTP-first packs for OAuth2/OIDC, passwords, MFA, passkeys, misconfig probes, and
          RBAC. Browser automation fills the gaps when a flow needs a real page.
        </p>
        <div className="cta-row">
          <a className="btn btn-ghost" href="/packs/">
            Browse packs
          </a>
          <a className="btn btn-ghost" href="https://github.com/Romstar/auth-chaser">
            View source
          </a>
        </div>
      </section>
    </main>
  );
}

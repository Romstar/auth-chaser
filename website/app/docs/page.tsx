export default function DocsPage() {
  return (
    <main className="doc-page">
      <h1>How to use auth-chaser</h1>
      <p>
        Full reference also lives in the repository at{" "}
        <a href="https://github.com/Romstar/auth-chaser/blob/main/docs/HOW_TO_USE.md">
          docs/HOW_TO_USE.md
        </a>
        . This page is the practical path from install to CI.
      </p>

      <h2>1. Confirm authorization</h2>
      <p>
        Only test applications you own or have written permission to test. Every run requires{" "}
        <code>--confirm-authorized</code> or <code>safety.confirm_authorized: true</code>.
      </p>

      <h2>2. Install</h2>
      <pre>{`git clone https://github.com/Romstar/auth-chaser.git
cd auth-chaser
make build && make install
auth-chaser version`}</pre>
      <p>
        Prefer OS packages when available — see{" "}
        <a href="/download/">Download</a> for apt/dnf foundations and Docker.
      </p>

      <h2>3. First chase</h2>
      <pre>{`auth-chaser list-checks

auth-chaser check \\
  --target https://app.example.com \\
  --confirm-authorized \\
  --packs auth.core,misconfig.auth \\
  --format text`}</pre>

      <h2>4. Config file</h2>
      <p>
        Copy <code>configs/chase.example.yaml</code>, set the target, and keep secrets in the
        environment with <code>{"${VAR}"}</code> placeholders.
      </p>
      <pre>{`export AUTH_CHASER_PASSWORD='test-only-password'
auth-chaser check --config chase.yaml`}</pre>

      <h2>5. Self-hosted SaaS</h2>
      <pre>{`auth-chaser serve --addr :8080 --data-dir .auth-chaser-data
# open http://localhost:8080/`}</pre>
      <p>
        Use <code>POST /api/v1/chase</code> with <code>{`"async": true`}</code> for queued jobs.
        Optional control-plane auth: <code>--api-token</code> or{" "}
        <code>AUTH_CHASER_API_TOKEN</code>.
      </p>

      <h2>6. CI with SARIF</h2>
      <pre>{`auth-chaser check \\
  --config chase.yaml \\
  --confirm-authorized \\
  --format sarif \\
  --fail-on-critical > auth-chaser.sarif`}</pre>

      <h2>7. Browser gaps</h2>
      <p>
        HTTP covers most packs. For JS login, MFA UI, or passkeys, install Chrome and pass{" "}
        <code>--browser</code>. Checks that need the browser skip cleanly when it is off.
      </p>

      <h2>Safety rules</h2>
      <ul>
        <li>Host and path allowlists on every request and browser navigation</li>
        <li>Rate limits and a hard request budget</li>
        <li>No PUT/PATCH/DELETE; POST only for declared happy-path steps</li>
        <li>No credential stuffing or brute force</li>
      </ul>

      <p>
        Deeper detail:{" "}
        <a href="https://github.com/Romstar/auth-chaser/blob/main/docs/THREAT_MODEL.md">
          threat model
        </a>{" "}
        and{" "}
        <a href="https://github.com/Romstar/auth-chaser/blob/main/docs/PACKAGING.md">
          packaging
        </a>
        .
      </p>
    </main>
  );
}

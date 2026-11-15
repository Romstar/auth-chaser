export default function DownloadPage() {
  return (
    <main className="doc-page">
      <h1>Install auth-chaser</h1>
      <p>
        Choose a path that fits your environment. OS package repositories are being prepared;
        local <code>.deb</code> / <code>.rpm</code> builds already work from this repo.
      </p>

      <h2>From source</h2>
      <pre>{`git clone https://github.com/Romstar/auth-chaser.git
cd auth-chaser
make build && make install
# binary → ~/.local/bin/auth-chaser`}</pre>

      <h2>Docker / self-host</h2>
      <pre>{`docker compose up --build -d
# UI on http://localhost:8080/`}</pre>
      <pre>{`auth-chaser serve --addr :8080 --data-dir .auth-chaser-data`}</pre>

      <h2>Debian / Ubuntu (.deb)</h2>
      <p>
        Build packages locally (requires{" "}
        <a href="https://nfpm.goreleaser.com/install/">nfpm</a>):
      </p>
      <pre>{`make package
sudo apt-get install ./dist/auth-chaser_*_amd64.deb`}</pre>
      <p>
        A public apt repository is the next step. Foundation files live under{" "}
        <code>packaging/apt/</code>. When the repo is live:
      </p>
      <pre>{`sudo apt-get update
sudo apt-get install auth-chaser`}</pre>

      <h2>Fedora / RHEL (.rpm / dnf)</h2>
      <pre>{`make package
sudo dnf install ./dist/auth-chaser-*.x86_64.rpm`}</pre>
      <p>
        Repo template: <code>packaging/rpm/auth-chaser.repo</code>. Planned install path:
      </p>
      <pre>{`sudo dnf install auth-chaser`}</pre>

      <h2>GitHub release binaries (no Go required)</h2>
      <p>
        Every push to <code>main</code> refreshes the rolling{" "}
        <a href="https://github.com/Romstar/auth-chaser/releases/latest">latest</a> release
        with linux amd64 and arm64 tarballs.
      </p>
      <pre>{`curl -fsSL -o auth-chaser.tgz \\
  https://github.com/Romstar/auth-chaser/releases/latest/download/auth-chaser-linux-amd64.tar.gz
tar -xzf auth-chaser.tgz
sudo install -m 755 auth-chaser-linux-amd64 /usr/local/bin/auth-chaser
auth-chaser version`}</pre>

      <h2>Packaging details</h2>
      <p>
        Read{" "}
        <a href="https://github.com/Romstar/auth-chaser/blob/main/docs/PACKAGING.md">
          docs/PACKAGING.md
        </a>{" "}
        for apt/dnf repository setup, signing, and systemd service notes.
      </p>
    </main>
  );
}

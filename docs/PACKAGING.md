# Packaging for apt and dnf

This repository builds Linux packages so auth-chaser can ship through **apt** (Debian/Ubuntu) and **dnf** (Fedora/RHEL/CentOS Stream).

## What is in place today

| Piece | Location | Purpose |
|-------|----------|---------|
| nfpm config | [`packaging/nfpm.yaml`](../packaging/nfpm.yaml) | Single definition for `.deb` and `.rpm` |
| Build script | [`scripts/package.sh`](../scripts/package.sh) | Cross-compile binary + run nfpm |
| Makefile | `make package` | Local package build |
| CI job | `.github/workflows/packages.yml` | Build and upload `.deb` / `.rpm` artifacts |
| Unit file (optional) | `packaging/auth-chaser.service` | systemd unit for `serve` mode |

```bash
# Install nfpm: https://nfpm.goreleaser.com/install/
make package
ls dist/
# auth-chaser_<version>_amd64.deb
# auth-chaser-<version>-1.x86_64.rpm
```

Install a local build:

```bash
# Debian/Ubuntu
sudo apt-get install ./dist/auth-chaser_*_amd64.deb

# Fedora/RHEL
sudo dnf install ./dist/auth-chaser-*.x86_64.rpm
```

The package installs:

- `/usr/bin/auth-chaser` — CLI + server binary
- `/usr/lib/systemd/system/auth-chaser.service` — optional self-host service
- `/usr/share/doc/auth-chaser/` — short docs

## Path to a public apt repository

1. Build signed `.deb` files on each release (CI already produces unsigned artifacts).
2. Host an apt repo with one of:
   - [reprepro](https://wiki.debian.org/DebianRepository/SetupWithReprepro) on static hosting
   - [aptly](https://www.aptly.info/)
   - A managed host (Cloudsmith, Gemfury, PackageCloud)
3. Sign the Release file with a project GPG key.
4. Publish install instructions:

```bash
curl -fsSL https://apt.example.com/auth-chaser.gpg | sudo gpg --dearmor -o /usr/share/keyrings/auth-chaser.gpg
echo "deb [signed-by=/usr/share/keyrings/auth-chaser.gpg] https://apt.example.com stable main" \
  | sudo tee /etc/apt/sources.list.d/auth-chaser.list
sudo apt-get update
sudo apt-get install auth-chaser
```

Foundation files for that later step:

- `packaging/apt/distributions` — reprepro distributions stub
- `packaging/apt/README.md` — operator notes

## Path to a public dnf repository

1. Build signed `.rpm` files on each release.
2. Host a yum/dnf repo (`createrepo_c`) or publish to [COPR](https://copr.fedorainfracloud.org/).
3. Sign RPMs with the project GPG key.
4. Ship a `.repo` file:

```ini
[auth-chaser]
name=auth-chaser
baseurl=https://rpm.example.com/$releasever/$basearch/
enabled=1
gpgcheck=1
gpgkey=https://rpm.example.com/auth-chaser.gpg
```

```bash
sudo dnf config-manager --add-repo https://rpm.example.com/auth-chaser.repo
sudo dnf install auth-chaser
```

Foundation files:

- `packaging/rpm/auth-chaser.repo` — repo file template
- `packaging/rpm/README.md` — operator notes

## Signing (not automated yet)

Do not commit private GPG keys. When ready:

1. Create a release-signing key offline.
2. Store the private key in CI secrets (`GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`).
3. Extend `scripts/package.sh` to run `dpkg-sig` / `rpmsign` after nfpm.

## Versioning

Package version follows `VERSION` in the Makefile / git tag (`v0.2.0` → `0.2.0`). Bump with annotated tags before a release cut.

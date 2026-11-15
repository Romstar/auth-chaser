#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${VERSION:-0.2.0}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}"

mkdir -p dist

if ! command -v nfpm >/dev/null 2>&1; then
  echo "nfpm not found. Install from https://nfpm.goreleaser.com/install/" >&2
  echo "Example: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest" >&2
  exit 1
fi

for GOARCH in amd64 arm64; do
  echo "Building linux/${GOARCH} binary…"
  CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH}" go build -trimpath -ldflags "${LDFLAGS}" \
    -o "dist/auth-chaser-linux-${GOARCH}" ./cmd/auth-chaser

  # nfpm expands only a limited set of env vars in some versions; render config explicitly.
  CFG="$(mktemp)"
  sed \
    -e "s/\${VERSION}/${VERSION}/g" \
    -e "s/\${GOARCH}/${GOARCH}/g" \
    packaging/nfpm.yaml > "${CFG}"

  echo "Packaging ${GOARCH} deb + rpm…"
  nfpm package --config "${CFG}" --packager deb --target "dist/auth-chaser_${VERSION}_${GOARCH}.deb"
  nfpm package --config "${CFG}" --packager rpm --target "dist/auth-chaser-${VERSION}-1.${GOARCH}.rpm"
  rm -f "${CFG}"
done

echo "Packages:"
ls -la dist/*.{deb,rpm}

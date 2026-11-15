#!/bin/sh
set -eu

if ! getent group auth-chaser >/dev/null 2>&1; then
  groupadd --system auth-chaser || true
fi
if ! getent passwd auth-chaser >/dev/null 2>&1; then
  useradd --system --gid auth-chaser --home-dir /var/lib/auth-chaser \
    --shell /usr/sbin/nologin --create-home auth-chaser || true
fi

mkdir -p /var/lib/auth-chaser
chown auth-chaser:auth-chaser /var/lib/auth-chaser || true

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

exit 0

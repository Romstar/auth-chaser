#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
make install
echo "Installed auth-chaser to ${HOME}/.local/bin/auth-chaser"

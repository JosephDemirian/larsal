#!/usr/bin/env bash
# Server blind (P16, SYN-02.9, story E16-S3): app-server never links the
# vault reader, so the server cannot open a vault. Fails when app-server's
# dependency tree (every feature, every target; normal, build and dev edges)
# holds app-format, app-core, app-platform, app-ffi or app-sync. app-model's
# json.rs and app-crypto are allowed (LD-263 (14)).
#
#   scripts/check-server-blind.sh
set -euo pipefail
cd -P "$(dirname "$0")/.."
command -v cargo >/dev/null || . "$HOME/.cargo/env"
names=$(cargo tree --offline --locked -p app-server --all-features --target all \
  -e normal,build,dev --prefix none -f '{p}' | sed 's/ .*//' | sort -u)
linked=$(grep -xE 'app-(format|core|platform|ffi|sync)' <<<"$names" || true)
if [ -n "$linked" ]; then
  echo "app-server's tree holds:" $linked
  echo "check-server-blind: FAIL"
  exit 1
fi
echo "app-server: $(grep -c . <<<"$names") packages, none of app-format, app-core, app-platform, app-ffi, app-sync"
echo "check-server-blind: PASS"

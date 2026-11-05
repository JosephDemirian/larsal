#!/usr/bin/env bash
# Server blind (P16, SYN-02.9, story E16-S3): larsal-server never links the
# vault reader, so the server cannot open a vault. Fails when larsal-server's
# dependency tree (every feature, every target; normal, build and dev edges)
# holds larsal-format, larsal-core, larsal-platform, larsal-ffi or larsal-sync. larsal-model's
# json.rs and larsal-crypto are allowed (LD-263 (14)).
#
#   scripts/check-server-blind.sh
set -euo pipefail
cd -P "$(dirname "$0")/.."
command -v cargo >/dev/null || . "$HOME/.cargo/env"
names=$(cargo tree --offline --locked -p larsal-server --all-features --target all \
  -e normal,build,dev --prefix none -f '{p}' | sed 's/ .*//' | sort -u)
if linked=$(printf '%s\n' "$names" | grep -xE 'larsal-(format|core|platform|ffi|sync)'); then
  echo "larsal-server's tree holds:" $linked
  echo "check-server-blind: FAIL"
  exit 1
else
  result=$?
  [ "$result" -eq 1 ] || exit "$result"
fi
count=$(printf '%s\n' "$names" | grep -c .)
[ "$count" -gt 0 ]
echo "larsal-server: $count packages, none of larsal-format, larsal-core, larsal-platform, larsal-ffi, larsal-sync"
echo "check-server-blind: PASS"

#!/usr/bin/env bash
# E16-S7a check 7: larsal-ffi without its `sync` feature links nothing of
# larsal-sync. Fails when larsal-ffi's tree (default features, `net` and every
# other feature its Cargo.toml lists; every target; normal and build edges)
# holds larsal-sync, when the tree with `sync` does not, or when any tree cannot
# be read whole: cargo failed, the feature is missing, or the list lacks a crate
# every tree holds. Fails too when scripts/build-core.sh names `sync` or
# --all-features: SYN-03 keeps sync off in the app build. E16-S7b and E16-S9 take
# this out when they turn it on.
#
#   scripts/check-sync-link.sh
set -euo pipefail
cd -P "$(dirname "$0")/.."
command -v cargo >/dev/null || . "$HOME/.cargo/env"
red() {
  echo "$1"
  echo "check-sync-link: FAIL"
  exit 1
}
# Sets `names` to one lane's package names. The list is read whole first: a pipe
# into `grep -q` cuts it short, and pipefail then reads a match as no match.
lane() {
  local list crate
  list=$(cargo tree --offline --locked -p larsal-ffi "$@" --target all -e no-dev \
    --prefix none -f '{p}') || red "cargo tree failed with: ${*:-default features}"
  names=$'\n'$(printf '%s\n' "$list" | sed 's/ .*//' | sort -u)$'\n'
  for crate in larsal-ffi larsal-format larsal-platform larsal-crypto; do
    case $names in
      *$'\n'"$crate"$'\n'*) ;;
      *) red "the tree with ${*:-default features} is cut short: no $crate" ;;
    esac
  done
}
links_sync() {
  case $names in
    *$'\n'larsal-sync$'\n'*) return 0 ;;
    *) return 1 ;;
  esac
}
build_core=$(cat scripts/build-core.sh)
case $build_core in
  *sync* | *--all-features*) red "scripts/build-core.sh asks for sync: it stays off in the app build" ;;
esac
others=$(sed -n '/^\[features\]/,/^\[/s/^\([A-Za-z0-9_-][A-Za-z0-9_-]*\) *=.*/\1/p' \
  crates/larsal-ffi/Cargo.toml)
fail=0
lane
if links_sync; then
  echo "larsal-ffi with default features links larsal-sync"
  fail=1
fi
for feature in $(printf '%s\n' net $others | sort -u); do
  [ "$feature" != sync ] || continue
  lane --features "$feature"
  if links_sync; then
    echo "larsal-ffi with feature '$feature' links larsal-sync"
    fail=1
  fi
done
lane --features sync
links_sync || red "larsal-ffi with sync shows no larsal-sync: this check reads nothing"
[ "$fail" -eq 0 ] || red "larsal-ffi links larsal-sync without its sync feature"
echo "larsal-ffi: no larsal-sync with default features or any feature but sync; present with sync; build-core.sh asks for no sync"
echo "check-sync-link: PASS"

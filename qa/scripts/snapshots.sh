#!/usr/bin/env bash
# Mac QA screenshots of E5-S3 and E5-S4 without any window on screen: the
# debug Larsal runs hidden (LARSAL_TEST_HIDDEN: no window, never active, own
# instance folder), renders its real main window view offscreen and writes a
# PNG (macos/Larsal/Snapshot.swift). Vaults unlock only through F06 with the demo
# passwords of testdata/README.md. Build first: scripts/build-core.sh, then
# xcodebuild (check.sh G2 does both).
#
#   qa/scripts/snapshots.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
app=target/xcode/Build/Products/Debug/Larsal.app/Contents/MacOS/Larsal
[ -x "$app" ] || { echo "no $app: build the debug app first"; exit 1; }
rich=testdata/rich-v4.larsalvault
big=testdata/big-10000.larsalvault

# snap <out.png> <appearance> <ui> <password or -> <vault>
snap() {
  local out=$1 look=$2 ui=$3 password=$4 vault=$5 dir
  dir=$(mktemp -d)
  if [ "$password" = - ]; then
    env LARSAL_TEST_INSTANCE_DIR="$dir" LARSAL_TEST_HIDDEN=1 LARSAL_DEBUG_SNAPSHOT="$out" \
      LARSAL_DEBUG_APPEARANCE="$look" LARSAL_DEBUG_UI="$ui" "$app" ${vault:+"$vault"} </dev/null >/dev/null
  else
    printf '%s\n' "$password" | env LARSAL_TEST_INSTANCE_DIR="$dir" LARSAL_TEST_HIDDEN=1 LARSAL_DEBUG_SNAPSHOT="$out" \
      LARSAL_DEBUG_APPEARANCE="$look" LARSAL_DEBUG_UI="$ui" "$app" --password-stdin "$vault" >/dev/null 2>&1
  fi
  rm -rf "$dir"
  echo "$out"
}

s3=qa/E5-S3 s4=qa/E5-S4
snap $s3/larsal-start-dark.png dark "" - ""
snap $s3/larsal-unlock-empty-dark.png dark "" - $rich
snap $s3/larsal-unlock-empty-light.png light "" - $rich
snap $s3/larsal-unlock-wrong-password-dark.png dark "" wrong $rich
snap $s3/larsal-unlock-wrong-password-light.png light "" wrong $rich
snap $s4/larsal-main-dark.png dark "select=Full demo entry;show=Password" demo-pass-5 $rich
snap $s4/larsal-main-light.png light "select=Full demo entry;show=Password" demo-pass-5 $rich
snap $s4/larsal-search-dark.png dark "search=attachment" demo-pass-5 $rich
snap $s4/larsal-search-light.png light "search=attachment" demo-pass-5 $rich
snap $s4/larsal-search-tips-dark.png dark "select=Full demo entry;tips=1" demo-pass-5 $rich
snap $s4/larsal-recycle-bin-dark.png dark "place=bin" demo-pass-5 $rich
snap $s4/larsal-search-big-10000-dark.png dark "search=Entry 0999" demo-pass-6 $big

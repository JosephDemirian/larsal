#!/usr/bin/env bash
# SwiftLint, a check tool (LD-156 (4), installed under the E0 check-tool
# permission). One pinned release; its zip is checked against the SHA-256
# below before it is unpacked. The checksum is the one GitHub lists for the
# release asset (https://github.com/realm/SwiftLint/releases/tag/0.65.1).
#
#   scripts/install-swiftlint.sh          install once
#   scripts/install-swiftlint.sh --path   print where the pinned binary is
set -euo pipefail
VERSION=0.65.1
SHA256=c1e429b0599cf1b516f369a2d9ec04eaf0e436f3c12b637df8851fa52ff694d0
DIR="$HOME/.local/share/swiftlint/$VERSION"
BIN="$DIR/swiftlint"

if [ "${1:-}" = --path ]; then echo "$BIN"; exit 0; fi
if [ -x "$BIN" ]; then echo "SwiftLint $VERSION is installed: $BIN"; exit 0; fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/larsal-swiftlint.XXXXXX") || exit 1
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/swiftlint.zip" \
  "https://github.com/realm/SwiftLint/releases/download/$VERSION/portable_swiftlint.zip"
echo "$SHA256  $tmp/swiftlint.zip" | shasum -a 256 -c -
unzip -q "$tmp/swiftlint.zip" swiftlint -d "$tmp/out"
mkdir -p "$DIR"
install -m 0755 "$tmp/out/swiftlint" "$BIN"
echo "SwiftLint $("$BIN" version) installed: $BIN"

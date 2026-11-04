#!/bin/bash
# G4 interop (plan/attacks-and-checks.md): Larsal's saves open in the reference
# CLI with the same export as the original.
#
#   REF_CLI=<reference CLI> scripts/interop.sh [cases file]
#
# For each case Larsal opens the vault and saves a version 4 copy into a temp
# folder (example `resave`, the real `larsal_format::save`); then
# scripts/testdata/interop_compare.py has the reference CLI export both files
# and compares them field by field, attachments byte for byte (its header says
# exactly what is compared and the only version-form rules applied).
#
# Cases: every vault in testdata/ (built in). A cases file adds lines of
# tab-separated fields: name, vault path, password ("-" for none), key file
# (optional). Lines starting with # are skipped. The resave example reads "no
# password" as an empty line, so a vault with the empty password needs
# another tool; interop_compare.py can compare a copy made that way.
#
# Exit 1 when any case fails. Nothing is written outside the temp folder.
set -uo pipefail

die() { echo "interop: $*" >&2; exit 1; }
[ -n "${REF_CLI:-}" ] || die "REF_CLI is not set. Set it to the path of the reference CLI."
[ -f "$REF_CLI" ] && [ -x "$REF_CLI" ] || die "REF_CLI ($REF_CLI) is not an executable file."
[ $# -le 1 ] || die "usage: interop.sh [cases file]"
[ $# -eq 0 ] || [ -f "$1" ] || die "cases file $1 not found"
export REF_CLI

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DATA=$ROOT/testdata
command -v cargo >/dev/null || . "$HOME/.cargo/env"
cargo build -q --offline --locked --manifest-path "$ROOT/Cargo.toml" -p larsal-format --example resave || die "build failed"
RESAVE=$ROOT/target/debug/examples/resave
TMP=$(mktemp -d "${TMPDIR:-/tmp}/larsal-interop.XXXXXX") || die "cannot create a private temporary folder"
trap 'rm -rf "$TMP"' EXIT

# The testdata/README.md vault table.
builtin_cases() {
  local k
  printf '%s\t%s\t%s\t%s\n' password-only "$DATA/password-only.larsalvault" demo-pass-1 ""
  for k in binary32 hex64 hashed xml-v1 xml-v2 cli-made; do
    printf '%s\t%s\t%s\t%s\n' "keyfile-$k" "$DATA/keyfile-$k.larsalvault" - "$DATA/key-$k.larsalkey"
  done
  printf '%s\t%s\t%s\t%s\n' password-and-keyfile "$DATA/password-and-keyfile.larsalvault" demo-pass-2 "$DATA/key-hex64.larsalkey" \
    default-time "$DATA/default-time.larsalvault" demo-pass-3 "" \
    rich-v3 "$DATA/rich-v3.larsalvault" demo-pass-4 "" \
    rich-v4 "$DATA/rich-v4.larsalvault" demo-pass-5 "" \
    big-10000 "$DATA/big-10000.larsalvault" demo-pass-6 ""
}

cases() { builtin_cases; [ $# -eq 0 ] || grep -v '^#' "$1"; }

failed=0 total=0
while IFS=$'\t' read -r name vault pass key; do
  [ -n "$name" ] || continue
  total=$((total + 1))
  copy=$TMP/$total.larsalvault
  line=$pass; [ "$pass" = - ] && line=""
  if ! printf '%s\n' "$line" | "$RESAVE" "$vault" "$copy" ${key:+"$key"} >"$TMP/resave.log" 2>&1; then
    echo "FAIL $name: Larsal could not resave it: $(tail -n 1 "$TMP/resave.log")"
    failed=$((failed + 1))
    continue
  fi
  echo "     $name: $(sed -e 's/.*(version \([0-9.]*\)) -> .*(version \([0-9.]*\),.*/version \1 saved as \2/' "$TMP/resave.log")"
  if [ "$pass" = - ]; then
    env -u INTEROP_PASSWORD python3 -I -B "$ROOT/scripts/testdata/interop_compare.py" "$vault" "$copy" ${key:+"$key"}
  else
    INTEROP_PASSWORD=$pass python3 -I -B "$ROOT/scripts/testdata/interop_compare.py" "$vault" "$copy" ${key:+"$key"}
  fi || failed=$((failed + 1))
done < <(cases "$@")

echo "interop: $((total - failed)) of $total cases pass"
[ "$failed" -eq 0 ]

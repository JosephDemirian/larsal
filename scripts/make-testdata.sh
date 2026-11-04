#!/bin/bash
# Test data kit (story E0-S5): makes the demo vaults in testdata/ with the
# reference CLI and stores each vault's expected content as JSON.
#
#   REF_CLI=<reference CLI> scripts/make-testdata.sh            remake testdata/
#   REF_CLI=<reference CLI> scripts/make-testdata.sh --verify   compare with testdata/,
#       exit 1 on any difference
#
# Both modes build everything in a temp folder. The normal mode copies it into
# testdata/ only after every vault and check succeeded.
#
# Inputs come from scripts/testdata/make_inputs.py (fixed XML documents, kept
# in a temp folder only, and fixed key files). See testdata/README.md.
set -eo pipefail

die() { echo "make-testdata: $*" >&2; exit 1; }

[ -n "$REF_CLI" ] || die "REF_CLI is not set. Set it to the path of the reference CLI."
[ -f "$REF_CLI" ] && [ -x "$REF_CLI" ] || die "REF_CLI ($REF_CLI) is not an executable file."
case "$1" in
  "") VERIFY=0 ;;
  --verify) VERIFY=1 ;;
  *) die "usage: make-testdata.sh [--verify]" ;;
esac

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DATA=$ROOT/testdata
HELPERS=$ROOT/scripts/testdata
TMP=$(mktemp -d "${TMPDIR:-/tmp}/larsal-testdata.XXXXXX") || die "cannot create a private temporary folder"
trap 'rm -rf "$TMP"' EXIT
OUT=$TMP/out
mkdir "$TMP/xml" "$TMP/export" "$OUT"

# cli <password> <args...>: run the reference CLI, password on stdin (twice, for "repeat").
# No -q: it also hides the CLI's error text. Prompts go to stderr, kept for failures only.
cli() {
  local pass=$1; shift
  "$REF_CLI" "$@" 2>"$TMP/err" <<EOF || { cat "$TMP/err" >&2; die "reference CLI failed: $1"; }
$pass
$pass
EOF
}

python3 -I "$HELPERS/make_inputs.py" "$TMP/xml" "$OUT"

# The CLI makes this key file from random bytes, so it is made once and kept.
CLI_KEY=key-cli-made.larsalkey
if [ -f "$DATA/$CLI_KEY" ]; then
  cp "$DATA/$CLI_KEY" "$OUT/"
else
  [ "$VERIFY" = 0 ] || die "testdata/$CLI_KEY is missing; run without --verify first."
  cli "" db-create --set-key-file "$OUT/$CLI_KEY" "$TMP/throwaway.larsalvault" > /dev/null
fi
python3 -I -c 'import hashlib, sys; sys.stdout.buffer.write(hashlib.sha256(open(sys.argv[1], "rb").read()).digest())' \
  "$OUT/$CLI_KEY" > "$TMP/xml/$CLI_KEY.raw"

FAIL=0
same() {  # same <made> <stored>
  cmp -s "$1" "$2" && return
  echo "DIFFERENT: ${2#$ROOT/}"
  diff -u "$2" "$1" | head -40 || true
  FAIL=1
}

# attachments <vault> <password> <document>: read every attachment in the
# document's list (written by make_inputs.py) back through the CLI and compare
# it with the bytes make_inputs.py wrote. This is the only proof for 4.1
# vaults: their XML export leaves the bytes out.
attachments() {
  local ent att shown=${1#"$ROOT"/}
  shown=${shown#"$TMP"/}
  while IFS='|' read -r ent att <&4; do
    rm -f "$TMP/att"
    cli "$2" attachment-export "$1" "$ent" "$att" "$TMP/att" > /dev/null
    cmp -s "$TMP/att" "$TMP/xml/att-$att" ||
      { echo "DIFFERENT: attachment $att of \"$ent\" in $shown"; FAIL=1; }
  done 4<"$TMP/xml/$3.attachments"
}

if [ "$VERIFY" = 1 ]; then
  for f in "$OUT"/*.larsalkey; do same "$f" "$DATA/${f##*/}"; done
fi

N=0
# name | XML document | password | key file | -t in ms (empty: the CLI's default)
while IFS='|' read -r name doc pass key ms <&3; do
  [ -n "$name" ] || continue
  new=(import) open=() twin=()
  [ -z "$pass" ] || new+=(-p)
  [ -n "$pass" ] || { open+=(--no-password); twin+=(--no-password); }
  [ -z "$key" ] || { new+=(--set-key-file "$OUT/$key"); open+=(-k "$OUT/$key"); twin+=(-k "$TMP/xml/$key.raw"); }
  [ -z "$ms" ] || new+=(-t "$ms")

  cli "$pass" "${new[@]}" "$TMP/xml/$doc.xml" "$OUT/$name.larsalvault" > /dev/null
  cli "$pass" export "${open[@]}" -f xml "$OUT/$name.larsalvault" > "$TMP/export/$name.xml"
  python3 -I "$HELPERS/to_json.py" "$TMP/export/$name.xml" "$OUT/$name.json"
  # Opening with the 32 raw key bytes proves the CLI read the key file as the kind its name says.
  [ -z "$key" ] || cli "$pass" db-info "${twin[@]}" "$OUT/$name.larsalvault" > /dev/null
  attachments "$OUT/$name.larsalvault" "$pass" "$doc"

  if [ "$VERIFY" = 1 ]; then
    same "$OUT/$name.json" "$DATA/$name.json"
    # The stored vault must still export to the stored JSON.
    cli "$pass" export "${open[@]}" -f xml "$DATA/$name.larsalvault" > "$TMP/export/$name.stored.xml"
    python3 -I "$HELPERS/to_json.py" "$TMP/export/$name.stored.xml" "$TMP/$name.stored.json"
    same "$TMP/$name.stored.json" "$DATA/$name.json"
    attachments "$DATA/$name.larsalvault" "$pass" "$doc"
  fi
  N=$((N + 1))
  echo "$name: done"
done 3<<'EOF'
password-only|basic|demo-pass-1||100
keyfile-binary32|basic||key-binary32.larsalkey|100
keyfile-hex64|basic||key-hex64.larsalkey|100
keyfile-hashed|basic||key-hashed.larsalkey|100
keyfile-xml-v1|basic||key-xml-v1.larsalkey|100
keyfile-xml-v2|basic||key-xml-v2.larsalkey|100
keyfile-cli-made|basic||key-cli-made.larsalkey|100
password-and-keyfile|basic|demo-pass-2|key-hex64.larsalkey|100
default-time|basic|demo-pass-3||
rich-v3|rich-v3|demo-pass-4||100
rich-v4|rich-v4|demo-pass-5||100
big-10000|big|demo-pass-6||100
EOF

if [ "$VERIFY" = 1 ]; then
  # No stale or extra file in testdata/: exactly what a run makes, plus README.md.
  # The Option A demo vaults are made by our own code (testdata/README.md).
  diff <(ls "$DATA" | grep -v '^option-a-' | sort) <( (ls "$OUT"; echo README.md) | sort) ||
    { echo "DIFFERENT: the file list of testdata/ (< extra, > missing)"; FAIL=1; }
  [ "$FAIL" = 0 ] || { echo "verify: FAIL"; exit 1; }
  echo "verify: PASS ($N vaults: fresh and stored vaults export to the stored JSON and hold the attachment bytes)"
else
  [ "$FAIL" = 0 ] || die "FAIL; testdata/ was not changed."
  cp -f "$OUT"/* "$DATA/"
  echo "made $N vaults in testdata/"
fi

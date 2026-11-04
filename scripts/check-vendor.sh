#!/usr/bin/env bash
# Own every dependency (story E0-S7, LD-221, LD-247): every build reads only
# this tree. Four checks (1 and 2 for the workspace and for fuzz/):
#  1. Sources: `cargo metadata --offline --locked --all-features`, run with
#     an empty cargo home (no cache, no user config), lists only path
#     packages inside this tree and crates.io packages read from
#     vendor/crates-io (the source replacement of .cargo/config.toml). Every
#     feature of our crates counts: `net` reaches packages (ureq, rustls,
#     base64, ...) that the default features do not. A git or other registry
#     source, a path outside the tree or the cargo cache fails. Every
#     target's source file (library, build script, binaries, tests) is a .rs
#     file in its own package folder, with no `..` in its path: targets
#     outside their package or not a .rs file fail (a Cargo.toml can be
#     valid Rust too).
#  2. Stubs (LD-247 (3)): a copy whose .cargo-checksum.json lists no files is
#     a stub for a package never built on a Mac. `cargo tree` for
#     aarch64-apple-darwin and x86_64-apple-darwin (every feature of our
#     crates; normal, build and dev edges) must name none of them.
#  3. Links: no symbolic link in the folders that hold package sources
#     (vendor/, crates/, fuzz/), so a path inside the tree cannot lead out.
#  4. Lists and cut copies: every copy but a stub lists every file on disk,
#     in any folder, except its list itself (cargo hashes only the files a
#     list names, and builds a build.rs it finds when the manifest names none).
#     The copies named in cut_copies (E0-S7 steps 2 and 4, E16-S3), and no other, keep
#     the list cargo vendor wrote as .cargo-checksum.upstream.json. Each lost
#     only what its Cargo.toml cut and whole files never compiled on a Mac: its
#     .cargo-checksum.json names the same package and every file it lists but
#     Cargo.toml and the upstream list has its upstream hash, so no code line
#     changed and no file was added (rule 3 for crypto copies).
#
#   scripts/check-vendor.sh
set -euo pipefail
cd -P "$(dirname "$0")/.."
command -v cargo >/dev/null || . "$HOME/.cargo/env"
root=$PWD
home=$(mktemp -d) && trap 'rm -rf "$home"' EXIT
export CARGO_HOME=$home
crates_io=registry+https://github.com/rust-lang/crates.io-index
stubs=$(for f in vendor/crates-io/*/.cargo-checksum.json; do
  if jq -e '.files == {}' "$f" >/dev/null; then basename "$(dirname "$f")"; fi
done | sort)
fail=0
links=$(find vendor crates fuzz -path fuzz/target -prune -o -type l -print)
[ -z "$links" ] || { echo "symbolic links in the package folders:"; echo "$links"; fail=1; }
cut=0
cut_copies='aead-0.6.1 aes-0.9.3 aes-gcm-0.11.1 argon2-0.6.0 base16ct-1.0.0 base64ct-1.8.3 bcrypt-pbkdf-0.11.0
  bit-vec-0.10.1 blake2-0.11.0 block-buffer-0.12.1 blowfish-0.10.0 byteorder-1.5.0 cbc-0.2.1
  chacha20-0.10.2 cipher-0.5.2 cmov-0.5.4 const-oid-0.10.2 cpufeatures-0.3.1 crypto-bigint-0.7.10
  ctr-0.10.1 ctutils-0.4.6 curve25519-dalek-5.0.0 curve25519-dalek-derive-0.1.1 der-0.8.2 digest-0.11.3
  ed25519-3.0.0 ed25519-dalek-3.0.0 elliptic-curve-0.14.2 errno-0.3.14 ff-0.14.0
  flate2-1.1.10 getrandom-0.2.17 getrandom-0.4.3 hkdf-0.13.0 hmac-0.13.0 hybrid-array-0.4.15
  inout-0.2.5 libc-0.2.191 libsqlite3-sys-0.38.2 memchr-2.8.3 mio-1.2.4 num-traits-0.2.19
  objc2-app-kit-0.3.2 objc2-core-foundation-0.3.2
  objc2-foundation-0.3.2 objc2-io-kit-0.3.2 once_cell-1.21.4 p256-0.14.0 pbkdf2-0.13.0 pem-rfc7468-1.0.0
  png-0.18.1 poly1305-0.9.1 polyval-0.7.3 quick-xml-0.42.0 rand_core-0.10.1 rcgen-0.14.10
  regex-automata-0.4.18 rfc6979-0.6.0 ring-0.17.14 rustix-1.1.5 salsa20-0.11.0 sec1-0.8.1 sha1-0.11.0 sha2-0.11.1
  socket2-0.6.5 ssh-cipher-0.3.0 ssh-encoding-0.3.0 subtle-2.6.1 tempfile-3.27.0 textwrap-0.16.4 time-0.3.55
  tokio-1.53.3 twofish-0.8.0 typenum-1.20.1 untrusted-0.9.0 yasna-0.6.0 zeroize-1.9.1'
uncut=$(comm -13 <(printf '%s\n' $cut_copies | sort) \
  <(find vendor/crates-io -mindepth 2 -maxdepth 2 -name .cargo-checksum.upstream.json | cut -d/ -f3 | sort))
[ -z "$uncut" ] || { echo "upstream lists in copies not named as cut:" $uncut; fail=1; }
for d in $cut_copies; do
  up=vendor/crates-io/$d/.cargo-checksum.upstream.json
  [ -e "$up" ] || { echo "vendor/crates-io/$d: a cut copy without its upstream list"; fail=1; continue; }
  cut=$((cut + 1))
  changed=$(jq -rn --slurpfile u "$up" --slurpfile n "${up%.upstream.json}.json" '
    if $u[0].package != $n[0].package then "the package checksum" else
      $n[0].files | to_entries[] | select(.key != "Cargo.toml" and
        .key != ".cargo-checksum.upstream.json" and $u[0].files[.key] != .value) | .key end')
  [ -z "$changed" ] || { echo "${up%/*}: not upstream beyond its cut:" $changed; fail=1; }
done
for c in vendor/crates-io/*/; do
  c=${c%/}
  grep -qxF "${c##*/}" <<<"$stubs" && continue
  unlisted=$(comm -23 <(cd "$c" && find . -type f ! -path ./.cargo-checksum.json | sed 's|^\./||' | sort) \
    <(jq -r '.files | keys[]' "$c/.cargo-checksum.json" | sort))
  [ -z "$unlisted" ] || { echo "$c: files not in its list:" $unlisted; fail=1; }
done
for manifest in Cargo.toml fuzz/Cargo.toml; do
  meta=$(cargo metadata --offline --locked --all-features --format-version 1 --manifest-path "$manifest")
  outside=$(jq -r --arg root "$root/" --arg cio "$crates_io" '.packages[] |
    select((if .source == null then .manifest_path | startswith($root)
            else .source == $cio and (.manifest_path | startswith($root + "vendor/crates-io/")) end) | not) |
    "  \(.name) \(.version): \(.source // "path") at \(.manifest_path)"' <<<"$meta")
  echo "$manifest: $(jq '.packages | length' <<<"$meta") packages, $(jq --arg cio "$crates_io" \
    '[.packages[] | select(.source == $cio)] | length' <<<"$meta") from vendor/crates-io"
  [ -z "$outside" ] || { echo "$manifest: read from outside the tree:"; echo "$outside"; fail=1; }
  roots=$(jq -r '.packages[] | (.manifest_path | rtrimstr("Cargo.toml")) as $d | .targets[] |
    select((.src_path | startswith($d)) and (.src_path | contains("/../") | not) and (.src_path | endswith(".rs")) | not) |
    "  \(.name): \(.src_path)"' <<<"$meta")
  [ -z "$roots" ] || { echo "$manifest: targets outside their package or not a .rs file:"; echo "$roots"; fail=1; }
  for target in aarch64-apple-darwin x86_64-apple-darwin; do
    built=$(cargo tree --offline --locked --workspace --all-features -e normal,build,dev \
      --target "$target" --prefix none -f '{p}' --manifest-path "$manifest" |
      sed -E 's/^([^ ]+) v([^ ]+).*/\1-\2/' | sort -u)
    compiled=$(comm -12 <(echo "$stubs") <(echo "$built"))
    [ -z "$compiled" ] || { echo "$manifest $target: stubs compiled:" $compiled; fail=1; }
  done
done
echo "stubs (never built for a Mac): $(grep -c . <<<"$stubs")"
echo "cut copies (checked against their upstream list): $cut"
[ "$fail" -eq 0 ] || { echo "check-vendor: FAIL"; exit 1; }
echo "check-vendor: PASS"

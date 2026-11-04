#!/usr/bin/env bash
# One check command (story E0-S2). Runs every quick gate, keeps going after a
# failure, prints one summary line per gate and exits 1 if any gate failed.
#
#   scripts/check.sh                  run from anywhere
#   FUZZ_SECONDS=60 scripts/check.sh  time per fuzz target (default 30)
#
# Logs: target/check/<step>.log (the name guard skips target/).
# Every cargo build runs --offline --locked from the copies in vendor/ (E0-S7,
# LD-221); cargo-fuzz takes no --locked, so .cargo/config.toml's offline
# setting holds it.
set -u
cd "$(dirname "$0")/.." || exit 1
command -v cargo >/dev/null || . "$HOME/.cargo/env"
# The Swift steps need Xcode; xcode-select may point at the Command Line Tools.
export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
LOGS=target/check
mkdir -p "$LOGS"
FUZZ_SECONDS=${FUZZ_SECONDS:-30}
# 0 means "no limit" to libFuzzer, so only a positive whole number is allowed.
case $FUZZ_SECONDS in '' | *[!0-9]* | 0*) echo "FUZZ_SECONDS must be a positive whole number"; exit 1 ;; esac

bad=""      # failed steps of the current gate
note=""     # extra text for the current gate's summary line
summary=""  # all summary lines
failed=0

line() { local dots=".................."; printf '%s %s %s\n' "$1" "${dots:${#1}}" "$2"; }

# run <step> <command...>: output goes to the step's log; on failure print its tail.
run() {
  local step=$1; shift
  "$@" >"$LOGS/$step.log" 2>&1 && return 0
  bad="$bad $step"
  echo "--- $step FAILED. Last lines of $LOGS/$step.log:"
  tail -n 30 "$LOGS/$step.log"
  return 1
}

# gate <label> <function>: runs one gate and records its summary line.
gate() {
  local status
  echo "--- $1"
  bad="" note=""
  "$2"
  if [ -n "$bad" ]; then status="FAIL (${bad# })"; failed=1
  else case $note in
    SKIP*) status=$note ;;   # a skip counts as a pass
    *) status="PASS${note:+ ($note)}" ;;
  esac; fi
  summary="$summary$(line "$1" "$status")
"
}

# Unsafe count of our own crates. Only larsal-platform and larsal-hwkey may have any;
# every other crate must also carry #![forbid(unsafe_code)] (Rust rule 2).
# Limits: cargo-geiger refuses the virtual root manifest and wants an absolute
# --manifest-path, so it runs once per crate. It reads source, so unsafe made by
# macros is not counted; the forbid line in lib.rs, main.rs and src/bin roots
# covers this crate's own macros only: macros from other crates are not
# reported (UniFFI's scaffolding, LD-157). Build scripts, and macros in tests/, examples/ and benches/
# roots, are not covered: that needs the workspace unsafe_code lint (E0-S1).
# cargo-geiger reads every dep-info file in target/debug, also those of
# packages a lockfile change removed, whose sources are gone (LD-257). So the
# gate first clears target/debug (a cache only) when Cargo.lock is newer than
# its last clean, which the file .lock-clean in it marks (LD-257 (3)).
unsafe_count() {
  local name manifest n f total=0 crates=0 debug=${CARGO_TARGET_DIR:-target}/debug
  if [ ! -e "$debug/.lock-clean" ] || [ Cargo.lock -nt "$debug/.lock-clean" ]; then
    echo "Cargo.lock is newer than the last clean of $debug: cargo clean --profile dev"
    { cargo clean --offline --profile dev && mkdir -p "$debug" && touch "$debug/.lock-clean"; } || return 1
  fi
  while read -r name manifest; do
    n="" f=""
    read -r n f < <(cargo geiger --offline --locked --manifest-path "$manifest" --output-format Json --include-tests </dev/null |
      jq -r --arg n "$name" '.packages[] | select(.package.id.name == $n) | .unsafety |
        "\([.used, .unused | .[].unsafe_] | add) \(.forbids_unsafe)"')
    case "$name:$n:$f" in
      larsal-platform:[0-9]*:* | larsal-hwkey:[0-9]*:* | *:0:true) echo "$name: $n unsafe" ;;
      *:[0-9]*:*) echo "$name: $n unsafe, forbids unsafe: $f (outside larsal-platform and larsal-hwkey: need 0 and #![forbid(unsafe_code)])"; return 1 ;;
      *) echo "$name: cargo-geiger failed (stale build files? run cargo clean)"; return 1 ;;
    esac
    total=$((total + n)) crates=$((crates + 1))
  done < <(cargo metadata --offline --locked --no-deps --format-version 1 | jq -r '.packages[] | "\(.name) \(.manifest_path)"')
  [ "$crates" -gt 0 ] || { echo "no crates found"; return 1; }
  note="unsafe count $total in $crates crates"
}

# Swift format and lint (Swift rule 2), all of macos/. The generated bindings
# in macos/LarsalCore/Generated are skipped: swift format does not follow that
# link, and .swiftlint.yml excludes it.
swift_format() { swift format lint --strict --recursive macos; }
swiftlint_lint() {
  local bin
  bin=$(scripts/install-swiftlint.sh --path)
  [ -x "$bin" ] || { echo "SwiftLint is not installed: run scripts/install-swiftlint.sh"; return 1; }
  (cd macos && "$bin" lint --strict --quiet)
}

g1() {
  run fmt cargo fmt --all -- --check
  run fmt-fuzz cargo fmt --manifest-path fuzz/Cargo.toml -- --check
  run clippy cargo clippy --offline --locked --workspace --all-targets -- -D warnings
  run clippy-app09 cargo clippy --offline --locked -p larsal-ffi --test app09 -- -D warnings  # test = false: not in --all-targets
  run clippy-net cargo clippy --offline --locked -p larsal-platform --features net --all-targets -- -D warnings  # off by default (E6-S7)
  run vendor scripts/check-vendor.sh  # E0-S7: only this tree is read; no stub is built for a Mac
  run server-blind scripts/check-server-blind.sh  # P16 (E16-S3): larsal-server never links the vault reader
  run names-self-test scripts/check-names.sh --self-test  # a broken guard fails G1
  run names scripts/check-names.sh
  run unsafe unsafe_count
  run swift-format swift_format
  run swiftlint swiftlint_lint
}
# Timed tests (MOD-08.22, FEA-01.32, LD-126 (4)) prove their bounds in a
# release build; some run only there.
g2() {
  run test cargo test --offline --locked --workspace
  run test-net cargo test --offline --locked -p larsal-platform --features net  # the opt-in network client, off by default (E6-S7)
  run test-release cargo test --offline --locked --release -p larsal-core --test fea01 --test fea05 --test fea06 --test fea07 --test mod08 --test mod11
  run test-release-browser cargo test --offline --locked --release -p larsal-browser --test int03  # INT-03.17's timed bounds (F-244, F-245)
  # The Mac app: the Rust core as a Swift package, then the unit tests, then
  # the APP-09 cases that run the built Larsal.app (each with its own instance
  # folder). The UI tests need a logged-in screen and run in Mac QA (G8).
  run build-core scripts/build-core.sh &&
    run xcode-test xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS \
      -derivedDataPath target/xcode test -skip-testing:LarsalUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES &&
    run app09 cargo test --offline --locked -p larsal-ffi --test app09
}
# F-114: the fuzz workspace has the same policy; its run reads deny.toml
# without the `larsal-platform/net` feature line, which only the root has.
deny_fuzz() {
  sed '/^features = \["larsal-platform\/net"\]$/d' deny.toml >"$LOGS/deny-fuzz.toml"
  cargo deny --offline --locked --manifest-path fuzz/Cargo.toml --config "$LOGS/deny-fuzz.toml" check
}
deny() {
  run deny cargo deny --offline --locked check
  run deny-fuzz deny_fuzz
}
# F-113: cargo audit matches packages by name, version and crates.io source
# in a lockfile, and the [patch] path copies (vendor/zxcvbn LD-136,
# vendor/ssh-key LD-209) have no source there, so it skips them. Their list,
# one vendor/<name>/Cargo.toml each with the upstream name and version, goes
# to a lockfile of its own as crates.io packages. The plain copies in
# vendor/crates-io keep their crates.io entries in Cargo.lock.
audit_copies() {
  local lock=$LOGS/path-copies.lock m
  echo 'version = 4' >"$lock"
  for m in vendor/*/Cargo.toml; do
    awk -F'"' '/^\[/ { p = ($0 == "[package]") } p && /^name = / { n = $2 } p && /^version = / { v = $2 }
      END { printf "\n[[package]]\nname = \"%s\"\nversion = \"%s\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n", n, v }' "$m" >>"$lock"
  done
  grep -A1 '^name = ' "$lock"
  grep -q '^name = ' "$lock" || { echo "no path copies found in vendor/"; return 1; }
  cargo audit -n -f "$lock"
}
audit() {
  run audit cargo audit -n
  run audit-fuzz cargo audit -n -f fuzz/Cargo.lock  # F-114
  run audit-copies audit_copies                       # F-113
}
# Target names only in the list log; stderr joins it only when the command fails.
fuzz_list() {
  cargo +nightly fuzz list 2>"$LOGS/fuzz-list.err" || { cat "$LOGS/fuzz-list.err" >&2; return 1; }
}
# Wait in the parent so every worker failure reaches the gate summary.
fuzz_wait() {
  local pid step
  while [ "$#" -gt 0 ]; do
    pid=$1 step=$2; shift 2
    if ! wait "$pid"; then
      bad="$bad $step"
      echo "--- $step FAILED. Last lines of $LOGS/$step.log:"
      tail -n 30 "$LOGS/$step.log"
    fi
  done
}
fuzz() {
  local t list=$LOGS/fuzz-list.log
  local -a pending=()
  [ -f fuzz/Cargo.toml ] || { note="SKIP (no fuzz targets yet)"; return; }
  run fuzz-list fuzz_list || return
  [ -s "$list" ] || { note="SKIP (no fuzz targets yet)"; return; }
  # The smoke reads only the seeds in fuzz/corpus/<target>; new units go to a
  # fresh fuzz/target/smoke/<target>, which the name guard skips (a document the
  # fuzzer finds can hold the root element name as text, AGENTS.md rule 1).
  # The grown corpus of the long runs (fuzz/target/corpus) is not loaded: it
  # takes minutes per target (Checker, 2026-10-27).
  # Four independent targets at a time; keep each target's full time and seeds.
  for t in $(cat "$list"); do
    (
      rm -rf "fuzz/target/smoke/$t" && mkdir -p "fuzz/target/smoke/$t" &&
        cargo +nightly fuzz run "$t" "fuzz/target/smoke/$t" "fuzz/corpus/$t" -- -max_total_time="$FUZZ_SECONDS"
    ) >"$LOGS/fuzz-$t.log" 2>&1 &
    pending+=("$!" "fuzz-$t")
    if [ "${#pending[@]}" -eq 8 ]; then
      fuzz_wait "${pending[@]}"
      pending=()
    fi
  done
  if [ "${#pending[@]}" -gt 0 ]; then fuzz_wait "${pending[@]}"; fi
  note="$(wc -l <"$list" | tr -d ' ') targets, ${FUZZ_SECONDS}s each"
}

gate "G1 static" g1
gate "G2 tests" g2
gate "deny" deny
gate "audit" audit
gate "fuzz smoke" fuzz

echo
printf '%s' "$summary"
[ "$failed" -eq 0 ] && { line Overall PASS; exit 0; }
line Overall "FAIL (logs in $LOGS/)"
exit 1

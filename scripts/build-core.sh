#!/usr/bin/env bash
# Builds the Rust core for the Mac app (LD-156 (2)):
#   1. larsal-ffi as a static library (host target, aarch64-apple-darwin);
#   2. its Swift bindings, C header and module map (uniffi-bindgen-swift,
#      library mode);
#   3. LarsalFFI.xcframework from the library and the header;
#   4. the local package macos/LarsalCore finds both through its Generated link;
#   5. the third-party notices for Larsal.app (scripts/make-sbom.sh, E14-S2);
#   6. larsal-bridge, the browsers' host program (E7-S6, INT-01.4), which the
#      Xcode project copies into Larsal.app/Contents/MacOS.
# Everything it makes is in target/larsal-core/ and is never kept in the source
# tree. The x86_64 slice and lipo wait for E14.
#
#   scripts/build-core.sh             debug core, for check.sh
#   scripts/build-core.sh --release   optimized core for a Release app (Rust rule 11)
#   scripts/build-core.sh --no-net    with no network code at all (SN-05, F-093);
#                                     combines with --release
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || . "$HOME/.cargo/env"
export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
# The app's deployment target (macos/Larsal.xcodeproj): rustc and the C parts
# that `cc` compiles (ring, under `net`) build for it, so the linker sees one
# macOS version.
export MACOSX_DEPLOYMENT_TARGET=14.0

profile=debug cargo_flags=() features=(--features net)
for arg in "$@"; do
  case "$arg" in
    --release) profile=release cargo_flags=(--release) ;;
    --no-net) features=() ;;
    *) echo "build-core: unknown argument $arg (only --release, --no-net)" >&2; exit 2 ;;
  esac
done
out=${CARGO_TARGET_DIR:-target}/larsal-core
lib=${CARGO_TARGET_DIR:-target}/$profile/liblarsal_ffi.a  # cargo's output folder (E14-S4)
bindgen=${CARGO_TARGET_DIR:-target}/debug/uniffi-bindgen-swift

# Two cargo runs: built together, the generator's command line crates would
# be unified into larsal-ffi's uniffi and land in the static library.
# `net`: the HTTPS client of the breach check (E5-S7, FEA-06) and the icon
# download (F-094); it connects only when the user asks (SN-01). --no-net
# leaves it out: the online check and the icon download then say that this
# build of Larsal has no network code.
cargo build --offline --locked ${cargo_flags[@]+"${cargo_flags[@]}"} -p larsal-ffi ${features[@]+"${features[@]}"}
cargo build --offline --locked -p uniffi-bindgen
# Its own run too: built with larsal-ffi, cargo would unify larsal-platform's
# features (AppKit, the zeroing allocator) into the relay, which links libc only.
cargo build --offline --locked ${cargo_flags[@]+"${cargo_flags[@]}"} -p larsal-bridge

rm -rf "$out"
mkdir -p "$out/Swift" "$out/include"
"$bindgen" --swift-sources "$lib" "$out/Swift"
"$bindgen" --headers --modulemap --module-name LarsalFFI \
  --modulemap-filename module.modulemap "$lib" "$out/include"
xcodebuild -create-xcframework -library "$lib" -headers "$out/include" \
  -output "$out/LarsalFFI.xcframework" >/dev/null
ln -sfn "$(cd "$out" && pwd -P)" macos/LarsalCore/Generated
cp "${CARGO_TARGET_DIR:-target}/$profile/larsal-bridge" "$out/larsal-bridge"
# E14-S2: the third-party notices and bill of materials for Larsal.app; the
# Xcode project copies them, with LICENSE, into the bundle's Resources.
scripts/make-sbom.sh "$out/notices"
echo "build-core ($profile): $out/LarsalFFI.xcframework, $out/Swift/LarsalCore.swift and $out/larsal-bridge"

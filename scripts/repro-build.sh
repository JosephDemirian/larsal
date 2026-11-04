#!/usr/bin/env bash
# Reproducible release build (E14-S4, AT-J04, LD-222): the `larsal` tool,
# liblarsal_ffi.a, larsal-bridge (E7-S6) and Larsal.app from this tree with fixed
# settings, then their SHA-256. It copies the tree to one fixed folder, /private/tmp/larsal-repro,
# and builds there from empty folders, so two runs give the same hashes
# wherever the tree is, on the same toolchain (BUILDINFO). One run at a time.
#
#   scripts/repro-build.sh            larsal tool, core library and Larsal.app
#   scripts/repro-build.sh --rust     larsal tool, core library and larsal-bridge only
#   scripts/repro-build.sh --no-net   the core with no network code (SN-05, F-093);
#                                     combines with --rust
#
# Output in ${CARGO_TARGET_DIR:-target}/repro/ of the tree it was started
# from: the four, the bill of materials and notices (scripts/make-sbom.sh),
# BUILDINFO and SHA256SUMS of them all.
# Signing waits for D7 (E14-S3): Larsal.app is signed ad hoc, as every local build.
set -euo pipefail
cd -P "$(dirname "$0")/.."
command -v cargo >/dev/null || . "$HOME/.cargo/env"
export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}

app=yes net=(--features net) core_args=()
for arg in "$@"; do
  case "$arg" in
    --rust) app= ;;
    --no-net) net=() core_args=(--no-net) ;;
    *) echo "repro-build: unknown argument $arg (only --rust, --no-net)" >&2; exit 2 ;;
  esac
done

# One fixed build path (reproducible-builds.org/docs/build-path; Debian
# records it in .buildinfo): the maps below take the path out as text, but
# not its length. Swift passes the unmapped file name's length to its closure
# check, and the linker's UUID counts the length of the object paths.
root=/private/tmp/larsal-repro
if [ "$(pwd -P)" != "$root/src" ]; then
  out=${CARGO_TARGET_DIR:-$PWD/target}/repro
  mkdir "$root" || { echo "repro-build: $root is in use (another run; remove it if none runs)" >&2; exit 1; }
  trap 'rm -rf "$root"' EXIT
  rsync -a --exclude /target --exclude /fuzz/target --exclude /larsal-shots ./ "$root/src/"
  CARGO_TARGET_DIR=$root/target "$root/src/scripts/repro-build.sh" "$@"
  rm -rf "$out" && mkdir -p "$out" && ditto "$root/target/repro" "$out"
  echo "repro-build: copied to $out"
  exit 0
fi

# Physical paths (pwd -P): the linker and SwiftPM resolve links (/tmp is
# /private/tmp), so a map from a logical path would not match.
src=$(pwd -P)
target=${CARGO_TARGET_DIR:-$src/target}
mkdir -p "$target" && target=$(cd -P "$target" && pwd -P)
cargo_home=$(cd -P "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)

# Fixed inputs (reproducible-builds.org): one time stamp for every tool that
# reads one (no git yet, rule 6; then `git log -1 --format=%ct`), archive
# members without dates, the same macOS floor as build-core.sh.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1793232000} # 2026-10-29 00:00 UTC
export ZERO_AR_DATE=1
export MACOSX_DEPLOYMENT_TARGET=14.0
export CARGO_INCREMENTAL=0
# LD-303 (4): libsqlite3-sys (larsal-server) builds its bundled SQLite as
# shipped: no system SQLite through pkg-config, no extra C flags, no changed
# limits. Its build script reads these from the environment.
unset LIBSQLITE3_SYS_USE_PKG_CONFIG LIBSQLITE3_FLAGS $(compgen -e | grep '^SQLITE_MAX_' || true)
# No build path or user name in the output: the tree, cargo's home and the
# target folder become fixed names (the last matching prefix wins, so the
# target folder, which may sit inside the tree, comes last). The C parts
# (ring) get the same map. RUSTFLAGS is not in cargo's symbol hash (cargo 1.39).
# The linker's UUID counts the length of the debug map's object paths, and one
# is the toolchain in the home folder: -S writes no debug map (`larsal` is
# stripped anyway), so the user name's length cannot change the hash.
export RUSTFLAGS="--remap-path-prefix=$src=/larsal --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$target=/target -C link-arg=-Wl,-reproducible -C link-arg=-Wl,-S"
export CFLAGS="-ffile-prefix-map=$src=/larsal -ffile-prefix-map=$cargo_home=/cargo -ffile-prefix-map=$target=/target"
export CARGO_TARGET_DIR=$target

# Separate runs, as in build-core.sh: built together, cargo would unify
# larsal-ffi's `net` feature into the app tool.
cargo build --release --offline --locked -p larsal-cli
cargo build --release --offline --locked -p larsal-ffi ${net[@]+"${net[@]}"}
# E7-S6: the browsers' host program, also in its own run (libc only).
cargo build --release --offline --locked -p larsal-bridge
out=$target/repro
rm -rf "$out" && mkdir -p "$out"
cp "$target/release/larsal" "$target/release/liblarsal_ffi.a" "$target/release/larsal-bridge" LICENSE "$out/"

if [ -n "$app" ]; then
  scripts/build-core.sh --release ${core_args[@]+"${core_args[@]}"}
  dd=$target/xcode-release
  # Stripped as an archive is (the debug map holds object paths; the dSYM
  # keeps the debug info), Swift's #filePath mapped. Xcode links with
  # -reproducible itself. It writes /private/tmp paths as /tmp: both forms.
  # Apple's linker lays out objc_msgSend selector stubs in a different order
  # from link to link (same inputs, LD-222), so Swift calls objc_msgSend directly.
  xcb() { xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -configuration Release \
    -destination platform=macOS -derivedDataPath "$dd" build \
    DEPLOYMENT_POSTPROCESSING=YES STRIP_INSTALLED_PRODUCT=YES \
    OTHER_SWIFT_FLAGS="\$(inherited) -file-prefix-map $src=/larsal -file-prefix-map ${src#/private}=/larsal -file-prefix-map $dd=/dd -file-prefix-map ${dd#/private}=/dd -Xfrontend -disable-objc-msgsend-selector-stubs" \
    >>"$out/xcodebuild.log" 2>&1 ||
    { tail -30 "$out/xcodebuild.log" >&2; exit 1; }; }
  xcb
  # actool races when it writes the catalog's appearance table: about one
  # compile in ten puts the names (DarkAqua, System) in another order, and
  # CodeResources and the executable's signature follow (LD-222). The file is
  # not edited: Larsal is built again from an empty derived-data folder until the
  # names are in sorted order, the usual one. (Deleting only the bundle's copy
  # does not work: Xcode copies its compiled one back and does not sign again.)
  app_dir=$dd/Build/Products/Release/Larsal.app
  for try in 1 2 3 4 5 6 7 8; do
    python3 -I -c 'import re,sys; n=re.findall(rb"NSAppearanceName\w+", open(sys.argv[1],"rb").read()); sys.exit(n != sorted(n))' \
      "$app_dir/Contents/Resources/Assets.car" && break
    [ "$try" = 8 ] && { echo "repro-build: Assets.car kept another appearance order 8 times" >&2; exit 1; }
    echo "repro-build: Assets.car appearance order differs, building Larsal again"
    rm -rf "$dd"; xcb
  done
  codesign --verify --strict "$app_dir"
  ditto "$dd/Build/Products/Release/Larsal.app" "$out/Larsal.app"
fi

scripts/make-sbom.sh "$out"

# No build folder, tree or home folder (the user name) left in any output.
if grep -rlF -e "$src" -e "${src#/private}" -e "$target" -e "${target#/private}" -e "$HOME" \
  --exclude=xcodebuild.log "$out"; then
  echo "repro-build: the files above hold a build path" >&2; exit 1
fi
cd "$out"
# The build environment, as Debian's .buildinfo: a rebuild needs the same.
{ echo "Build path: $root"; echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"; rustc -vV; cargo -V
  if [ -n "$app" ]; then xcodebuild -version; echo "macOS SDK: $(xcrun --sdk macosx --show-sdk-build-version)"; fi
  echo "macOS: $(sw_vers -productVersion) ($(sw_vers -buildVersion))"; } >BUILDINFO
find . -type f ! -name SHA256SUMS ! -name xcodebuild.log -print0 | LC_ALL=C sort -z |
  xargs -0 shasum -a 256 >SHA256SUMS
grep -E ' \./(larsal|liblarsal_ffi\.a|larsal-bridge|Larsal\.app/Contents/MacOS/(Larsal|larsal-bridge))$' SHA256SUMS
echo "repro-build: $(wc -l <SHA256SUMS | tr -d ' ') files hashed in $out/SHA256SUMS"

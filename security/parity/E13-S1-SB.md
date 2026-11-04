# E13-S1 parity sign-off: Build and supply chain (SB)

Rows: SB-01, SB-02, SB-03 in [plan/security.md](../../plan/security.md). Story: E13-S1.
Date: 2026-10-29. Verify agent, group SB.

| Row | Result |
|---|---|
| SB-01 | Waits for D7 (E14-S3). Today's tree checked as far as it goes without a signing team. |
| SB-02 | **Verified** |
| SB-03 | Waits for E14-S4 (running now) and for a signing key (D7, E14-S3 or E14-S6). |

How it was run: the reference source and the installed reference app were read only. The reference's bundle was inspected with `codesign` and `spctl`; it was never launched. Our checks ran on the shared tree read only, with `CARGO_TARGET_DIR=/tmp/e13s1-target`. Every probe and the Release build ran in a private copy (`/tmp/e13s1-SB-copy`, rsync without `target` and `app-shots`, its own target and derived data folders). Both folders were deleted at the end. `cargo deny` and `cargo audit` ran offline (`--frozen`, `--no-fetch`) against advisory databases fetched earlier today (last advisory commit 2026-10-29 15:05, 1386 advisories), so nothing left this Mac. One exception to note: `spctl` on the reference's bundle, which has no stapled ticket, lets the system look up its notarization ticket from Apple, as Gatekeeper does at any first launch; it sends that bundle's code hash, no project data.

## SB-01 Signed and notarized builds, hardened runtime, one Keychain access group

**Reference.** The installed 2.7.11 bundle carries a Developer ID signature with a secure time stamp. Its code directory has the hardened runtime flag. Its entitlements are the application identifier and one `keychain-access-groups` entry for its own team and bundle id, nothing else: no `get-task-allow`, no library-validation, JIT or dyld-environment exception. Gatekeeper accepts it as "Notarized Developer ID". The notarization ticket is **not** stapled to the installed bundle (`stapler validate`: "does not have a ticket stapled to it"), so an offline Mac cannot check its notarization on first launch.

```
$ codesign -dv --verbose=2 <reference bundle>
CodeDirectory v=20500 size=12323 flags=0x10000(runtime) hashes=374+7 location=embedded
Authority=Developer ID Application: <reference team>
Timestamp=Nov 25, 2025 at 1:25:11 AM
Runtime Version=26.1.0
$ codesign -d --entitlements - --xml <reference bundle> | plutil -p -
  "com.apple.application-identifier" => "<team>.<bundle id>"
  "keychain-access-groups" => [ 0 => "<team>.<bundle id>" ]
$ spctl -a -vv <reference bundle>
accepted
source=Notarized Developer ID
$ xcrun stapler validate <reference bundle>
... does not have a ticket stapled to it.
```

**App today.** `macos/App.xcodeproj` sets `ENABLE_HARDENED_RUNTIME = YES` for the App target in Debug and Release, signs ad hoc (`CODE_SIGN_IDENTITY = "-"`) and has no entitlements file. The plan for the release (E14-S3, LD-156 (8)) is Developer ID, `notarytool`, `stapler staple` and the one entitlement `keychain-access-groups`. A Release App.app built today from a private copy:

```
$ scripts/build-core.sh --release && xcodebuild -project macos/App.xcodeproj -scheme App \
    -configuration Release -destination platform=macOS -derivedDataPath <copy>/dd build SWIFT_TREAT_WARNINGS_AS_ERRORS=YES
** BUILD SUCCEEDED **   (16 min 52 s wall clock, 75 s CPU)
$ codesign -dv --verbose=2 App.app
Identifier=com.app.desktop
Format=app bundle with Mach-O thin (arm64)
CodeDirectory v=20500 size=34896 flags=0x10002(adhoc,runtime) hashes=1084+3 location=embedded
Signature=adhoc
TeamIdentifier=not set
$ codesign -d --entitlements - --xml App.app     -> no entitlements at all (so no get-task-allow)
$ codesign --verify --strict --verbose=2 App.app -> valid on disk, satisfies its Designated Requirement
$ spctl -a -vv -t exec App.app                   -> rejected (ad hoc, as expected before D7)
```

The hardened runtime flag is on and there is no `get-task-allow` and no exception entitlement. Missing today, by plan: the Developer ID signature, the time stamp, notarization, the stapled ticket and the `keychain-access-groups` entitlement (needed only from E6-S3 Touch ID onward).

**Result: waits for D7.** Developer ID signing, notarization and stapling need the Apple signing team (README D7, W-02); AT-J05 runs in E14-S3. The hardened runtime part is already on in today's Release build. Note for E14-S3: our plan staples the ticket, which the reference's installed bundle does not do, so App will check offline too.

## SB-02 Pins and checks dependencies

**Reference.** Its dependency manifest pins the package registry to one fixed commit (a "builtin baseline" hash), so a build gets the library versions of that commit; the registry's port files carry the hash of each source download. The build script refuses libraries older than a floor (Qt 6.2.4, Botan 2.19.1, zlib 1.2.0). A release can also be built against the system's libraries instead, with only those floors. Its CI runs static code scanning of its own C++ code on every push, pull request and weekly; the repository has no dependency vulnerability scan and no license or source policy for its libraries.

**App today.**

1. Every third-party crate is pinned exactly, and only once, in the root `[workspace.dependencies]`; the 11 crates of the workspace name them with `workspace = true`. Read from `cargo metadata --locked --offline`: 66 non-path dependency entries in our crates, every requirement starts with `=`, every source is crates.io. All 44 direct crates are on the approved list in plan/architecture.md. The fuzz workspace pins its own few crates with `=` too.
2. The lock file holds the whole graph with a SHA-256 per crate: `Cargo.lock` 267 packages, 13 our own, 254 from crates.io, 254 with a checksum; `fuzz/Cargo.lock` 127 packages, 117 from crates.io, 117 with a checksum. Two patched crates are kept as source in `vendor/` (LD-136, LD-209). The toolchain is pinned (`rust-toolchain.toml`: 1.99.1). The Mac app has no remote Swift packages (0 `XCRemoteSwiftPackageReference`; only the local `AppCore`). SwiftLint, the one downloaded tool, is checked against a pinned SHA-256 before it is unpacked (`scripts/install-swiftlint.sh`). The release script being built in E14-S4 (`scripts/repro-build.sh`) builds with `--locked`.
3. Two gates check the graph (the `deny` and `audit` gates of `scripts/check.sh`, run here directly): `cargo deny` (known vulnerabilities and yanked versions are errors; licenses on an allowlist; crates.io only, unknown registries and git sources denied; no wildcards; no OpenSSL or native TLS; one version of every crypto and key-encoding crate) and `cargo audit`.

```
$ cargo metadata --format-version 1 --no-deps --locked --offline   -> exit 0 (lock file current)
$ cargo deny --frozen check        -> exit 0
advisories ok, bans ok, licenses ok, sources ok
  (one warning: two versions of syn, build-time; multiple-versions is "warn" outside the crypto list)
$ cargo audit --no-fetch           -> exit 0
      Loaded 1386 security advisories (from ~/.cargo/advisory-db)
    Scanning Cargo.lock for vulnerabilities (267 crate dependencies)
  one allowed warning: RUSTSEC-2026-0374 basic-toml unmaintained (build-time, in the UniFFI generator, ignored in deny.toml with its reason)
$ cargo audit --no-fetch -f fuzz/Cargo.lock   -> exit 0, 127 crate dependencies, nothing found
```

Probes in the private copy (each undone before the next):

| Probe | Command | Result |
|---|---|---|
| P1 a vulnerable version in the lock file: quick-xml 0.42.0 changed to 0.40.0 | `cargo audit --no-fetch` | exit 1: RUSTSEC-2026-0194 and RUSTSEC-2026-0195, "error: 2 vulnerabilities found!" |
| P2 one digit of quick-xml's SHA-256 changed in the lock file | `cargo fetch --locked --offline` | exit 101: "error: checksum for `quick-xml v0.42.0` changed between lock files" |
| P3 app-format asks for `quick-xml = "*"` instead of the workspace pin | `cargo deny --frozen check bans` | exit 2: `error[wildcard]` for app-format and `error[workspace-duplicate]` (a declaration bypasses the workspace pin); lock file unchanged |
| P4 quick-xml's source in the lock file changed to another registry | `cargo deny --frozen check sources` | exit 1: cargo refuses the lock file ("cannot update the lock file ... --frozen"); the deny `sources` rule itself was not reached offline, it is shown by the policy above and the PASS |

**Result: verified.** App pins every crate exactly and by hash, and checks the graph for vulnerabilities, licenses, sources and duplicates on every check run. The reference pins one registry commit and checks version floors only. App is at least as strong.

## SB-03 Detached signature and SHA-256 digest for every release file; App adds reproducible builds

**Reference.** Its release tool has a sign command: for every release file it writes an ASCII-armored detached GPG signature (`<file>.sig`) and a digest file (`<file>.DIGEST`, one line "SHA-256 hash, two spaces, file name").

**App today.** No release file exists yet. E14-S4 (running now) is writing `scripts/repro-build.sh`: a fixed-input release build that writes `SHA256SUMS` for the `app` tool, `libapp_ffi.a` and App.app; AT-J04 (two builds, same hashes) is its check. Not run here: it is another agent's open story and two full release builds. No step makes a detached signature of the release files yet, and no story names one: E14-S3 is Apple code signing and notarization, E14-S4 is the reproducible build and bill of materials, E14-S6 is publication.

**Result: waits for E14-S4** (digest and reproducible build) and for a release signing key (D7, E14-S3 or E14-S6). Finding returned to the lead: the detached signature has no owning story or acceptance check.

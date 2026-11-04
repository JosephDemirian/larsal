# App

A password manager written in Rust. Mac first. Open source.
The owner named it **Larsal** on 2026-11-02: what it is and where the name comes from are in [ABOUT.md](ABOUT.md). The code says "App" until the rename pass (E14-S1).

**Status:** planning. Nothing is built yet.

## What it will be

- Every feature of the reference app, rebuilt in Rust with our own structure and names.
- The same vault file format (version 4 to read and write, version 3 to read) and the same algorithms: AES-256 or ChaCha20 to encrypt the file, Argon2 to harden the master password. Vaults open in both apps.
- Proven crypto libraries only. We never write our own cipher.
- The look in [design/mockup.html](design/mockup.html).
- Proof before trust: every security feature of the reference app is listed, built, attacked and signed off ([plan/security.md](plan/security.md)).

## Read in this order

1. [AGENTS.md](AGENTS.md): rules for every agent.
2. [plan/architecture.md](plan/architecture.md): components, folders, files, approved crates, Rust rules.
3. [plan/security.md](plan/security.md): what we protect, and the security features we must match.
4. [plan/attacks-and-checks.md](plan/attacks-and-checks.md): attacks we try, checks we run.
5. [plan/epics.md](plan/epics.md): epics, stories, sprints, the board.
6. [plan/team.md](plan/team.md): agent roles and how work moves.
7. [spec/README.md](spec/README.md): behavior cards.

## Owner decisions

| # | Decision | Until decided | Recommendation |
|---|---|---|---|
| D1 | Product name | **Decided by the owner 2026-11-02: Larsal** ([ABOUT.md](ABOUT.md)); "App" stays in the code until the rename pass (E14-S1) | Check trademarks and the domains (larsal.app, larsal.com) before the rename |
| D2 | License | **Decided by the owner 2026-10-31:** Mac app GPL-3.0-or-later; sync server AGPL-3.0; team features under App's own paid license; contributors sign App's contributor agreement (plan/product-vision.md, LD-262) | GPL-3.0-or-later, so forks stay open |
| D3 | Screen layer | **Decided by the owner 2026-10-27:** native macOS, Swift screens, Rust engine | Swift screens (SwiftUI) over the Rust engine as a library, joined by generated bindings, the way proven password managers do it (LD-155, LD-156). Not Tauri. |
| D4 | Browser extension | **Decided by the owner 2026-10-31:** our own extension for every major browser, Chrome and Safari first (E7), plus a web version served by App's server (LD-272). Your steps later, none blocks today (LD-274 (8)): yes to download Rust's wasm32 standard library; yes to install Edge, Vivaldi, Opera and Arc for tests; the store accounts and fees; the domain; hosting | Our own extension right after the Mac app (E7). The reference app's extension can't be used: it would put its name in our code. |
| D5 | Git | **Decided by the owner 2026-11-04:** initialize git, push to `https://github.com/JosephDemirian/larsal.git`, and keep small, clear commits under the owner's name only (LD-342) | Commit each checked change; keep build output and local state out of git |
| D6 | Outside security audit before 1.0 | **Owner 2026-10-31: yes**, booked before any sync server ships; the owner books and pays (LD-262) | Yes. It costs money, so the owner decides. |
| D7 | Apple Developer account ($99 a year) | Not bought | Buy before E14, for signed and notarized builds. Also needed for Touch ID quick unlock in signed builds (provisioning profile, TN3137). Until then E6-S3 can use a free personal signing team, which needs the owner's Apple ID in Xcode (owner item). |

## Checks

Run `scripts/check.sh` from any folder. It runs every quick gate from [plan/attacks-and-checks.md](plan/attacks-and-checks.md), even after one fails:

- **G1 static:** `cargo fmt --check`, `cargo clippy` with warnings as errors (also for the opt-in network client, `app-platform --features net`), the name guard `scripts/check-names.sh` (its `--self-test` first, then the scan), and the `cargo-geiger` unsafe count (only `app-platform` and `app-hwkey` may have unsafe code; every other crate, `app-ffi` included, must carry `#![forbid(unsafe_code)]`: rustc does not report the `unsafe` that UniFFI's macros generate, and refuses hand-written `unsafe`). Then `swift format lint --strict --recursive` on `macos/App`, `macos/AppTests` and `macos/AppCore/Package.swift`, and `swiftlint lint --strict` in `macos/` (SwiftLint 0.65.1, pinned with its SHA-256 checksum in `scripts/install-swiftlint.sh`; run that script once to install it). The generated bindings are not linted.
- **G2 tests:** `cargo test --workspace`, the network client's tests (`cargo test -p app-platform --features net`, local servers only), and the timed tests in a release build. Then `scripts/build-core.sh` (the Rust core as the Swift package `AppCore`; its output is in `target/app-core/`, never kept), then `xcodebuild test` on scheme `App` with `-skip-testing:AppUITests` and warnings as errors (build output in `target/xcode/`), then the APP-09 cases that run the built `App.app` (`cargo test -p app-ffi --test app09`; not part of `cargo test --workspace`, which runs before the app is built). The UI tests (`AppUITests`) need a logged-in screen, so they run in Mac QA (G8), not here.
- **deny:** `cargo deny check`. **audit:** `cargo audit`.
- **fuzz smoke:** each target in `fuzz/` for 30 seconds with the nightly toolchain (`FUZZ_SECONDS=60 scripts/check.sh` to change it). Skipped until fuzz targets exist.

It prints one line per gate and exits 1 if any gate failed. Logs are in `target/check/`.

The pinned toolchain (`rust-toolchain.toml`) installs with `rustup toolchain install 1.99.1` if rustup does not fetch it.

The Swift steps need Xcode (27.0 on this Mac), not the Command Line Tools that `xcode-select` points at. The scripts set `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` when it is unset. By hand:

```
scripts/build-core.sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  xcodebuild -project macos/App.xcodeproj -scheme App -destination 'platform=macOS' test
```

To build App with no network code at all (SN-05), add `--no-net` to `scripts/build-core.sh` (or to `scripts/repro-build.sh`): the core is built without app-ffi's `net` feature, and the online password check and the website icon download then say that this build has no network code.

## License

App is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version (SPDX: `GPL-3.0-or-later`).

App is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with App, in [LICENSE](LICENSE). If not, see <https://www.gnu.org/licenses/>.

Copyright (C) 2026 [Licensor legal name]. The server (when built), the paid team features and the contributor agreement: [legal/README.md](legal/README.md).

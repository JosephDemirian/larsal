# Architecture

Current original material in the client, server, team features, extension and web vault uses the [Larsal Source-Available License 1.0](../LICENSE). License columns below refer to that file. Third-party material retains its own terms, including MPL-2.0 covered files and modifications, permissive code, CC data and OFL fonts. Earlier grants and signed agreements remain valid. The former license split in LD-262 and LD-266 is historical; the contributor and team-license drafts are withdrawn for new use (LD-345, [legal/README.md](../legal/README.md)).

## The shape

One Rust workspace. The core is plain Rust: no screen, no operating system calls. The Mac app is native: SwiftUI screens in `macos/` over the Rust engine, linked in as a library and joined by bindings that UniFFI generates (README D3, LD-155, LD-156; the layout comes from [native-app-research.md](native-app-research.md)).

```
macos/      ── SwiftUI screens from design/mockup.html, lock signals, window guard
 │   only the functions larsal-ffi exports (UniFFI)
 ▼
larsal-ffi     ── the bindings crate: holds the open vaults (the session), auto-save, events
 │       └── larsal-platform: clipboard, Touch ID Keychain, hardening, network (used by larsal-ffi and larsal-cli)
 ▼
larsal-core    ── every operation on a vault
 ▼
larsal-format  ── reads and writes vault files and key files
 ▼
larsal-model   ── the data types
larsal-crypto  ── the only door to crypto crates
larsal-qr      ── the QR matrix and Wi-Fi join text of Show as QR Code; the only importer of `qrcode` (used by larsal-ffi and larsal-cli)

Plug-ins to larsal-ffi: larsal-browser (E7), larsal-autotype (E8), larsal-sshagent (E9), larsal-hwkey (E10), larsal-share (E11), larsal-files (E22; reached from E22-S4), larsal-folders (E23; reached from E23-S4)
larsal-cli: the command line tool, built on larsal-core and larsal-platform, and larsal-qr for `show --qr`
```

Dependencies point down only. `larsal-crypto` depends on no other crate of ours; `larsal-model` depends only on `larsal-crypto`, for its secret types (spec/decisions.md LD-75).

## Folders

```
.
├── AGENTS.md, CLAUDE.md, README.md
├── Cargo.toml               workspace
├── rust-toolchain.toml      pinned Rust version
├── deny.toml                dependency policy: licenses, advisories, sources, bans
├── crates/
│   ├── larsal-crypto/
│   ├── larsal-model/
│   ├── larsal-format/
│   ├── larsal-core/
│   ├── larsal-platform/
│   ├── larsal-ffi/             the bindings crate: the only crate that exports to Swift
│   ├── larsal-cli/
│   ├── larsal-qr/              (E21-S3) Show as QR Code's encoder, shared by larsal-ffi and larsal-cli
│   ├── larsal-browser/         (E7)
│   ├── larsal-autotype/        (E8)
│   ├── larsal-sshagent/        (E9)
│   ├── larsal-hwkey/           (E10)
│   ├── larsal-share/           (E11)
│   ├── larsal-files/           (E22) file encryption in the public file format
│   ├── larsal-folders/         (E23) encrypted folders in the public classic format 8
│   └── uniffi-bindgen/      the bindings generator, pinned to the same UniFFI version
├── macos/                   Larsal.xcodeproj, Larsal/, LarsalTests/, LarsalUITests/, Larsal.entitlements, LarsalCore/Package.swift
├── extension/               our browser extension (E7, decision D4)
├── fuzz/                    cargo-fuzz targets
├── vendor/                  every outside package as Larsal's own copy (E0-S7, LD-221): crates-io/ (cargo vendor --versioned-dirs), zxcvbn/, ssh-key/, uniffi/, uniffi_core/, uniffi_bindgen/, ureq/ and ureq-proto/ (patched copies)
├── .cargo/config.toml       source replacement: crates.io read from vendor/crates-io, offline
├── testdata/                demo vaults and their expected exports
├── tests/                   cross-crate, interop and end-to-end tests
├── scripts/                 check.sh, check-names.sh, check-vendor.sh, make-testdata.sh, interop.sh, build-core.sh, repro-build.sh, make-sbom.sh
├── spec/                    behavior cards (clean room)
├── security/                findings and parity evidence
├── qa/                      Mac QA reports and screenshots
├── plan/                    this plan
└── design/                  mockup.html
```

The generated `LarsalFFI.xcframework` and Swift sources are not kept: `scripts/build-core.sh` makes them on every build.

## Components

### larsal-crypto

The only crate that imports crypto crates. Small enough to read in one sitting.

| File | What it does |
|---|---|
| `secret.rs` | `SecretBytes`, `SecretString`: memory wiped on drop, no `Clone`, `Debug` prints `[hidden]`, no `Display`, constant-time equality |
| `random.rs` | The OS random source only: `fill`, `bytes(n)`, `below(n)` without bias. Fails closed if the OS source fails. |
| `hash.rs` | SHA-256, SHA-512, SHA-1 (SHA-1 only where a format or standard demands it) |
| `mac.rs` | HMAC-SHA-256, HMAC-SHA-1, HMAC-SHA-512 (one-time passwords, FEA-04), constant-time verify. E23: HMAC-SHA-384 and -512 checks (RFC 4231). |
| `cipher.rs` | AES-256-CBC with PKCS#7 padding, Twofish-CBC, ChaCha20. Encrypt and decrypt, streaming for large data. One generic error for any decrypt failure. |
| `stream.rs` | Keystreams for protected fields: ChaCha20 (version 4), Salsa20 (reading version 3) |
| `kdf.rs` | Argon2d, Argon2id, AES-KDF. Parameter limits. `benchmark(target)` returns settings that take the target time on this Mac. For encrypted imports (FEA-08, LD-142): PBKDF2 with HMAC-SHA-256 or HMAC-SHA-512, HKDF-Expand with SHA-256, and Argon2id, each refusing settings outside the FEA-08.68 ranges before any work. For file encryption (E22, LD-379): scrypt, refusing a cost above its ceiling before any work. E23: `scrypt_settings`, RFC 7914 validity (N below 2^(16r), p within its limit) apart from the cost ceiling (LD-376). |
| `bridge.rs` (E7) | The browser bridge channel: X25519 key exchange, HKDF-SHA256 with one key per direction, AES-256-GCM with 12-byte nonces; the extension does the same with WebCrypto (LD-274 (1)) |
| `sign.rs` (E7) | ECDSA P-256 and Ed25519, for passkeys |
| `aead.rs` (E22) | ChaCha20-Poly1305 in place (RFC 8439): seal and open with the caller's key, nonce and associated data. No arrangement of chunks or counters. An open checks the tag first and leaves the data unchanged when it fails. |
| `bech32.rs` (E22) | Original Bech32 text for keys, never Bech32m: read and write with a checked prefix, length and padding; private text only in `SecretString`, decoded keys only in `SecretBytes` |
| `gcm.rs` (E23) | AES-256-GCM with a caller's nonce, for formats that fix their own nonce rule (NIST CAVP vectors). |
| `siv.rs` (E23) | AES-SIV, RFC 5297 (both appendix vectors). |
| `keywrap.rs` (E23) | AES key wrap, RFC 3394 section 4.6. |
| `text.rs` (E23) | NFC normalization of passwords, with its bound after normalization. |
| `base64.rs` | Padded URL-safe base64 with one text per value (E23). |
| `ssh.rs` (E9) | OpenSSH private keys through `ssh-key`: parse, public parts, decrypt with a round ceiling checked first, private fields in the agent's wire form as `SecretBytes` (INT-06.6 to INT-06.10). E9-S2: Ed25519 and ECDSA P-256 signatures for Larsal's own agent and the session binding check, through `ed25519-dalek` and `p256` (INT-06.33) |

Must: standard test vectors for every function. No state, no file access, no logging.

### larsal-files

File encryption (E22-S3; FIL-01, FIL-03): one file in the public file format, in the passphrase mode or the public key mode, as a stream, with working memory that does not grow with the file. It arranges the format and the flow; every primitive and random byte comes through `larsal-crypto`, every descriptor call through `larsal-platform`. `#![forbid(unsafe_code)]`. No process, no network, no ambient key search. No FFI yet: E22-S4 adds the screens' side.

| File | What it does |
|---|---|
| `decrypt.rs` | The flow as states, each made only from the one before it: `Snapshot` (one read handle on sealed ciphertext), `Unwrapped` (header bound, file key unwrapped, MAC proven), `Validation` (`Ready(Validated)` or `Weak(WeakFile)`, every chunk, the final marker and the end proven with the plaintext thrown away), `Validated` (the only state that hands out plaintext, on a second pass that checks everything again). `open_bounded` for key files. `Snapshot::in_memory` is the crate's own; the fuzz target reaches it only through the `fuzz-door` feature, never on in a product build. |
| `encrypt.rs` | `encrypt_stream`, `encrypt_file`: every random draw and the key derivation first, so a failure there leaves no output |
| `header.rs` | The binary header: read strictly and bounded before anything is buffered, kept as read so the MAC runs over the original bytes; written canonically |
| `payload.rs` | The 64 KiB chunks: checked counter, final marker and end of file, two wiping buffers |
| `armor.rs` | The byte source: binary as it is, or decoded from strict armor. Armor is read only, never written |
| `keys.rs` | `Recipient`, `Identities`, identity lists and encrypted key files with a bounded read, `generate_identity` |
| `fsio.rs` | Every file system call of the crate: the source by one no-follow handle, ciphertext-only scratch sealed to an unlinked read handle, the new output by exclusive create (ciphertext may go to a disk that cannot keep a file private, plaintext may not), cleanup through its own descriptor, and the sweep of crash leftovers |
| `label.rs` | The cleaned plain text a screen may show for a file name |
| `limits.rs` | Every limit of FIL-03 in one place |
| `error.rs` | The fixed messages of FIL-03. Every failure a file can cause is the one `Error::Decrypt`; the internal cause reaches only the crate's vector runner |

Must: `testdata/age-testkit/` holds the published test files (C2SP/CCTV, see its `SOURCE.md`), pinned by count and hash, and they run in every `cargo test`. The runner also proves itself on `testdata/derived/`, written by a separate script from the public format text and the RFC vectors. Tests name their FIL rows.

### larsal-folders

Encrypted folders (E23-S3; FIL-04, FIL-06): a folder of files, each file and each name encrypted on its own, in the public classic format 8 with SIV_GCM, profile classic8-gcm-local-1 of LD-372. Every other profile is refused by name. It arranges the format and the flow; every primitive and random byte comes through larsal-crypto, every descriptor call through larsal-platform. `#![forbid(unsafe_code)]`. No process, no network. No FFI yet: E23-S4 adds the screens' side. Content goes in 32 KiB chunks on at most 4 scoped worker threads and 8 buffers, in order, with no runtime crate.

| File | What it does |
|---|---|
| `vault.rs` | Create, unlock, lock (revoked flag at once, then the key lock waits for running passes and the keys drop), listing, lookup, the session's stores. |
| `format.rs` | The signed configuration and the key file, read strictly and bounded before any key work. |
| `keys.rs` | The master keys and their wrap. |
| `names.rs` | Names sealed with the parent ID, storage paths, shortened names. |
| `content.rs` | The header, the chunk pipeline, small objects. |
| `read.rs` | Snapshot, Validated, write_to. |
| `write.rs` | Every change, by private staging, recovery copies first, exclusive rename or swap. |
| `recovery.rs` | The journal with its MAC, resume and discard. |
| `budget.rs` | The shared header ledger. |
| `stores.rs` | The local stores, proven private. |
| `limits.rs` | Every limit in one place. |
| `error.rs` | The fixed messages. |
| `seam.rs` | Fault points, test builds only. |
| `fuzz_door.rs` | The fuzz target's way in, feature `fuzz-door`, never on in a product build. |

Must: `testdata/desktop-vault/` holds a demo vault the format's public desktop app made (MIT, see its `SOURCE.md`), pinned by name and hash, and it opens in every `cargo test`. The library-made vaults are AGPL and never in the tree: their tests are ignored and read `LARSAL_PEER_VAULTS`. Tests name their FIL rows.

It installs no allocator: the scrypt crate's working blocks rely on the zeroing allocator of the front end, so `larsal-ffi`'s must stay in the path.

### larsal-model

The vault data types. No file access, no crypto calls.

| File | What it holds |
|---|---|
| `vault.rs` | `Vault`: metadata, settings, field protection flags, history limits, recycle bin id, root group, deleted objects, encryption settings |
| `group.rs` | `Group`: name, notes, icon, times, tags, settings it passes to its entries, child groups and entries |
| `entry.rs` | `Entry`: standard fields and custom fields, each with a protected flag. Protected values use secret types. |
| `attachment.rs` | Attachment name, data, protected flag |
| `times.rs` | Timestamps (seconds since 0001-01-01 UTC): created, modified, accessed, expires, location changed, usage count |
| `icon.rs` | Standard icon number or custom icon id |
| `custom_data.rs` | Key and value pairs that plug-ins keep on the vault, groups and entries |
| `autotype.rs` | Auto-Type settings and window associations |
| `uuid.rs` | 16-byte ids |
| `unknown.rs` | Unknown document parts, kept exactly as read so a save loses nothing |
| `invariants.rs` | Unique ids, one root, at most one recycle bin, no group cycles |
| `json.rs` | Larsal's own JSON reader and writer (RFC 8259, at most 16 MiB and 127 levels), for Larsal's own settings files, saved searches, site access, last-use items and the instance line; not for secrets (E0-S7 step 3c, LD-260) |

### larsal-format

The vault file format: version 4 read and write, version 3 read only. Key files. Works on bytes (`Read`, `Write`), never on paths.

| File | What it does |
|---|---|
| `limits.rs` | Every size limit in one place: header field, block, total file, decompressed payload, document depth, attachment, KDF cost ceilings |
| `header.rs` | Outer header read and write |
| `kdf_params.rs` | The typed key-value map that stores KDF settings |
| `keys.rs` | Composite key from password, key file and hardware-key response; derived cipher key and HMAC key |
| `keyfile.rs` | Read every key file kind; create new key files |
| `integrity.rs` | Header hash and header HMAC; HMAC block stream (version 4) |
| `hashed_blocks.rs` | Hashed block stream (version 3) |
| `payload.rs` | Encrypt and decrypt the payload; gzip with limits |
| `inner.rs` | Inner header (field stream key, attachment pool) and the protected-field stream |
| `document/read.rs`, `document/write.rs` | The XML document to and from `larsal-model`, keeping unknown parts |
| `document/encode.rs` | Times, booleans, ids, base64 |
| `share_item.rs` | The share settings item of a group (INT-08.2 to INT-08.4), read by larsal-share and by larsal-core's references (MOD-08.32) |
| `version.rs` | Picks the lowest file version that holds every feature in use (spec FMT-16) |
| `detect.rs` | Tells a vault file from other files by its first bytes |
| `error.rs` | The ten kinds of spec FMT-01.33: `NotAVault`, `OldFormat`, `Unsupported`, `Corrupt`, `NoCredentials`, `KeyFile` (with a reason), `HardwareKey` (with a reason), `TooLarge`, `WrongKey`, `Io`. `WrongKey` only when the header HMAC fails (version 4) or the start bytes do not match (version 3, LD-12). |

Must: fresh random values on every save (spec CRY-03). XML DTD and entities rejected. Every read bounded by `limits.rs`. Open, save, open again keeps every piece of user data, including parts we do not understand.

### larsal-core

Every operation on a vault. Pure logic, plus `storage.rs`, the only file that touches vault files on disk.

| File | What it does |
|---|---|
| `edit.rs` | Create, change, move, sort and delete entries and groups; timestamps |
| `history.rs` | Entry history: when a version is kept, count and size limits |
| `recycle.rs` | Move to the recycle bin, restore to the previous group, empty, deleted-objects list |
| `attachments.rs` | Add, rename, remove, export; one stored copy for identical files; size limits |
| `refs.rs` | Field references and placeholders, safe against loops, bounded |
| `search/parse.rs`, `search/run.rs` | The search language and running it |
| `generator/password.rs`, `generator/passphrase.rs`, `generator/wordlist.rs` | Password and passphrase generator; the 7,776-word list with its license (CC BY 4.0) in the file header and its attribution in `ATTRIBUTION`, shown in About, `larsal --license` and the third-party notices (E14-S2) |
| `totp.rs` | One-time password settings, storage forms, codes |
| `health.rs` | Strength estimate, reuse, expiry, exclusions, scores |
| `breach.rs` | Builds the 5-character hash-prefix query and reads the answer. The network call itself is in `larsal-platform`. |
| `stats.rs` | Vault statistics |
| `merge.rs` | Merge two vaults or two versions of one vault without losing data |
| `import/`, `export/` | One file per format |
| `settings.rs` | Vault settings, encryption changes, master key change reminders |
| `expiry.rs` | Expired entries, expire now |
| `clone.rs` | Clone with options |
| `storage.rs` | Atomic save, backup before save, change-on-disk detection |

### larsal-platform

The operating system. Traits in the crate root, macOS code in `macos/`. Windows and Linux can plug in later. Features: `memory` (libc only; all larsal-format takes, E6-S6), `appkit` (the clipboard, OS version and physical memory: objc2, Foundation, AppKit; larsal-cli and larsal-ffi), `net` (`net.rs`, off by default, LD-194) and `device-key` (`device_key.rs`: security-framework; larsal-ffi's `sync` turns it on, E16-S7a).

| File | What it does |
|---|---|
| `clipboard.rs` | Copy marked as concealed and transient (`objc2-app-kit`); clear after the timeout only while `changeCount` still shows our value; clear on lock and quit. Shared with `larsal-cli` (SC-07) |
| `quick_unlock.rs` | Touch ID: a Keychain item behind biometrics (data protection keychain, current biometric set, this device only) through `security-framework`, removed when biometrics change. The key never becomes a Swift value |
| `hardening.rs` | Deny debugger attach and core dumps in release builds; called first at start-up. Shared with `larsal-cli` |
| `memory.rs` | The zeroing global allocator (LD-133, LD-193): every block Rust frees is zeroed before the system gets it back; installed by the `larsal` tool and larsal-ffi. `lock` keeps key pages out of swap (`mlock`, APP-11.9); larsal-format's `keys::LockedKey` uses it for every key it holds |
| `net.rs` | One HTTPS client (rustls) for opt-in features, with timeouts and no cookies; its certificate check is Larsal's own verifier over macOS's trust evaluation (`macos/trust.rs`, LD-247 (2)). Since E16-S6 also GET and PUT with the caller's headers for the sync routes, and the pinned path for Larsal's demo server (SYN-01.2, P17): only the certificate whose SHA-256 is the pin, never macOS's trust evaluation, the handshake signatures still checked; the fingerprint read is one handshake that sends no request |
| `device_key.rs` | The P-256 sign-in key (SYN-04.1, P5; E16-S6) through `security-framework`'s safe API: the Secure Enclave, this device only, or a software key in the data protection keychain on an Intel Mac without one (both after W-02); the login keychain for the app until W-02; an in-memory test-seam key for tests (LD-317). Signs and gives the 65-byte public key; never the private key's bytes |
| `macos/` | Bridges to macOS APIs. The only place `unsafe` is allowed in this crate; every block has a `// SAFETY:` note (enforced by `clippy::undocumented_unsafe_blocks`). Since E5-S1: the per-user temp folder, the socket peer user id, terminal echo for `--password-stdin` (a quit signal at the prompt puts the terminal back first, then ends Larsal, as `readpassphrase(3)` does), kernel and OS versions; one quit-signal guard (`signals.rs`) for the echo-off prompt and the command line's clip wait (E12-S1: SIGINT, SIGTERM, SIGQUIT and SIGHUP are noted, the cleanup runs, then the signal ends the process; a signal ignored at start stays ignored, LD-178); the local UTC offset from `localtime_r` (LD-178). Quit signals and the M09-06 alert are Swift (`macos/`). Since E23-S3, `macos/folder.rs` gains the descriptor steps a folder needs: open_dir, open_dir_in, make_dir_in, names_in, info_in, info_of, open_regular_in, remove_dir_in, rename_new_in (exclusive), swap_in, free_bytes. Each works relative to an open folder, with no link followed. |

Lock signals and screen protection are Swift (`macos/Larsal/Platform/`), as in proven Mac apps.

### larsal-ffi

The bindings crate: the only crate that exports anything to Swift. UniFFI 0.32.2 with proc-macros (no UDL files). Crate types `lib` and `staticlib`.

| File | What it does |
|---|---|
| `lib.rs` | `uniffi::setup_scaffolding!`; the UniFFI Objects `Session` and `Vault`, which Swift holds only as handles |
| `start.rs` | Start-up (APP-09.1): `start` runs steps 1 to 9 before any window (Rust prints every message and keeps the F06 passwords), `launch_finished` steps 11 to 13 and opens the channel to requests (Finder and Dock opens wait in Swift, then go through `Session.open`, LD-277 (3)); the Swift `LarsalEvents` callback brings the window to front |
| `instance.rs` | One instance: lock file, socket and its request channel (APP-09.7 to APP-09.14) |
| `cli.rs` | Flags F01 to F11, help, version, debug info, file arguments, `--password-stdin` lines (APP-09.2 to APP-09.6, APP-09.16) |
| `session.rs` | The `Session` Object (E5-S2): open vaults, locked or unlocked, which vault is shown; open, unlock, lock, close, switch; the hooks that open files and lock all |
| `share.rs` | Shared groups (E11-S3, INT-08) over larsal-share: the import and export passes of each vault on a worker thread, their triggers, the approval records and the path guard |
| `views.rs` | List views without secrets, the sidebar, entry view, Show (one `String`), Copy (`copy_field`, the value stays in Rust), live one-time codes (E5-S2) |
| `api/vault.rs` | Create, vault settings |
| `api/entries.rs` | Edit, delete, restore, clone |
| `api/groups.rs` | Create, rename, move, delete groups |
| `api/generator.rs` | Generate, strength estimate |
| `api/reports.rs` | Health Check, breach check, statistics, passkeys, browser statistics |
| `api/larsal_settings.rs` | Larsal settings from the settings inventory (spec APP-01) |
| `API.md` | Every exported function, its inputs and outputs, and the secret it returns, if any (only the crossings of LD-220). Replaces `COMMANDS.md` |
| `autosave.rs` | Save after every change, per spec APP-05 |
| `events.rs` | Locked, changed on disk, expired entries, clipboard countdown; sent to Swift through a callback interface |
| `log.rs` | A `tracing` layer that drops field values (Rust rule 9) and calls the Swift `LogSink` callback |
| `messages.rs` | One plain message per error kind and reason (spec APP-06); never a secret or text from a file (SF-18). Pure Rust, so it is built and tested before the shell (E3-S9) |

Must: exported functions return records that hold no secrets, except the crossings LD-220 names, each started by the user or drawn on screen by design: the Show value (one `String`), the live one-time codes of the entries in view, the setup secret of the one-time password sheet, the QR matrix the user asked for, the generator's value, and the wizard's and vault settings' password and repeat, and the wizard's generate while that sheet is open (`crates/larsal-ffi/API.md` names each export). A record that carries one hides it in `Debug` and is not `Clone` (F-062). Copy is a Rust call; the value never reaches Swift. Errors are typed and hold no secret (AT-E03). Only generated scaffolding is `unsafe`; no hand-written `unsafe` (Rust rule 2). The open dialog accepts any file; `larsal-format/detect.rs` decides if it is a vault. Saving keeps the file's existing name.

Gone with Tauri (E5-S1 deletes them from the old `crates/larsal-desktop/`, which becomes `larsal-ffi`): `main.rs`, `build.rs`, `tauri.conf.json`, `capabilities/`, `gen/`, `permissions/`, `icons/`, `COMMANDS.md`. Menus moved to Swift.

### macos/

The Mac app in Swift, built from [design/mockup.html](../design/mockup.html). A checked-in Xcode project; no project generator.

| Path | What it does |
|---|---|
| `Larsal.xcodeproj` | Synchronized folders and a shared scheme `Larsal`; Swift 6, macOS 14, hardened runtime, no App Sandbox |
| `Larsal/` | SwiftUI screens from the mockup, one `@Observable` view model per screen, menus and shortcuts (SwiftUI commands, the AppKit menu bar icon), files opened from Finder (`application(_:open:)`, `CFBundleDocumentTypes`) |
| `Larsal/main.swift` | The entry: calls `start` in Rust first (APP-09.1), then exits, shows the M09-06 alert, or runs the SwiftUI app |
| `Larsal/Platform/` | Quit signals (SIGINT, SIGTERM, SIGQUIT start the orderly quit through dispatch sources; SIGHUP ignored; APP-09.27), bring to front (APP-09.22), files opened from macOS (APP-09.23, URL opens ignored), lock signals (sleep, screen sleep, user switch, screen lock; idle time counted from events inside the app), window guard (`sharingType = .none` on every window, secure input), biometry availability (`LAContext`, only to show or hide the Touch ID button), log sink (`os.Logger`, subsystem `app.larsal.desktop`) |
| `LarsalCore/Package.swift` | Local package: the generated `LarsalFFI.xcframework` as a `binaryTarget` plus the generated Swift (built in Swift 5 mode); both made by `scripts/build-core.sh` in `target/larsal-core/`, reached through the link `LarsalCore/Generated` |
| `LarsalTests/` | Unit tests (Swift Testing) |
| `LarsalUITests/` | UI tests (XCTest UI testing) for Mac QA, G8 |
| `Larsal.entitlements` | Release: `keychain-access-groups` only, for quick unlock. Debug builds add `get-task-allow` |

Must: no secret is kept beyond Show: the view model drops the Show value on Hide, on entry change and on lock. Vault text is shown as plain `String` text, never through `LocalizedStringKey` or Markdown. Every call into Rust goes through `larsal-ffi`. The look matches the mockup.

### larsal-cli

The command line tool `larsal` (E12). Same operations as the app. Password prompts without echo. Never prints a secret unless the command asks for it. `show --qr` prints one selected value as a QR code in block characters (FEA-10.22, .23, E21-S3): only to a terminal large enough for it, or with `--stdout` as plain cells to a pipe or file; its matrix comes from larsal-qr, the encoder the app uses.

### larsal-qr

Show as QR Code's encoder (FEA-10.4 to .10, E21-S3): `encode()` (the 1,272-byte bound, ECI 26 and one byte segment at level H, the smallest version), `symbol()` (the one `qrcode` call site, LD-198) and the Wi-Fi join text (`join_text()`; `wire()` and `join_buffer()` are private; a tests-only `written()` behind the `test-join` feature, which only larsal-ffi's dev-dependency turns on, serves larsal-ffi's join tests). Its `Matrix` has private fields over a `SecretBytes` and its join text is a `SecretString`, both wiped on drop (Rust rule 3); `qrcode`'s own copies are wiped by the program's zeroing allocator, which the `larsal` tool and larsal-cli's unit test program (larsal-cli `main.rs`) and the larsal-ffi library with every program that links it install; larsal-cli's `int10` test program links larsal-qr without it and encodes demo values only. No file, network, process or environment access; `#![forbid(unsafe_code)]`. No test program of its own: larsal-ffi's and larsal-cli's tests drive it.

### Plug-ins

| Crate | Epic | What it does |
|---|---|---|
| `larsal-browser` | E7 | Browser bridge host, encrypted channel, URL matching, site access prompts, passkeys |
| `larsal-autotype` | E8 | Sequence parser, window matching, typing on macOS (Accessibility permission) |
| `larsal-sshagent` | E9 | Adds and removes keys in the system SSH agent |
| `larsal-hwkey` | E10 | Hardware key challenge-response over USB |
| `larsal-share` | E11 | Shared groups and remote sync |
| `larsal-files` | E22 | File encryption in the public file format: see its section above. No FFI until E22-S4 |
| `larsal-folders` | E23 | Encrypted folders in the public classic format 8: see its section above. No FFI until E23-S4 |

### Other folders

- `fuzz/`: one target per parser: vault file, key file, KDF map, document, TOTP link, search query, Auto-Type sequence, CSV import, JSON import, .1pux import (ZIP), OPVault import, version 1 import, browser message, file format (armor, header, chunks and the validated decrypt flow), folder format (configuration, key file, names, shortened names, content, and sealed round trips).
- `testdata/`: demo vaults with demo passwords and their expected exports (JSON). `testdata/README.md` lists each file and its password. Never a real vault. The reference app's own test vaults stay outside this folder; tests read them through `REF_TESTDATA`.
- `tests/`: interop tests (need `REF_CLI`) and end-to-end tests.
- `scripts/`: `check.sh` runs every quick gate. `build-core.sh` builds the Rust static library, runs `uniffi-bindgen-swift` in library mode and wraps the result in the `LarsalCore` package (host target only; the x86_64 slice and `lipo` wait for E14). `check-names.sh` is the name guard; it stores the banned words encoded, so the script itself stays clean. `check-vendor.sh` (E0-S7) proves that every build reads only this tree (`vendor/` and our crates) and that no stub is built for a Mac. `make-testdata.sh` makes demo vaults. `interop.sh` runs interop tests. `repro-build.sh` is the release build: the `larsal` tool, `liblarsal_ffi.a` and Larsal.app with fixed settings (locked crates, build paths mapped to fixed names, a fixed `SOURCE_DATE_EPOCH`), then `make-sbom.sh` (CycloneDX bill of materials and third-party notices) and the SHA-256 of every file, all in `target/repro/`; it builds a copy of the tree in one fixed folder (`/private/tmp/larsal-repro`), compiles `Assets.car` again when actool's race changes its appearance order, and records the toolchain in `BUILDINFO`, so two runs on the same toolchain give the same hashes wherever the tree is (AT-J04, LD-222).
- `security/`: `findings.md` (created with the first finding) and parity evidence.
- `qa/`: Mac QA reports and screenshots, demo data only.

## Approved crates

Exact versions are pinned in E0. Adding a crate needs a Checker review (gate G6 and attack AT-J03) and a new line in this table.

Every crate below, and every package they pull in, is Larsal's own copy in the tree (E0-S7, LD-221): plain copies in `vendor/crates-io/<name>-<version>/` (made once by `cargo vendor --versioned-dirs`, read through the source replacement in `.cargo/config.toml`; builds run `--offline --locked`), the patched copies in `vendor/zxcvbn`, `vendor/ssh-key`, `vendor/uniffi`, `vendor/uniffi_core`, `vendor/uniffi_bindgen`, `vendor/ureq` and `vendor/ureq-proto` (`[patch.crates-io]`; each lists its changes at the top of its `Cargo.toml`). Crypto copies are byte-for-byte the published package except whole files cut: ring's `crypto/fipsmodule/aes/asm/aesni-x86_64.pl` (LD-247 (4)) and, since E0-S7 step 4b, the `tests/` and `benches/` of 55 crypto copies and the files that only other targets build (ring's assembly for other systems, the 32-bit, `fiat` and other-architecture backends, getrandom's backends for other systems; `spec/research/dependencies.md` section 17); packages never built on a Mac are stubs (`Cargo.toml`, an empty `lib.rs`, LD-247 (3)). Adding or updating a crate is one reviewed copy into `vendor/crates-io` (the per-package table: `spec/research/dependencies.md`). `scripts/check-vendor.sh` (gate G1) fails when a build would read a package from outside the tree or compile a stub for a Mac.

Pinned in E0 (`[workspace.dependencies]` in `Cargo.toml`): the newer RustCrypto generation (cipher 0.5, digest 0.11), because the older one has an unfixed advisory in `p256`. A crate whose license is outside the `deny.toml` allowlist, or that brings a duplicate crypto crate, gets a named exception in `deny.toml` with a written reason, reviewed under AT-J03 when it is first used. The allowlist itself is not widened.

| Need | Crate |
|---|---|
| AES, CBC mode | `aes`, `cbc` |
| ChaCha20, Salsa20 | `chacha20`, `salsa20` |
| Twofish | `twofish` |
| Argon2 | `argon2` |
| SHA-2, SHA-1 | `sha2`, `sha1`. Since E0-S7 step 4b both are cut copies: no `tests/` or `benches/`, and no LoongArch, RISC-V or WebAssembly backend (`cpufeatures` lost its LoongArch file); the x86 and aarch64 backends stay |
| HMAC | `hmac` |
| File and folder passphrase KDF | `scrypt` =0.12.0, default features off; larsal-crypto only. No PHC/getrandom/parallel features. Uses the existing pbkdf2/HMAC/SHA-2/Salsa generation; it has no zeroize feature. Heap, stack, backend/error and abort wiping remain implementation checks. AT-J03 Lead and independent Checker approved in writing, 2026-11-05 (LD-379). |
| File AEAD and native key encoding | `chacha20poly1305` =0.11.0, defaults off, zeroize only; `bech32` =0.11.1, defaults off; larsal-crypto only. Existing poly1305/zeroize through ssh-cipher stays required; the wrapper flag alone does not enable it. No new random source, reduced-round or plugin path (LD-379). |
| Folder filename authentication and key wrap | `aes-siv` =0.8.0, `aes-kw` =0.3.1 and `cmac` =0.8.0, defaults off and zeroize on at the direct larsal-crypto edges; `dbl` =0.5.0 is transitive only. Declared transitive defaults remain explicit in the Cargo graph; no PMAC/OID or older crypto generation is enabled. Exact backend/state wiping remains implementation proof (LD-379). |
| Folder password/name NFC | `unicode-normalization` =0.1.25, defaults off, larsal-crypto only; transitive `tinyvec` =1.10.0 with alloc and `tinyvec_macros` =0.1.1. The table is Unicode 17; newer-repertoire interoperability is unproved. Exact NFC/no-retry behavior and temporary-copy wiping remain implementation checks (LD-379). |
| Constant-time compare | `subtle` |
| OS random source | `getrandom` (through `rand_core`). Since E0-S7 step 4b getrandom 0.4.3, and 0.2.17 under ring, keep only their macOS backend, `getentropy` (LD-221 (7)); 0.2.17 also keeps its `custom` feature file. A `getrandom_backend` cfg for another backend no longer builds; none is set |
| Wipe memory | `zeroize` |
| Browser bridge channel (E7) | `x25519-dalek`, `hkdf`, `aes-gcm` (E16-S2's crates; `crypto_box` dropped, LD-274 (1)) |
| HPKE, key wrap and signatures for sync (E16-S2) | `hpke` =0.14.1 (features `x25519`, `aes`, `alloc`) with `x25519-dalek` =3.0.0 and `zeroize_derive`, and `aes-gcm` =0.11.1 as a direct dependency; larsal-crypto only (AT-J03: LD-303) |
| Sync server (E16-S3, `larsal-server` only) | The crates listed under "Approved crates to add" below, at the versions in `Cargo.lock` (AT-J03: LD-303); its TLS is the exception of rule 6 below (P20) |
| ECDSA P-256 (E7 passkeys; E9-S2 Larsal's own SSH agent) | `p256` =0.14.0, no default features, feature `ecdsa` only; larsal-crypto only, first used by E9-S2 in `ssh.rs` (signatures for Larsal's own agent, session binding check, INT-06.33). New in the tree through it: `ecdsa` 0.17.0, `elliptic-curve` 0.14.2, `primeorder` 0.14.0, `primefield` 0.14.0, `rfc6979` 0.6.0, `crypto-bigint` 0.7.10 (0.7.7 was yanked upstream; bump in LD-201), `ff` 0.14.0, `group` 0.14.0, `wnaf` 0.14.1, `der` 0.8.2, all MIT OR Apache-2.0; `num-traits` 0.2.19 (build script through `autocfg`) was test-only and is now linked through `crypto-bigint`. Unsafe only in `elliptic-curve`, `der` (newtype casts) and `crypto-bigint` (limb casts); signing constant-time, variable-time code only in verification. AT-J03 signed with conditions by the E9-S2 Checker 1, LD-201 (co-signed by the lead). Since E0-S7 step 4b `p256` and the copies under it are cut copies: no `tests/` or `benches/`, and `p256` lost its 32-bit field and scalar files |
| Ed25519 (E7 passkeys; E9-S2 Larsal's own SSH agent) | `ed25519-dalek` =3.0.0, no default features, feature `zeroize` only; larsal-crypto only, first used by E9-S2 in `ssh.rs` (as for `p256`). New in the tree through it: `ed25519` 3.0.0 (MIT OR Apache-2.0), `curve25519-dalek` 5.0.0 (BSD-3-Clause; a build script picks the backend), `curve25519-dalek-derive` 0.1.1 (proc macro, MIT OR Apache-2.0), `fiat-crypto` 0.3.0 (MIT OR Apache-2.0 OR BSD-1-Clause), build-only `rustc_version` 0.4.1 (MIT OR Apache-2.0, run by that build script); `ed25519-dalek` itself is BSD-3-Clause. `curve25519-dalek-derive` and `fiat-crypto` are built only for x86_64 SIMD or the `fiat` backend, not on arm64 (the `serial` backend, one `unsafe` table cast). `cargo deny check licenses bans sources` ok. AT-J03 signed with conditions by the E9-S2 Checker 1, LD-201 (co-signed by the lead). Since E0-S7 step 4b `curve25519-dalek` is cut further: no `tests/` or `benches/`, and no 32-bit (`u32`) or `fiat` backend files, so `curve25519_dalek_bits = "32"` and the `fiat` backend no longer build (neither is set); the `serial` 64-bit backend and the x86_64 SIMD backends stay |
| SSH keys (E9) | `ssh-key` =0.7.0-rc.11 as Larsal's patched copy in `vendor/ssh-key` (reads a short ECDSA scalar, LD-209), features `alloc`, `ecdsa`, `encryption` (larsal-crypto `ssh.rs` only; rc.11 is the newest release, no stable 0.7 yet, and 0.6.7 is the older generation; re-pin at 0.7.0). `bcrypt-pbkdf` is named only to turn on its `zeroize`. New in the tree through it: `ssh-cipher`, `ssh-encoding`, `bcrypt-pbkdf`, `blowfish`, `aes-gcm`, `ghash`, `polyval`, `universal-hash`, `aead`, `ctr`, `poly1305`, `pem-rfc7468`, `sec1`, `base16ct`, `signature`, all MIT OR Apache-2.0; no build scripts and no `unsafe` in `ssh-key`, `ssh-cipher`, `ssh-encoding`, `bcrypt-pbkdf` and `blowfish`. AT-J03 signed with conditions, LD-182 (co-signed by the lead). Since E0-S7 step 4b these copies (not `vendor/ssh-key`) have no `tests/` or `benches/`, and `polyval` lost its 32-bit multiply file |
| XML | `quick-xml` (DTD off). Since E0-S7 step 4d a cut copy: its serde reader and writer (`src/de/`, `src/se/`, `serde_helpers.rs`) and its tokio reader and writer, behind features Larsal never turns on, are cut |
| Gzip | `flate2` with the pure Rust backend (`miniz_oxide` 0.9.1). Since E0-S7 step 4d a cut copy: the C and zlib-rs backends (`src/ffi/c.rs`, `src/ffi/zlib_rs.rs`) and the features and `libz-sys`, `libz-ng-sys` tables that named them are cut |
| Base64, Base32, hex | `base64ct` in larsal-crypto only: `base64.rs` takes every call our crates made to the `base64` crate (E0-S7 R5, LD-258 (2)); larsal-format's lenient document base64 (FMT-12.20) and the `{T-CONV:/…/base64/}` encoder in larsal-core `refs.rs` stay Larsal's own code; `base64` is in no manifest of ours and left the tree in E0-S7 step 4d (Larsal's ureq and ureq-proto copies no longer name it); Base32 is Larsal's own code in larsal-core `totp.rs` (the unused `data-encoding` pin left Cargo.toml in E0-S7 step 2, LD-254 (3)); `deny.toml` bans `base64ct` for every other crate (`wrappers`: larsal-crypto and the argon2, pem-rfc7468 and ssh-encoding copies that already use it, LD-261 (4)) |
| Strength estimate | `zxcvbn` 3.1.1 as Larsal's patched copy in `vendor/zxcvbn` (LD-136, AT-J03 signed LD-138; its plain copies wait for the zeroing allocator, LD-133). No outside package of its own since E0-S7 step 3a: its statics, its reference year and its six patterns are Larsal's code in the copy (LD-136 changes 7 to 9, in place of `lazy_static`, `time`, `regex` and `fancy-regex`; `itertools` left in step 1, change 6), and no build script runs (`build = false`, LD-255 (1)) |
| PBKDF2, HKDF (encrypted imports, FEA-08) | `pbkdf2`, `hkdf` (larsal-crypto only; LD-142, AT-J03 at the E4-S13 Checker). ZIP files are read by Larsal's own small reader on top of `flate2` (LD-142) |
| Patterns (search FEA-01.32, placeholder replace MOD-08.22) | `regex-automata`, `regex-syntax` (the linear-time engine crates of the `regex` project; bounded by LD-113, LD-118, LD-120, LD-122; AT-J03 signed with conditions, LD-115). Built with only the features named in `Cargo.toml` since E0-S7 step 3a: until then `regex`, through `zxcvbn`, also turned on its literal prefilters (`aho-corasick`), full DFAs and every Unicode table; `regex` left the tree in step 3a. Since E0-S7 step 4a `regex-automata` is a cut copy: the full-DFA engines (`dfa-build`, `dfa-search`: 10 files of `src/dfa/`; `onepass.rs` stays) and its own `perl_word` table, built only when `syntax` or `unicode-perl` is off, are cut, and its manifest no longer names `aho-corasick` (the multi-literal prefilter, never on), which left the tree. `regex-syntax` stays whole: the tests build it with every Unicode table, since `proptest` takes its default features |
| Icon images (MOD-06, LD-65) | `png` (PNG only; LD-109; AT-J03 signed with conditions, LD-115). Since E0-S7 step 4d `png` is a cut copy whose manifest no longer names its own `miniz_oxide` 0.8 (its code never calls it: it works through `fdeflate` and `flate2`), so `miniz_oxide` 0.8.9 and its LD-115 `deny.toml` skip are gone and `flate2`'s 0.9.1 is the one copy. ICO is Larsal's own reader in larsal-core `icons.rs` since E0-S7 step 3c (R10, in place of `ico`, which left the tree): the directory with at most 256 images, each inside the file, then the PNG through `png` or the BMP (1, 4, 8, 16, 24 and 32 bits, the mask) within the byte and pixel limits; its test encoder is in larsal-core `tests/common/ico.rs` |
| QR symbols (FEA-04.23, FEA-10, D-04-9) | `qrcode` =0.14.1 without default features (no `image`, `svg`, `pic`: the module matrix only; imported only by `larsal-qr` `src/lib.rs` `symbol()`, which larsal-ffi (the Mac app's authenticator setup code and Show as QR Code) and larsal-cli (`larsal show --qr`, E21-S3) reach: larsal-cli reaches the matrix through larsal-qr, never by importing `qrcode`; larsal-ffi keeps it as a dev-dependency for one test; MIT OR Apache-2.0, no dependencies, no `unsafe`, no build script; passively maintained, 0.14.1 of 2024-07-05 the newest; the matrix and the join text larsal-qr hands out are a `SecretBytes` and a `SecretString`, wiped on drop; the crate's own copies of the secret are freed unwiped and wiped by the zeroing allocator (LD-193) of the program: the `larsal` tool and larsal-cli's unit test program (larsal-cli `main.rs`) and the larsal-ffi library with every program that links it (the Mac app, larsal-ffi's test programs) install it; larsal-cli's `int10` test program links larsal-qr without it and encodes demo values only; AT-J03 signed with conditions by the E5-S5 Checker 1 and co-signed by the lead, LD-198, its reach amended for E21-S3) |
| Errors, data | JSON: Larsal's own reader and writer in larsal-model `json.rs` since E0-S7 step 3c (R12, in place of `serde_json` and `serde`, which stay in the tree, none of them linked into Larsal: `serde`, `serde_derive` and `serde_core` for `uniffi_macros`, uniffi's proc macro, which runs on the host in every larsal-ffi build, and for `cargo_metadata`, `askama` and `basic-toml` in the bindings generator; `serde_json` for `cargo_metadata` in the bindings generator): RFC 8259, at most 16 MiB and 127 levels, members in key order, numbers kept as written; not for secrets (imports keep their own reader, larsal-core `import/json.rs`). Error types: Larsal's own `Display` and `std::error::Error` impls, written by hand, since E0-S7 step 3b (R4, in place of `thiserror`, which stays in the tree only for `cargo_metadata` in the bindings generator) |
| Logging (Rust rule 9) | `tracing` (AT-J03 review when first used) |
| Swift bindings | `uniffi` =0.32.2 (`larsal-ffi` and `crates/uniffi-bindgen` only; MPL-2.0: named exact-version `deny.toml` exceptions for the UniFFI crates; AT-J03 signed with conditions, LD-157; LD-156). Since E0-S7 step 4c `uniffi` and `uniffi_core` are Larsal's patched copies in `vendor/uniffi` and `vendor/uniffi_core`, their edited files still MPL-2.0: `uniffi` no longer names `uniffi_pipeline` (F6: under the generator's `cli` feature since step 4c, gone with that feature in step 5), so larsal-ffi's library no longer compiles it, `tempfile`, `fastrand`, `rustix`, `errno`, `heck`, `indexmap`, `hashbrown` or `equivalent` (they still run at build time, inside `uniffi_macros` and the bindings generator; `rustix` without its Linux backend, `src/backend/linux_raw/`, since step 5); `uniffi_core` writes the two `static_assertions` macros the scaffolding calls with the standard library (R14), and `static_assertions` left the tree. Since E0-S7 step 5 the bindings generator `crates/uniffi-bindgen` reads its few options itself over uniffi's `bindgen` feature (no `cli` feature: `clap`, `clap_builder`, `clap_derive`, `clap_lex`, `anstyle` and `strsim` left the tree), and `uniffi_bindgen` is Larsal's patched copy in `vendor/uniffi_bindgen`: only the Swift generator, no UDL parser (`uniffi_udl`, `weedle2`, `nom` and `minimal-lexical` left the tree); the Swift bindings are byte-identical |
| macOS APIs | `objc2`, `objc2-foundation`, `objc2-app-kit` (clipboard), `security-framework` (Keychain) (E0 confirms each exists and is maintained). Since E16-S6 `security-framework` =3.7.0 is a plain copy with `security-framework-sys` 2.17.0, `core-foundation` 0.10.1 and `core-foundation-sys` 0.8.7 (all MIT OR Apache-2.0, no build scripts; AT-J03: LD-303), no default features, `OSX_10_15` only; larsal-platform `device_key.rs` only, feature `device-key`. Since E0-S7 step 4a `objc2-foundation` and `objc2-app-kit` are cut copies: they keep only the generated files of the features our crates turn on (Foundation: `NSArray`, `NSData`, `NSDictionary`, `NSError`, `NSFileWrapper`, `NSProcessInfo`, `NSSet`, `NSString`, `NSURL`; AppKit: `NSPasteboard`, `NSPasteboardItem`) |
| Hardware keys over USB (E10) | `objc2-io-kit` =0.3.2 (features `std`, `hid`) and `objc2-core-foundation` =0.3.2 (`std`, `CFArray`, `CFDate`, `CFDictionary`, `CFNumber`, `CFRunLoop`, `CFSet`, `CFString`; the plug-in watch of LD-190 uses the array, dictionary and run loop types, which `hid` also turns on), larsal-hwkey `usb/` only: the IOKit HID manager, no libusb (D-INT07-1, LD-173). Same project and licences as `objc2` (Zlib OR Apache-2.0 OR MIT); no build scripts; their one dependency `bitflags` 2.13.2 was already in the tree. AT-J03 signed with conditions by the E10-S1 Checker 1, LD-188 (co-signed by the lead). Since E0-S7 step 4a both are cut copies: they keep only the generated files of the features turned on for both Mac targets (`hid`; for `objc2-core-foundation` also `CFData`, `CFPlugInCOM`, `CFURL` and `CFUUID`, which other features turn on) |
| macOS system calls (larsal-platform `macos/` only) | `libc` 0.2.191 (`confstr`, `getpeereid`, `geteuid`, signal mask and `sigwait`, `tcgetattr`/`tcsetattr`, `uname`, `poll`, `raise`, `sigaction`, `setrlimit`, `ptrace` for hardening, E6-S4; `localtime_r` for the local UTC offset, E12-S1; `clock_gettime` with `CLOCK_THREAD_CPUTIME_ID` for the KDF benchmark clock (LD-72), E5-S8; `memset_s`, `mlock`, `munlock`, `sysconf` for memory hygiene, E6-S6, and in its test tools `memmem`, `memcmp`, `proc_pid_rusage`; `acl_get_fd_np` and `acl_free` are not in this crate, so `macos/folder.rs` declares them, and `fstatfs` for a mount's ignore-ownership flag, E22-S3); already in the tree through getrandom. AT-J03 signed, LD-157. Since E0-S7 step 4a a cut copy: the modules for Apple systems and the shared files stay, the 390 files for other systems are cut |
| HTTPS for opt-in features | `ureq` =3.5.0 without default features (HTTP/1.1 only; no gzip, cookies, proxy or TLS feature of its own; `forbid(unsafe_code)`, no build script), `rustls` =0.23.46 (`std`, `tls12`, `ring`: TLS 1.2 and 1.3 only; `forbid(unsafe_code)`) on `ring` 0.17.14 (C and assembly built by `cc`; the standard rustls provider), Larsal's own certificate verifier in place of `rustls-platform-verifier` (LD-247 (2), E0-S7 step 1: rustls's `ServerCertVerifier` over macOS's trust evaluation, the Security framework linked directly in `macos/trust.rs`: `SecPolicyCreateSSL` with the host name, `SecTrustCreateWithCertificates`, `SecTrustEvaluateWithError`; signatures through rustls's `verify_tls12_signature` and `verify_tls13_signature`; no crate, no crypto of its own), larsal-platform `net.rs` only, feature `net`, off by default (LD-194). New in the tree: `rustls-webpki`, `rustls-pki-types`, `untrusted`, `ureq-proto`, `http`, `httparse`, `utf8-zero`, `percent-encoding`, `getrandom` 0.2.17 (ring only: a named `deny.toml` skip), build-only `cc`, `shlex`, `find-msvc-tools` (`bytes`, `itoa`, `once_cell` were already in the tree; `log` is Larsal's own facade in `crates/log` since E0-S7 step 3b (R6, `[patch.crates-io]`): ureq and ureq-proto call it, nothing is logged). Tests only, and since E16-S3 also a normal dependency of `larsal-server` for its first-start certificate (P17, LD-303): `rcgen` =0.14.10 (`crypto`, `ring`; makes the test certificates; `forbid(unsafe_code)`) with `yasna` (`time` was already in the tree). Licences: MIT OR Apache-2.0, except `rustls` (Apache-2.0 OR ISC OR MIT), `ring` (Apache-2.0 AND ISC), `rustls-webpki` and `untrusted` (ISC), `bytes` (MIT). Never OpenSSL or native-tls (`deny.toml`). AT-J03 signed with conditions by the E6-S7 Checker 1 and co-signed by the lead, LD-197. The Mac app's core links it (`scripts/build-core.sh` builds larsal-ffi with `net`): the TLS exception of LD-220 (2) to "only larsal-crypto imports crypto crates" and Rust rule 7; `ring` and its `getrandom` serve TLS only and touch no vault key. Since E0-S7 step 4b ring keeps only the pregenerated assembly of the two Mac targets (`*-ios64.S` for arm64, `*-macosx.S` for x86_64): the assembly for Linux, Windows and 32-bit systems, the perlasm scripts for 32-bit ARM and x86 and `tests/` are cut; its build script reads the same files as before on both Mac targets. Since E0-S7 step 4d `ureq` and `ureq-proto` are Larsal's patched copies in `vendor/ureq` and `vendor/ureq-proto` (R13; each lists its changes at the top of its `Cargo.toml`): ureq's proxy (HTTP CONNECT and SOCKS), cookie, JSON, charset, gzip and brotli, lossy UTF-8, query and form code and its own tests are cut, and ureq-proto no longer makes a Basic authorization header from a user name and password in the URI; `base64` and `utf8-zero` left the tree, `percent-encoding` stays only for `askama` in the bindings generator, and the request bytes Larsal sends are the same |
| File change watch | None: the system's kqueue vnode sources through Swift's `DispatchSource` (`macos/Larsal/Platform/DiskWatch.swift`, APP-05.24; LD-216) |
| Command line | Larsal's own option parser in larsal-cli `args.rs` since E0-S7 step 3c (R9, in place of `clap`, which left the tree in E0-S7 step 5 with uniffi's `cli` feature: the bindings generator reads its few options itself); larsal-cli renders help and errors itself (INT-10); `rpassword` (not used: larsal-platform's echo-off guard reads passwords) |
| Tests, fuzzing | `proptest`, `libfuzzer-sys`, `arbitrary` |
| Tools (not linked) | `cargo-deny`, `cargo-audit`, `cargo-geiger`, `cargo-fuzz`; for Swift, `swift format` (ships with Xcode) and SwiftLint 0.65.1 (a check tool under the E0 install permission; pinned with its SHA-256 checksum in `scripts/install-swiftlint.sh`; installed in E5-S1) |

Open for E6-S3: SR-04 encrypts the quick unlock key parts with AES-256-GCM. Decided at story start from proven apps (AGENTS.md rule 9): `aes-gcm` in `larsal-crypto` with an AT-J03 review, or the approved `aes`, `cbc` and `hmac`.

## Rust rules

1. Edition 2024. Toolchain pinned in `rust-toolchain.toml`.
2. `#![forbid(unsafe_code)]` in every crate except `larsal-platform` and `larsal-hwkey` (and `larsal-web`'s `src/abi.rs` only, for the wasm exports, LD-274 (3)). In those two, `unsafe` lives only in `macos/` or `usb/` files, every block has a `// SAFETY:` note, and two Checkers review it. `larsal-ffi` carries the forbid too (confirmed in E5-S1): rustc does not report the `unsafe` in the scaffolding UniFFI's macros generate (it exports C symbols), and it refuses any hand-written `unsafe`.
3. Secrets use only `SecretBytes` and `SecretString`. No `Clone`, no `Debug` or `Display` output, no `format!` with a secret, no secret inside an error value.
4. No panics on input. In `larsal-crypto`, `larsal-format` and `larsal-core` these clippy lints are errors: `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`. Overflow checks stay on in release builds.
5. Every length read from a file is checked against `larsal-format/limits.rs` before anything is allocated.
6. MACs and keys are compared only with constant-time functions.
7. Random numbers come only from `larsal-crypto::random`. One exception (LD-194, LD-197, LD-220 (2)): rustls draws its TLS randoms through `ring` in larsal-platform's opt-in `net` client, which the Mac app links; they serve TLS only.
8. One error type per crate (`thiserror`). The screen gets plain-language messages from `larsal-ffi`. Details go to the debug log, without secrets.
9. Logging uses `tracing` with a filter that drops field values. Release builds log no vault content.
10. Tests: unit tests next to the code, standard test vectors for crypto, property tests for every round trip, a fuzz target for every parser.
11. Release profile: `lto = true`, `codegen-units = 1`, `panic = "abort"`, `overflow-checks = true`, symbols stripped. A Rust panic ends the app: UniFFI cannot turn it into a Swift error. This fails closed and is accepted.
12. No network in `larsal-crypto`, `larsal-model`, `larsal-format` or `larsal-core`. Network only in `larsal-platform/net.rs`, and only after the user turned the feature on.
13. Public functions say in plain words what they guarantee.
14. `rustfmt` formatting; clippy with warnings as errors.

## Swift rules

1. Swift 6 language mode, with the main actor as the default isolation. macOS 14 or newer.
2. `swift format lint --strict` and `swiftlint lint --strict`; warnings are errors.
3. Unit tests use Swift Testing; UI tests use XCTest UI testing (`LarsalUITests`).
4. Logging uses `os.Logger`. No vault content in any log (LD-67).
5. Plain SwiftUI with one `@Observable` view model per screen. View models hold view data only and call `larsal-ffi`. AppKit only where SwiftUI has a gap.
6. No Swift package from outside without an AT-J03 review and a line in the approved table.
7. Builds and tests run with `xcodebuild` and `DEVELOPER_DIR` set to Xcode (README, Checks).

## Main flows

- **Open:** path → bytes → `larsal-format` reads the header → `larsal-crypto` derives keys on a worker thread while the screen shows progress → header HMAC check (`WrongKey` if it fails) → block HMAC checks (`Corrupt` if one fails) → decrypt, decompress, parse → the `Vault` lives in the session.
- **Show:** Swift asks for one field of one entry → `larsal-ffi` returns that one value as a `String` → Swift drops it on Hide, on entry change and on lock.
- **Copy:** Swift calls `session.copy_field` → `larsal-platform` puts the value on the clipboard, marked concealed and transient, and starts the clear timer; Swift shows the countdown from an event. The value never reaches Swift.
- **Save:** `larsal-core` applies the change → `larsal-format` writes bytes with fresh random values → `storage.rs` writes a temp file next to the vault, syncs it to disk, swaps it in, and keeps a backup if that setting is on.
- **Lock:** the session drops the vault and its memory is wiped, our clipboard value is cleared, SSH keys leave the agent, the screen shows the unlock view.

## Performance targets

- Unlock: the KDF time (about 1 second by default) plus under 0.5 seconds for a 10,000-entry vault.
- Search: under 50 ms on 10,000 entries.
- Every click paints at once. Slow work shows progress in place.

## Sync server and sharing (E15 to E19)

Owner decision LD-262 (2): sync, family and teams are built now; billing, prices, the self-host package and the App Store follow once these work. The server is built and tested on this Mac only (127.0.0.1, demo data); nothing is hosted without the owner's yes (AGENTS.md rule 7), and the outside audit (D6) is booked before any server ships (LD-262 (5)). Every choice below and its sources: [spec/research/sync-server.md](../spec/research/sync-server.md) (picks P1 to P25; the lead's rulings LD-263 to LD-266). Nothing in this section changes a row above; each new crate gets its line in the approved table only when its AT-J03 review is signed.

### The shape

```
macos/            ── account, sync status, members, invite and code screens (Option A frames)
 ▼
larsal-ffi           ── feature `sync` (needs `net`): account, sync and sharing calls
 ▼
larsal-sync          ── the client: sign-in, the sync loop, the rollback guard, sharing      repository LICENSE
 ├── larsal-core        merge (MOD-11), credential change, save
 ├── larsal-platform    net.rs (HTTPS, pinned demo certificate), device_key.rs (Secure Enclave)
 └── larsal-proto     ── the wire format, shared with the server                          repository LICENSE
       └── larsal-crypto (signatures, HPKE, key wrap), larsal-model (json.rs only)

larsal-server        ── one binary: HTTPS, the store, the routes, family groups              repository LICENSE
 ├── larsal-proto, larsal-crypto, larsal-model (json.rs only)
 └── larsal-server-teams ── team features, feature `teams` only                           repository LICENSE
```

Cloud-folder sync (E15) adds no crate: coordinated access and the conflict-copy finder are Swift in `macos/Larsal/Platform/`, the deletion rule is larsal-core's merge.

Two separate sharing features (P24). E11's shared groups (INT-08, LD-262 (6)) are the free option with no server: `larsal-share` copies one group of your own vault to a container file protected by a share password, in a folder people share. E18's family and team sharing is server sharing: `larsal-sync` `share.rs` (with `larsal-proto` and `larsal-server`) handles shared vaults keyed by a random key, wrapped to each member, with a signed member list. Neither crate calls the other. The screens use different words: a shared group is "a group of your vault, shared as a file"; a family or team vault is "a vault shared through your server". The E16-S8 frames show both, side by side. A family can move later by importing the container into a new shared vault with the existing merge.

### New crates

| Crate | Licence | What it holds |
|---|---|---|
| `larsal-proto` | `LICENSE` | `routes.rs`: paths, methods and statuses (412, 428, 413, 403, 401, 429, P3). `messages.rs`: every request and reply record, read and written with larsal-model `json.rs`; vault bytes travel as raw bodies, never JSON. `signin.rs`: the challenge message (label, server origin, nonce, device id). `members.rs`: the member-list entry and the rules to accept one (P9). `wrap.rs`: the wrapped-key record (suite id, enc, ct, info, signer, signature) (P8). `compare.rs`: commit-then-reveal and the 6-digit code (P10). `limits.rs`: every size and count, checked before anything is allocated. Crypto only through larsal-crypto |
| `larsal-sync` | `LICENSE` | `client.rs`: HTTP calls through larsal-platform `net.rs` (Rust rule 12 holds). `sync.rs`: download, merge, safe-save, PUT with If-Match, retry at most 3 times, the timing of P3. `state.rs`: local state, never synced: per vault the highest version, the SHA-256 of the last synced bytes, the key epoch, the member-list sequence number and hash, pinned identity keys (P4). `account.rs`: sign-up, the account secret, the two-secret key wrap, the Recovery Kit, unlock, a new Mac (P6). `devices.rs`: device list, revoke, sign out everywhere. `share.rs`: groups, shared vaults, wraps, invites, the code compare, removal and the "Passwords <name> could see" list (P8 to P12) |
| `larsal-server` | `LICENSE` | `main.rs`: flags (Larsal's own parser, as larsal-cli), data folder, first-start certificate (rcgen) and its printed fingerprint, binds 127.0.0.1 by default. `http.rs`: the hyper service, one route match, body limits (http-body-util), timeouts, rate limits. `tls.rs`: tokio-rustls with ring. `store.rs`: SQLite (WAL, `synchronous=FULL`): accounts, devices, sessions, vault rows, member lists, wraps, invites. `blobs.rs`: content-addressed vault files (temp file, `F_FULLFSYNC`, rename), the compare-and-swap commit, the orphan sweep at start, old versions kept for restore. `auth.rs`: challenges, session tokens (SHA-256 stored), idle and absolute expiry. `vaults.rs`, `accounts.rs`, `groups.rs`: the routes, with family groups (Organizer and Member, at most 6). Its current original material follows the repository LICENSE; the former server-specific license choice is recorded in LD-266 (3) |
| `larsal-server-teams` | `LICENSE` (the former separate team-license draft is retained as history only) | The only folder with paid code. Team groups: Owner, Admin, Member, Read-only, per-vault Can view, Can edit, Can manage, many shared vaults per group. Later (LD-262 (2)): seats and the license-file check. Linked into `larsal-server` only through the cargo feature `teams`; the build without it is the server for families. The Mac app never holds paid code. Licensing follows `LICENSE`, with third-party material and any earlier grants retaining their own terms; the former contributor-agreement plan is historical (LD-262 (3), superseded by LD-345) |

Additions to existing crates (new files, no existing row changed):
- `larsal-crypto`: signatures (ECDSA P-256 verify, Ed25519 sign and verify) in `sign.rs`; `hpke.rs` (HPKE base mode, the one suite of P8, single-shot seal and open); `wrap.rs` (AES-256-GCM key wrap, and the two-secret key: Argon2id over the account password combined with the account secret through HKDF, P6).
- `larsal-platform`: `device_key.rs` (the P-256 sign-in key in the Secure Enclave through `security-framework`, this device only; a software P-256 key in the data protection keychain where there is no Secure Enclave. Before W-02 gives the entitlement, neither store works (TN3137): cargo tests use a software key behind a test seam, and the app keeps a software key in the login keychain; the this-device-only checks stay open until W-02); `net.rs` gains PUT, request headers (If-Match, If-None-Match, the session token) and a pinned-certificate path for the demo server (SN-03 review).
- `larsal-ffi`: feature `sync` (needs `net`), additive; without it no sync code is linked, so the no-network build (SN-05) remains.
- `scripts/check.sh`: a "server blind" line that fails when `cargo tree -p larsal-server` holds `larsal-format`, `larsal-core`, `larsal-platform`, `larsal-ffi` or `larsal-sync` (P16).

### How data flows

- **Add a vault to the server:** larsal-core adds a random 32-byte key-file part through the credential change and saves (P7) → larsal-sync wraps that part with HPKE to the account's own X25519 key (from E17-S1; until then the part stays in the device store of this Mac, E16-S7b) → PUT of the vault bytes with `If-None-Match: *` (a new vault), then the wrap record → the server writes the blob file, then commits the row.
- **Sync:** for each linked vault, GET with `If-None-Match` (304 when the server still holds the version this Mac saw; `GET /v1/vaults` lists ids, versions and sizes when the user picks a vault, SYN-03.2, SYN-03.5) → larsal-core opens it and merges the local copy into it (the deletion pass included, P2) → safe-save locally → PUT with `If-Match` and the uploader's Ed25519 signature over vault id, version and SHA-256 (for a shared vault, also over the group, the epoch and the uploader's member-list head, SHR-03.10) → on 412, again (at most 3) → `state.rs` records the new version and hash; anything older than the record is refused (P4). The signature needs the identity key, so PUT signing of personal vaults starts in E17-S1; until then the version and hash guard of P4 applies alone. A key change follows LD-264 (P3): the merge result takes the newer of the two keys, except that a copy under a key this Mac retired never gives its key or its deletions (LD-267 (2)); if the server copy does not open with this Mac's key, Larsal asks for the credentials that copy opens with (MOD-11.29, APP-05.29), never "the new" ones, and uploads nothing until it opens. For a shared vault, LD-290 (2) applies instead: a version that passes SHR-03.12's signed-upload check and opens with the key of its epoch is a copy of the same vault, and every upload takes the current epoch's key with no question (SHR-01.13, SHR-01.14).
- **Sign-in:** the server sends a nonce → the Secure Enclave key signs the challenge of `larsal-proto` `signin.rs` → the server checks it with the stored public key and returns a 32-byte session token (it keeps only the SHA-256).
- **A new Mac:** the existing Mac and the new one run the code compare (P10) → after "Codes match" the existing Mac seals the account secret to the new Mac (HPKE) and signs its device key → the user types the account password on the new Mac, which unwraps the account keys from the server's blob. Or: the Recovery Kit (its recovery sign-in key) plus the account password.
- **Share:** a member makes a group (the first, self-signed member-list entry) and a shared vault keyed only by a random 32-byte key → an Organizer (team: an Owner or Admin) makes an invite code (5 days, one use, no key inside) → the code compare → "Codes match" on both Macs → the newcomer signs its consent → the inviter signs the add entry with that consent, and a signed HPKE wrap of each vault key the newcomer may read → the newcomer checks the whole list from its first entry, pins every key in it (the inviter's must equal the compared one) and opens its wraps (SHR-03.7, SHR-03.8, SHR-01.10).
- **Remove a member:** the admin signs the remove entry (new epoch) → a new vault key, the credential change, the save → new wraps for the others → PUT with `If-Match` → the server deletes the removed member's wraps and open invites, and answers them 403 on the group's routes while the list does not name them (SHR-04.5) → Larsal shows the "Passwords <name> could see" list (items deleted for good show as one line with their count and dates, since the deleted-objects list keeps no names).

### What the server sees

**Zero-knowledge is Larsal's core promise (LD-340).** No server of ours, and no one who runs or breaks into one, holds anything that can open a vault, a file or a key, or test a guess at a password. It holds against a hostile server, not only on the way between two ends, and every feature follows it, the new ones too (E21 to E24). E13-S8 proves it with tests.

| The server sees | The server never sees |
|---|---|
| Account ids, device public keys, the recovery public key, session token hashes | Any password, master password or account password, in any form: no hash, no verifier, no OPAQUE record |
| Who is in which group and with which role (the signed member list), identity public keys | Vault contents, entry counts, entry types or entry times |
| Each uploaded vault's outer header, in clear by format (FMT-02), and in it field 12, public custom data (FMT-03.22, SYN-03.14): it can hold text a user typed, such as a public name (MOD-12.4, SF-12) | Anything in the vault's encrypted part |
| Vault ids, versions, sizes, upload times, IP addresses | Vault keys, key-file parts, the account secret, private keys (it holds them only wrapped: under HPKE to a member's key, or under the two-secret key of P6) |
| Invite codes (as hashes) and the commitment messages of a code compare | The 6-digit code itself until both sides reveal; it cannot make a valid one (one guess, P10) |

The server can still refuse service, delete data, hold back or replay old versions to one member, or fork two members. Clients catch rollback with local state (P4), and a client refuses a member-list fork it sees (P9, E18-S2). Every upload of a shared vault names the uploader's member-list head, signed with the upload, so a member who reads a version made on another branch refuses it and stops using the group (SHR-02.12; LD-290 (3)). Data the server makes or replays alone never stops a group (SHR-02.9). A server that also keeps the vault apart, or holds entries back from one member, is found only when two members pick Sync now and compare the entry number and the list code on the members page (SHR-02.13; SUNDR); that is the remaining known limit.

### Rules for this part

1. The server never links the vault reader: the "server blind" check of P16.
2. Nothing made from a password leaves the Mac, except the account-key blob, which also needs the 256-bit account secret (P6).
3. Clients trust signatures, never the server's word: member lists, key wraps and uploads are checked on every Mac (P9, P11).
4. Every request parser has a fuzz target; every body has a size limit before it is read.
5. The server binds 127.0.0.1 and runs with demo data until the owner says yes to hosting.
6. Rust rules 1 to 14 apply to every new crate, with the clippy lints of rule 4 as in larsal-core. Two exceptions, recorded like LD-220 (2) (P20, LD-263 (18)): `larsal-server` holds the server's own network code (Rust rule 12 names only the client's `net.rs`), and its TLS (tokio-rustls, rustls, ring, and rcgen for the TLS certificate and key only) imports crypto outside larsal-crypto and draws TLS randoms through ring (rules 3 and 7). Session tokens, nonces and invite codes still come from `larsal-crypto::random`.
7. Crypto, Keychain and secret handling get two Checkers, as everywhere. `device_key.rs` uses `security-framework`'s safe API; any `unsafe` it needs stays in larsal-platform `macos/` (Rust rule 2).

### Approved crates to add

After each AT-J03 review, as listed with reasons in [spec/research/sync-server.md](../spec/research/sync-server.md), section 11, each at the newest release that is at least 14 days old on the day its vendoring story starts (P21, LD-266 (5)): `hpke` (with `x25519-dalek`, `zeroize_derive`; larsal-crypto only), `aes-gcm` as a direct larsal-crypto dependency, `security-framework` for `device_key.rs` (with `core-foundation`, `core-foundation-sys` and `security-framework-sys`; its copy is made by E16-S6 unless E6-S3 made it), and for `larsal-server` only: `hyper`, `hyper-util`, `http-body`, `http-body-util`, `tokio` (with `mio`, `socket2`), `pin-project-lite`, `futures-core`, `atomic-waker`, `httpdate`, `smallvec`, `tokio-rustls` (`ring`), `rusqlite` (`bundled`, with `libsqlite3-sys`, `fallible-iterator`, `fallible-streaming-iterator`, and the build-only `pkg-config` and `vcpkg` that libsqlite3-sys's build script needs to compile), and `rcgen` as a normal dependency. `windows-sys` and `wasi` are never copied: the tokio, mio and socket2 copies lose the target tables that name them, as the tree does today (LD-303). The AT-J03 review of all of them is LD-303; the versions are the 2026-11-01 answer of LD-301 (1).

## Browser extension and web vault (E7, E20)

Owner decision LD-272: Larsal builds its own browser extension for every major browser, Chrome and Safari first, then Firefox, Edge, Brave and the other Chromium browsers; and a web vault served by Larsal's own server, after E16 and the account part of E17. Everything is built and tested on this Mac first; store accounts, fees, publishing, a domain and hosting are owner steps (AGENTS.md rule 7). Every choice below and its sources: [spec/research/browser-and-web.md](../spec/research/browser-and-web.md) (picks B1 to B30); the lead writes the LD rows. Nothing in this section changes a row above; B3 is taken (LD-274 (1)): the `bridge.rs` row and the "Browser bridge channel (E7)" row above say so. No outside crate or package is added: the extension's channel uses the browser's own WebCrypto (B3), and Larsal's side uses `x25519-dalek`, `hkdf` and `aes-gcm`, which E16-S2 brings.

### The shape

```
Chrome, Edge, Brave, Vivaldi, Opera, Chromium, Arc, Firefox
  extension/        ── popup, options page, in-page frames (extension origin), content scripts, background
   │  native messaging (stdin/stdout); every message after hello sealed with WebCrypto (INT-01)
   ▼
  larsal-bridge        ── relay program in Larsal.app/Contents/MacOS: copies frames, holds no key
   │  Unix socket in the user temp folder (INT-01.6)
   ▼
  Larsal (macos/ + larsal-ffi) ── larsal-browser: channel, associations, matching, prompts, passkeys
                            (larsal-core, larsal-crypto)

Safari
  extension/ (Safari build, the same files)
   │  browser.runtime.sendNativeMessage
   ▼
  Larsal's Safari app extension (macos/, sandboxed, app group only) ── relay, holds no key
   │  Unix socket bridge.sock in the app-group container (INT-01.13)
   ▼
  Larsal ── larsal-browser (the same code)

Any browser, Larsal not installed
  web/ index.html, app.js, app.css  +  vault.wasm (larsal-web)
   │  HTTPS fetch from the same origin: WebAuthn sign-in, the account blob, vault bytes, wraps
   ▼
  larsal-server        ── static route for web/ (strict headers, signed manifest), WebAuthn routes, the E16 to E18 routes
```

### Parts

| Part | Where | Licence | What it does | What it never does |
|---|---|---|---|---|
| The extension | `extension/`: `background.js` and its modules (ES modules), `popup/`, `options/`, `frames/` (the 7 in-page frames as extension pages), `content/` (classic files in a fixed order), `page/` (the passkey page script), `manifest.json.in`, `build.py`, `test/`; data files `_locales/`, `words.txt` and `public_suffix_list.dat` (MPL-2.0 data, kept unchanged with its license file, LD-221 (1), LD-295 (2)) | `LICENSE` | Draws Option A's 15 extension frames; finds sign-in fields; asks Larsal for matches, entries, codes, passwords and passkeys; fills on a user action (B9); keeps its identification key as a non-extractable WebCrypto key in IndexedDB (B3) | Stores a password or any vault data; runs code that is not in its own files; uses `innerHTML`; takes a page's word for its URL or origin (only `runtime.MessageSender`, B9) |
| `larsal-bridge` | `crates/larsal-bridge/` (new binary crate), built into `Larsal.app/Contents/MacOS/` | `LICENSE` | The host program of INT-01.4 and INT-01.5: hardening (APP-11), then copies length-prefixed frames between standard input and output and Larsal's socket; answers 43, 44 and 45 itself | Holds a key, opens a box, links larsal-crypto, larsal-format or larsal-core |
| Safari app extension | A Safari web extension target in `macos/Larsal.xcodeproj` (`SafariWebExtensionHandler.swift`); its resources are the Safari build of `extension/` | `LICENSE` | Relays each Safari message, unchanged, to `bridge.sock` in the app group `‹team id›.app.larsal.browser` (INT-01.13) | Keeps state, reads content, touches the Keychain, unlocks |
| `larsal-browser` | `crates/larsal-browser/` (E7, already in the plug-in table) | `LICENSE` | The channel and its limits (INT-01), associations and site access (INT-02), URL matching (INT-03), passkeys (INT-04), the manifest writer for each browser (INT-01.8 to INT-01.11), the two sockets | Writes outside the INT-01.8 folders; sends anything in clear but the plain errors |
| `larsal-web` | `crates/larsal-web/` (new), the only crate built for `wasm32-unknown-unknown`, into `vault.wasm` | `LICENSE` | For the browser what larsal-ffi is for Swift: the signed-in account and the open vaults in wasm memory, about 15 byte-buffer exports and two imports (random, time) in `src/abi.rs` (B15) | Links larsal-platform, larsal-sync or larsal-ffi; makes a request (JavaScript fetches; Rust rule 12 holds) |
| The web pages | `web/`: `index.html`, `app.js` (one ES module, no imports), `app.css` (Option A's locked CSS and its local fonts) | `LICENSE` | Sign-in with a passkey, unlock, browse, search, Show, Copy, codes (B26); edits later | Keeps a token or key in any storage API; builds DOM from strings |
| larsal-server additions | `crates/larsal-server/` `web.rs` (static route, headers, manifest check), `webauthn.rs` (register and assert); larsal-proto `webauthn.rs` (CBOR and COSE reader, fuzzed) | `LICENSE` | Serves `web/` and `vault.wasm` with B21's headers, only when the folder matches its signed release manifest (B22); checks WebAuthn assertions with larsal-crypto's P-256 verify; stores the PRF-wrapped blob per passkey | Links larsal-web, larsal-format, larsal-core, larsal-platform, larsal-ffi or larsal-sync (the P16 check also names larsal-web) |

Additions to existing crates and files (new files or new functions, no existing row changed):
- `larsal-crypto`: the channel's key schedule (X25519, HKDF-SHA256, AES-256-GCM) in a new `bridge.rs`, from E7-S1 on top of E16-S2's crates. On wasm, `larsal-crypto::random` stays the only door; it reaches `crypto.getRandomValues` through getrandom's custom backend, whose one function larsal-web defines with the error type larsal-crypto re-exports (`larsal_crypto::random::BackendError`), so larsal-web never depends on getrandom (B16).
- `larsal-format`: open and save take the time from the caller (B17).
- `vendor/crates-io/getrandom-0.4.3/src/backends/custom.rs` restored byte for byte from upstream (LD-221 (3), (7)); `.cargo/config.toml` sets `getrandom_backend = "custom"` and `curve25519_dalek_bits = "64"` for the wasm target only.
- `macos/`: the Safari target, the app-group entitlement on Larsal and on its app extension (needs a team id: D7, or the free personal team if it can sign a group), and a build phase that copies `larsal-bridge` into the bundle.
- `scripts/repro-build.sh`: builds `larsal-bridge` with Larsal, and `vault.wasm` with the web release manifest.

### How data flows

- **Hello:** the background opens one `connectNative` port → the browser starts `larsal-bridge` → the background makes a WebCrypto X25519 session key pair and sends hello → Larsal answers with its session key and a `sid` → both derive the two direction keys with HKDF; from then on every message is AES-256-GCM (B3). On `onDisconnect` the background connects again and says hello again (B4).
- **Matches:** a content script reports sign-in fields → the background takes `url`, `origin` and `frameId` from `runtime.MessageSender` → `logins.find` → Larsal matches (INT-03) and returns summaries without secrets (D-INT01-9) → the background draws them only in the popup or in an extension-origin frame, where the page cannot read them.
- **Fill:** the user picks an entry in the in-page menu (after the B10 checks), presses Fill in the popup, or uses the keyboard command → `logins.get` → Larsal applies site access (INT-02), asks when needed, also for INT-02.19's frames and forms of other sites → the reply reaches the background → the background sends the user name and password to that one frame's content script, which fills and drops them.
- **Save and update:** the content script sees a submitted form → the save or update frame asks the user → `logins.save` or `logins.update` → Larsal saves through larsal-core.
- **Passkeys:** the page script in the page's world wraps `navigator.credentials` → the content script passes the options to the background → `passkey.create` or `passkey.get` with the origin from `MessageSender` → Larsal checks and signs (INT-04) → the response goes back to the page; when Larsal refuses or is not reachable, the browser's own passkey flow runs.
- **Safari:** the background sends each message with `sendNativeMessage` → Safari calls Larsal's app extension → it relays one frame to `bridge.sock` and returns one reply frame → Larsal finds the session by `sid` (INT-01.14).
- **Unlock and lock:** `unlock` makes Larsal show its own unlock panel (B8); the extension never sees a master password. Larsal's notices (INT-01.46) tell Chrome-family and Firefox sessions about lock changes; Safari's popup asks `status` when it opens.
- **Web sign-in:** the page asks for a challenge → WebAuthn `get` with that nonce, user verification required → larsal-server checks the assertion with larsal-crypto's P-256 verify → a 32-byte session token, kept only in the module's memory (B20, B23).
- **Adding a browser:** larsal-web makes a one-time HPKE key → a signed-in Mac runs the SYN-05 code compare and seals the account secret to it, or the user types the Recovery Kit → the page registers its passkey as a device, signed with the identity key by the approving Mac (SYN-06.11 step 5) or, in the kit path, by larsal-web after the account unlock; the server refuses an unsigned one → with PRF, the account secret is wrapped under HKDF of the PRF output and stored on the server per passkey (B24).
- **Web unlock:** the user types the account password → larsal-web unwraps the account keys (P6) → per server vault, it unwraps the key-file part (P7) and opens the vault with its master password in wasm (Argon2 at the vault's own settings, B18) → JavaScript gets list text only.
- **Show and Copy on the web:** JavaScript asks for one field of one entry → larsal-web returns that one value → JavaScript shows or copies it inside the click and drops it on Hide, on entry change and on lock (B19, B25).
- **Web lock:** idle 300 s, reload, tab close, `pagehide` or a trap → larsal-web drops the session (its types wipe) → JavaScript zero-fills the wasm memory and drops the instance (B19, B20).

### What each part can see

| Part | Can see | Never sees |
|---|---|---|
| A web page the user visits | Its own DOM, including the fields Larsal fills at the moment of fill | The in-page menus' content (extension-origin frames in a closed shadow root), match lists, any other entry, the channel keys |
| A content script | The page's fields; the one user name and password the background hands it for a fill | Other entries, the identification key, the channel keys |
| The background | Session keys (non-extractable), the identification key (non-extractable), summaries and the entries the user asked for, while it draws or fills them | A master password, a vault key, a vault file |
| `larsal-bridge`, the Safari app extension | Message lengths and sealed bytes | Any plain content, any key |
| Larsal (`larsal-browser`) | Everything in its unlocked vaults, as today | The pages themselves; only the URLs the extension sends |
| The web page's JavaScript | List text, the one Show or Copy value, sealed bytes from the server, the session token | The account secret, account keys, vault keys, the decrypted vault outside what it was given (they stay in wasm memory); but served code can read wasm memory (B19, B22) |
| larsal-server | What "What the server sees" above lists, plus WebAuthn public keys and the PRF-wrapped blob, which it cannot open | The PRF output, the account password, any vault content |

The web vault trusts the server that serves its code; the Mac app and the signed extension do not (B22). That is a known limit, said on the sign-in page and written by the lead like LD-266 (4); the signed release manifest and, later, the extension's check of the served files narrow it.

### Rules for this part

1. The extension stores no vault data: only its identification key (non-extractable), its settings, and, in memory, the replies it is drawing or filling (INT-01, B3).
2. The extension runs only its own packaged files: no remote code, no outside package, no bundler output, the default MV3 CSP, no `innerHTML` (B1, B2).
3. Every fill needs a user action, and every URL, origin and frame id comes from `runtime.MessageSender` (B9); the in-page frames run B10's checks before a click counts.
4. `larsal-bridge` and the Safari app extension relay bytes only; they never open a sealed message.
5. `larsal-web` is the only wasm crate; `unsafe` lives only in its `abi.rs`, each block with a `// SAFETY:` note and two Checkers (a Rust rule 2 exception like larsal-platform's, B15). It never links larsal-platform, larsal-sync or larsal-ffi; larsal-server never links it.
6. On the web, secrets live only in wasm memory; no storage API holds a token or a key; a lock wipes and drops the instance (B19, B20). Random numbers come only from `larsal-crypto::random`, through the custom getrandom backend on wasm (B16).
7. Every web response carries B21's headers; larsal-server serves only a `web/` folder that matches its signed manifest (B22).
8. Tests never take the owner's screen (rule 10): headless Chrome with a throwaway profile and a test HOME, test sites on `.test` names with a certificate only that profile trusts (never an IP host: WebAuthn refuses one), macOS's `jsc`, offscreen `WKWebView`; runs in real Safari and Firefox windows wait for the owner's go. No test writes into the owner's browser folders (INT-01.10).
9. Crypto, `unsafe`, the channel and the web unlock path get two Checkers, as everywhere.

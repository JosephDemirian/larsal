# E13-S1 Parity sign-off, group SI (Integrations)

Story: E13-S1 Parity sign-off. Matrix: [plan/security.md](../../plan/security.md), table "Integrations (SI)". Cards: INT-01 to INT-09 in [spec/integrations](../../spec/integrations/).
Date: 2026-10-29.
Role: Verify for group SI. I did not build any of these parts. I read the reference source and ran the reference app's command line tool, read only, with a throwaway `HOME` under /tmp.

## Result

| Row | Result | Why |
|---|---|---|
| SI-01 | waits for E7-S1 and D4 | No browser bridge in App yet (no `app-browser` crate, no `extension/`) |
| SI-02 | waits for E7-S2 and D4 | Same |
| SI-03 | waits for E7-S3 and D4 | Same |
| SI-04 | waits for E7-S4 and D4 | Same |
| SI-05 | waits for E7-S5 and D4 | Same |
| SI-06 | waits for E8-S2 (Swift part) and E8-S3 | The matching and picker model are built and pass; typing, the focus check and the picker window are not built |
| SI-07 | **verified** | Every behaviour of the row re-checked today with my own driver against a throwaway OpenSSH agent, plus the builder suites |
| SI-08 | **verified** (software only, OD-01) | The reference's own hardware-key test vault opens in both tools with the same answer; same composite key; device tests pass on the simulated key. A real-key run stays open |
| SI-09 | waits for E11 and W-15 | No share import or export yet. The core merge rule of LD-61 already passes (T52) |
| SI-10 | waits for E7-S4 and D4 | No browser bridge |
| SI-11 | waits for E7-S4 and D4 | Same |
| SI-12 | waits for E7-S1, E7-S2 and D4 | Same |
| SI-13 | waits for E11 and W-15 (D-INT09-1) | No remote sync in App |
| SI-14 | waits for E8-S3 | No typing and no permission request yet. The row's reference text is wrong (finding F1) |

Findings: F1 (Low, matrix wording, SI-14). F2 (Low, two timing tests fail at a load average near 300). No row shows App weaker than the reference.

## Setup

- Shared build: `CARGO_TARGET_DIR=/tmp/e13s1-target`, toolchain 1.99.1, `--locked`.
- Probe code only in a private copy: `rsync -a --exclude target --exclude app-shots --exclude /fuzz/artifacts` of the tree to `/tmp/e13s1-SI-copy` at 20:42, with its own target `/tmp/e13s1-SI-copy-target`. The driver `crates/app-sshagent/tests/vfy_si07.rs` exists only there. No product file was changed.
- **The owner's agent was never contacted.** Every cargo run had `SSH_AUTH_SOCK` pointing at a canary socket (`/tmp/e13s1-si/canary.sock`, python listener PID 67869). Its log after all runs: `canary up` and no connection. Every `ssh-agent`, `ssh-add` and `ssh-keygen` ran with a cleared environment (`PATH=/usr/bin:/bin`, `HOME=/tmp/e13s1-si/a`). The one throwaway agent (PID 7607) was stopped by its PID when the driver ended. `ps -p 7607` then found nothing.
- Reference tool runs: `env -i HOME=/tmp/e13s1-si/home PATH=/usr/bin:/bin TMPDIR=/tmp/e13s1-si/home`, on a copy of the reference's hardware-key test vault (`/tmp/e13s1-si/ref/hk.vault`, SHA-256 `566be617…8fad3b`, the same before and after every run).
- Other agents edited the tree and built in the shared target during my runs. The load average went from 200 to 363. Two effects:
  - The first doc-test run failed with "can't find crate". The re-run passed (0 doc tests in all three crates).
  - The first `app-ffi --test ssh` run failed to compile: another story added `app-platform` to app-core at 20:46:08. The re-run compiled.
  - The two timing failures are in F2.
- No window, no screen capture, no pasteboard, no keychain.

## SI-01 Browser bridge encryption and association

**Reference.** It uses a public-key box (X25519 key agreement with XSalsa20-Poly1305) from libsodium. The key pair is made per session. A small relay program carries the messages over a local socket that only the user can open. The installed manifests list only the official extension ids. An association needs the user's confirmation and a name, and it is kept in the vault. A message may be up to 1 MiB / 1.6 = 655,360 bytes (640 KiB). Each reply carries the request nonce plus one, and no list of used nonces is kept.

**App.** Not built. `ls crates` lists `app-autotype app-cli app-core app-crypto app-ffi app-format app-hwkey app-model app-platform app-sshagent uniffi-bindgen`, with no `app-browser`. `ls extension` says "No such file or directory". The root manifest only pins `crypto_box = "=0.9.1"` for E7. E7-S1 is `todo` in plan/epics.md, and E7 starts after decision D4 (README: "Not in the first Mac build").

**Result:** waits for E7-S1 and D4. Status left `todo`.

## SI-02 Site access prompts

**Reference.** A site gets a credential only after the access dialog. Allow and Deny are remembered per entry, for the site host and the form host. HTTP authentication always asks unless its option is on (default off). Always-allow access is an option (default off). The defaults in its config table: `AlwaysAllowAccess` false and `HttpAuthPermission` false.

**App.** Not built (see SI-01).

**Result:** waits for E7-S2 and D4.

## SI-03 URL matching

**Reference.** It matches by registrable domain and host suffix, by port when the entry has one, and by scheme (`MatchUrlScheme` default true). Paths count only for quoted and wildcard additional URLs. A local file page needs an exact match.

**App.** Not built (see SI-01).

**Result:** waits for E7-S3 and D4.

## SI-04 Per-entry browser settings

**Reference.** Entries and groups can hide from the browser, skip auto-submit, follow HTTP auth rules, ignore a leading www, or answer one association only. Expired entries are left out unless `AllowExpiredCredentials` is on (default false). Extra string fields with the bridge's field prefix are sent (`SupportKphFields` default true).

**App.** Not built (see SI-01).

**Result:** waits for E7-S4 and D4.

## SI-05 Passkeys

**Reference.** The passkey code checks that:
- the challenge has at least 16 characters;
- the user id is 1 to 64 bytes;
- the origin is https, with localhost and file pages only under `AllowLocalhostWithPasskeys` (default false);
- the key type is ES256, RS256 or EdDSA.

The confirm dialog runs a countdown timer.

**App.** Not built (see SI-01). Card INT-04 exists.

**Result:** waits for E7-S5 and D4.

## SI-06 Auto-Type

**Reference.** Global Auto-Type:
- returns at once when one of its own windows is active;
- remembers the active window;
- waits the start delay, bounded to 100 to 10,000 ms;
- before each action, stops when the active window changed ("Active window changed, interrupting auto-type").

Limits: at most 100 repeats and a key delay of at most 500 ms. The picker is closed by the main window's "database locked" signal. Options: relock after Auto-Type (default false), always ask (default true), skip the main-window confirmation (default false). The source does not skip recycle-bin entries by itself.

**App.** Built so far: the parser (E8-S1, Done) and the Rust part of E8-S2 (matching, the picker model, recycle bin left out). Today, in the tree:

```
cargo test --locked -p app-sshagent -p app-hwkey -p app-autotype --no-fail-fast
  app_autotype lib      test result: ok. 3 passed
  tests/int05.rs        test result: FAILED. 50 passed; 1 failed   (t40, see F2)
  tests/int05_match.rs  test result: ok. 37 passed
t40 alone, 5 runs of the built binary: ok, ok, ok, ok, ok
```

Not built: typing, the focus check before each key, the floating picker, and lock and relock in the app (E8-S2 Swift part, E8-S3 `todo`). `grep -rl "CGEventPost|CGEventCreateKeyboardEvent|AXIsProcessTrusted" crates macos` finds only `macos/App/AppSettingsModel.swift`, which reads `AXIsProcessTrusted()` to show a status in Settings.

**Result:** waits for E8-S2 and E8-S3. Status left `todo`.

## SI-07 SSH agent

**Reference** (agent client, entry settings, key reader, main window):
- **Settings.** A new entry's settings are all off, and the lifetime is 600 s.
- **Unlock.** Every entry not in the recycle bin whose key is allowed and set to add on open is added. Constraints are sent when lifetime or confirm is on.
- **Other vaults.** A key that its records hold for another vault is refused ("ownership conflict").
- **Lock.** Keys marked remove-on-lock are removed. Every record of that vault is dropped.
- **Turning the feature off and quit.** Both call the same remove-all-identities routine, which removes only the marked keys.
- **The menu action.** It sends the agent's remove-all message (19, and the old 9), so other programs' keys go too.
- **Key files.** Encrypted keys use bcrypt-pbkdf with the round count read from the file, with no bound. The old PEM form uses an MD5 key derivation.
- **Key generator.** The source has one: RSA 2048 to 4096, ECDSA 256 to 521, and Ed25519.

**App, today.**

1. Builder suites (tree, canary socket):

```
app_sshagent lib       test result: ok. 22 passed
tests/agent.rs         test result: ok. 24 passed   (t31 lifetime, t32 confirm, t35 remove all, at_h01, t22 rounds, t16 old forms)
tests/own_agent.rs     test result: ok. 34 passed   (t40_t41 other vault, t42 at_h01 lock, t46 turn off, t70 remove all, t53 ask)
app-ffi tests/ssh.rs   test result: FAILED. 15 passed; 1 failed   (int06_22: 900 ms bound at load ~300, see F2)
  int06_22 alone, 3 runs: ok (3.96 s, 4.05 s, 3.51 s)
app-crypto ssh         test result: ok. 7 passed; ssh_wipe: f_070_unknown_type_private_bytes_are_wiped_on_drop ... ok
```

2. My own driver (private copy, `cargo test --locked -p app-sshagent --test vfy_si07 -- --nocapture`). It used app-sshagent's public API only and one throwaway `/usr/bin/ssh-agent -D -a`. The demo keys were made by `ssh-keygen`. Each list is `ssh-add -l` run from outside, comments sorted. Setup:
   - **Vault A** holds:
     - kA, marked;
     - kB, P-256, protected with `demo-ssh-pass`, unmarked;
     - kC, not added on unlock;
     - kE, not allowed;
     - kL, lifetime 2 s;
     - kQ, ask first;
     - kD, in the recycle bin.
   - **Vault B** holds kA again, unmarked.
   - **kX** is added by `ssh-add`, as another program would.

```
1 defaults: allow false add_at_open false remove_at_close false confirm false use_lifetime false lifetime 600 s
2 other program added kX: ["kX"]
3 unlock A: ["kA", "kB", "kL", "kX"] refused [] in 570.005416ms
3 ask-first key kQ: place Some(Own), in system agent: false
3 lifetime: at 1.00570375s kL listed true
3 lifetime: at 3.001570166s kL listed false
4 unlock B refused "A again": MI06-05 OtherVault("Vault A") "This key is already loaded from another open vault, Vault A. Lock that vault or remove the key there first."
4 after B: ["kA", "kB", "kX"]
5 lock A in 373.792µs, refused 0: ["kB", "kX"]
6 unlock B again: refused 0: ["kA", "kB", "kX"]
7 turn off: refused 0: ["kB", "kX"]
8 before remove all: refused 0: ["kA", "kB", "kX"]
8 remove all: Ok("ok"): ["has"]
9 rounds: MAX_ROUNDS 1000; 1001-round key: MI06-16 TooManyRounds(1001) in 2.25µs
test vfy_si07 ... ok
```

What the driver showed, by step:
- **Step 3:** only allowed, add-on-unlock keys outside the bin went in (no kC, kD or kE). The protected key was decrypted in memory from the entry's password. The lifetime reached the agent: kL was listed at 1.0 s and gone at 3.0 s. The ask-first key went to App's own agent, never to the system agent (D-INT06-1 (b)).
- **Step 4:** the other-vault refusal, as in the reference, and App names the vault.
- **Step 5:** the lock removed the marked key in 0.37 ms (AT-H01) and kept the unmarked one and the other program's key.
- **Step 7:** turning the feature off removed B's unmarked kA, the extra step App takes (LD-63). It left kX, the other program's key. kB stayed because A's lock had dropped its record, as the reference does (INT-06.24).
- **Step 8:** remove all emptied the agent, other programs' keys included. "has" is the third word of `ssh-add -l`'s "The agent has no identities."
- **Step 9:** a 1,001-round key was refused before any key derivation, the bound the reference lacks (INT-06.9).

The reference's quit behaviour (keep unmarked keys, remove marked ones) is `int06_25_quit_keeps_unmarked_keys_and_removes_apps_socket`, which passed in the app-ffi run above.

Differences that are not weaker:
- DSA and the MD5-based PEM form are refused (D-INT06-2, test `t16_old_forms_dsa_and_text_are_refused`).
- There is no key generator (D-INT06-6; `ssh-keygen` makes keys). This is a missing feature, not a security gap.
- "Ask before each use" is App's own question, where the reference sends the confirm limit to an agent that cannot ask on a stock Mac.

Still open, not part of this row's proof: V-INT06-3 (the macOS system agent itself, owner's go). The throwaway agent is the same `/usr/bin/ssh-agent` binary.

**Result: verified.**

## SI-08 Hardware keys

**Reference** (composite key and challenge-response key):
- **Version 4.** The challenge is the KDF seed. Each device's 20-byte answer is hashed. The SHA-256 over those hashes is added after the other key parts, and the KDF then transforms the whole key.
- **Version 3.** It challenges with the master seed and adds the answer after the transform.

**App, today.**

```
python3 -I py/hk.py ref/hk.vault      (secret and salt of FMT-01 Vector HK)
salt in file: True
var answer ec5f7c1427d8b26b9984228abb98621b1165ba18 R 709b0674…5bf6a C df5d072b…d8bfa1
fix answer 9c401f62a28029f837efbec2c66c5a0ff89a19c0 R ac09bcf2…9f797d C 23112080…f06d6e

cargo test --locked -p app-format --test keys   test result: ok. 40 passed (twice)
  fmt_04_6_e_vector_hk asserts R = 709b0674…, C = df5d072b… (variable) and C = 23112080… (fixed): equal to python
cargo test --locked -p app-hwkey   lib: ok. 37 passed; real_key: 1 passed, 1 ignored (T53, real key, OD-01); watch: ok. 1 passed
```

The same reference vault, password `a`, with the variable-mode answer as a 20-byte key file. The key-file part is SHA-256 of the answer, which is the same bytes the hardware part adds, so this checks the whole composite key without a device:

| Tool | Answer | Exit | Output |
|---|---|---|---|
| Reference CLI `db-info` | variable | 0 | "Cipher: AES 256-bit", "KDF: Argon2d (8 rounds, 131072 KB)", "Number of groups: 1", "Number of entries: 2" |
| Reference CLI | fixed | 1 | "Invalid credentials … (HMAC mismatch)" |
| Reference CLI | none | 1 | same |
| App `app db-info` (debug build of today's tree) | variable | 0 | "Key derivation: Argon2d, 128 MiB, 8 iterations, 4 lanes", "Groups: 1", "Entries: 2" |
| App | fixed | 1 | "Wrong password, key file or security key. Check them and try again." |
| App `--hw-key 2`, no key plugged in | — | 1 | "Your security key is not connected. Plug it in, then try again." (AT-H03, M06-17) |

The device side (frames, CRC, slots, touch wait, missing key, wrong key giving the wrong-password result) passed today in app-hwkey's tests on the simulated key:
- t01/t02: open and save;
- t04/t34: AT-H04;
- t35: AT-H03;
- t03, t13 to t21, t49.

The other direction (the reference opens a vault App wrote with a hardware key) is in [E10-S1](E10-S1-hardware-keys.md) section 3 and was not repeated.

**Result: verified, software only.** The proof uses a software answer and the reference's own test vault (OD-01, "Software only"). A run with a real key (T53, V-INT07-1 to V-INT07-5) stays open until the owner has a key (E14).

## SI-09 Shared groups

**Reference.**
- Import and export run only when the app settings allow them. Both are empty, so off, by default.
- Import opens the container and ignores the signature file ("ignore signature file").
- Since 2.7.0 the installed 2.7.11 does the same.

**App.** No share import, export or watch is built: E11 is `todo` and its scope waits for W-15. One part already in app-core passes today. The merge kind `SharedImport` matches ids only inside the shared group (LD-61, MOD-11.4). Private copy, `merge.rs` and `mod11.rs` byte-equal to the tree:

```
cargo test --locked -p app-core --test mod11   test result: ok. 45 passed; 0 failed; 4 ignored
  mod11_04_matching_by_id: "T52 (LD-61): a share matches ids only inside the shared group."
```

**Result:** waits for E11 and W-15. Status left `todo`.

## SI-10 Saving logins from the browser

**Reference.** An update asks first unless `AlwaysAllowUpdate` is on (default false).

**App.** Not built (see SI-01).

**Result:** waits for E7-S4 and D4.

## SI-11 One-time codes for the extension

**Reference.** The one-time code request checks the association, then a valid entry id, and returns that entry's current code. There is no site check.

**App.** Not built (see SI-01).

**Result:** waits for E7-S4 and D4.

## SI-12 Other bridge requests

**Reference.** The vault-hash request:
- decodes the message (key exchange only);
- needs a non-empty hash;
- answers with the hash, with no association check.

Listing all entries is under `AllowGetDatabaseEntriesRequest` (default false). Opening the unlock dialog is under `UnlockDatabase` (default true).

**App.** Not built (see SI-01).

**Result:** waits for E7-S1, E7-S2 and D4.

## SI-13 Remote sync

**Reference.** The remote-sync code exists in the 2.8.0 source (download and upload with timeouts, a temporary folder, `kill()` on timeout). The 2.7.11 tag has no file of it (`git ls-tree -r --name-only 2.7.11` of the GUI folder: 0 remote files).

**App.** Not built: no sync code in any crate. E11 is `todo` and D-INT09-1 is part of W-15.

**Result:** waits for E11 and W-15.

## SI-14 Accessibility permission

**Reference.** On the first global Auto-Type it asks for **both** the Accessibility permission (with the system prompt) and the Screen Recording permission (a screen-content check). It shows "requires the Accessibility and Screen Recorder permission …" and stops when either is missing. Both the current source and the installed 2.7.11 tag do this. The row says the reference uses "no Screen Recording permission". That is App's design (LD-176), not the reference's behaviour: see F1.

**App.** Not built: E8-S3 is `todo`. Settings only reads `AXIsProcessTrusted()` for display.

**Result:** waits for E8-S3. Status left `todo`.

## Findings

- **F1 (Low, matrix wording, SI-14).** The "reference app does" text says "no Screen Recording permission". The reference asks for Accessibility and Screen Recording. The current source and the 2.7.11 tag both do. App asks for less (Accessibility only, LD-176), so App is not weaker, but the parity row describes App rather than the reference. Smallest fix: write "Asks macOS for the Accessibility and Screen Recording permissions when global Auto-Type is first used and stops with a message when either is missing. App: Accessibility only, window titles through the Accessibility API (LD-176)".
- **F2 (Low, test timing under load).** Two tests with wall-clock bounds failed once each while the load average was about 250 to 360 from other agents' builds:
  - `t40_slowest_fuzz_inputs_stay_fast`: 100 ms, failed twice, then passed 5 of 5 alone;
  - `int06_22_unlock_adds_off_the_calling_thread_and_mi06_18_names_the_failures`: 900 ms, failed once, then passed 3 of 3 alone.

  They are not product failures, but they will fail in a busy CI. Smallest fix: run them only in release, or raise the bounds with a note.

## CPU

| Step | User CPU | Wall clock |
|---|---|---|
| Suites, first run (shared target, mostly waiting on its lock) | about 160 s | about 12 min |
| Re-runs | about 95 s | about 14 min |
| Driver build and run (copy) | 172 s | 189 s |
| app-core mod11 (copy) | under 120 s | |

No single run took over 30 minutes.

## Clean-up

- Canary PID 67869 stopped by PID. Throwaway agent PID 7607 stopped by the driver.
- `/tmp/e13s1-si`, `/tmp/e13s1-SI-copy` and `/tmp/e13s1-SI-copy-target` deleted. `/tmp/e13s1-target` is shared and was left in place.

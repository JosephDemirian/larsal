# E9-S2 Keys from attachments or files (INT-06; AT-H01, AT-C01; T24, T74)

Story: E9-S2 Keys from attachments or files, Larsal's own agent and its dialog. Card: [INT-06](../../spec/integrations/INT-06-ssh-agent.md). Decisions: LD-173, LD-201, LD-202, LD-203, LD-207, LD-209, LD-213, LD-170 (4), LD-126.
Date: 2026-10-28.
Role: Verify, round 3, for the whole story after the LD-213 fix round (Rust part, Swift and wiring). I did not build or check it. Rounds 1 and 2 (the same role, earlier today) failed with 2 and with 1; their records follow below.
Result: **signed.** The round 2 fail is fixed, and both of LD-213's other parts hold. The probe that found the fail now finds 0 requests denied unseen, out of 1,440. Every end-to-end check, A to E, passed again. Each LD-213 fix has a test that fails when the fix is undone. Real windows, VoiceOver and real key presses need Mac QA (owner's go).

## Round 3 (2026-10-28, after LD-213)

### Summary

- **Round 2 fail (1), denied unseen:** fixed. Round 2's probe (6 signers at once, question time 300 ms, 15 rounds, nobody answers) ran 16 times: 4 runs one after the other, then 4 and 8 runs side by side to raise the load. Result: **1,440 requests, 0 denied unseen**. One round was asked out of id order by itself, and its question still showed: `shown [1, 2, 4, 5, 3, 6]`. The forced pause (the first request waits 500 ms between its id and its queue ticket) passed 3 of 3. The higher id showed first and ran out its 1 s. The lower id then showed and signed on Allow Once (reply 14). Control, with round 2's highest-id mark put back (mutation L1): the forced pause fails (`X's question was denied unseen`), and the probe fails in 2 of 2 runs (`shown [1, 2, 4, 5, 6]`: id 3 denied unseen).
- **LD-213 (2), the key comment:** proven with `ssh-add -l` against a throwaway OpenSSH agent and against Larsal's agent, on saved vaults through larsal-ffi. With the UserName protected by its own flag, or by the vault's flag, every fallback comment is `id_key`, `id_sysfile` or `id_askfile`, with no `alex` anywhere. With neither flag, the card's `alex@…` stays.
- **LD-213 (3), held keys:** Swift `heldKey` passes. Repeated Return and Space at 1.1 s and at 30 s do not choose Allow Once; a fresh press at 1.1 s does. With the `isARepeat` guard removed, the test fails with 2 issues (mutation S1). The R06-6 first second still holds (mutation S2 fails its test).
- **A to E:** all pass (details below). The full Swift run passed: 215 tests in 33 suites, `SshKeyUseTests` 4 of 4. Parity `dialogs-ssh-key-use`: PASS (light 0.38 %, dark 0.40 %, images byte-equal to the tree's). Mutations: 9 of 9 Rust and 2 of 2 Swift caught.
- **The owner's agent was never contacted.** A canary socket stood as `SSH_AUTH_SOCK` for every cargo, driver and xcodebuild run: 0 connections.

### Setup

- **Private copies.** At 20:24, `rsync -a --exclude target --exclude larsal-shots --exclude /fuzz/artifacts` of the tree went to `/tmp/e9s2x-verify-copy`. That copy was used for the suites, the driver, Swift and parity, with `CARGO_TARGET_DIR=/tmp/e9s2x-verify-target`, `-derivedDataPath /tmp/e9s2x-verify-dd`, and `scripts/build-core.sh` into the copy's own `target/`. A second copy, `/tmp/e9s2x-verify-copy2` (target `/tmp/e9s2x-verify-target2`), took the Rust mutations. Clippy ran in the tree with `/tmp/e9s2x-verify-clippy`.
- **Tree unchanged under me.** I took SHA-256 sums of 68 E9-S2 files (larsal-sshagent `src` and `tests`, larsal-ffi `ssh.rs`, `session.rs` and `tests/ssh.rs`, larsal-crypto `ssh.rs`, `SshKeyUse*.swift`, the root and fuzz manifests and locks, `deny.toml`, `vendor/ssh-key`, the 4 larsal-shots of the frame) at 20:24 and at 20:45. All were equal except the root `Cargo.toml`: another story removed its unused `notify = "=8.2.0"` workspace line at 20:45:08. No SSH crate names it, and `Cargo.lock` is unchanged. Before any change of mine, the copy's E9-S2 files were equal to the tree's.
- **SSH safety.** Every `ssh-agent`, `ssh-add`, `ssh-keygen`, `ssh`, `stat` and `sshd` ran with a cleared environment (`PATH=/usr/bin:/bin`, `HOME` a /tmp folder). `ssh` ran with `-F <throwaway config> -o IdentityFile=none -o UserKnownHostsFile=<throwaway>`. `ssh -G` printed `identityagent /tmp/e9s1-26158-va20/Larsal/agent.sock`, `identityfile none`, `globalknownhostsfile /dev/null` and `userknownhostsfile /tmp/e9s1-26158-va20/ssh_known`, and no `.ssh` path. Throwaway agents (`ssh-agent -D -a`) and `sshd -D` on 127.0.0.1 were stopped by their PIDs when dropped (for example agent 26162 and sshd 26177). My canary (`canary.py`, PID 15899) logged 0 connections. Nothing was added to any keychain.
- **No window, no general pasteboard.** xcodebuild ran with `-skip-testing:LarsalUITests`, or `-only-testing:LarsalTests/SshKeyUseTests`. The frame renders in a borderless window at −20,000 that is never ordered front. `export-reference.mjs` and `mockup-dom.mjs` used headless Chrome.
- **Demo data only:** K1 (the card's demo key) protected with `demo-ssh-pass`, keys made by `ssh-keygen` 10.3 in the test folders, and demo vaults saved with `demo-ssh-vault`.
- **Driver.** My tests were appended to the copy's `crates/larsal-ffi/tests/ssh.rs`, so they use its helpers. They were built with `cargo rustc --locked -p larsal-ffi --test ssh --profile test -- --cap-lints warn`, because the memory scan calls `mach_vm_region_recurse`, `mach_vm_read_overwrite` and `mincore`. Each test ran in its own process (`--exact … --nocapture --test-threads=1`). The forced-pause probe needs a hook in the copy's `server.rs` `ask`, used only when `VFY_PAUSE_FIRST` is set. The hook was in place for the probe runs and the mutation copy only. For the A, C, D and LD-213 (2) runs, `server.rs` was put back byte-equal to the tree's and rebuilt.

### Existing tests (copy, product code equal to the tree, 20:24 to 20:26)

`cargo test --locked -p larsal-sshagent -p larsal-crypto -p larsal-ffi --no-fail-fast`: exit 0.

| Crate | Target | Result |
|---|---|---|
| larsal-crypto | lib, cipher, hash, kdf, mac, random, secret, stream | 47, 21, 6, 35, 8, 7, 10, 19 passed |
| larsal-ffi | lib | 99 passed, including `ssh::tests::ld213_a_lower_id_asked_after_a_cancelled_higher_one_still_shows` and `int06_34_a_cancel_before_its_question_shows_is_deny_at_once` |
| larsal-ffi | `ssh` | 16 passed, including `int06_34_a_new_agent_asks_again_after_a_lock_ended_a_question` |
| larsal-ffi | `session`, clipboard, edit, generator, key_pages, memory, messages, new_vault, option_a, reports, vault_settings | 11, 9, 19, 12, 2, 1, 7, 11, 8, 3, 6 passed |
| larsal-sshagent | unit, `agent.rs`, `own_agent.rs` | 22, 24, 34 passed, including `ld213_a_protected_user_name_never_reaches_a_key_comment` |

### LD-213 (1): round 2's probe and the forced pause

`vfy_r2_six_signers_none_denied_unseen`: one ask-first key, question time 300 ms. A poller reads `ssh_question()` every 0.2 ms and never answers. Each round starts 6 signers on one barrier. A request is "denied unseen" when its reply is `[5]` and no question for it showed.

```
4 runs one after another (load 16):   PROBE requests 90, denied unseen 0, rounds asked out of id order 0   (x4)
4 runs side by side (load 28):         PROBE requests 90, denied unseen 0, rounds asked out of id order 0   (x4)
8 runs, 2 x 4 side by side:            PROBE requests 90, denied unseen 0, rounds asked out of id order 0   (x7)
                                       round 0: shown [1, 2, 4, 5, 3, 6], replies all [5], denied unseen 0, out of id order true
                                       PROBE requests 90, denied unseen 0, rounds asked out of id order 1
```

`vfy_r2_forced_pause_lower_id_still_shows` (`VFY_PAUSE_FIRST=1`, question time 1 s; X signs, Y signs 100 ms later), 3 of 3:

```
[vfy] first shown: id 2
[vfy] Y (higher id) reply [5] after its 1 s
[vfy] second shown: id 1 (1005 ms after the first ended)      (1002 and 1000 ms in runs 2 and 3)
[vfy] X (lower id) reply type 14 after Allow Once
```

The code path (larsal-ffi `ssh.rs`, read in full). `Ask::cancel(id)` adds the id to `cancelled` only when that question is not the one on the window. `Ask::ask(id)` removes it under `now`'s lock and is then Deny at once. Both functions take `now` first, then `cancelled`, so the lock order is the same and nothing deadlocks. Ids are unique in the process (`QUESTION_IDS`). An id that stays in the set (a cancel that lands just after its question ended, or a question thread that failed to start; the ponytail note) can never match a later question.

### LD-213 (2): no protected UserName in a key comment

`vfy_ld213_2_no_protected_user_name_in_a_key_comment`: one saved vault per case, with four entries whose keys have no comment and whose UserName is `alex`. Two keys go to the system agent (attachment `id_key`, file `keys/id_sysfile`) and two ask first (attachment `id_key`, file `keys/id_askfile`, P-256). Larsal's socket lists its own keys, then the system agent's.

```
UserName own flag true, vault flag false:
  ssh-add -l (throwaway system agent):  … id_key (ED25519) | … id_sysfile (ED25519)
  ssh-add -l (Larsal's agent):             … id_key (ED25519) | … id_askfile (ECDSA) | … id_key (ED25519) | … id_sysfile (ED25519)
UserName own flag false, vault flag true:
  ssh-add -l (throwaway system agent):  … id_key (ED25519) | … id_sysfile (ED25519)
  ssh-add -l (Larsal's agent):             … id_key (ED25519) | … id_askfile (ECDSA) | … id_key (ED25519) | … id_sysfile (ED25519)
UserName own flag false, vault flag false:
  ssh-add -l (throwaway system agent):  … alex@id_key (ED25519) | … alex@id_sysfile (ED25519)
  ssh-add -l (Larsal's agent):             … alex@id_key (ED25519) | … alex@id_askfile (ECDSA) | … alex@id_key (ED25519) | … alex@id_sysfile (ED25519)
```

A saved vault marks the field when the vault's flag is on. So for the vault's flag on its own, the proof is larsal-sshagent's in-memory test, `ld213_…`, which mutation L4 fails. The "Larsal key" branch cannot be reached with real data, as the Builder reported: an empty name is a folder, and a folder cannot be opened.

### LD-213 (3): held keys (Swift)

In the full run, and in `-only-testing:LarsalTests/SshKeyUseTests`: ✔ "LD-213 (3): a held Return or Space never chooses Allow Once, also after the first second". `answerSsh(allow:from:)` reads `isARepeat` only on `keyDown` events. Both buttons answer through it; Escape (`onExitCommand`) is Deny. Mutation S1 (guard removed) fails with 2 issues at `SshKeyUseTests.swift:97` (`window.sshAsk == ask`), one for Return and one for Space.

### A. End to end (own driver, copy)

| Test | Result | Time |
|---|---|---|
| `vfy_a1_attachment_and_file_keys_lock_lock_all_close` | ok | 75.5 s (two file scans of /tmp) |
| `vfy_a2_ask_first_real_ssh_binding_queue_lock` | ok | 4.4 s |
| `vfy_c1_no_answer_within_sixty_seconds_is_deny` | ok | 61.3 s |
| `vfy_m_memory_scan_t24_t74` | ok | 4.5 s |
| `vfy_ld213_2_no_protected_user_name_in_a_key_comment` | ok | 2.3 s |

**A1.** The vault has four entries: "Att key" (K1 protected, attachment, remove-on-lock, `SaveAttachmentToTempFile` on); "File key" (Ed25519, protected with `vfy-file-pass`, in `keys/id_file` relative to the vault folder, remove-on-lock); "Plain key" (P-256 without a passphrase, not marked); and "Wrong pass".

```
[vfy] unlock returned in 215.34325ms
[vfy] ssh-add -l (system agent) after unlock:
256 SHA256:R3aMsbAq88Fv8wlNcuy3oN+ZIl7yqPd3lRkAP/AP+uc demo@app (ED25519)
256 SHA256:LLSLK+G0DuL/eNoie/NtqdTw5s95of9uWv3NGuLPhDE file@vfy (ED25519)
256 SHA256:Wjj7+nEZILf2JxXvJdDuAW3VbObKd24jK3rRgjqgRfI ecdsa@app (ECDSA)
[vfy] ssh-keygen -lf of the three keys: the same sizes, fingerprints and types (an encrypted file's comment reads "no comment")
[vfy] failures (MI06-18 details): [SshFailure { title: "Wrong pass", id: "MI06-15", message: "The entry's password does not unlock this key." }]
[vfy] banner: Some("Some SSH keys were not loaded: Wrong pass.")
[vfy] files changed since the unlock (scanned) / holding a private key: 582 / [7 files, all in /tmp/e9s2x-verify-clippy (my clippy build's incremental data)]
[vfy] control file written after the unlock: scanned 4461 / hits [control.txt in the vault folder; my mutation copy's build data and source; a mutation test's own ssh-keygen demo keys]
[vfy] lock returned in 1.357292ms; ssh-add -l now: 256 SHA256:Wjj7… ecdsa@app (ECDSA)
[vfy] lock_all returned in 117.459µs; ssh-add -l now: 256 SHA256:Wjj7… ecdsa@app (ECDSA)
[vfy] close returned in 103.833µs; ssh-add -l now: 256 SHA256:Wjj7… ecdsa@app (ECDSA)
```

- **No plaintext key on disk.** The scan walks `TMPDIR` and `/private/tmp` 6 levels deep. It reads every file changed since the unlock and looks for the text `PRIVATE KEY`, K1's 32-byte seed and the seed as hex (the needles are held XOR-masked). No hit is in the vault folder or in `TMPDIR`. The only hits are my own cargo outputs (compiled test sources hold the demo key text) and demo key files written by the tests themselves. The control file is found, so the scan works. The only file call in the product SSH code is still `create_dir_all` for the socket folder.
- **No secret in the texts:** the failures and the banner hold none of the passwords, the vault password or `PRIVATE KEY` (asserted). Before lock-all and before close, the vault was unlocked again and all three keys were listed again.

**A2.**

```
[vfy] ssh-add -l (system agent): The agent has no identities.
[vfy] Larsal's socket ssh-add -l: 256 SHA256:R3aMsbAq88Fv8wlNcuy3oN+ZIl7yqPd3lRkAP/AP+uc demo@app (ED25519)
[vfy] ssh-keygen -lf k1e: 256 SHA256:R3aMsbAq88Fv8wlNcuy3oN+ZIl7yqPd3lRkAP/AP+uc no comment (ED25519)
[vfy] stat:
drwx------ 700 josephilhan /tmp/e9s1-26158-va20/Larsal
srw------- 600 josephilhan /tmp/e9s1-26158-va20/Larsal/agent.sock
[vfy] ssh_agent_info: Some(SshAgentInfo { socket: "/tmp/e9s1-26158-va20/Larsal/agent.sock", setup_line: "IdentityAgent \"/tmp/e9s1-26158-va20/Larsal/agent.sock\"", error: None })
[vfy] sshd: pid 26177 on 127.0.0.1:52511
[vfy] question (ssh, allow=true): SshQuestion { id: 1, heading: "Allow a program to use “Server root · web-01”?", text: "A program wants to sign in to web01.example with this key." }
[vfy] ssh with allow=true: ok=true out="signed-in"
[vfy] ssh with allow=false: ok=false out="josephilhan@127.0.0.1: Permission denied (publickey)."
[vfy] session-bind reply: [6]
[vfy] LD-203 (2) plain data: A program wants to sign with this key.
[vfy] LD-203 (2) publickey sign-in, bound session: A program wants to sign in to db.example with this key.
[vfy] LD-203 (2) publickey sign-in, other session: A program wants to sign with this key.
[vfy] LD-203 (2) hostbound sign-in, bound host key: A program wants to sign in to db.example with this key.
[vfy] LD-203 (2) hostbound sign-in, other host key: A program wants to sign with this key.
[vfy] LD-203 (2) publickey sign-in, bytes after it: A program wants to sign with this key.
[vfy] two signers after 1.5 s: shown Some(9), replies done: false false
[vfy] second question after the first was answered: id 9 then id 10
[vfy] lock during the question: lock returned in 25.125µs; reply [5] 65.083µs after the lock; question now None
[vfy] 1 s later the window reads None; Larsal's socket ssh-add -l: The agent has no identities.
[vfy] after turn-off: socket exists false
[vfy] new agent's question: SshQuestion { id: 12, … text: "A program wants to sign with this key." }
[vfy] new agent, Allow Once: reply type 14
[vfy] after lock_all and stop_ssh_agent: socket exists false
```

`ssh` names `web01.example` (Larsal's throwaway `known_hosts`), not 127.0.0.1, so Larsal checked the binding `ssh` sent. The six raw cases ran on one connection bound to a second host key (`db.example`), signed by a throwaway agent that holds it. Another user ID on the socket still needs the CI root fixture. Its unit test, `server::tests::t52_peer_of_another_user_is_refused`, passed in the suites.

### B. Frame `dialogs-ssh-key-use` (copy)

1. `node design/option-a/tools/export-reference.mjs` gave `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`. The frame's reference PNGs and `manifest.json` are byte-equal to the tree's.
2. `scripts/build-core.sh` gave `build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift`, exit 0.
3. `xcodebuild test … -derivedDataPath /tmp/e9s2x-verify-dd -skip-testing:LarsalUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` gave `✔ Test run with 215 tests in 33 suites passed after 115.527 seconds` and `✔ Suite SshKeyUseTests passed`, 4 of 4: the frame (light and dark), R06-6, LD-213 (3), and parity Deny and Allow Once. The 4 rendered files `larsal-shots/{light,dark}/dialogs-ssh-key-use.{png,ax.json}` are byte-equal to the tree's.
4. `node design/parity/tools/mockup-dom.mjs dialogs` gave `21 frames, 147 text runs` (light and dark). `swift design/parity/tools/ocr.swift …` gave `dialogs-ssh-key-use.png 4` (light and dark).
5. `node design/parity/tools/compare.mjs dialogs` gave `dialogs: 17/17 PASS` and `dialogs-ssh-key-use PASS L 0.38% (0.38) D 0.4% (0.4)`.

The tree's `design/parity/dialogs/` was not changed this round: the images and numbers are the same as in round 2's record below.

### C. Timing

- **R06-6:** the Swift test passes, and mutation S2 (the first second set to 0) fails it with 2 issues (`SshKeyUseTests.swift:55`, `:76`).
- **60 s, the real code path** (`larsal_sshagent::QUESTION_TIME`): `no answer: reply [5] after 60.002254292s; question now None`. A late Allow Once is ignored, and the question stays closed. With the time set to 63 s (mutation M11), the test fails at 62.9997 s.
- **One question at a time:** A2 above; the probe's rounds show their questions one at a time.

### D. Rule 4

- **FFI surface** (larsal-ffi `ssh.rs`, read in full). `SshQuestion { id, heading, text }`, `SshFailure { title, id, message }` and `SshAgentInfo { socket, setup_line, error }` hold words only. LD-213 adds no export. No `println!`, `eprintln!`, `dbg!`, `log::` or `tracing::` in larsal-sshagent, larsal-crypto `ssh.rs`, larsal-ffi `ssh.rs` or `SshKeyUse.swift` (grep).
- **Memory scan, T24 and T74** (the AT-C01 method, inside the process). The scan walks the process's own map with `mach_vm_region_recurse` and follows submaps. It takes each readable region that is writable or tagged, and reads the pages that `mincore` reports resident or paged out, using `mach_vm_read_overwrite`. The needles are XOR-masked, and the read buffer is skipped and wiped.

  ```
  [vfy] memory scan start: K1 seed 0 hit(s), passphrase 0 hit(s) in 35 MB read
  [vfy] memory scan T24 added to the system agent, 1 s later: K1 seed 0 hit(s), passphrase 1 hit(s) in 110 MB read
  [vfy] memory scan T24 after close: K1 seed 0 hit(s), passphrase 0 hit(s) in 120 MB read
  [vfy] memory scan T74 control, Larsal's agent holds the key: K1 seed 1 hit(s), passphrase 1 hit(s) in 114 MB read; seed at [(104e647d7, 7)]
  [vfy] memory scan T74 after lock, 1 s later: K1 seed 0 hit(s), passphrase 0 hit(s) in 122 MB read
  ```

  The one passphrase hit while the vault is open is the vault's own Password field, and it goes with the close. While Larsal's agent holds the key, the control finds the seed once (MALLOC_TINY, tag 7). A view-level dump of the real `Larsal.app` (lldb) stays with Mac QA.

### E. Mutations (each restored and checked equal to the tree)

Tool: `mut.py` (exact replacements; it runs the tests, restores the file and asserts it is equal again). Rust in the second copy (target `-target2`, `RUSTFLAGS=--cap-lints warn` for the driver). Swift in the first copy (`-only-testing:LarsalTests/SshKeyUseTests`). Afterwards, every product file of both copies was byte-equal to the tree's, apart from the copy-2 hook in `server.rs`.

| # | Mutation | File | Caught by | Result |
|---|---|---|---|---|
| L1 | round 2's highest-id mark put back (`cancel` always records; `ask` denies any id at or below it) | larsal-ffi `ssh.rs` | lib `ld213_…`; forced pause; probe | `question 7 was denied unseen` (left None, right Some(7)); `X's question was denied unseen`; probe 2 of 2 runs `denied unseen 1` (`shown [1, 2, 4, 5, 6]`) |
| L2 | the cancelled-id check removed | larsal-ffi `ssh.rs` | lib `int06_34_a_cancel_before…` | FAILED: left `Err(Timeout)`, right `Ok(false)` |
| L3 | the UserName's own flag ignored | `entry.rs` | own_agent `ld213_…`; `vfy_ld213_2` | FAILED: `["alex@id_plain"]` and `["alex@id_key", "alex@id_sysfile"]` |
| L4 | the vault's UserName flag ignored | `entry.rs` | own_agent `ld213_…` | FAILED: `["alex@id_plain"]` (the saved-vault driver passes: the save marks the field) |
| M1 | the lock skips `Keyring::lock` | larsal-ffi `ssh.rs` | `int06_24` ×2 | 2 FAILED (K1 left in the system agent) |
| M2 | sign without asking | `server.rs` | `int06_34_the_window_answers…` | FAILED |
| M3 | a host named for any request | `server.rs` | `t57_ld203_2_…`; A2 | FAILED: `Some("web01.example")` for other data; A2's plain-data case |
| M4 | socket 0666 | `server.rs` | A2; `t52_…` | FAILED: `(448, 438)` instead of `(448, 384)`; `438` instead of `384` |
| M11 | question time 63 s | `server.rs` | C1 | FAILED: Deny after 62.9997 s |
| S1 | the `isARepeat` guard removed | `SshKeyUse.swift` | `heldKey` | 2 issues at `SshKeyUseTests.swift:97`, `** TEST FAILED **` |
| S2 | R06-6's first second set to 0 | `SshKeyUse.swift` | `firstSecond` | 2 issues (`:55`, `:76`), `** TEST FAILED **` |

Unmutated re-run after S1 and S2: `✔ Test run with 4 tests in 1 suite passed`, `** TEST SUCCEEDED **`.

### Other checks (tree)

- `cargo clippy --locked -p larsal-sshagent -p larsal-crypto -p larsal-ffi --all-targets -- -D warnings` (own target dir): `Finished`, exit 0.
- `cargo fmt --all -- --check` and `cargo fmt --manifest-path fuzz/Cargo.toml -- --check`: exit 0.
- `cargo deny --offline check`: `advisories ok, bans ok, licenses ok, sources ok` (one duplicate warning for `syn`, which was there before).
- `scripts/check-names.sh`: `names: PASS (3097 files scanned, 15 vault files name-only)`, run again after my edits (below).
- `xcrun swift format lint --strict` and swiftlint 0.65.1 `lint --strict --quiet` on `SshKeyUse.swift` and `SshKeyUseTests.swift`: exit 0.
- Not run this round: fuzzing (LD-213 changes no reader; round 2 ran `ssh_settings_read` and `ssh_key_read` for 30 s each) and larsal-core (unchanged by LD-213).

### Open, not blocking

- **The requesting program's name.** It needs a peer process ID call (`LOCAL_PEERPID`) in larsal-platform `macos/`, which is unsafe and needs two Checkers. Until then, the question says "A program".
- **The parts that wait for W-05 and D-INT06-7:** the settings row with Copy Setup Line, Not loaded, the INT-06.43 notes, MI06-27, R06-7 and MI06-18's Details button.
- **Another user ID on Larsal's socket:** needs the CI root fixture.
- **The long fuzz runs:** E13-S3.
- **Needs Mac QA (owner's go):** real windows, the focus ring and Full Keyboard Access order, VoiceOver reading the sheet, real Return and Space presses and their repeats in the key window, and Larsal coming to the front. Checker 1 also asked whether AppKit's Space fires on key release; that is part of this QA.

### Notes for the lead

- INT-06.8 in the card still says only `<entry user name>@<attachment name or file name>`. LD-213 (2) holds the rule (protected parts left out, "Larsal key"). The card could gain it as INT-06.34 gained LD-203 (2), when the spec owner next edits INT-06.
- With an unprotected but empty UserName, the fallback is `@<name>`, as the card's reference rule says. This is not part of LD-213.
- The natural race is rare at today's load: 1 round in 240, against round 2's 4 requests in 450 at load 20 to 65. The forced pause makes the case certain, and it passes.

### Cleanup

- Canary PID 15899 (mine) was stopped by its PID. Its log held 0 connections.
- Every throwaway agent and `sshd` of my runs was stopped by its PID when dropped. Every `/tmp/e9s1-<pid>-*` folder of my runs was removed when dropped; none were left at the end. PIDs 6258 (`ssh-agent -d -a /tmp/spec-int05-07/…`, since Oct 25) and 85551 (`ssh-agent -l`, since Oct 27) are not mine and were left alone.
- I deleted `/tmp/e9s2x-verify-copy`, `-copy2`, `-target`, `-target2`, `-clippy`, `-dd`, `-scripts` and `-proof`. The outputs quoted here were copied from `-proof` first.
- In the tree I changed only this file and the E9-S2 status line in `plan/epics.md`.

## Round 2 (history, same role, 2026-10-28): failed (1), Low

The sections from "Setup" to "Cleanup" below are round 2's record (driver `verify3_e9s2.rs`, copies `/tmp/e9s2w-verify3-*`). Round 2's result:

Result: **failed (1), Low.** Both round 1 fails are fixed and proven. Every behaviour check passed again. One new gap came with the fix of round 1's finding 2:

1. **Low: a sign request can be denied without its question.** The fix's "highest cancelled id" in larsal-ffi `ssh.rs` assumes questions are asked in id order. Larsal's agent hands out the id before the request takes its place in the question queue, so two requests that arrive together can be asked in the other order. When the question shown first then ends without an answer (60 s, a lock, a remove), the other request, which has the lower id, gets Deny at once and never shows. Proven with no code change: 6 signers started together, question time 300 ms, 4 runs of 15 rounds: 1, 0, 1 and 2 requests denied unseen; a print in that branch shows `ask(3) is Deny at once, cancelled mark 6`. Fails safe (Deny, nothing signs). Smallest fix under Fails.

- **Round 1 fail (1), the deny gate:** fixed. `cargo deny --offline check` gives `advisories ok, bans ok, licenses ok, sources ok`. With the yanked 0.7.7 put back (private copy), it gives `error[yanked]` and `advisories FAILED`. The root and fuzz locks hold the same versions of every shared package.
- **Round 1 fail (2), the dead question:** fixed. Round 1's probe (the question thread starts 200 ms late, a lock 50 ms after the sign request) leaves 0 of 5 questions on the window; with the fix's check removed, 5 of 5. A turn-off and turn-on then asks again (new agent, Allow Once signs).
- **A, end to end** (own driver over larsal-ffi's exports, throwaway OpenSSH 10.3p1 agents and a loopback `sshd`, 4 of 4 pass): attachment and file keys added on unlock, fingerprints from `ssh-add -l` equal to `ssh-keygen -lf`; no key file written (scan with control); marked keys gone on lock, lock-all and close (0.24 to 1.6 ms); an ask-first key only in Larsal's agent; `ssh` signs in on Allow Once, not on Deny; the host is named only for a bound sign-in (6 raw cases); one question at a time; a lock ends the question in 1.4 ms and frees the key; socket 0600 in a 0700 folder.
- **B, frame `dialogs-ssh-key-use`:** PASS, light 0.38 %, dark 0.40 %, 5 of 5 strings, 0 token mismatches, boxes within 0.5 pt. Snapshots, app and diff images byte-equal to the tree's.
- **C, timing:** R06-6 passes and its test fails with the first second removed; the real 60 s question time gave Deny at 60.018 s; one question at a time.
- **D, rule 4:** the FFI surface carries words only; no logging in the SSH code; memory scan: K1's seed 0 hits after the add (T24) and 0 after the lock (T74), 1 hit in the control while Larsal's agent holds the key.
- **E, mutations:** 9 of 9 Rust and 2 of 2 Swift mutations caught, all in a private copy.
- **The owner's agent was never contacted:** a canary socket stood as `SSH_AUTH_SOCK` for every run; 0 connections.

## Setup

- **Private copies, made fresh.** At 19:12 `rsync -a --exclude /target --exclude /fuzz/target --exclude /fuzz/artifacts` of the tree to `/tmp/e9s2w-verify3-copy` (driver, Swift, parity), then `larsal-shots/` too; a second copy `/tmp/e9s2w-verify3-copy2` for mutations and probes. New folder names and new build folders (`/tmp/e9s2w-verify3-target`, `-target2`, `-clippy`, `-dd`), so round 1's stale-build trap cannot recur.
- **Tree unchanged under me.** SHA-256 of 92 E9-S2 files (larsal-sshagent, `vendor/ssh-key`, larsal-ffi `ssh.rs` and `tests/ssh.rs`, larsal-crypto `ssh.rs`, `SshKeyUse*.swift`, the Cargo and fuzz manifests and locks, `deny.toml`, the SSH fuzz targets and corpora, the 4 larsal-shots) at 19:12 and at the end: equal. `session.rs`, `views.rs`, `lib.rs` and `MainWindow.swift` in the copy are equal to the tree's at the end. `MainWindowModel.swift` gained another story's save-before-lock code at 19:23; its SSH lines (`sshAsk`, `refreshSsh()`, `stopSshAgent()`) are unchanged.
- **Tools:** cargo-deny 0.20.2, OpenSSH_10.3p1 (`/usr/bin`, `/usr/sbin/sshd`), Xcode with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`, swiftlint 0.65.1. Load average 20 to 65 during the runs.
- **SSH safety.** Every `ssh-agent`, `ssh-add`, `ssh-keygen`, `ssh`, `stat` and `sshd` ran with a cleared environment (`PATH=/usr/bin:/bin`, `HOME` a /tmp folder). `ssh` ran with `-F <throwaway config> -o IdentityFile=none`; `ssh -G` printed `identityagent /tmp/e9s1-61437-va20/Larsal/agent.sock`, `identityfile none`, `globalknownhostsfile /dev/null`, `userknownhostsfile /tmp/e9s1-61437-va20/ssh_known`, and no `.ssh` path. Throwaway agents (`ssh-agent -D -a`) and `sshd -D` on 127.0.0.1 were stopped by their PIDs on drop (for example agent 53210, sshd 61701). My canary (`canary.py`, PID 38564) listened at `SSH_AUTH_SOCK` for every cargo, driver, xcodebuild and fuzz run: `canary-hits.log` 0 lines. Nothing was added to any keychain.
- **No window, no general pasteboard.** xcodebuild ran with `-skip-testing:LarsalUITests` (LarsalTests has no host app); the frame renders in a borderless window at −20,000 that is never ordered front. `export-reference.mjs` and `mockup-dom.mjs` ran headless Chrome. The reference app's window was not used; its command line tool (throwaway `HOME`, `--help` only) lists no SSH or agent command (`grep -ciE "ssh|agent"`: 0), so there was nothing to spot-check there.
- **Demo data only:** K1 (the card's demo key) protected with `demo-ssh-pass`, keys made by `ssh-keygen` 10.3 in the test folders, demo vaults saved with `vfy3-vault-pass`.

## Round 1 fails, re-checked

### Fail 1: the deny gate

```
$ cargo deny --offline check            (copy)
warning[duplicate]: found 2 duplicate entries for crate 'syn'   (there before E9-S2)
advisories ok, bans ok, licenses ok, sources ok

$ cargo update -p crypto-bigint --precise 0.7.7 --offline   (second copy)
 Downgrading crypto-bigint v0.7.10 -> v0.7.7
$ cargo deny --offline check
error[yanked]: detected yanked crate (try `cargo update -p crypto-bigint`)
advisories FAILED, bans ok, licenses ok, sources ok
$ cp <tree>/Cargo.lock Cargo.lock && cmp …   → restored
```

- **Locks.** Root and fuzz: crypto-bigint 0.7.10, ctutils 0.4.6, der 0.8.2, elliptic-curve 0.14.2, p256 0.14.0, ecdsa 0.17.0, ed25519-dalek 3.0.0, curve25519-dalek 5.0.0, ssh-key 0.7.0-rc.11 from the path. Of 121 shared packages, the only ones with a version set that differs are `bit-set`, `bit-vec` and `getrandom`, where the root holds extra versions (other workspace crates) and every fuzz version is also in the root.
- **The diff (spot check of the Builder's LD-201 note).** Registry copies: no `build.rs` in any of crypto-bigint 0.7.7, 0.7.10, ctutils 0.4.5, 0.4.6; lines containing `unsafe`: 32 and 32, 1 and 1; `diff -r … | grep "^[<>].*unsafe"`: none. The 0.7.10 CHANGELOG: 0.7.6 to 0.7.8 "yanked due to breaking changes in [#1373]"; 0.7.10 (2026-10-26) "Optimize Montgomery multiplication carry propagation (#1376)", "Replace `ctutils` primitives with faster internal primitives (#1377)". LD-201 carries the bump note; `plan/architecture.md`'s p256 row names 0.7.10.

### Fail 2: the dead question

Probe `probe_dead_question` (second copy): sign, lock 50 ms later, read the window 1 s later, 5 rounds. P3 and P4 add `std::thread::sleep(200 ms)` at the top of `Ask::ask` (the question thread starts late); P4 also removes the fix's `id <= cancelled` check.

```
P0 (no change):                PROBE rounds with a question left after the lock: 0 of 5
P3 (late thread, fix kept):    PROBE rounds with a question left after the lock: 0 of 5
P4 (late thread, fix removed): round 0: reply [5], window 1 s after the lock: Some(SshQuestion { id: 1, … }) … round 4: … id: 5 …
                               PROBE rounds with a question left after the lock: 5 of 5
```

The new tests pass in the suites (below): `ssh::tests::int06_34_a_cancel_before_its_question_shows_is_deny_at_once` and `int06_34_a_new_agent_asks_again_after_a_lock_ended_a_question`. Both fail with their part undone (mutations M5 and M6).

## A. End to end (driver `verify3_e9s2.rs`, private copy only)

Build: `cargo rustc --locked -p larsal-ffi --test verify3_e9s2 --profile test -- --cap-lints warn` (the memory scan calls `mach_vm_region_recurse`, `mach_vm_read_overwrite` and `mincore`; the workspace forbids `unsafe`, so only this test target is capped; the product crates are unchanged). Then the binary with `--nocapture --test-threads=1 <name>`, each test in its own process.

| Test | Result | Time |
|---|---|---|
| `va1_attachment_and_file_keys_lock_lock_all_close` | ok | 59.62 s (two file scans of /tmp) |
| `va2_ask_first_key_real_ssh_binding_queue_lock` | ok | 5.64 s |
| `vc1_no_answer_within_sixty_seconds_is_deny` | ok | 60.85 s |
| `vm_memory_scan_t24_t74` | ok | 4.81 s |

### va1: attachment and file keys, lock, lock-all, close

The vault holds four entries: "Att key" (K1 protected, attachment, remove-on-lock, `SaveAttachmentToTempFile` on); "File key" (an Ed25519 key protected with `vfy3-file-pass` in the file `keys/id_file`, relative to the vault folder, remove-on-lock); "Plain key" (a P-256 key without a passphrase, attachment, not marked); "Wrong pass" (K1 protected, the entry's password wrong).

```
[verify] system agent: pid 56627 at /tmp/e9s1-56583-a1/s
[verify] unlock returned in 229.765708ms
[verify] ssh-add -l (system agent) after unlock:
256 SHA256:R3aMsbAq88Fv8wlNcuy3oN+ZIl7yqPd3lRkAP/AP+uc demo@app (ED25519)
256 SHA256:3QxdReRSQnGuLPUdzM1u2Cy+mjP9Q33PS2N1UOVasRw file@vfy (ED25519)
256 SHA256:2SDMPYb16mmjTqMmRSxMl+r0U01fYtoRupooQYC1q7Y plain@vfy (ECDSA)
[verify] ssh-keygen -lf of the three public keys:   (the same three lines)
[verify] failures (MI06-18 details): [SshFailure { title: "Wrong pass", id: "MI06-15", message: "The entry's password does not unlock this key." }]
[verify] banner: Some("Some SSH keys were not loaded: Wrong pass.")
[verify] scan roots: ["/var/folders/95/…/T/", "/private/tmp"] (vault folder /tmp/e9s1-56583-va10)
[verify] files changed since the unlock (scanned) / holding a private key: 39 / []
[verify] control file written after the unlock: scanned 1603 / hits ["/private/tmp/e9s1-56583-va10/control.txt"]
[verify] lock returned in 358.708µs; ssh-add -l now: 256 SHA256:2SDM… plain@vfy (ECDSA)
[verify] lock_all returned in 1.616291ms; ssh-add -l now: 256 SHA256:2SDM… plain@vfy (ECDSA)
[verify] close returned in 236.5µs; ssh-add -l now: 256 SHA256:2SDM… plain@vfy (ECDSA)
```

- **No plaintext key on disk.** The scan walks `TMPDIR` and `/private/tmp` (the vault folder is inside it) 6 levels deep, skips other agents' build folders (`*-target`, `*-dd`, `*-copy`), reads every file changed since the unlock and looks for the text `PRIVATE KEY`, K1's 32-byte seed and the seed as hex (the needles are held XOR-masked). 0 files hit; the control file is found, so the scan works. (The first try counted the driver's own demo key files, written 1 s before the start mark; the start mark now follows a 1.1 s pause after they are written.) As in round 1, the only file call in larsal-sshagent's and larsal-ffi `ssh.rs`'s product code is `create_dir_all` for the socket folder.
- **No secret in the texts.** The failures and banner hold none of the four passwords, the vault password or `PRIVATE KEY` (asserted).
- **Before each of lock-all and close** the vault was unlocked again and all three keys were listed again.

### va2: "ask first" key, real ssh, host binding, one question at a time, lock, turn-off and turn-on

```
[verify] system agent ssh-add -l (ask-first key): The agent has no identities.
[verify] Larsal's socket ssh-add -l: 256 SHA256:R3aMsbAq88Fv8wlNcuy3oN+ZIl7yqPd3lRkAP/AP+uc demo@app (ED25519)
[verify] ssh-keygen -lf k1e.pub: 256 SHA256:R3aMsbAq88Fv8wlNcuy3oN+ZIl7yqPd3lRkAP/AP+uc demo@app (ED25519)
[verify] stat:
drwx------ 700 josephilhan /tmp/e9s1-61437-va20/Larsal
srw------- 600 josephilhan /tmp/e9s1-61437-va20/Larsal/agent.sock
[verify] ssh_agent_info: Some(SshAgentInfo { socket: "/tmp/e9s1-61437-va20/Larsal/agent.sock", setup_line: "IdentityAgent \"/tmp/e9s1-61437-va20/Larsal/agent.sock\"", error: None })
[verify] sshd: pid 61701 on 127.0.0.1:65047
[verify] ssh -G: ["identityagent /tmp/e9s1-61437-va20/Larsal/agent.sock", "identityfile none", "globalknownhostsfile /dev/null", "userknownhostsfile /tmp/e9s1-61437-va20/ssh_known"]; any .ssh path: false
[verify] question (ssh, allow=true): SshQuestion { id: 1, heading: "Allow a program to use “Server root · web-01”?", text: "A program wants to sign in to web01.example with this key." }
[verify] ssh with allow=true: ok=true out="signed-in"
[verify] question (ssh, allow=false): SshQuestion { id: 2, … text: "A program wants to sign in to web01.example with this key." }
[verify] ssh with allow=false: ok=false out="sign_and_send_pubkey: signing failed for ED25519 \"demo@app\" from agent: agent refused operation … Permission denied (publickey)."
[verify] session-bind reply: [6]
[verify] LD-203 (2) plain data: A program wants to sign with this key.
[verify] LD-203 (2) publickey sign-in, bound session: A program wants to sign in to db.example with this key.
[verify] LD-203 (2) publickey sign-in, other session: A program wants to sign with this key.
[verify] LD-203 (2) hostbound sign-in, bound host key: A program wants to sign in to db.example with this key.
[verify] LD-203 (2) hostbound sign-in, other host key: A program wants to sign with this key.
[verify] LD-203 (2) publickey sign-in, bytes after it: A program wants to sign with this key.
[verify] two signers after 1.5 s: first id 9, shown now Some(9), replies done: false false
[verify] second question after the first was answered: id 9 then id 10
[verify] lock during the question: lock returned in 34.667µs; ssh ended 1.391708ms after the lock, ok=false "…agent refused operation…"; question now None
[verify] 1 s later the window reads None
[verify] Larsal's socket ssh-add -l after the lock: The agent has no identities.
[verify] after turn-off: socket exists false
[verify] new agent's question: SshQuestion { id: 12, heading: "Allow a program to use “Server root · web-01”?", text: "A program wants to sign with this key." }
[verify] new agent, Allow Once: reply type 14
[verify] after lock_all and stop_ssh_agent: socket exists false
```

- **Host names.** `ssh` names `web01.example` (Larsal's throwaway `known_hosts`), not 127.0.0.1, so the binding `ssh` sent was checked. The six raw LD-203 (2) cases ran on one connection bound to a second host key (`db.example`, an `ssh-keygen` key whose signature over the session ID the driver made with larsal-crypto); the host is named only for the two sign-in requests that carry the bound session (and, for the host-bound form, the bound host key) with nothing after them.
- **After the lock** Larsal's agent lists 0 keys (`own_count` 0, `ssh-add -l` "no identities").
- **Another user ID: not testable here.** It needs a second user (the CI root fixture). The rule is `server.rs` `same_user` (`peer.is_ok_and(|uid| uid == own)`), called for every connection; its unit test `server::tests::t52_peer_of_another_user_is_refused` (502 against 501, root and an error refused) passed in the suites.

### Existing tests on fresh builds (`suites.log`, 19:12 to 19:14, copy)

`cargo test --locked -p larsal-sshagent -p larsal-crypto -p larsal-ffi --no-fail-fast`: exit 0.

| Crate | Target | Result |
|---|---|---|
| larsal-crypto | lib (unit, includes `ssh::tests` 7) | 47 passed, 1 ignored |
| larsal-crypto | cipher, hash, kdf, mac, random, secret, stream | 21, 6, 35, 8, 7, 10, 19 passed |
| larsal-ffi | lib (unit) | 96 passed (includes `ssh::tests::int06_34_a_cancel_before_its_question_shows_is_deny_at_once`) |
| larsal-ffi | `ssh` | 16 passed |
| larsal-ffi | `session` | 11 passed |
| larsal-ffi | clipboard, edit, generator, key_pages, memory, messages, new_vault, option_a, reports, vault_settings | 9, 19, 12, 2, 1, 7, 11, 8, 3, 6 passed |
| larsal-sshagent | unit | 22 passed |
| larsal-sshagent | `agent.rs` | 24 passed |
| larsal-sshagent | `own_agent.rs` | 33 passed |

larsal-ffi `ssh` (16): `int06_21`, `int06_22`, `int06_24` ×3 (lock, close and lock-all, lock during decryption), `int06_25`, `int06_26` ×2, `int06_31`, `int06_34` ×4 (Allow Once and Deny, SR-16 lock, a new agent asks again, no answer), `ld203_5_otp_field_as_key_passphrase_gives_mi06_14`, `ld207` ×2.

`cargo test --locked -p larsal-core --no-fail-fast` (copy, 19:42 to 19:43, `refs::copy_context` lives here): 29 test targets, 712 passed, 0 failed.

## B. Frame `dialogs-ssh-key-use` (BUILD-AND-VERIFY "Prompt for the Verify fleet")

All in the copy, in this order:

1. `node design/option-a/tools/export-reference.mjs` → `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`. The frame's light and dark reference PNGs and `manifest.json` are byte-equal to the tree's (`cmp`). Manifest record: texts "Allow ssh to use “Server root · web-01”?", "ssh wants to sign in to 203.0.113.10 with this key.", "Deny", "Allow Once"; accessible name = the title.
2. `scripts/build-core.sh` → `build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift`, exit 0.
3. `xcodebuild test -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e9s2w-verify3-dd -skip-testing:LarsalUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` (offscreen): `Test run with 204 tests in 33 suites failed … with 2 issues`. Both issues are another story's (Notes). `SshKeyUseTests`:
   - ✔ "Option A dialogs-ssh-key-use, offscreen, light and dark" (18.3 s);
   - ✔ "R06-6: Return and Space do nothing for the first second; a click, Escape and Deny act at once";
   - ✔ "Parity dialogs-ssh-key-use: the question shows over the window; Deny and Allow Once answer and close it";
   - ✔ Suite SshKeyUseTests passed.

   `larsal-shots/{light,dark}/dialogs-ssh-key-use.{png,ax.json}` rendered 19:36:53 and 19:36:59: all 4 byte-equal to the tree's.
4. `node design/parity/tools/mockup-dom.mjs dialogs` → `light: 21 frames, 147 text runs`, `dark: 21 frames, 147 text runs`. `swift design/parity/tools/ocr.swift larsal-shots/light/dialogs-*.png larsal-shots/dark/dialogs-*.png` → `dialogs-ssh-key-use.png 4` (light and dark). The xcodebuild log became `target/parity/behaviour.log`.
5. `node design/parity/tools/compare.mjs dialogs` → `dialogs: 17/17 PASS`, `dialogs-ssh-key-use  PASS  L 0.38% (0.38) D 0.4% (0.4)`.

| Check | Light | Dark |
|---|---|---|
| 1 Present | yes, 460 × 152 pt, size equal | yes |
| 2 Text | 5 found exact (title, text, Deny, Allow Once, accessible name); 0 missing, 0 extra | same |
| 3 Tokens | #ffffff 87.8 → 88 %, #1d1f20 (primary) 4.7 → 4.6 %, #4b5057 (graphite) 2 → 2 %; IBM Plex Sans 16/600 title, 14/400 text; Phosphor `terminal-window` (fill) | #1a1a1d 84 → 84.5 %, #ededef 5.7 → 6.3 %, #131315 2.7 → 2.6 %, graphite 2 → 2 %; same fonts and glyph |
| 4 Geometry | dialog 0,0,460,152 Δ 0; Deny Δ −0.5,0,+0.5,0; Allow Once Δ 0; title run Δ 0; text run Δ width +0.5 | same |
| 5 Pixels | 0.38 % (residual 0.38 %) | 0.40 % |
| 6 Behaviour | ParityTests: Deny and Allow Once answer and close; Escape is Deny (`onExitCommand`, Deny is `cancel: true`); a question Rust no longer asks closes on the next read | same |
| 7 Accessibility | every control named (AXHeading, AXStaticText, 2 AXButton, group named by the title); contrast text on surface 18.43 | text on surface as in the report's contrast table |

Verdict: **PASS.** This frame's record in the copy's `findings.json` equals the tree's apart from the Verify note; its `app/` and `diff/` images (light and dark) are byte-equal to the tree's. I updated only this frame's Verify note in `design/parity/dialogs/report.md`, `report.html` and `findings.json`.

The question text in the frame names the program (`ssh`) because the mockup draws it; until the peer process ID exists Larsal says "A program" (open item).

Needs Mac QA (owner's go): the focus ring and Full Keyboard Access order of the two buttons, VoiceOver reading the sheet, real Return and Space key presses in the key window, and Larsal coming to the front (`Front.bring`).

## C. Timing

- **R06-6.** The Swift test passes with a fake clock: Return at 0.5 s does nothing (`window.sshAsk` unchanged), at 1.1 s it answers and closes; a click on Allow Once at 0.1 s acts; Escape and Deny at 0 s act; Return and Space arrive as `keyDown` events, a `leftMouseUp` does not. Mutation MS1 (below) makes it fail.
- **60 s, the real code path.** `vc1` uses `larsal_sshagent::QUESTION_TIME` (60 s):

  ```
  [verify] question time: 60s
  [verify] no answer: reply [5] after 60.01767775s; question now None
  ```

  A late Allow Once is ignored and the question stays closed. With the time set to 63 s (M11) the test fails at 63.03 s.
- **One question at a time.** Two signers: after 1.5 s only the first question shows (id 9) and neither reply has come; after Deny the second shows (id 10); both get `[5]`. 6 signers at once (probe below): every round shows its questions one at a time.

## D. Rule 4

- **The FFI surface** (`crates/larsal-ffi/src/ssh.rs`, read in full; the generated `LarsalCore.swift` has exactly these SSH calls: `setSshAgent`, `stopSshAgent`, `sshQuestion`, `answerSshQuestion(id:allow:)`, `takeSshFailures`, `sshAgentInfo`). `SshQuestion { id, heading, text }` holds MI06-29 and MI06-30, -31 or -37 filled with the title (or the mask, LD-207) and the host or nothing; `SshFailure { title, id, message }` and `SshAgentInfo { socket, setup_line, error }` hold no secret. `set_ssh_options` and `ssh_settled` are test-only and not exported. Passphrases resolve inside Rust (`EntryKey::passphrase`, `refs::copy_context`); the key, the passphrase and the data to sign never cross. Swift (`SshKeyUse.swift`) holds a `SshQuestion` and a `Date`.
- **Logs and error text.** No `println!`, `eprintln!`, `dbg!`, `log::` or `tracing::` in larsal-sshagent, larsal-crypto `ssh.rs` or larsal-ffi `ssh.rs`. `Error` (larsal-sshagent `lib.rs`) holds paths, names and flags. `AgentKey`'s Debug is `AgentKey(<alg> [hidden])`; `OpenSshKey`'s is its algorithm and fingerprint; `EntryKey` and `Step` derive Debug over those.
- **Memory scan, T24 and T74** (AT-C01 method, inside the process, as in round 1). The scan walks the process's own map with `mach_vm_region_recurse` (submaps followed), takes each readable region that is writable or tagged (heap, stacks), and reads the pages `mincore` reports resident with `mach_vm_read_overwrite`. The needles are compiled in XOR-masked, and the read buffer itself is skipped and zeroed after each scan.

  ```
  [verify] memory scan start: K1 seed 0 hit(s), passphrase 0 hit(s) in 35 MB read; at []
  [verify] memory scan T24 added to the system agent, 1 s later: K1 seed 0 hit(s), passphrase 1 hit(s) in 104 MB read; at [(8d3c040b0, 2)]
  [verify] memory scan T24 after close: K1 seed 0 hit(s), passphrase 0 hit(s) in 104 MB read; at []
  [verify] memory scan T74 control, Larsal's agent holds the key: K1 seed 1 hit(s), passphrase 1 hit(s) in 104 MB read; at [(101cca2c7, 7), (8d3c040a0, 2)]
  [verify] memory scan T74 after lock, 1 s later: K1 seed 0 hit(s), passphrase 0 hit(s) in 104 MB read; at []
  [verify] summary: seed held 1, after lock 0
  ```

  - **T24:** 1 s after the add to the system agent, K1's seed is not in Larsal's memory. The one passphrase hit (MALLOC_SMALL, tag 2) is the unlocked vault's own Password field; it is gone after the close.
  - **T74:** after the lock Larsal's agent lists 0 keys and the seed is gone 1 s later.
  - **The control:** while Larsal's agent holds the key the scan finds the seed once (MALLOC_TINY, tag 7), so the scan sees a held key.
  - A view-level dump of the real `Larsal.app` (lldb) stays with Mac QA, as in E6-S6.

## E. Mutations (second copy; each restored and compared with `cmp` to the tree)

Tool: `mut.py` (exact replacements, run, restore, `cmp`); Swift: `swiftmut.sh` (copy 1, `-only-testing:LarsalTests/SshKeyUseTests`). Every file was restored equal to the tree.

| # | Mutation | File | Test | Result |
|---|---|---|---|---|
| M1 | the lock skips `Keyring::lock` | larsal-ffi `ssh.rs` | `ssh` `int06_24` | 2 FAILED: `int06_24_lock_removes…` "AT-H01" (K1 left), `int06_24_close_and_lock_all…` |
| M2 | sign without asking | `server.rs` | `int06_34_the_window_answers…` | FAILED: `no question` |
| M3 | host named for any request | `server.rs` | va2; `t57_ld203_2_…` | va2 FAILED (`plain data: … sign in to db.example`); `t57_ld203_2_other_data_on_a_bound_session_names_no_host` FAILED (`left: Some("web01.example") right: None`) |
| M4 | socket 0666 | `server.rs` | va2 | FAILED: `left: (448, 438) right: (448, 384)` |
| M5 | the fix's `id <= cancelled` check removed | larsal-ffi `ssh.rs` | `ssh::tests::int06_34_a_cancel_before…` | FAILED: `Deny at once`, `left: Err(Timeout) right: Ok(false)` |
| M6 | question ids per agent (`QUESTION_IDS.store(1)` in `start`) | `server.rs` | `int06_34_a_new_agent_asks_again…` | FAILED: `no question` |
| M7 | no unlock hook | larsal-ffi `session.rs` | `int06_24_lock_removes…` | FAILED: nothing listed after unlock |
| M10 | the lock keeps Larsal's own keys (both `drop_own` calls) | `keyring.rs` | `int06_34_sr16`, `int06_31` | `int06_34_sr16_lock_closes_the_question_as_deny` FAILED (no reply after the lock); `int06_31` passed (it covers decryption) |
| M11 | question time 63 s | `server.rs` | vc1 | FAILED: Deny after `63.028568458s` |
| MS1 | R06-6 first second → 0 s | `SshKeyUse.swift` | `SshKeyUseTests` | 2 issues: `!ask.takes(allow: true, byKey: true, at: Self.start + 0.5)`, `window.sshAsk == ask`; `** TEST FAILED **` |
| MS2 | an ended question stays on the window | `SshKeyUse.swift` (`refreshSsh`) | `SshKeyUseTests` | 1 issue: `window.sshAsk == nil` (SshKeyUseTests.swift:99); `** TEST FAILED **` |

Probes (not mutations of behaviour under test; second copy):

| # | Change | Probe | Result |
|---|---|---|---|
| P0 | none | dead question; inversion | 0 of 5; questions shown `[6, 7]` |
| P1 | first `ask()` in `server.rs` pauses 500 ms between its id and its ticket | inversion | shown `[2]`: question 1 never shows; replies X `[5]`, Y `[5]` |
| P2 | P1 plus the fix's check removed | inversion | shown `[2, 1]`: question 1 shows after 2 times out |
| P3 | question thread starts 200 ms late | dead question | 0 of 5 (fix holds) |
| P4 | P3 plus the fix's check removed | dead question | 5 of 5 |
| P5 | none | natural: 6 signers at once, 300 ms, 15 rounds | round 13: shown `[79, 80, 82, 83, 84]`, 1 request denied unseen |
| P6 | a print in the fix's Deny-at-once branch only | natural, 4 runs | 0, 1, 2 requests denied unseen; prints `ask(3) is Deny at once, cancelled mark 6`, `ask(49) … mark 50`, `ask(87) … mark 89` |

## Other checks

- `cargo clippy --locked -p larsal-sshagent -p larsal-crypto -p larsal-ffi --all-targets -- -D warnings` (tree, own target dir): `Finished`, no warning.
- `cargo fmt --all -- --check` and `cargo fmt --manifest-path fuzz/Cargo.toml -- --check` (tree): clean.
- `scripts/check-names.sh` (tree): `names: PASS (3093 files scanned, 15 vault files name-only)`.
- `xcrun swift format lint --strict` and swiftlint 0.65.1 `lint --strict --quiet` on `SshKeyUse.swift` and `SshKeyUseTests.swift`: exit 0.
- Fuzz smoke (second copy): `cargo +nightly fuzz list` includes `ssh_key_read` and `ssh_settings_read`; `ssh_settings_read` 30 s: `Done 1153791 runs in 31 second(s)`; `ssh_key_read` 30 s: `Done 730756 runs in 31 second(s)`; both artifact folders empty; `fuzz/Cargo.lock` unchanged by the build (`cmp` equal to the tree's).

## Fails

1. **Low: a sign request can be denied without its question** (INT-06.33 "for a key it holds, Larsal asks the question"; INT-06.34 "further sign requests wait in order").
   - **Where.** larsal-ffi `ssh.rs` `Ask`: `ask(id)` returns false at once for any `id <= cancelled`, the highest cancelled id. larsal-sshagent `server.rs` `sign` takes `QUESTION_IDS.fetch_add` before `ask()` takes its queue ticket, so two requests that arrive together can be asked in the opposite order of their ids (a preemption or the queue lock's wake-up order).
   - **What happens.** Request X gets id N and request Y id N+1, but Y is asked first. Y ends without an answer (60 s, a lock of Y's vault, a remove or lifetime end of Y's key): `cancel(N+1)` raises the mark. X's turn comes: `N <= N+1`, so X gets Deny at once and its question never shows; `ssh` prints "agent refused operation". Nothing ever signs without Allow Once.
   - **Proof.** P5 and P6 (no behaviour change; 6 signers at once, question time 300 ms): 4 of 450 requests denied unseen, with the branch named by the print. P1 and P2 make it certain with a pause: with the mark, question 1 never shows; without it, it shows after question 2 times out.
   - **Realistic trigger:** parallel `ssh` runs with one ask-first key (for example a deployment tool's parallel connections, or parallel `git` fetches), where one question is left unanswered for 60 s or its vault locks.
   - **Smallest fix:** in larsal-ffi `ssh.rs`, keep the exact ids cancelled before they showed instead of the highest one: `cancel(id)` adds `id` to a small set when it is not the shown question; `ask(id)` returns false at once when it removes `id` from that set. The process-wide counter stays for uniqueness. (Or: hand out the question id together with the queue ticket, under the queue lock in `server.rs`, so ids rise in asking order.) Test: `cancel(8)`, then `ask(7)` on another thread shows question 7 and Allow Once returns true; it fails with today's mark. The existing `int06_34_a_cancel_before…` test keeps its meaning.

## Open, not blocking (allowed by the brief)

- **The requesting program's name.** It needs a peer process ID call (`LOCAL_PEERPID`) in larsal-platform `macos/`, which is unsafe and needs two Checkers. Until then the question says "A program".
- **Parts the mockup does not draw** wait for the owner's frames (D-INT06-7, W-05): the settings row with Copy Setup Line, the Not loaded state, the INT-06.43 notes, MI06-27, R06-7's wording and MI06-18's Details button. `ssh_agent_info` and `take_ssh_failures` are ready on the Rust side.
- **Another user ID on Larsal's socket** (T26 style): needs a second user (the CI root fixture).
- **The longer fuzz runs** wait for E13-S3.
- **The INT-06.8 fallback comment** `<user name>@<name>` reaches the system agent even when the UserName is protected (for the lead, from the Builder).
- **T24 and T74** ran again with the AT-C01 method (above); a standing test is still not in the suites.

## Notes for the lead

- **Another story's Swift failure.** The full xcodebuild run had 2 issues, both in `AccessibilityWalkTests` "AT-K06" for the "settings" and "vault settings" windows: the settings pages' Back button (16 × 16 at 253,27) and the Less and More stepper buttons "the focus cannot reach it". These are E5-S9 settings controls, not E9-S2 code (E9-S2 adds no settings row). 202 other tests passed, including every SSH test.
- **R06-6 and key repeat** (from round 1, still true): a Return held down sends repeated `keyDown` events, so a repeat after the first second would choose Allow Once. Ignoring `isARepeat` events would close it; the card does not ask for it.
- **Leftovers of an earlier, unfinished Verify run** (before round 1) are still in /tmp: `/tmp/e9s2w-verify-proof`, `-scripts`, `-refhome`, `-sums-start.txt`, and its canary process PID 20154 (`canary.py`, started 15:51). Not mine; left alone. The lead may stop PID 20154 by its PID.

## Round 1 (history, same role, 2026-10-28)

Failed (2): (1) `cargo deny check` failed on the yanked `crypto-bigint` 0.7.7 that `p256` (LD-201) brought; (2) Low: a lock that landed before the question thread showed its question left a dead question on the window (probe 5 of 5). Passed then: the own driver against throwaway OpenSSH 10.3p1 agents and a loopback `sshd` (4 of 4), the frame (light 0.38 %, dark 0.40 %), R06-6, 60 s (Deny at 60.003 s), the T24 and T74 memory scan, 9 of 9 Rust and 1 of 1 Swift mutations, canary 0 connections. Both fails were fixed by the Builder (LD-201 bump note; `Ask`'s cancelled mark and the process-wide question ids) and are re-checked above.

## Cleanup

- Canary PID 38564 (mine) stopped by its PID; its log held 0 connections at the end.
- Deleted `/tmp/e9s2w-verify3-copy`, `-copy2`, `-target`, `-target2`, `-clippy`, `-dd`, `-refhome`, `-scripts` and `-proof` (the outputs quoted here were taken from `-proof` first). None left.
- Every throwaway agent and `sshd` of my runs was stopped by its PID on drop, and every `/tmp/e9s1-<pid>-*` test folder was removed on drop. At the end, the only agent with an `e9s1-` folder was PID 38977, a child of `/tmp/e5s10-checker1-target/…/ssh-…` (PID 38566, started 19:45:58): another agent's run, left alone. PIDs 6258, 20154 and 85551 were running before this task and are not mine.
- In the tree I changed only this file, this frame's Verify note in `design/parity/dialogs/report.md`, `report.html` and `findings.json`, and the E9-S2 status line in `plan/epics.md`. `scripts/check-names.sh` after the edits: `names: PASS (3093 files scanned, 15 vault files name-only)`.

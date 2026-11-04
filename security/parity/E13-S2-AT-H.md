# E13-S2 attack campaign, group AT-H: SSH agent and hardware keys (AT-H01 to AT-H04)

Story: E13-S2. Catalog: [plan/attacks-and-checks.md](../../plan/attacks-and-checks.md), group AT-H. Cards: [INT-06](../../spec/integrations/INT-06-ssh-agent.md), [INT-07](../../spec/integrations/INT-07-hardware-keys.md), FMT-04. Decisions: LD-173, LD-175, LD-213, OD-01.
Date: 2026-10-29. Role: Red team. I did not build or review these stories.
Earlier proof, history only: [E9-S1](E9-S1-ssh-agent-client.md), [E9-S2](E9-S2-ssh-keys.md), [E10-S1](E10-S1-hardware-keys.md). Every result below was run again on today's tree.

| Row | Result | One line |
|---|---|---|
| AT-H01 | **failed** (one sequence) | Lock, Lock Everything and close remove marked keys in 10 to 18 ms and App's own keys in about 50 ms, also when the lock lands in the middle of the unlock's adds (56 runs, 0 keys left). **But** when the agent socket setting changes while a vault is unlocked, the lock removes from the new socket and the key stays in the old agent, with no message (F-H1, Medium). |
| AT-H02 | passed | The lifetime reaches the system agent as limit `01` with the seconds and the agent drops the key on time; "Ask before each use" keys never reach the system agent: App's agent asks before every signature (deny, allow, no answer, stale answer) and drops the key when its lifetime ends. |
| AT-H03 | passed (simulated key, OD-01) | A key pulled after any of the 10 frame reports or any reply read gives M06-17 "Your security key is not connected…" at unlock and at save; a failed save hands nothing to the writer: file bytes, modification time and folder unchanged. A real key pulled mid-call needs the owner's key (Mac QA). |
| AT-H04 | passed (simulated key, OD-01) | Another key, another slot's secret, no key, or both wrong: `WrongKey` and M06-06, the same error and words as a wrong password. The reference CLI does the same on its hardware-key test vault. |

Findings: **F-H1 Medium** (AT-H01, socket change), **F-H2 Low** (lock blocks 2 s per key on a silent agent), **F-H3 Medium** (hardware keys not wired into the app or the CLI), **F-H4 Low** (two SSH tests fail under heavy load). Details at the end.

## Setup

- **Tree.** Today's tree, read only. `. "$HOME/.cargo/env"`, toolchain 1.99.1, `CARGO_TARGET_DIR=/tmp/e13s2-target` (the shared red team build), `--offline`. No product file was changed.
- **Driver.** My own crate `/tmp/e13s2-H/driver` (binary `e13s2h`), outside the workspace, with path dependencies on app-ffi, app-sshagent, app-crypto, app-format, app-model, app-hwkey and app-core, the tree's `Cargo.lock` and the tree's two `[patch.crates-io]` lines. It drives the same exports the window app calls: `Session::new`, `set_ssh_options`, `set_ssh_agent`, `save_settings`, `open`, `unlock`, `lock`, `lock_all`, `close`, `ssh_question`, `answer_ssh_question`, `take_banner`. No builder test code was used.
- **Agents.** Throwaway OpenSSH 10.3 agents (`/usr/bin/ssh-agent -D -a /tmp/e13s2-H/r/<case>/…`), started by the driver with a cleared environment (`PATH=/usr/bin:/bin`, `HOME` a /tmp folder) and stopped by their PIDs (for example 28080, 35297, 45906, 50457, 56120 and 56122; each "stopped" line is in the logs). A small python recorder (`/tmp/e13s2-H/scripts/proxy.py`, run with `python3 -I`) sits in front of an agent where noted: it logs each request's type and, for adds, the last 6 bytes, where the limits sit; on demand it holds removals (message 18) without an answer, or delays every request.
- **The owner's agent was never contacted.** Every driver and cargo run had `SSH_AUTH_SOCK=/tmp/e13s2-H/canary.sock`, a socket of mine that logs each connection: **0 connections**. Every `ssh-add`, `ssh-keygen` and `ssh-agent` ran with a cleared environment. No `~/.ssh` file was read; no keychain was touched; the settings store of a test session lives in memory only.
- **Demo data only.** Keys made by `ssh-keygen` in `/tmp/e13s2-H/r/…` (passphrase `demo-h-pass` where protected); demo vaults saved by app-format with password `demo-h-vault` (SSH) or `demo-hk-pass` (hardware key); demo HMAC secrets `e13s2h demo secret A 20b` and `… B 20b`. A copy of the reference's hardware-key test vault in `/tmp/e13s2-H/ref/` (SHA-256 `566be617…ad3b` before and after).
- **No window, no pasteboard.** Nothing was launched in the window app; nothing touched any pasteboard.
- **Load.** Other agents were building at the same time: load average 160 to 250 (`uptime` 21:04 and 21:07).

## AT-H01 Keys after lock

**Method (row):** lock the vault, list the agent's keys; pass when the keys are gone within 1 second. Card scope (INT-06.24, INT-06.31): keys marked remove-on-lock leave the system agent; keys in App's own agent always leave.

**Commands.** `e13s2h h01a`, `h01b`, `h01c`, `h01d`, `h01e`, `h01f`, `h01g`, `h01h` (logs in `/tmp/e13s2-H/logs/`). Listing is `/usr/bin/ssh-add -l` against the system agent's socket and against App's socket (`<case>/App/agent.sock`), polled every 2 ms after the lock call.

### a. Lock, Lock Everything, close (`h01a`)

Vault: "Marked" (Ed25519, protected, remove-on-lock), "Unmarked" (P-256, remove-on-lock off), "Asks" (Ed25519, ask before each use, so App's own agent).

```
[lock] after unlock: system ["k1@e13s2h", "k2@e13s2h"] | App's socket ["k3@e13s2h", "k1@e13s2h", "k2@e13s2h"]
[lock] call returned 549.792µs; k1 gone from system agent at Some(9.664084ms); k3 gone from App's socket at Some(55.204459ms)
[lock] 1 s later: system ["k2@e13s2h"] | App's socket ["k2@e13s2h"]
[lock_all] call returned 125.375µs; k1 gone from system agent at Some(14.094917ms); k3 gone from App's socket at Some(58.224625ms)
[close] call returned 63µs; k1 gone from system agent at Some(18.319417ms); k3 gone from App's socket at Some(51.305875ms)
```

The k3 time is measured after the k1 poll ends, so it includes it. "Unmarked" stays in the agent after the lock, as INT-06.24 and the reference do. No banner.

### b. Lock while the unlock's adds still run (`h01b`)

12 keys with remove-on-lock (10 plain, 2 protected that take about 200 ms each to decrypt) and 1 ask-first key. 36 runs: lock or Lock Everything 0, 1, 2, 5, 10, 20, 50, 100, 150, 200, 300 and 450 ms after `unlock` returned, 3 each. Then 20 more runs that lock at once, with no listing between unlock and lock.

```
delay   0 ms rep 0: listed at the lock 10; 1 s after the lock: system 0 App 0
… (every delay the same)
RACE runs 36, locks that landed mid-adds 36, keys left 1 s after a lock 0
RACE no-probe runs 20, keys left 1 s after a lock 0
```

Every lock landed while the protected keys were still being decrypted; no key was added after a lock. Code: the lock sets the vault's stop flag before `Keyring::lock`, and `add_planned` checks it again under the operations lock (`keyring.rs`).

### c. The system agent stops answering at the lock (`h01c`)

3 marked keys and 1 ask-first key behind the recorder; after the unlock the recorder holds every removal (message 18) without an answer.

```
after unlock: system ["m0@e13s2h", "m1@e13s2h", "m2@e13s2h"] | App's own key in App's socket: Some(1)
lock() returned after 6.003885208s (3 marked keys, agent silent on removals)
App's own key in a raw list of App's socket right after lock() returned: Some(0)
App's own key gone (raw list) at Some(51.610875ms)
banner: Some("App couldn't take the key of “Marked 0” out of the SSH agent. Use Remove All Keys from SSH Agent… to clear it. … “Marked 1” … “Marked 2” …")
system agent itself afterwards: ["m0@e13s2h", "m1@e13s2h", "m2@e13s2h"]
```

App's own key went at once and MI06-19 names every key left behind: as the card says. But the lock call itself waited 2 s per key (6.0 s for 3), and the window app calls it on the main thread: F-H2 (Low).

### d. The agent socket setting changes while the vault is unlocked (`h01d`, `h01f`) — fails

Two throwaway agents, A and B. The vault has one key with remove-on-lock. S-SSH-02 (the socket override) is A at the unlock, then changed to B, then the vault locks.

`h01d` calls `set_ssh_agent(true, B, "")`, which is what Settings › OK runs (`app_settings.rs` `apply_ssh`). `h01f` goes through `Session::save_settings` itself:

```
h01d: unlocked with S-SSH-02 = A: A ["k1@e13s2h"] | B []
h01d: S-SSH-02 changed to B, then lock() in 170.417µs
h01d: 1 s after the lock: A ["k1@e13s2h"] | B [] | banner None
h01d: socket changed to B and feature off in one OK: A ["k1@e13s2h"] | B [] | banner None
h01f: Settings: SSH on, socket A; unlocked: A ["k1@e13s2h"] | B []
h01f: Settings: socket B (OK), then lock; 1 s later: A ["k1@e13s2h"] | B [] | banner None
```

The marked key stays in agent A after the lock, and after turning the feature off, with no MI06-19: a program using A can still sign with it. Cause: `Keyring`'s records do not keep the agent a key went to; `remove_from_system` asks `system_agent()`, which reads the setting at the time of the lock, and B's "not holding it" is not an error (`keyring.rs`). The reference removes from the socket set at lock time too (its agent client connects to the current socket path), so App matches the reference but not the card's promise. F-H1 (Medium).

### e. One key in two entries (R06-5) and a lock during a question (`h01e`, `h01g`)

```
h01e (asking entry first):  after unlock: system [] | App's socket ["k4@e13s2h"]; lock: k4 gone from App's socket at 52.237875ms; 1 s later: system [] | App's socket []
h01g (non-asking entry first): after unlock: system [] | App's socket ["k8@e13s2h"]
  requests the system agent got: 11 (one list) only — no add of k8 at any time
  question shown: "Allow a program to use “Asks (second)”?"
  lock during the question: signer ended 837.25µs after the lock: ok=false (… agent refused operation)
  question now None; App's socket []
```

### f. Unlock never waits for the agent (`h01h`)

The recorder delays every request 3 s:

```
agent delay None s: open 95.167µs, unlock 1.131138583s     (first unlock in the process)
agent delay Some("3") s: open 32.862666ms, unlock 18.938334ms
agent delay None s: open 80.875µs, unlock 970.25µs
agent delay Some("3") s: open 56.125µs, unlock 966.583µs
agent delay None s: open 145.25µs, unlock 2.223625ms
agent delay Some("3") s: open 88µs, unlock 1.8635ms
```

So the failing builder test `int06_22…` (below) is the load, not a wait on the agent.

### g. Builder tests on today's tree

`cargo test --offline -p app-sshagent -p app-hwkey`, `-p app-ffi --test ssh`, `-p app-ffi --lib ssh`, all with the canary as `SSH_AUTH_SOCK`:

- app-sshagent unit 22 passed; `tests/agent.rs` first run 22 passed, 2 failed (`at_h01_remove_leaves_agent_within_1s`, `t33_add_again_replaces_limits`, both `Unreachable { …, why: Connect }` at the throwaway agent's first connect); re-run with `--no-fail-fast`: **24 passed**; `tests/own_agent.rs` **34 passed**.
- app-ffi `ssh` 15 passed, 1 failed: `int06_22_unlock_adds_off_the_calling_thread…` (`unlock waited for the agent: 2.376944375s`; alone, 3 more times: 1.54 s, 1.23 s, 1.06 s against its 900 ms bound). Section f shows the unlock does not wait. app-ffi lib `ssh` 5 passed, among them `int06_24_at_h01_a_lock_during_decryption_adds_nothing_to_the_system_agent`.
- Both failures are F-H4 (Low).

**Result AT-H01: failed** in the sequence of section d (F-H1). Every other path passed: lock, Lock Everything and close within 18 ms (system agent) and about 50 ms (App's agent), 56 race runs with 0 keys left, a silent agent, R06-5 both orders, a lock during a question.

## AT-H02 Key limits

**Method (row):** add a key with lifetime and confirm settings; pass when the agent shows both limits. Card (INT-06 Verification, LD-173 (b)): the lifetime reaches the system agent (proof by behavior: `ssh-add -l` does not print limits); a key that asks before each use never reaches the system agent and every signature needs Allow Once (T51, T53, T57); App's agent drops it when its lifetime ends (INT-06.35).

**Commands.** `e13s2h h02`. Vault: "Lifetime 3 s" (k5, Ed25519), "Asks, lifetime 8 s" (k6, Ed25519, ask before each use plus lifetime 8 s), "Asks (P-256), no lifetime" (k7). The recorder sits in front of the system agent. Only the `.pub` files stay on disk after the vault is made, so `ssh-keygen -Y sign -f <key>.pub` can sign only through an agent. My first run had left the private files in place: `ssh-keygen` then fell back to them when the agent did not hold the key. I discarded that run; the output below is the corrected one. App's question time is 3 s. A thread answers the questions through `answer_ssh_question`, after R06-6's first second.

```
proxy saw (plain adds, type 17): (none)
proxy saw (adds with limits):  type=25 len=138 tail=680100000003
t=691.516333ms system ["k5@e13s2h"] | App's socket ["k6@e13s2h", "k7@e13s2h", "k5@e13s2h"]
k5 (lifetime 3 s) gone from the system agent at Some(2.903078458s) after the unlock
sign 1 with k6 through App's socket: ok=false in 1.134488375s: … agent refused operation      (Deny)
sign 2 with k6 through App's socket: ok=true in 1.174870375s: Good "file" signature with ED25519 key SHA256:TnStXLk6…   (Allow Once)
sign 3 with k6 through App's socket: ok=false in 3.061887167s: … agent refused operation      (no answer: Deny at 3 s)
sign 4 with k7 through App's socket: ok=true in 1.140853833s: Good "file" signature with ECDSA key SHA256:UaCraYG4…
asked: q1 "Allow a program to use “Asks, lifetime 8 s”?" / "A program wants to sign with this key." -> Some(false)
asked: q2 … -> Some(true); q3 … -> None; q4 "Allow a program to use “Asks (P-256), no lifetime”?" … -> Some(true)
sign through the system agent's own socket with k6: (false, "No private key found for public key …/k6.pub")
k6 (lifetime 8 s) gone from App's socket at Some(9.481829625s) after the unlock; App's socket now ["k7@e13s2h"]
sign with k6 after its lifetime: (false, "No private key found …"); questions asked for it: []
first (denied): (false, … agent refused operation)
second (old id answered Allow): (false, … agent refused operation, 3.071627s); ids [5, 6]
```

- **Lifetime:** the only add the system agent saw is message 25 ending `68 01 00 00 00 03`: the last comment byte, then limit 1 with 3 seconds and no confirm byte. The agent dropped k5 by itself about 3 s after the add.
- **Confirm:** neither ask-first key was ever sent to the system agent (no message 17 or 25 for them). Each signature through App's socket asked once. Deny, no answer and a stale answer (the id of an earlier question) all refused, and Allow Once signed with a signature that `ssh-keygen -Y check-novalidate` accepts.
- **Both limits on one key:** k6 asked on every use and left App's agent when its 8 s ended; after that no signature and no question.
- **Builder tests:** `t28_lifetime_bytes_after_the_comment`, `t31_lifetime_2s_key_gone_after_3s`, `t37_lifetime_0_refused_nothing_sent` and `t33` (on the re-run) pass in `tests/agent.rs`; `own_agent.rs` 34 pass.

**Result AT-H02: passed.** The real macOS system agent (V-INT06-3) still waits for the owner's go, as before.

## AT-H03 Key pulled out

**Method (row):** remove the hardware key during unlock and during save; pass on a clear error with the vault file intact. Simulated key per OD-01: no hardware key is plugged into this Mac (IOKit lists 4 HID devices, 0 with a key vendor id; `ioreg -r -c IOHIDDevice -l` finds no vendor id 4176 or 7504).

**My simulated key.** `driver/src/hw.rs`, written from INT-07.9 to INT-07.12 behind app-hwkey's public `Bus` and `Device` traits: 8-byte feature reports; a status report with the slot bits; 70-byte frames in 10 parts, each part's CRC checked (start `FFFF`, reflected `8408`); variable-mode HMAC-SHA1 through app-crypto; the reply in 4 reports with the ones' complement CRC; and the reset report. "Pulled out" makes the next write or read fail with `Missing`; after that, the list is empty. The crate's own `#[cfg(test)]` device was not used.

**Commands.** `e13s2h hw` (demo vault: password + key A in slot 2, 1,797 bytes), `e13s2h hwreal` (this Mac's real IOKit layer). Messages come from app-ffi's `messages::for_open_error`, which the unlock screen uses.

```
control: right password, key A slot 2: Ok(opened, 1 entries)
not plugged in:                   Err(HardwareKey(Missing)) -> M06-17 "Your security key is not connected. Plug it in, then try again."
pulled after write  0 … 9:        Err(HardwareKey(Missing)) -> M06-17 "…"      (10 lines, every frame report)
pulled after write 10:            Ok(opened, 1 entries)   (the answer was already read; only the reset report failed)
pulled after reply read 0 … 4:    Err(HardwareKey(Missing)) -> M06-17 "…"
pulled, zero reports instead of errors: Err(HardwareKey(SlotNotConfigured)) -> M06-19 "…" in 2.194184666s
== save (app-format builds the bytes, app-core's safe write only when it got them)
pulled after write 0, 1, 3, 6, 9; after reply read 0, 2; not plugged in:
    save refused: HardwareKey(Missing) -> M06-17 "…"; nothing handed to the writer
file sha256 before d0d61e834d91100f519c013cf6434d886b53839d099d0b935ed015aab41411fa after d0d61e83…11fa | equal true | mtime equal true
folder before ["hk.appvault"] after ["hk.appvault"]
the file still opens with key A: Ok(opened, 1 entries)
control, key present: saved 2165 bytes: Ok("ok"); control reopened: Ok(opened, 2 entries)
== real IOKit bus on this Mac, no key plugged in
open: Err(HardwareKey(Missing)) -> M06-17 "…"; save: Err("HardwareKey(Missing) -> M06-17")
```

- A failed challenge stops the save before any byte is built, so no temp file or backup appears.
- The zero-report case is a device that answers blank reports after removal instead of an error. It gives M06-19 (slot not set up) after 2 s: still a clear error, but the wrong one. The IOKit layer maps `kIOReturnNoDevice` and `kIOReturnNotAttached` to `Missing` (`usb/mod.rs`). What a real key returns when it is pulled mid-call is LD-188 condition 5: needs a real key (Mac QA, owner's go).
- **Builder tests:** app-hwkey unit 37 passed, among them `t35_at_h03_key_missing_or_removed` and `t04_t34_at_h04_other_secret_or_mode_is_the_wrong_key_result`. `tests/real_key.rs`: 1 passed, 1 ignored (T53, real key). `tests/watch.rs`: 2 passed.
- **The app and the CLI cannot reach this code (F-H3).**
  - `Session`'s unlock passes `hardware_key: None` (`session.rs`). No crate depends on app-hwkey. The unlock screen's "Use a security key" switch is disabled ("Security keys come in E10.").
  - `app db-info --hw-key 2 hk.appvault` (release `app` from the shared build) asks for the password, then prints "Your security key is not connected. Plug it in, then try again." without looking for a key (`vault.rs` `read_creds`). Without `--hw-key` it prints M06-06; `--hw-key 3` gives the slot error. The demo vault's SHA-256 was the same after these runs.

**Result AT-H03: passed** on the simulated key and on the real IOKit layer without a key. The real-key half (pulled mid-call) is Mac QA. The in-app path does not exist yet (F-H3).

## AT-H04 Wrong hardware key

**Method (row):** use another key; pass when the result is the same as a wrong password.

```
wrong password, key A:                 Err(WrongKey) -> M06-06 "Wrong password, key file or security key. Check them and try again." in 771.079667ms
right password, key B (other):         Err(WrongKey) -> M06-06 "…" in 576.880042ms
right password, slot 1 (other secret): Err(WrongKey) -> M06-06 "…" in 1.317267834s
right password, no key given:          Err(WrongKey) -> M06-06 "…" in 676.139ms
wrong password, key B:                 Err(WrongKey) -> M06-06 "…" in 266.182667ms
slot 1 not set up on key B:            Err(HardwareKey(SlotNotConfigured)) -> M06-19 "The chosen slot of your security key is not set up for challenge-response. Choose another slot."
SAME AS WRONG PASSWORD: other key true | other slot true | both wrong true | message equal true
```

The times vary with the machine's load (load average about 200), not with the case. Each case runs the KDF; the slowest is a right-key case.

**Against the reference** (REF_CLI `db-info`, throwaway `HOME=/tmp/e13s2-H/refhome`, which stayed empty; the reference's hardware-key test vault; its variable-mode answer as a 20-byte key file, and the same answer with one bit flipped):

```
REF_CLI password=a key-file=answer-right.key exit=0 :: Number of entries: 2
REF_CLI password=b key-file=answer-right.key exit=1 :: Error while reading the database: Invalid credentials were provided, please try again.
REF_CLI password=a key-file=answer-wrong.key exit=1 :: Error while reading the database: Invalid credentials were provided, please try again.
App, reference vault, right password, right answer: Ok(opened, 2 entries)
App, reference vault, wrong password, right answer: Err(WrongKey) -> M06-06 "Wrong password, key file or security key. Check them and try again."
App, reference vault, right password, wrong answer: Err(WrongKey) -> M06-06 "…"
```

App's runs feed the answer through app-format's `ChallengeResponse`, without a device. Both apps treat a wrong answer exactly like a wrong password.

**Result AT-H04: passed** on the simulated key. Another physical key needs the owner's keys (Mac QA). The unlock screen cannot use a key yet (F-H3).

## Findings

| ID | Severity | Area | Steps to reproduce (demo data) | Smallest fix |
|---|---|---|---|---|
| F-H1 | Medium | SSH agent, lock (AT-H01, INT-06.24, INT-06.26) | 1. Start two throwaway agents A and B (`ssh-agent -D -a /tmp/x/A.sock`, the same for B). 2. A demo vault with one entry: an Ed25519 key in attachment `id_key` and "Remove the key when the vault locks" on. 3. SSH agent on, socket override A (`save_settings`: `ssh.enabled` on, `ssh.socket_override` A); unlock; `SSH_AUTH_SOCK=A ssh-add -l` lists the key. 4. Settings: socket override B, OK (`save_settings`). 5. Lock. 6. After 1 s, `SSH_AUTH_SOCK=A ssh-add -l` still lists the key; no MI06-19. Turning the feature off in the same OK leaves it too. (`e13s2h h01d`, `h01f`.) The reference behaves the same; the card promises the removal. | Keep the agent's socket path in each `Record` when the key is added (`load_held` already holds the `Agent`), and remove from that path in `remove_from_system` (lock, turn off) and `unload`. Or: when `set_agent_settings` gets a new socket while records exist, first remove App's recorded system-agent keys from the old one, as turn-off does. Test: the h01d sequence ends with A empty. |
| F-H2 | Low | SSH agent, lock (INT-06.24) | Recorder in front of a throwaway agent that never answers message 18; a vault with 3 remove-on-lock keys; unlock, then `Session::lock`: the call returns after 6.0 s (2 s per key). The window app calls `session.lock`/`lockAll` on the main thread (`MainWindowModel.lockNow`, `lockAll`, also for automatic locks), so the window hangs 2 s per marked key. The vault is locked first, App's own keys go at once, and MI06-19 is right, so nothing leaks. (`e13s2h h01c`.) | In `Keyring::remove_from_system`, after the first removal that times out, skip the agent for the rest and report them all in MI06-19. Or run the system-agent removals on a background thread once the vault is locked. |
| F-H3 | Medium | Hardware keys, wiring (AT-H03, AT-H04 end to end; SF-04, SI-08) | 1. Make a vault protected with a password plus a hardware key (the reference's test vault, or `e13s2h hw`'s `hk.appvault`). 2. In the app, "Use a security key" on the unlock screen is disabled ("Security keys come in E10."); the new vault wizard's and vault settings' "Add…"/"Change…" are the same. 3. `app db-info --hw-key 2 hk.appvault`: password prompt, then "Your security key is not connected…", without looking for a key. Code: `session.rs` passes `hardware_key: None`; no crate depends on app-hwkey; `app-cli` `vault.rs` `read_creds` always returns M06-17. E10-S1 is Done and gives this wiring to E5-S3, E5-S8, E12, APP-01.16 and MOD-12.10, which are all Done, so no open story owns it. | Give the wiring a story (or reopen E5-S3/E12-S1's hardware-key rows): app-ffi's unlock takes an optional `KeyChoice` and builds `HardwareKey { bus: UsbBus::new(), … }` into `Credentials`, with the touch events to the screen; app-cli's `read_creds` does the same for `--hw-key`; the key stays in `Keep` for saving. Then run AT-H03 and AT-H04 again through the session, the CLI and a real key. |
| F-H4 | Low | Tests (check gate) | Under load (load average 160 to 250): `cargo test -p app-sshagent --test agent` failed 2 of 24 once (`Unreachable { …, why: Connect }` at a fresh throwaway agent; passed on re-run). `cargo test -p app-ffi --test ssh int06_22` failed 4 of 4 runs with the unlock at 1.06 to 2.38 s against a 900 ms bound; `h01h` shows the unlock does not wait for the agent. Likely causes: `Throwaway::start` waits only for the socket file, which `ssh-agent` creates with `bind` before `listen`; and a wall-clock bound that includes the process's first unlock. | `Throwaway::start` waits until a connect (or a list) succeeds, not only for the file. `int06_22` compares against the agent's 1 s, for example by asserting that `unlock` returns before the fake agent has read its first add, instead of a fixed 900 ms. |

Not findings:
- Unmarked keys stay in the system agent after a lock (INT-06.24, the reference does the same).
- A crash or a hard kill of App leaves marked keys in the system agent until their lifetime ends. That is how every agent client works; the lifetime limit is the user's protection.

## Cleanup and cost

- Every agent and recorder the driver started was stopped by its PID (lines `[agent pid … stopped]`, `[proxy pid … stopped]` in the logs). Afterwards `ps -axo pid,command | grep /tmp/e13s2-H` showed only my canary (PID 72753), stopped by its PID at the end. `/tmp/e13s2-H` was deleted at the end. My builder test runs left no `/tmp/e9s1-*` folder; one that showed up afterwards belonged to another agent's running test (`/tmp/e13s6a-builder-target/…`) and was left alone.
- CPU: test build 3 min 31 s user; driver builds about 3 min user in total; builder test runs about 3 min; driver runs about 4 min wall in total. Well under 30 minutes. No fuzzing in this group.
- Re-run after the half-done edit: my first driver build failed in app-core `storage.rs` (`app_platform` not found) while another agent was editing app-core for F-047 (files changed at 20:46:08). The same build passed a minute later, with no change of mine.

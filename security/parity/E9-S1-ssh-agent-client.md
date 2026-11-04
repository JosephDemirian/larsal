# E9-S1 Agent client (SI-07 client part, AT-H01, AT-H02)

Story: E9-S1 Agent client. Card: [INT-06](../../spec/integrations/INT-06-ssh-agent.md). Decisions: LD-173, LD-175, LD-179, LD-182, LD-183.
Date: 2026-10-28.
Role: Verify. I did not build or review this story. No reference access was needed, and none was used.
Result: **signed.**

- **Tests:** `cargo test -p larsal-sshagent` 32 passed (8 unit, 24 integration); larsal-crypto `ssh` 3 passed; larsal-platform `pipe` test passed in debug and `--release`.
- **Own driver against throwaway OpenSSH 10.3 agents:** lifetime 2 s listed at 0.01 s and 1.01 s and gone at 3.01 s by `ssh-add -l`. Lifetime 0 and 1,000,000,000 give MI06-17 and nothing is sent. Confirm is refused without askpass. With a scripted askpass the agent asks on every use (3 signs, 3 prompts, the deny fails). Remove, remove absent, remove all and list all match `ssh-add -l`.
- **AT-H01:** remove plus `ssh-add -l` took 12 ms (limit 1 s).
- **AT-H02:** the lifetime is enforced by the agent, and the confirm limit is set: the agent refuses or asks on use.
- **Keys:** all 14 keys (7 types and sizes, plain and protected) read, unlock, add and list. Each fingerprint equals `ssh-keygen -lf` on both the `.pub` and the private file, and `ssh-add -l` lists all 14. DSA gives MI06-12; the 6 older forms give MI06-11. 1,001 rounds are refused in under 1 ms; 1,000 are accepted.
- **Hostile agents:** 20 cases times 4 requests, plus 1,200 random replies: every run gave a typed result. No panic, no hang; the slowest run took 2.02 s.
- **Fuzz:** `ssh_key_read` ran 120 s, 9,116,923 runs. No crash, no artifact.

## Setup

- **Build.** `. "$HOME/.cargo/env"`, `CARGO_TARGET_DIR=/tmp/v-e9s1-target`, toolchain 1.99.1 (nightly for fuzz only). OpenSSH_10.3p1 from `/usr/bin`.
- **The owner's agent was never contacted.** Every `ssh-agent`, `ssh-add` and `ssh-keygen` ran under a cleared environment (`PATH=/usr/bin:/bin`, `HOME=/tmp/v-e9s1/home`). Only the throwaway's own `SSH_AUTH_SOCK` was set, where one was needed. Two throwaway agents ran in the foreground (`ssh-agent -D -a /tmp/v-e9s1/ag-*/s`), PIDs 60790 and 60912. Each was stopped by its PID with SIGTERM. Afterwards `ps -axo pid,command | grep "ssh-agent -D -a /tmp/(v-)?e9s1"` printed 0 lines, and no `/tmp/e9s1-*` folder was left after the Builder's tests.
- **Demo keys only.** Made in `/tmp/v-e9s1/keys` by `ssh-keygen` 10.3 with passphrase `demo-verify-pass`:
  - Ed25519, ECDSA P-256, P-384 and P-521, RSA 2048, 3072 and 4096, each plain and protected (aes256-ctr, bcrypt, 24 rounds);
  - Ed25519 with aes256-gcm and with chacha20-poly1305;
  - Ed25519 with `-a 1001` and with `-a 1000` (both made for real; the round counts were read back from the files);
  - older forms: `-m PEM` RSA plain and protected, `-m PEM` ECDSA, `-m PKCS8` plain and protected;
  - a DSA key from `openssl dsaparam -genkey 1024`, which gives `DSA PRIVATE KEY`;
  - the same DSA numbers (p 1024 bits, q 160 bits) written into an OpenSSH-format file by a small script, because `ssh-keygen` 10.3 says `unknown key type dsa`.
- **Driver.** A separate crate in `/tmp/v-e9s1/driver`, outside the workspace. It uses path dependencies on `larsal-sshagent` and `larsal-crypto`, the workspace `Cargo.lock` and `--offline`. Only the public API is used: `SshKey::read`, `unlock`, `Agent::at`, `add`, `remove`, `remove_all`, `list`, `Error::id` and `message`. The scenarios ran from Python scripts in `/tmp/v-e9s1/scripts`. None of the Builder's test code was used.
- **Nothing in the project changed** except this file and the E9-S1 status line. `find crates fuzz/fuzz_targets fuzz/corpus -newer <first demo key>` printed nothing. Fuzz artifacts went to `/tmp`.

## 1. Builder tests and INT-06 case map

`cargo test -p larsal-sshagent`: `32 passed (3 suites, 11.12s)`. A second run listed every test as `ok`:

- **Unit tests:** `agent::tests::{add_message_is_exact_and_bounded, identities_parse_and_bounds, override_wins_then_environment, hostile_identities_never_panic}`, `messages::tests::{fill_is_one_pass, messages_fill_in_the_cards_words, table_has_every_id_once_in_order}`, `key::tests::hostile_key_files_never_panic`. Total: 8 passed.
- **Integration tests:** `tests/agent.rs`, 24 passed, in 11.07 s.

`cargo test -p larsal-crypto ssh`: `ssh::tests::{other_labels_and_garbage_are_none, k1_public_parts_match_the_card, k1_agent_form_is_type_public_and_seed_with_public}`, 3 passed.

Cases owned by E9-S1 (the client and key reading):

| Case | Test | Part not in E9-S1 |
|---|---|---|
| T14 | `t14_size_limits_before_parsing` (1 MiB + 1 gives MI06-08, empty gives MI06-09) | A folder path giving MI06-07 (file source): E9-S2 |
| T16 | `t16_old_forms_dsa_and_text_are_refused` | |
| T17 | `t17_type_names_and_fingerprints` | |
| T18 | `t18_protected_key_shows_public_parts_without_passphrase` | MI06-27 on the page and the decryption spy: E9-S2 (the crate's `read` never decrypts) |
| T20 | `t20_protected_keys_load_and_list` | |
| T21 | `t21_empty_and_wrong_passphrase` | |
| T22 | `t22_rounds_over_1000_refused_before_any_work` | |
| T25 | `t25_no_agent_set`, `override_wins_then_environment` | Settings page "Not set": E9-S2 |
| T26 | `t26_not_a_socket_of_ours_nothing_written` (file, link, 104-byte path, missing socket or folder) | **Socket of another user: missing.** The card runs it only as a root fixture in CI, and there is no CI yet |
| T27 | `t27_silent_oversize_unknown_and_closed_replies` | |
| T28 | `t28_lifetime_bytes_after_the_comment` | |
| T29 | `t29_confirm_after_lifetime` | History case of option (a), LD-173 |
| T30 | `t30_security_key_provider_extension` | Choice from S-SSH-03 or `SSH_SK_PROVIDER`: E9-S2 |
| T31 | `t31_lifetime_2s_key_gone_after_3s` | |
| T32 | `t32_confirm_is_kept_and_refused_without_askpass` | History, option (a). The askpass half is section 4 here |
| T33 | `t33_add_again_replaces_limits`, plus `t28` (message 17) | Uses a real agent and 2 s, not a fake clock and 120 s |
| T34 | `t34_remove_absent_key_is_not_an_error` | "Not loaded" on the page: E9-S2 |
| T35 | `t35_remove_all_one_message_19_and_agent_empty` | Menu, M08-04 and toast: E9-S2 |
| T36 | `t36_count_that_cannot_fit`, `identities_parse_and_bounds` | |
| T37 | `t37_lifetime_0_refused_nothing_sent` | The stored value from the settings: E9-S2 |
| T68 | `t68_one_request_at_a_time_one_message_per_connection` | |
| INT-06.9 | `int06_9_ciphers_ssh_keygen_offers` | |
| INT-06.15 | `int06_15_every_type_ssh_keygen_makes_is_taken` | |
| AT-H01 | `at_h01_remove_leaves_agent_within_1s` | The lock path: E9-S2 |
| MI06 table | `messages::tests::*` | |

Not covered at E9-S1:

- **E9-S2.** These need the entry settings, sources, records, lock or unlock, Larsal's own agent or screens: T01 to T13, T15, T19, T23, T24 (the memory scan needs a load from an entry and the debug wipe hook), T38 to T59, T61 to T67, and T69 to T74.
- **Kept for history only** (option (a), LD-173): T60.
- **Missing:** only the other-user half of T26 (above).

## 2. The crate's API against a throwaway agent, with the agent's view

`python3 -I scripts/agent_run.py`, exit 0.

```
[agent main] pid=60790 sock=/tmp/v-e9s1/ag-main/s env=['HOME', 'PATH']
ssh-add -l at start: The agent has no identities.
== 2a. add with lifetime 2 s
driver add ed life=2: rc=0 ADD OK SHA256:tc6CYrObBUi++NQcdzscWE+Y+9pamZOBdX6BYQCUTp0 ms=0
  t=0.01s ssh-add -l: 256 SHA256:tc6CYrObBUi++NQcdzscWE+Y+9pamZOBdX6BYQCUTp0 ed@verify (ED25519)
  t=1.01s ssh-add -l: 256 SHA256:tc6CYrObBUi++NQcdzscWE+Y+9pamZOBdX6BYQCUTp0 ed@verify (ED25519)
  t=3.01s ssh-add -l: The agent has no identities.
  driver list: rc=0 LIST 0
== 2b. lifetime 0 (and 1,000,000,000)
driver add ed life=0: rc=2 ERR MI06-17 | The time limit must be at least 1 minute. | Lifetime
driver add ed life=1000000000: rc=2 ERR MI06-17 | The time limit must be at least 1 minute. | Lifetime
  ssh-add -l: The agent has no identities.
== 2d. remove one
driver remove ed: rc=0 REMOVE removed=true
  remove + ssh-add -l took 12 ms; after: [ec256, rsa3072, edp]     (ed gone, the others stay)
driver remove ed again (absent): rc=0 REMOVE removed=false
driver list: LIST 3 (ec256@verify, rsa3072@verify, edp@verify; same fingerprints as ssh-add -l)
== 2e. remove all (with a key another program added)
  ssh-add ec384: rc=0 Identity added: /tmp/v-e9s1/keys/ec384 (ec384@verify)
  before: ec256, rsa3072, edp, ec384 (4 keys)
driver remove-all: rc=0 REMOVE-ALL OK
  remove-all + ssh-add -l took 12 ms; after: The agent has no identities.
[stopped pid=60790]
```

The confirm steps are in section 4.

## 3. AT-H01: keys leave when asked

- **Driver.** `remove`, followed by `ssh-add -l`, took **12 ms** together, against INT-06.24's 1 s. `ssh-add -l` showed the key gone and the other keys still there.
- **Remove all.** Remove all followed by `ssh-add -l` also took 12 ms.
- **Builder's test.** `at_h01_remove_leaves_agent_within_1s` passed.
- **Not here.** The lock that triggers the removals is E9-S2 (T42 to T45).

## 4. AT-H02: the limits really reach the agent

- **Lifetime.** The agent drops the key between 1.01 s and 3.01 s (section 2). `t31` also passed.
- **Confirm, no askpass.** Without an askpass helper the agent refuses the key on use, and a control key without the limit signs. Throwaway agent `main`, signing with only the public key in the folder, so `ssh-keygen` must use the agent:
  ```
  driver add ec256 confirm: rc=0 ADD OK
  sign with ec256 through the agent: rc=255 Signing data failed: agent refused operation
  sign with rsa3072 through the agent: rc=0 Write signature to data.sig
  ```
- **Confirm, with askpass.** With a scripted askpass helper (throwaway agent `askpass`, PID 60912, environment `SSH_ASKPASS`, `SSH_ASKPASS_REQUIRE=force`, `DISPLAY=:0`), the agent asks on every use:
  ```
  askpass exits 0: sign rc=0 signature=made
  askpass exits 1: sign rc=255 signature=none
  askpass exits 0: sign rc=0 signature=made
  askpass log (3 prompts): "Allow use of key ed@verify? Key fingerprint SHA256:tc6CYrObBUi++NQcdzscWE+Y+9pamZOBdX6BYQCUTp0." each time
  ```
- **Under (b).** LD-173 sends keys that ask before each use to Larsal's own agent, not to the system agent. That part of AT-H02 is E9-S2 (T51, T53, T57). The client still sends the limit correctly when asked (T29).

## 5. Key handling

`bash scripts/keys.sh`, release driver:

```
ed        ED25519      enc=false SHA256:tc6CYrObBUi++NQcdzscWE+Y+9pamZOBdX6BYQCUTp0 MATCH | UNLOCK OK ms=0
edp       ED25519      enc=true  SHA256:nNXWUMNGMfLFSoL28Js0qqoKNR4X9/6kPlq7HtqxDt0 MATCH | UNLOCK OK ms=194
ec256     ECDSA        enc=false SHA256:OiD+JluhcF7trvbRl6sKzT9++o7DDAL0O2FRnTIkFVU MATCH | UNLOCK OK ms=0
ec256p    ECDSA        enc=true  SHA256:77m8Ocqk4fVbNHngmYV6VBy6flsTTKgn1mhLjPzw+Oc MATCH | UNLOCK OK ms=194
ec384     ECDSA P-384  enc=false SHA256:bpZJlBgrQBYtLvrvR/BC5Zo1KM0zAK4lctASk+RkFNs MATCH | UNLOCK OK ms=0
ec384p    ECDSA P-384  enc=true  SHA256:YlZZIppn9Mjj5ts6aOkK+nJU4N15mdZzy/hnTzJCHnY MATCH | UNLOCK OK ms=194
ec521     ECDSA P-521  enc=false SHA256:+SbRoR0NYpjoXjYelRiIdWj0cmLnnUnEMZHdT6FN6Ic MATCH | UNLOCK OK ms=0
ec521p    ECDSA P-521  enc=true  SHA256:D4rIUWPd8dvM1MUPhk/gS8eL0oQ1A+1CYANtm2ogd+I MATCH | UNLOCK OK ms=195
rsa2048   RSA 2048     enc=false SHA256:iq6+UAvj6wt0De2K2X3saFlRqB4XiXIgpjOEtDYDIIU MATCH | UNLOCK OK ms=0
rsa2048p  RSA 2048     enc=true  SHA256:Hkc9hTprCwc988kC3CswyOvMbqDZUvWWSx7Q3McgjkI MATCH | UNLOCK OK ms=195
rsa3072   RSA 3072     enc=false SHA256:tedikKtEfoBtVSco2BtWhn33zzg4CS4Dlww6EtWWZWY MATCH | UNLOCK OK ms=0
rsa3072p  RSA 3072     enc=true  SHA256:WHlAYRaNVxpRfH72IwIWJVDgfmb0SAJnWTcJoGoz5eo MATCH | UNLOCK OK ms=195
rsa4096   RSA 4096     enc=false SHA256:iOJMsY5elsLudnBNg8tsjF6eI2l2WL/g/uFg/iIjKfg MATCH | UNLOCK OK ms=0
rsa4096p  RSA 4096     enc=true  SHA256:V5q5ztioQt8DBOUalMqCj6x2Q/wV3SiBr/4Tl4UHl6k MATCH | UNLOCK OK ms=195
```

- **Fingerprints.** MATCH means the fingerprint equals both `ssh-keygen -l -E sha256 -f <key>.pub` and the same command on the private file.
- **Through the real agent.** All 14 keys were added through the driver (the protected ones with the passphrase). `ssh-add -l` listed 14, and every `ssh-keygen` fingerprint was among them. The driver's own list found all 14 blobs (0 unknown).
- **Wrong passphrases.**
  - `wrong-pass` gives `ERR MI06-15 | The entry's password does not unlock this key.`
  - An empty passphrase gives `MI06-14` in 0 ms.
- **Other ciphers.** aes256-gcm and chacha20-poly1305 unlock.
- **DSA and older forms.** All exit 2:
  - `dsa-openssh` (OpenSSH format): `ERR MI06-12 | dsa-openssh is a DSA key, which OpenSSH no longer supports. Use an Ed25519 key instead.`
  - `old-dsa-pem`, `old-rsa-pem`, `old-rsa-pem-enc`, `old-ec-pem`, `old-pkcs8` (`PRIVATE KEY`), `old-pkcs8-enc` (`ENCRYPTED PRIVATE KEY`): each `ERR MI06-11 | <name> uses an older key format. Convert a copy with "ssh-keygen -p -f <path>", then use the converted file.`
  - A text file gives MI06-10, an empty file MI06-09, and 1,048,577 bytes MI06-08.
- **Rounds.**
  - The 1,001-round key (made by `ssh-keygen -a 1001`), 3 runs: each `UNLOCK ms=0`, `ERR MI06-16 | This key's passphrase protection uses 1001 rounds; Larsal allows at most 1,000. ...`, and `real 0.00` for the whole process.
  - The 1,000-round key: `UNLOCK OK ms=8229`, at the cap and accepted.
- **Leak check** (my own, not asked for): read plus unlock, 200,000 times in one process. RSS stayed flat:
  - Ed25519 8,720 to 8,864 KB;
  - RSA 4096 8,720 to 8,944 KB;
  - P-521 8,720 to 8,912 KB;
  - DSA 8,720 to 8,944 KB;
  - text 8,528 to 8,592 KB.

## 6. Hostile agent replies

`python3 -I scripts/hostile.py`. A fake agent socket (Python, my user) served each case once. The driver ran `list`, `add` (message 25, lifetime 60), `remove` and `remove-all` against each case, with a 10 s hang limit.

| Reply | All 4 requests |
|---|---|
| Accepts and never answers | MI06-02 Timeout, 2.01 to 2.02 s |
| Never accepts (the connection waits in the queue) | MI06-02 Timeout, 2.01 to 2.02 s |
| Header 100, then 1 byte every 0.4 s | MI06-02 Timeout, 2.01 s (one deadline for the whole reply) |
| Closes at once; reads, then closes; header 10 with 3 bytes, then close | MI06-02 Closed, 0.01 s |
| Length 0 | MI06-02 Protocol |
| Length 0xFFFFFFFF; length 262,145; a 300 KiB reply sent in full | MI06-02 TooLong, 0.01 s |
| Message 99; message 14 | MI06-02 Protocol |
| 12 with count 1,000,000 in 9 bytes; 12 with blob length 0xFFFFFFF0 | MI06-02 Protocol (list); same for the others |
| 12 with a non-UTF-8 comment | list: 1 key (lossy comment); others: MI06-02 Protocol |
| 12, then 4 KiB of junk on the same connection | list: 0 keys (only one reply read); others: MI06-02 |
| Exactly 262,144 bytes (12, count 0, padding) | list: 0 keys (the bound is inclusive); others: MI06-02 |
| Reply 5 | list: MI06-02; add: MI06-04 with "It may not accept a time limit."; remove: `removed=false`; remove all: MI06-21 |
| Reply 6 | list: MI06-02; add, remove and remove all: success |

- **Random replies.** 300 random replies per request (body 0 to 600 bytes, length field random in 30% of cases): every run exited 0 or 2.
  - list: 300 MI06-02;
  - add: 245 MI06-02, 28 MI06-04, 27 OK;
  - remove: 251 MI06-02, 22 not held, 27 removed;
  - remove all: 244 MI06-02, 32 MI06-21, 24 OK.
- **Result.** `BAD cases: 0; slowest run 2.02s`. No exit code 101 and no "panicked" in any output.
- **Socket rules** (extra): a symlink to a live socket, a regular file and a missing path each gave MI06-03. No connection reached the real socket (`accept` gave WouldBlock), and the file stayed unchanged.

## 7. Fuzz target `ssh_key_read`, 120 s

- **Corpus.** The 16 seeds were copied to `/tmp/v-e9s1/fuzz/corpus`.
- **Build.** `cargo +nightly fuzz build ssh_key_read --target-dir /tmp/v-e9s1-target/fuzz`: 52.9 s.
- **Run.** `cargo +nightly fuzz run ssh_key_read --target-dir /tmp/v-e9s1-target/fuzz /tmp/v-e9s1/fuzz/corpus -- -max_total_time=120 -artifact_prefix=/tmp/v-e9s1/fuzz/artifacts/` exited 0:
  ```
  #17	INITED cov: 1568 ft: 1934 corp: 15/10233b exec/s: 0 rss: 49Mb
  #9116923	DONE   cov: 2368 ft: 3618 corp: 495/177Kb lim: 4096 exec/s: 75346 rss: 652Mb
  Done 9116923 runs in 121 second(s)
  ```
- **Result.** No crash, 0 artifacts in `/tmp`, and `fuzz/artifacts/ssh_key_read` in the project still empty. The corpus copy grew to 529 files.
- **RSS.** The 652 MB is the sanitizer's own memory. The plain-build leak check in section 5 is flat.

## 8. `pipe.rs` (LD-179)

`cargo test -p larsal-platform pipe` and `cargo test -p larsal-platform --release pipe` both pass:
`macos::pipe::tests::a_write_to_a_closed_socket_is_an_error_not_a_signal ... ok`, 1 passed. Its child `broken_pipe_child` is ignored when run on its own, by design.

- **What the test proves.** The control child, without the call, must die by SIGPIPE; the guarded child must exit 0.
- **Product call.** `crates/larsal-ffi/src/start.rs:232` calls `ignore_broken_pipes()` in `harden()`, at the start of the window app.

## Open points (none blocks E9-S1)

1. **T26, other user's socket.** It needs a root fixture in CI, which does not exist yet. The path, link, file, length and missing cases pass, but the `getpeereid` refusal of a socket owned by another user is not proven on this Mac.
2. **V-INT06-3, the macOS system agent.** Not run: that agent is the owner's own, which this brief forbids. It waits for the owner's go.
3. **Timing in D-INT06-3.** In Larsal's release build, 24 rounds take 0.195 s and 1,000 rounds 8.2 s. The card's figures, 0.15 s and 6.2 s, were measured with `ssh-keygen -y`. The cap holds; the card's worst-case number could say 8 s.
4. **Not in this story.** AT-H01's lock path and the confirm half of AT-H02 under (b) belong to E9-S2.
5. **LD-183.** INT-06 now carries both LD-183 points in its MI06-03 and MI06-10 rows, which closes the Checker's note.

## CPU

About 12 CPU-minutes in total. The longest single run was the 120 s fuzz run (121.8 s wall, 117 s user). The fuzz build used 224 s of CPU and the first test build 100 s. No run came near 30 minutes.

## Clean-up

- Both throwaway agents were stopped by their PIDs (60790, 60912).
- `/tmp/v-e9s1` (demo keys, driver, scripts, fuzz copy) and `/tmp/v-e9s1-target` were deleted after the runs.

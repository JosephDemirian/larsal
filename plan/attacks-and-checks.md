# Attacks and checks

Every attack here becomes a test where it can be automated, and a scripted manual run where it can't. Red team agents run them with demo data only and file findings. A story that touches an area runs that area's attacks before it is Done.

## Attack catalog

### AT-A: Vault file attacks

| ID | Attack | How | Passes when |
|---|---|---|---|
| AT-A01 | Wrong credentials | Wrong password, wrong key file, missing hardware key, each alone and combined | Open fails with the wrong-key message, nothing is decrypted, every wrong case gives the same message |
| AT-A02 | Header tampering | Flip each header byte, one at a time | Every file is rejected; no panic |
| AT-A03 | Payload tampering | Flip, cut, swap, repeat and append payload blocks | Rejected as damaged; no partial data shown |
| AT-A04 | Truncation | Cut the file at every 1 KB step | Rejected; no panic |
| AT-A05 | KDF cost bomb | Argon2 memory set to 4 TiB, iterations to 2^63, parallelism to 2^24 | Refused before any work, or the user is asked with the cost shown |
| AT-A06 | Decompression bomb | A small payload that inflates to many GB | Stopped at the limit; memory stays flat |
| AT-A07 | XML attacks | DOCTYPE, entity expansion, external entities, 100,000 nesting levels, a 1 GB text node | Rejected without memory blow-up |
| AT-A08 | Hostile document inside valid encryption | Made with a demo key: duplicate ids, group cycles, missing fields, bad attachment refs, huge counts | Handled safely; the user sees a clear message; nothing crashes |
| AT-A09 | Downgrade | A file that claims an old version or weak KDF settings | A save keeps or raises the security level, never lowers it without the user's choice |
| AT-A10 | Fuzzing | cargo-fuzz on every parser, 24 hours per target | Zero crashes, zero hangs over 10 seconds, memory under the limit |
| AT-A11 | Differential fuzzing | The same mutated files go to our reader and the reference CLI | Both reject, or both accept with the same content. Known differences where Larsal is stricter (LD-84): a broken gzip trailer at a 16 KiB boundary, and a version 4 file with its final block removed; a version 3 header with inner stream id 3 (FMT-02.20) and a protected value holding a `00` byte, which Larsal keeps whole (FMT-09.15; LD-149) |
| AT-A12 | Key file attacks | 1 GB key file, malformed structured key file, wrong check value | Safe, clear errors |

### AT-B: Crypto checks

| ID | Check | How | Passes when |
|---|---|---|---|
| AT-B01 | Known answers for primitives | RFC and NIST test vectors | All pass |
| AT-B02 | Known answers for whole files | Demo vaults made by the reference CLI | Every one opens with the expected content |
| AT-B03 | Fresh randomness | Save 10,000 times | No master seed, IV, nonce, salt or field stream key repeats |
| AT-B04 | One random source | Code search plus review | Only `larsal-crypto::random` produces random values |
| AT-B05 | Constant time | Review plus a timing test on MAC checks | No timing difference beyond noise |
| AT-B06 | KDF cost is real | Time an unlock with default settings on this Mac | At least the target time; stored settings equal the ones used |
| AT-B07 | No padding oracle | Bad padding versus wrong key | The cipher API gives one error for any decrypt failure; in files, padding is checked only after integrity passes (spec/decisions.md LD-04); no timing difference beyond noise |

### AT-C: Memory attacks

| ID | Attack | How | Passes when |
|---|---|---|---|
| AT-C01 | Secrets after lock | On a debug build with attach allowed, dump the app's memory after lock and search for the demo master password, a demo entry password and the derived key | None found |
| AT-C02 | Secret after Hide | Show a password, hide it, switch entries, dump memory | The value is not found |
| AT-C03 | Debugger and core dumps | Attach a debugger to a release build; force a crash | Attach refused; no core dump written |
| AT-C04 | Crash reports | Force a panic with a vault open | The crash report holds no secret |
| AT-C05 | Swap | Inspect memory regions holding keys | Key pages are locked in RAM where the spec says so |
| AT-C06 | Logs | Run the full QA script at the highest log level | Logs hold no demo secret |

### AT-D: Clipboard and screen

| ID | Attack | How | Passes when |
|---|---|---|---|
| AT-D01 | Clipboard manager | Run a clipboard history app, copy a password | The history does not store it |
| AT-D02 | Timed clear | Copy, wait for the timeout; copy, then copy something else before the timeout | Our value is cleared; the user's newer content is left alone |
| AT-D03 | Clear on lock and quit | Copy, then lock; copy, then quit | Clipboard cleared both times |
| AT-D04 | Screen capture | With protection on, try each capture path: the screenshot tool, screen recording (ScreenCaptureKit) and screen sharing | `sharingType = .none` is set on every window, and the result for each capture path (blank, left out, or shown) is recorded. Apple calls `.none` legacy and says not to rely on it, so a shown window is recorded, not failed (SC-05) |
| AT-D05 | Keystroke tap | A demo event-tap logger runs while the master password is typed | It receives no keystrokes |

### AT-E: Screen layer and the Swift–Rust boundary

| ID | Attack | How | Passes when |
|---|---|---|---|
| AT-E01 | Text injection | Markdown, link and control-character text in every text field: title, username, URL, notes, tags, attribute names and values, attachment names, group names, vault name | Shown as plain text: no link, no formatting, nothing runs |
| AT-E02 | Dangerous links | `javascript:`, `file:`, `data:` and unknown schemes in URL fields | The URL opener refuses them; the app never opens them |
| AT-E03 | Boundary abuse | Call every `larsal-ffi` export with hostile arguments (huge strings, ids from another vault), after lock, and from two threads at once | A typed error comes back; no panic; no secret in the error |
| AT-E04 | Retired | There is no web engine (LD-156) | Replaced by: `otool -L` lists no WebKit, plus E6-S7's network capture |
| AT-E05 | Retired | There are no developer tools to open (LD-156) | Covered by AT-C03 and AT-J05 |
| AT-E06 | Drag and drop | Drop files and links on the window | Nothing opens or runs, except our attachment drop target and a vault-file drop, which only shows an unlock screen (APP-09.26, LD-153) |
| AT-E07 | Secrets in the screen | Check the Swift view state and the process memory after Hide and after lock (one process now) | No secret remains |
| AT-E08 | Local listeners | List open ports and sockets of the app | No local web server, no open port; the listeners are the instance socket of APP-09.14, with the SSH agent on (S-SSH-01) Larsal's own agent socket of INT-06.32, and, with the browser bridge on, the bridge sockets of INT-01 (the host socket and the Safari app-group socket), each Unix, owner-only, same user (LD-191) |

### AT-F: Browser bridge

| ID | Attack | How | Passes when |
|---|---|---|---|
| AT-F01 | No association | Send a request from an unknown client | Refused |
| AT-F02 | Replay | Resend an old encrypted message | Refused |
| AT-F03 | Wrong keys | Swap or corrupt keys | Refused |
| AT-F04 | Silent association | Try to associate without the user's confirm | Refused |
| AT-F05 | Lookalike sites | Lookalike letters, punycode, attacker subdomains, http instead of https, other ports | No fill |
| AT-F06 | Foreign frames | A credential request from a frame of another site | Handled per spec INT-02; no silent fill |
| AT-F07 | Flood | Thousands of requests per second | The app stays responsive; no secret in any error |
| AT-F08 | Wrong passkey | Ask for another site's passkey | Refused |
| AT-F09 | Invisible extension UI | A test page hides or covers the in-page menu while it asks for a click: opacity 0 on the host, `html` or `body`; `filter:opacity(0)`; a full-page overlay with `pointer-events:none`; its own popover; an element added after the host (Toth's methods, spec/research/browser-and-web.md B10; INT-11.18, INT-11 T38 and T67) | No fill and no request to Larsal; the menu closes, the badge shows `!` and the next popup shows MI11-63 (INT-11.18, LD-274) |

### AT-G: Auto-Type

| ID | Attack | How | Passes when |
|---|---|---|---|
| AT-G01 | Lookalike window | Another program shows a window with the target's title | No typing without the user's confirm, per spec INT-05 |
| AT-G02 | Focus change | Switch windows during typing | Typing stops |
| AT-G03 | Hostile sequence | Huge repeat counts, recursive references | Bounded; nothing hangs |

### AT-H: SSH agent and hardware keys

| ID | Attack | How | Passes when |
|---|---|---|---|
| AT-H01 | Keys after lock | Lock the vault, list the agent's keys | Keys gone within 1 second |
| AT-H02 | Key limits | Add a key with lifetime and confirm settings | The agent shows both limits |
| AT-H03 | Key pulled out | Remove the hardware key during unlock and during save | Clear error; the vault file stays intact |
| AT-H04 | Wrong hardware key | Use another key | Same result as a wrong password |

### AT-I: Disk and sync

| ID | Attack | How | Passes when |
|---|---|---|---|
| AT-I01 | Crash during save | Kill the app at random points during save, 1,000 runs | The file is always the old or the new version, never broken |
| AT-I02 | Disk full | Save on a full disk image | Old file intact; clear error |
| AT-I03 | No permission | Save into a read-only folder | Clear error; nothing lost |
| AT-I04 | Link tricks | Symlinks and hard links at the vault path | Behavior per spec APP-05; never writes to an unexpected file |
| AT-I05 | Two writers | Two windows edit one vault; cloud conflict copies | A merge keeps every entry of both sides, except an entry that the same vault's deleted-objects list removed after its last change (FMT-15.11, LD-265) |
| AT-I06 | File permissions | Create new vaults, backups and exports | Owner-only permissions (0600) |
| AT-I07 | Planted sync commands | A demo vault, and a merge source whose custom data wins, carry remote sync commands that create a marker file; open, merge, save, then pick the sync (INT-09) | Nothing runs on open, merge or save; picking the sync first shows the full commands (INT-09.20); Cancel runs nothing and leaves no marker or temp folder; the settings page's Test shows the commands first too, and an Apply that changed only the name or a timeout approves nothing (INT-09.5 to INT-09.7) |
| AT-I08 | Hostile sync commands and downloads | Commands that never end, start children, ignore SIGTERM, flood output, wait for input, or write a non-vault file, a KDF cost bomb, a decompression bomb or another vault (INT-09) | Each run ends within its timeout plus 2 s with every process of its group gone; Larsal's memory stays flat; the vault is unchanged; no temp folder is left |

### AT-J: Supply chain and build

| ID | Check | How | Passes when |
|---|---|---|---|
| AT-J01 | Known vulnerabilities | `cargo audit` | Zero |
| AT-J02 | Policy | `cargo deny check` | Licenses on the allowlist, crates.io only, no duplicate crypto crates, no OpenSSL |
| AT-J03 | New dependency review | Maintainers, `unsafe` count, build scripts, download count, last release | Lead and a Checker approve in writing |
| AT-J04 | Reproducible build | Two clean builds | Same binary hash, or every difference explained |
| AT-J05 | Signing | Gatekeeper check of the release: `codesign -d --entitlements -`, `codesign -dv`, `spctl -a -vv`, `stapler validate` | Signed, notarized and stapled, hardened runtime flag on, no `get-task-allow` |
| AT-J06 | Names and secrets | Name guard and a secret scan of the whole folder | Clean |

### AT-K: Mac app behavior

| ID | Check | How | Passes when |
|---|---|---|---|
| AT-K01 | Lock events | Screen lock, sleep, user switch, idle timer, each on this Mac | Every one locks |
| AT-K02 | Biometry change | Add a new fingerprint | Quick unlock stops until the password is typed again |
| AT-K03 | Quick unlock off | Turn the setting off, or close the vault | Its Keychain item is gone |
| AT-K04 | Expired warning | Unlock a demo vault with expired entries | Warning shown per spec |
| AT-K05 | Looks like the mockup | Screenshots of every screen next to design/mockup.html | Matches, or each difference approved by the owner |
| AT-K06 | VoiceOver | Use unlock, list, detail and editor with VoiceOver | Every control is named and usable |

### AT-L: Hostile sync server

| ID | Attack | How | Passes when |
|---|---|---|---|
| AT-L01 | Rollback and replay | A test server serves a lower version, the same version with other bytes, and an old file under a new version number (SYN-03.7) | The first two are refused with `MSG-SYNC-ROLLBACK` and nothing is merged or uploaded; the third is merged with `MSG-SYNC-WENT-BACK` and no newer entry, deletion or KDF setting is lost |
| AT-L02 | Lost update | Two clients PUT on one version at once; a PUT with no precondition, or with `If-Match: *` (SYN-01.6, SYN-02.4) | One gets 412 and its next try merges, so both changes survive; no precondition and `If-Match: *` get 428 |
| AT-L03 | Oversized and slow requests | A body one byte over FMT-01.31's limit; a request line of 9 KiB; a request head of 33 KiB; a body that sends one byte every 61 s; a TLS ClientHello cut off halfway; a connection left idle after one reply (SYN-01.10, SYN-01.11) | 413 before the body is read; 414 for the request line and 431 for the head, each with no body; the slow body's connection closes after the first 60 s gap, the cut-off handshake's after 30 s with no HTTP reply, and the idle one 30 s after its reply; nothing stored |
| AT-L04 | Planted copy under an old key | A server copy under a password this Mac retired, with `MasterKeyChanged` in the future and deletions (SYN-03.9, MOD-11.31) | `MSG-SYNC-OLD-KEY` before any merge; no key, deletion or metadata taken; nothing changes without the user's click |
| AT-L05 | Swapped certificate | A pinned server presents another certificate, also one macOS trusts (SYN-01.2) | No request is sent; `MSG-SYNC-CERT-CHANGED` |
| AT-L06 | Offline guessing | A test gets every row and file of the server and 1,000 demo passwords that include the demo vault's master password and the demo account password (SYN-02, SYN-06) | No vault, account blob or key-file wrap opens; nothing on the server lets a guess be checked |
| AT-L07 | Sign-in replay and forgery | Reuse a nonce; sign for another origin or device id; change one byte; sign in after a revoke (SYN-04.4, SYN-04.8) | 401 every time, with the same body |
| AT-L08 | Password leaves the Mac | A test proxy records every request of a full sign-up, sync and approval run (SYN-03.14, SYN-04.10) | No password, no value made from one other than the account blob of SYN-06.4, no key-file part, no approval code before the claim, no plain vault content |
| AT-L09 | Hostile replies and parsers | Fuzz every request and reply parser; replies over the limits; malformed JSON; an account blob of version 2 (SYN-01.10, SYN-01.15, SYN-06.4) | No crash, hang or allocation over the limits; the blob is refused before any KDF runs |
| AT-L10 | Relay in the middle of the code compare | A test relay swaps keys at each step, or sends a second commitment (SYN-05) | The codes differ and nothing is sealed or pinned; a second commitment is refused |
| AT-L11 | Server text on screen | Error bodies with markup and long text (SYN-01.9) | Larsal shows only its own words |
| AT-L12 | Swapped account keys, seal or device | A test server returns other account keys, replaces the sealed account secret, or registers a device without the identity signature (SYN-06.6, SYN-06.11) | `MSG-ACCOUNT-KEYS-CHANGED`; the seal is refused; the device gets no account secret |
| AT-L13 | BW01, forced enrolment | When a member accepts an invite, a test server swaps the inviter's identity key in the compare and adds its own enrolment key to every reply (SHR-03.7, SHR-03.8) | The codes differ and nothing is signed, wrapped or pinned; no request from the invitee holds a wrap, anything sealed, or a private key or secret of the invitee's, wrapped or plain; unknown reply fields are ignored |
| AT-L14 | BW02, rotation to a server key | During a removal, a test server lists an extra recipient, serves another X25519 key for a remaining member, and serves a wrap of its own key for the new epoch (SHR-01.9 to SHR-01.11, SHR-04.4) | The rotating Mac wraps only to keys of its verified list; the injected recipient gets nothing; the server's wrap fails the signer check (a manager of the vault) or the key check and is deleted by its recipient; every member's new key matches the remove entry's key check |
| AT-L15 | BW08, injected group | A test server makes its own group (a self-signed create, an add of the victim's account, a wrap of a key it chose) and offers it to the victim and to a new Mac of the victim's account (SHR-02.10, SHR-01.10) | The group is never shown, opened, wrapped to or written to on either Mac; no upload, entry or wrap for it |
| AT-L16 | BW09, group overwrite | Right after a member makes a group, a test server replaces the create entry's keys, the first vault's key check, or the wrap for the creator's second Mac (SHR-02.6, SHR-01.4, SHR-01.10) | Every changed entry is refused by every client; the second Mac refuses the wrap; the group keeps the creator's keys |
| AT-L17 | LP07, swapped recipient key | A test relay replaces the invitee's X25519 or identity key in the compare; a test server later serves a member's entry with another X25519 key (SHR-03.7, SHR-02.9, SHR-02.11) | The codes differ and nothing is wrapped; the changed entry gives MSG-GROUP-BAD-LIST, MSG-GROUP-FORK or MSG-GROUP-KEY-CHANGED; no wrap goes to the swapped key |
| AT-L18 | DL02, swapped sharer key | A test relay replaces the inviter's identity key in the compare (SHR-03.7, SHR-03.8) | The codes differ; the invitee pins nothing and accepts no add entry signed by the swapped key |
| AT-L19 | Member-list rollback | A test server serves an older head, drops entries from the end, or serves wraps and versions of an older epoch or head after a newer one (SHR-02.9, SHR-03.12 step 6) | MSG-GROUP-ROLLBACK or MSG-GROUP-BAD-VERSION; the Mac's state, keys and vault are unchanged; nothing uploaded; the next honest reply is accepted |
| AT-L20 | Member-list fork | Two Organizers sign entries on one head; a test server keeps both, shows each to different members, and each then signs a further entry on its own branch; the server serves one member the other's entries and a version the other uploaded. Separately, it holds a remove entry back from one member and keeps the two members' uploads apart (SHR-02.9, SHR-02.12, SHR-02.13) | The other branch's entry at the Mac's own seq (a sibling on its prev) gives MSG-GROUP-BAD-LIST and changes nothing; the entry built on it, or a version that names the other branch's head, each signed by a current member, gives MSG-GROUP-FORK, the Mac stops using the group, and its vaults still open on it; the held-back member refuses the other's uploads with MSG-GROUP-BAD-VERSION; after both members pick Sync now, the two branches show different list codes, and the held-back member shows a lower entry number than the other |
| AT-L21 | Removed member keeps access | After a removal or a leave, a test server keeps serving the person, accepts their uploads signed under an old head, and serves those uploads to the others (SHR-04.4, SHR-04.5, SHR-03.12 step 4) | The person holds no key of the new epoch and opens no later version; every other Mac refuses their uploads; the honest server answers them 403 |
| AT-L22 | Forged fork | A test server with no member key sends: a reply head with the Mac's seq and another hash; an entry with another prev and a bad signature; an entry a removed member signed on an old head; a member's entry of another group at this group's next seq; a member's entry it answered 412 falsely, after the member signed that seq again and the Mac took the second entry; an honest version with an edited Upload-List-Head; and an honest version whose head it holds back (SHR-02.9, SHR-02.12, SHR-03.12) | Only MSG-GROUP-BAD-LIST or MSG-GROUP-BAD-VERSION, never MSG-GROUP-FORK; nothing changes; the group stays in use and the next honest reply is accepted |

## Check gates

| Gate | What | Tools | When | Who |
|---|---|---|---|---|
| G1 Static | Format, lints, name guard, `unsafe` count | `rustfmt`, `clippy`, `scripts/check-names.sh`, `cargo-geiger`; `swift format lint --strict`, `swiftlint lint --strict` | Every build | Builder runs, Checker confirms |
| G2 Tests | Unit and property tests | `cargo test`, `proptest`; `scripts/build-core.sh`, then `xcodebuild test` without `LarsalUITests`, warnings as errors | Every story | Builder |
| G3 Known answers | Standard vectors and reference-made demo vaults | `cargo test` | Every E2 and E3 story, and nightly | Verify |
| G4 Interop | Our saves open in the reference CLI with the same export; reference vaults open in ours | `scripts/interop.sh` with `REF_CLI` | From E3 on | Verify |
| G5 Fuzzing | 10 minutes per target per story; 24 hours per target per sprint | `cargo fuzz` | Every parser story; each sprint | Red team |
| G6 Review | Line-by-line review against the Rust rules and security rules. Two Checkers for crypto, format, `unsafe` and secret handling. | Reading | Every story | Checker |
| G7 Attacks | The attack groups for the area | This catalog | Security-relevant stories | Red team |
| G8 Mac QA | Scripted walk through the real app with demo vaults; screenshots | The `LarsalUITests` suite (XCTest UI testing), computer use or UI scripting on this Mac; needs a logged-in screen, so not in `check.sh` | Every screen story | Mac QA |
| G9 Parity | Every parity row has proof | [security.md](security.md) | End of each epic, and E13 | Verify |
| G10 Release | AT-J01 to AT-J06, zero open Critical or High findings, owner sign-off | All | E14 | Lead |

## Findings

| Severity | Meaning | Rule |
|---|---|---|
| Critical | Secret leak, broken crypto, vault damage, code execution | All work in the area stops until fixed and re-tested |
| High | A protection is missing or can be bypassed | Blocks the epic |
| Medium | A defense-in-depth gap | Fixed in the sprint, or the owner accepts it in writing |
| Low | Hygiene | Backlog |

Findings go to `security/findings.md`, one row each: ID, date, severity, area, steps to reproduce with demo data, status, fix proof. The agent who found a problem is never the one who fixes it.

## The final verification fleet (E13)

| Agents | Job |
|---|---|
| One per parity group (SF, SR, SC, SD, SG, SI, SN, SB) | Re-read the reference source for that group, confirm our behavior, attach proof to each row |
| One per attack group (AT-A to AT-K) | Run every attack in the group, file findings |
| Two code reviewers | Read every `unsafe` block, every crypto call, every place a secret type is converted or exposed |
| One Mac QA | Run the full QA script on a release build |
| The lead | Collects results, files findings, has fixes made, re-runs the failed checks |

Exit: every parity row `verified` with proof, every attack passed, zero open Critical or High findings, a short report for the owner.

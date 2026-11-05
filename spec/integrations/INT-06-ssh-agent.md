# INT-06 SSH agent

Status: reviewed (LD-173, LD-175)
Epics: E9-S1 (agent client, limits), E9-S2 (keys from attachments and files, unlock and lock); the editor page and the detail row are built with E9-S2 on top of E5-S5; INT-06.31 to INT-06.36 (Larsal's own agent) are built in E9-S2 too (decided: spec/decisions.md LD-173, no new story)
Parity rows: SI-07, SD-05, SR-16, SR-07, SR-12 (the "SSH key" file dialog folder only)

## What it does

An entry can carry an SSH private key: as one of its attachments, or as a path to a key file on this Mac. A small settings attachment in the same entry says how Larsal uses that key with an SSH agent: add it when the vault unlocks, remove it when the vault locks, ask before each use, remove it after a time limit.

Larsal does not sign anything for normal keys. It is a client of the agent that already runs on the Mac: it decrypts the key in memory, sends it to the agent with the OpenSSH agent protocol (add with a lifetime and a confirm limit, remove one, remove all, list), and wipes its own copy. Programs such as `ssh` and `git` then use the key through the agent. On macOS that agent is the system `ssh-agent`, started by launchd on demand; its socket path reaches Larsal through `SSH_AUTH_SOCK`.

For keys marked "Ask before each use" the system agent cannot ask the user on a stock Mac (observed, see INT-06.37). The locked design shows Larsal's own question instead. Decided (D-INT06-1 (b), LD-173): Larsal runs a small agent inside Larsal for those keys only (INT-06.31 to INT-06.36).

Neighbor cards: FMT-14 (the settings attachment name, stored encoded), FMT-13 and MOD-05 (attachments), MOD-04 (recycle bin), MOD-08 (placeholders in the password), APP-01 (S-SSH-01 to S-SSH-03, the file dialog folder roles), APP-02 (lock steps), APP-03 (clipboard for the public key and fingerprint), APP-06.22 (after-unlock steps), APP-08 (menu items, ⌃H and ⌃⇧H, M08-04), FEA-08 (imports that carry SSH keys), INT-07 (security keys for vaults; not the same thing as SSH keys that live on a security key).

Public standards a Builder needs: the SSH agent protocol (IETF draft-ietf-sshm-ssh-agent, which describes OpenSSH's agent protocol), RFC 4251 (data types: `string`, `mpint`, `uint32`, `byte`, `boolean`), RFC 4253 section 6.6 (public key blobs), RFC 8709 (Ed25519 keys), RFC 5656 (ECDSA keys), RFC 8332 (RSA with SHA-2 signatures). The OpenSSH private key file format and bcrypt-pbkdf are read through the approved `ssh-key` crate.

## Inputs and outputs

**The settings attachment.** Name: the 17 ASCII bytes `4B 65 65 41 67 65 6E 74 2E 73 65 74 74 69 6E 67 73` (stored encoded, name rule; FMT-14). Content: a small XML document (INT-06.1). It is an ordinary attachment in the vault file (FMT-13), so it is kept in history, merged and exported like any other attachment.

**The key.** Either another attachment of the same entry, or a file on disk named by a path in the settings. The private key may be encrypted; then the entry's Password field holds its passphrase.

**The agent.** A Unix domain socket. Path: S-SSH-02 when set, else `SSH_AUTH_SOCK` from Larsal's environment. On this Mac (macOS 26.6) launchd gives `/var/run/com.apple.launchd.<random>/Listeners`; older macOS releases used `/private/tmp/com.apple.launchd.<random>/Listeners` (the mockup's example). The random part changes at every login.

**Larsal settings** (APP-01): S-SSH-01 `ssh.enabled` (off), S-SSH-02 `ssh.socket_override` (empty), S-SSH-03 `ssh.sk_provider_override` (empty).

**Outputs.** Messages to the agent; the "Loaded" state on the detail view and the editor page; the public key line and fingerprint (not secret); the messages of this card.

**Limits** (Larsal's own unless marked as the reference's):

| Limit | Value | Rule |
|---|---|---|
| Key file or key attachment size | 1 MiB (1,048,576 bytes); the reference has it for files only | INT-06.5 |
| Settings attachment size | 64 KiB | INT-06.2 |
| bcrypt-pbkdf rounds in an encrypted key | 1 to 1,000 (D-INT06-3) | INT-06.9 |
| Lifetime | 1 to 999,999,999 seconds stored (the reference's spin box maximum); the editor control steps 1 to 1,440 minutes | INT-06.20 |
| Agent reply size | 262,144 bytes (256 KiB, the OpenSSH agent's own message limit) | INT-06.14 |
| Agent connect plus reply time | 2 seconds per request | INT-06.14 |
| Socket path length | 103 bytes (the macOS Unix socket path limit is 104 bytes with the final zero) | INT-06.13 |
| Question dialog | 60 seconds, then Deny | INT-06.34 |

## Rules

### Entry settings and where the key lives

INT-06.1 **Settings document.** UTF-8 XML. Root element `EntrySettings`. Child elements, each holding text; element names are exact and case-sensitive:

| Element | Type | Default | Meaning in Larsal |
|---|---|---|---|
| `AllowUseOfSshKey` | boolean | false | The editor's main switch "Use this entry's key with the SSH agent" |
| `AddAtDatabaseOpen` | boolean | false | "Add the key when the vault unlocks" |
| `RemoveAtDatabaseClose` | boolean | false | "Remove the key when the vault locks" |
| `UseConfirmConstraintWhenAdding` | boolean | false | "Ask before each use" |
| `UseLifetimeConstraintWhenAdding` | boolean | false | The switch of "Remove the key after" |
| `LifetimeConstraintDuration` | integer, seconds | 600 | The time of "Remove the key after" |
| `Location` | element | | Holds the four elements below |
| `Location/SelectedType` | text | `file` | `attachment` or `file` |
| `Location/AttachmentName` | text | empty | Name of the key attachment |
| `Location/SaveAttachmentToTempFile` | boolean | false | Kept as read, never used (Larsal never writes a key to disk) |
| `Location/FileName` | text | empty | Path of the key file |

INT-06.2 **Reading.**
- Booleans: true when the text starts with `t` or `T`, otherwise false (reference).
- The integer: decimal digits with an optional sign; any other text gives 0 (reference). INT-06.20 decides what Larsal does with a value below 1.
- `SelectedType`: exactly `attachment` selects the attachment; any other value selects the file (reference).
- Unknown elements, at the top level or inside `Location`, are skipped.
- Elements may come in any order; a later duplicate wins.
- Larsal goes further: a settings attachment over 64 KiB, one that is not well-formed XML, one whose root is not `EntrySettings`, or one with a DTD gives "settings cannot be read": the entry has no usable SSH key (INT-06.4) and the editor shows MI06-24. Larsal never changes such an attachment unless the user saves the SSH page (INT-06.3). The reference stops reading at the first XML error and uses what it read so far.

INT-06.3 **Writing.** Larsal writes the settings attachment only when the user saves the entry editor after the SSH page was shown and its values differ from what was read. Then:
- When every value equals its default (INT-06.1), Larsal removes the attachment (reference).
- Otherwise Larsal writes this layout, UTF-8, LF line ends, two spaces per level, a final LF: the line `<?xml version="1.0" encoding="UTF-8"?>`; the root start tag with the two namespace declarations `xmlns:xsd="http://www.w3.org/2001/XMLSchema"` and `xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`; the six top-level elements in the order of INT-06.1, booleans as `true` or `false`, the integer in decimal; `Location` with its four elements in that order; an empty `AttachmentName` or `FileName` written as an empty element (`<FileName/>`). Text is escaped as XML requires. This is the reference's layout, so the reference reads Larsal's documents.
- Unknown elements read from the old document are not written back (reference).
- `AllowUseOfSshKey` is the main switch. Reference difference: the reference's editor ignores its old value and writes it as "add on unlock or remove on lock". So a document Larsal wrote with the switch on and both boxes off reads in the reference as allowed; a document with the switch off and a box on becomes allowed again after the reference saves the entry (expected interop difference, harmless: the reference only adds on unlock when both are true).
- The settings attachment is never listed in the key picker (INT-06.41) and is managed only through the SSH page; it stays visible and removable in the attachment list (MOD-05). Removing it there in the editor resets the SSH page to the defaults (reference).

INT-06.4 **"The entry has an SSH key".** True when all hold: S-SSH-01 is on; the entry is not in the recycle bin (Larsal goes further for menus: the reference shows its menu items for bin entries too; SD-05); the settings attachment exists and can be read; `AllowUseOfSshKey` is true; and the selected source is set (a non-empty attachment name, or a non-empty file name). This test drives the menu items "Load into SSH Agent" and "Remove from SSH Agent" (APP-08), the detail view row (INT-06.43) and the add on unlock (INT-06.22). Whether the key itself can be read is checked only when it is used or shown.

INT-06.5 **The key source.**
- Attachment: the entry's attachment with exactly the stored name. Missing: MI06-06. The settings attachment itself is never a key.
- File: the stored path, expanded once: a leading `~/` becomes the home folder; then each `$NAME` (a letter, then letters, digits or `_`) becomes the value of that environment variable, or nothing when it is unset. Larsal expands in one pass, left to right; text produced by an expansion is not expanded again. Reference difference: it repeats until no `$NAME` is left, so a variable whose value contains its own name never ends. `${NAME}` and `%NAME%` are not expanded (reference). A relative result is taken from the folder of the vault file (reference). The file is read when the key is used or shown, never cached, never written.
- Both: more than 1 MiB gives MI06-08 before anything is parsed; zero bytes gives MI06-09; a file that cannot be opened (missing, a folder, no permission) gives MI06-07.

INT-06.6 **Key forms Larsal reads** (D-INT06-2).
- The OpenSSH private key format (PEM label `OPENSSH PRIVATE KEY`, content starting with the 15 bytes `openssh-key-v1` and a zero byte), unencrypted or encrypted. `ssh-keygen` writes this form by default since OpenSSH 7.8 (2018).
- Key types: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `ssh-rsa`, `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`. These are the reference's types except DSA.
- `ssh-dss` (DSA): MI06-12. OpenSSH 10.0 removed DSA; the reference still reads it.
- The older PEM forms (labels `RSA PRIVATE KEY`, `DSA PRIVATE KEY`, `EC PRIVATE KEY`), PKCS#8 (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`) and PuTTY files: MI06-11. Reference difference: it reads `RSA PRIVATE KEY` and `DSA PRIVATE KEY`, unencrypted or encrypted with AES-128-CBC or AES-256-CBC through the MD5-based key derivation; it refuses `EC PRIVATE KEY`, PKCS#8 and PuTTY.
- Anything else, or a broken file: MI06-10.
- A file may list several keys; Larsal uses the first, as the reference does (`ssh-keygen` always writes one).

INT-06.7 **The public part.** The OpenSSH format stores the public key outside the encrypted part, so Larsal shows the type, the fingerprint and the public key line without the passphrase.
- Fingerprint: `SHA256:` followed by the SHA-256 of the public key blob in standard base64 without `=` padding, as `ssh-keygen -l` prints. Larsal shows only this form. Reference difference: it shows the MD5 form too.
- Public key line: the type name, a space, the blob in standard base64, and, when the comment is known, a space and the comment (the `.pub` line `ssh-keygen` writes).
- Type names on screen: `ED25519`, `ECDSA` (with the curve size when it is not 256: `ECDSA P-384`), `RSA` (with the bit length: `RSA 3072`), `ED25519-SK`, `ECDSA-SK`.

INT-06.8 **The comment.** The comment stored inside the private part of the key. When it is empty, Larsal uses `<entry user name>@<attachment name or file name>` (reference). A protected user name (its own flag or the vault's flag) is left out together with its `@`, and an empty result becomes `Larsal key` (LD-213 (2)): no protected value goes into a comment that other programs can list. The comment is not secret: every program that lists the agent sees it. For an encrypted key the comment is known only after the key is decrypted (MI06-27 until then).

INT-06.9 **Encrypted keys.**
- The passphrase is the entry's Password field after placeholders and references are resolved, as Copy Password resolves them (MOD-08). Reference difference: it uses the raw field text, so a password that is a reference to another entry never unlocks the key in the reference.
- An empty passphrase for an encrypted key: MI06-14, nothing else tried.
- KDF `bcrypt` with its salt and round count from the key file. The round count must be 1 to 1,000 (D-INT06-3), checked before any work: else MI06-16. Measured on this Mac (Apple M4 Pro) with `ssh-keygen -y`: 24 rounds (the `ssh-keygen` default in OpenSSH 10.3) take 0.15 s, 1,000 rounds take 6.2 s. The reference has no bound (SI-07, LD-73). Larsal's own build takes about 0.2 s for 24 rounds and 8.2 s for 1,000 (Verify E9-S1, 2026-10-28), so the worst case is about 8 s.
- Ciphers: those the `ssh-key` crate decrypts, at least `aes256-ctr` (the `ssh-keygen` default), `aes128-ctr`, `aes192-ctr`, `aes256-gcm@openssh.com` and `chacha20-poly1305@openssh.com`; others give MI06-13 with the cipher name. Reference difference: it refuses `aes256-gcm@openssh.com` and treats `chacha20-poly1305@openssh.com` as plain ChaCha20, so such keys fail there.
- A wrong passphrase (the two check numbers at the start of the decrypted part differ, or the authentication tag fails): MI06-15.
- Decryption runs off the main thread. The editor never decrypts by itself; decryption happens only for an add (INT-06.22, INT-06.27) and for Larsal's own agent (INT-06.33).

INT-06.10 **Secret handling.** The decrypted private key, the passphrase and every buffer that held them live only in Larsal's secret types in Rust and are wiped right after the add message is sent (or, for Larsal's own agent, when the key leaves it). They never go to logs, error values, crash reports or the screen layer (AGENTS rule 4, SR-07). The screen gets only the type, the fingerprint, the comment, the public key line and the Loaded state.

### Talking to the agent

INT-06.11 **Which agent.** S-SSH-02 when it is not empty after trimming spaces, else `SSH_AUTH_SOCK` from Larsal's own environment, read when each request starts. Neither set: MI06-01, no request. On macOS an app started from Finder, the Dock or at login gets `SSH_AUTH_SOCK` from launchd, which also starts the system agent on the first connection (the agent's launchd job: `/usr/bin/ssh-agent -l`, socket key `SSH_AUTH_SOCK`; read with `plutil` and `launchctl print` on this Mac).

INT-06.12 **One request per connection.** Larsal connects, writes one message, reads one reply and closes, as the reference does. Messages never overlap: Larsal sends at most one request at a time to the agent.

INT-06.13 **Socket checks** (Larsal goes further; the reference only checks that the path exists). Before connecting: the path is at most 103 bytes, it is a socket (checked without following a final link), and its owner is the current user. After connecting: the peer's user id (`getpeereid`) is the current user's. Any failure: MI06-03, nothing sent. Observed on this Mac: the launchd socket and its folder belong to the user, folder mode 0700.

INT-06.14 **Framing.** Each message is a `uint32` length in big-endian order followed by that many bytes; the first byte is the message number. The connect and the whole reply must finish within 2 seconds; a reply longer than 262,144 bytes is refused. Timeout, closed connection or oversize reply: MI06-02. Reply numbers: 6 success, 5 failure, 12 identity list; anything else to Larsal's request is a protocol error (MI06-02).

INT-06.15 **Add.** Message 17 (add identity) when no limit applies, else 25 (add identity with limits). Body: `string` key type, the private key fields of the table below, `string` comment (INT-06.8); then, for message 25, in this order: the lifetime limit (byte 1, `uint32` seconds) when the lifetime switch is on; the confirm limit (byte 2) when "Ask before each use" is on and D-INT06-1 is (a); for the two `sk-` types always the extension limit (byte 255, `string` `sk-provider@openssh.com`, `string` the provider of INT-06.38). The fields are copied from the key's private part as stored in the OpenSSH file (the same encoding):

| Key type | Private key fields, in order |
|---|---|
| `ssh-ed25519` | `string` public key (32 bytes), `string` secret seed and public key (64 bytes) |
| `ecdsa-sha2-nistp256`, `-nistp384`, `-nistp521` | `string` curve name (`nistp256`, `nistp384`, `nistp521`), `string` public point, `mpint` private scalar |
| `ssh-rsa` | `mpint` n, `mpint` e, `mpint` d, `mpint` iqmp, `mpint` p, `mpint` q |
| `sk-ssh-ed25519@openssh.com` | `string` public key, `string` application, `byte` flags, `string` key handle, `string` reserved |
| `sk-ecdsa-sha2-nistp256@openssh.com` | `string` curve name, `string` public point, `string` application, `byte` flags, `string` key handle, `string` reserved |

Reply 6: added. Reply 5: MI06-04 with the hints that apply. Observed on a throwaway OpenSSH 10.3 agent: an unknown limit byte and the provider extension on a key that is not `sk-` both give 5.

INT-06.16 **Adding again.** Adding a key the agent already holds succeeds and replaces its comment and its limits: a second add without the lifetime takes the time limit away, a second add without confirm takes the confirm away (observed on a throwaway OpenSSH 10.3 agent). Larsal uses this: "Load into SSH Agent" on a loaded key refreshes its limits.

INT-06.17 **Remove one.** Message 18, `string` public key blob (RFC 4253 section 6.6). This needs no passphrase. Reply 6: removed. Reply 5 means the agent does not hold the key (observed); Larsal then shows the Not loaded state without an error.

INT-06.18 **Remove all.** Message 19 (remove all identities). Reply 6: MI06-20; otherwise MI06-21. Reference difference: it then sends a second request meant as the protocol version 1 remove-all (message 9), but because it reuses the first request's buffer the bytes sent are `13 09`, a second remove-all with a stray byte (OpenSSH 10.3 answers both `09` alone and `13 09` with success; observed on a throwaway agent); it treats any reply as success. Larsal sends one message 19.

INT-06.19 **List.** Message 11; reply 12: `uint32` count, then per key `string` public key blob and `string` comment. Larsal reads at most as many entries as the reply holds and refuses a count that cannot fit the reply (MI06-02). A key is Loaded when its blob is in the list.

INT-06.20 **Lifetime.** The agent removes the key by itself when the lifetime ends. Larsal sends the stored seconds unchanged when they are 1 to 999,999,999. A stored value below 1 with the lifetime switch on: MI06-17 and no add. Observed: an OpenSSH agent given lifetime 0 accepts the key and drops it at once, so the reference's "0" silently loads nothing. The editor control (INT-06.40) shows minutes and steps by 1 minute from 1 to 1,440 (24 hours); a stored value that is not a whole number of minutes shows rounded up, and the stored value is kept until the user moves the stepper (D-INT06-4).

### When keys go in and out

INT-06.21 **Feature off.** While S-SSH-01 is off Larsal never contacts any agent and never opens Larsal's own agent socket. The editor's SSH page, the detail view row and the SSH menu items are hidden (APP-08, reference). Settings attachments in entries are kept unchanged.

INT-06.22 **On unlock.** When the "vault unlocked" signal arrives (APP-06.22 step 10, after the vault shows), Larsal goes through its entries in tree order (a group's own entries in their stored order first, then its subgroups, depth-first; reference) and, for each entry with an SSH key (INT-06.4) whose `AddAtDatabaseOpen` is true, reads, decrypts and adds the key (INT-06.15 or, with "Ask before each use" under D-INT06-1 (b), INT-06.31). This runs in the background; the user can work meanwhile. Failures (key not readable, not decrypted, refused by the agent, or refused by INT-06.23) are collected and shown once as MI06-18, listing each entry title with its reason. Reference difference: it says nothing when a key cannot be read or decrypted; it shows each agent refusal as its own message, so only the last one stays visible; and it stays silent when the key is already in its records from any vault, which hides the other-vault refusal of INT-06.23.

INT-06.23 **Larsal's records.** For every key Larsal added, Larsal keeps: its public key blob, the vault session that added it, its remove-on-lock flag, and whether it sits in the system agent or in Larsal's own agent. These records live in memory only. Adding a key that Larsal's records hold for another open vault is refused with MI06-05 (reference).

INT-06.24 **On lock.** As step 10 of the lock (APP-02.15), for the vault being locked: each recorded key with remove-on-lock is removed (INT-06.17, or from Larsal's own agent); then every record of that vault is dropped, also those whose key stays in the agent (reference). Closing a vault locks it first, so close does the same (reference). The removals finish within 1 second of the lock (AT-H01) unless the agent does not answer (2 s timeout each). A failed removal never holds the lock; MI06-19 shows after it.

INT-06.25 **On quit.** Every unlocked vault is locked (APP-02), so INT-06.24 runs for each. Keys without remove-on-lock stay in the system agent after Larsal quits (reference). Keys in Larsal's own agent always go away with it (INT-06.32).

INT-06.26 **Feature turned off.** When S-SSH-01 goes from on to off, Larsal removes every key in its records, with or without remove-on-lock, then drops all records and closes Larsal's own agent socket. It never removes keys other programs added (decided: spec/decisions.md LD-63). Reference difference: it removes only the keys marked remove-on-lock.

INT-06.27 **Per entry.**
- "Load into SSH Agent" (APP-08, ⌃H), the detail view's "Load key" button, and the editor's "Add to agent now": read, decrypt and add the selected entry's key. In the editor, the page's current values are used, saved or not (reference). The record's remove-on-lock flag comes from those values.
- "Remove from SSH Agent" (⌃⇧H) and the editor's "Remove from agent": remove the key (INT-06.17) and drop its record.
- Changing "Remove the key when the vault locks" on the editor page while the key is recorded changes the record at once, before the entry is saved (reference).
- Each action shows its result in place: the Loaded state, or the error message.

INT-06.28 **Remove all keys.** Tools menu "Remove All Keys from SSH Agent…", after M08-04 (APP-08): message 19 to the system agent, every key leaves Larsal's own agent too, all records are dropped. This also removes keys other programs added to the system agent; M08-04 says so (SI-07).

INT-06.29 **Entry changes while a key is loaded.** Moving the entry to the recycle bin, deleting it, editing its key or settings, or deleting the key attachment does not touch the agent. The key stays until the vault locks (if marked), the lifetime ends, or the user removes it (reference). The record stays with the vault.

INT-06.30 **The Loaded state.** Larsal lists the agent (INT-06.19) when the detail view or the editor's SSH page shows an entry with an SSH key, and after each add or remove. A key whose lifetime ended shows Not loaded at the next list. No polling.

### Ask before each use (D-INT06-1)

Rules INT-06.31 to INT-06.36 apply: option (b) was decided (spec/decisions.md LD-173). INT-06.37 records why option (a) was not chosen; INT-06.37, MI06-34 and test cases T29, T32 and T60 are kept for history and are not built.

INT-06.31 **Where these keys go.** A key with "Ask before each use" on is never sent to the system agent. Larsal keeps it, decrypted, inside its own agent (INT-06.32) from the add until it is removed: by the lock of its vault (always, whatever remove-on-lock says: Larsal keeps no decrypted key of a locked vault, AT-C01), by lifetime, by "Remove from SSH Agent", by "Remove All Keys…", by turning the feature off, or by quitting. The add, remove and record rules of INT-06.22 to INT-06.29 apply unchanged.

INT-06.32 **Larsal's own agent socket.** Path `~/Library/Application Support/Larsal/agent.sock` (placeholder name, renamed with D1), mode 0600 in a folder of mode 0700. Larsal creates it when S-SSH-01 is on and Larsal runs, removes a stale file of that name first only when it is a socket owned by the user, and deletes it at quit or when the feature is turned off. Every connection must come from the current user (`getpeereid`); others are closed at once. Larsal reads the same message framing and limits as INT-06.14.

INT-06.33 **What Larsal's agent answers.**
- 11 (list): the public blobs and comments of the keys it holds (all of them belong to unlocked vaults, INT-06.31), followed by the list of the system agent (INT-06.11) when one is reachable.
- 13 (sign: `string` key blob, `string` data, `uint32` flags): for a key it holds, Larsal asks the question (INT-06.34); Allow Once signs the data and replies 14 (`string` signature: `string` algorithm name, `string` signature blob); Deny, the timeout or a lock reply 5. RSA follows the flags: 2 means `rsa-sha2-256`, 4 means `rsa-sha2-512`, neither means `ssh-rsa` with SHA-1, which Larsal refuses with 5 (OpenSSH has not used it by default since 8.8). For a key it does not hold, Larsal forwards the request to the system agent and passes the reply back.
- 27 (extension) named `session-bind@openssh.com`: Larsal records the host key for that connection (used by INT-06.34) and replies 6 after the signature in it checks with the host key; other extensions are forwarded.
- Every other message (17, 18, 19, 25 and the rest) is forwarded to the system agent byte for byte. With no system agent: 5.
- Signing uses only approved crates through larsal-crypto (AGENTS rule 3): Ed25519 (`ed25519-dalek`) and ECDSA P-256 (`p256`). RSA needs an RSA crate (the same question as D-INT04-2) and P-384, P-521 and the `sk-` types are not signed by Larsal. For those types the switch "Ask before each use" is disabled with MI06-33.

INT-06.34 **The question** (frame `dialogs-ssh-key-use`). Larsal comes to the front and shows a dialog: title MI06-29, text MI06-30 (or MI06-31 when the host is unknown), buttons "Deny" and "Allow Once" (the primary button, as drawn; Return chooses it, Escape chooses Deny).
- The program is the name of the process at the other end of the socket, read from the kernel by its process id (`LOCAL_PEERPID`), for example `ssh` or `git`.
- The host is known when the connection sent a checked session binding (INT-06.33), the data to sign is a `publickey` sign-in request (RFC 4252 section 7: the session ID, byte 50, user name, service, method `publickey` or the host-bound form `publickey-hostbound-v00@openssh.com`, TRUE, the algorithm and the key being used, then for the host-bound form the server host key, which must be the bound one; nothing after it) carrying the session ID of the connection's last checked binding, and the bound host key matches a line of `~/.ssh/known_hosts` with a plain host name; hashed lines cannot be named. Larsal shows the first matching name. Any other data leaves the host unknown (MI06-31), so a process that binds a session of its own cannot have Larsal name that host for other data (LD-203 (2); OpenSSH's agent checks the same for keys limited to hosts).
- One question at a time; further sign requests wait in order. No answer within 60 seconds: Deny. A lock of the key's vault closes the question as Deny (SR-16). There is no "always allow" (each use asks, as the setting says).

INT-06.35 **Lifetime in Larsal's agent.** Larsal removes the key from its own agent when the lifetime ends, counted from the add.

INT-06.36 **Setting it up.** SSH clients reach Larsal's agent only when told to. The settings page shows Larsal's socket and a button that copies the line `IdentityAgent "<path>"` for `~/.ssh/config` (MI06-32). Because Larsal's agent forwards everything it does not handle, a host pointed at it still sees the system agent's keys while Larsal runs. When Larsal is not running, the socket is gone and `ssh` falls back to its key files.

INT-06.37 **Option (a) instead.** "Ask before each use" sends the confirm limit (INT-06.15) to the system agent, which then asks through its askpass helper before every use. A stock Mac has no helper: the launchd job of the system agent has no `SSH_ASKPASS` and no `DISPLAY` in its environment (observed with `launchctl print`), and an OpenSSH agent without a helper refuses every signature of such a key (observed on a throwaway agent: reply 5). So under (a) Larsal shows MI06-34 when the switch is turned on and with each add of such a key; the dialog frame is not used.

### Settings page

INT-06.38 **SSH Agent settings page** (frame `settings-settings-ssh-agent`; APP-01.31).
- "Work with the SSH agent" (VoiceOver "SSH") with the line "Adds keys from entries to the system agent.": S-SSH-01. The rows below, under the heading "Agent", are disabled while it is off (APP-01.5).
- "Status": the socket path in use (INT-06.11) in the code font, or "Not set"; and the state: "Connected" when a list request (INT-06.19) succeeds, else "Not connected" with the reason (MI06-01, MI06-02 or MI06-03). Larsal checks when the page opens, when the switch turns on and when the socket setting changes.
- "Use a different socket": a switch (VoiceOver "Socket"); on, it shows a path field for S-SSH-02 (spaces trimmed on save). Off clears S-SSH-02.
- "Security key provider", "For sk-ed25519 keys on a hardware key.": a picker with "Built-in" (sends `internal`) and "Choose a library…" (MI06-26; a file chooser; the path is stored in S-SSH-03). With S-SSH-03 empty, the provider is `SSH_SK_PROVIDER` from Larsal's environment, else `internal` (reference). MI06-28 shows under the picker when "Built-in" is chosen: observed on this Mac, the system OpenSSH has no built-in provider (`ssh-keygen -t ed25519-sk` says no provider was given), and an OpenSSH agent accepts only provider libraries in its allowed folders.
- Under D-INT06-1 (b): one more row, "Larsal's agent", with Larsal's socket path, the state "Ready" or the error, and the button "Copy Setup Line" (MI06-32). The mockup has no such row (D-INT06-7).

### Editor page and detail view

INT-06.39 **Page visibility.** The editor's "SSH Agent" page shows only while S-SSH-01 is on (reference). It is shown for every entry, with or without settings.

INT-06.40 **Editor page** (frame `editor-editor-ssh-agent`), top to bottom:
- Main switch "Use this entry's key with the SSH agent" (`AllowUseOfSshKey`; VoiceOver name "SSH agent"), with the line "‹entry title› · the entry's password unlocks the key" when the key is encrypted, else "‹entry title›".
- "Private key": two choices. "From an attachment" with a picker of the entry's attachments (INT-06.41); "From a file on this Mac" with the path (home shown as `~`) and a Choose button. The choice is `SelectedType`.
- A key panel (INT-06.42): "Type", "Fingerprint" (code font), "Comment", "Public key" (code font, wrapping) and "Copy public key".
- "Agent": "Add the key when the vault unlocks" (VoiceOver "Add on unlock"), "Remove the key when the vault locks" ("Remove on lock"), "Ask before each use" ("Confirm") with the line "Larsal shows a question every time a program wants to sign with the key." (under (b); under (a) MI06-34 replaces it), "Remove the key after" with a minutes stepper ("Less", "More") and its switch ("Lifetime").
- "Add to agent now", "Remove from agent", and the state "Loaded in agent" or "Not loaded".
- Every control except the two buttons changes the entry draft (saved with the editor's Save). The two buttons act at once (INT-06.27). Controls below the main switch stay enabled when it is off, so the user can prepare the settings.

INT-06.41 **Choosing the key.** The attachment picker lists the draft's attachments except the settings attachment, as "‹name› · ‹size›", sorted by name; picking one selects "From an attachment". A name stored in the settings that no attachment has shows as "‹name› (missing)". The file chooser starts in the folder of the "SSH key" role (APP-01.15) and stores the chosen path as it is (absolute); a path typed by the reference stays as stored until the user picks another.

INT-06.42 **The key panel.** It reads the selected key whenever the source changes or the page opens (INT-06.5 to INT-06.8; no decryption). Readable: type, fingerprint, comment (or MI06-27 for an encrypted key until an add decrypted it in this session), public key line. Not readable: the panel shows the message of INT-06.5 or INT-06.6 in place of the rows. No source chosen: MI06-36. "Copy public key" copies the public key line (not a secret; APP-03 decides the clipboard handling).

INT-06.43 **Detail view row** (frame `states-server-with-ssh-key`). For an entry with an SSH key: a field "SSH key · ‹type›" with the fingerprint and a copy button ("Copy fingerprint"); a field "SSH agent" with the state ("Loaded" or "Not loaded") and a note: "Removed when the vault locks" when remove-on-lock is on or the key asks before each use (INT-06.31), else "Stays loaded after the vault locks", with ", removed after ‹n› min" added when the lifetime switch is on (MI06-25). The quick action "Load key" runs INT-06.27. A key that cannot be read shows its message in the field instead.

INT-06.44 **No key generator.** Larsal does not create SSH keys (D-INT06-6). The reference's editor has a generator (RSA 2048 to 4096, ECDSA 256 to 521, Ed25519) that writes the new key as an attachment named after its type.

### Messages

Larsal's own wording; IDs are ours; ‹…› marks a placeholder. No text is taken from the reference.

| ID | Kind | Rule | Larsal text |
|---|---|---|---|
| MI06-01 | error | INT-06.11 | No SSH agent was found. macOS normally provides one through SSH_AUTH_SOCK; you can also set a socket in SSH Agent settings. |
| MI06-02 | error | INT-06.14, INT-06.19 | Larsal couldn't reach the SSH agent at ‹path›. |
| MI06-03 | error | INT-06.13 | Larsal won't use ‹path›: it is not an SSH agent socket that belongs to you. (Also for a missing socket or folder: nothing is sent, LD-183.) |
| MI06-04 | error | INT-06.15 | The SSH agent did not take the key of “‹title›”. Then, per case: "It may not accept a time limit." (lifetime on); "Keys on a security key need a provider the agent accepts. Check SSH Agent settings." (`sk-` type) |
| MI06-05 | error | INT-06.23 | This key is already loaded from another open vault, ‹vault name›. Lock that vault or remove the key there first. |
| MI06-06 | error | INT-06.5 | “‹title›” has no attachment named ‹name›. |
| MI06-07 | error | INT-06.5 | Larsal can't open the key file ‹path›. |
| MI06-08 | error | INT-06.5 | ‹name› is over 1 MiB, so it can't be an SSH key. |
| MI06-09 | error | INT-06.5 | ‹name› has no content. |
| MI06-10 | error | INT-06.6 | ‹name› is not an SSH private key Larsal can read. (Also for an unknown cipher name, which the key reader refuses while reading, before MI06-13 could apply; LD-183.) |
| MI06-11 | error | INT-06.6 | ‹name› uses an older key format. Convert a copy with "ssh-keygen -p -f ‹file›", then use the converted file. |
| MI06-12 | error | INT-06.6 | ‹name› is a DSA key, which OpenSSH no longer supports. Use an Ed25519 key instead. |
| MI06-13 | error | INT-06.9 | ‹name› uses ‹cipher or type›, which Larsal can't read. |
| MI06-14 | error | INT-06.9 | This key is protected by a passphrase. Put the passphrase in the entry's Password field. |
| MI06-15 | error | INT-06.9 | The entry's password does not unlock this key. |
| MI06-16 | error | INT-06.9 | This key's passphrase protection uses ‹n› rounds; Larsal allows at most 1,000. Protect it again with fewer rounds, for example "ssh-keygen -p -a 100 -f ‹file›". |
| MI06-17 | error | INT-06.20 | The time limit must be at least 1 minute. |
| MI06-18 | banner | INT-06.22 | Some SSH keys were not loaded: ‹titles›. Button "Details" lists each title with its message. |
| MI06-19 | banner | INT-06.24 | Larsal couldn't take the key of “‹title›” out of the SSH agent. Use Remove All Keys from SSH Agent… to clear it. |
| MI06-20 | toast | INT-06.18 | Every key was removed from the SSH agent. |
| MI06-21 | error | INT-06.18 | The SSH agent did not remove its keys. |
| MI06-22 | state | INT-06.38 | Connected / Not connected |
| MI06-23 | state | INT-06.40, INT-06.43 | Loaded in agent / Loaded / Not loaded |
| MI06-24 | note | INT-06.2 | Larsal can't read this entry's SSH settings. Saving this page replaces them. |
| MI06-25 | note | INT-06.43 | Removed when the vault locks / Stays loaded after the vault locks / , removed after ‹n› min |
| MI06-26 | label | INT-06.38 | Built-in / Choose a library… |
| MI06-27 | placeholder | INT-06.8, INT-06.42 | Shown after the key is unlocked |
| MI06-28 | hint | INT-06.38 | The SSH agent built into macOS has no built-in provider. To use keys that live on a security key, choose a provider library. |
| MI06-29 | dialog title | INT-06.34 | Allow ‹program› to use “‹entry title›”? |
| MI06-30 | dialog text | INT-06.34 | ‹program› wants to sign in to ‹host› with this key. |
| MI06-31 | dialog text | INT-06.34 | ‹program› wants to sign with this key. |
| MI06-32 | row | INT-06.36 | Larsal's agent · ‹path› · Ready. Button "Copy Setup Line"; toast after copying: Setup line copied. Add it to ~/.ssh/config for the hosts that should use keys that ask first. |
| MI06-33 | hint | INT-06.33 | Asking before each use works with Ed25519 and ECDSA P-256 keys. |
| MI06-34 | warning | INT-06.37 | The SSH agent in macOS can't ask you. With this on, every use of the key is refused unless the agent has an askpass helper. |
| MI06-35 | toast | INT-06.42, INT-06.43 | Public key copied / Fingerprint copied |
| MI06-36 | note | INT-06.42 | Choose the private key: an attachment or a file. |


## Edge cases and errors

- **No agent at all** (`SSH_AUTH_SOCK` unset, as in a launch from a shell that removed it, and no override): the settings page warns (MI06-01); unlock adds fail as one MI06-18; the menu items stay visible while the feature is on (reference).
- **Agent socket replaced by another user's socket** (an override pointing into `/tmp`): refused by INT-06.13 before anything is sent.
- **Two open vaults with the same key:** the second add is refused (MI06-05) while the first vault holds the record; after the first vault locks, its records are gone and the second vault may add the key (reference).
- **Same key in two entries of one vault:** allowed; one record; the last add sets the limits (INT-06.16).
- **A key added by another program before Larsal:** Larsal's add succeeds and replaces its limits (INT-06.16); Larsal records it and, with remove-on-lock, removes it at lock, also though another program added it first (reference does the same).
- **Lifetime ended before lock:** the removal at lock gets reply 5, which is not an error (INT-06.17).
- **Agent restarted** (logout, `launchctl kickstart`): all keys are gone; Larsal's records stay until lock; removals get reply 5 and stay silent.
- **Key file on an unplugged drive:** MI06-07 at the add; the entry keeps its settings.
- **Encrypted key, entry password empty:** MI06-14; the reference says the same with its own text.
- **Entry password is a placeholder or reference:** resolved first (INT-06.9).
- **Recycle bin:** no add on unlock and no menu items for bin entries (SD-05, reference for unlock); a key already loaded stays when its entry moves to the bin (INT-06.29).
- **History items:** never added; the settings attachment in history is data only.
- **Imports that carry SSH keys as fields** (for example `ssh_private_key` from FEA-08): the agent uses only attachments and files, as the reference does; the user moves the key into an attachment.
- **Hostile settings attachment** (huge, a DTD, deep nesting): bounded by INT-06.2; no entity is expanded.
- **Hostile key file:** size bounded (INT-06.5), rounds bounded (INT-06.9); parsing goes through the `ssh-key` crate and never panics; a malformed key is MI06-10.
- **Many keys at unlock:** the background task adds one key after another; locking the vault while it runs stops it after the current key, and that key is then handled by the lock rules.
- **Under (b), `ssh` asks Larsal's agent while the vault is locked:** the key left Larsal's agent at the lock (INT-06.31), so it is not listed and `ssh` tries other keys; Larsal does not prompt to unlock (Larsal's own choice; the reference has no own agent). Bitwarden instead prompts to unlock (its help page, "Behavior by vault state").
- **Not on Mac.** The reference on Windows talks to Pageant, the OpenSSH named pipe `\\.\pipe\openssh-ssh-agent`, or both (S-NOMAC-08, -09); a Pageant message is limited to 8,192 bytes.

## Lead decisions

Decided: spec/decisions.md LD-173, all seven as recommended. D-INT06-1 (b) is built in E9-S2 (no new story); D-INT06-7 needs new frames in the locked mockup, asked of the owner before E9.

| ID | Question | Options | Recommended, with evidence |
|---|---|---|---|
| D-INT06-1 | Who answers "Ask before each use" (INT-06.31 to INT-06.37) | (a) Send the confirm limit to the system agent, as the reference does; warn that a stock Mac cannot ask. (b) System agent for every other key; keys that ask live in a small agent inside Larsal that shows Larsal's own question and forwards all else to the system agent. (c) Larsal runs its own agent for every key, as Bitwarden, Strongbox and Secretive do | (b). Every proven Mac password manager or key app with a per-use question shows its own question from its own agent: Bitwarden ("Ask for authorization when using SSH agent", own socket `~/.bitwarden-ssh-agent.sock`), Strongbox (own socket, "approve or deny the request", shows the process), Secretive ("notifies you whenever your keys are accessed"). The stock system agent cannot ask (INT-06.37, observed). The locked mockup shows Larsal's question (`dialogs-ssh-key-use`) and the system agent socket on the settings page, and only (b) fits both. Cost: Larsal signs for those keys (Ed25519 and P-256 with approved crates; RSA waits for an RSA crate) and the user adds one `IdentityAgent` line. (c) would also change the settings frame and lose the reference's behavior for normal keys. LD-173: INT-06.31 to INT-06.36 are built in E9-S2 |
| D-INT06-2 | Key forms (INT-06.6) | (a) OpenSSH format only, every type but DSA; (b) also the old PEM RSA and DSA forms with the MD5-based derivation, as the reference; (c) also PKCS#8 | (a). `ssh-keygen` writes the OpenSSH format by default since 2018; Strongbox requires it ("Be stored in the standard OpenSSH format", other formats "need conversion with ssh-keygen"); Bitwarden takes OpenSSH or PKCS#8. The approved `ssh-key` crate reads only the OpenSSH format; (b) would add DER parsing, MD5 and old ciphers for a form users can convert in one command (MI06-11) |
| D-INT06-3 | bcrypt-pbkdf round ceiling (INT-06.9; LD-73) | 1,000 rounds; or another number | 1,000: 6.2 s on this Mac (measured), 40 times the OpenSSH 10.3 default of 24 and 10 times the common hardening advice of 100; anything above it looks like an attack on Larsal's time |
| D-INT06-4 | Lifetime control (INT-06.20) | (a) minutes 1 to 1,440 with the stored seconds kept until changed; (b) seconds 0 to 999,999,999 as the reference | (a): the mockup draws a minutes stepper ("10 min"); 0 seconds loads nothing (observed), so it is refused |
| D-INT06-5 | Passphrase source (INT-06.9) | (a) the Password field resolved like Copy Password; (b) the raw field text as the reference | (a): a reference to another entry is a normal way to share one passphrase; the reference's raw use fails silently for it |
| D-INT06-6 | Key generator (INT-06.44) | leave it out; or build one | Leave it out: the mockup has no generator; `ssh-keygen` makes keys; Bitwarden generates Ed25519 only. Add later if users ask |
| D-INT06-7 | Mockup gaps | (1) Under (b), the settings page row "Larsal's agent" with "Copy Setup Line" (INT-06.38); (2) the "Not loaded" state and the note texts of INT-06.43 that the frames do not draw; (3) MI06-27 for an encrypted key's comment | Add all three to the mockup with the owner's approval (AT-K05) |

Check with Verify:

| ID | What to check |
|---|---|
| V-INT06-1 | The reference reads a settings document written by Larsal (INT-06.3) and adds the key; read the reference's settings reader again for whitespace inside boolean elements |
| V-INT06-2 | The exact bytes the reference writes for a settings document (declaration, attribute order, final line end), to confirm INT-06.3 |
| V-INT06-3 | The macOS system agent (not a throwaway one) accepts the lifetime limit and drops the key in time (AT-H02), with a demo key, and that nothing else is in it before and after |
| V-INT06-4 | Under (b): `ssh -o IdentityAgent=...` to a local demo `sshd` sends `session-bind@openssh.com`, and Larsal names the host from a plain `known_hosts` line |

## Security notes

- **SI-07** (parity row): add on unlock, lifetime 600 s by default when on, confirm, both off by default per entry; remove marked keys on lock and quit; Remove All also removes other programs' keys (asked first, M08-04); refuse a key another open vault added. Larsal goes further: rounds bounded (INT-06.9, LD-73); turning the feature off removes every key Larsal added (LD-63); socket owner and peer checks (INT-06.13); one-pass path expansion (INT-06.5); DSA and the MD5-based PEM form not read (D-INT06-2).
- **AT-H01:** keys marked remove-on-lock leave the agent within 1 second of the lock (INT-06.24); keys in Larsal's own agent always leave it at the lock (INT-06.31). **AT-H02:** the lifetime limit reaches the system agent (INT-06.15, T28, T31; proof by behavior, because `ssh-add -l` does not print limits); under (b) the confirm limit is Larsal's own question: such a key never reaches the system agent and every signature needs Allow Once (T51, T53, T57).
- **SD-05:** recycle bin entries are never added on unlock and never offered in menus.
- **SR-16:** the lock removes marked keys; a failed removal never blocks the lock; under (b) a lock closes an open question as Deny.
- **SR-07 and AGENTS rule 4:** decrypted keys and passphrases live only in Rust secret types and are wiped right after use (INT-06.10). Under (b) the keys that ask stay decrypted in Larsal's memory while loaded and their vault is unlocked, and are wiped at its lock (INT-06.31); that is the same exposure as the system agent's memory, inside Larsal's hardened process (APP-11).
- **The question's program name is a hint:** any process of the same user can choose its own name, so the name helps the user notice an unexpected request but proves nothing. "Ask before each use" protects only the copy in Larsal's agent: a copy of the same key that another program added to the system agent is used without asking.
- **What must never happen:** a key sent to a socket that belongs to another user; a private key, passphrase or decrypted byte in a log, error text or the Swift layer; a hang from a hostile key file; a key Larsal added staying in the agent after the feature is turned off; a signature under (b) without the user's Allow Once.
- **What the agent itself exposes:** any process of the same user can use a loaded key through the agent without asking, unless the key asks first; the comment and public key are visible to any such process. This is how agents work; "Ask before each use" is the protection (the OpenSSH manual says the same of its confirm option).

## Test cases

Demo files under `/tmp/spec-int06/` (test HOME `/tmp/spec-int06/home`). Never the user's own agent: every test runs with `SSH_AUTH_SOCK` unset or pointing at a throwaway agent started with `ssh-agent -a /tmp/spec-int06/agent.sock`, points S-SSH-02 at it, and stops it by its PID at the end. Clipboard cases (T65, T72) use a private named test pasteboard (AGENTS rule 10), never the general pasteboard. For the confirm tests of option (a) (not built, LD-173) a second throwaway agent runs with `SSH_ASKPASS=/tmp/spec-int06/askpass.sh`, `SSH_ASKPASS_REQUIRE=force` and `DISPLAY=:0`; the script appends its prompt to a log and exits with a scripted status (0 allows, 1 denies).

Demo key K1 (Ed25519, comment `demo@app`, fingerprint `SHA256:R3aMsbAq88Fv8wlNcuy3oN+ZIl7yqPd3lRkAP/AP+uc`), made by `ssh-keygen` for this card:

`-----BEGIN OPENSSH PRIVATE KEY-----`
`b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW`
`QyNTUxOQAAACAXBQ6tk+9cBEQnipP+gWQhhyC3TUJgLfuhlQjm1wPZhgAAAJCFFnN8hRZz`
`fAAAAAtzc2gtZWQyNTUxOQAAACAXBQ6tk+9cBEQnipP+gWQhhyC3TUJgLfuhlQjm1wPZhg`
`AAAEBFcbeDr4WGNkaX3X0F79RKibjugiw6qJhq2wgi7SoGGRcFDq2T71wERCeKk/6BZCGH`
`ILdNQmAt+6GVCObXA9mGAAAACGRlbW9AYXBwAQIDBAU=`
`-----END OPENSSH PRIVATE KEY-----`

Public key line: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcFDq2T71wERCeKk/6BZCGHILdNQmAt+6GVCObXA9mG demo@app`.

Made in the test setup with `ssh-keygen` from K1: K1e (K1 protected with `ssh-keygen -p -N demo-ssh-pass`: `aes256-ctr`, `bcrypt`, 24 rounds, 16-byte salt; same fingerprint), K1big (the same with `-a 1001`), Kp (`ssh-keygen -t rsa -b 2048 -m PEM -N demo-ssh-pass`: label `RSA PRIVATE KEY`, `DEK-Info: AES-128-CBC`), K8 (`-m PKCS8`, unencrypted), K2 (`-t ecdsa -b 256`, comment `ecdsa@app`), Kr (`-t rsa -b 3072`, unencrypted).

Demo vault V (`ssh-demo.larsalvault`, password `demo-ssh-vault`, S-SSH-01 on):
- E1 "Server root · web-01": user `root`, password `demo-ssh-pass`, attachment `id_ed25519` = K1e, settings S1 = allow, add, remove on; confirm and lifetime off; 600; `attachment`, `id_ed25519`.
- E2 "Plain key": user `alex`, password empty, attachment `id_plain` = K1 with its comment removed (`ssh-keygen -c -C ""`), settings allow and add on, remove off.
- E3 "File key": settings allow on, add off, `file`, `~/keys/k2` (= K2 under the test HOME).
- E4 "Old key": attachment `id_rsa` = Kp, settings allow and add on.
- E5 "Binned": in the recycle bin, attachment K2, settings allow and add on.
- E6 "No settings": attachment K2 only.

| Case | Given | When | Then |
|---|---|---|---|
| T01 INT-06.1 | S1 as Larsal writes it (INT-06.3) | Read | allow, add, remove true; confirm, lifetime false; 600; `attachment`; `id_ed25519`; temp-file false; file empty |
| T02 INT-06.2 | Booleans `True`, `tRUE`, `yes`, empty; lifetime `abc`, `-5`, `90` | Read | true, true, false, false; 0, -5, 90 |
| T03 INT-06.2 | `SelectedType` `Attachment`; an unknown element `Foo` before `Location`; `AddAtDatabaseOpen` twice (false, then true) | Read | file selected (exact match only); Foo skipped; add true |
| T04 INT-06.2 | Settings with a DTD; a 70 KiB settings attachment; root `Settings` | Open the editor's SSH page; unlock V | MI06-24 each time; the entry has no SSH key (no add, no menu items); the attachment bytes unchanged after the vault is saved |
| T05 INT-06.3 | E6 (K2 attached as `id_ecdsa`); on the SSH page turn the main switch on, choose `id_ecdsa`, save | Read the new attachment | Exactly the layout of INT-06.3 with allow true, the other booleans false, 600, type `attachment`, name `id_ecdsa`, temp-file false, `<FileName/>`, final LF |
| T06 INT-06.3 | E1; turn every control back to the defaults, save | Read the entry | The settings attachment is gone |
| T07 INT-06.3 | E1 opened in the editor, SSH page never shown; change the title, save | Compare | The settings attachment is byte-for-byte unchanged |
| T08 INT-06.3 | In the editor's attachment list, remove the settings attachment of E1 | Look at the SSH page | Every control shows its default |
| T09 INT-06.4 | V unlocked | Select E5; select E6; select E1 | E5 and E6: no SSH menu items, no SSH detail row; E1: both items and the row |
| T10 INT-06.4 | S-SSH-01 off | Select E1, open the editor | No SSH menu items, no detail row, no SSH page (INT-06.21, INT-06.39) |
| T11 INT-06.5 | E3 with `~/keys/k2`; then with `$HOME/keys/k2`; then `$NOPE/k2` | Show the key panel | First two: ECDSA, K2's fingerprint; third: MI06-07 for `/k2` |
| T12 INT-06.5 | Environment `LOOP='$LOOP'`, file name `$LOOP/k` | Show the key panel | Returns at once with MI06-07 for `$LOOP/k` (one pass); no hang |
| T13 INT-06.5 | Vault at `/tmp/spec-int06/v/V.larsalvault`, file name `k2rel` with K2 at `/tmp/spec-int06/v/k2rel` | Show | ECDSA key read from the vault's folder |
| T14 INT-06.5 | Key attachment of 1,048,577 bytes; empty attachment; file name pointing to a folder | Load into SSH Agent each | MI06-08 (nothing parsed); MI06-09; MI06-07 |
| T15 INT-06.5 | E1 with `AttachmentName` `id_missing` | Load | MI06-06 |
| T16 INT-06.6 | E4 (Kp); K8; a DSA key file made by an older `ssh-keygen` (test asset); a text file | Show the key panel | MI06-11; MI06-11; MI06-12; MI06-10 |
| T17 INT-06.6 | K1, K2, Kr, and test assets for P-384, P-521, `sk-ssh-ed25519` and `sk-ecdsa` (public parts made by the `ssh-key` crate's test helpers) | Show the key panel | Types `ED25519`, `ECDSA`, `RSA 3072`, `ECDSA P-384`, `ECDSA P-521`, `ED25519-SK`, `ECDSA-SK` |
| T18 INT-06.7 | E1 (K1e, encrypted) | Open the SSH page | Type `ED25519`, fingerprint `SHA256:R3aMsbAq88Fv8wlNcuy3oN+ZIl7yqPd3lRkAP/AP+uc`, comment MI06-27, public key line without comment; no decryption ran (spy) |
| T19 INT-06.8 | E2 (K1 without comment, user `alex`) | Load into SSH Agent; list the agent | Comment `alex@id_plain` |
| T20 INT-06.9 | E1 with password `demo-ssh-pass` | Load | Reply 6; the agent lists K1's blob with comment `demo@app` |
| T21 INT-06.9 | E1 with password empty; with `wrong-pass` | Load | MI06-14 (no KDF ran, spy); MI06-15 |
| T22 INT-06.9 | Attachment K1big | Load | MI06-16 naming 1001, returned in under 50 ms (no KDF ran) |
| T23 INT-06.9 | E1's password set to `{REF:P@T:Shared}` and an entry "Shared" with password `demo-ssh-pass` | Load | Added |
| T24 INT-06.10 | Debug build with the secret wipe hook | Load E1, then scan the process memory for `demo-ssh-pass` and for K1's 32-byte seed `4571b783af8586364697dd7d05efd44a89b8ee822c3aa8986adb0822ed2a0619` after 1 s | Not found outside the vault's own protected field storage (AT-C01 method) |
| T25 INT-06.11 | `SSH_AUTH_SOCK` unset, S-SSH-02 empty | Open the settings page | Status "Not set", MI06-01 |
| T26 INT-06.13 | S-SSH-02 = a regular file; = a symbolic link to the throwaway socket; = a socket owned by another user (test fixture run as root in CI only) | Open the settings page | MI06-03 each; nothing written to any of them |
| T27 INT-06.14 | A fake agent that accepts and never answers; one that answers with a 300 KiB reply; one that answers byte 99 | Load E1 | MI06-02 after 2 s; MI06-02; MI06-02 |
| T28 INT-06.15 | E1 with lifetime on, 120 | Load, recording the bytes sent (fake agent) | Message 25; after the comment: `01 00 00 00 78`; no other limit |
| T29 INT-06.15 | Under (a): E1 with confirm and lifetime 120 | Load (fake agent) | Message 25 ending in `01 00 00 00 78 02` |
| T30 INT-06.15 | An `sk-ssh-ed25519` test key; S-SSH-03 empty, `SSH_SK_PROVIDER` unset | Load (fake agent) | Message 25 ending in byte 255, `string` `sk-provider@openssh.com`, `string` `internal` |
| T31 INT-06.15 | Throwaway OpenSSH agent; E1 with lifetime 2 | Load; list at once; list after 4 s | Listed; then not listed (AT-H02, lifetime) |
| T32 INT-06.15 | Askpass agent (exit 0), option (a), E1 with confirm | Load; then `ssh-keygen -Y sign -n file -f k1.pub data` with that agent | Signature made; the askpass log holds one prompt naming `demo@app` and K1's fingerprint (AT-H02, confirm). With exit 1: the signing fails |
| T33 INT-06.16 | E1 loaded with lifetime 120 | Turn the lifetime off on the page, Add to agent now; wait past 120 s (fake clock in a fake agent) | One key; the second add sent message 17; still listed |
| T34 INT-06.17 | Throwaway agent without K1 | Remove from SSH Agent on E1 | Reply 5; the page shows "Not loaded"; no error |
| T35 INT-06.18 | Throwaway agent holding K1 and K2 (K2 added with `ssh-add`) | Tools, Remove All Keys from SSH Agent…, Remove All | Message 19 only (no message 9); agent empty; MI06-20 |
| T36 INT-06.19 | Fake agent answering a count of 1,000,000 in a 9-byte reply | Open E1's SSH page | MI06-02; no large allocation |
| T37 INT-06.20 | E1 with lifetime on, stored 0 | Load | MI06-17; nothing sent |
| T38 INT-06.20 | Stored 90 | Open the page | Stepper shows 2 min; saving without touching it keeps 90; pressing More then Less stores 120 |
| T39 INT-06.22 | V locked; throwaway agent empty | Unlock V | E1 and E2 hold the same key K1, so the agent lists one key, with the comment of the later add in tree order (`alex@id_plain`); E3 is not added (add off); E4 fails; E5 is not tried; MI06-18 names "Old key" only |
| T40 INT-06.22 | V unlocked with E1 added, S-SSH-01 on | Lock, unlock again with E1 still in the agent (remove-on-lock turned off first) | No message for E1 |
| T41 INT-06.23 | V and a copy W (other path, same keys) | Unlock V, then W | W's adds of K1 fail with MI06-05 naming V |
| T42 INT-06.24 | V unlocked; then Load into SSH Agent on E1 (remove on; this later add of K1 sets its record, INT-06.16) and on E3 (K2, remove off) | Lock V; list the agent within 1 s | K1 gone, K2 still there (AT-H01); Larsal holds no record of V |
| T43 INT-06.24 | Agent killed after unlock | Lock V | The lock finishes; MI06-19 for E1 after the unlock view shows |
| T44 INT-06.24 | Close V's window instead of locking | List the agent | Same as T42 |
| T45 INT-06.25 | E1 and K2 loaded as in T42 | Quit Larsal | K1 gone, K2 stays |
| T46 INT-06.26 | V unlocked; E1 (remove on) and E3's K2 (remove off) loaded by Larsal; K9 added by `ssh-add` | Turn S-SSH-01 off | K1 and K2 gone; K9 stays (LD-63) |
| T47 INT-06.27 | E1 in the editor, unsaved change: remove-on-lock off | Add to agent now; then lock V without saving (discard) | Added; at lock K1 stays (the record took the page value) |
| T48 INT-06.27 | E1 loaded with remove on | Open the editor, turn remove-on-lock off, Cancel the editor, lock | K1 stays (the record changed at once, as the reference) |
| T49 INT-06.29 | E1 loaded | Move E1 to the recycle bin; list the agent | K1 still listed |
| T50 INT-06.30 | E1 loaded with lifetime 2 (throwaway agent) | Open the detail view after 4 s | "Not loaded" |
| T51 INT-06.31 | (b): E1 with confirm on; E2's add on unlock off (E2 holds the same K1) | Unlock V | The system agent does not list K1; Larsal's agent lists K1 followed by the system agent's keys |
| T52 INT-06.32 | (b): Larsal running, feature on | `stat` Larsal's socket and folder; connect as another user (CI fixture) | Modes 0600 and 0700; the other user's connection is closed at once |
| T53 INT-06.33 | (b): E1 with confirm loaded; `ssh-keygen -Y sign` through Larsal's socket | Answer Allow Once | A valid Ed25519 signature (checked with `ssh-keygen -Y verify`) |
| T54 INT-06.33 | (b): K2 (ECDSA P-256) with confirm; Kr with the switch | Open the page for Kr; sign with K2 | Kr: "Ask before each use" disabled with MI06-33; K2: signature checks |
| T55 INT-06.33 | (b): Larsal's agent; `ssh-add -l` and `ssh-add k9` through Larsal's socket | Run | The list shows Larsal's keys then the system agent's; K9 lands in the system agent (forwarded) |
| T56 INT-06.33 | (b): RSA key in Larsal's agent (only if an RSA crate is approved); sign request with flags 0 | Send | Reply 5 |
| T57 INT-06.34 | (b): sign request from `ssh` with a checked session binding for host key H; `known_hosts` has `web01.example H` | Show | Title "Allow ssh to use “Server root · web-01”?", text with `web01.example`; Escape gives 5 |
| T58 INT-06.34 | (b): two sign requests at once; no answer | Wait | One dialog at a time; the first ends as Deny after 60 s (fake clock), then the second shows |
| T59 INT-06.34 | (b): dialog open | Lock V | Dialog closes; reply 5 |
| T60 INT-06.37 | (a): turn "Ask before each use" on for E1 | Look | MI06-34 under the switch |
| T61 INT-06.38 | Settings page, throwaway agent at S-SSH-02 | Open | Status shows the path and "Connected"; with the agent stopped: "Not connected" and MI06-02 |
| T62 INT-06.38 | Provider picker | Choose "Built-in"; choose a library at `/tmp/spec-int06/libsk.dylib` | S-SSH-03 = empty and MI06-28 shown (the picker shows Built-in when S-SSH-03 is empty and `SSH_SK_PROVIDER` unset); S-SSH-03 = the path |
| T63 INT-06.40 | E1 in the editor | Read the page | Texts and VoiceOver names of frame `editor-editor-ssh-agent`; stepper "10 min" disabled while the lifetime switch is off |
| T64 INT-06.41 | E1 with attachments `id_ed25519` (444 B), `notes.txt`, and the settings attachment | Open the picker | Two items, sorted, with sizes; no settings attachment |
| T65 INT-06.42 | E3 | Copy public key | Clipboard holds K2's public key line with comment `ecdsa@app`; MI06-35 |
| T66 INT-06.43 | E1 loaded, remove on, lifetime on 10 min | Show the detail view | "SSH key · ED25519", the fingerprint, "Loaded", "Removed when the vault locks, removed after 10 min", button "Load key" |
| T67 INT-06.44 | Editor SSH page | Look for a key generator | None |
| T68 INT-06.12 | Fake agent that records connections and answers slowly (1 s) | Load E1, and press Remove from SSH Agent while the add runs | Two connections one after the other, each with exactly one message; the remove starts only after the add's reply |
| T69 INT-06.21 | S-SSH-01 off; fake agent at S-SSH-02 counting connections | Unlock V, select E1, open the editor | Zero connections; Larsal's own agent socket does not exist |
| T70 INT-06.28 | (b): Larsal's agent holds K1 (E1 with ask on); the system agent holds K2 from E3 | Remove All Keys from SSH Agent…, Remove All; then lock V | Both agents empty, Larsal's records empty; the lock sends no remove message |
| T71 INT-06.35 | (b): E1 with ask on and lifetime 2 | List Larsal's socket at once and after 4 s | Listed, then not listed |
| T72 INT-06.36 | (b): settings page | Press Copy Setup Line | The clipboard holds `IdentityAgent "` + Larsal's socket path + `"`; MI06-32's toast shows |
| T73 INT-06.39 | S-SSH-01 on; E6 (no settings) | Open the editor | The SSH Agent page is listed and shows the defaults (main switch off, `From a file on this Mac` selected, 10 min) |
| T74 INT-06.31 | (b): E1 with confirm on and remove-on-lock off, loaded; debug build with the secret wipe hook | Lock V; list Larsal's socket; scan the process memory for K1's seed after 1 s | Nothing listed from V; the detail note before the lock read "Removed when the vault locks"; seed not found (AT-C01 method) |

## How this was learned

- Read in the reference source (development branch): the SSH agent client (socket choice from the override and the environment, the existence check, the one-message-per-connection exchange with its 500 ms connect wait, the add with lifetime, confirm and security key provider limits, the error text built from the limits, the remove, the remove-all with the extra version 1 message, the list, the loaded check, the per-vault ownership table, the unlock, lock and turn-off handlers, the remove-on-lock update); the entry settings class (defaults, the XML reader and writer, the attachment name, the key loading from an attachment or a file with the 1 MiB file limit, relative paths, environment expansion, the comment fallback); the OpenSSH key class (PEM extraction, the supported labels, the version 1 key format, the type templates for public and private parts, bcrypt and the MD5-based derivation, the cipher list, the check numbers, MD5 and SHA-256 fingerprints); the cipher name mapping; the environment expansion helper; the entry editor's SSH page and its screen definition (controls, the lifetime spin box range, which buttons are enabled when, the allow flag computed from two boxes, the decrypt, copy and generate actions, the attachment list without the settings attachment); the vault view's add and remove actions and lock and unlock calls; the close handler that locks first; the main window's menu enable rules, clear-agent action and quit handler; the SSH settings page, its screen definition and the settings defaults table; the key generator dialog.
- Ran on this Mac (macOS 26.6, OpenSSH 10.3p1) in `/tmp/spec-int06/` with demo keys made by `ssh-keygen`: two throwaway agents (`ssh-agent -a`, stopped by their PIDs) and a small python3 script that speaks the agent protocol. Observed: adding a key again replaces its comment and limits; removing an absent key gives failure; lifetime 0 is accepted and the key is gone at once; a lifetime of 2 s removes the key; a key with the confirm limit is refused at signing without a helper, and with a scripted askpass helper the agent asks once per use (allow signs, deny fails), its prompt naming the comment and the fingerprint; an unknown limit and the provider extension on a normal key give failure; message 9 gives success. Read the system agent's launchd job with `plutil` and `launchctl print` (no askpass, no display in its environment) and the socket's owner and mode with `ls`. Timed `ssh-keygen -y` at 24 and 1,000 rounds. `ssh-keygen -t ed25519-sk` reported that no provider was given. The user's own agent was never contacted.
- Checked the reference's installed version only through the source; its window app was not launched.
- Proven standard (AGENTS rule 9), read 2026-10-28: Bitwarden help pages "SSH agent" (https://bitwarden.com/help/ssh-agent/) and "About SSH" (https://bitwarden.com/help/about-ssh/): own agent socket, Ed25519 and RSA, OpenSSH or PKCS#8 imports, keys cannot be added or constrained with `ssh-add`, the "Ask for authorization when using SSH agent" setting, behavior by vault state. Strongbox knowledge base "Use Strongbox As Your SSH Agent" (https://strongbox.reamaze.com/kb/ssh-agent/ssh-agent): own socket in its group container, `IdentityAgent` setup, RSA and Ed25519 in OpenSSH format only, the entry's password as passphrase, approve or deny per request with the process shown. Secretive (https://github.com/maxgoedjen/secretive): notifies on every key use. The reference: a client of the system agent only, as INT-06.11 to INT-06.30 describe.

## Review 2026-10-28

Second Spec review. Checked against the reference source (the agent client, the entry settings reader and writer, the lock and unlock handlers, the editor page's screen definition), the OpenSSH agent protocol (draft-miller-ssh-agent, now draft-ietf-sshm-ssh-agent), LD-173, the frames `settings-settings-ssh-agent`, `editor-editor-ssh-agent`, `dialogs-ssh-key-use` and `states-server-with-ssh-key`, and on a throwaway OpenSSH 10.3 agent in `/tmp` (own `SSH_AUTH_SOCK`, stopped by its PID; the user's agent was never contacted). Re-observed: K1's fingerprint, public key line and seed; add with lifetime 120, add again (comment and limits replaced), remove (6), remove of an absent key (5), lifetime 0 (accepted, gone at once), lifetime 2 (gone after 3 s), an unknown limit byte (5), the provider extension on a normal key (5), message `09` alone and `13 09` (both 6), message 99 (5). Stat of the launchd socket: owned by the user, folder mode 0700.

Fixes made (16): Epics line and "What it does" follow LD-173; the "Ask before each use" intro marks INT-06.37, MI06-34, T29, T32 and T60 as not built; the Lead decisions intro and D-INT06-1 say LD-173; INT-06.18 states what the reference really sends for its second remove-all (`13 09`, any reply taken as success); INT-06.22 gives the reference's entry order (a group's own entries, then its subgroups); INT-06.22's reference difference corrected (silent on unreadable keys and on already-recorded keys) and its clause about "a key Larsal already holds for this vault" removed, because no record of a vault exists when it unlocks; INT-06.31 removes keys from Larsal's agent at every lock of their vault (the card's own edge case and INT-06.33 already assumed it; AT-C01), with INT-06.33's list wording, the INT-06.43 note and the edge case aligned; INT-06.38 gains the frame's line "Adds keys from entries to the system agent.", the heading "Agent" and the VoiceOver names "SSH" and "Socket"; security notes: AT-H01 and AT-H02 under (b), the SR-07 line, a note that the question's program name is only a hint and that a copy of the key in the system agent is not asked about; the test setup now forbids the user's `SSH_AUTH_SOCK` and the general pasteboard; T42 and T45 load E1 by hand (E2's later add of the same K1 with remove off would otherwise set the record and keep K1 at lock); T51 turns E2's add on unlock off; new T74 for the lock rule of INT-06.31.

Findings, each with a proposed ruling (the default rule of spec/decisions.md applies until the lead rules):

| ID | Finding | Proposed ruling |
|---|---|---|
| R06-1 | After the INT-06.31 fix, a key that asks before each use always leaves at lock, but the editor's "Remove the key when the vault locks" switch can still show off for it. | While "Ask before each use" is on, that switch shows on and is disabled; the stored `RemoveAtDatabaseClose` value is kept unchanged (so the reference reads the document as before). Test: T63 extended. |
| R06-2 | INT-06.33 does not say how Larsal's agent talks to the system agent for forwarded requests. One new connection per forwarded request loses the session binding: the OpenSSH agent then treats the request as local use and skips the destination limits a user set with `ssh-add -h`. The card also does not say which host the question names when one connection carries several bindings (agent forwarding), or what happens with a host key Larsal cannot check (RSA, P-384, P-521). | For each client connection Larsal opens one connection to the system agent and keeps it for the life of that client connection; every `session-bind@openssh.com` is checked by Larsal when it can (Ed25519, P-256), then forwarded on that connection, and the system agent's reply goes back. The question names the host of the last checked binding; when any binding on the connection says it is forwarded, the text says "‹program› wants to sign in to ‹host› through a forwarded connection." (new MI06-37). A binding Larsal cannot check leaves the host unknown (MI06-31). Tests: V-INT06-4 extended with `ssh -A` and with an RSA host key. |
| R06-3 | Requests on Larsal's socket that touch Larsal's own keys are forwarded: `ssh-add -d` (18) and `ssh-add -D` (19) through Larsal's socket leave Larsal's keys in place, and `ssh-add -x` (22) locks only the system agent while Larsal's keys stay usable. | 18 for a key Larsal's agent holds removes it there, drops its record and replies 6; 19 empties Larsal's agent and drops those records, then is forwarded; 22 and 23 are answered 5 and not forwarded (Larsal's agent has no agent lock; the vault lock does that job). Tests: three rows next to T55. |
| R06-4 | Self-loop: a user who points `SSH_AUTH_SOCK` (for example with `launchctl setenv`) or S-SSH-02 at Larsal's own socket makes Larsal's agent forward to itself, and Larsal's own adds go to Larsal's agent. | Before connecting, INT-06.13 also compares the target with Larsal's own socket (same device and inode); a match counts as "no system agent": Larsal's client requests show MI06-01, and Larsal's agent answers only for its own keys (5 for the rest). Test: S-SSH-02 set to Larsal's socket; load E3; sign through Larsal's socket; no hang, MI06-01, reply 5. |
| R06-5 | The same key in two entries, one that asks and one that does not (E1 and E2 in the demo vault), lands in both Larsal's agent and the system agent, so it can be used without asking. | A key lives in one place only: adding it to one agent first removes Larsal's own copy from the other (INT-06.16's "the last add decides" carried over to (b)), and the record notes where it now is. Test: unlock V with both E1 (asks) and E2 (does not); then only the system agent holds K1, without confirm; load E1 by hand; then only Larsal's agent holds it. |
| R06-6 | INT-06.34 lets Return choose "Allow Once". The dialog comes up without any action in Larsal, often while the user is still typing in a terminal, so a stray Return can allow a signature. | Keep "Allow Once" drawn as the primary button (frame), but Return and Space do nothing for the first second after the dialog shows; Escape and clicks on Deny work at once. Browsers delay the default button of their install and permission prompts by about one second for the same reason (for example the `security.dialog_enable_delay` preference, 1,000 ms). Test: a fake clock; Return at 0.5 s does nothing, Return at 1.1 s allows. |
| R06-7 | The settings frame says "For sk-ed25519 keys on a hardware key."; LD-101 (3) says user-facing text says "security key", and the provider also serves `sk-ecdsa` keys. | Change the line to "For keys that live on a security key." in the mockup, with the owner's approval together with D-INT06-7 (AT-K05). |


## E24-S1 proposed extension — 2026-11-05

Status: DRAFT, unadopted. Builds E24-S2/S3/S6/S7; order and primary source catalog in [research](../research/passkeys-and-ssh.md). No preceding implemented requirement, rule ID, T01–T74 or historical proof is edited. All new behavior that conflicts with E9 needs explicit Lead amendment; external proposed aftertexts assign no LD numbers. All cases below are new and unrun.

### E24 proposed rules

INT-06.E24.01 **Generation choices.** New SSH Key appears on the editor SSH page. Default Ed25519 (32-byte random seed, fixed 256-bit public encoding); no size picker for it. Offer ECDSA P-256/P-384/P-521 and RSA 3072/4096 as explicit choices, RSA 3072 initially selected when RSA chosen. No RSA 1024/2048 generation, DSA, hybrid or security-token key generation. E9's supported imported key forms/types remain eligible for the all-key agent and are not silently reduced to new-generation choices; missing implementations gate success. Source: [P10](../research/passkeys-and-ssh.md#p10).

INT-06.E24.02 **Crypto custody.** Generate, parse, derive public parts and sign only through approved larsal-crypto imports and OS random source. Reuse E9 ssh.rs, SecretBytes/SecretString, protected attachment and existing save operation; no subprocess makes keys, no home-made math/DER cipher/RNG. Key draft stays wipeable in Rust; Swift gets an opaque handle and public metadata only. RSA/P-384/P-521 and security-key sign wrappers require G03 before use; a missing dependency is not permission for a system-agent escape. Source: [P10](../research/passkeys-and-ssh.md#p10).

INT-06.E24.03 **Public comment.** Comment field starts empty, accepts at most 256 UTF-8 bytes and no line breaks/control/direction-override characters; rejects invalid text without silent rewriting. It is a public label, may be blank, and must not derive from protected username/password/path or OS login identity. Store chosen comment in OpenSSH private structure and public line after one separator when nonempty; literal text only. Changing comment revokes remembered approval/revision while keeping key identity. Source: [P10](../research/passkeys-and-ssh.md#p10).

INT-06.E24.04 **OpenSSH and saving.** New key is one-key openssh-key-v1 in the existing protected vault attachment, with correct public blob, check values, padding and chosen public comment using approved serializer. Unencrypted inner representation is allowed only inside Rust secret/vault protection, never a readable private-key disk file. The explicit Generate and Add Key action generates a Rust draft and commits it through normal atomic save; durable-save success is reported only after commit, never private export. Cancellation before commit discards the draft. Save to new attachment with collision refusal; replacement requires separate review and normal history rules. Cancel/editor close/lock wipes uncommitted draft; persistence failure preserves existing entry and reports unsaved state. Source: [P10](../research/passkeys-and-ssh.md#p10).

INT-06.E24.05 **Public result.** After durable save show algorithm/size, complete SHA256 fingerprint and OpenSSH public line from same key. Copy Public Key and Save Public Key are explicit public-only actions through existing APP-03/storage paths, with public comment disclosure and destination/overwrite review; no launch, clipboard or public file write just from opening panel. Public output remains readable after lock; it is not encrypted or recallable. Source: [P10](../research/passkeys-and-ssh.md#p10).

INT-06.E24.06 **Generation verification and races.** Each allowed generated key must be independently parsed by ssh-keygen -y and fingerprinted with -lf and authenticate to loopback sshd via the agent, using demo keys/private HOME and no private key disk output. A descriptor/pipe interoperability route must be proven before accepting S2; its feasibility is OPEN, not assumed. Bind generation/save to draft/vault revision; changes invalidate late results. No CLI/private-export workaround silently resolves the acceptance wording. Source: [P10](../research/passkeys-and-ssh.md#p10).

INT-06.E24.07 **One agent for all keys.** E24 proposes Larsal's own E9 agent as the only serving path for every enabled vault key, ordinary or ask-first. Do not send private add packets to another agent, proxy signing, merge foreign lists or silently select an on-disk key. Existing system-agent behavior .15–.30/.33/.36 is preserved but requires explicit Lead migration amendment. Existing external copies cannot be recalled; users must remove/revoke those separately. Do not contact/remove the owner's system agent automatically. Source: [P11](../research/passkeys-and-ssh.md#p11).

INT-06.E24.08 **Socket and protocol.** Reuse existing owner-only Unix socket in 0700 directory, socket 0600, same-user peer check and bounded E9 framing (256 KiB maximum, 2-second framing I/O; user decision has separate 60-second deadline). Enabling is opt-in, no TCP listener. Refuse self-loop, symlink/foreign-owner stale path and unexpected peer. Agent list returns only enabled live keys of unlocked vaults with public comments; locked returns empty and sign failure, never unlocks silently. Source: [P11](../research/passkeys-and-ssh.md#p11).

INT-06.E24.09 **Verified program identity.** Before every sign, obtain kernel peer identity, effective UID, process instance/start identity and executing code identity; bind to connection and revalidate immediately before signature release. Verify dynamic code with Security APIs/audit identity as P15; retain code requirement plus executable identity sufficient to reject replacement/update/exec. Display name/path is a hint only. PID reuse/name spoof/path match alone never authorizes. Exact race-safe API and invalidation guarantees are G04 OPEN; identity failure refuses sign with a visible explanation. Source: [P15](../research/passkeys-and-ssh.md#p15).

INT-06.E24.10 **Remembered approval tuple.** For ordinary keys show Deny (default), Allow Once and Allow Until Lock. A remembered grant is in Rust memory only for (user, vault session/generation, entry/key fingerprint and revision, verified live peer program instance and code identity, purpose). It ends at earliest lock/close/sleep/user switch/quit/feature-off, key lifetime/removal/edit/delete/recycle, approval revoke, process exit/restart/exec/code change or session loss. It survives new connections from that same verified live instance while these values still match, never across restarts/unlocks and never syncs. Source: [P16](../research/passkeys-and-ssh.md#p16).

INT-06.E24.11 **Ask-every-use and denial.** Preserve Ask before each use as the stricter per-key mode: only Deny and Allow Once, no remembered grant; switching it on clears earlier grants. Ordinary first sign also always asks. Deny, close, Escape, timeout or failed/cancelled fresh verification returns protocol failure 5 and signs nothing; no deny-cache silently turns into allow. Fresh Touch ID after E6-S3 signed availability, otherwise Rust vault-password verification for each new grant/Allow Once; unlock alone is not new-program approval. Source: [P16](../research/passkeys-and-ssh.md#p16).

INT-06.E24.12 **Approval purpose.** Separate remembered scopes for checked SSH authentication, git SSHSIG signing and unknown/general signing. Parse the entire bounded payload and match requested key/flags before labelling purpose; a caller-supplied description cannot upgrade arbitrary data to a known purpose. An unknown/unbound request may use Allow Once after showing Unknown purpose and verified local program, but cannot remember it. Git helper request must contain bound git namespace; ordinary SSH request may never reuse git approval. Source: [P13](../research/passkeys-and-ssh.md#p13).

INT-06.E24.13 **Forwarded use.** Track complete validated session-bind chain per connection including is_forwarding, duplicates and conflicting bindings; parse full SSH login and match session/user/key/host-bound key before calling it checked SSH authentication. Any forwarded request always asks Allow Once, shows Forwarded connection and verified local relay; remote program/hostname are unknown unless cryptographically bound and independently named from user-selected host data. Do not read ~/.ssh automatically. A session binding is not proof of remote program identity or a permission for arbitrary signatures. Source: [P12](../research/passkeys-and-ssh.md#p12).

INT-06.E24.14 **Authorization transaction.** Consent token binds exact data digest/length, key/entry revision, vault generation, peer instance/connection, parsed purpose/binding and original deadline. After UI verification, Rust rechecks the tuple, consumes once and signs that request only; check again before output. A changed request, key, vault, peer, connection or purpose fails and drops consent. Neither request IDs nor UI booleans can be replayed to sign a second payload. Source: [P11](../research/passkeys-and-ssh.md#p11).

INT-06.E24.15 **Lock and key lifetime.** Lock request immediately revokes grants and queued/in-flight use before saving/teardown; every key in own agent removed/wiped on lock regardless old remove-on-lock option. Deadline/lifetime checked at every authorization and release. Close, quit and feature-off act likewise; failures do not delay lock. E9's optional lifetime still limits key presence independently of approval. Never sign while locked or resume old request after unlock. A delivered signature cannot be revoked. Source: [P11](../research/passkeys-and-ssh.md#p11).

INT-06.E24.16 **Change and explicit revocation.** Settings lists in-memory grants by public key/fingerprint, verified program, purpose and Until lock, with Revoke and Revoke All; counts/status are public metadata. Revoke invalidates waiting completion tokens immediately. Any entry/key/settings edit, external file identity/content change, attachment deletion, recycle/delete, sync replacement or lost writable access invalidates that key's grants and loaded revision before further use; re-add requires current validated key and new approval. Mere comment changes revoke too. Source: [P15](../research/passkeys-and-ssh.md#p15).

INT-06.E24.17 **All-key backend matrix.** Final own-agent serving must cover existing E9 Ed25519, ECDSA P-256/P-384/P-521, RSA (SHA-2 flags only) and supported sk key handles. Hardware keys require an explicitly selected, reviewed provider and actual user presence; no auto-load of arbitrary library/path from imported data, no software substitution. RSA missing/both-conflicting/unknown flags fail; SHA-1 never used. DSA/old unsupported formats remain explicit E9 unsupported cases. P-384/P-521/RSA/sk backend/crypto/API reviews are G03 OPEN and block their success claims, not remove them from every-key acceptance. Source: [P10](../research/passkeys-and-ssh.md#p10).

INT-06.E24.18 **Management messages.** External agent protocol mutation cannot inject arbitrary private keys or load libraries into Larsal: add/constrained add, smartcard add/remove and unknown extensions fail; list/sign are supported, session-bind processed locally, remove key/remove all affects Larsal's own loaded set and revokes grants; lock/unlock agent protocol replies failure and directs to vault lock. No forwarding of management or extension messages. User-facing Remove All Keys wording explicitly limits scope to Larsal's loaded keys, requiring Lead amendment of old system-agent remove-all wording. Source: [P11](../research/passkeys-and-ssh.md#p11).

INT-06.E24.19 **Prompt, queue and keyboard.** One decision UI at a time, at most 4 pending per peer/16 globally; 60-second monotonic deadline from receipt includes queue. Flood fails boundedly without extending timers. Deny initially focused/default; Escape denies immediately. No incoming Return/Space used to approve; allow only deliberate focused activation after key-up and at least 1 second. Exiting process/disconnect/lock closes own question. Display the full selected public-key fingerprint, concrete local program/code hint, purpose, destination/unknown and grant duration; Git prompts also show the labelled payload digest and distinguish a verified local relay from an unknown direct caller; private material never appears. Source: [P17](../research/passkeys-and-ssh.md#p17).

INT-06.E24.20 **Git wire semantics.** Create OpenSSH SSHSIG v1 in namespace git, empty reserved field, SHA-512 by default (SHA-256 read/verify), with selected SSH public blob and correct algorithm signature. Sign the domain-separated SSHSIG structure containing digest of exact payload; never raw payload/hash alone, no newline/encoding rewrite. Output armored BEGIN/END SSH SIGNATURE, standard base64 wrapped at 76 columns and final LF. RSA signatures are rsa-sha2-256/512 only. Reuse approved Rust hashes/signers, not external signing process. Source: [P13](../research/passkeys-and-ssh.md#p13).

INT-06.E24.21 **Git helper contract.** Propose bundled executable larsal-sign as gpg.ssh.program; reuses Rust core/agent authorization and accepts OpenSSH-compatible -Y sign -n git -f PUBLIC_KEY [-U] [--] PAYLOAD_FILE. With file input create PAYLOAD_FILE.sig only after success, using safe no-link/new-file/owner-only output; stdout is empty. Input '-' reads bounded/streamed stdin and writes armor to stdout. Only exact public selector is accepted, never auto-read private paths. Do not choose the first available key, shell-expand values, download tools or access ~/.ssh. Cancel/deny/lock returns nonzero and creates no partial/new output; existing .sig untouched on collision/error. Source: [P14](../research/passkeys-and-ssh.md#p14).

INT-06.E24.22 **Verification helper behavior.** Because Git reuses gpg.ssh.program, larsal-sign must accept -Y find-principals, -Y verify and -Y check-novalidate with exact argument/stdin/output/exit semantics Git needs. Smallest proposal: delegate only these public verification modes via fixed absolute /usr/bin/ssh-keygen, argv without shell, bounded public files/input, no agent/private environment; validate platform tool supports options. Never delegate signing or private selectors. Unsupported installed verification version is a visible implementation gate; not a forged valid verdict. Preserve stderr/status Git uses, no secret logs. Source: [P14](../research/passkeys-and-ssh.md#p14).

INT-06.E24.23 **Git configuration and trust.** Settings shows reviewable repo-local recipe: gpg.format=ssh, gpg.ssh.program=<bundled larsal-sign>, user.signingkey=<chosen public .pub path or key:: public line>, commit.gpgsign=true; optional tag.gpgsign separate. Provide public key and optional allowed-signers example with explicit user principal and namespaces=git. No automatic global config/trust-store write. Signature proves possession, not hosting-account identity; verification needs gpg.ssh.allowedSignersFile and honors revocation/validity. Wrong key/untrusted principal is not success. Git signer approval does not imply repository contents were reviewed. Source: [P14](../research/passkeys-and-ssh.md#p14).

INT-06.E24.24 **Git request context.** Git helper uses authenticated local IPC, identifies itself and actual verified direct caller when available; do not call every request git because helper binary is trusted. Bind git purpose to parsed namespace/payload; show the full selected-key fingerprint, concrete requester/code hint and labelled payload digest. Distinguish a verified local relay from an unknown direct caller; unknown direct provenance offers only deliberate once or refusal, never a remembered grant. Repository/branch/message claimed through argv is an unverified hint; unknown repo remains Unknown repository. No inherited local generic or forwarded approval becomes git authority. Direct malicious helper invocations still trigger the same new-program/purpose authorization. Source: [P15](../research/passkeys-and-ssh.md#p15).

INT-06.E24.25 **Public key across surfaces.** Mac, extension, web vault and CLI show full public key, algorithm/size, SHA256 fingerprint and explicit public comment. Copy public key, copy fingerprint and save public .pub require user action; generic Show/private attachment/attribute/export/CLI modes expose no E24 private key. Web stays Rust/Wasm for vault operations and CSP; public DOM output is plain text. No browser/Web vault agent socket, local CLI execution, SSH login or signing server API is implied. Source: [P10](../research/passkeys-and-ssh.md#p10).

INT-06.E24.26 **Explicit extension fill.** Reuse E7 association/site access and browser-provided sender origin/frame IDs, no new permission model. Explicit Fill Public Key from trusted extension UI captures tab/frame/document/navigation generation, secure top origin and visible writable textarea/input selected by user on an add-SSH-key form. Show full origin, chosen key fingerprint and public-comment disclosure. Revalidate all target identity/visibility/focus immediately before filling; never auto-submit, generate key, fill private key or use title/classifier alone as authority. Same-origin form is supported; cross-origin/hidden/detached/read-only/sandboxed or changed target is refused with reselection. Source: [P17](../research/passkeys-and-ssh.md#p17).

INT-06.E24.27 **Management boundaries.** Passkey list/delete follows INT-04.E24.22; SSH entry edit/comment/delete uses existing model/save/recycle permissions from every surface. Proposed CLI larsal ssh list VAULT, larsal ssh public VAULT ENTRY_ID, larsal ssh new VAULT --type TYPE [--bits SIZE] [--comment TEXT], larsal ssh remove VAULT ENTRY_ID and larsal ssh approvals/revoke via authenticated local app, all public results only. New/remove require interactive confirmation or explicit --yes for mutating noninteractive use. Web/extension manage metadata/delete/public key; native generation/sign/agent setup and protected migration stay in capable native/Rust paths with honest unavailable states. No private export command. Source: [P11](../research/passkeys-and-ssh.md#p11).

INT-06.E24.28 **History and zero knowledge.** Private drafts and loaded keys never leave Rust outside protected vault/exchange storage; Show exception remains only original user-selected single field and grants no private SSH-key output. Key deletion/revoke prevents future agent uses but does not erase encrypted history/backups or revoke public key at remote hosts; disclose and offer existing history/entry controls. Sync/server stores only existing encrypted vaults/wraps; no new password hash, verifier, escrow or sign endpoint. A hostile server still cannot test account-password guesses under LD-340. Source: [P16](../research/passkeys-and-ssh.md#p16).

INT-06.E24.29 **Accessible states and errors.** Use Option A shared tokens/fonts/icons, both themes. Label algorithm, size, public comment, full key/fingerprint, origin and approval duration; default Deny/Cancel for destructive/new-authority decisions; keyboard/VoiceOver all controls, semantic busy/error status, reduced motion and long-text wrapping. Fixed messages distinguish Key not saved, Key type needs a reviewed signing backend, Program identity could not be checked, Vault locked, Request expired, Request denied, Destination changed and Signature could not be made. No private parser text or assumed capture exclusion; APP-10 adopted limits hold. Source: [P17](../research/passkeys-and-ssh.md#p17).

INT-06.E24.30 **Draft and regression boundary.** All additions and modified-behavior proposals remain DRAFT for E24-S2/S3/S6/S7. .44/T67 (no generator), old system-agent routing/lock retention/ask-every-use scopes and existing verified E9 results are unchanged historical contracts until Lead explicitly adopts amendments. Every new case must have later positive/negative proof and a private-copy removal control where security relevant. Missing identity/backend/hardware/verification capability cannot close full E24 acceptance. Second Spec and independent Verify are separate people after this draft. Source: [P11](../research/passkeys-and-ssh.md#p11).

### E24 rule-to-case map and cases

Demo keys only, private HOME/repo/pasteboard and throwaway agents/loopback hosts, after separate implementation authorization. No owner SSH folder/agent/keychain or real credentials. All mutation controls in private proof copies. A described expected success is not a run result.

| Case and rule | Given | When | Then |
|---|---|---|---|
| E24-S01 · INT-06.E24.01 | blank editor and each algorithm selection; invalid size and hardware/DSA request | choose New SSH Key | Ed25519 default; ECDSA has exactly three sizes, RSA exactly two; invalid generation refused before work; supported imported-key serving obligations remain present. |
| E24-S02 · INT-06.E24.02 | RNG failure, key-generation failure and approved signer instrumentation | create each supported key | Fail closed with no attachment/file/UI secret on failure; success public key corresponds to Rust private value; dependency gate unmet remains unresolved, not a narrower PASS. |
| E24-S03 · INT-06.E24.03 | empty comment, valid Unicode label, 257-byte label, newline and protected username | generate or edit comment | Blank/valid label retained exactly, invalid labelled error and no generation; public output contains only explicit comment, no protected fallback. |
| E24-S04 · INT-06.E24.04 | existing key attachment, duplicate name, disk failure, successful atomic save and cancel | Generate and Add Key | Valid OpenSSH key inside encrypted saved vault; old attachment unchanged on failure/cancel, no private file/temp; draft wiped; replacing a key never happens by name collision. |
| E24-S05 · INT-06.E24.05 | saved key for every generated algorithm and public destination collision | copy/save public part; later lock | Exact public blob/comment and fingerprint; private markers absent; collision asks before replacement; no action before explicit click; copied/saved public material persists as disclosed. |
| E24-S06 · INT-06.E24.06 | each algorithm/size with independent parser; lock/cancel while RNG/sign/save worker completes | execute S2 success and controlled race cases later | Parser/public/fingerprint/auth all agree; no private disk file; late result dropped on stale generation; unavailable harness/backend remains OPEN/FAIL, never skipped PASS. |
| E24-S07 · INT-06.E24.07 | normal key, ask-first key, duplicate public key and an unrelated external-agent key | enable E24 and request list/sign | Only eligible Larsal keys listed/served, private data never forwarded; no connection to system agent, no deletion of unrelated keys; external-copy caveat visible. |
| E24-S08 · INT-06.E24.08 | socket replacement/foreign owner, framing oversize, partial frame and locked vault | connect/list/sign | Safe peer receives public eligible list only; malformed/unsafe connection bounded/refused; no prompt-to-unlock side effect and no private output. |
| E24-S09 · INT-06.E24.09 | same name/path from two processes; PID reuse, exec and modified executable at barriers | request sign and revalidate peer | Fresh verified program gets question; no old permission reused by impostor/new image; disappearance/revalidation failure signs nothing; API uncertainty remains unresolved rather than trusting name. |
| E24-S10 · INT-06.E24.10 | same live peer reconnects; a second/restarted peer; lock/unlock or code update | Allow Until Lock then sign repeatedly | Same bounded tuple signs without second question; each changed tuple prompts anew; no persistent/synced grant; no Grant All Programs action. |
| E24-S11 · INT-06.E24.11 | ordinary first request; ask-every-use key with old ordinary grant; cancelled Touch ID/password | Allow Once/Deny/timeout then retry | Allowed request signs exactly once after valid verification; every ask-first use asks; deny/failure signs nothing and retry never inherits consent. |
| E24-S12 · INT-06.E24.12 | one program with SSH grant submits git SSHSIG and arbitrary data; wrong-key payload | request new purpose | Distinct purpose prompts; arbitrary or malformed data never inherits a grant; unknown purpose offers only deliberate once, no fabricated host/repo claim. |
| E24-S13 · INT-06.E24.13 | two-hop checked bindings; wrong signature/session, duplicate binding, unbound forwarded data and local approved ssh relay | try remote authentication and general signing | Forged/mismatched chain fails; valid forwarded demo login can succeed only after per-use approval; no local remembered grant authorizes remote requests; unknown remote labels stay explicit. |
| E24-S14 · INT-06.E24.14 | digest/key/purpose/connection substitution at pre-approval/pre-sign/pre-release barriers | approve then race substitutions or replay token | One exact request may succeed; every stale/substituted/replayed path produces no signature and requires a new review; owned buffers wiped. |
| E24-S15 · INT-06.E24.15 | loaded ordinary/ask-first keys with remove-on-lock false; in-flight sign and expired lifetime | lock at barriers then unlock | No key/grant/signature after revocation; removal within original 1-second obligation measured later; failed cleanup reported without holding lock; new unlock requires new approval. |
| E24-S16 · INT-06.E24.16 | approved key edited/deleted/recycled/replaced by sync or selected file changed; grant revoked while sign awaits | sign again | Old revision is unusable immediately, late completion fails; unrelated keys remain; newly validated revision requires fresh approval and removal cannot leave a loaded stale key. |
| E24-S17 · INT-06.E24.17 | one demo of each existing supported type; valid RSA 256/512 flags, absent/unknown flags; absent hardware/provider | sign through own agent and compare independently | Every supported ready backend signs correctly after approval; SHA-1/bad flags refused; unavailable backend shows exact unmet gate, with that positive case still OPEN; no private forwarding. |
| E24-S18 · INT-06.E24.18 | messages 17/25/20/26, 18/19, 22/23 and unknown extension | send against isolated own socket | Injection/provider load/agent unlock refused with no side effect; own remove operations drop key/grants, keep unrelated external keys; known session-binding responses respect exact validation. |
| E24-S19 · INT-06.E24.19 | flood while terminal Return is held, timeout in queue, peer disconnect and key switch | show prompt and attempt early/default confirmation | No unintended sign, Deny reachable immediately, bounded queue; one correct prompt with full selected-key fingerprint, concrete requester/code hint, purpose/duration and labelled Git digest, long values readable, same deadline and no private content in accessibility tree; approved focused activation after guard succeeds. |
| E24-S20 · INT-06.E24.20 | binary commit/tag payload including NUL/newlines; wrong namespace/version/hash/key variants | sign then independently verify | Exact original payload verifies using OpenSSH and git; any payload/namespace/key mutation fails; no raw signature passed as SSHSIG, no SHA-1. |
| E24-S21 · INT-06.E24.21 | Git 2.56 invocation file/stdin modes, spaced names/--, output collision/link and unmatched public selector | run helper with demo isolated agent | Git reads correct .sig for file mode; stdout armor only for stdin; no private file/read, overwrite or shell execution; all failures nonzero and no partial artifact. |
| E24-S22 · INT-06.E24.22 | Git calls all three verification modes with allowed signers, time and revocation options; missing/old verifier | verify demo commit through helper | Valid/trusted case passes; invalid/untrusted/revoked/wrong namespace fails appropriately; no vault unlock or agent connection during verification; unsupported tool reports failure without signing. |
| E24-S23 · INT-06.E24.23 | throwaway repo and HOME, explicit allowed signers, valid/revoked/wrong principal/key and changed payload | sign commit/tag and run git verify-commit plus ssh-keygen -Y verify | Both accept correct trusted demo key; all negative cases fail; owner's/global config untouched; recipe paths/quoting exact, no private file. |
| E24-S24 · INT-06.E24.24 | malicious direct helper caller supplies trusted program/repo labels; actual Git parent exit/reuse | request signature | No label spoof earns approval; verified caller/code/lifetime checked; unknown provenance once-only or refused, no remembered grant based on repo path; normal Git succeeds with honest context; the frame and live prompt distinguish verified local relay from unknown direct caller and show full selected-key fingerprint, requester/code hint and labelled digest without implying Git-parent identity. |
| E24-S25 · INT-06.E24.25 | same saved demo key on all four surfaces; generic attachment/show-protected/export requests | display/copy/save public and ask for private | Public values identical and independently parseable; no private key bytes in DOM/JSON/stdout/errors/files; unsupported native actions explained with route to app without secret handoff. |
| E24-S26 · INT-06.E24.26 | Chrome/Safari add-key demo form; overlay, cross-origin iframe, hidden/read-only field and navigation/focus swap | select public key and activate Fill | Exact public line in only reviewed field for stable secure target, input event for form state, no submit; every hostile/changed target gets no fill and accessible Pick Field Again. |
| E24-S27 · INT-06.E24.27 | all surfaces with read-only/locked vault; CLI invalid flags/type, noninteractive mutation and absent local app | list/edit/delete/generate/revoke | Allowed metadata/public ops succeed; writes honor vault rights/atomic save; invalid/locked/absent app errors fixed, no private output; unavailable path does not satisfy the native positive case. |
| E24-S28 · INT-06.E24.28 | deleted/replaced key with history and hostile server dump; malformed generic reveal requests | lock/delete/sync and inspect every output | No private bytes/server verifier; old loaded revision unusable; history retention and remote revocation separate; public copied data not mislabelled secret-wiped. |
| E24-S29 · INT-06.E24.29 | each new frame both themes, keyboard-only/VoiceOver and long values; generation/agent/helper error fixtures | complete/cancel actions and resize/text-size change | Reachable visible focus/actions and accurate status, no clipped full identity on review, no color-only state; no secret in UI/accessibility/log/capture; native behavior still requires device proof. |
| E24-S30 · INT-06.E24.30 | unchanged old card/tests and this proposed appendix only | assess readiness and claim success | No old case renamed/recounted as E24 proof, no story Done/board/parity changes; conflict register and gates supplied for selective Lead adoption. |

### E24 frame links

[Frame coverage](../research/passkeys-and-ssh.md#frame-coverage) maps every new state, including [New SSH Key](../../design/option-a/proposals.html#e24-s1-new-ssh), [program approval](../../design/option-a/proposals.html#e24-s1-ssh-approval), [git setup](../../design/option-a/proposals.html#e24-s1-git-setup) and [public-key fill](../../design/option-a/proposals.html#e24-s1-fill-public-key). Static proposals execute no key generation, authentication, signing, fill, copy or revocation. Existing locked/proposed frames remain exact.


## E24-S1 review and adoption record

2026-11-05: the exact revised specification and static proposals received fresh second Spec and independent Verify APPROVE, with R1–R4/N1 closed. The sealed pre-adoption complete source manifest is `8e0f22f647e509c5263995837624f57a5b2f6fb136a8b7f8c28c87ae54a1f4a1`; second Spec seal `5d3c7d944de41b109064b0d3cf51ec8b10c68825dc6c89a8962c48e762a91091`; Verify seal `f345bd00ee81226d2219d17909092c3b686d2be29850231feeb380e19c6d0dc2`. Proof covers56 rule/case/source pairs,112 fresh removal controls,80 themed source-bound PNGs plus2 accepted long captures and129 older frames/rectangles preserved per theme. Verify corrected contact-sheet accounting without changing the images or earlier proof. The full canonical frozen-source guard passed11604 scanned files plus19 vault names; actual-current adoption guard remains Root's separate requirement.

The DRAFT/unadopted status labels in the sealed appendices describe their pre-adoption state. This record and LD-380–396 adopt their written contracts only and explicitly supersede the listed legacy clauses for E24 implementation; historical rules/cases/proof keep their old scope. AT-KEY-01–18 and KEY-P1–7 are final catalog IDs with all runtime proof OPEN/todo. All17 acceptance conflicts remain visible in those rulings and their implementing gates; no successful capability is waived. G01–G05, Apple receiver identity, private Data/copy/transport custody, provisioned signing, signer backends, peer identity, descriptor feasibility and every implementing positive/hostile/removal/native/AX/capture obligation remain OPEN. Static evidence proves no running provider, exchange, generation, signing or secure custody. Detector/storage/bootstrap findings remain recorded externally. Original187-story scope, E24 Order and all S2–S7 acceptance/status lines are unchanged. Root closes only S1 after selective current-source equality, actual-current canonical guard and its owner-only commit; no implementation or runtime PASS follows.

# Test data

Demo vaults for tests, made by the reference CLI, and the expected content of each vault as JSON.
Everything here is demo data: fake passwords, fake names, `example.com` addresses. Never put a real vault here.

## Make and check

The scripts need the reference CLI. Set `REF_CLI` to its path in your shell (never write it into a file).

```
REF_CLI=<path to the reference CLI> scripts/make-testdata.sh            # remake everything in testdata/
REF_CLI=<path to the reference CLI> scripts/make-testdata.sh --verify   # check; exit 1 on any difference
```

- `scripts/testdata/make_inputs.py` writes fixed XML documents (fixed UUIDs, fixed times, fixed demo values) into a temp folder, and writes the fixed key files. The XML documents are deleted after the run; none is stored in the project.
- The reference CLI's `import` turns each XML document into a vault, then its `export` writes the vault back out as XML, and `scripts/testdata/to_json.py` turns that into `<vault>.json`.
- After making each key file vault, the script opens it again with a file that holds just the 32 raw key bytes the key file should give. This proves the CLI read each key file as the kind its name says (and did not, for example, hash a hex file).
- `make_inputs.py` also writes the list of attachments in each XML document. For every vault, the script reads each listed attachment back with the CLI's `attachment-export` and compares it byte for byte with the bytes `make_inputs.py` wrote. Today only `rich-v3` and `rich-v4` have attachments.
- Both modes build everything in a temp folder. The normal mode copies it into `testdata/` only after every vault and check succeeded, so a failed run leaves `testdata/` as it was.
- `--verify` checks: the fixed key files are byte-identical, the fresh vaults export to the stored JSON, the stored vaults still export to the stored JSON, the stored rich vaults hold the right attachment bytes, and `testdata/` holds exactly the files a run makes plus this README.
- Vault bytes change on every run (fresh salts and random values). The content does not.
- A full run takes about 10 seconds.

## Vaults

All vaults use the cipher and key derivation the reference CLI offers. It has no option to pick them: the help of `import` and `db-create` lists only key file, password and decryption time options, and `db-edit` only key file, password and hardware key options; none picks the cipher, key derivation or version. `db-info` reports:

- Cipher: AES 256-bit
- Key derivation: AES-KDF
- Compression: gzip (header compression flag 1; read from the header, not from `db-info`)

"Version" is the file format version from the vault header (bytes 8 to 11). The CLI writes version 3.1 unless the content needs 4.x fields; then it writes 4.0 or 4.1 (group custom data alone gives 4.0; FMT-01.25).
"Rounds" is the AES-KDF round count. With `-t 100` the CLI benchmarks this Mac for a 100 ms unlock, so the count changes from run to run (about 13 million). Without `-t` it uses its default, a fixed 1,000,000 rounds, with no benchmark.

| Vault | Password | Key file | Version | Rounds | Content |
|---|---|---|---|---|---|
| `password-only.appvault` | `demo-pass-1` | none | 3.1 | `-t 100` | basic |
| `keyfile-binary32.appvault` | none | `key-binary32.appkey` | 3.1 | `-t 100` | basic |
| `keyfile-hex64.appvault` | none | `key-hex64.appkey` | 3.1 | `-t 100` | basic |
| `keyfile-hashed.appvault` | none | `key-hashed.appkey` | 3.1 | `-t 100` | basic |
| `keyfile-xml-v1.appvault` | none | `key-xml-v1.appkey` | 3.1 | `-t 100` | basic |
| `keyfile-xml-v2.appvault` | none | `key-xml-v2.appkey` | 3.1 | `-t 100` | basic |
| `keyfile-cli-made.appvault` | none | `key-cli-made.appkey` | 3.1 | `-t 100` | basic |
| `password-and-keyfile.appvault` | `demo-pass-2` | `key-hex64.appkey` | 3.1 | `-t 100` | basic |
| `default-time.appvault` | `demo-pass-3` | none | 3.1 | default (1,000,000) | basic |
| `rich-v3.appvault` | `demo-pass-4` | none | 3.1 | `-t 100` | rich, fields a 3.1 file holds |
| `rich-v4.appvault` | `demo-pass-5` | none | 4.1 | `-t 100` | rich, plus fields only 4.x holds |
| `big-10000.appvault` | `demo-pass-6` | none | 3.1 | `-t 100` | 10,000 small entries |

"none" in the Password column means the vault has no password at all (open it with the key file only).

### Option A demo vaults (made by our own code)

The screens' demo data (design/option-a/mockup.js: the Personal vault with its 25 entries, groups, tags, codes and passkeys; Work; an empty Family vault). Made by `cargo test -p app-ffi --test option_a -- --ignored make_option_a_vaults` (Argon2id, 1 MiB, 2 passes: demo vaults for screen tests), checked by the other tests in `crates/app-ffi/tests/option_a.rs`. The snapshot tests copy them to `target/option-a/Passwords/` as `Personal.appvault`, `Work.appvault` and `Family.appvault`. Not made by `scripts/make-testdata.sh` and not in its `--verify` list.

| Vault | Password | Version | Content |
|---|---|---|---|
| `option-a-personal.appvault` | `demo-pass-7` | 4.1 | the mockup's Personal vault: 23 live entries, 2 in the recycle bin, 7 groups, tags, 7 one-time codes, 4 passkeys, a card, a Wi-Fi entry, an SSH entry with a demo public key, site access hosts on GitHub, Google, Figma and Amazon, two connected browsers (Firefox on MacBook, Safari) with demo keys (E5-S7 Browser report); public colour `#22a6bd`, icon 0 |
| `option-a-work.appvault` | `demo-pass-8` | 4.0 | one entry; public colour `#ff9500`, icon 1 |
| `option-a-family.appvault` | `demo-pass-9` | 4.0 | empty, as right after the new vault wizard; public colour `#f2385a`, icon 2 |
| `option-a-work-key-change.appvault` | `demo-pass-8` | as Work | the Work vault after one App save with the force-once request on (`MasterKeyChangeForceOnce`, MOD-13.13): it asks for a new master key at the next unlock (the forced prompt, MOD-13.8, F-074). Made by `cargo test -p app-ffi --lib make_key_change_forced_vault -- --ignored` |

Fake data only: the names, addresses and passwords are the mockup's demo values; the one-time code secrets (`DEMOGITHUB234567` and the like) and the SSH key are our own demo values; the "private key" attachment is filler text.
Each vault `<name>.appvault` has its expected content in `<name>.json`.

### Content

- **basic**: database "Demo"; one group "Demo" with one entry "Demo login" (user `demo-user`, password `demo-entry-pass-1`, a URL and a one-line note).
- **rich-v3**: database "Rich demo" with a description, default user name and color.
  - Nested groups: Rich demo > Work > Servers > Old servers, and Personal. "Work" has auto-type and search turned off, is collapsed, has its own auto-type sequence and a custom icon.
  - "Full demo entry": all five standard fields; multi-line notes; protected custom fields `Demo PIN` and `otp` (TOTP as an `otpauth://` URI); unprotected `Demo hint`; an empty custom field; a value with leading and trailing spaces; tags `demo,work`; expiry on 2025-06-30; custom icon; colors; override URL; auto-type default sequence and one window association; three attachments: `notes.txt` (text), `bytes.bin` (all 256 byte values), `empty.bin` (0 bytes); three older versions in history.
  - "Shared attachment 1" and "Shared attachment 2": each has `shared.txt` with the same content (stored once in the file).
  - Unicode title in Latin, Greek, Cyrillic, Hebrew, Arabic, Devanagari, Japanese, Korean, Chinese and an emoji; unicode user name and password.
  - XML special characters: `< > & " '` and `]]>` in title, password and notes.
  - An entry with every standard field empty.
  - Recycle bin (enabled) holding a deleted entry and a deleted group with an entry inside.
  - One deleted-object record (a UUID and a deletion time).
  - Custom data on the database ("demo-meta-key").
- **rich-v4**: the same as rich-v3, plus 4.x fields: custom data on the root group and on "Full demo entry", the custom icon's name and time, "exclude from reports" on "Full demo entry", tags on the "Work" group, and the previous parent group of the two deleted items.
- **big**: database "Big demo"; one group with entries "Entry 00001" to "Entry 10000", each with a user name (`user00001`) and password (`demo-pw-00001`).

All times are fixed in 2024. Fields never set (for example the last selected group) export as the all-zero UUID.

## Key files

| File | Kind | What it holds |
|---|---|---|
| `key-binary32.appkey` | 32-byte binary | 32 fixed bytes, used as the key as they are |
| `key-hex64.appkey` | 64 hex characters | exactly 64 bytes of hex text, no newline; the key is the 32 bytes the hex spells |
| `key-hashed.appkey` | any other file | one line of text; the key is the SHA-256 of the whole file |
| `key-xml-v1.appkey` | XML key file, version 1.00 | the 32 key bytes in base64 |
| `key-xml-v2.appkey` | XML key file, version 2.0 | the 32 key bytes in hex, with a check value (first 4 bytes of their SHA-256) |
| `key-cli-made.appkey` | made by the reference CLI | 128 random bytes, so it is the "any other file" kind (SHA-256 of the file) |

The reference CLI opens all six, but warns that `key-binary32`, `key-hex64` and `key-xml-v1` use an old key file format. It does not warn for `key-hashed`, `key-xml-v2` or `key-cli-made`.

The first five are written from fixed demo bytes on every run. `key-cli-made.appkey` is random, so the script makes it once (with the CLI's `db-create --set-key-file`) and reuses it; delete it only if you also remake every vault.

## The JSON files

`to_json.py` turns the XML export into JSON by these rules, so any test can rebuild the same JSON from its own reading of a vault:

- An element with no attributes and no child elements becomes its text (`""` when empty).
- Any other element becomes an object: `"@name"` for each attribute, `"#text"` for the text of an element without child elements, and one key per child element name: the child's value when the name appears once, a list in document order when it appears more than once.
- The top level is `{root element name: object}`.
- Keys are sorted; two-space indent; UTF-8.
- The creator field (`Meta` > `Generator`) is dropped.
- Any key or string that contains a banned word (see the name guard) is written as `"hex:"` plus its UTF-8 bytes in hex. Today that is the root element name and one custom data key. Nothing is dropped for this reason.

Normalized, because the reference CLI changes them on every save:

| What | Why |
|---|---|
| The order of the items in every `CustomData` block: sorted by `Key` | the CLI writes custom data items in a different order each time |
| Custom data item `_LAST_MODIFIED`: every field but `Key` is `"normalized"` | the CLI stamps it with the save time, on the database and on every group or entry that has custom data |
| Any custom data item whose key ends in `_RANDOM_SLUG` (today only on the database; its key is stored as `hex:`): every field but `Key` is `"normalized"` | the CLI fills it with new random bytes on every save |

Nothing else is changed. `--verify` proves every other field is the same on every run.

## Things to know when you use these files

- **Times.** In 3.1 exports times are text (`2024-01-01T00:00:00Z`); in 4.1 exports they are base64 of a little-endian count of seconds since year 1 (`gPcj3Q4AAAA=`). The JSON keeps what the CLI wrote.
- **Attachments in 3.1.** The export holds them in `Meta` > `Binaries`, gzip-compressed and base64-encoded (`"@Compressed": "True"`); entries point at them by `@Ref`.
- **Attachments in 4.1.** The CLI's XML export of a 4.x vault leaves the attachment bytes out and writes every reference as `Ref="0"`. So in `rich-v4.json` each attachment's name is right, but its `@Ref` is not a real index and its bytes are missing. The bytes are checked another way: the script reads each `rich-v4` attachment back with `attachment-export` and compares it with the input bytes, which are the same as in `rich-v3.json`. So take the bytes from `rich-v3.json`.
- **Protected values.** The export writes protected values as plain text with `ProtectInMemory="True"`.
- **Tags.** The CLI rewrites the tag separator `;` to `,`.
- **Size.** `big-10000.json` is about 14 MB.

## Variants the reference CLI cannot make

The CLI has no cipher or key derivation option, so these come later, from another source, per the interop matrix in spec card FMT-01:

- the ChaCha20 and Twofish ciphers;
- the Argon2d and Argon2id key derivations;
- version 4.0, and 4.x with anything but AES-256 and AES-KDF;
- vaults without compression, and other settings it does not expose;
- hardware key (challenge-response) vaults;
- attachment bytes for 4.x vaults in the XML export (see above; `attachment-export` covers them).

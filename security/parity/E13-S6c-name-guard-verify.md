# E13-S6 parts c and c2: name guard Verify (2026-10-30)

Verify agent for the name guard rows of E13-S6 parts c and c2 (story E0-S3, check AT-J06). I did not build or check the guard. I did not open the reference source or run the reference app. The banned list was read only from the guard's own WORDS_HEX, as the setup lines at the top of security/findings.md do. No helper agents, no scripts/check.sh, no cargo, no xcodebuild.

**Verdict: signed (13 re-tested).** All 13 rows were re-tested with their own steps. Every repro gives names: FAIL, exit 1, and every clean root gives names: PASS, exit 0.

- 7 rows pass every check and are set to "fixed, re-tested (Verify 2026-10-30)": F-013, F-017, F-020, F-031, F-115, F-119, F-120.
- 6 rows pass their steps, but at least one mutant of their fix passes the self-test: F-014, F-015, F-016, F-018, F-019, F-121. The task requires every mutant to fail the self-test, so their status is left alone.
- Each of those gaps, and one Known limits gap (a compressed format the guard does not know), is Low. All are ordinary_work false: the guard catches each form today, and only a later edit that broke it would go unnoticed. Under LD-233 (3) they are listed below for Known limits (or one self-test line each). Nothing is an ordinary-work gap.

## Setup

- Guard under test: `scripts/check-names.sh`, SHA-256 `0b6dbde46e895766637adbf07de71ef335fb223f774dd5cfc9b65dcde3dd5d3a`.
- Private copy: `rsync -a --exclude target --exclude larsal-shots` to `/tmp/e13s6c-verify-copy` (143 MB). Its guard is `cmp`-identical to the shared one.
- W = banned word 1, decoded from WORDS_HEX; h = its first 3 letters, t = the rest. My driver (`/tmp/e13s6c-verify-work/drive.py`) reads them the same way and never holds them as text.
- Each repro uses a new folder `/tmp/e13s6c-verify-r/rNNN` with an empty AGENTS.md:
  1. Run the guard on the clean folder: expect names: PASS, exit 0.
  2. Plant one probe and run the guard again ("after"): expect names: FAIL, exit 1.
  3. Run the "before" guard on the same folder. "Before" is the shared guard with that row's whole fix undone, kept as a patched file in `/tmp/e13s6c-verify-work/before/<row>.sh`.
- Mutants: I patch the private copy's `scripts/check-names.sh`, run `--self-test`, then copy the shared file back and run `cmp`. All 91 restores gave "same".
- Nothing was planted in the shared tree. Only my own processes were stopped, by PID. All my /tmp folders are deleted at the end.

## Whole-guard checks

| Check | Command | Result |
|---|---|---|
| Self-test, shared guard | `scripts/check-names.sh --self-test` | self-test: PASS, exit 0; step 1: 114 hits; step 2: 0 hits, 7 files scanned, 1 name-only; step 4 peaks 1.3, 16.9, 18.9, 18.0, 26.4, 16.9, 0.3 MB; 2.81 s user, 4.38 s real |
| Full scan, shared tree | `/usr/bin/time -l scripts/check-names.sh` | names: PASS (3183 files scanned, 16 vault files name-only), exit 0; **13.49 s user**, 22.52 s real, 310 MB max RSS (load average 14 to 19 at the time) |

**Fails closed.** Each case below gives names: FAIL, exit 1 (fresh /tmp roots):

- Unreadable input: a file with mode 000, a folder with mode 000, a folder with mode 444 ('cannot read (Permission denied)').
- Bad roots: a missing root, a root with 0 files, a root that is a file.
- Broken or truncated archives, each a 'cannot unpack' hit naming the error:
  - broken gzip; truncated gzip of W; gzip with trailing junk (BadGzipFile);
  - truncated bzip2; truncated xz;
  - truncated zip (BadZipFile); a zip member encrypted with a demo password (RuntimeError); a zip member in deflate64 (NotImplementedError).
- Too deep: gzip nested 9 deep ('nested too deep').
- Unsupported packing: a zstd frame; a Brotli *.br file; a WOFF2 header not on the allow list; an allowed font with one byte changed. Each gives 'zstd or Brotli data, which python3 cannot unpack'.
- Too large: a 4 GiB gzip of zeros, and 64 MB of zeros as gzip, bzip2, xz and zip ('unpacks past 16 MB').
- No interpreter: a copy whose python3 path does not exist exits 127.

**Run time** (shared guard, one 1 MB file per root, user seconds), all linear:

| Input | Result | User s |
|---|---|---|
| 500k `ESC [` | PASS | 0.87 |
| 1M `ESC` | PASS | 0.95 |
| 500k `ESC BEL` | PASS | 1.09 |
| 500k `x BS` | PASS | 0.77 |
| 100k CR lines | PASS | 0.63 |
| unclosed OSC of 1 MB | PASS | 0.68 |
| 2 MB base64 run of random bytes | FAIL | 1.46 |
| 333k `%41` | PASS | 0.53 |
| 333k `<a>` | PASS | 0.54 |
| 200k `ESC [ CAN ESC P SUB` | PASS | 0.84 |

The 2 MB base64 run gave false hits on two 4-letter words. Random bytes give false hits, as the header says, and a false hit fails safe.

## F-013: Latin-1 soft hyphen byte

- Steps: h, the byte \255, then t, in a .txt file. Also a cp1252 .md file with other 8-bit letters before it.
- Before (\xad drop undone): PASS, exit 0 for both.
- After: FAIL, exit 1 ('content holds word 1') for both.
- Mutant M01 (no \xad drop): self-test FAIL, 'missed case: F-013 Latin-1 soft hyphen byte'.
- Result: **pass**.

## F-014: UTF-16 with no NUL and no BOM

- Steps: W in fullwidth letters, in four forms: UTF-16LE, UTF-16BE, and each after a 1-byte prefix (odd offset). For each form I checked that the data holds no NUL and no BOM.
- Before (UTF-16 decoded only when a NUL is present): PASS, exit 0 for all 4.
- After: FAIL, exit 1 for all 4.
- Mutants:
  - Killed: M02 (UTF-16 only with a NUL; 'missed case: F-014 UTF-16 fullwidth letters, no NUL or BOM') and M05 (UTF-16BE only).
  - **Survived**: M03 (UTF-16 at alignment 0 only) and M04 (UTF-16LE only). The self-test case is little-endian at offset 0, so nothing pins the other byte order or the odd alignment. M03 misses the odd-offset probe and M04 misses the UTF-16BE probe (PASS, exit 0); the shared guard gives FAIL on both.
- Result: steps pass; **mutant check fails** (finding V-1). Status left alone.

## F-015: characters that hide only in a terminal

- Steps: the row's three forms (an ANSI color code, a backspace overstrike, a hair space U+200A).
- Also re-run:
  - Checker round 3's 13 repros (security/parity/E13-S6c-checker-r3.md), plus the carriage return inside a CSI and the OSC ended by BEL;
  - the round 2 and round 3 repros: ESC CR [; ESC CR [ after a DCS body and after an OSC body; ESC BEL BS [; plain BEL BS; ESC BEL BEL [; ESC BEL DEL [;
  - 8-bit CSI, OSC, DCS, SOS, PM and APC; the typo fixed with backspaces; a CR overwrite; a color code in a file name.
- Before (whole terminal view undone: no TERM, ESC_C0 or overstrike view, NARROW not applied): PASS, exit 0 for every one.
- After: FAIL, exit 1 for 32 of the 34. The other two are Checker round 3 repros 5 (h ESC BEL X t) and 7 (h ESC DEL X t), which give **PASS, and that is correct**:
  - In the vte-style table the Checker cited (`anstyle-parse-1.0.0/src/state/codegen.rs`, Escape state), a C0 inside an escape runs without changing the state, DEL is ignored, and 0x58 'X' goes to SosPmApcString. So ESC BEL X opens an SOS string, and a terminal hides t as well.
  - The guard reads it the same way since part c2 round 2 (ESC_C0).
  - The same forms with a real final byte (ESC BEL B, ESC DEL B, ESC BEL ( B) and ESC BEL X with an ST before t give FAIL, exit 1. Plain ESC X gives PASS, the same as with BEL.
  - The row's proof still says all 13 repros give FAIL, which round 2 made stale (open issue 1).
- Mutants:
  - Every mutant the row names is killed: no C0 in CSI (M07), no C0 in ESC (M08), CAN not ending OSC (M09), SUB not ending DCS (M12), CSI final byte required (M14), C0 dropped instead of kept (M16), DEL out of C0 (M17), BEL out of C0 (M18), BEL not ending OSC (M19), and \x98, \x9e, \x9f dropped (M20 to M22).
  - Round 2's mutants are killed too: no ESC_C0 (M26), the run moved without ESC \ (M27), the run dropped (M28), DEL out of ESC_C0 (M29), ESC_C0 without '+' (M30), no column drop (M31), STILL without C1, DEL or BEL (M32 to M34).
  - Also killed: the whole fix undone (M06), CAN and SUB inside the C0 class (M13), \x90, \x9d and \x9b dropped (M23 to M25), no terminal view (M35), backspace or CR not moving (M36, M37), MOVE without a lone CR (M38), hair space out of NARROW (M39), NARROW not applied (M40), file names without the shown view (M41).
  - M42 (terminal view drawn one character at a time, quadratic) never ends the self-test. I stopped it by its PID after 8 min. It never passes, but the linear-time case catches it by hanging, not with a 'missed case' line.
  - **Survived**: M10 (SUB not ending an OSC), M11 (CAN not ending DCS, SOS, PM or APC) and M15 (ESC final byte required). Each misses a real probe (PASS, exit 0) that the shared guard catches (FAIL, exit 1): h ESC ] 0;x SUB t; h ESC P j CAN followed by ESC _ j CAN, with t split around the second code; h ESC ( ESC [1m t.
- Result: steps pass; **mutant check fails** (finding V-2). Status left alone.

## F-016: Markdown marks inside the word

- Steps: h and t joined by `**` emphasis, by `*`, by backtick code and by `~~` strike, in an .md file.
- Before (MARK not applied): PASS, exit 0 for all 4.
- After: FAIL, exit 1 for all 4.
- Mutants:
  - Killed: M43 (MARK not applied) and M44 (MARK without *).
  - **Survived**: M45 (MARK without the backtick) and M46 (MARK without ~). The self-test case uses only `**`. Each survivor misses its probe (PASS); the shared guard gives FAIL.
- Result: steps pass; **mutant check fails** (finding V-3). Status left alone.

## F-017: a hostile environment swaps the interpreter

- Steps: a fake developer folder whose usr/bin/xcrun and usr/bin/python3 print 'names: PASS (fake)' and exit 0. Then `DEVELOPER_DIR=<it> scripts/check-names.sh <root holding W>`.
- Before (env -i removed): 'names: PASS (fake xcrun)', exit 0.
- After: names: FAIL, exit 1.
- These also give FAIL, exit 1:
  - PYTHONHOME and PYTHONPATH pointed at a scratch folder;
  - BASH_ENV and ENV set to a script that prints a fake PASS;
  - exported bash functions named env and exec, run through the #! line.
- The accepted residual (LD-226 (3)) is real: `BASH_ENV=<script> bash scripts/check-names.sh <root>` prints the fake PASS, exit 0. The header names it (lines 45 to 48).
- Mutant M47 (env -i removed): self-test FAIL, 'missed case: F-017 environment not cleared'.
- Result: **pass**.

## F-018: extended attributes

- Steps, each in its own root:
  - `xattr -w user.note "see $W"` on a file;
  - `xattr -w "user.$W" 1` on a file;
  - the value on a folder;
  - the value on a symlink with `xattr -s` (links not followed; the hit is on ./l, and the target holds only com.apple.provenance);
  - a gzip value written with `xattr -wx`.
- Before (no xattr scan): PASS, exit 0 for all 5.
- After: FAIL, exit 1 for all 5 ('xattr value: content holds word 1', 'xattr name holds word 1', 'xattr value: unpacked stream: ...').
- Mutants:
  - Killed: M48 (no xattrs), M49 (names not matched), M50 (values not matched).
  - **Survived**: M51 (XATTR_NOFOLLOW off, so links are followed). The self-test's link is broken and has no xattr. M51 gives PASS, exit 0 on the symlink root; the shared guard gives FAIL.
- Result: steps pass; **mutant check fails** (finding V-4). Status left alone.

## F-019: escape and lookalike forms

- Steps: %xx percent-encoding; a \ooo octal escape; \N{LATIN SMALL LETTER ...}; small capitals; Latin alpha; and a letter with a stroke (U+A741 for the first letter).
- Before (percent, octal, \N and Latin-name mapping undone): PASS, exit 0 for all 6.
- After: FAIL, exit 1 for all 6.
- Mutants:
  - Killed: M52 (no percent), M53 (no octal), M54 (no \N), M55 (no small capitals), M56 (no alpha).
  - **Survived**: M57 (letters WITH a hook, stroke or other mark not mapped). No self-test case has such a letter. M57 misses the U+A741 probe; the shared guard gives FAIL.
- Result: steps pass; **mutant check fails** (finding V-5). Status left alone.

## F-020: zlib, raw deflate and zip after a prefix

- Steps: a file that is one zlib stream; a file that is one raw deflate stream; a zlib stream inside a PDF-like file; a zip after a shell prefix.
- Before (no stream search; zip only at the start): PASS, exit 0 for all 4.
- After: FAIL, exit 1 for all 4 ('unpacked stream' or 'unpacked member: content holds word 1').
- Mutants M58 (no zlib streams), M59 (no raw deflate) and M60 (no zip after a prefix): each self-test FAIL with its case.
- The row's Known limit (raw deflate that does not start the file) is real: a probe gives PASS.
- Result: **pass**.

## F-031: regression guard for the pixel-data inflate step

- Steps: make the inflate step unbounded and run the self-test.
- Before: the row says the self-test passed with it.
- After: M61 (`d.decompress(z)` in inflates()) gives self-test FAIL, 'missed case: F-031 pixel data unpacked in 1 MB steps'. M62 (cap removed from streams()) gives 'missed case: F-031 zlib stream inside a file stops at 16 MB'.
- Shared step 4 peaks: 1.3 MB and 16.9 MB.
- Result: **pass**.

## F-115: base64, Brotli and zstd

- Steps, each in a root with an empty AGENTS.md:
  - a `data:text/plain;base64,...` URI holding W in an .html file;
  - a base64 run in a .json file;
  - a 394-byte Brotli stream named p.br and a 447-byte zstd stream named p.zst, each made with the local tools from a 2.1 KB text holding W once (neither holds W as raw bytes);
  - a WOFF2 header not on the allow list.
- Before (no base64; no zstd, Brotli or WOFF2 check): PASS, exit 0 for all 5.
- After: FAIL, exit 1 for all 5 ('unpacked base64: content holds word 1' or 'cannot unpack (... zstd or Brotli data ...)').
- Also FAIL:
  - PEM at 64 columns, MIME at 76 (LF and CRLF), one line in json.dumps;
  - zstd inside a gzip file, an allowed font with one byte changed.
- 18 mutants each make the self-test FAIL with its case (M63 to M80): no base64, no zstd/Brotli/WOFF2 check, no zstd check, no .br check, no WOFF2 check, zstd check on whole files only, no data: branch, data: payload without spaces, case-sensitive marker, the old marker, no blank after the ;, no blank before the comma, run threshold 400, no wrapped branch, wrapped branch without \r? or without [ \t]*, the old cut, spaces not removed.
- Result: **pass**.

## F-119: size cap for gzip, bzip2, xz and zip

- Steps: `head -c 4294967296 /dev/zero | gzip -9 > <root>/z.gz` (4.2 MB). The row writes `head -c 4G`, which macOS head rejects ('illegal byte count'), so it made an empty gzip that passes as clean (open issue 2).
- After: 'cannot unpack (ValueError: unpacks past 16 MB)', FAIL, exit 1, in 3.75 s real, 2.30 s user, 414 MB max RSS. The memory is the views of the 4.2 MB file itself.
- 64 MB of zeros as gzip, bzip2, xz and zip: each FAIL, exit 1, 0.5 s, 136 to 157 MB max RSS.
- Before (no cap), 64 MB gzip: PASS, exit 0, 32.4 s real, 742 MB max RSS.
- Mutants: M81 (cap removed from capped()) misses all four step 4 cases; M82, M83 and M84 (gzip, bzip2, xz uncapped) each miss their own case, and so does M85 (zip member uncapped).
- Result: **pass**.

## F-120: zlib streams matched one at a time

- Steps: one file holding six zlib streams of 15 MB each (W at the end of each), against a file holding one.
- I measured with tracemalloc on the guard's own content_hits, as the row's proof did. Max RSS hardly moves under memory pressure because macOS compresses idle zero pages.
- After: six streams peak at 255.8 MB, the same as one stream (255.7 MB). The guard gives FAIL, exit 1, with 6 hits.
- Before (all parts collected first): 334.3 MB for six streams (+78.6 MB, about five held streams).
- Mutant M86 (all parts collected first): self-test FAIL, 'missed case: F-120 zlib streams matched one at a time'.
- Result: **pass**.

## F-121: control characters in printed file names

- Steps: in one root, a file named ESC [8m, W, ESC [0m .txt, and a file named h, DEL, U+009B, t .txt.
- After: FAIL, exit 1. The output holds 0 raw ESC, 0 raw DEL and 0 raw U+009B, and shows the text `\x1b` 2 times, `\x7f` once and `\x9b` once.
- Before (raw print): 2 raw ESC, 1 raw DEL and 1 raw U+009B.
- Mutants:
  - Killed: M87 (raw print), M88 (C0 only), M89 (C0 and C1), M90 (C0 and DEL), each with 'missed case: F-121 control characters in a printed file name'.
  - **Survived**: M91 (the backslash not escaped). Under M91, a file named W, a backslash, then x1b .txt prints as `...\x1b.txt`, the same as an escaped ESC. The shared guard prints `...\x5cx1b.txt`. No raw control byte is printed either way.
- Result: steps pass; **mutant check fails** (finding V-7). Status left alone.

## Known limits check

The header's two Known limits sentences (lines 49 to 63) were checked against the decisions:

- **LD-229 (2):** the terminal sentence matches it item for item: a raw single C1 byte in non-UTF-8 text, a C1 code point inside a 7-bit code, a tab as one column, a carriage return inside a file name, and cursor moves other than backspace and CR removed, not followed.
- **LD-226 (2):** narrowed by LD-229. CAN and SUB are no longer limits; they are caught (Checker round 3 repros 9 to 13 give FAIL).
- **LD-226 (3):** the residual is in the header and is real (F-017 above).
- **LD-232 (1):** a bare Brotli stream is named, and zstd inside other files falls under 'other compressed streams inside other formats'.
- **LD-233 (3):** base64url and base64 wrapped under 40 columns or not at a multiple of 4 are named.
- The other items are earlier limits: raw deflate not at the start (F-020), images (F-012 and F-024), the vault signature (F-011), lookalikes (F-007 and F-019). The two round 3 additions (JSON-escaped line breaks or slashes, a percent-encoded data: payload) fall under LD-233 (3)'s rule as not ordinary work (see below).

Every limit is real (a probe gives PASS, exit 0), and every nearby non-limit is caught (FAIL, exit 1):

| Limit probe (PASS) | Non-limit probe (FAIL) |
|---|---|
| raw deflate after a 4-byte prefix | zstd frame at the start of a file |
| zlib stream with header 0x58 (8 KB window) | Brotli stream named *.br |
| bare Brotli stream named p.bin | zstd frame inside a gzip file |
| zstd, gzip and xz each after a prefix | base64 at 64 columns (PEM), at 76 (MIME, LF and CRLF), one line in JSON |
| base64 wrapped at 32 and at 70 columns | the same base64url bytes as plain base64 |
| JSON with escaped line breaks (json.dumps of base64.encodebytes) | a data: payload not percent-encoded |
| base64url | the Kelvin sign for the first letter |
| a percent-encoded data: payload | W in a PNG tEXt chunk |
| U+0138 (kra) for the first letter | W in an APNG fdAT chunk |
| W in stored PNG pixel data | the vault signature and W under another extension |
| W after the vault signature in *.larsalvault | the same CSI as UTF-8 U+009B |
| raw byte 0x9B before 1m | 8 spaces instead of the tab |
| U+0085 inside a 7-bit CSI | a CR overwrite in content |
| a tab, then CR overwrite | |
| a CR inside a file name | |
| CSI D cursor back | |

The APNG fdAT item names a false-hit source, not an evasion: fdAT data is matched, so W there is found.

**Ordinary-work test of the limits.**

- Foundation's JSONSerialization and JSONEncoder escape '/' as '\/' by default, and macos/LarsalTests/SnapshotTests.swift uses JSONSerialization. So I measured one-line base64 in such JSON:
  - 20 text blobs holding W: 0 missed. Base64 of ASCII text holds no '/' unless every third byte is '?' or DEL.
  - 20 binary blobs with W inside: 10 missed.
  - That needs binary data holding W, base64-encoded by Swift's Foundation JSON into the tree. No such file exists: the 7 JSON files with base64 are written by our Rust tools and hold no '\/'. So ordinary_work is false, and the item stays a named limit.
- The other limits need a deliberate form (a prefix before a stream, a narrow wrap, url-safe or percent-encoded base64, lookalikes, pixels, terminal tricks).

**Not caught, not named:**

- A compressed format the guard does not know, for example a legacy .lzma ('alone') file made by `lzma.compress(..., format=lzma.FORMAT_ALONE)` holding W, gives PASS, exit 0 (matched raw, never unpacked).
- The header says "Anything it cannot read or unpack fails the guard", and the Known limits name only compressed streams *inside* other formats.
- The tree holds no .lzma, .7z, .lz4, .lzfse, .Z or .dmg file, and Python's lzma module writes xz by default, so ordinary_work is false (finding V-6: name it under Known limits).

## Mutants (91, private copy, each restored, then `cmp` same)

| Row | Killed | Survived |
|---|---|---|
| F-013 | M01 | |
| F-014 | M02, M05 | M03, M04 |
| F-015 | M06 to M09, M12 to M14, M16 to M41 (M42 hangs, stopped by PID) | M10, M11, M15 |
| F-016 | M43, M44 | M45, M46 |
| F-017 | M47 | |
| F-018 | M48 to M50 | M51 |
| F-019 | M52 to M56 | M57 |
| F-020 | M58 to M60 | |
| F-031 | M61, M62 | |
| F-115 | M63 to M80 | |
| F-119 | M81 to M85 | |
| F-120 | M86 | |
| F-121 | M87 to M90 | M91 |

## Findings (all Low, all ordinary_work false; for Known limits under LD-233 (3), or one self-test line each)

- **V-1 (F-014):** the self-test does not pin UTF-16BE or the odd alignment (M03, M04 survive). Smallest fix: append UTF-16BE at an odd offset to the 'F-014 UTF-16 fullwidth letters, no NUL or BOM' case, for example `b'x' + ...encode('utf-16-be')` as a second case.
- **V-2 (F-015):** the self-test does not pin SUB ending an OSC, CAN ending a DCS, SOS, PM or APC, or an ESC with no final byte (M10, M11, M15 survive). Smallest fix: add `'\x1b]0;x\x1a'`, `'\x1bPj\x18'` and `'\x1b(\x1b[1m'` splits to the 'F-015 C0, CAN and SUB inside terminal codes' case.
- **V-3 (F-016):** the self-test does not pin the backtick or ~ marks (M45, M46 survive). Smallest fix: one case with h, backtick, t, backtick and one with h ~~ t ~~.
- **V-4 (F-018):** the self-test does not pin "links not followed" (M51 survives). Smallest fix: set an xattr holding a word on a symlink in step 1 with XATTR_NOFOLLOW.
- **V-5 (F-019):** the self-test does not pin Latin letters WITH a hook, stroke or other mark (M57 survives). Smallest fix: a case with U+A741 (or any 'WITH STROKE' letter) for the first letter.
- **V-6 (Known limits):** compressed formats the guard does not know are matched raw, not failed. Smallest fix: name them in the Known limits sentence ("compressed formats other than gzip, bzip2, xz, zip, zlib and raw deflate, such as legacy .lzma or 7z, are matched raw").
- **V-7 (F-121):** the self-test does not pin the backslash escape that keeps printed names unambiguous (M91 survives). Smallest fix: put a literal backslash in the step 1 file name with ESC and check that the report shows `\x5c`.

## Open issues

1. F-015's proof says all 13 Checker round 3 repros give FAIL. Since part c2 round 2, repros 5 and 7 (ESC BEL X, ESC DEL X) give PASS, which is correct under the DEC parser model (ESC X opens SOS). The wording needs a fix.
2. F-119's steps use `head -c 4G`, which macOS head rejects. The re-test used `head -c 4294967296`.

## Cleanup

My /tmp folders (`/tmp/e13s6c-verify-copy`, `/tmp/e13s6c-verify-work`, `/tmp/e13s6c-verify-r`) and the temp folder of the self-test I stopped (PID 1864) were deleted. No other process was touched.

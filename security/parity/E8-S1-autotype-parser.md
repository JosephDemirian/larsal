# E8-S1 Sequence parser and placeholders (INT-05.1 to INT-05.18, AT-G03, SD-08 Auto-Type part)

Story: E8-S1 Sequence parser and placeholders. Card: [INT-05](../../spec/integrations/INT-05-auto-type.md). Decisions: LD-176, LD-177, LD-184. Neighbor card: [MOD-08](../../spec/model/MOD-08-references-placeholders.md).
Date: 2026-10-28.
Role: Verify. I did not build or review this story. No reference access was needed, and none was used.
Result: **signed.**

- **Tests:** `cargo test -p larsal-autotype`: 52 passed (1 unit, 51 in `tests/int05.rs`). Every INT-05 case this story owns maps to a test.
- **Own probes:** 214 checks in a separate crate, written from the card. 213 matched the card. The last one is a card gap, not a build error (G1 below).
- **AT-G03:**
  - 32 levels of nesting read; 33 give MI05-25. 1,000,000 levels fail in 87 ms.
  - Counts up to 100,000 digits give MI05-12 in 4 ms.
  - 10,000 keys pass and 10,001 give MI05-21. 60,000 ms of waits pass and 60,001 give MI05-22.
  - 256 characters to pick pass and 257 give MI05-18.
  - All 10 self-reference and growth shapes give MI05-27 in under 1 ms (the 16-fold growth shape in 0.4 ms).
  - A 64 MiB sequence peaks at 387 MB at most, input included, and takes at most 3.2 s.
- **R05-4:** Larsal's own shortcut gives MI05-26 in every written form; other modifiers pass.
- **`{TOTP}`:** written in the sequence, the code is computed when typing reaches it. Reached through a field, it is computed when the plan is made. Invalid settings give MI05-16 on both paths, also through a reference and in the editor check.
- **Secrets:** the plan's `Debug` output shows `[hidden]` for every value. 18 failing sequences, run through both the plan and the editor check, hold no value in any message.
- **T40:** `autotype_sequence` ran 601 s and 144,097 runs: no crash, no timeout, no artifact. Replayed in release, the slowest of the 2,116 corpus inputs took 32 ms. The two `tests/data` inputs took 18.4 ms and 10.8 ms in release.

## Setup

- **Build.** `. "$HOME/.cargo/env"`, `CARGO_TARGET_DIR=/tmp/v-e8s1-target`, toolchain 1.99.1. Nightly was used only for `cargo +nightly fuzz` (cargo-fuzz 0.13.2), with `--target-dir /tmp/v-e8s1-target/fuzz`.
- **Probe crate.** `/tmp/v-e8s1-probe`, outside the workspace. It has path dependencies on `larsal-autotype`, `larsal-core`, `larsal-model` and `larsal-crypto`, a copy of the workspace `Cargo.lock`, the `zxcvbn` patch, `--offline`, and release with `lto`, `codegen-units = 1` and `overflow-checks`.
  - It uses only the public API: `plan`, `check`, `Plan::{actions, keys, waits_ms, picks, fill_picks, otp_code}`, `Error::id` and `Display`, `Layout::new`, `Options`, `Shortcut`, `Mods`, `refs::Context` and `totp::code_for`.
  - Its own demo vault holds an entry P with marker values `SECRET-UN-17` and `SECRET-PW-41`, a reference target Q and the card's E3. Its own US layout table was written from Carbon `kVK_ANSI_*`.
  - None of the Builder's test code was used.
- **Nothing in the project changed** except this file and the E8-S1 status line. `find fuzz crates/larsal-autotype -newer /tmp/v-e8s1-probe/Cargo.toml -not -path "*/target/*"` printed nothing. The fuzz corpus was a `/tmp` copy, and artifacts went to `/tmp/v-e8s1-artifacts` (left empty). `fuzz/Cargo.lock` and `Cargo.lock` were not touched. Every `/tmp/v-e8s1-*` folder was deleted at the end.
- **No window and no typing.** This story types nothing, and no probe posted a key event or touched a pasteboard. Every process I started ran in the foreground of its command and ended there, so nothing had to be stopped.

## 1. Builder tests and INT-05 case map

`cargo test -p larsal-autotype`: `cargo test: 52 passed (3 suites, 0.45s)`. A second run listed each test as `ok`: `read::tests::ld184_1_memory_follows_the_braces` (unit) and 51 in `tests/int05.rs`.

In release, `cargo test -p larsal-autotype --release --test int05 -- t40_slowest r05_2_deep t37`: `t37_growth_bound`, `r05_2_deep_nesting_fails_fast` and `t40_slowest_fuzz_inputs_stay_fast` passed, `3 passed; 0 failed`.

Cases owned by E8-S1 (the reader and the planner, INT-05.1 to INT-05.18):

| Case | Test | What the planner level proves; what is left |
|---|---|---|
| T01 | `t01_default_sequence` | Text, Tab, text, Return. The plan carries a 500 ms start delay and a 25 ms pause. Event timing is E8-S3 |
| T02 to T14 | `t02_brace_escapes`, `t03_unpaired_brace`, `t04_lone_braces_are_characters`, `t05_modifiers`, `t06_dangling_modifiers`, `t07_repeat_counts`, `t08_repeat_over_100`, `t09_overflowing_counts_fail`, `t10_names_ignore_case`, `t11_keypad_and_right_command` (and `t11_leading_zeros_are_not_keys`, LD-184 (2)), `t12_keys_a_mac_lacks`, `t13_brace_and_paren_names`, `t14_count_on_text_key_and_tilde` | Fully covered |
| T15 | `t15_delay` | `Wait(500)`, `Wait(10000)` and MI05-13. The fake-clock wait is E8-S3 |
| T16, T17 | `t16_key_pause`, `t17_delay_needs_a_number` | Fully covered |
| T18 | `t18_start_delay_and_pause_clamped` | Clamped to 100 ms and 500 ms. Timing is E8-S3 |
| T19 | `t19_clearfield` | Fully covered |
| T20 | `t20_totp_computed_when_typing_reaches_it` | An `Otp` mark; `otp_code(10:00:30)` gives the 10:00:30 step. The run's clock is E8-S3 |
| T21 | `t21_totp_none_or_invalid` | Fully covered |
| T22 to T24 | `t22_pickchars`, `t23_pickchars_field_names`, `t24_pick_cancel_types_nothing` | `picks()` gives 14 and 4. The filled picks give `d`, Tab, `m`. Cancel means the caller drops the plan. The dialog itself (INT-05.36) is E8-S2 |
| T25 | `t25_pick_over_256_characters` | Fully covered |
| T26 | `t26_mode_virtual` | Text is marked for key-code typing. The key-code lookup (INT-05.41) is E8-S3 |
| T27 to T34 | `t27_ignored_commands`, `t28_custom_fields`, `t29_unknown_placeholders`, `t30_field_name_with_digits`, `t31_references`, `t32_conversions`, `t33_control_characters_in_values`, `t34_modifiers_on_a_placeholder_are_ignored` | Fully covered |
| T35 | `t35_unicode` | `é😀` counts as 2 keys. The single event holding both UTF-16 halves (INT-05.40) is E8-S3 |
| T36 | `t36_run_bounds` | Fully covered, picked characters included |
| T37 | `t37_growth_bound` | MI05-27 (R05-7) in under 1 s |
| T38, T39 | `t38_messages_hold_no_values`, `t39_editor_check` | Fully covered |
| T40 | fuzz target `autotype_sequence`, `t40_slowest_fuzz_inputs_stay_fast` | Section 6 |
| T41 | `t41_command_names_ignore_case` | Fully covered |
| T98, planner half | `t98_combination_follows_the_layout` | ⌘ with key 0x0C on an AZERTY table. Reading the macOS layout is E8-S3 |
| T99 | `t99_no_key_for_the_character` | MI05-23 |
| T108, planner half | `t108_effective_sequences_through_the_planner` | `{PASSWORD}{ENTER}` for E4 through `entry_sequence`. Type Login with S-AT-04 is E8-S2 |
| R05-2 | `r05_2_deep_nesting_fails_fast`, `r05_2_thirty_two_levels_read`; seeds `seed-07` to `seed-09` | Covered |
| R05-3 | `r05_3_control_characters_in_the_sequence` | Covered |
| R05-4 | `r05_4_own_shortcut_fails_before_typing` | Covered. The fake hot key service is E8-S2 |
| R05-7 | `r05_7_self_reference`, `t37_growth_bound` | Covered |
| LD-184 (1) to (3) | `ld184_1_memory_follows_the_braces`, `t11_leading_zeros_are_not_keys`, `ld184_3_totp_through_a_field` | Covered |

Not E8-S1:
- **E8-S2** (INT-05.19 to INT-05.36): T42 to T89, T109, and the window half of T108. R05-1 and R05-5 are window matching, also E8-S2.
- **E8-S3** (INT-05.37 to INT-05.47): T90 to T107 and T110.

No case owned by E8-S1 is missing.

## 2. The grammar against INT-05 (own probes)

`/tmp/v-e8s1-target/release/v-e8s1-probe probes` printed `TOTAL pass 213 fail 1`. Each line names the sequence, the plan or the reason, and the time. Results by rule:

- **INT-05.2 escapes and count:**
  - `{{}{{}` gives `{{`; `{}}{}}` gives `}}`; `a{{}b{}}c` gives `a{b}c`.
  - These give MI05-11: `{{}TAB}`, `{{}}` (escapes are read left to right), `{`, `}` and `{TAB}{`.
  - `}{` and `{}` are typed as characters.
  - `{C:{{}}x` gives `x`.
- **INT-05.3 tokens:**
  - `+a` gives key 0x00 with ⇧. `^+%#a` gives ⌃⌥⇧⌘. `##a` counts ⌘ once. `^A` presses 0x00 with ⌃.
  - `+{ENTER}` gives 0x24 with ⇧. `^{TAB 2}` gives two Tabs with ⌃.
  - `+` and `a+^` give MI05-24 with the texts `+ at the end…` and `+^ at the end…`.
  - `^ß` and `+{{}` give MI05-23.
  - `{T-CONV:/{USERNAME}/upper/}` reads as one token.
- **INT-05.4:** `~@ x` and `é😀` are typed as text. No Return.
- **INT-05.6 key names**, each code taken from the card's table:
  - All 31 names and case forms press their code: TAB, ENTER, SPACE, the arrows, HOME, END, PGUP, PGDOWN, PGDN, BACKSPACE, BS, BKSP, DELETE, DEL, ESC, HELP, CAPSLOCK, WIN, LWIN, RWIN 0x36, ADD 0x45, SUBTRACT 0x4E, MULTIPLY 0x43 and DIVIDE 0x4B.
  - F1 to F16 press the 16 codes in the card's order. `{numpad0}` to `{numpad9}` press 0x52 to 0x59, 0x5B and 0x5C.
  - The 7 keys a Mac lacks press nothing, `{insert 5}` included.
  - `{LEFTBRACE}…` gives `{}()`. The nine character names give `()[]+%^~#`. `{+ 3}{~ 2}{LEFTBRACE 2}` gives `+++~~{{`.
  - These give MI05-19: `{F17}`, `{F0}`, `{F01}`, `{F016}`, `{NUMPAD10}`, `{NUMPAD01}`, `{TAB3}`, `{TAB 3 }`, `{TAB`␉`3}`, `{TABX}` and `{a}`.
- **Counts (INT-05.6, INT-05.17):**
  - `{TAB  3}` (two spaces) gives 3 Tabs. `{LEFT 007}` gives 7. `{SPACE 0}{ENTER 0}` gives nothing. `{UP 100}` and `+{UP 100}` give 100 presses.
  - These give MI05-12: `{UP 101}`, `{TAB 18446744073709551615}`, `{TAB 18446744073709551616}`, a 100,000-digit count (3.8 ms), `{INSERT 101}` and `{+ 101}`.
- **INT-05.7 waits and pauses:**
  - `{DELAY 0}{delay 10000}{Delay  5}` gives waits of 0, 10,000 and 5 ms.
  - `{DELAY 10001}` and a 26-digit delay give MI05-13.
  - `{DELAY5}`, `{DELAY 1 2}`, `{DELAY x}` and `{DELAY =5}` give MI05-19.
  - `{DELAY}`, `{DELAY=}`, `{DELAY=abc}`, `{DELAY=-1}` and `{DELAY=5 0}` give MI05-15.
  - `{DELAY=0}{DELAY=500}{DELAY= 50 }{delay=7}` gives pauses of 0, 500, 50 and 7 ms.
  - `{DELAY=501}` and `{DELAY=4294967296}` give MI05-14.
  - S-AT-09 and S-AT-10 are clamped: 0 and 10,000 give 100 and 500; 99,999 and 0 give 10,000 and 0.
- **INT-05.8:**
  - `{CLEARFIELD}` gives 0x00 with ⌘, then 0x33. The count is ignored, even `{clearfield 99999999999}`.
  - On an AZERTY table it gives 0x0C with ⌘, then 0x33.
- **INT-05.10:**
  - `{PICKCHARS}` picks from 12 characters, also with the count `999`.
  - `{PICKCHARS:attr1}`, `:UserName` and `:Field 2` pick from their fields.
  - `:Notes` (empty) gives no pick.
  - `:Nope`, `:` (empty name), `:ATTR1` (case matters) and `:attr1:C=2` give MI05-17.
- **INT-05.11:**
  - `{MODE=VIRTUAL}ab{MODE=NORMAL}c` gives key-code text `ab`, then text `c`.
  - `{mode=xxvirtual}` switches to key codes. `{MODE=VIRTUALx}` and `{MODE=}` switch back.
  - Key-code mode reaches resolved placeholders too.
  - `{MODE =VIRTUAL}` gives MI05-19.
- **INT-05.12:**
  - `{BEEP}{beep 100 200}{VKEY 13}{vkey-ex 1}{APPACTIVATE Notes}{c:x}{C:{TAB}}{BEEPX}z` gives only `z`.
  - `{C}` gives MI05-19.
- **INT-05.13 placeholders through MOD-08**, references inside the vault included:
  - Standard fields in any case.
  - Custom fields: `{S:Missing}` gives nothing, with no error. `{S:UserName}` gives the username. `{s:attr1}` gives MI05-19.
  - `{UUID}` gives 32 hex digits.
  - `{URL:HOST}/{URL:PORT}/{URL:SCM}/{URL:PATH}` gives `example.com/8443/https//path`.
  - `{DT_UTC_YEAR}-{DT_UTC_MONTH}` gives `2026-10`. `{DB_DIR}` is empty for an unsaved vault.
  - `{FOO}` and `{USERNAME 2}` give MI05-19.
  - References:
    - `{REF:U@I:<E3>}` gives `demo@mail.example`, and so does the upper-case id.
    - `{REF:P@T:Demo Mail}` gives `demo-pass-1`.
    - A reference with no match gives nothing. The lower-case `{ref:…}` gives MI05-19.
    - `{REF:T@I:{S:Target}}` resolves the search text first (MOD-08.14).
    - The found entry's `{S:Inner}` resolves in that entry's own context (MOD-08.16).
    - A username that holds a reference also resolves.
    - An entry outside the vault gets MI05-19 for a reference (MOD-08.29).
  - Conversions:
    - `{T-CONV}` with U, lower, hex and base64 gives `ABab6162YWI=`.
    - A wrong type, 3 parts, `{T-CONV:}` and a line feed give MI05-20.
    - `{T-REPLACE-RX:/{USERNAME}/SECRET-(..)/x$1/}` gives `xUN-17`.
    - 4 parts, `(b`, a back-reference and a lookahead give MI05-20.
- **INT-05.14 and R05-3 control characters:**
  - The sequence `a`␁`b`␡`c`CR LF`d`TAB`e`NUL gives `abcd`, Tab, `e`. `+`TAB gives Tab with ⇧. `^`LF`x` gives `x`.
  - The resolved value `p`CR CR LF`q`LF LF`r`ESC`s`U+0085`t`DEL gives `p`, Return, Return, `q`, Return, Return, `rs`U+0085`t`. A lone CR is one Return; CR LF is one Return; C1 controls are kept, as the card names only U+0000 to U+001F and U+007F.
  - `^%{S:attr1}` ignores the modifiers. A value of `^%v{TAB}` is typed as text.

**G1, the one probe that did not match my guess (a card gap).**
- `{S:a{}}b}` typed `b}`. The escape turns the token's text into `{S:a}b}`, which MOD-08 scans as the span `{S:a}` (no such field, so empty) followed by `b}`.
- INT-05.13 says "resolved with MOD-08, as one span". Under that reading the field would be named `a}b`, and the sequence would type nothing.
- MOD-08.1 has no form for a literal brace inside a span, so the card does not say which is meant. Neither choice can type a value the sequence could not already type.
- Proposed ruling for the lead: keep the current behaviour (escapes do not survive into MOD-08), and add one line and a test to INT-05.13. This does not block E8-S1.

## 3. AT-G03 bounds with hostile inputs

All timings below are in release on this Mac, which was not otherwise idle (load average 5 to 12).

- **Nesting (R05-2):**
  - `{C:` with 31 more levels inside reads, and the next character `y` is typed. With 33 levels: MI05-25, `{C:{a{a… has braces nested more than 32 deep.` (the first 40 characters).
  - 33 levels after other tokens, with `^%` in front, or inside `{S:…}` also give MI05-25. A 32-level `{S:…}` does not.
  - 100 escapes `{{}` inside a token are not nesting.
  - 100,000 levels give MI05-25 in 8.9 ms; 1,000,000 levels in 87 ms.
- **Huge counts:** `{TAB 18446744073709551616}`, a 100,000-digit count (3.8 ms), `{DELAY 99999999999999999999999999}` and `{DELAY=4294967296}` give MI05-12, MI05-12, MI05-13 and MI05-14. Ignored counts stay ignored: `{CLEARFIELD 99999999999}`, `{PICKCHARS 999}`, `{totp 5}`.
- **10,000 keys:**
  - Exactly 10,000 passes: `a` × 10,000, `{TAB 100}` × 100, `{CLEARFIELD}` × 5,000 (2 presses each), and 9,994 `a` plus `{TOTP}` (6 digits counted).
  - These give MI05-21: one key more in each case, 9,999 `a` plus `{CLEARFIELD}`, a resolved value of 10,001 line feeds, and two 5,000-character fields plus `x`.
  - 20,000 resolved U+0001 characters count 0 keys.
  - `fill_picks` that would pass 10,000 keys gives MI05-21, and the plan stays unchanged.
- **60 s of waits:** `{DELAY 10000}` × 6 and `{DELAY 1}` × 60,000 give 60,000 ms. Each with 1 ms more gives MI05-22. `{DELAY=500}` × 1,000 counts 0 ms of waits.
- **`{PICKCHARS}` over 256:**
  - 256 characters pass. 256 × `é` (512 bytes) passes: the limit counts characters.
  - 257 gives MI05-18, and so does a short field that resolves to 257 characters. A 1,000,000-character field also gives MI05-18.
  - The editor check passes a 300-character pick field (it tests that the field exists, not its length) and gives MI05-17 for a missing one.
- **Self-references** (each MI05-27, `‹token› refers to itself or grows too large.`, under 1 ms):
  - `{USERNAME}` in UserName, `x{title}` in Title, UserName and Password pointing at each other, `{S:A}` in A.
  - A reference to the entry's own id, and two entries referring to each other.
  - 16 × `{USERNAME}` through a field (0.4 ms).
  - A chain of 9 fields that double a 4,096-character value.
  - `{PICKCHARS}` on a self-referring password, and `{T-CONV}` around a self-reference.
  - The run's meter: 200,000 × `{S:Missing}` ends with MI05-27 in 101 ms, and 100 regex conversions in 0.4 ms.
- **A 64 MiB sequence** (67,108,864 bytes). Each line was one process measured by `/usr/bin/time -l` (maximum resident set size, the 64 MiB input included). The plan and the editor check ran as separate processes, and each pair gave the same peak:

| Shape | Result | Time (plan / check) | Peak |
|---|---|---|---|
| `a` × 64 Mi | MI05-21 | 1.18 s / 1.18 s | 67 MB |
| line feed × 64 Mi (dropped, 0 keys) | plan, 0 actions | 2.38 s / 2.38 s | 66 MB |
| `{C:x}` repeated | plan, 4 actions | 3.15 s / 3.16 s | 117 MB |
| `{DELAY 0}` repeated | plan, 7,456,544 actions, 0 ms | 2.97 s / 2.96 s | 324 MB |
| `{DELAY=0}` repeated | plan, 7,456,544 actions | 2.97 s / 2.95 s | 324 MB |
| `{a` × 22,369,621 then `}` × 22,369,621 | MI05-25 | 1.88 s / 1.94 s | 301 MB |
| `}` × 32 Mi then `{` × 32 Mi | MI05-21 | 1.30 s / 1.29 s | 387 MB |
| one `{S:` + 64 MiB + `}` | MI05-27 | 2.41 s / 2.38 s | 260 MB |
| one `{C:` + 64 MiB + `}` | plan, 0 actions | 2.36 s / 2.33 s | 196 MB |
| `{S:Missing}` repeated | MI05-27 | 1.36 s / 1.37 s | 89 MB |

  An earlier combined run (plan and check in one process) added `{INSERT}` (98 MB), `{MODE=VIRTUAL}` (84 MB), `{{}` (67 MB, 0.26 s), `{FOO`+64 MiB+`}` and `{T-REPLACE-RX:` with a 64 MiB pattern (both MI05-27, 324 MB), and a field of 50,331,648 bytes (the largest value, MOD-01.9), plain or all U+0001, behind `{NOTES}` (MI05-27 in 19 µs, 98 MB).

  Memory stays linear: at most 387 MB, about 5.8 bytes per input byte. Before LD-184 the Checker estimated about 6 GB. No shape took more than 3.2 s.

## 4. R05-4 and `{TOTP}` (LD-184)

**Larsal's own shortcut.**
- With ⌃⌥V (0x09) set, these give MI05-26 naming the token as written: `x^%v` (`^%v is Larsal's own Auto-Type shortcut.`), `%^v`, `^%V`, `^^%%v`, and `{MODE=VIRTUAL}^%v`.
- These pass: `^%+v`, `^v`, `%v`, `#^%v`, `v`, `^%c`, and a username of `^%v`, which is typed as text.
- The editor check also gives MI05-26.
- With ⌃⌥Tab set: `a^%{TAB}`, `^%{TAB 3}` and `^%`TAB give MI05-26. `^%{TAB 0}` presses nothing and passes.
- With ⌘A set: `{CLEARFIELD}` gives MI05-26.
- With no shortcut, `^%v` passes.

**`{TOTP}`.** Entry with `otpauth://…secret=JBSWY3DPEHPK3PXP&period=30&digits=6`, plan made at 10:00:29 UTC.
- `{TOTP}{TIMEOTP}{totp 5}{MODE=VIRTUAL}{TOTP}` gives four `Otp` marks (the last in key-code mode) and counts 24 keys.
- `otp_code(10:00:30)` equals `totp::code_for` at 10:00:30 and differs from the 10:00:29 step. `otp_code(10:01:05)` equals its own step. So a `{TOTP}` written in the sequence is computed when typing reaches it (D-INT05-8).
- These give the code of plan time, as text: `{S:Code}` with `Code` = `{TOTP}`, `{T-CONV:/{TOTP}/upper/}` through a field, and `{REF:U@I:<Q>}` where Q's username is `{TOTP}` (Q's own code).
- With invalid settings `secret=SECRETOTP!!`, these give MI05-16: `x{TOTP}`, `{TIMEOTP}`, `x{S:Code}`, and the reference to Q. The editor check gives MI05-16 for `{TOTP}` and for `{S:Code}`.
- An entry with no one-time password types nothing for `a{TOTP}` and for `a{S:Code}`, with no error.

## 5. Secrets

**The plan's `Debug` output.** The plan came from `{USERNAME}{TAB}{PASSWORD}{PICKCHARS:Pin}{TOTP}{NOTES}x` and was printed before and after `fill_picks`. It begins `Plan { start_delay_ms: 500, key_pause_ms: 25, actions: [Text { text: [hidden], by_key: false }, Key { code: 48, mods: Mods(0) }, Text { text: [hidden], by_key: false }, Pick { value: [hidden], by_key: false }, Otp { by_key: false }, …`. The one-time settings print as digits, period, algorithm, encoder, form and problem only (larsal-core `totp::Settings`).

None of these appeared in either output: `SECRET-UN-17`, `SECRET-PW-41`, `JBSWY3DPEHPK3PXP`, `value1`, `PICKME-99`, or the current code.

**Messages.** 18 failing sequences, run through both `plan` and `check`, gave MI05-11 to MI05-25 and MI05-27, with MI05-16 twice and MI05-27 twice. Most failed after values were resolved:
- `{USERNAME}{PASSWORD}{TAB 101}`;
- `{PASSWORD}^ü`;
- a pick field of 360 characters;
- a 12,000-character field;
- a field that holds the password text and refers to itself;
- a reference into a loop;
- an invalid one-time secret holding the marker `SECRETOTP`.

No `Display` or `Debug` text held a marker. Code reading agrees:
- every reason holds a token as written, cut to 40 characters (`error::shown`), a modifier run, or one character of the sequence text (`NoKey` is built only in `combo`, which never receives a resolved value);
- `crates/larsal-autotype/src` has no `println`, `eprintln`, `dbg!`, `log::` or `tracing` (`grep` exit 1).

## 6. T40: 10-minute fuzz run

Command, started 05:55:21, ended 06:05:24, exit 0:

```
cargo +nightly fuzz run autotype_sequence --target-dir /tmp/v-e8s1-target/fuzz /tmp/v-e8s1-corpus/autotype_sequence -- -max_total_time=600 -timeout=1 -report_slow_units=1 -artifact_prefix=/tmp/v-e8s1-artifacts/ -print_final_stats=1
```

- **Corpus:** a `/tmp` copy of the 12 seeds `seed-00` to `seed-11`. Deep nesting is in `seed-07` to `seed-09`.
- **Result:**
  - `Done 144097 runs in 601 second(s)`; final line `cov: 6151 ft: 30378 corp: 2107/1744Kb`.
  - 3,900 new units; 2,116 files left in the `/tmp` corpus.
  - **0 crashes**, no failed assertion (the target checks every plan against INT-05.16 and its own key and wait count), **0 timeouts** at 1 s, `stat::slowest_unit_time_sec: 0`, and no artifact.
  - `peak_rss_mb: 1139`, under the 2,048 MB default limit.
- **That RSS is the sanitizer's, not a leak.**
  - Replaying the grown corpus once in the fuzz build (2,118 runs) already reached 871 MB.
  - The same 2,116 inputs in a plain release build peaked at 30.6 MB. Ten passes (21,160 runs) peaked at 33.0 MB.
  - Larsal's crates hold no global cache (`grep` for `thread_local`, `OnceLock`, `static … Mutex`, `Box::leak` and `mem::forget` finds only the per-call `OTP_INVALID` flag and fixed tables).
- **The slowest input, in release.**
  - The probe repeats the target's entry, options, plan, check and `fill_picks` for every file.
  - Across all 2,116 corpus inputs, 0 took over 100 ms. The slowest took 30.5 to 32.4 ms over three runs: `87f6a7b5…` (6,890 bytes, a run of `{T-REPLACE-RX:/{USERNAME}/a/b/}` tokens; `f87b9974…` is next at 29.9 ms).
- **The `tests/data` inputs in release:**
  - The probe timed `slow-1` at 18.4 ms and `slow-2` at 10.8 ms, both under 100 ms.
  - `t40_slowest_fuzz_inputs_stay_fast` passed under `--release`.

## 7. CPU used

The longest single run was the fuzz: 602.7 s wall, 552.0 s user and 19.5 s sys, on one core.

Builds took about 10 CPU-minutes:
- the test build: 216 s user;
- the fuzz build: 225 s user;
- the release test build and the probe builds.

Probes, memory runs and replays took about 4 CPU-minutes. The total was about 25 CPU-minutes, and no run came near 30 minutes.

## Notes, not blocking

1. **G1** (section 2): escaped braces inside a placeholder are not defined by INT-05.13. A card line and a test are proposed.
2. **Actions that type nothing are not counted.** 64 MiB of `{DELAY 0}` or `{DELAY=0}` makes 7.46 million plan actions (324 MB, 3.0 s). This is bounded and linear, so it is no failure.
   - Smallest change if wanted: push nothing for `{DELAY 0}`, and let a `Pause` replace a `Pause` right before it.
   - E8-S2 should not run the editor check on every keystroke for very long sequences: a 64 MiB check takes about 3 s.
3. **`fill_picks` counts positions past the field's end toward the 10,000-key check**, although they are skipped. This is strict in the safe direction, and the dialog only sends positions within the length.
4. **For E8-S3:**
   - INT-05.45 describes the layout table as "character to key and modifiers". E8-S1's `Layout` holds only keys with no modifier, which is all INT-05.42 needs. Key-code mode (INT-05.41) will need the modifier forms.
   - The typing loop must call `Plan::otp_code` at the moment it reaches each `Otp` (D-INT05-8).
5. **For the lead:** the SD-08 row in [plan/security.md](../../plan/security.md) still says AT-G03 is not signed. The bounds part is proven here. The row also names a Red team run (G7), which this file does not replace.

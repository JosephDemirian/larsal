# E5-S6 Generator: Verify proof

Story: E5-S6 Generator in the toolbar and in the editor (plan/epics.md). Checks: uses `larsal-core`; cards FEA-02 and FEA-03 cases pass through the screen.
Cards: FEA-02, FEA-03, FEA-05 (levels where shown). Decisions: LD-163 (4), LD-181, LD-204 (W-10).
Verify agent, 2026-10-28. I did not build or check this story before.

**Verdict: signed.** Nothing failed. Below: what passes, what waits for W-10 (LD-204), and the advisory open issues.

| Check | Result |
|---|---|
| A. Design parity, section `generator` | **3 of 3 frames PASS**, light and dark. Pixels: 1.28 / 1.28 %, 1.08 / 0.98 % and 1.53 / 1.39 %. Outside the accepted areas: 0.75 / 0.77, 0.56 / 0.48 and 0.38 / 0.25. 0 missing strings, 0 token mismatches, 0 boxes or text runs off by more than 2 pt, 0 unnamed controls. Static tokens 45 of 45. Contrast: 42 pairs, lowest 4.87:1. Report: [design/parity/generator/report.md](../../design/parity/generator/report.md) and report.html. |
| B1. One random source | PASS. There is no random API in Swift. larsal-ffi calls only `larsal_crypto::random`. larsal-core's generator draws only through `larsal_crypto::random::below`. |
| B2. FEA-02 and FEA-03 cases through the screen | Every row the drawn screen can reach passes (table in section 2). The rest is one of three kinds: waiting for W-10 (controls Option A does not draw), a later story or the command line, or a test of the core alone. Each of those has its own test, and those tests pass. |
| B3. Secrets | PASS. The value lives in Rust as a `SecretString`. Swift holds only the shown copy. Nothing is left after close, lock or a new value: the API checks show it, and so does a scan of the process's own memory. Debug hides the value. |
| B4. Mutations (private copy) | 14 mutants: 11 in Rust, 3 in Swift. 13 were caught by the tests. One survived: an off-by-one in a duplicate guard. It is advisory, see open issue 1. |

All work ran in a private copy: `rsync -a --exclude /target --exclude /fuzz/target` to /tmp/e5s6v-copy at 12:48.

- **Own directories.** `target` was linked to /tmp/e5s6v-target, with `CARGO_TARGET_DIR=/tmp/e5s6v-target` and `-derivedDataPath /tmp/e5s6v-dd`.
- **The code checked is the code in the tree.** At 13:11, `cmp` showed these files have the same bytes in the copy and in the shared tree: `crates/larsal-ffi/src/generator.rs`, `crates/larsal-ffi/src/session.rs`, `crates/larsal-core/src/generator/mod.rs`, `macos/Larsal/Generator.swift` and `macos/Larsal/GeneratorPanel.swift`.
- **Other agents' changes.** They changed other files meanwhile, such as reports, ssh and editor pages. Diffs of `EditorEntryPage.swift`, `EntryListView.swift`, `MainWindow.swift` and `Controls.swift` touch nothing about the generator.
- **My own tests.** They existed only in the copy: `crates/larsal-ffi/tests/verify_e5s6.rs`, and `macos/LarsalTests/VerifyE5S6Tests.swift` with the suites `VerifyE5S6Tests` and `VerifyE5S6MemoryTests`.
- **No product code was edited.** The copy and the /tmp folders were deleted at the end.
- **Rule 10.** No window was opened, nothing took focus, and the general pasteboard was never written or read; only its change count was compared.

## Part A: design parity of section `generator`

I followed design/option-a/BUILD-AND-VERIFY.md, "Prompt for the Verify fleet".

1. `node design/option-a/tools/export-reference.mjs` (in the copy, headless Chrome)
   - Printed `light: 91 frames`, `dark: 91 frames`, `manifest.json: 91 frames`, exit 0, 50.7 s.
   - The fresh manifest is byte-equal to the tree's.
   - The generator-password and generator-passphrase references are byte-equal to the tree's, light and dark.
   - generator-generator-in-the-window differs in 13 of 4,329,600 pixels, in a strip at y 1048 to 1056 (2×). With pixelmatch threshold 0.1 that is 0 pixels, 0.000 %. This is rasteriser noise, so the tree's references are current.
2. `scripts/build-core.sh` printed `build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift`. Time: 56.4 s wall, 272 s user.
3. `node design/parity/tools/mockup-dom.mjs generator` printed `light: 3 frames, 280 text runs -> target/parity/dom-light.json` and `dark: 3 frames, 280 text runs -> target/parity/dom-dark.json`.
4. `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e5s6v-dd test -skip-testing:LarsalUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES > target/parity/behaviour.log`
   - The first try stopped with `ParityEditorPagesTests.swift:316:35: error: ambiguous use of 'accessibilityValue()'`. That is unfinished E5-S5 work, not this story. The tree already had the fixed file, so I copied it in.
   - The second try passed:
     - `✔ Suite GeneratorSnapshotTests passed after 22.604 seconds.`
     - `✔ Suite ParityGeneratorTests passed after 61.700 seconds.`
     - `✔ Test run with 110 tests in 18 suites passed after 73.104 seconds.`
     - `** TEST SUCCEEDED **`
5. The final generator run is in Part B, run S2. It wrote the snapshots that were compared:
   - larsal-shots/light/generator-generator-in-the-window.png, generator-password.png and generator-passphrase.png;
   - larsal-shots/dark/ with the same three names;
   - each with its `.ax.json`.
6. `swift design/parity/tools/ocr.swift larsal-shots/light/generator-*.png larsal-shots/dark/generator-*.png` read 6 images (119, 16, 20, 124, 16 and 19 text boxes).
7. `node design/parity/tools/compare.mjs generator` printed:

```
generator: 3/3 PASS
generator-generator-in-the-window              PASS                   L 1.28% (0.75) D 1.28% (0.77)
generator-password                             PASS                   L 1.08% (0.56) D 0.98% (0.48)
generator-passphrase                           PASS                   L 1.53% (0.38) D 1.39% (0.25)
```

The results went into the tree: design/parity/generator/report.html, report.md and findings.json, plus app/<theme>/<id>.png and diff/<theme>/<id>.png. report.md and report.html have a "Verify run for E5-S6" section with these commands.

| Frame | Present L/D | Pixels L / D (outside accepted) | Missing | Token mismatches | Geometry > 2 pt | Verdict |
|---|---|---|---|---|---|---|
| generator-generator-in-the-window | yes / yes | 1.28 % (0.75) / 1.28 % (0.77) | 0 | 0 / 0 | 0 boxes, 0 runs | PASS |
| generator-password | yes / yes | 1.08 % (0.56) / 0.98 % (0.48) | 0 | 0 / 0 | 0 boxes, 0 runs | PASS |
| generator-passphrase | yes / yes | 1.53 % (0.38) / 1.39 % (0.25) | 0 | 0 / 0 | 0 boxes, 0 runs | PASS |

What I checked by eye on the images, with mockup and app stacked:

- **Accepted differences, from findings.json:**
  - generator-passphrase: the mockup's "Strong" is "Weak" in the app, in the warning colour. FEA-03.7 gives 64.62 bits for 5 words, and FEA-05.4 rates that Weak (LD-163 (4), LD-204).
  - generator-generator-in-the-window: the needs-attention count is 7 where the mockup draws 6. The rail's "Strong · … about 131 bits" is "Excellent · … about 124 bits". Both are the card's rules, as in section `main`.
- **Live values (format only):**
  - the password, 20 printable characters with one of each chosen type;
  - the passphrase, 5 list words joined with "-";
  - the bits;
  - one-time codes and the save time.
- **Extra accessibility strings, which are not drawn:** "Generated password" (the output field's VoiceOver name), "on" (the look-alikes value) and "closed" (from the window behind the popover).
- **Two rendering differences, both inside the pixel limit:**
  - The tick in the look-alikes check box: the app draws Phosphor `check` at 12 pt; the mockup draws a 2-px CSS tick. This is the shared `CheckMark` (Forms.swift), which other sections also use.
  - White-on-dark button text looks a little heavier. `Btn` uses weight 500, the same as `.btn` in app.css, so this is rasterisation.
- **Behaviour (check 6).** The mockup's controls are the `gmode` tabs, `regen`, `copy=generated`, `glen`, the `gset` chips, `gwords`, the separator and case segments, `new`, and the editor's "Use password". Each one is pressed through the accessibility tree by ParityGeneratorTests, listed in run S2.
- **Accessibility (check 7):**
  - Every control has a VoiceOver name (0 unnamed).
  - The range is focusable, steps with the arrow keys, and has a 2-pt accent ring when focused.
  - The chips, the look-alikes row, Copy, New password and Use are standard SwiftUI buttons.
  - Contrast: lowest 4.87:1.
  - Focus on a real key window is Mac QA (LD-169), as in the other sections.

## Part B

### 1. One random source (FEA-02.6, AT-B04, SG-01)

```
$ grep -rnE '\.random\(|randomElement|shuffled\(|shuffle\(|SecRandom|arc4random|drand48|srand|SystemRandomNumberGenerator|GKRandom|RandomNumberGenerator|random_' macos --include='*.swift'
(no output, exit 1)
$ grep -rnE "rand::|getrandom|OsRng|thread_rng|rand_core|SystemTime.*seed|fastrand|random\(" crates/larsal-ffi/src crates/larsal-ffi/Cargo.toml
(no output)
$ grep -rnE "rand::|getrandom|OsRng|thread_rng|rand_core|fastrand|StdRng|SmallRng" crates/larsal-core/src crates/larsal-core/Cargo.toml
(no output)
$ grep -rn "random" crates/larsal-ffi/src
edit.rs:1029  larsal_crypto::random::bytes(128)        (shredding a file copy, not the generator)
edit.rs:2259  larsal_crypto::random::below(36)        (a temp file name, not the generator)
cli.rs:171    larsal_crypto::random::SOURCE_CRATES    (the crate guard)
generator.rs:145  MSG_RANDOM text only
$ grep -n "random\|below" crates/larsal-core/src/generator/mod.rs
6:  //! - Every random index comes from `larsal_crypto::random::below`: the OS
34:         larsal_crypto::random::below(n).ok()        (the only source: `impl Source for Os`)
$ cargo tree -p larsal-ffi -e normal -i rand_core --depth 2
rand_core v0.10.1
├── larsal-crypto v0.1.0
│   ├── larsal-core … larsal-ffi … larsal-format … larsal-model … larsal-sshagent
```

The generator path is as follows:

- In Rust, `make()` in `larsal-ffi/src/generator.rs` calls `larsal_core::generator::password::generate` and `passphrase::generate`.
- Their only source is `Os::below`, which is `larsal_crypto::random::below` (`crates/larsal-core/src/generator/mod.rs:34`).
- Swift never makes a value: `GeneratorModel` only calls `session.generate(options:)`.

The core tests pass:

- `cargo test -p larsal-crypto below`: `random::tests::below_draws_again_after_a_rejected_value`, `below_fails_closed_on_a_stuck_source`, `below_zero_is_an_error_and_draws_nothing` and `below_stays_in_range`, all ok.
- `cargo test -p larsal-core --test fea02 --test fea03`: `ok. 20 passed`, `ok. 16 passed`.

### 2. Card cases through the screen

The cases were driven through the same larsal-ffi calls that `GeneratorModel` makes: `generator_options`, `generate`, `edit_generated`, `copy_generated`, `use_generated` and `close_generator`. Each case uses only values the drawn controls can set:

- the five chips;
- look-alikes on or off;
- every group always on;
- length 8 to 64 on the range, or 1 to 999 from the editor field's length;
- words 3 to 10;
- separators `- . space _`;
- cases lower, Title and UPPER.

Screen-only behaviour was driven through `GeneratorModel` and the accessibility tree (Swift).

Test sets:

- **R**: builder's `crates/larsal-ffi/tests/generator.rs`, 12 tests, plus the unit test `generator::tests::d_02_5_lock_during_rating_keeps_nothing`.
- **V**: my `verify_e5s6.rs`, 15 tests.
- **S**: builder's `ParityGeneratorTests` (9 tests) and `GeneratorSnapshotTests`.
- **VS**: my `VerifyE5S6Tests` (2 tests) and `VerifyE5S6MemoryTests` (1 test).
- **C**: larsal-core and larsal-crypto tests.

How to read the Result column:

- **PASS:** the case passed through the screen's calls.
- **W-10:** the case needs a control that Option A does not draw. It waits for W-10 (LD-204) and is not a fail.
- **Later:** the case belongs to another story or to the command line.

#### FEA-02

| Case | Result | Proof |
|---|---|---|
| FEA-02.1 order | W-10 (the brackets chip is Advanced; the scripted source is test-only) | C `generator::password::tests::fea02_1_order_scripted` ok. The screen passes its chips in table order lower, upper, digits, special, extended (`make()`). |
| FEA-02.1 sets | PASS | V `v_fea02_1_sets_each_chip_alone`: each chip alone, look-alikes off, 3 × 999 characters (999 is the screen's maximum). All characters are in the class; distinct characters seen per chip: A–Z 26/26, a–z 26/26, 0–9 10/10, !@#$ 32/32, Äéß 94/94 (U+0080–U+00A0 and U+00AD never drawn). |
| FEA-02.2 removed set | PASS (dashes come through the `!@#$` chip) | V `v_fea02_2_removed_set`: all five chips, look-alikes on, 60 × 999 = 59,940 characters. None of `l B G I O 0 1 6 8 \|` or U+00B7 appears; `o S 5 Z 2` and U+00F9 all appear. 177 = 25 + 22 + 6 + 31 + 93 distinct characters. |
| FEA-02.2 extra untouched | W-10 (extra field) | none |
| FEA-02.3 dedupe within extra; doubled weight; extra alone | W-10 (extra field) | C `fea02_03_extra_characters` ok |
| FEA-02.4 excluded; excluded wins over extra | W-10 (excluded field) | C fea02 ok |
| FEA-02.5 no characters | PASS at the call. The chips cannot reach it: the last chip on stays on (D-02-3); mutant M13 shows the Swift test enforces it. | V `v_fea02_5_and_14_invalid`: "Choose at least one character type." |
| FEA-02.5 all excluded | W-10 | C fea02 ok |
| FEA-02.5 too short | PASS | V: lower and upper, length 1 (a 1-character field) gives "A character of every chosen type needs a length of at least 2.". S `invalid`: a field "ab" with four chips gives "…at least 4.", Copy and Use password are disabled. |
| FEA-02.5 excluded group does not count; extra counts as group | W-10 | C fea02 ok |
| FEA-02.5 length 0 | PASS at the call (an empty field gives the saved length, so the screen cannot ask for 0) | V: lengths 0 and 1000 both give "Choose a length from 1 to 999." |
| FEA-02.6 bound | Core only | C `below_draws_again_after_a_rejected_value` ok |
| FEA-02.6 fail closed | Core, plus the screen's error path | C `fea02_6_fail_closed` and `fea03_6_fail_closed` ok. A source failure goes through the same `keep_made` Err path as invalid options: the value is dropped, nothing is shown, Copy and Use are off (R `d_02_3_invalid_options`, S `invalid`). |
| FEA-02.7 uniform (statistical) | PASS (one group, so the draw stays uniform with every group on) | V `v_fea02_7_digits_uniform`: 0–9 alone, look-alikes off, 10,000 × 100. Chi-square 21.40 < 44.81 (an earlier run gave 9.98). |
| FEA-02.7 uniform full set | W-10 (needs every group off and the six symbol chips) | C `fea02_07_uniform_picks` ok |
| FEA-02.7 extended (statistical) | PASS | V `v_fea02_7_extended_uniform`: Äéß alone, look-alikes on, 10,000 × 93. 93 characters seen, U+00B7 never. Chi-square 90.98 < 171.40 (earlier run 78.22). |
| FEA-02.7 scripted; FEA-02.8 scripted | Core only (scripted source) | C `fea02_7_scripted`, `fea02_8_scripted` ok |
| FEA-02.8 exact distribution; FEA-02.9 positions | W-10 (extra) | C `fea02_08_…`, `fea02_09_…` ok |
| FEA-02.9 small groups | PASS | V `v_fea02_9_small_groups`: A–Z a–z 0–9, look-alikes on, length 32, 20,000 values. Mean digit count 4.290 (4.283 ± 0.06); pool 53; every value has lower, upper and digit. |
| FEA-02.10 screen range | W-10 (the 1–999 number field is not drawn; the range is 8–64, LD-204) | What is drawn: the range clamps, and a length above 64 puts the thumb at the end (`RangeSlider`). R `fea_02_17_start_length`: 1,500 gives 999. |
| FEA-02.10, .11, .21 command line rows | Later (INT-10, E12) | none |
| FEA-02.11 defaults | PASS | R `fea_02_11_defaults`: password tab, 20, the four chips on, Äéß off, look-alikes and every group on; 200 values each have one of every type and no look-alike. S `openClose`: 20 characters. |
| FEA-02.12 Larsal simple view | PASS | V `v_fea02_12_app_simple_view`: defaults at a 4-character field's length 4, 10,000 values. Each has exactly one lower, one upper, one digit and one symbol, and no look-alike. |
| FEA-02.12 hidden options; FEA-02.13 Larsal hex | W-10 (Advanced) | C `fea02_13_hex_preset` ok |
| FEA-02.12 reference rows, FEA-02.13 reference hex | The reference app's behaviour, not Larsal's | none |
| FEA-02.14 live | PASS for the drawn controls; the extra field is W-10 | S `passwordControls`: New password, each chip, the range (VoiceOver increment to 21) and look-alikes each make a new value. S `passphraseControls`: tab, separator, case and words. |
| FEA-02.14 invalid | PASS | V: lower and upper at length 2 is valid; length 1 gives no value, `MSG-GEN-TOO-SHORT`, Copy empty and Use refused. S `invalid` and `refusedEdit`: Copy and Use password are disabled. |
| FEA-02.15 strength | PASS, in the mockup's "level · whole bits" (LD-204) | V `v_fea02_15_strength_line`: `YQC3kbXbjC652dTDH` has E 88.77 and shows Good · 89 bits (17 characters); `Bs5ZFfthWzR8DGFEjaCM6bGqhmCT4km` has E 174.00 and shows Excellent · 174 bits (31). VS `copy`: the screen's strings hold the level and "N bits" that Rust rated. The character count is kept, but Option A's line does not draw it (LD-204). |
| FEA-02.15 empty | PASS | V: an empty edit gives Poor · 0 bits, 0 characters (Bad shown as Poor, FEA-05.8); Copy is empty and Use is refused. In Swift, Copy and Use are disabled on an empty value (mutant M14). |
| FEA-02.16 edit | PASS | R `fea_02_16_use_and_edit` and V `v_fea02_16_17_existing_entry`: typing `demo-pass-42`, then Use, puts it in the draft. S `edit`: "demo" typed in the field, then Use password, puts "demo" in the draft. |
| FEA-02.17 popup length | PASS | V: a 12-character field gives length 12; R: 1,500 characters give 999. S `editorUse`: Open generator (⌥⌘G) opens at the field's length with "Use password". |
| FEA-02.17 repeat field; browser request | Later (E5-S8, INT-08, INT-01/E7) | none |
| FEA-02.18 save on Apply | PASS | VS `saving`: popup, length 24, Use password; the next popup opens at 24. |
| FEA-02.18 no save on Close | PASS | VS `saving`: popup on an empty field, length 30, closed (MenuLayer close); the next popup opens at 24. The window's generator saves when it closes (33). |
| FEA-02.19 new entry | Later (the APP-01 setting, E5-S9). The mockup's "New entry with it" is a separate action and passes (S `newEntry`: new entry, draft = value). | none |
| FEA-02.20 copy | PASS | V `v_fea02_20_copy_markers_and_clear`: label `Password`, 10 s; private pasteboard types `org.nspasteboard.ConcealedType`, `org.nspasteboard.TransientType`, `public.utf8-plain-text`; after 11 s the value is gone. VS `copy`: through the screen, the toast is "Password copied." / "Clears in 10 s." (LD-181), the popover stays open (LD-204), both markers are on the private board, the board is cleared after 11 s, and the general change count is unchanged. |
| FEA-02.22 scalar | W-10 (extra) | C `fea02_22_unicode_scalar_values` ok |
| FEA-02.23 secret | PASS at model level | VS `memory`, see section 3 |
| FEA-02.23 logs | PASS | There is no logging in the generator code: no `log::`, `tracing::` or `println!` in generator.rs and larsal-core/generator, and the Swift app's 3 `Logger` calls print no values. The 3 values from the final snapshots (from `.ax.json`) appear in none of the 5 logs. |
| FEA-02 AT-B04 | PASS | Section 1 |

#### FEA-03

| Case | Result | Proof |
|---|---|---|
| FEA-03.1 facts | Core; the screen uses the built-in list | C fea03 ok. V: every drawn word is in `wordlist::builtin()`. |
| FEA-03.1 attribution | Later (About, E14-S2, D2) | none |
| FEA-03.2 display | PASS in "level · whole bits" | V: 6 words, formula 77.55, shows Good · 78 bits. S: the Words range decremented to 6 shows 78 bits. |
| FEA-03.3 defaults | PASS | V `v_fea03_3_defaults_and_7_bands`: 7 lower-case list words, one space, Good · 90. S `passphraseControls`: the same through the Passphrase tab. |
| FEA-03.3 command line rows, FEA-03.12 command line, FEA-03.13 missing file, FEA-03.16 | Later (INT-10, E12) | none |
| FEA-03.4 separator | PASS with the built-in list (list A needs the list picker, W-10) | V `v_fea03_4_5_separator_and_case`: 4 words with `.`, `_` and space, 200 each: exactly 3 separators, none at the ends. With `-`: at least 3 (4 list words contain a hyphen), none at the ends. |
| FEA-03.4 empty separator; long separator | W-10 (not a drawn separator; list A) | C `fea03_4_separator_scripted` ok |
| FEA-03.5 title; upper | PASS (built-in list) | V: 200 each. Title is first upper and rest lower; UPPER is all upper; words are from the list. S: the Title and UPPER segments. |
| FEA-03.5 mixed; full mapping; title rest | W-10 (no mixed chip; user lists) | C `fea03_5_case_scripted` ok |
| FEA-03.6 uniform; mixed position | W-10 | C `fea03_06_uniform_picks_with_replacement` ok |
| FEA-03.6 repeats (statistical) | PASS | V `v_fea03_6_repeats`: 100,000 passphrases of 7 words; 278 have a repeated word (270 ± 80; earlier run 297). |
| FEA-03.7 formula (list A); empty list | W-10 (list picker) | C fea03 ok |
| FEA-03.7 bands | PASS | V: 3 words 38.77 shows Poor · 39; 5 words 64.62 shows Weak · 65; 7 words 90.47 shows Good · 90; 8 words 103.40 shows Excellent · 103. The other drawn counts: 4 words 51.70 shows Weak · 52; 6 words 77.55 shows Good · 78; 9 words 116.32 shows Excellent · 116; 10 words 129.25 shows Excellent · 129. |
| FEA-03.7 not adjusted | PASS for the drawn options (Title with `_` shows 90 bits); mixed and `#` are W-10 | V |
| FEA-03.8 to FEA-03.14 (word list files, signed lists, uniqueness, bad text, small-list warning, empty list, the picker with Add and Remove) | W-10 (D-03-6: the list picker is not drawn) | C fea03 ok (16 tests) |
| FEA-03.15 restore tab | PASS | VS `saving`: Passphrase, 9 words, Use password from the popup; the window's generator then opens on Passphrase with 9 words and a 9-word value. |
| FEA-03.17 secret | PASS (same path as FEA-02.23) | Section 3 |
| D-03-5 limits | PASS | V: 0, 101 and 1001 words give "Choose from 1 to 100 words."; a 65-character separator gives "The separator can have at most 64 characters."; 64 is allowed (R). R `d_03_5_oversized_separator_is_not_saved`: a 10 MiB separator is not saved. |
| D-03-7 edit | PASS | V: typing "demo" over a 7-word phrase shows Poor · 12 bits (FEA-05 E 11.99, not the formula's 90). S `edit` shows the same through the field. |
| FEA-03 AT-B04 | PASS | Section 1 |

FEA-05, where shown:

- The level is `Level::of(score(E))`, with Bad shown as Poor (FEA-05.8).
- The colours on Option A's tokens are: Bad and Poor `negative`, Weak `warning`, Good and Excellent `positive`. Option A has no `poor` token.
- The bar is drawn on the mockup's 130-bit scale.

### 3. Secrets (FEA-02.23, FEA-03.17, AGENTS.md rule 4)

- **In Rust.**
  - `State.value: Option<SecretString>` holds the value made or typed.
  - `copy_generated` and `use_generated` act on it; the value never comes back from Swift.
  - `Generated.value` is the one shown copy (the Show exception).
  - `use_generated` hands a fresh `String` to `set_password`, which wraps it in a `SecretString`.
- **In Swift.** `GeneratorModel.value` is the only copy. `close()` sets it to `""`; lock goes through `overlay` and `closed()`; a new value replaces it.
- **API proof.**
  - R `d_02_5_value_dropped`: close, lock, lock-all and close-vault each leave Copy empty.
  - The unit test `d_02_5_lock_during_rating_keeps_nothing`: a lock while a value is being made keeps nothing.
  - R `fea_02_16_refused_edit_drops_the_value`.
  - V `v_secret_drops`: after a new value, Copy holds the new one; close and lock leave nothing; the saved options hold no value.
  - S `lock`: the Lock button closes the popover and empties the Swift value.
- **Debug.**
  - V prints `Generated { value: "<hidden>", rating: Rating { level: "Excellent", word: "Excellent", segments: 4, … chars: 20, bits: 118 }, problem: None }`.
  - R `rule_3_generated_debug_hides_the_value`.
  - VS: `String(reflecting:)` and `String(describing:)` of the model do not contain the value.
- **Memory (AT-C02, model level).** VS `VerifyE5S6MemoryTests` scans the test process's own resident readable and writable memory. It uses `mach_vm_region_recurse` on `mach_task_self`, plus `mincore` and `memchr`. No debugger and no prompt are involved. The needle is kept only reversed, in UTF-8 and UTF-16LE. Output:

```
VERIFY E5S6 memory shown (value A): utf8 2 utf16 0
VERIFY E5S6 memory after a new value: A utf8 0 utf16 0
VERIFY E5S6 memory shown (value B): utf8 2 utf16 0
VERIFY E5S6 memory after close: B utf8 0 utf16 0
VERIFY E5S6 memory shown (value C): utf8 2 utf16 0
VERIFY E5S6 memory after lock: C utf8 0 utf16 0; A utf8 0 utf16 0; B utf8 0 utf16 0
✔ Test "Verify FEA-02.23 AT-C02: the value in this process's memory while shown, after a new value, close and lock" passed after 1.542 seconds.
```

While the value is shown there are two copies: the Swift string and Rust's `SecretString`. After a new value, after close and after lock there are none.

This scan is model level, without the rendered text field. A dump of the real Larsal.app with lldb is Mac QA: developer mode is off, as noted in E6-S6.

### 4. Mutations (private copy only; each restored and checked with `cmp` afterwards)

Rust: `/tmp/e5s6v-mutate.sh <id> <file> <line> <perl-subst>` ran `cargo test --no-fail-fast -p larsal-ffi --test generator --test verify_e5s6 --lib -- --skip v_fea02_20 --skip v_fea02_7 --skip v_fea03_6 --skip v_fea02_9`, which skips my 4 slow statistical and timer tests.

- The lib binary's 2 failing `reports::tests` are baseline. They fail without any mutant: `cargo test -p larsal-ffi --lib` gives `39 passed; 2 failed` (`fea_05_15_health_report_matches_the_sidebar`, `fea_05_26_expire_now_from_the_report`). That is unfinished E5-S7 work in the copy, so they are left out below.
- Swift: `/tmp/e5s6v-swiftmut.sh` ran `xcodebuild … test -only-testing:LarsalTests/ParityGeneratorTests -only-testing:LarsalTests/VerifyE5S6Tests`.

| ID | Mutant | Caught by |
|---|---|---|
| M1 | generator.rs:273 `Ok(made) if state.drops == start => made` becomes `Ok(made) => made` (a lock while rating keeps the value) | `generator::tests::d_02_5_lock_during_rating_keeps_nothing` FAILED |
| M2 | generator.rs:392 `close_generator` no longer drops the value | R `d_02_5_value_dropped`, V `v_secret_drops` FAILED |
| M3 | session.rs:667 `lock` no longer calls `drop_generated()` | R `d_02_5_value_dropped`, V `v_secret_drops` FAILED |
| M4 | generator.rs:339 a refused edit (over 64 KiB) keeps the value | R `fea_02_16_refused_edit_drops_the_value` FAILED |
| M5 | generator.rs:110 `Debug` prints the value | R `rule_3_generated_debug_hides_the_value`, V `v_secret_drops` FAILED |
| M6 | generator.rs:201 `every_group: false` | R `fea_02_11_defaults`, `d_02_3_invalid_options`; V `v_fea02_5_and_14_invalid`, `v_fea02_12_app_simple_view` FAILED |
| M7 | generator.rs:200 `exclude_lookalike: false` | R `fea_02_11_defaults`, `fea_02_1_chips`; V `v_fea02_12_app_simple_view`, `v_fea02_2_removed_set` FAILED |
| M8 | generator.rs:179 the passphrase is rated by the estimate, not the FEA-03.7 formula | R `fea_03_7_passphrases`, V `v_fea03_3_defaults_and_7_bands` FAILED. The first form did not compile (E0382); it was rewritten as `let bits = estimate(&value); return Ok((value, bits));` |
| M9 | generator.rs:236 Bad is no longer shown as Poor (`level == Level::Excellent`) | R `fea_03_7_passphrases`, `d_02_3_invalid_options`; V `v_fea03_3_defaults_and_7_bands`, `v_fea02_15_strength_line` FAILED |
| M10 | generator.rs:224 `too_long` lets a 65-character separator through (`nth(MAX_SEPARATOR + 1)`) | **Survived.** Generation is still refused by larsal-core's own check (`SeparatorTooLong`, mapped to the same message). Only `close_generator`'s save filter is weaker, and no test saves a separator of exactly 65 characters. Open issue 1. |
| M11 | larsal-core generator/mod.rs:34 the source becomes `Some(n - 1)` (no randomness) | V `v_fea02_1_sets_each_chip_alone`, `v_fea02_2_removed_set`, `v_secret_drops` FAILED. larsal-core `--test fea02`: 10 failed (`fea02_06_os_source_without_bias`, `fea02_07_uniform_picks`, …); `--test fea03`: `fea03_06_uniform_picks_with_replacement` FAILED. The builder's 12 R tests all pass on this mutant: they show values only, never randomness. That is covered by C and V. |
| M12 | Generator.swift:87 `close()` keeps the Swift value | S `openClose`, `newEntry`, `lock`; VS `saving`, `copy` FAILED (5 issues) |
| M13 | Generator.swift:60 the last chip may turn off | S `passwordControls` FAILED: `Expectation failed: generator.options.special` |
| M14 | GeneratorPanel.swift:34 Use password is not disabled on an empty value | S `invalid` and `refusedEdit` FAILED: `screen.node(name)?.isAccessibilityEnabled?() == false` |

## Test runs and their output

**R1.** `cargo test -p larsal-ffi --test generator`

```
running 12 tests
test fea_02_18_saving ... ok
test fea_03_7_passphrases ... ok
test d_03_5_oversized_separator_is_not_saved ... ok
test rule_3_generated_debug_hides_the_value ... ok
test fea_02_1_chips ... ok
test fea_02_20_copy ... ok
test fea_02_11_defaults ... ok
test d_02_5_value_dropped ... ok
test d_02_3_invalid_options ... ok
test fea_02_16_use_and_edit ... ok
test fea_02_17_start_length ... ok
test fea_02_16_refused_edit_drops_the_value ... ok
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s
```

**R2.** `cargo test -p larsal-ffi --lib generator`

```
test generator::tests::d_02_5_lock_during_rating_keeps_nothing ... ok
```

**R3.** `cargo test -p larsal-core generator`

```
test generator::password::tests::chars_buffer_round_trips_and_swaps ... ok
test generator::passphrase::tests::fea03_8_order_scripted ... ok
test generator::passphrase::tests::fea03_6_fail_closed ... ok
test generator::passphrase::tests::fea03_4_separator_scripted ... ok
test generator::passphrase::tests::fea03_5_case_scripted ... ok
test generator::password::tests::fea02_1_order_scripted ... ok
test generator::password::tests::fea02_7_scripted ... ok
test generator::password::tests::fea02_6_fail_closed ... ok
test generator::password::tests::fea02_8_scripted ... ok
test result: ok. 9 passed
test fea05_09_generator ... ok
```

**R3, continued.** `cargo test -p larsal-core --test fea02 --test fea03` printed `ok. 20 passed` and `ok. 16 passed`.

**R4.** `cargo test -p larsal-ffi --test generator --test verify_e5s6 -- --nocapture --test-threads 8` (final run, code equal to the tree) printed `ok. 12 passed` and `ok. 15 passed; 0 failed … finished in 57.78s`.

The first run of V had 1 failure, and it was in my own test: the `!@#$` set check left out `|`, which is allowed with look-alikes off. I fixed the test and the code was unchanged. The V lines:

```
V FEA-02.1 sets: chip A–Z alone, look-alikes off, 3 x 999: 26 distinct of 26, all in the class
V FEA-02.1 sets: chip a–z alone, look-alikes off, 3 x 999: 26 distinct of 26, all in the class
V FEA-02.1 sets: chip 0–9 alone, look-alikes off, 3 x 999: 10 distinct of 10, all in the class
V FEA-02.1 sets: chip !@#$ alone, look-alikes off, 3 x 999: 32 distinct of 32, all in the class
V FEA-02.1 sets: chip Äéß alone, look-alikes off, 3 x 999: 94 distinct of 94, all in the class
V FEA-02.2 removed set: all five chips, look-alikes on, 60 x 999 = 59,940 chars: none of l B G I O 0 1 6 8 | U+00B7; o S 5 Z 2 U+00F9 all seen; 177 distinct
V FEA-02.5 too short / FEA-02.14 invalid: lower+upper length 1 -> value "" problem Some("A character of every chosen type needs a length of at least 2.")
V FEA-02.5 length 0: problem Some("Choose a length from 1 to 999.")
V FEA-02.5 length 1000: problem Some("Choose a length from 1 to 999.")
V FEA-02.5 no characters: problem Some("Choose at least one character type.")
V FEA-02.7 uniform: 0–9 alone, look-alikes off (one group), 10,000 x 100: chi-square 21.40 (bar 44.81)
V FEA-02.7 extended: Äéß alone, look-alikes on, 10,000 x 93: 93 characters seen, U+00B7 seen false, chi-square 90.98 (bar 171.40)
V FEA-02.9 small groups: A–Z a–z 0–9, look-alikes on, length 32, 20,000: mean digits 4.290 (4.283 ± 0.06), pool 53 characters
V FEA-02.12 Larsal simple view: defaults at the field's length 4, 10,000: each one lower, one upper, one digit, one symbol, no look-alike
V FEA-02.15 strength: YQC3kbXbjC652dTDH: FEA-05 E 88.77 -> shown Good · 89 bits, 17 chars
V FEA-02.15 strength: Bs5ZFfthWzR8DGFEjaCM6bGqhmCT4km: FEA-05 E 174.00 -> shown Excellent · 174 bits, 31 chars
V FEA-02.15 empty: shown Poor · 0 bits, 0 chars; copy empty true
V FEA-02.17 popup length: field of 12 -> length 12
V FEA-02.16 edit: Use after typing demo-pass-42 -> draft "demo-pass-42"
V FEA-02.20 copy: label "Password" seconds 10 empty false; private pasteboard types ["org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType", "public.utf8-plain-text"]; holds the value true
V FEA-02.20 copy: after 11 s the private pasteboard holds the value: false
V FEA-03.3 defaults: 7 words, one space, all lower and in the list true; Good · 90 bits
V FEA-03.7 bands: 3 words: formula 38.77 -> shown Poor · 39 bits
V FEA-03.7 bands: 4 words: formula 51.70 -> shown Weak · 52 bits
V FEA-03.7 bands: 5 words: formula 64.62 -> shown Weak · 65 bits
V FEA-03.7 bands: 6 words: formula 77.55 -> shown Good · 78 bits
V FEA-03.7 bands: 7 words: formula 90.47 -> shown Good · 90 bits
V FEA-03.7 bands: 8 words: formula 103.40 -> shown Excellent · 103 bits
V FEA-03.7 bands: 9 words: formula 116.32 -> shown Excellent · 116 bits
V FEA-03.7 bands: 10 words: formula 129.25 -> shown Excellent · 129 bits
V FEA-03.7 not adjusted (Title, _): 90 bits
V FEA-03.4 separator: 4 words with . _ space: exactly 3 separators, none at the ends, 200 each; with - at least 3, none at the ends
V FEA-03.5 title and upper: 200 each, Title = first upper rest lower, UPPER = all upper, words from the list
V FEA-03.6 repeats: 100,000 passphrases of 7 words: 278 with a repeated word (270 ± 80)
V D-03-5: 0 words -> Some("Choose from 1 to 100 words.")
V D-03-5: 101 words -> Some("Choose from 1 to 100 words.")
V D-03-5: 1001 words -> Some("Choose from 1 to 100 words.")
V D-03-5: separator of 65 -> Some("The separator can have at most 64 characters.")
V D-03-7 edit: demo -> Poor · 12 bits (FEA-05 E 11.99; formula would be 90)
V secrets: a new value replaces the old (Copy holds the new); Debug Generated { value: "<hidden>", … }; close and lock leave nothing to copy; saved options hold no value
```

**S1.** The full Swift run is Part A step 4: 110 tests in 18 suites, all passed.

**S2.** The final generator run:

```
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath /tmp/e5s6v-dd test -only-testing:LarsalTests/GeneratorSnapshotTests -only-testing:LarsalTests/ParityGeneratorTests -only-testing:LarsalTests/VerifyE5S6Tests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES
```

The general pasteboard change count was 10145 before and 10145 after. Output:

```
✔ Test "Parity generator-generator-in-the-window: Generator opens the popover with a value; again closes it" passed.
✔ Test "Verify FEA-02.18 and FEA-03.15: saved on Use and on closing the window's generator, not on closing a popup" passed.
✔ Test "Parity generator-generator-in-the-window: Copy copies the shown value in Rust and says so" passed.
✔ Test "Parity generator-generator-in-the-window: New entry with it opens a new entry holding the value" passed.
✔ Test "Parity generator-generator-in-the-window: a lock closes the popover and drops the value (D-02-5)" passed.
✔ Test "Option A generator frame, offscreen, light and dark" with 3 test cases passed.
✔ Test "Parity generator-password: New password, the chips, the slider and look-alikes each make a new value" passed.
✔ Test "Parity generator-password: the editor's generate button opens it with Use password at the field's length" passed.
✔ Test "Parity generator-password: options that make nothing show the reason; Copy and Use are off (D-02-3)" passed.
✔ Test "Parity generator-passphrase: Passphrase, the separator, the case and the words slider make new phrases" passed.
✔ Test "Parity generator-password: a refused paste over 64 KiB shows the reason; Copy and Use are off (FEA-02.16)" passed.
✔ Test "Parity generator-passphrase: typing over the value rates the text; Use takes the edit (FEA-02.16, D-03-7)" passed.
✔ Test "Verify FEA-02.20, LD-181, LD-204: Copy through the screen: markers, notice, stays open, cleared after 10 s" passed.
VERIFY E5S6 saving: popup Use saves 24; popup close keeps 24; passphrase 9 restored; window close saves 33
VERIFY E5S6 copy: types ["NSStringPboardType", "org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType", "public.utf8-plain-text"]; toast Password copied. Clears in 10 s.; strength Excellent · 112 bits
VERIFY E5S6 copy: after 11 s private pasteboard holds the value: false
✔ Test run with 13 tests in 3 suites passed.
** TEST SUCCEEDED **
```

**S3.** `xcodebuild … test -only-testing:LarsalTests/VerifyE5S6MemoryTests` printed `✔ Test run with 1 test in 1 suite passed after 1.542 seconds.` and `** TEST SUCCEEDED **`. The scan output is in section 3.

## Noise and other agents' work

- **The general pasteboard count over the full run.** It went from 10142 to 10143 during the 110-test run. That run also had other agents' tests and the owner at work. The generator suites run alone left it at 10145 and 10145, and the in-test check (`ParityGeneratorTests` `copy`) passed both times. Per the brief, this is noise, not a fail.
- **ParityEditorPagesTests.swift compile error.** The copy had E5-S5's unfinished version; the tree's fixed file built.
- **`reports::tests` failures.** Two of them fail in the copy's larsal-ffi lib. That is unfinished E5-S7 work.

## Open issues (advisory; not fails)

1. **M10 survived.** `close_generator`'s separator filter is not tested at its boundary. The smallest fix is to add a case to R `d_03_5_oversized_separator_is_not_saved`: save a 65-character separator, then expect the saved options to be unchanged. Generation itself is guarded twice (larsal-ffi and larsal-core).
2. **The builder's R tests never check randomness (M11).** That is covered by larsal-core `fea02` and `fea03` and by Verify's statistical rows. If more cover is wanted, one R test could assert that two values differ.
3. **W-10 (LD-204).** These are waiting for the owner's mockup addition, then their build and Verify:
   - the length field 1 to 999 and the words field 1 to 100;
   - every group;
   - Advanced: the symbol chips, extra, excluded and hex;
   - the mixed case chip;
   - the word-list picker.
4. **The check box tick.** The shared `CheckMark` draws Phosphor `check` at 12 pt, thinner than the mockup's 2-px CSS tick. This is inside the pixel limit, and it is the same in every section.
5. **Mac QA.** Focus on a real key window (LD-169), and an lldb memory dump of Larsal.app with the field rendered (AT-C02; developer mode is off on this Mac).

## Files

- Changed by Verify:
  - design/parity/generator/report.html, report.md and findings.json, plus app/ and diff/ (regenerated by compare.mjs, with a Verify section appended);
  - this file;
  - the E5-S6 status line in plan/epics.md.
- Not changed: product code, notes.mjs and the reference images.
- Snapshots checked: design/parity/generator/app/{light,dark}/generator-generator-in-the-window.png, generator-password.png and generator-passphrase.png. Diffs: design/parity/generator/diff/{light,dark}/ with the same names.

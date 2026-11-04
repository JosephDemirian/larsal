# E13-S6 part c, Checker 1 round 3 findings (2026-10-30)

Sent back after round 3; the lead takes the Checker's tested fix in part c2 (LD-229). Each finding is copied as the Checker returned it. Setup lines: the top of security/findings.md.

## Finding 1: F-015: C0 controls, DEL, CAN and SUB inside terminal codes split the guard's view but not the screen (scripts/check-names.sh lines 92-97, TERM, and line 242 in shown())

**Problem.** These rules are in the vte-derived state table (local cargo registry, anstyle-parse-1.0.0/src/state/codegen.rs; the DEC parser model): (a) In CsiEntry/Param/Intermediate and Escape/EscapeIntermediate, bytes 0x00-0x17, 0x19 and 0x1C-0x1F are run and the code goes on; 0x7F is ignored. (b) 0x18 (CAN) and 0x1A (SUB) end any code or string from any state. TERM allows no C0 inside a CSI. It needs a final byte, so an unfinished CSI leaves its parameters behind, and a parameter byte after an intermediate ends it. The ESC rule removes only ESC plus one character. String bodies run past CAN and SUB. Using the setup lines in security/findings.md, each of these prints names: PASS, exit 0 (format gets "${W:0:3}" "${W:3}"): '%s\033[\007m%s', '%s\033[1\0101m%s', '%s\302\233\0071m%s', '%s\033(\007B%s', '%s\033\007X%s', '%s\033[1\177m%s', '%s\033\177X%s', '%s\033[ 1m%s', '%s\033[1\030%s', '%s\033]\030%s', '%s\033]0;x\030%s', '%s\033P\030%s', '%s\033_\032%s'. A run inside the code can also move the cursor: 'XXX' + k[3:] + '\x1b[\r1m' + k[:3] shows k on a terminal. The guard deletes or mangles that \r, so its terminal view misses it. The F-015 row says 'the others end only at ST', which a VT-style parser (the vte table) does not do.

**Smallest fix (tested by the Checker in a private copy).**

```
Replace TERM with these lines (the comment can be reworded):
# As a VT parser reads them: CAN, SUB or ESC end any code; C0 controls inside a CSI or ESC code run without ending it (kept, so the terminal view sees a backspace or carriage return there); DEL there is ignored.
C0 = '\x00-\x17\x19\x1c-\x1f\x7f'
TERM = re.compile('(?P<s>(?:\x1b\\]|\x9d)[^\x07\x18\x1a\x1b\x9c]*[\x07\x9c]?|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f])[^\x18\x1a\x1b\x9c]*\x9c?)' '|(?:\x1b\\[|\x9b)[%s -?]*[@-~]?|\x1b[%s -/]*[0-~]?' % (C0, C0))
In shown(): t = MARK.sub('', TERM.sub(lambda m: '' if m['s'] else re.sub('[^\b\r\n\t]', '', m[0]), TAG.sub('', t))).
Add two cases after 'F-015 8-bit terminal codes':
('F-015 C0, CAN and SUB inside terminal codes', 'can.txt', k[0] + '\x1b[\x071\x7fm' + k[1] + '\x1b(\x07B' + k[2] + '\x1b]0;x\x18' + k[3] + '\x1bP\x1a' + k[4] + '\x1b[1\x18' + k[5] + '\x1b[ 1m' + k[6:])
('F-015 carriage return inside a terminal code', 'csicr.txt', 'XXX' + k[3:] + '\x1b[\r1m' + k[:3])
Tried in my private copy: self-test PASS (92 hits); all 13 repros and the 21 older repros give FAIL; the copy scans PASS (2917 files, 9.6 s user). Worst cases stay linear: 500k ESC [ in 0.24 s, 1M ESC in 0.44 s. The current guard with only these cases added misses both. Each of the 11 mutants of the fix fails the self-test: no C0 in CSI, no C0 in ESC, CAN not ending OSC, SUB not ending DCS, CSI final required, C0 dropped instead of kept, DEL not in the class, old CSI shape, BEL alone left out of the C0 class, and the two in the next finding. Also update the TERM comment, the header, and the F-015 row ('BEL ends only OSC; strings end at ST; CAN, SUB or ESC end any code; C0 controls inside CSI and ESC codes are run').
```

## Finding 2: F-015: the new self-test cases leave part of the round-2 fix unchecked (scripts/check-names.sh lines 463-465)

**Problem.** No case checks that BEL ends an OSC. Mutant MOSTB passes the self-test: in the OSC rule, [^\x07\x1b\x9c]*[\x07\x9c]? becomes [^\x1b\x9c]*\x9c?. With MOSTB, '%s\033]0;x\007%s' (an OSC title ended by BEL, the way xterm and every common terminal use it) would pass the guard. The 8-bit case holds only DCS (U+0090): removing \x98, \x9e or \x9f alone from [\x90\x98\x9e\x9f] passes the self-test (mutants MD98, MD9E, MD9F). The builder's mutant MD only removed all four at once.

**Smallest fix (tested by the Checker in a private copy).**

```
End 'F-015 BEL inside a control string' with an OSC closed by BEL: k[:3] + '\x1b_junk\x07junk\x1b\\' + k[3:5] + '\x1b]0;x\x07' + k[5:]. Add 8-bit SOS, PM and APC to 'F-015 8-bit terminal codes': k[:1] + '\x9b1m' + k[1:2] + '\x9d0;x\x9c' + k[2:3] + '\x90junk\x07junk\x9c' + k[3:4] + '\x98a\x9c' + k[4:5] + '\x9eb\x9c' + k[5:6] + '\x9fc\x9c' + k[6:]. Tried in my private copy: with these cases, the mutants for BEL not ending OSC and for \x98 dropped each fail the self-test. The current code still passes.
```

## Checker notes for the lead

- F-015 loop: if you would rather not run a 4th round on this Low finding, the other choice is to accept these as a known limit in the guard header ('C0, DEL, CAN or SUB inside terminal codes are not read as a terminal reads them'). I advise fixing instead: the fix is the small, tested change given under findings, and a red team re-test would find these repros.
- Builder's proposal on raw single C1 bytes (non-UTF-8 terminals): I agree to accept it. The raw Latin-1 view does not go through shown() (line 246). macOS terminals run in UTF-8. A related limit I also advise accepting: a C1 code point inside a 7-bit code. VTE stops the code there, but the vte crate's byte table does not, so whichever rule the guard picks, one terminal leaves a gap. Both should be one line under Known limits in the header, added in the next fix pass.
- F-017 residual (an explicit `bash scripts/check-names.sh` run with a hostile BASH_ENV), carried over by the builder: I agree to accept it. It needs control of the environment, and the header already names it.

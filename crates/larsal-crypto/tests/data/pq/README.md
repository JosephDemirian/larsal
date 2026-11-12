# Post-quantum known answers (CRY-05.16, story E25-S2)

The files here are cuts of published test vectors that `src/pq/tests.rs` reads in every
`cargo test`. Each test checks its file's SHA-256 (the "kept" column) before reading it.
`cut.py` remakes every file from the downloads, byte for byte:

    python3 -B -I cut.py <downloads> <out>

The cut keeps only the ML-KEM-768 and ML-DSA-65 cases (no pre-hash groups: Larsal has no
HashML-DSA), the composite case `id-MLDSA65-Ed25519-SHA512` and Appendix C of X-Wing draft 11.
It writes one line per record: a kind, then `key=value` pairs. Values are lower-case hex, and
results are words. A `group` line sets fields for the lines below it. Nothing is computed: every
value is copied from its file.

Downloaded 2026-11-09 (LD-428). Commits without a tag were pinned with `git ls-remote` at
2026-11-09T12:21:21Z.

| Kept file | Bytes | Kept SHA-256 | Source, pinned | Downloaded SHA-256 |
|---|---|---|---|---|
| `mlkem768-acvp.txt` | 443,480 | `491953645a0d8be76ce5abe3b71606c8948b08e88d8b2131925b7a5a6bcd271f` | usnistgov/ACVP-Server at `975de31eb83d87039ec88934fdc47d8c312b892d`, `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json` and `ML-KEM-encapDecap-FIPS203/internalProjection.json` (https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/…) | keyGen `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b`; encapDecap `a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f` |
| `mlkem768-wycheproof.txt` | 2,648,723 | `d1da45e27e10ad0a5f51499b43a07b9ffb65a25f986af8a23211c7118eabdfa2` | C2SP/wycheproof at `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`, `testvectors_v1/mlkem_768_test.json`, `mlkem_768_encaps_test.json`, `mlkem_768_keygen_seed_test.json`, `mlkem_768_semi_expanded_decaps_test.json` (https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/…) | `c59c067ae794c343df575dd90f6f7458f51881b11a22d6e9d8677c8d9ee21e90`; `9d4381f94c40853bba430245b94968b7390d9175aacd9f1ae4e250a71c78b713`; `fde5abe284396f4cb3c4610b90d680f0b57782e94c3365c97aee59e24881ebe4`; `e4438ab7d4dd7b6ace7165e45aeed4403082f981f86300c8369f69d3d071060a` |
| `mldsa65-acvp.txt` | 2,791,716 | `c32e32783c82088bc1ba0ab4d6a375d6e309e92c6dfa4e55d8afa36f48369620` | usnistgov/ACVP-Server at `975de31eb83d87039ec88934fdc47d8c312b892d`, `gen-val/json-files/ML-DSA-keyGen-FIPS204`, `ML-DSA-sigGen-FIPS204` and `ML-DSA-sigVer-FIPS204`, each `internalProjection.json` | keyGen `e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf`; sigGen `72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22`; sigVer `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437` |
| `mldsa65-wycheproof.txt` | 2,356,012 | `53cebf39c3d23a904c725633baca8e24dd029e01f355debe639ea5506f4b7f03` | C2SP/wycheproof at `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`, `testvectors_v1/mldsa_65_verify_test.json` and `mldsa_65_sign_seed_test.json` | `1ca235f61928421a173a171780beb00264ae9155dc33c52a11e1766cc7979034`; `e26b2bb9ab8d45ed570ba6828c7e40b6fa3e1545bb8bc2c449c77531760133e0` |
| `composite-mldsa65-ed25519.txt` | 17,920 | `d4cadfadfe63f6fb8526633cf899164f5ae4bf031760573199bfee86304d8e2b` | RFC 10073 Appendix E, test case `id-MLDSA65-Ed25519-SHA512`: lamps-wg/draft-composite-sigs at `f0627ab34acfe1aee0abce4bee91ed2b577eab76` (2026-01-07, the commit the RFC names), `src/testvectors.json`, from https://codeload.github.com/lamps-wg/draft-composite-sigs/tar.gz/f0627ab | tarball `9fb83337bba1ad4b09de19845a84e5f86a2800f1906510edaac56a40ea08d902`; `src/testvectors.json` inside it `a60f697f9fd94c3cd5e4501a40c4396d9a9ffc7cf0f8a1ddd87dedbb46a7abf0` |
| `xwing-draft11.txt` | 15,156 | `18134890933e3f86ce21771d98813800a65b6328e6cbc0bc49099e9c1d7d19c6` | X-Wing draft 11 Appendix C, **provisional** (the appendix says its vectors will be replaced; a later draft's replace them only by a card change): https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-11. The same three vectors as the vendored x-wing 0.1.1's `tests/test-vectors.json`. The pin is the kept file's SHA-256 with the draft's name and number, draft-connolly-cfrg-xwing-kem-11. | Not a pin: datatracker makes the page anew on each fetch, so its SHA-256 changes (three fetches on 2026-11-09 gave `41f7d35a…`, `02c1cd02…` and `4bbd171c…`), and `cut.py` gives the kept file byte for byte from each. |
| `cut.py` | 7,834 | — | Larsal's own script (above) | — |

Total kept: 8,273,007 bytes of vectors, plus `cut.py` and this README.

Not here, because the tests read them in place: the hybrid HPKE suite's record (25722, 1, 3)
in `vendor/crates-io/hpke-0.14.1/test-vectors/pq-6433c8f.json` (hpkewg/hpke-pq at commit
6433c8f, SHA-256 `35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c`), and the
`mlkem768_x25519` vectors in `hybrid-defafa2.json` next to it
(cfrg/draft-irtf-cfrg-concrete-hybrid-kems at commit defafa2, SHA-256
`08b47d9fe5c827f7ceb20dd10a59bc853a949d6eaf0ad835405e86d833f92bad`). The copy's checksum list
(scripts/check-vendor.sh) pins both too.

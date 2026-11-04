# E14-S1: Larsal name and integration

Verified 2026-11-04. The product, crates and imports, command, native project/package/targets, identifiers, environment variables and vault/key/share extensions use the current Larsal names. Platform and generic terms, vendor bytes, exact owner quotations and dated proof retain their recorded scope. The first-party licensing amendment is verified in [E14-S2](E14-S2-license.md#current-source-available-terms).

## Source and review binding

The tested source has 11,612 files. Frozen inventory SHA-256: `7530d5dd07bba32434ba37111595a839790510b817c7c5a32f3fdfef4315ba99`; runtime source-manifest SHA-256: `b5facb8f32a6bb2ed92776af3e56787b6341b456c55e599e2e0939e65ad7592a`. Independent source reviews, known-answer controls and runtime/artifact verification passed. Runtime/artifact report SHA-256: `4c408efb1e1ac0afec26fdd0f1dd71ae0152adbe6393be1c1a637c9b15a25a82`. Actual-main integration signoff SHA-256: `24e2dce599e1bfa87555a280030fe8a39a2506083c629b9571de5b8ca470b9c2`.

All 8,141 vendor records, 27 inventoried quotation spans and 292 historical snapshot files retain their expected bytes and permissions. The 42,135 retained lexical matches have classified reasons; none is unclassified. The later completion changes are Markdown evidence/status updates only; they are reviewed separately and do not relabel the earlier whole-source execution hash.

## Complete check

The actual child command was `env CARGO_BUILD_JOBS=8 bash scripts/check.sh`, offline in its private fixture. It exited 0 in 1,368.65 seconds under the existing 1,790-second cap. Actual terminal summary:

```text
G1 static ......... PASS (unsafe count 413 in 18 crates)
G2 tests .......... PASS
deny .............. PASS
audit ............. PASS
fuzz smoke ........ PASS (29 targets, 30s each)
Overall ........... PASS
```

| Scope | Passed | Failed | Ignored |
|---|---:|---:|---:|
| Workspace, 134 printed harnesses | 3,170 | 0 | 72 |
| Network, 3 harnesses | 66 | 0 | 7 |
| Timed release, 6 harnesses | 275 | 0 | 0 |
| Browser release | 45 | 0 | 0 |
| APP-09 | 18 | 0 | 0 |

Xcode reports 398 tests in 57 suites passed in 290.540 seconds and TEST SUCCEEDED. All 29 manifest targets occur exactly once in the fuzz list, retain the original seed/output paths and `-max_total_time=30`, and have positive Done markers at 31 seconds. Four targets run at a time; parent waits collect every failure. Six private regression cases cover out-of-order completion, multiple failures, failed cleanup/mkdir, final-batch drain and owned-process cancellation. Earlier full-command timeouts remain negative history. The longer runtime request was not approved and was unnecessary for this passing run.

Separate retained sync-package proof has 428 passed, 0 failed and 8 ignored on unchanged inputs. Printed totals do not imply that ignored manual cases or helper tests ran. Twelve demo interoperability cases passed under the restrictive private environment; their normalization, history-attachment export and duplicate-path limits remain. No reference code was copied or translated.

## Isolation and findings

F-133's E14 remainder and F-289 through F-295 are independently verified. Production attachment-copy path selection ignores hostile test overrides; debug/test roots are private, owned and validated. Release isolation tests report 5 passed/1 child ignored; cleanup-parent tests report 2 passed/2 children ignored, with explicit parent assertions and two rejected unsafe mutations. The existing serialization fix remains.

Clipboard tests retain all three private-provenance assertions and make no general-pasteboard observation. Five shell helpers fail closed when private temporary allocation fails. Compiler, Swift temporary-root and hidden-child routes have retained positive/negative controls and restrictive-profile proof. Current generated output contains 168 PNG and 160 accessibility JSON files under the private target snapshot directory; all 292 historical inputs are unchanged. This is output custody, not a fresh visual-parity claim.

Changed synthetic demo answers were independently derived through public primitives, with original answers as controls. Hardware-secret length, stream shape, assertions and malformed-corpus modes remain intact. No cipher implementation or security threshold was relaxed.

## Actual main application

The same reviewed one-time script, SHA-256 `68a7f749c926b2f979760fbaadb89820ad8fd91ee7afd3d7e0e8c9772024cb9c`, was applied to main: 1,307 files changed, 999 paths moved, no deferred ledgers. Actual main then matched all 11,612 frozen paths, bytes and full modes, including 1,666 parent directories plus the root. The second apply changed zero files and paths; the audit passed.

Cleanup removed only the obsolete Generated link itself, eight identity-checked empty directories and two identified old build-output roots. Fresh open-file checks were quiet before output removal. No links were followed and no process was stopped. Owner cache and README bytes were preserved. Independent actual-main verification signed this integration before completion metadata was written.

## Current artifacts and release limits

Fresh copied CLI license output matches the approved terms and credit. Strict app and bridge signature checks pass; generated and packaged bridge code matches after signature-only normalization. Names, intentional Debug identifier, version, license, fonts, credits, resource notice and BOM were rebound to the completed outputs.

These are ad-hoc development signatures. Developer ID, notarization, document associations, public release, legal review, outside audit and visible Mac QA retain their own gates. No full official BOM-schema validation or legal certification is claimed.

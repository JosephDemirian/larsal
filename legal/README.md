# App's licenses

Owner decision D2 (README.md) and LD-262 (3) (spec/decisions.md), 2026-10-31. This page says it in plain words; the license files are the legal texts.

**A lawyer must read both drafts, [CONTRIBUTOR-AGREEMENT.md](CONTRIBUTOR-AGREEMENT.md) and [TEAMS-LICENSE.md](TEAMS-LICENSE.md), before the first sale and before App accepts the first outside contribution.**

The licensor is written as "[Licensor legal name]" until the company and the product name are set (README decision D1).

## Which license covers which part

| Part | Where | License |
|---|---|---|
| The Mac app, the engine and the `app` command line tool | everything in this folder today: `macos/`, `crates/`, `fuzz/`, `scripts/` and the rest | **GPL-3.0-or-later**: [LICENSE](../LICENSE) |
| The sync server | `crates/app-server/` | **AGPL-3.0-or-later**: [crates/app-server/LICENSE](../crates/app-server/LICENSE) |
| The team features of the server | one folder of the server, not built yet; never in the Mac app | **App Teams License**, paid: [TEAMS-LICENSE.md](TEAMS-LICENSE.md) |
| Work from outside contributors | any part | The contributor signs [CONTRIBUTOR-AGREEMENT.md](CONTRIBUTOR-AGREEMENT.md) first |
| Third-party code, fonts and data | `vendor/`, the app bundle | Their own licenses: `THIRD-PARTY-NOTICES.md` (made by `scripts/make-sbom.sh`, shipped in App.app), [LICENSES.md](../macos/App/Resources/LICENSES.md) (fonts, icons, logos), and the built-in word list's CC BY 4.0 |

In plain words:

- **GPL-3.0-or-later:** anyone may use, change and share App. Whoever shares App, changed or not, must also offer its source under the same license. There is no warranty. App shows this notice in its About window and in `app --license`.
- **AGPL-3.0:** the same for the server, and whoever runs a changed server for others must also offer them its source.
- **App Teams License:** anyone may read and test the team features for free. Real use needs a paid subscription or license file from us. Nobody else may sell the team features, host them for others, give copies to anyone outside their company, or get around the license file check.
- **Contributor agreement:** contributors keep their copyright. They give us a license that lets us also sell App under other licenses, for example for the App Store. In return we promise that each contribution also stays under the license its part had when it was sent.

## Why these texts

- **GPL-3.0:** the exact text of <https://www.gnu.org/licenses/gpl-3.0.txt> (read 2026-10-31, SHA-256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`; the test `e14_2_license_is_the_exact_gpl_3_0_text` checks it). The "or later" notice in README.md is the one in the license's own "How to Apply These Terms to Your New Programs".
- **AGPL-3.0:** the exact text of <https://www.gnu.org/licenses/agpl-3.0.txt> (read 2026-11-01, SHA-256 `0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0`; the test `e16_3_server_license_is_the_exact_agpl_3_0_text` checks it). The server takes the "or later" form too (LD-303 (4)).
- **Contributor agreement: the Harmony agreements.** They are a license, not a transfer: the contributor keeps the copyright. Their Option Five lets the maker license a contribution under any license, commercial ones included, which the paid license and the App Store need, and promises that the contribution also stays under the project's own license, the fairer kind of agreement that [business-model.md](../spec/research/business-model.md) section 2 (What this means for App) asks for. They come in matched versions for individuals and for entities, and their license (CC BY 3.0) lets us reuse them with credit. Studied and not used: the Apache Software Foundation's ICLA and CCLA (also a license, and the ASF's license FAQ allows reuse, but it promises only use that fits the ASF's nonprofit status and says nothing about other licenses), and Bitwarden's Contributor Agreement (a copyright assignment, which takes the contributor's copyright, and it gives no right to reuse its text).
- **Teams license: the PolyForm Free Trial and Internal Use licenses 1.0.0.** Their terms let anyone use and change them, on the condition that a changed text no longer names PolyForm; so TEAMS-LICENSE.md does not. We kept their plain grants, patent defense and liability terms, took the 32-day fix of Internal Use, and wrote App's own terms for testing, production use with a license file, no sale, no hosting for others and the license file check. The model is the one of Bitwarden's license for its paid server folder and of GitLab's Enterprise Edition license: free for development and testing, production use only with a paid subscription. Studied and not used: the Bitwarden License Agreement v1 and the GitLab EE license (no right to reuse their text), and the Elastic License 2.0 (no reuse statement found on elastic.co; its rule against getting around the license key is written in our own words).
- **Word list:** EFF's copyright page puts its own material under CC BY 4.0, and the FSF lists CC BY 4.0 as compatible with every GNU GPL version, so the list can be compiled into App. Its attribution is `ATTRIBUTION` in `crates/app-core/src/generator/wordlist.rs`.

## Sources (read 2026-10-31)

- GNU GPL version 3: <https://www.gnu.org/licenses/gpl-3.0.txt>. GNU AGPL version 3: <https://www.gnu.org/licenses/agpl-3.0.txt> (read 2026-11-01). The FSF license list: <https://www.gnu.org/licenses/license-list.html> (CC BY 4.0, MPL-2.0, Apache-2.0).
- Harmony agreements: <https://www.harmonyagreements.org/agreements>, the combined template <https://www.harmonyagreements.org/docs/ha-combined-v1>, how to use them <https://harmonyagreements.org/use>.
- Apache: the ICLA <https://www.apache.org/licenses/icla.pdf>, reuse of the CLAs in the license FAQ <https://www.apache.org/foundation/license-faq.html>.
- Bitwarden: its Contributor Agreement (the text that <https://cla-assistant.io/bitwarden/clients> signs), <https://github.com/bitwarden/server/blob/main/LICENSE_BITWARDEN.txt> and <https://github.com/bitwarden/server/blob/main/LICENSE_FAQ.md>.
- GitLab EE license: <https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/LICENSE>.
- Elastic License 2.0: <https://www.elastic.co/licensing/elastic-license> and its FAQ.
- PolyForm: <https://github.com/polyformproject/polyform-licenses> (README section "License", and the 1.0.0 texts of Free Trial and Internal Use).
- EFF: <https://www.eff.org/copyright>.

## Still open

- The licensor's legal name, address and jurisdiction (D1 and the company); how contributors sign (for example a signing check on pull requests, with E14-S6).
- The team folder's path and file headers, when the team features are built (E18).
- Each binary release must come with its source or a written offer of it (GPL-3.0 section 6): the public repository at the same tag (E14-S6).
- For the lawyer: whether the teams license's rule against copies outside your company also covers a public fork or a published patch of the team folder.

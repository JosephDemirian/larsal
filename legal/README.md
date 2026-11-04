# Larsal's license

Larsal's original code, executables, documentation and assets are covered by the [Larsal Source-Available License 1.0](../LICENSE). Joseph Demirian is the licensor. This page summarizes the terms; `LICENSE` is the legal text.

## In plain words

- You may inspect and download the source, compile it unchanged, and run it for personal or private family use, or your organization's internal use, including business use. This includes self-hosting solely for your private family group or organization; providing hosting to customers or the public requires written permission. Paid-feature restrictions still apply.
- You may share unmodified copies for free, keeping the license, copyright and third-party notices.
- Modification, resale, charging for access, rebranding, bypassing paid-feature restrictions, or using Larsal's code or assets to develop or operate a competing product or service requires prior written permission. Ordinary build configuration and runtime settings are allowed.
- Independently created software that does not copy Larsal's protected material is not prohibited.
- This is source-available software, not open-source software. It comes with no warranty, subject to applicable law. Contact <hello@JosephDemirian.com> for separate permission.

## Third-party material and earlier rights

Third-party code, fonts, icons, word lists and data keep their own licenses. This includes permissive licenses, MPL-2.0 covered files and modifications, OFL fonts, and the unmodified CC BY 4.0 word list. The repository license does not restrict those grants. See `THIRD-PARTY-NOTICES.md`, made by `scripts/make-sbom.sh` and shipped in Larsal.app, [the resource notices](../macos/Larsal/Resources/LICENSES.md), and the relevant source directories.

Rights already granted under an earlier license are not revoked. Earlier signed contributor or commercial agreements keep their own terms; this policy does not rewrite them.

## Earlier drafts

[CONTRIBUTOR-AGREEMENT.md](CONTRIBUTOR-AGREEMENT.md) and [TEAMS-LICENSE.md](TEAMS-LICENSE.md) are retained historical drafts from 2026-10-31. They are withdrawn as offers for new contributions or new licenses. The current repository permissions come from `LICENSE`; separate permissions need a written agreement.

- The contributor drafts adapt the Harmony Combined Contributor Agreement Template, Version 1.0 (2011-07-04), by Project Harmony, under [CC BY 3.0](https://creativecommons.org/licenses/by/3.0/). Their full attribution and changes remain in [the draft](CONTRIBUTOR-AGREEMENT.md#source-and-attribution). Its Section 2.3 promised the contribution's submission-date license as well as any other license; an earlier signed agreement retains that promise.
- The team draft adapts the [PolyForm Free Trial and Internal Use licenses 1.0.0](https://github.com/polyformproject/polyform-licenses), whose reuse terms require a modified license to use a different name. It retained their plain grants, patent defense and liability terms, used Internal Use's 32-day cure period, and added the project's evaluation, paid production use and license-file terms. That draft is not the current repository license.

The earlier licensing research remains in [business-model.md](../spec/research/business-model.md) and the historical decisions in [spec/decisions.md](../spec/decisions.md).

## Legal review gate

**A lawyer must review the current license and any contribution or commercial agreement before the first sale, first outside contribution or public release.** The earlier draft review requirement remains; changing the repository license does not satisfy it. Contributor signing, any separate paid terms and their legal details still need that review.

<details>
<summary>Historical license research (2026-10-31 and 2026-11-01)</summary>

The following rationale, sources and recorded checks describe the retired license policy. They are retained as history, not current permissions or acceptance criteria; LD-345 supersedes that policy.

## Why these texts

- **GPL-3.0:** the exact text of <https://www.gnu.org/licenses/gpl-3.0.txt> (read 2026-10-31, SHA-256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`; the test `e14_2_license_is_the_exact_gpl_3_0_text` checks it). The "or later" notice in README.md is the one in the license's own "How to Apply These Terms to Your New Programs".
- **AGPL-3.0:** the exact text of <https://www.gnu.org/licenses/agpl-3.0.txt> (read 2026-11-01, SHA-256 `0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0`; the test `e16_3_server_license_is_the_exact_agpl_3_0_text` checks it). The server takes the "or later" form too (LD-303 (4)).
- **Contributor agreement: the Harmony agreements.** They are a license, not a transfer: the contributor keeps the copyright. Their Option Five lets the maker license a contribution under any license, commercial ones included, which the paid license and the App Store need, and promises that the contribution also stays under the project's own license, the fairer kind of agreement that [business-model.md](../spec/research/business-model.md) section 2 (What this means for Larsal) asks for. They come in matched versions for individuals and for entities, and their license (CC BY 3.0) lets us reuse them with credit. Studied and not used: the Apache Software Foundation's ICLA and CCLA (also a license, and the ASF's license FAQ allows reuse, but it promises only use that fits the ASF's nonprofit status and says nothing about other licenses), and Bitwarden's Contributor Agreement (a copyright assignment, which takes the contributor's copyright, and it gives no right to reuse its text).
- **Teams license: the PolyForm Free Trial and Internal Use licenses 1.0.0.** Their terms let anyone use and change them, on the condition that a changed text no longer names PolyForm; so TEAMS-LICENSE.md does not. We kept their plain grants, patent defense and liability terms, took the 32-day fix of Internal Use, and wrote Larsal's own terms for testing, production use with a license file, no sale, no hosting for others and the license file check. The model is the one of Bitwarden's license for its paid server folder and of GitLab's Enterprise Edition license: free for development and testing, production use only with a paid subscription. Studied and not used: the Bitwarden License Agreement v1 and the GitLab EE license (no right to reuse their text), and the Elastic License 2.0 (no reuse statement found on elastic.co; its rule against getting around the license key is written in our own words).
- **Word list:** EFF's copyright page puts its own material under CC BY 4.0, and the FSF lists CC BY 4.0 as compatible with every GNU GPL version, so the list can be compiled into Larsal. Its attribution is `ATTRIBUTION` in `crates/larsal-core/src/generator/wordlist.rs`.

## Sources (read 2026-10-31)

- GNU GPL version 3: <https://www.gnu.org/licenses/gpl-3.0.txt>. GNU AGPL version 3: <https://www.gnu.org/licenses/agpl-3.0.txt> (read 2026-11-01). The FSF license list: <https://www.gnu.org/licenses/license-list.html> (CC BY 4.0, MPL-2.0, Apache-2.0).
- Harmony agreements: <https://www.harmonyagreements.org/agreements>, the combined template <https://www.harmonyagreements.org/docs/ha-combined-v1>, how to use them <https://harmonyagreements.org/use>.
- Apache: the ICLA <https://www.apache.org/licenses/icla.pdf>, reuse of the CLAs in the license FAQ <https://www.apache.org/foundation/license-faq.html>.
- Bitwarden: its Contributor Agreement (the text that <https://cla-assistant.io/bitwarden/clients> signs), <https://github.com/bitwarden/server/blob/main/LICENSE_BITWARDEN.txt> and <https://github.com/bitwarden/server/blob/main/LICENSE_FAQ.md>.
- GitLab EE license: <https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/LICENSE>.
- Elastic License 2.0: <https://www.elastic.co/licensing/elastic-license> and its FAQ.
- PolyForm: <https://github.com/polyformproject/polyform-licenses> (README section "License", and the 1.0.0 texts of Free Trial and Internal Use).
- EFF: <https://www.eff.org/copyright>.

</details>

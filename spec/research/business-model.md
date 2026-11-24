# How Larsal is built and sold: research

> Licensing update (LD-345, 2026-11-04): the former GPL/AGPL/paid-draft licensing recommendations below are historical and superseded. Current first-party permissions come from the root LICENSE. Third-party licenses and their recorded research remain unchanged.


For the owner's vision of 2026-10-31. The plan that comes from it is [plan/product-vision.md](../../plan/product-vision.md).

Date: 2026-10-31. Research only. No product code, build file or other plan file was changed.

How to read this file:
- Every fact has its source link. All pages were read on 2026-10-31, unless a fact says otherwise.
- Prices are **as of 2026-10-31**. Bitwarden changed its prices in January 2026. Check every price again before you use it in public.
- Facts about Larsal come from project files. Their paths are given.
- Larsal is the product name ([AGENTS.md](../../AGENTS.md), Naming). The reference app is not named (rule 1).
- Only public pages were read. No project content was sent to any site. No code was copied.

The owner's question, shortened: build and sell Larsal the way Bitwarden does. But Larsal is a Mac app, not a web app on a server. People download it, keep the vault encrypted, and sync it through any cloud. Later, a subscription for family or team sync. Maybe a server that people host themselves, with the app as its client. Many versions from one code base. Sell part of it, but stay open source so people can check that it is safe.

## Contents

1. Bitwarden plans and self-hosting
2. Licensing and how it builds in the open
3. Cryptography of sync and sharing
4. Any-cloud native apps and how they sell
5. Selling a Mac app
6. Fit to Larsal
7. Open questions

## 1. Bitwarden plans and self-hosting

### 1.1 Plans for people (as of 2026-10-31)

- **Free:** $0, shown as "Always free". Unlimited passwords and devices, sync, generator, passkeys, encrypted export, two-step login, phishing protection, email alias integration, Send (text only), and sharing with one other person. Source: [Bitwarden Pricing (personal)](https://bitwarden.com/pricing/).
- **Premium:** $1.65 a month, or $19.80 billed yearly, for 1 person. Adds an authenticator (TOTP codes), 5 GB of file attachments, emergency access, vault health reports and alerts with password coaching, Send with files, more two-step login options (up to 10 security keys, Yubico OTP, Duo), priority support and self-hosting options. Source: [Bitwarden Pricing (personal)](https://bitwarden.com/pricing/).
- **Families:** $3.99 a month, or $47.88 billed yearly, for up to 6 Premium accounts. Adds unlimited sharing and collections, 5 GB personal plus 5 GB shared storage, and self-hosting options. Source: [Bitwarden Pricing (personal)](https://bitwarden.com/pricing/).
- **The January 2026 change:** on 2026-01-20 Bitwarden raised Premium to $1.65 a month ($19.80 a year) and Families to $3.99 a month. It added health alerts, password coaching and a phishing blocker ("coming soon"), raised storage to 5 GB and security keys to 10, and gave existing customers a one-time 25% discount. It said the free plan "remains unchanged". Source: [Bitwarden launches enhanced premium plan (Bitwarden Community Forums)](https://community.bitwarden.com/t/bitwarden-launches-enhanced-premium-plan/93006).
- **Free organization:** 2 users and 2 collections, no attachments, text-only Send. Families, Teams and Enterprise organizations have unlimited collections. The page says it is current "as of June 4, 2024", so it may be out of date. Source: [Password Manager Plans (Bitwarden Help)](https://bitwarden.com/help/password-manager-plans/).

### 1.2 Plans for businesses (as of 2026-10-31)

- **Teams:** $4 per user a month, billed yearly, unlimited users. Event and audit logs, Directory Connector, SCIM, collections, API access, user groups and Duo for the organization. No self-host option. Source: [Bitwarden Business Pricing](https://bitwarden.com/pricing/business/).
- **Enterprise:** $6 per user a month, billed yearly. Adds SSO, policies, custom roles, account recovery, Access Intelligence, a free Families plan for every member, and self-hosting. 14-day trial. Source: [Bitwarden Business Pricing](https://bitwarden.com/pricing/business/).
- **Teams Starter** closed to new organizations on 2024-06-11. Existing customers keep their price. Source: [Updates to Password Manager Plans & Subscriptions (Bitwarden Help)](https://bitwarden.com/help/updates-to-plans/).
- **Storage:** paid organizations get 5 GB of attachment storage, then $0.33 per GB a month, and a 14-day trial. Source: [About Organizations (Bitwarden Help)](https://bitwarden.com/help/about-organizations/).
- **Secrets Manager:** Free has 2 users, 3 projects and 3 machine accounts. Teams is $6 per user a month with 20 machine accounts. Enterprise is $12 per user a month with 50. Extra machine accounts are $1 each. Self-hosting is "Coming Soon". Sources: [Secrets Manager Plans (Bitwarden Help)](https://bitwarden.com/help/secrets-manager-plans/) for the limits, [Bitwarden Business Pricing](https://bitwarden.com/pricing/business/) for the prices.
- **Passwordless.dev:** Free up to 10,000 users and 1 app. Pro is $0.05 per user a month for the first 10,000 users, then $0.01. Enterprise is $3 per user a month, with self-hosting in beta. Source: [Bitwarden Passwordless.dev](https://bitwarden.com/products/passwordless/).

### 1.3 Self-hosting and the license file

- Self-hosting is free. A self-hosted server shows only the free features until a license file is uploaded. Source: [License Paid Features (Bitwarden Help)](https://bitwarden.com/help/licensing-on-premise/).
- For Premium, the person downloads the license file under Settings > Subscription on the cloud account. For an organization, the owner downloads it under Billing > Subscription and enters the server's installation ID. One subscription allows one organization on one server. Seat counts come from the license. Source: [License Paid Features (Bitwarden Help)](https://bitwarden.com/help/licensing-on-premise/).
- An organization license must be updated within 60 days of billing renewal, or the organization is disabled. With cloud contact on, a billing sync token lets the server fetch its license itself. Families organizations update only by hand. Source: [License Paid Features (Bitwarden Help)](https://bitwarden.com/help/licensing-on-premise/).
- Only Families and Enterprise organizations can move to a self-hosted server. The free 2-person organization and Teams cannot. Source: [Self-host an Organization (Bitwarden Help)](https://bitwarden.com/help/self-host-an-organization/).
- The installation ID and key come from bitwarden.com/host. They register the server for security notices, push relay and license checks. The standard server calls the cloud for updates, push and sponsorships. Offline guides exist to avoid that. Source: [Hosting FAQs (Bitwarden Help)](https://bitwarden.com/help/hosting-faqs/).
- The standard server is a set of Docker containers run by Docker Compose. It uses MSSQL Express by default (10 GB limit). It needs at least 2 GB of RAM (4 GB recommended), 12 GB of disk, a domain, ports 80 and 443, and SMTP for email. Source: [Linux Standard Deployment (Bitwarden Help)](https://bitwarden.com/help/install-on-premise-linux/).
- **Bitwarden lite** (formerly Unified) left beta in December 2025. It is one Docker image that needs about 200 MB of RAM, runs on ARM, and uses SQLite, PostgreSQL, MySQL/MariaDB or MSSQL. Bitwarden says it is for personal use and home labs, not business. Source: [Bitwarden lite deployment (Bitwarden Help)](https://bitwarden.com/help/install-and-deploy-lite/).

### 1.4 The "Always free" wording

- It's FOSS reported that "Always free" left the pricing page in mid-April 2026 and came back after May 14. A staff member blamed a marketing oversight. The site also reported an unannounced CEO change (February 2026) and CFO change (April 2026). Source: [Things Are Quietly Changing at Bitwarden, and People Are Worried (It's FOSS)](https://itsfoss.com/news/bitwarden-quiet-changes/).
- The new CEO's post of 2026-05-18 says open source, auditable code and self-hosting are core. It says the free tier stays, rules out a trial model or bait-and-switch, and promises to explain changes. Source: [My first 100 days at Bitwarden (Bitwarden Blog)](https://bitwarden.com/blog/my-first-100-days-at-bitwarden/).

### What this means for Larsal

- Bitwarden gives one person everything that matters for free: unlimited items, unlimited devices and sync. It sells sharing, administration and some personal extras.
- A self-hosted server unlocks paid features with a license file from the cloud account. The file is not what protects the business. The paid code is under a license that does not allow production use without paying (section 2.1).
- Write Larsal's "free forever" promise in the repository, not only on a website. Bitwarden's wording lived on its website; it went missing from the pricing page for about a month, and Bitwarden staff called that a marketing mistake (research 1.4).
- Decide which features stay free before any paid plan exists. Never take a free feature away later. Larsal already has attachments, TOTP codes and health reports at no cost, for parity with the reference app (E4-S4, E4-S10 and E4-S11 in [plan/epics.md](../../plan/epics.md)).

## 2. Licensing and how it builds in the open

### 2.1 One license per part

- **Server:** AGPL-3.0 by default. Only the folder `bitwarden_license` (enterprise modules such as Commercial.Core and SSO) is under the Bitwarden License v1.0. A build with the `OSS` define leaves that module out. The Bitwarden License is not approved by the OSI. Sources: [bitwarden/server LICENSE_FAQ.md](https://github.com/bitwarden/server/blob/main/LICENSE_FAQ.md), [bitwarden/server LICENSE.txt](https://github.com/bitwarden/server/blob/main/LICENSE.txt).
- **The paid license:** the Bitwarden License Agreement v1 (2020) allows the paid modules only for internal development and testing, outside production. It forbids selling, distributing or sublicensing them, removing marks, and building a competing product. Bitwarden can end it by notice. Source: [bitwarden/server LICENSE_BITWARDEN.txt](https://github.com/bitwarden/server/blob/main/LICENSE_BITWARDEN.txt).
- **Clients** (web, browser, desktop, command line): GPL-3.0 by default. Code under `bitwarden_license` is under the Bitwarden License v1.0. Source: [bitwarden/clients LICENSE.txt](https://github.com/bitwarden/clients/blob/main/LICENSE.txt).
- **Phone apps:** the iOS repository (Swift) and the Android repository (Kotlin) are GPL-3.0. Each holds both the Password Manager and the Authenticator app. Sources: [bitwarden/ios (GitHub)](https://github.com/bitwarden/ios), [bitwarden/android (GitHub)](https://github.com/bitwarden/android).
- **Name and logo:** the license files grant no trademark rights. Anyone may fork the code. Nobody may use the name or logo for a fork, call a changed build official, or put the mark in a product or domain name. Source: [bitwarden/server TRADEMARK_GUIDELINES.md](https://github.com/bitwarden/server/blob/main/TRADEMARK_GUIDELINES.md).

### 2.2 The shared Rust core

- sdk-internal is a Rust workspace. Its open packages are GPL-3.0. Commercial packages add code under a separate license. The bindings are WASM for the web and UniFFI (`bitwarden-uniffi`) for Swift and Kotlin. Bitwarden says it is for its own apps, not for public use. Source: [bitwarden/sdk-internal (GitHub)](https://github.com/bitwarden/sdk-internal).
- Bitwarden's rule: everything except presentation belongs in the shared Rust SDK. That means crypto, business logic, state and sync, API calls and data models. Source: [SDK Architecture (Bitwarden Contributing Docs)](https://contributing.bitwarden.com/architecture/sdk/).
- This is Larsal's own shape: a Rust engine with Swift screens over UniFFI. Sources: [plan/architecture.md](../../plan/architecture.md); LD-155 in [spec/decisions.md](../decisions.md).

### 2.3 The 2024 SDK episode

- Desktop 2024.10.0 needed an SDK whose license said it may not be used for software other than Bitwarden. So the GPL desktop app could no longer be built from free code (issue #11611). On 2024-10-20 the CTO called this "merely a bug". On 2024-10-24 the clients moved to a new GPL-only repository, sdk-internal. The old SDK became sdk-secrets, for Secrets Manager. The CTO promised separate build variants if commercial code is added later. The issue closed on 2024-10-25. Source: [Desktop version 2024.10.0 is no longer free software (bitwarden/clients #11611)](https://github.com/bitwarden/clients/issues/11611).
- The Register: the SDK moved to unmodified GPLv3 after the complaint. The commit said "most" crates would be GPL or the SDK License, which left room for non-free parts later. Source: [Bitwarden GPLs its password manager SDK (The Register, 2024-11-04)](https://www.theregister.com/2024/11/04/bitwarden_gpls_password_manager/).
- The Secrets Manager SDK license allows use only to build apps that work with Bitwarden servers: for family use, or internal business use with a paid server license. It forbids selling such apps, changing or redistributing the SDK, and building for other servers. Source: [bitwarden/sdk-sm LICENSE](https://github.com/bitwarden/sdk-sm/blob/main/LICENSE).

### 2.4 Two builds from one repository (2026)

- On 2026-10-09 Bitwarden announced that, from its next release, app-store apps are commercially licensed builds. Staff later said direct downloads from the website move too. Asked about the portable desktop app, staff said they would find out, and no answer followed in the thread. Each release makes a commercial build and a GPLv3 build, and both are on GitHub. All current features are in both. Some future features, mostly for business, will be in the commercial build only. Self-hosting does not change, and community servers choose which features to support. The notice points to the clients LICENSE.txt for license details. Source: [Published version update in app stores (Bitwarden Community Forums, Notices)](https://community.bitwarden.com/t/published-version-update-in-app-stores/102750).
- Pull request #18094 (merged 2026-09-24) added a commercial desktop app in `bitwarden_license/bit-desktop`. Its entry points extend the open ones. Its build points the SDK at `@bitwarden/commercial-sdk-internal`. The build configs are named oss and commercial, and CI builds both. Source: [[PM-25909] Commercial desktop builds (bitwarden/clients #18094)](https://github.com/bitwarden/clients/pull/18094). Pull request #23778 (merged 2026-10-12) uploads both the open and the commercial Mac App Store builds to TestFlight. Source: [bitwarden/clients #23778](https://github.com/bitwarden/clients/pull/23778).
- Windows releases now ship an open installer and a "commercial-" installer. Pull request #24328 (merged 2026-10-30) fixed a checksum mismatch in the commercial Chocolatey package for 2026.10.0. Source: [fix: point commercial Chocolatey package at the commercial installer (bitwarden/clients #24328)](https://github.com/bitwarden/clients/pull/24328).

### 2.5 Contributor agreement

- A pull request is not merged until its author signs the Contributor Agreement at cla-assistant.io. Source: [Contributing (Bitwarden Contributing Docs)](https://contributing.bitwarden.com/contributing/).
- In 2021 a contributor called the agreement one-sided. The maintainer answered that some enterprise customers want commercial licenses, and that needs Bitwarden to own the copyright. Without the agreement, contributors keep their copyright and block those deals. The agreement did not change. Source: [Implement a fair and bilateral Contributor Agreement or remove it completely (bitwarden/server #1115)](https://github.com/bitwarden/server/issues/1115).
- The exact text of the agreement could not be read: cla-assistant.io did not show it. One forum quote says it assigns "all right, title, and interest". This is not checked.

### 2.6 Releases

- Versions are YYYY.M.patch, released about once a month. At research time the latest were server 2026.10.1, desktop 2026.10.2 and mobile 2026.10.1. Tags look like vYYYY.MM.#-component. Source: [Bitwarden Release Notes](https://bitwarden.com/help/releasenotes/).
- A release branch (`rc`) is cut from main on the first business day after code freeze. It is protected (pull request, approval and code owner review), used for regression tests and as the release source, and then deleted. Hotfixes branch from the release tag and cherry-pick from main. Source: [Branching (Bitwarden Contributing Docs)](https://contributing.bitwarden.com/contributing/pull-requests/branching/).
- Desktop v2026.10.2 (released 2026-10-29) shipped 56 files on GitHub. They include a universal macOS .dmg and .zip, with a SHA-256 hash beside each file. A third-party analysis says the Mac app is Developer ID signed and notarized with the hardened runtime. Bitwarden does not document this itself. Source: [bitwarden/clients Releases (GitHub)](https://github.com/bitwarden/clients/releases).

### 2.7 How Bitwarden earns trust

- The pitch: the code is public, so buyers can check the security claims instead of trusting them. It adds Cure53 audits, community review, compliance certificates and self-hosting with Docker. Closed tools are called impossible to check. Source: [Open Source Password Manager (Bitwarden)](https://bitwarden.com/open-source/).
- Blog of 2023-01-24: openness comes before trust. Public code lets users check claims such as end-to-end encryption, and more readers find more flaws. Source: [Bitwarden open source security explained (Bitwarden Blog)](https://bitwarden.com/blog/bitwarden-open-source-security-explained/).
- Yearly outside audits with reports, 2018 to 2025: Cure53 (most years), Insight Risk Consulting, Fracture Labs, IOActive (clients and SDKs, 2024), Mandiant and Unit 42 (mobile), and ETH Zurich (cryptography under a hostile server, 2025). Bitwarden also claims SOC 2 Type 2, SOC 3, ISO 27001, HIPAA and GDPR, and runs a bug bounty on HackerOne. Source: [Is Bitwarden audited? (Bitwarden Help)](https://bitwarden.com/help/is-bitwarden-audited/).
- Only the SOC 3 report can be downloaded. The SOC 2 report is on request. FedRAMP High is being pursued. Source: [Bitwarden Compliance](https://bitwarden.com/compliance/).
- Security reports go through HackerOne. Researchers must give a reasonable time to fix and may encrypt with a published PGP key. No response times and no safe-harbor wording are given. Source: [bitwarden/clients SECURITY.md](https://github.com/bitwarden/clients/blob/main/SECURITY.md). The audit page calls the HackerOne program "private". Its scope and payouts could not be checked.

### 2.8 Servers made by others

- Vaultwarden is a community Rust server that works with Bitwarden clients. It is AGPL-3.0. It was called bitwarden_rs and was renamed to avoid trademark confusion. It says it is not linked with Bitwarden, Inc. One active maintainer works for Bitwarden and contributes on their own time, with review by others. It supports organizations, Send, attachments, two-step login and emergency access. Source: [dani-garcia/vaultwarden (GitHub)](https://github.com/dani-garcia/vaultwarden).
- Bitwarden says most client features should work with unofficial servers such as Vaultwarden, but it "cannot guarantee" that, and its support may be limited. Source: [Hosting FAQs (Bitwarden Help)](https://bitwarden.com/help/hosting-faqs/).

### What this means for Larsal

- **Copy the license split.** Engine and Mac app: GPL-3.0-or-later (decision D2 in [README.md](../../README.md)). Any server: AGPL-3.0, like Bitwarden's server and Vaultwarden. Paid-only code: one top-level folder under a source-available license that allows non-production use only. Everything outside that folder stays fully open.
- **Keep the paid folder small and away from the vault.** The vault engine, the file format and the crypto stay in GPL code. Paid code only adds features on top. The any-cloud researcher (section 4) warns that a paid folder inside the Mac app costs trust, as the 2024 episode showed. The fit research (section 6) says the plan check belongs on a server, never in GPL client code. [plan/product-vision.md](../../plan/product-vision.md) therefore puts the paid folder in the server only.
- **Two builds, one tag.** If paid code exists, build an open and a commercial version from the same tag and publish both with SHA-256 hashes. A CI check deletes the paid folder and then builds and tests the open version. That check would have stopped the 2024 episode.
- **Contributor agreement before the first outside pull request,** if the owner wants the Mac App Store or commercial licenses. If Larsal ships only as a signed download and never relicenses, a DCO (a sign-off line on each commit) is enough. A DCO gives no right to relicense. A fairer agreement can promise that a GPL version stays available. The text needs a lawyer.
- **Name and trust.** Register the product name (D1) and publish trademark guidelines: forks may use the code, not the name. Publish every outside audit (D6), a short security paper and a SECURITY.md. Larsal's reproducible build is already Done (E14-S4 in [plan/epics.md](../../plan/epics.md)): anyone can check that a download matches the source. We found no Bitwarden page that offers this (not checked, section 7), so it can be one of Larsal's main trust points.
- **Releases:** a fixed monthly YYYY.M.patch rhythm, a protected release branch and cherry-picked hotfixes work well. Release notes say what is in each build.
- **Expect other servers.** Document the vault file use and the sync protocol. Others will build servers, as Vaultwarden did. Say early: allowed, not supported, not under our name.

## 3. Cryptography of sync and sharing

### 3.1 Keys and login

- The master password goes through PBKDF2-SHA256, 600,000 iterations on the client by default, salted with the account email. That makes a 256-bit master key. HKDF stretches it to 512 bits. Neither key is ever stored on or sent to the server. Source: [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/).
- HKDF-Expand with the labels "enc" and "mac" makes two 32-byte keys. The 64-byte user key is also an encryption half plus a MAC half. Each user has an RSA key pair with a 2048-bit modulus. The login hash is one PBKDF2 round over the master key, with the password as salt. Source: [Zero Knowledge (About) Encryption: A Comparative Security Analysis of Three Cloud-based Password Managers (Scarlata, Torrisi, Backendal, Paterson; USENIX Security 2026 prepub)](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf).
- Argon2id is an option next to PBKDF2. Its defaults are 32 MiB of memory, 6 iterations and 4 threads (these may have changed). Changing the KDF re-wraps the key but does not rotate it. 2023.2.0 made 600,000 the default for new accounts. 2026.2.1 made 600,000 the minimum, with an upgrade at the next unlock. Source: [Encryption Key Derivation (Bitwarden Help)](https://bitwarden.com/help/kdf-algorithms/).
- A random 512-bit user key is encrypted with AES-256 under the stretched master key. The server stores that wrapped key and returns it on sync. The server hashes the login hash again, with PBKDF2-SHA256, a random salt and 600,000 iterations. Source: [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/). The KDF page gives a total of 700,000 instead. The two pages disagree. Source: [Encryption Key Derivation (Bitwarden Help)](https://bitwarden.com/help/kdf-algorithms/).
- The server stores the re-hashed login hash, the wrapped user key, the RSA public key, the RSA private key wrapped by the user key, the encrypted items and the wrapped organization keys. It never holds the master password, the master key or the plain user key. On top, it encrypts those columns with KMS keys over Azure disk encryption. Source: [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/).

### 3.2 Items and the stored format

- Each item has its own random 64-byte key, wrapped by the user key or by the organization key. An attachment has its own key too. Source: [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/).
- Each field of an item is encrypted on its own. Before 2024.2.0, fields used the user key directly. Old items were not moved to per-item keys. A sync returns each item as JSON with plain field names. Organization names and policies are plain on the server. Source: [Zero Knowledge (About) Encryption (USENIX Security 2026 prepub)](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf).
- An encrypted value is written as `type.iv|data|mac`. Type 2 is AES-256-CBC with HMAC-SHA256. Type 0, plain AES-CBC, is deprecated because it is not authenticated. A COSE variant is now preferred. Old variants can "rarely, if ever" be removed for decryption. Source: [Bitwarden SDK API docs: bitwarden_crypto::EncString](https://sdk-api-docs.bitwarden.com/bitwarden_crypto/enum.EncString.html).
- Version 2, from 2026: a COSE XChaCha20-Poly1305 user key, a required public-key pair, and a required signing key pair as the root of trust. The signing key signs the public key and a "security state" that blocks format downgrades. Every encrypted object carries a key ID. The client must refuse to unlock if any of these is missing. These pages are on a preview docs host and may change. Source: [Bitwarden contributing docs (preview): User encryption](https://km-crypto-docs.contributing-docs.pages.dev/architecture/cryptography/specification/user-encryption).
- The "data envelope" gives each stored document its own key, named by a key ID. It uses XChaCha20-Poly1305 with a 24-byte random nonce in COSE, and pads the plain text to 64-byte blocks to hide its length. A namespace number in the protected header stops a document being opened in the wrong slot. The stated attacker is a fully compromised server. Preview docs host. Source: [Bitwarden contributing docs (preview): Data envelope](https://km-crypto-docs.contributing-docs.pages.dev/architecture/cryptography/specification/data-envelope).

### 3.3 Sharing, recovery and Send

- The organization key comes from a secure random generator and is never stored plain on the server. It is wrapped with RSA-OAEP to each member's public key. To add a member, an existing member takes the newcomer's public key from the server and wraps the key to it. Source: [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/).
- Joining takes three steps: invite, accept, confirm. Email invitations expire after five days. At the confirm step the admin compares the member's fingerprint phrase through another channel. The phrase is five words from the EFF long word list and cannot be changed. Sources: [Manage users (Bitwarden Help)](https://bitwarden.com/help/managing-users/), [Fingerprint phrase (Bitwarden Help)](https://bitwarden.com/help/fingerprint-phrase/).
- Every member gets the same organization key, so collections are not a crypto boundary. Bitwarden marked this "Accepted", a design choice (Issue 10, Low). Source: [Bitwarden Cryptography Report](https://bitwarden.com/assets/Kki4W785JIPOdFj6EeWB5/dbf51066c1041aa90dc503ca0c911194/2025_Bitwarden_Cryptography_Report.pdf).
- Forum users say there is no supported way to rotate the organization key except starting a new organization (June 2025, not official). Source: [What to do if organization member is compromised? (Bitwarden Community)](https://community.bitwarden.com/t/what-to-do-if-organization-member-is-compromised/86107). Vaultwarden 1.30.3 got CVE-2024-39925 (published 2024-09-13): a member who left kept the organization key. Source: [CVE-2024-39925 record](https://cveawg.mitre.org/api/cve/CVE-2024-39925).
- User key rotation is optional and done during a master password change. The help page calls it "a potentially dangerous operation": users must log out of every client first, or an old session can corrupt data. Source: [Encryption Key Rotation (Bitwarden Help)](https://bitwarden.com/help/article/account-encryption-key/).
- Emergency access (Premium and paid organizations): an invitation lasts five days. On confirm, the grantor's user key is wrapped to the grantee's public key. Access opens when the grantor approves or when a wait time runs out (at least one day). Access is view or takeover. Takeover sets a new master password and removes two-step login. Sources: [Emergency Access (Bitwarden Help)](https://bitwarden.com/help/emergency-access/), [Add and manage trusted emergency contacts](https://bitwarden.com/help/add-and-manage-trusted-emergency-contacts/).
- Account recovery (Enterprise only): the member's user key is wrapped to the organization's public key. An admin unwraps it and wraps it again for a new master password. The action is logged, and members can be enrolled automatically. Source: [Account Recovery (Bitwarden Help)](https://bitwarden.com/help/account-recovery/).
- Trusted devices (sign-in without a master password) need account recovery on. Each device keeps a device key that never leaves it. A new device is approved by another device, by an admin (requests expire after a week) or with the master password. Source: [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/).
- Passkey login uses the PRF extension of the authenticator. Both the browser and the authenticator must support it. An account can have up to five passkeys. Source: [Log in with Passkeys (Bitwarden Help)](https://bitwarden.com/help/login-with-passkeys/).
- Send: each Send gets a new 128-bit secret. HKDF-SHA256 turns it into a 512-bit key for AES-256. The key travels in the URL fragment, which never reaches the server. A Send password is only a server access check. Source: [Send Encryption (Bitwarden Help)](https://bitwarden.com/help/send-encryption/). Sends are deleted after 7 days by default. The page says both "up to 30 days" and "a maximum allowed value of 31 days". Source: [Send Lifespan (Bitwarden Help)](https://bitwarden.com/help/send-lifespan/).

### 3.4 How Bitwarden syncs

- The sync endpoint returns everything for the user on every call: a full snapshot, not "changes since". Source: [bitwarden/server: SyncController.cs (GitHub)](https://github.com/bitwarden/server/blob/main/src/Api/Vault/Controllers/SyncController.cs).
- Clients ask for the account's revision date to decide if a full sync is needed. The server changes that date whenever synced data changes. Source: [bitwarden/server issue #2615](https://github.com/bitwarden/server/issues/2615).
- Apps sync at login and "regularly when unlocked", plus a manual "Sync now". Organization items reach other users every 30 minutes. The page says nothing about conflicts. Source: [Sync your Vault (Bitwarden Help)](https://bitwarden.com/help/vault-sync/).
- There is no merge. A save from an old copy is refused with "The cipher you are updating is out of date. Please save your work, sync your vault, and try again." The evidence is community posts and a commit in Vaultwarden. Source: ['cipher out of date' error (Bitwarden Community)](https://community.bitwarden.com/t/cipher-out-of-date-error-bitwarden-password-manager/86851).

### 3.5 What critics found

- **Server-side iterations (2023):** the default was 100,001 iterations on the client plus 100,000 on the server. The server rounds protect only the login hash, not the vault key, so stolen vault data faces only the client count. Some old accounts had 5,000. The server tells the client which count to use. Bitwarden moved new accounts to 350,000 the same day, and OWASP raised its advice to 600,000. Source: [Wladimir Palant: Bitwarden design flaw: Server side iterations](https://palant.info/2023/01/23/bitwarden-design-flaw-server-side-iterations/).
- **The ETH Zurich study:** it assumed a fully hostile server. For people who self-host, that server is their own. It found 12 attacks in four groups: key escrow (BW01 to BW03), item-level encryption (BW04 to BW07), sharing (BW08 to BW10) and old formats (BW11 and BW12). The causes: public keys that are not authenticated, no key separation, metadata that is not authenticated, and support for old unauthenticated CBC. Source: [Zero Knowledge (About) Encryption (USENIX Security 2026 prepub)](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf).
- **Bitwarden's answer (2026-02-16):** 10 issues were reported to it (12 in the paper), rated medium or low. Seven are fixed or being fixed. Three are accepted as design choices. The researchers picked Bitwarden largely because its code is open. Source: [Security through transparency: ETH Zurich audits Bitwarden cryptography (Bitwarden Blog)](https://bitwarden.com/blog/security-through-transparency-eth-zurich-audits-bitwarden-cryptography/).
- **The attacks one by one,** all from the [Bitwarden Cryptography Report](https://bitwarden.com/assets/Kki4W785JIPOdFj6EeWB5/dbf51066c1041aa90dc503ca0c911194/2025_Bitwarden_Cryptography_Report.pdf) and the paper above:
  - BW07, KDF downgrade (Issue 7): KDF settings sit on the server, plain and not authenticated. A hostile server could set the count to 1 at login, which makes guessing about 300,000 times faster. Forced downgrades are now blocked. Authenticated KDF settings are still being researched.
  - BW01, auto-enrolment (Issue 2): a hostile server could switch on recovery enrolment and swap in its own public key when a user joins an organization. Fix: fingerprint prompts, with key signing in development.
  - BW02, key rotation (Issue 1): rotation wrapped the new key to emergency and recovery public keys that were not checked. Fixed with fingerprint checks (clients pull request #12655).
  - BW08 and BW09 (Issue 5): a server can add a user to any organization, or replace a new organization's keys. Nothing proves membership. Accepted, with signing in development.
  - BW05 and BW06 (Issue 6): nothing tied a ciphertext to its field. A server could move a password into the URL field, and the icon request then leaked it. Fixed only for items made after July 2024.
  - BW11 and BW12 (Issue 3): old CBC support let a server force a downgrade. Old types are now "effectively totally removed". Issue 9 (changeable format, plain metadata) is accepted.
- **The paper's fixes:** authenticated encryption only, a key per field and item, authenticate all metadata (KDF settings too), authenticate public keys (check out of band and keep known keys, or use a PKI), and sign wrapped keys. The price is breaking format changes. Source: [Zero Knowledge (About) Encryption, Section 5 (USENIX Security 2026 prepub)](https://www.usenix.org/system/files/conference/usenixsecurity26/sec26_prepub_scarlata.pdf).
- **Website icons:** for each login with a web address, the client asks Bitwarden's icon server for that hostname's icon. Bitwarden calls this a "leak". Users can turn it off. Source: [Data Privacy for Website Icons (Bitwarden Help)](https://bitwarden.com/help/website-icons/).
- **What is encrypted:** item names, notes, attachments, custom fields, usernames, passwords, password history, web addresses, TOTP secrets, card and identity fields, Send content, and folder and collection names. The list does not cover item type, favorite, folder ID, organization ID or revision dates. Source: [Vault Data (Bitwarden Help)](https://bitwarden.com/help/vault-data/).
- **Plain web addresses** are LastPass history, not Bitwarden. LastPass stored them unencrypted from 2008, and they were in the vault backup stolen in 2022. LastPass later started to encrypt them. Sources: [LastPass Is Encrypting URLs (LastPass blog)](https://blog.lastpass.com/posts/lastpass-is-encrypting-urls-heres-whats-happening), [Notice of recent security incident (LastPass blog)](https://blog.lastpass.com/posts/notice-of-recent-security-incident).

### What this means for Larsal

- **Threat model first.** Every cloud folder and every server is fully hostile, our own paid server too. Write this into [plan/security.md](../../plan/security.md) before E11 or any server work.
- **Keep one encrypted file per vault as the unit of sync.** Bitwarden's field-by-field encryption is the root of BW04 to BW07 and BW10. A whole file that the key authenticates avoids that class. The cloud sees only the file name, size and times, so suggest neutral file names. Larsal already promises that a tamperer with write access is found before data is used ([plan/security.md](../../plan/security.md), "Who attacks").
- **Nothing made from the master password leaves the Mac.** A future server login uses a separate device credential or auth secret, never a password hash. The key settings stay inside the vault header that the key checks. A merge never lowers them, which Larsal already does (MOD-11; LD-60 and LD-132 in [spec/decisions.md](../decisions.md)).
- **Guard against rollback.** Per vault, keep the newest format version, the KDF strength and a save counter in the Keychain. Warn when a synced copy goes backwards. Never write an old format to a synced vault.
- **Sharing done right:** one key per shared vault, so it is a real crypto boundary. Wrap it to each member's public key. Check each public key by fingerprint at invite, pin it, and warn loudly when it changes. Removing a member makes a new key, and Larsal lists the passwords to change. No silent key escrow: recovery and emergency access only by each person's choice, confirmed by fingerprint. For free users, a printed recovery kit.
- **Do not fetch icons through our own server by domain.** Features that need a trusted clock or storage (emergency-access wait times, Send links, push sync) need a server. A plain cloud folder cannot do them.

## 4. Any-cloud native apps and how they sell

### 4.1 Enpass: the closest match

- Enpass syncs "without sending any data to Enpass servers", through Dropbox, Google Drive, OneDrive, iCloud, Box, WebDAV or Nextcloud. It also has local Wi-Fi sync and Folder Sync. Source: [Syncing and accessing Enpass data across devices (Enpass Help)](https://help.enpass.io/personal/latest/all/creating-syncing-vaults).
- Its security paper v1.4 (2025-08-22) calls the cloud "a dumb drive" that holds the same encrypted vault file as the device. Device B downloads the new vault, opens it locally, merges it, and uploads if it has its own changes. Conflicts are solved only on the device. Cloud access uses the provider's OAuth, and the token stays on the device. Source: [Enpass Security Whitepaper v1.4](https://dl.enpass.io/docs/whitepaper/enpass-security-whitepaper.pdf).
- The vault is a small plain metadata file for sync, a SQLCipher (AES-256) database, and separate encrypted attachment files, so big files sync on their own. Source: [Enpass Security Whitepaper v1.4](https://dl.enpass.io/docs/whitepaper/enpass-security-whitepaper.pdf).
- Enpass for Business keeps vault files in the company's OneDrive, SharePoint or Google Drive. A License Server manages subscriptions. "Enpass Hub", hosted or self-hosted, is a key directory: it stores RSA-3072 wrapped vault keys and metadata for sharing, recovery and audit, and "never vault content". Source: [Enpass Security Whitepaper v1.4](https://dl.enpass.io/docs/whitepaper/enpass-security-whitepaper.pdf).
- Business sharing has two layers. The cloud grants access to the file, and the Hub delivers the vault key wrapped to the member's public key. "Neither layer alone is sufficient." Source: [How vault sharing works (Enpass Business Help)](https://help.enpass.io/business/latest/microsoft-365/how-vault-sharing-works).
- Personal sharing has no server. The owner makes a separate vault and gives the other person its password and the cloud login. Enpass advises a separate cloud account for the shared vault. Source: [Sharing a vault in Enpass (Enpass Help)](https://help.enpass.io/personal/latest/all/vault-sharing).
- The Family Plan covers up to 6 people and is sold only on enpass.io. Larsal stores sell only single-person plans. Source: [Sharing an Enpass family plan (Enpass Help)](https://help.enpass.io/personal/latest/all/sharing-an-enpass-family-plan).
- Prices, from a third-party tracker captured 2026-10-12 (the vendor page returned HTTP 403, so treat these as approximate): Free plan; Premium $1.99 a month billed yearly; Family $2.99 a month at first, raised to $3.99 in August 2026. A free plan came and the lifetime plan went in September 2026. Source: [Enpass Pricing Plans & History (PricingSaaS)](https://pricingsaas.com/companies/enpass).
- Enpass is freemium, and its source is not published. Source: [Enpass (Wikipedia)](https://en.wikipedia.org/wiki/Enpass).

### 4.2 Standard Notes

- Plans (as of 2026-10-31): Standard $0 a year, Productivity $90, Professional $120 with 100 GB of encrypted storage and "subscription sharing with up to 5 accounts". Source: [Standard Notes Plans](https://standardnotes.com/plans).
- The app repository is AGPL-3.0, with end-to-end encrypted sync. The server can be self-hosted, and clients can point at another sync server. Source: [standardnotes/app README](https://github.com/standardnotes/app).
- On a self-hosted server, a database insert gives a subscription that unlocks server-side features only. Client-side premium features need a paid "offline" plan. Source: [Subscriptions on your self-hosted server (Standard Notes Help)](https://standardnotes.com/help/self-hosting/subscriptions). That plan was $39 a year against $120 hosted, in a 2023 post that may be out of date. Source: [Making self-hosting easy for all (Standard Notes blog, 2023-01-20)](https://standardnotes.com/blog/making-self-hosting-easy-for-all).
- Proton bought Standard Notes in April 2024. It said the app stays open source, the free version stays free, and prices would not change. Source: [Proton has acquired encrypted note-taking app Standard Notes (TechRadar)](https://www.techradar.com/pro/security/proton-has-acquired-encrypted-note-taking-app-standard-notes).

### 4.3 Joplin

- The code is AGPL-3.0-or-later, except folders with their own license file. Logos and icons are all rights reserved, and "Joplin" is a registered EU trademark. Source: [laurent22/joplin LICENSE](https://github.com/laurent22/joplin/blob/dev/LICENSE).
- Joplin Server has its own "Personal Use License": personal, non-commercial use only. Commercial use needs written permission. Source: [Joplin Server LICENSE.md](https://github.com/laurent22/joplin/blob/dev/packages/server/LICENSE.md).
- Joplin Cloud (as of 2026-10-31): Basic EUR 28.69 a year (2 GB), Pro EUR 57.48 a year (30 GB, can share), Teams EUR 80.28 per user a year, and the self-hosted Server Business EUR 30 to 40 per user a year. No free tier; 14-day trial. Source: [Joplin Cloud Plans](https://joplinapp.org/plans/).
- Joplin syncs with Joplin Cloud, Nextcloud, S3, WebDAV, Dropbox, OneDrive or a local folder. Source: [Synchronisation (Joplin Help)](https://joplinapp.org/help/apps/sync/).
- Its master key is protected by a password the user picks and travels through sync. The password cannot be recovered. Turning encryption on at several devices at once can make several keys. Source: [End-To-End Encryption (Joplin Help)](https://joplinapp.org/help/apps/sync/e2ee/).
- On a conflict, Joplin copies the local note into a "Conflict" notebook and keeps the remote one. The user merges by hand. Source: [What is a conflict? (Joplin Help)](https://joplinapp.org/help/apps/conflict/).

### 4.4 Obsidian

- The app is free. Sync is $4 per user a month billed yearly ($5 monthly). Publish is $8 per site a month yearly ($10 monthly). A commercial license ($50 per user a year) is optional (as of 2026-10-31). Source: [Obsidian Pricing](https://obsidian.md/pricing).
- Sync Standard: 1 GB, 1 vault, 5 MB files, 1 month of history. Sync Plus: 10 to 100 GB, 10 vaults, 200 MB files, 12 months of history. Source: [Sync plans and storage (Obsidian Help)](https://obsidian.md/help/sync/plans). Sync Plus costs $8 a month billed yearly, or $10 billed monthly (as of 2026-10-31). Source: [Obsidian Sync](https://obsidian.md/sync).
- Sync is end-to-end encrypted by default (AES-256-GCM, key from scrypt; the password is not stored or recoverable). An optional mode uses a key Obsidian holds. The local vault is not encrypted. Source: [Security and privacy (Obsidian Help)](https://obsidian.md/help/sync/security).
- In a shared vault, each person needs their own Sync subscription, at most 20 people. Source: [Collaborate on a shared vault (Obsidian Help)](https://obsidian.md/help/sync/collaborate).
- Other sync tools work on its local files. Obsidian warns: do not sync one vault through several services. Source: [Sync your notes across devices (Obsidian Help)](https://obsidian.md/help/sync-notes).
- "Obsidian is not open source software." Source: [obsidianmd/obsidian-releases README](https://github.com/obsidianmd/obsidian-releases).

### 4.5 Proton Pass

- Plans (as of 2026-10-31): Free ($0; unlimited logins and devices, 10 email aliases), Pass Plus $35.88 a year, Pass Family $59.88 a year for up to 6 people with an admin panel, Proton Unlimited $119.88 a year. Free can share with up to 2 others; vault and link sharing are paid. Source: [Proton Pass Pricing](https://proton.me/pass/pricing).
- In Pass Family the admin invites members by email (each needs a Proton account), makes shared vaults, and gives each person view, edit or manage rights. Source: [Pass Family admin guide (Proton Support)](https://proton.me/support/pass-family-admin-guide).
- The iOS app repository is GPL-3.0. Source: [protonpass/ios-pass README](https://github.com/protonpass/ios-pass).
- On 2023-07-19 Proton published the client code (browser extensions, iOS and Android) and a Cure53 audit from May and June 2023. Source: [Proton Pass is open source and audited for security (Proton Blog)](https://proton.me/blog/pass-open-source-security-audit).
- No official self-hosting was found.

### 4.6 How cloud services handle a conflict

- Dropbox makes a "conflicted copy" when the same file changes in two places or offline. The file name gets the editor's name, the date and "conflicted copy". Dropbox does not merge: "compare both versions and merge them manually." Source: [What's a conflicted copy? (Dropbox Help)](https://help.dropbox.com/organize/conflicted-copy).
- iCloud picks one "conflict winner", the same on every device, and keeps the losing versions. The app finds them with NSFileVersion, merges or picks, replaces the file, removes the other versions, and marks each one resolved last. Source: [Resolving Document Version Conflicts (Apple Document-Based Larsal Programming Guide)](https://developer.apple.com/library/archive/documentation/DataManagement/Conceptual/DocumentBasedAppPGiOS/ResolveVersionConflicts/ResolveVersionConflicts.html).

### What this means for Larsal

- **The free core is the Enpass model, and Larsal already has it.** One encrypted file in any folder the user picks: iCloud Drive, Dropbox, Google Drive, OneDrive, Nextcloud or WebDAV, or a USB stick. Larsal runs no sync network. It watches the file and merges on the Mac (section 6.1). No server, no account, no cost.
- **Always merge. Never pick a side.** Joplin's Conflict notebook and Dropbox's "merge by hand" lose passwords in a vault. When a cloud makes a second copy, Larsal opens it with the same key, merges, saves once and removes the copy. Tell users: one sync service per vault, as Obsidian does.
- **Money goes where a file alone falls short:** hosted sync and storage (Standard Notes, Joplin, Obsidian), and seats and sharing for families and teams (Bitwarden, Enpass, Proton Pass). Market anchors as of 2026-10-31: Bitwarden Families $47.88 a year for 6, Teams $4 per user a month, Proton Pass Family $59.88 a year, Enpass Family about $36 to $48 a year.
- **Sharing needs a small key directory.** It stores only public keys, wrapped keys, invites and seats, and never sees vault data. Bitwarden's server and Enpass Hub both work this way. The shared vault file can stay in the members' own cloud folder.
- **Sell a service, not a lock.** In GPL code anyone can delete a check in the app. Bitwarden and Enpass put the paid check on a server. Standard Notes' client-only "offline plan" is the weak form.

## 5. Selling a Mac app

### 5.1 Outside the Mac App Store

- The Apple Developer Program costs $99 a year (as of 2026-10-31). Source: [Apple Developer Program](https://developer.apple.com/programs/).
- Outside the store you sign with a Developer ID certificate, turn on the hardened runtime, notarize with notarytool, and staple the ticket, so Gatekeeper accepts the download. Developer ID apps can use CloudKit and push. Source: [Signing Mac Software with Developer ID (Apple Developer)](https://developer.apple.com/developer-id/).
- A "merchant of record" sells for you and collects and files VAT and sales tax. Prices as of 2026-10-31:
  - Paddle: 5% + 50c per sale. Source: [Paddle Pricing](https://www.paddle.com/pricing).
  - Lemon Squeezy: 5% + 50c, and it issues license keys. The seller is now "Link, LLC f/k/a Lemon Squeezy LLC". Source: [Lemon Squeezy Pricing](https://www.lemonsqueezy.com/pricing). Stripe bought it in 2024. Its CEO wrote on 2026-01-28 that it is moving users to Stripe Managed Payments and admitted "slower support responses and less frequent product updates". No shutdown date. Source: [Lemon Squeezy: 2026 Update](https://www.lemonsqueezy.com/blog/2026-update).
  - Stripe Managed Payments: Stripe is the merchant of record for software in 80+ tax countries, with Checkout and Payment Links only. Source: [Managed Payments (Stripe Docs)](https://docs.stripe.com/payments/managed-payments). It costs 3.5% per sale on top of card fees. Stripe Tax is 0.5% and Billing 0.7% (EU page). Source: [Stripe Pricing](https://stripe.com/pricing).
  - FastSpring: a merchant of record with a volume-based share, by quote. Source: [FastSpring Pricing](https://fastspring.com/pricing/).

### 5.2 Inside the Mac App Store

- Guideline 2.4.5: Mac App Store apps must be sandboxed, must not show a license screen or ask for license keys, and must update only through the store. Source: [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/).
- Guideline 3.1.1: unlocking features or subscriptions must use in-app purchase. 3.1.3(b): an app may honor a subscription bought on the web only if it also sells it as an in-app purchase. 3.1.3(c): "Consumer, single user, or family sales must use in-app purchase". 3.1.3(f): a free companion app to a paid cloud storage service needs no in-app purchase if it shows no buy buttons. Source: [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/).
- Guideline 3.1.1(a): apps on the United States storefront may link to other ways to buy. Other storefronts need an entitlement or forbid it. Source: [App Store Review Guidelines](https://developer.apple.com/app-store/review/guidelines/).
- On 2025-04-30 a US court barred Apple from taking commission on linked-out purchases. On appeal, the Ninth Circuit later allowed a commission limited to Apple's real costs; the amount was still being set. This may have moved since. Source: [Epic v. Apple, the Ninth Circuit weighs in (Perkins Coie)](https://perkinscoie.com/insights/update/epic-v-apple-ninth-circuit-weighs).
- The Small Business Program charges 15% for developers with up to $1M in proceeds the year before. Source: [App Store Small Business Program](https://developer.apple.com/app-store/small-business-program/).
- Subscriptions pay the developer 70% in a subscriber's first year and 85% after a year (85% always in the Small Business Program). Family Sharing can share a subscription with up to five family members, and turning it on cannot be undone. Source: [Auto-renewable Subscriptions (Apple Developer)](https://developer.apple.com/app-store/subscriptions/).
- A sandboxed app reaches a file the user picked again after relaunch with a security-scoped bookmark. Source: [Accessing files from the macOS App Sandbox (Apple Developer)](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox).

### 5.3 The GPL and the App Store

- The FSF (2010-05-26) says App Store usage rules, such as installing on only five approved devices, are "further restrictions" that the GPL forbids. This applies to all GPL and AGPL versions. Apple removed GNU Go after the FSF complained. Source: [More about the App Store GPL Enforcement (FSF)](https://www.fsf.org/blogs/licensing/more-about-the-app-store-gpl-enforcement).
- A VLC developer complained to Apple in October 2010, and Apple pulled VLC for iOS on 2011-01-07. Source: [VLC app removed from App Store (Engadget, 2011-01-08)](https://www.engadget.com/2011-01-08-vlc-app-removed-from-app-store.html). VLC came back in July 2013 after a license change. The iOS app is now GPLv2-or-later and MPLv2. Source: [videolan/vlc-ios README](https://github.com/videolan/vlc-ios).
- Pidgin has no iOS app: "The only (legal) way we can grant an exception to the license is for every copyright holder to agree to the exception." Source: [Why no iOS version (Pidgin)](https://developer.pidgin.im/wiki/WhyNoiOSVersion).
- The GNU GPL FAQ says the developer of a GPL program "is not bound by it", and a copyright holder "can release it under various different non-exclusive licenses at various times". Read through a mirror, because gnu.org returned HTTP 429. Source: [GNU GPL FAQ (mirror of gnu.org/licenses/gpl-faq.html)](https://www.southampton.ac.uk/~qs2g22/mirror/www.gnu.org/licenses/gpl-faq.html).
- Signal's former publisher added a GPLv3 "additional permission" to ship through the Apple App Store, as long as the source is offered. Only the copyright holder can grant it. Source: [signal-gpl-3.0-exception (ScanCode LicenseDB)](https://scancode-licensedb.aboutcode.org/signal-gpl-3.0-exception.LICENSE).
- Bitwarden ships its desktop app free in the Mac App Store. Source: [Bitwarden on the Mac App Store](https://apps.apple.com/app/bitwarden/id1352778147). Our reading, not stated by Bitwarden: it can probably do this because its contributor agreement lets it relicense the code (section 2.5). The listing shows only that the app is free, and issue #1115 gives enterprise licenses as the reason for the agreement. From its October 2026 release, store builds are commercially licensed (section 2.4).

### What this means for Larsal

- **Ship direct first:** a Developer ID signed, notarized download plus the command line tool. That is E14-S3 as written ("no App Sandbox", [plan/epics.md](../../plan/epics.md)). It needs D7, the $99 account.
- **Sell through a merchant of record,** so VAT and sales tax are handled everywhere. Paddle is the stable pick today. Lemon Squeezy is moving into Stripe Managed Payments. Check fees and countries again just before choosing.
- **The Mac App Store is a separate, later decision.** It needs the sandbox (security-scoped bookmarks for a vault in any folder), store-only updates, no license keys, in-app purchase for every personal and family plan, and a contributor agreement or a commercial store build. The cost is 15% under the Small Business Program.
- **No court has tested the GPL and App Store conflict.** A lawyer should confirm the plan before a store release. The bundle must also hold no third-party GPL-only code; check the license list in [deny.toml](../../deny.toml) then.

## 6. Fit to Larsal

### 6.1 What Larsal already has toward any-cloud sync

- **Safe saves.** Larsal writes a temp file in the same folder, fully syncs it, renames it over the vault, and syncs the folder. Before writing, it checks that the file on disk has not changed, and checks again under a lock just before the rename. So it never overwrites a change made elsewhere without asking. Source: [spec/app/APP-05-saving.md](../app/APP-05-saving.md), APP-05.10 and APP-05.11.
- **Change on disk.** Larsal watches the folder and the file with kqueue and also checks every 30 seconds. With no unsaved changes, it reloads (or asks). With unsaved changes, it asks Merge, Ignore, Discard or Cancel. A vault re-keyed elsewhere asks for the new key. A half-synced or unreadable file leaves the open copy alone ("It may still be syncing"). Sources: [spec/app/APP-05-saving.md](../app/APP-05-saving.md), APP-05.24 to APP-05.30; [macos/Larsal/Platform/DiskWatch.swift](../../macos/Larsal/Platform/DiskWatch.swift); LD-216 in [spec/decisions.md](../decisions.md).
- **Merge.** It matches by id, the newer change wins, and histories are joined. Same time with different content keeps both versions and records a Conflict. It never lowers the cipher, the KDF cost or protection flags. Sources: [spec/model/MOD-11-merge.md](../model/MOD-11-merge.md); LD-60 and LD-132 in [spec/decisions.md](../decisions.md).
- **Status:** E4-S12 Merge Done 2026-10-26 (no data lost in 1,000 random cases), E4-S15 Storage Done 2026-10-26, E5-S10 Saving Done 2026-10-28. Source: [plan/epics.md](../../plan/epics.md).
- **A build with no network code.** Without larsal-ffi's `net` feature, Larsal links no network code (SN-05). Sources: [plan/security.md](../../plan/security.md) SN-05; [README.md](../../README.md), Checks.
- **Promises.** A thief of the vault file cannot read it. A tamperer with write access (cloud folder, USB stick) is found before data is used. Quick unlock data is never synced. Sources: [plan/security.md](../../plan/security.md), "Who attacks"; [spec/app/APP-04-quick-unlock.md](../app/APP-04-quick-unlock.md).

### 6.2 Gaps for any-cloud sync

- **Conflict copies.** Larsal does not look for the copies that sync services make. The user merges them by hand. Source: [spec/app/APP-05-saving.md](../app/APP-05-saving.md), APP-05.17.
- **Deleted entries can come back.** The everyday merge (change on disk, merge from another copy) does not read the deleted-objects list. An entry deleted for good on one Mac comes back from a copy that still has it. Only the shared-group import applies deletions. Sources: [spec/format/FMT-15-deleted-objects.md](../format/FMT-15-deleted-objects.md), FMT-15.10 and FMT-15.11; [spec/model/MOD-11-merge.md](../model/MOD-11-merge.md), MOD-11.15.
- **No coordinated file access.** Larsal uses plain file calls; no NSFileCoordinator is used ([macos/Larsal/Platform/DiskWatch.swift](../../macos/Larsal/Platform/DiskWatch.swift), LD-216). Apple: "Your presenter objects are not notified about changes made directly using low-level read and write calls to the file. Only changes that go through a file coordinator result in notifications." Source: [NSFilePresenter (Apple Developer Documentation)](https://developer.apple.com/documentation/foundation/nsfilepresenter). NSFileCoordinator "coordinates the reading and writing of files and directories among multiple processes", and each coordinator should be used on one thread only. Source: [NSFileCoordinator (Apple Developer Documentation)](https://developer.apple.com/documentation/foundation/nsfilecoordinator).
- **Files that are not downloaded yet.** A cloud can keep only a placeholder ("dataless" file). The system fetches the contents when the file is opened, and never evicts a file with pending changes. Source: [Synchronizing the File Provider extension (Apple Developer Documentation)](https://developer.apple.com/documentation/fileprovider/synchronizing-the-file-provider-extension). An app can start the download and read its status. Source: [startDownloadingUbiquitousItem(at:) (Apple Developer Documentation)](https://developer.apple.com/documentation/foundation/filemanager/startdownloadingubiquitousitem(at:)).
- **iCloud conflicts** can be listed with NSFileVersion. Source: [unresolvedConflictVersionsOfItem(at:) (Apple Developer Documentation)](https://developer.apple.com/documentation/foundation/nsfileversion/unresolvedconflictversionsofitem(at:)).
- **Other facts:** Apple says file system event lists on disks other computers change are only advisory (old guide, may be out of date). Source: [File System Events Programming Guide (Apple)](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/UsingtheFSEventsFramework/UsingtheFSEventsFramework.html). Finder connects to SMB, NFS, WebDAV and FTP servers (FTP may be read-only). Source: [Servers and shared computers you can connect to on Mac (Apple Support)](https://support.apple.com/guide/mac-help/servers-shared-computers-connect-mac-mchlp3015/mac). A rename does not work across mount points. Source: [std::fs::rename (Rust std documentation)](https://doc.rust-lang.org/std/fs/fn.rename.html). Larsal's 30-second check already covers network disks.
- **README is out of date.** It says "Status: planning. Nothing is built yet", while [AGENTS.md](../../AGENTS.md) says the engine is done and the Mac app is being built. Source: [README.md](../../README.md).

### 6.3 Sharing: what is planned

- **Without a server (INT-08, planned, not built).** A group is copied into a separate container vault file, protected by a share password, in a shared folder. Modes: import, export, synchronize. Larsal adds approval outside the vault, keeps imports inside the share group, and imports before it exports. Recommended: unsigned containers. Size: about three stories. Source: [spec/integrations/INT-08-shared-groups.md](../integrations/INT-08-shared-groups.md). Weak points: one shared password, no way to remove one member without a new password for everyone, and the last writer wins on the file.
- **Remote sync by user commands (INT-09) stays out.** Two writers at once can race. "A conditional upload (RFC 9110 If-Match) is the proper fix, and a user command cannot express it in general." The card recommends leaving it out of the first release, because Mac users mostly sync through cloud folders, which the change-on-disk merge covers. Source: [spec/integrations/INT-09-remote-sync.md](../integrations/INT-09-remote-sync.md), D-INT09-1 and D-INT09-8.
- **E11 waits on the owner.** Its scope (INT-08 and INT-09) is the owner's call, W-15. Sources: [spec/decisions.md](../decisions.md), W-15 and LD-218; [plan/epics.md](../../plan/epics.md), E11.
- **INT-08's own review** notes that password managers that share (Bitwarden organizations, Proton Pass shared vaults) do it through their own servers. Source: [spec/integrations/INT-08-shared-groups.md](../integrations/INT-08-shared-groups.md), R08-2.

### 6.4 Sharing through a server, in Larsal's terms

- **The vault format does not change.** A vault's key can be built from a 32-byte key-file part alone, with no password. So a shared vault can be an ordinary vault file keyed by one random group key. Source: [spec/format/FMT-04-key-flow.md](../format/FMT-04-key-flow.md), FMT-04.3 and FMT-04.5.
- **The design:** each person has an X25519 key pair, with the private key kept encrypted by their own key. The group key is sealed to each member's public key. The server stores the encrypted vault file with a version number, the member list with roles, and the sealed keys. The client downloads, merges, and uploads only if the version has not moved (If-Match). Removing a member makes a new group key; the removed person keeps what they already had.
- **What the server sees:** accounts, who is in which group, file sizes, times and IP addresses. It never sees vault contents, group keys, private keys or passwords. Read-only roles can only be enforced by the server refusing uploads, because every member holds the same file key. A hostile server could swap a member's public key, unless members compare a fingerprint at join.
- **Crates:** the opt-in HTTPS client (ureq and rustls) exists behind the `net` feature. `crypto_box` (X25519 boxes) is pinned for E7 but must be re-pinned first (LD-203). `ed25519-dalek` is approved. No HTTP server crate and no database crate is approved; each new one needs an AT-J03 review. Sources: [plan/architecture.md](../../plan/architecture.md), Approved crates; [Cargo.toml](../../Cargo.toml); LD-203 in [spec/decisions.md](../decisions.md).
- **Keep the server blind in code.** A small Rust server that never links the vault decoder shows in its own code that it cannot decrypt.

### 6.5 Many versions from one code base

- Cargo features "should be additive. That is, enabling a feature should not disable functionality." Source: [Features (The Cargo Book)](https://doc.rust-lang.org/cargo/reference/features.html).
- Larsal already has one such switch: the `net` feature (the `--no-net` build). Source: [crates/larsal-ffi/Cargo.toml](../../crates/larsal-ffi/Cargo.toml).
- So: build switches only remove code (`net`, later `sync`). An account unlocks services at run time: server sync, families, teams, seats. One Mac app, not two. "With its own vault or not" is a run-time choice: local vaults only, or local vaults plus account vaults.
- A paid plan never locks anyone out of a local vault. When a plan ends, server sync stops. Larsal still opens, edits, saves and exports the local copies, because the vault is a standard file that opens with the key alone. The plan check lives on the server, never in GPL client code.

### 6.6 Licenses

- Allowed dependency licenses: MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unicode-3.0, plus named MPL-2.0 exceptions for the UniFFI 0.32.2 crates. The workspace has no license field yet and no LICENSE file. Sources: [deny.toml](../../deny.toml); [Cargo.toml](../../Cargo.toml).
- Not checked against a source in this research: AGPL-3.0 section 13 makes anyone who runs a changed server for others offer its source; GPLv3 section 13 allows combining with AGPLv3 code; MPL-2.0 is compatible with GPL-3.0. Check before E14-S2. Source to read then: [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html).
- A contributor agreement lets the owner relicense later: a commercial or App Store build, or a new license. Without one, every outside contribution fixes the license in place. A DCO gives no right to relicense. If the only money is the hosted service and support, no agreement is needed (sections 2.5 and 5.3).

### 6.7 Draft new epics

The reference app has no server. These epics are written from public standards and the sources above, so the clean room holds (AGENTS.md rule 2). Sizes are rough.

| Epic | What | Stories | Size |
|---|---|---|---|
| E15 Cloud-folder sync hardening | Coordinated file access around unlock, reload and save; "still downloading" and "offline" handling; a conflict-copy finder (iCloud versions, plus sibling files that open with the same key and have the same root group); a test matrix on iCloud Drive, Dropbox, OneDrive, Google Drive, SMB and WebDAV | about 4 | M |
| E16 Sync server and client | A protocol crate and a small server: encrypted file store with a version per vault, If-Match uploads, devices and tokens, limits, one SQLite file. Client loop: download, merge, upload, retry. Fuzz every request parser | 6 to 8 | L |
| E17 Accounts and billing | Sign-in with an auth secret kept apart from the vault key; the server stores only its hash; no password recovery, only an emergency kit; plan state on the server; payment provider | 5 to 6 | M to L |
| E18 Family and team sharing on the server | Key pair per person, group key per shared vault, invites with a fingerprint check, roles, removal with a new key; new mockup frames | about 6 | L |
| E19 Self-host package | One reproducible server binary (reuse `scripts/repro-build.sh`), config, TLS, backup and restore, admin tool, optional container image, docs | 3 to 4 | M |

Source for the sizes and contents: the fit research of 2026-10-31, built on the project files above.

### 6.8 Plan text that would change (only after the owner says yes)

- APP-05.17 gets the conflict-copy finder. APP-05.24 to APP-05.30 get coordinated access and dataless handling.
- FMT-15.10 and MOD-11.15 get a lead ruling: same-vault sync merges apply the deleted-objects list. It goes further than the reference app, so it needs a parity note.
- E14-S2 becomes "GPL-3.0-or-later client, AGPL-3.0 server, contributor agreement or not". E14-S6 adds the server repository.
- [plan/security.md](../../plan/security.md) gets a row on what a server can and cannot see.
- The README status line is fixed.
- Each choice becomes a decision card in [spec/decisions.md](../decisions.md) with these sources (rule 9), when the lead assigns it.

## 7. Open questions

For the owner (money, reach or legal, AGENTS.md rule 7):
- Which features are paid? Is family sharing through a shared cloud folder free, with only hosted sync, admin and teams paid? Or is family sync itself the paid item, as the owner suggested?
- Run our own hosted sync service, or only "bring your own cloud" plus a self-hosted server at first? A hosted service needs accounts, billing, uptime, backups, invite email and data-protection work.
- Self-hosted server: are family and team features free, or do they need a paid license file, as Bitwarden does?
- License for the paid folder: write our own (needs a lawyer) or adopt an existing source-available license? The options were not researched.
- Contributor agreement or DCO? Copyright assignment or a broad license grant? The text needs a lawyer.
- Mac App Store, yes or no? Yes means the sandbox, against E14-S3's "no App Sandbox", and a contributor agreement or a commercial store build.
- Real cloud accounts for the E15 test matrix. These tests leave this Mac and use demo vaults only.
- Book the outside audit (D6) before a server ships? The server and the sharing crypto are new attack surface.
- Prices and the payment provider. Check all prices again first.

For the lead (rule 9):
- Should same-vault sync merges apply the deleted-objects list, and with which time rule?
- Sealing group keys: `crypto_box` sealed boxes (after the LD-203 re-pin) or HPKE (RFC 9180, a new crate)? Account login: OPAQUE, or a derived auth secret?
- Should coordinated file access live in Swift around the Rust save, or in larsal-platform? Check the deadlock rules for a file presenter in the same process.
- How to recognise other providers' conflict-copy names. Vendor naming was only checked for Dropbox. A content-based finder (same name stem, opens with the same key, same root group) avoids depending on names.

Not checked or not settled:
- The exact text of Bitwarden's contributor agreement (section 2.5).
- The scope and payouts of Bitwarden's HackerOne program (section 2.7).
- Whether Bitwarden offers a reproducible build. We found no Bitwarden page that offers one, but did not check further, for example third-party rebuilds of its Linux packages (section 2, "What this means for Larsal").
- Which future Bitwarden features will be commercial-only, and the text of its new commercial license (section 2.4).
- Bitwarden's server re-hash count: 600,000 (whitepaper) or 700,000 in total (KDF page) (section 3.1).
- The emergency-access maximum wait time, which the official pages do not state.
- Enpass's merge rules and current prices from the vendor (section 4.1).
- On a future iPhone app, "any cloud" is harder: Dropbox, Google Drive and OneDrive need provider APIs or the Files app on iOS. Out of scope for the Mac app.
- A free family share with no server, with wrapped keys in the shared folder and fingerprints compared in person: no vendor studied ships this. It would need its own Spec card.

# E24-S1 Passkeys and SSH research

Status: DRAFT, 2026-11-05. Public primary research and static proposals only; no implementation approval, second Spec review, independent Verify, runtime pass or Done.
Scope: all E24-S1 and LD-338/339. Existing INT-04 and INT-06 bodies, IDs, cases and dated evidence remain exact. Appended E24 rules are proposals until Lead adoption. They do not retroactively amend E7/E9 or relabel their proof.

## Capability and build map

| Capability | Contract | Consumer and order |
|---|---|---|
| ssh-create | INT-06.E24.01–.06 | E24-S2 after S1 |
| ssh-authorize | INT-06.E24.07–.19 | E24-S3 after S2 |
| ssh-sign | INT-06.E24.20–.24 | E24-S3 after S2 |
| mac-provider | INT-04.E24.01–.11 | E24-S4 after S1, E7-S5, D7 and W-02 |
| credential-exchange | INT-04.E24.12–.21 | E24-S5 after S1 and E7-S5 |
| surfaces | INT-04.E24.22–.26; INT-06.E24.25–.30 | E24-S6 after S2, E7-S5, E7-S7i and E20-S8b |
| attacks | Cases in both appendices | E24-S7 after S3 and S6 |

S1 is ready now. Signing, entitlement provisioning, packages, hardware and custody proof are later implementation gates, not new S1 prerequisites. A refusal/unsupported state does not pass a required success. Windows, Linux and phones retain LD-339's first-release capability obligation; this Mac draft supplies no invented availability for those later native integrations.

## Sources and freshness

All public reads: 2026-11-05. Links below are primary documentation, specifications or publisher source. No external implementation code is copied or translated. Raw reads and unsuccessful fetches belong outside the tree. The installed API declarations are supporting evidence, not a successful signed-device test. The local SDK identifies itself as macOS 27.0; its availability annotations do not certify release support or behavior. No new 27-only feature is selected.

### P01
[W3C WebAuthn Level 3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/): Recommendation, 25 August 2026; supersedes Level 2. RP scoping, consent, presence versus verification, backup flags, abort and accessibility govern provider and extension ceremonies. New E24 ceremonies require a real verification event; a click alone cannot assert UV. Existing .33/R04-1 requires an explicit amendment, not rewritten history.

### P02
[Credential provider controller](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller) and [registration callback](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller/prepareinterface%28forpasskeyregistration%3A%29): current API documentation. The class begins on macOS 11; passkey callbacks and request/response types begin on macOS 14.0 (also iOS 17.0). Treating class availability as passkey availability is wrong. Local headers confirm macOS 14.0 on registration, assertion, request-list and interaction callbacks. Mac Catalyst is not the native macOS provider path.

### P03
[AutoFill entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.authentication-services.autofill-credential-provider), [capability dictionary](https://developer.apple.com/documentation/bundleresources/information-property-list/nsextension/nsextensionattributes/ascredentialproviderextensioncapabilities) and [extension point](https://developer.apple.com/documentation/bundleresources/information-property-list/nsextension/nsextensionpointidentifier): current platform configuration. Use the credential-provider extension target, entitlement true in app and extension, and `com.apple.authentication-services-credential-provider-ui` as its extension point. Set `ProvidesPasskeys` true and configuration UI explicitly. No claim that editing a plist grants a capability. Exact proposed entitlement set: `com.apple.developer.authentication-services.autofill-credential-provider=true` on host and extension, `com.apple.security.app-sandbox=true` on the extension only, and `com.apple.security.application-groups` with the provisioned group on both. The existing host remains unsandboxed. Both the host and extension credential-provider capability dictionaries set `ProvidesPasskeys=true`; the extension also sets `ShowsConfigurationUI=true`; exchange adds P08’s keys on eligible OS versions. `NSExtensionPrincipalClass` names the credential-provider controller subclass. No new keychain group or network-client/server entitlement is proposed.

### P04
[Application groups](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.application-groups), [container access](https://developer.apple.com/documentation/xcode/accessing-app-group-containers), [provisioning profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles), [macOS capabilities](https://developer.apple.com/help/account/reference/supported-capabilities-macos). Reuse E7's app-group relay architecture with a distinct purpose-bound endpoint; share no decrypted vault or secret store. The extension needs the sandbox and its own matching team-approved group entitlement. Exact provisioned group value and profile are D7/W-02 artifacts, not a fabricated team ID. The public capability table's icon cells are lost in text extraction: distribution-route eligibility remains OPEN until a profile and signed build prove it. Do not promise a free personal team, Developer ID or store route solely from this table. Release still needs hardened runtime, valid nested signatures and applicable notarization; no get-task-allow.

### P05
[Credential identity store](https://developer.apple.com/documentation/authenticationservices/ascredentialidentitystore), [request parameters](https://developer.apple.com/documentation/authenticationservices/aspasskeycredentialrequestparameters), [assertion credential](https://developer.apple.com/documentation/authenticationservices/aspasskeyassertioncredential), [registration credential](https://developer.apple.com/documentation/authenticationservices/aspasskeyregistrationcredential). Native requests supply RP and client-data hash, not an extension-trusted browser origin. Let the OS validate native associated domains; independently bind Rust's selected credential and operation to the exact request. Public request and signature objects may cross into the controller; private keys may not. [Registration exclusions](https://developer.apple.com/documentation/authenticationservices/aspasskeycredentialrequest/excludedcredentials) are available from macOS 15. Bind the OS list and apply WebAuthn P01 section6.3.2 same-RP/type canonical-ID exclusion after privacy-preserving consent; cancel discloses no existence. G01 must prove equivalent OS-mediated exclusion behavior on the required successful macOS 14 path; no fabricated 14 field, omission on 15+, silently raised minimum or unavailable-state substitute. Identity-store IDs and account labels are privacy-sensitive OS metadata. Purge on lock/removal; OS cache erasure/latency needs measurement.

### P06
[FIDO CXF 1.0, proposed standard with errata dated 9 March 2026](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html), especially §3.3.12. CXF supplies data structures, not encryption by itself. Passkeys carry credential ID, RP, account/display names, user handle, PKCS#8 DER key and extension data. IDs/key identity must survive migration. Nonzero-counter passkeys are excluded by the standard; imported counters stay zero. This is a stated interoperability limit, never a substitute for successful migration of eligible passkeys.

### P07
[FIDO CXP 1.0](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html): working draft, 3 October 2024, still linked by the [current publication index](https://fidoalliance.org/download-credential-exchange-specifications/). Its status differs from CXF's proposed standard. It describes protected exchange and receiver key negotiation; base64 JSON is not protection. No home-made zip/encryption wrapper or standalone CXP implementation is adopted here. An OS exchange API is not proof that it implements this exact wire revision; document/prove the negotiated profile before claiming CXP interoperability.

### P08
[Import manager](https://developer.apple.com/documentation/authenticationservices/ascredentialimportmanager), [token import](https://developer.apple.com/documentation/authenticationservices/ascredentialimportmanager/importcredentials%28token%3A%29), [export manager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager), [exported data](https://developer.apple.com/documentation/authenticationservices/asexportedcredentialdata). Local installed declarations place both managers and the data object at macOS 26.0/iOS 26.0/visionOS 26.0, unavailable on watchOS/tvOS. macOS 14/15 do not gain exchange from provider support. Required configuration: `SupportsCredentialExchange=true`, `SupportedCredentialExchangeVersions=["1.0"]` in extension capability dictionary; host `NSUserActivityTypes` contains the exported exchange-activity constant's value. The public article calls it `ASCredentialExchangeActivityType`, while the installed SDK exports `ASCredentialExchangeActivity`; reconcile the exact SDK declaration/value and OS delivery in G02, never invent a literal or assume both symbols exist. Receiver obtains a UUID via `ASCredentialImportToken`, calls `importCredentials(token:)`; exporter uses `requestExport(for:)` then `exportCredentials(_:)` for the negotiated format. Duplicate/stale/wrong-recipient tokens must fail without writes.

### P09
[Passkey exchange data type](https://developer.apple.com/documentation/authenticationservices/asimportablecredential/passkey). Installed declarations use Swift structs, including private-key `Data`, in `ASExportedCredentialData`; the managers are Swift API. No documented zero-copy Rust entry point or wiping guarantee was found. OPEN: prove a supported Rust-owned transfer bridge, foreign allocation lifetime, all copies, OS transport protection and importer/exporter retention, without sending private keys through Swift screen state or readable files. If the public API necessarily requires non-Rust readable copies, Lead must resolve the acceptance conflict before implementation; a hidden Swift struct is not a new allowed secret exception. Do not call this capability secure from HTML or substitute readable export.

### P10
[OpenSSH key format, 10.3p1 tag](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/PROTOCOL.key) and [key utility manual](https://man.openbsd.org/ssh-keygen). The released 10.3p1 baseline is 2 April 2026; it is not asserted to be the newest release. The current online manual is a moving development document and additionally lists a hybrid key type. Select the established Ed25519, RSA and NIST ECDSA forms supported by E9; no hybrid/DSA/security-token key generation is introduced. Ed25519 has a fixed seed/key size; ECDSA uses 256/384/521; RSA defaults to 3072 upstream. New RSA 3072 or 4096 are proposed, not 2048; existing E9 RSA import compatibility stays. Comments are public labels, not account secrets.

### P11
[RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html): Standards Track, May 2026, now the published agent protocol rather than the old draft cited by E9. Reuse existing bounded framing and socket code. An agent connection authenticates the local peer, not the human or every ancestor/client of that peer. List replies expose public keys; a sign request supplies arbitrary data. Program approval and purpose checks are Larsal policy, not protocol guarantees.

### P12
[OpenSSH agent extensions, 10.3p1](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/PROTOCOL.agent). Session binding proves a host key signed the session identifier, with a forwarding marker and connection lifetime. It does not authenticate a hostname, a remote program or arbitrary data as an SSH login. Keep checked binding chains and parse the host-bound login payload before naming a destination. Unbound or ambiguous data is shown honestly and never inherits a remembered local login approval.

### P13
[OpenSSH signature protocol, 10.3p1](https://raw.githubusercontent.com/openssh/openssh-portable/V_10_3_P1/PROTOCOL.sshsig). Use version 1 SSHSIG, a nonempty namespace, reserved string, SHA-256/SHA-512 digest and SSH signature encoding. Git uses namespace `git`; RSA uses SHA-2 signatures, never legacy SHA-1. Domain separation is what prevents a git authorization from turning into an SSH login authorization. No cryptographic primitive is implemented locally.

### P14
[Git 2.56 configuration](https://git-scm.com/docs/git-config/2.56.0), [Git signing call sites](https://raw.githubusercontent.com/git/git/v2.56.0/gpg-interface.c), [signature format](https://git-scm.com/docs/gitformat-signature). Git's SSH program is also invoked for verification; supporting only a sign verb is insufficient. The signing invocation uses `-Y sign -n git -f PUBLIC_KEY [-U] PAYLOAD_FILE` and consumes PAYLOAD_FILE.sig, not a stdout-only signature. Verification uses find-principals, verify and check-novalidate. Trust comes from allowed signers and revocation policy, not from the mere validity of a signature or a key comment.

### P15
[Dynamic guest code lookup](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes%28_%3A_%3A_%3A_%3A%29), [audit identity attribute](https://developer.apple.com/documentation/security/ksecguestattributeaudit). Proposal: bind consent to a kernel peer instance, verified running-code identity, key revision, purpose and vault generation; never to a process-supplied name/PID/path alone. The exact race-safe Unix peer/audit-token API, executable-replacement detection and required Security framework wrappers remain OPEN. E9's display name is only a hint. An unresolved process identity cannot earn remembered approval.

### P16
[Independent password manager's SSH documentation](https://bitwarden.com/help/ssh-agent/) and [independent security app's public design](https://github.com/maxgoedjen/secretive), fresh official reads. Both support local agent custody and explicit authorization; neither proves Larsal's security or grants permission to copy implementation. Reuse E9's own agent and approved signer modules. Proposed program-instance approval until lock is a stricter bounded product policy, not a claim that all peer apps have that exact policy.

### P17
[Apple accessibility guidance](https://developer.apple.com/design/human-interface-guidelines/accessibility) and [W3C WCAG 2.2](https://www.w3.org/TR/WCAG22/). Keyboard reachability, labelled controls, visible focus, semantic errors, adequate contrast and non-color status cues apply. Frames inherit Option A parts/tokens/assets only. APP-10's adopted capture limits apply: showing content to a recipient or OS API permits retention; window flags cannot prove capture exclusion.

## Platform and custody matrix

| Path | Intended supported surface | Material held and end of custody | Remaining proof |
|---|---|---|---|
| Native provider | signed native macOS 14.0+, Intel/Apple silicon build targets; actual OS/app matrix required | Rust vault/sign operation; OS receives credential ID, user handle, public data and signature only | profile, app enablement, signed Safari/native app registration/assertion, wrong RP, lock/races |
| Exchange | macOS 26.0+ managers; iOS/visionOS 26 APIs are future product obligations | Rust holds private material; earliest call receiving readable credential data is external handoff, even before success | P09 bridge and OS copy/protection/retention OPEN |
| macOS 14/15 exchange | no selected manager APIs | no private serialization/file fallback | show unavailable, retain E24-S5 success obligation on supported OS |
| SSH | native Mac Rust agent, E9 socket | Rust loaded keys only while vault unlocked; signatures/public key to requesting peer | all key backends, identity and lock race proof |
| Extension | Chrome and Safari builds first; existing E7 transport | selected public SSH line, passkey ceremony response only | browser origin/frame binding and explicit fill action |
| Web vault | E20 Rust/Wasm memory, existing CSP/served-code warning | public SSH and passkey metadata to DOM; no private key/credential secret exports to JS | authenticated encrypted save/delete and CSP; no server password verifier |
| CLI | local Rust core plus explicit public output | public metadata/key to stdout; secret input echo-off; no private-output escape | isolated HOME/repo/agent cases; local helper protocol |

A target can keep a public key, signature or a migrated credential after handoff. Lock revokes future operations, not already delivered results. A migrated private key is usable by its new provider; deleting it here does not revoke it there or at the site. Do not promise otherwise.

## Required review and proof gates

E24-G01: D7/W-02 provisioned extension and signed OS tests. E24-G02: P09 exchange custody, encoding/version and transport review. E24-G03: AT-J03 for missing signer/OS bridge features, with exact release, checksum, license, advisory and transitive closure checked at acquisition time. E24-G04: race-safe peer instance and executing-code identity. E24-G05: all required S2/S3/S4/S5/S6 success cases, plus negative/removal controls in private copies, two sensitive Checkers and independent Verify. Each gate is OPEN; none is silently reduced to a smaller supported subset.

Proposed attack/parity/decision/API/dependency aftertexts and amendment conflicts are external UNADOPTED material for Lead. No new LD number, attack catalog ID or parity sign-off is assigned here. The five owned files suffice for this draft; later surface-specific card splits may be proposed by Lead without duplicating rules.

## Frame coverage

All IDs below prefix `e24-s1-`, are proposals, and render in both light and dark. Captions name rules; cards name cases. No frame runs security logic. OS-managed chooser/Touch ID appearance is labelled as an external step, not a counterfeit system dialog.

| Frames | Rules | States and boundary |
|---|---|---|
| provider, provider-off, provider-unavailable | INT-04.E24.01–.04 | setup, disabled, unsigned/OS availability |
| register, select, verify, provider-empty | INT-04.E24.05–.08 | create, choose, fresh verification, no match |
| provider-busy, provider-error, locked | INT-04.E24.09–.11/.25 | busy, cancel/error/expired, lifecycle |
| exchange, exchange-review, exchange-duplicates | INT-04.E24.12–.19 | eligibility, exact selection/receiver, collisions |
| exchange-progress, exchange-complete, exchange-error, exchange-unavailable | INT-04.E24.13–.21/.25 | pending handoff, result, hostile/cancel, unsupported |
| passkeys, passkeys-empty, delete-passkey | INT-04.E24.22/.23/.26 | list/detail/empty and removal, retained copies |
| new-ssh, new-ssh-rsa, new-ssh-ecdsa, ssh-generating, ssh-created, ssh-save-error | INT-06.E24.01–.06 | all generation options, progress/result/cancel/error |
| ssh-agent, ssh-approval, ssh-once, ssh-forwarded, ssh-revocation, ssh-unknown | INT-06.E24.07–.19 | setup, bounded remember, per-use, forwarded, revoke, identity error |
| git-setup, git-approval, git-error | INT-06.E24.20–.24 | config review, purpose approval, failure |
| public-key, fill-public-key, fill-changed, web-keys, cli-keys | INT-06.E24.25–.30 | public display/save, explicit target fill, target change, web/CLI boundaries |
| Every new frame | INT-04.E24.24; INT-06.E24.29 | focus, names, keyboard/VoiceOver/reduced-motion/capture obligations |

Cases are executable specifications for later Builders/Verify, not tests run during S1. S1's static proof is separately reported externally. Fresh second Spec review, independent Verify and selective Lead adoption follow; no status/central record is changed here.



## E24-S1 review and adoption record

2026-11-05: the exact revised specification and static proposals received fresh second Spec and independent Verify APPROVE, with R1–R4/N1 closed. The sealed pre-adoption complete source manifest is `8e0f22f647e509c5263995837624f57a5b2f6fb136a8b7f8c28c87ae54a1f4a1`; second Spec seal `5d3c7d944de41b109064b0d3cf51ec8b10c68825dc6c89a8962c48e762a91091`; Verify seal `f345bd00ee81226d2219d17909092c3b686d2be29850231feeb380e19c6d0dc2`. Proof covers56 rule/case/source pairs,112 fresh removal controls,80 themed source-bound PNGs plus2 accepted long captures and129 older frames/rectangles preserved per theme. Verify corrected contact-sheet accounting without changing the images or earlier proof. The full canonical frozen-source guard passed11604 scanned files plus19 vault names; actual-current adoption guard remains Root's separate requirement.

The DRAFT/unadopted status labels in the sealed appendices describe their pre-adoption state. This record and LD-380–396 adopt their written contracts only and explicitly supersede the listed legacy clauses for E24 implementation; historical rules/cases/proof keep their old scope. AT-KEY-01–18 and KEY-P1–7 are final catalog IDs with all runtime proof OPEN/todo. All17 acceptance conflicts remain visible in those rulings and their implementing gates; no successful capability is waived. G01–G05, Apple receiver identity, private Data/copy/transport custody, provisioned signing, signer backends, peer identity, descriptor feasibility and every implementing positive/hostile/removal/native/AX/capture obligation remain OPEN. Static evidence proves no running provider, exchange, generation, signing or secure custody. Detector/storage/bootstrap findings remain recorded externally. Original187-story scope, E24 Order and all S2–S7 acceptance/status lines are unchanged. Root closes only S1 after selective current-source equality, actual-current canonical guard and its owner-only commit; no implementation or runtime PASS follows.

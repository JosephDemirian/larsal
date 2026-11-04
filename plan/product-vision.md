**Recommendation:** do it the Bitwarden way, shaped for a Mac app: ship App free first, with your vault synced through any cloud you already have, and add paid family and team sync on a server that anyone can also host, after the first release.

# Product vision

Date: 2026-10-31. For the owner. Every fact and its source is in [spec/research/business-model.md](../spec/research/business-model.md) ("research" below, with its section number).

## 1. The vision

You download App on your Mac. Your vault is encrypted on your Mac, and only your key opens it. You sync the vault file through a cloud you already have: iCloud Drive, Dropbox, OneDrive, Google Drive, a home server or a USB stick. That part is free, forever. Later, families and teams can pay for sync and sharing on our server. Anyone can also run that server on their own machine, and App is then its client. All the code is public, so anyone can check that it is safe. This is how Bitwarden works (research 1 and 2). The one difference: Bitwarden starts from a server, and App starts from your Mac. Enpass already sells this "your own cloud" model (research 4.1).

## 2. The editions, from one code base

Proposed, not in the plan yet: the paid editions, the server and the Never paid list come with the draft epics E16 to E18 and need your yes.

There is one Mac app. You do not download a new app for each plan. What you switch on decides the edition (research 6.5).

| Edition | What it is | Who it is for | Free or paid | License |
|---|---|---|---|---|
| **App** | The Mac app. Your vaults on your Mac, synced through any cloud folder | Everyone | Free, forever | GPL-3.0-or-later |
| **App, no network** | The same app with no network code inside at all (it exists today: SN-05 in [plan/security.md](security.md)) | People who want zero network | Free | GPL-3.0-or-later |
| **App Family and App Teams** | App signs in to our hosted server: shared vaults, invites, members, admin | Families (up to 6 people), small teams | Subscription | App: GPL-3.0-or-later. Server: AGPL-3.0, team features under a separate paid license |
| **Self-hosted server** | Our server on your own machine. App connects to it as its client | Home labs, companies | Core free. Team features need a license file bought from us, as Bitwarden does (research 1.3) | AGPL-3.0 core. Team features under the separate paid license |

Price examples from others, as of 2026-10-31: Bitwarden Families $47.88 a year for 6 people, Bitwarden Teams $4 per user a month, Proton Pass Family $59.88 a year (research 1.1, 1.2 and 4.5). Prices change, so we check again before we set ours.

**Never paid:**
- Your local vault: open, edit and save, with no limit on items or Macs.
- Its encryption, always at full strength.
- Export of all your data.
- Sync through your own cloud folder.
- If a plan ends, only server sync would stop. Your vaults would still open, save and export (research 6.5).

We would write this promise into the code repository, not only on a website. Bitwarden's "Always free" lived only on its website; it went missing from the pricing page for about a month, and Bitwarden staff called that a marketing mistake (research 1.4).

## 3. How it stays safe

Proposed, not in the plan yet: the server and sharing parts below come with the draft epics E16 to E18 and need your yes.

We treat every cloud and every server as an enemy, our own server too. A university team found 12 attacks on Bitwarden by doing exactly this (research 3.5).

**What a cloud folder sees:**
- One locked file, with its name, size and dates.
- Nothing inside it. Only your key opens it.
- If someone changes the file, App finds out before it uses the data ([plan/security.md](security.md), "Who attacks").

**What our server would see:**
- Who has an account, and who is in which family or team.
- File sizes, times and IP addresses.
- Never your passwords, notes, master password or keys. The server's code would not be able to open a vault (research 6.4).

**Extra rules that Bitwarden learned the hard way:**
- Your master password never leaves your Mac, not even in scrambled form (research 3.5).
- When you invite someone, you would both compare a short code, so a server could not slip in a fake member (research 3.3 and 3.5).
- When you remove someone, the shared vault would get a new key, and App would list the passwords they saw so you can change them (research 3.3).
- Anyone can check that the download matches the public code. App's reproducible build is already done (E14-S4 in [plan/epics.md](epics.md)). We found no Bitwarden page that offers this (research 2.7 and 7).

## 4. What changes in the plan

**Nothing on the board changes until you say yes.** The board is [plan/epics.md](epics.md): 96 stories today, 79 done (E11 is one story that waits for your choice W-15).

**Stays as it is:**
- E0 to E10, E12 and E13: the engine, the Mac app and the security checks.
- E14-S4, the reproducible build (Done).

**Changes, E11 first:**
- **E11 shared groups and remote sync:** build shared groups (INT-08) as the free family option with no server. Keep remote sync by commands (INT-09) out; a server does that job better. This is your open choice W-15 in [spec/decisions.md](../spec/decisions.md).
- **APP-05.17:** App finds the extra copies that clouds make when two Macs save at once, and merges them ([spec/app/APP-05-saving.md](../spec/app/APP-05-saving.md)).
- **FMT-15.10 and MOD-11.15:** an entry you delete on one Mac stays deleted after sync. Today it can come back from another copy (research 6.2).
- **E14-S2 license:** client GPL-3.0-or-later, server AGPL-3.0, paid team license, contributor agreement.
- **E14-S6 publication:** adds the server's code repository.

**New epics (drafts):**

| Epic | What it does | Rough size |
|---|---|---|
| E15 Cloud-folder sync hardening | Safer reads and writes in cloud folders, a "still downloading" message, finds and merges cloud copies, tests on real clouds. No server | about 4 stories, medium |
| E16 Sync server and client | Our small server that stores locked vault files, and App's sync with it | 6 to 8 stories, large |
| E17 Accounts and billing | Sign-in, plans and payments | 5 to 6 stories, medium to large |
| E18 Family and team sharing | Invites, members, roles, removing a member | about 6 stories, large |
| E19 Self-host package | One download to run the server yourself, with backups and docs | 3 to 4 stories, medium |

Details and sources: research 6.7 and 6.8.

## 5. What you decide

Each item has my pick. Items 2 to 4 cost money or reach outside this Mac, so they are yours ([AGENTS.md](../AGENTS.md), rule 7).

1. **Editions, prices and the Never paid list.** Pick: launch App free with any-cloud sync first. Keep everything on the Never paid list (section 2) free for good. Add paid Family and Teams sync later, and set prices then.
2. **The license set.** Pick: Mac app GPL-3.0-or-later. Server AGPL-3.0. Team features under a separate paid license, in one folder of the server only, never in the Mac app. Plus a contributor agreement, so we can sell other licenses and go to the App Store later. A lawyer writes the agreement and the paid license (research 2.1, 2.5 and 5.3).
3. **Mac App Store or direct sale first.** Pick: direct sale first. A signed download, sold through a company that handles tax for us, such as Paddle (5% + 50c a sale, as of 2026-10-31). It needs the $99-a-year Apple account (D7 in [README.md](../README.md)). The App Store comes later, after the contributor agreement (research 5).
4. **When to build the server.** Pick: after the Mac app's first release, as E15 onward. E15 (cloud folders, no server) comes first, then E16 to E19. Running our hosted server costs money each month, so that start is your yes too. E15 needs demo accounts on real clouds to test against (my pick: yes, demo vaults only), and the outside audit (D6) is booked before any server ships (my pick: yes).

**Next action:** reply "yes" to the four picks in section 5, or name the one you want changed.

## 6. Your answers (2026-10-31)

1. Free first and the Never paid list: yes. **But family, teams and sync are built now**, not after the first release.
2. Licenses: yes. My team writes the contributor agreement and the paid team license from published templates.
3. Direct sale first, through Paddle: yes.
4. The server: yes, once the main parts (sync, family, teams) work, the rest follows (payments, prices, the self-host package, the App Store).

Recorded as LD-262 in [spec/decisions.md](../spec/decisions.md).

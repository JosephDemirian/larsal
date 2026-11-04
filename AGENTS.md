# Rules for every agent

This folder is a new password manager written in Rust. Mac first. It will be open source.
It has no name yet. The placeholder name is **App** (see Naming).
Status: building. The Rust engine (vault format, crypto, vault operations) is done; the native macOS app (Swift screens over the Rust engine, LD-155) is being built. Start with [README.md](README.md).

## Rules that are never broken

1. **No outside product names.** Never write the name of the reference app, its file format, its file extensions or the names of its parts anywhere in this folder. That covers code, comments, docs, file names, UI text, test names and test data. Say "the reference app" or "the reference source". The name guard (story E0-S3) fails the checks when a banned word appears. The lead keeps the banned list outside this folder. When the vault format itself needs a string that contains a banned word (for example the document's root element name), cards, code and test data hold it only as hex bytes, never as text.
2. **Clean room.** Only Spec, Verify and Red team agents open the reference source or run the reference app. Builders work only from `spec/`, public standards (RFC, NIST) and this plan. Nobody copies or translates reference code, not one line. Why: our code must be our own work, so it carries our license and our name only.
3. **No home-made crypto.** Ciphers, hashes, key derivation and random numbers come only from the approved crates in [plan/architecture.md](plan/architecture.md). Only `app-crypto` imports them. Our own code arranges them: the vault file format and the key flow.
4. **Secrets stay in Rust.** Master keys, passwords and protected fields live in the Rust core, in types that wipe their memory when dropped. They never go to logs, error text, crash reports or the screen layer. One exception: the single value the user asked for with Show.
5. **Demo data only.** Never open a real password file. Tests use demo vaults with demo passwords, made by our tools or by the reference app's command line tool.
6. **Git is authorized** (owner 2026-11-04, LD-342). Keep small, clear commits and push to `https://github.com/JosephDemirian/larsal.git`. Commits carry the owner's name only. No agent or tool names, no "Co-Authored-By" lines.
7. **Ask before cost or reach.** Paid services, accounts, publishing, and anything that leaves this Mac need the owner's yes. Installing the Rust toolchain and the check tools in epic E0 is allowed once the owner starts the build.
8. **Done means proven.** A story is Done only when every acceptance check passed and a Verify agent signed it off with proof: commands run and their output, test names, screenshots.
9. **Don't reinvent the wheel.** Before any technical choice (architecture, library, tool, pattern), find out how proven apps of our kind do it: open source password managers and security apps. Use their common standard. Put the sources in spec/decisions.md. Don't ask the owner technical questions; the evidence decides. (Owner, 2026-10-27.)
10. **Never take over the owner's screen.** The owner works on this Mac. Screenshots come from offscreen rendering, test launches run hidden and never take focus, and no agent opens browser, Preview or Finder windows. A check that truly needs a visible window waits for the owner's go. Never write to or clear the owner's clipboard: no copy commands of App or the reference against the general pasteboard; tests use a private named pasteboard. (Owner, 2026-10-27; clipboard 2026-10-28.)
11. **Stop only your own processes, and leave others' files alone.** Other projects and agents run on this Mac. Stop a process by the PID you started; never `pkill -f` or `killall` by name. Tests that break code on purpose (mutation checks) run in a private copy of the tree, never in the shared one, so no other agent's edits are overwritten. (Owner's Mac, 2026-10-27; copy rule 2026-10-28.)

## Naming

Placeholders until the owner picks the name (decision D1). One agent renames all of them in one pass later.

| Thing | Placeholder |
|---|---|
| Product name in UI and docs | App |
| Rust crates | `app-crypto`, `app-model`, `app-format`, `app-core`, `app-platform`, `app-ffi`, `app-cli`, and later `app-browser`, `app-autotype`, `app-sshagent`, `app-hwkey`, `app-share` |
| Command line tool | `app` |
| Xcode project | `macos/App.xcodeproj`, scheme `App` |
| macOS bundle id | `com.app.desktop` |
| Vault file extension | `.appvault` (`.app` is taken on macOS: it marks programs) |
| Key file extension | `.appkey` |
| Settings folder | `~/Library/Application Support/App` |
| Keychain service | `com.app.vault` |
| Browser bridge host | `com.app.browser` |

## Where things are

| Path | What |
|---|---|
| `macos/` | The Mac app (from E5-S1): Xcode project, SwiftUI screens, local package `AppCore` |
| [design/option-a/mockup.html](design/option-a/mockup.html) | The approved look (Option A, locked by the owner 2026-10-27): every window of the Mac app and the browser extension, light and dark. Every screen copies it exactly. |
| [design/option-a/BUILD-AND-VERIFY.md](design/option-a/BUILD-AND-VERIFY.md) | How builders follow the mockup and how the Verify fleet proves parity, frame by frame |
| [design/website/index.html](design/website/index.html) | The website and landing page mockup. It loads `design/option-a/app.css` and `mockup.js`, so its app pictures are the locked design. |
| [design/mockup.html](design/mockup.html) | The old look, kept for history only. Spec cards that say "the mockup" mean Option A for looks; their behaviour rules still hold. |
| [plan/architecture.md](plan/architecture.md) | Components, folders, files, approved crates, Rust and Swift rules |
| [plan/native-app-research.md](plan/native-app-research.md) | How proven apps build a native Mac app on a Rust core; the source of LD-156 |
| [plan/security.md](plan/security.md) | What we protect, safe defaults, the security parity matrix |
| [plan/attacks-and-checks.md](plan/attacks-and-checks.md) | Every attack we try and every check we run |
| [plan/epics.md](plan/epics.md) | Epics, stories, acceptance checks, sprints, the board |
| [plan/team.md](plan/team.md) | Agent roles, how a story moves, how to brief and report |
| [spec/README.md](spec/README.md) | How behavior cards are written, and the list of cards |

## How to report

End every task with: story ID, files changed, proof (commands and their result), open issues, next step. Plain words. No claim without proof.

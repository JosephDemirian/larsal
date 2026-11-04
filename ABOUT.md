# Larsal

Larsal is the name the owner gave App on 2026-11-02. The code and the plan still say "App" until the rename pass (E14-S1). Before that pass, a check confirms that no trademark or domain stands in the way. The planned domain is larsal.app.

## What Larsal is

Larsal is a password manager and encryption app. It is open source and built Mac first.

**The core promise is zero-knowledge** (LD-340): we can't see your passwords, files or keys. Only you hold them. No server of ours, and no one who runs or breaks into one, holds anything that can open your data or test a guess at your password. Your password never reaches a server in any form, not even as a hash.

What it does:

1. **Keeps your secrets** in an encrypted vault file on your Mac: passwords, passkeys, one-time codes, SSH keys, notes and attached files. The vault uses the open vault file format that many password apps already read (version 4), with AES-256 or ChaCha20 and Argon2.
2. **Fills them in** on websites through Larsal's own browser extension: Chrome and Safari first, then Firefox, Edge, Brave and the other major browsers.
3. **Syncs** your vault through any cloud folder you already have (iCloud Drive, Dropbox, OneDrive, Google Drive), or through Larsal's own server, which you can also run yourself.
4. **Shares** vaults with your family (up to 6 people) or your team. Two people check each other with a code they both compare.
5. **Works in many places:** the Mac app, the browser extension, a web vault for a browser with no app installed, and the `larsal` command line tool (today `app`). Windows, Linux and phones come later.

Planned (plan/epics.md, E21 to E24):

- **Show as QR code:** one button shows a password as a QR code, so a phone can scan it.
- **Encrypt any file:** encrypt a file or an image on demand, in an open format that other apps can also open.
- **Encrypted folders:** a folder in any cloud where each file is encrypted on its own, so only changed files sync.
- **Passkeys and SSH keys everywhere:** Larsal becomes the Mac's passkey provider, makes SSH keys, approves each use, and signs git commits.

How it is paid for (plan/product-vision.md): the Mac app with your own vaults and your own cloud is free forever. Family and team sync on our server are paid plans. The app is GPL-3.0-or-later and the server is AGPL-3.0-or-later; see [legal/README.md](legal/README.md).

## Where the name comes from

The name comes from **Larsa**, an ancient city of Sumer in southern Mesopotamia. Its ruins lie in today's southern Iraq.

1. **The city of the sun god.** Larsa's god was the sun god, Utu in Sumerian and Shamash in Akkadian. He was the god of truth and justice: the light that shows what is true. Larsal tells you plainly what it can and cannot see.
2. **A home of early mathematics.** The clay tablet Plimpton 322 (about 1800 BC), a table of numbers tied to right triangles, most likely comes from Larsa. It is one of the oldest known works of number theory. Modern encryption is built on number theory, so the name points to the math that keeps your secrets safe.
3. **Law and fair rules.** Shamash is the god shown giving the laws to Hammurabi on the stone that holds Hammurabi's code. Larsal works by clear rules that protect you, and it breaks none of them.

The ending "-al" is our own. It makes a short name of two syllables that is easy to say and that belongs to no other product.

Sources: Plimpton 322 is in the Rare Book and Manuscript Library of Columbia University. The stone with Hammurabi's code is in the Louvre in Paris.

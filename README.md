# Larsal

A password manager for Mac, built with Rust and Swift.

Your passwords, notes and files belong to you. Larsal keeps them in an encrypted vault on your Mac. Your master password stays on your device.

Larsal is built around zero knowledge: only you hold the keys to your vault.

## What it does

- Stores passwords, secure notes and attachments in encrypted vaults.
- Generates passwords and passphrases.
- Handles time-based one-time codes.
- Keeps your vault files under your control.

Rust handles the vault, encryption and secrets. Swift provides the native Mac interface.

## Status

Larsal is in active development. The vault engine is implemented, and work continues on the Mac app, browser integration, sync and sharing.

There is no production release yet. Use demo data while development and security testing continue.

## License

See [LICENSE](LICENSE) for the terms of use. Third-party components retain their own licenses and notices.

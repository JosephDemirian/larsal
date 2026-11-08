# Source of these files

`desktop-vault/` holds unchanged copies of a demo vault that the public desktop app
made, published as test data of another project. `desktop-vault.LICENSE` is that
project's license text, unchanged.

- Project: github.com/ChrSchu90/CryptomatorVaultSync, folder `tests/test-vault/`
- Commit: 0e5d85ee84895c150250f271ae447f88bfcb0a10
- License: MIT, as `desktop-vault.LICENSE` says.
- Password: the project's published demo password, `cryptomator-vault-sync`. It guards
  nothing but this demo data.
- Files and their SHA-256, as `tests/peer.rs` (`DESKTOP_FILES`) pins them:

| File | SHA-256 |
|---|---|
| `IMPORTANT.rtf` | `d1194c5dddda2ad2d9d10ea7e43b670c181b650b070bcba096f57614df7dbadd` |
| `d/WN/WA7DFYE4SWMC3FAXOQKQUOZZ2YN2K5/BqCPA4XuGE1TGcVHmhDsUmgeZtQSTPT0MOB4.c9r` | `103355364c9128613cec68d6dcfe66f6864b457175b5d3a4ba3a8e63016e9af8` |
| `d/WN/WA7DFYE4SWMC3FAXOQKQUOZZ2YN2K5/LUQY1IVDNu3Z9TEcPCMJrbWXZs7MRJZ57ea93ZVHlh8=.c9r` | `c1384a52bbcf0baacc79055e13e412cc2b05d88b7b27fa0a01d5c5f9732f8c94` |
| `d/WN/WA7DFYE4SWMC3FAXOQKQUOZZ2YN2K5/dirid.c9r` | `a4af9cd9151990d5cebc45f51fee5fbb97b75999565e3cb85e9688e44c28b9a8` |
| `masterkey.cryptomator` | `5c0cf15a40ba04fd158a855b8ce49c2c7a131ec01d75e610cdcb4c05ed96ea6f` |
| `masterkey.cryptomator.5C0CF15A.bkup` | `5c0cf15a40ba04fd158a855b8ce49c2c7a131ec01d75e610cdcb4c05ed96ea6f` |
| `vault.cryptomator` | `ad47c1844724a4fe4c7d8bd01e5682a6c5f94ed67f4226acbfa7c35df01ada01` |
| `vault.cryptomator.AD47C184.bkup` | `ad47c1844724a4fe4c7d8bd01e5682a6c5f94ed67f4226acbfa7c35df01ada01` |

These files are data. Nothing in them runs. Do not edit them: a changed byte fails
`peer_desktop_made_vault_opens_with_names_and_hashes_pinned` by its hash.

The other peer vaults E23-S3 reads (a cryptographic library's `vault-gcm` and
`vault-ctrmac`) are under the AGPL and are never in this tree; their tests are ignored
and read them from `LARSAL_PEER_VAULTS`.

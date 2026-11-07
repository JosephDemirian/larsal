# Source of these files

The 147 test files here and `README.md` are unchanged copies of the published test
vectors of the age format.

- Project: github.com/C2SP/CCTV, folder `age/`
- Commit: 4448f2097b2daa812c91a26141f9f36c2096b9ca
- License: 0BSD, CC0 1.0 or Unlicense, to the project's choice, as `README.md` says.
- Folder hash: `461c15f61ce87a16ef71f22080a5d7876a1fa21b00c62a6a077883fb4a73555b`.
  That is the SHA-256 of one line `<name> <sha256 of the file>\n` per test file, by
  sorted name, leaving out the two `.md` files. `src/tests/vectors.rs` pins it.
- Each file was checked against the hashes in the manifest of the saved download,
  which has SHA-256 `300bce4a7afa15c4f96fa3cc8632077da8469b99ca1781163b59f171a81dbb30`.

These files are data. Nothing in them runs. Do not edit them: a changed row fails
the test by the hash.

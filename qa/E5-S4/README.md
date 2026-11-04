# E5-S4 Main window: screenshots

Made by `qa/scripts/snapshots.sh` with no window on screen (see qa/E5-S3/README.md): the hidden debug App renders its real main window view offscreen and writes the PNG. Vaults unlocked through F06 (`printf 'demo-pass-5\n' | App --password-stdin testdata/rich-v4.appvault`), never by a debug setting. Selection, Show, search text and the search tips come from the debug-only `APP_DEBUG_UI`; Show goes through the same `show_field` call as the eye button. Appearance from the debug-only `APP_DEBUG_APPEARANCE`. Mockup renders: `mockup-*.png`.

| Screenshot | Mockup |
|---|---|
| `app-main-dark.png`: "Full demo entry" selected, password shown, live code ring | `mockup-main-dark.png` |
| `app-main-light.png`: the same in light | `mockup-main-light.png` |
| `app-search-dark.png`, `app-search-light.png`: search `attachment`, 2 results | `mockup-search-dark.png` |
| `app-search-tips-dark.png`: search field focused, tips | `mockup-search-tips-dark.png` |
| `app-recycle-bin-dark.png`: the bin, an entry in it | none |
| `app-search-big-10000-dark.png`: `Entry 0999` on big-10000, 11 results | none |

Visible differences from the mockup:
- Content is rich-v4's: 6 entries in All Entries (the Work group has searching off, so its entries are not in All Entries, FEA-01.20), Work shown collapsed as the file stores it (MOD-02.5), no passkey, no second URL, no SSH key.
- Weak Passwords has no count: rating every password costs too much on large vaults; the view rates on click, inside the search work bound.
- Copy buttons are shown but disabled, with a tooltip: Copy waits for the Rust clipboard (E6-S1). The password value never reaches Swift for Copy.
- Edit, Restore, New Entry, New group, the generator and Reports are shown but disabled (E5-S5 and later). Attachments are listed without Open and Save.
- The "More actions" menu holds only Open URL and the disabled Copy items.
- Icons are SF Symbols, not the mockup's own line drawings. Entries with the default icon show the letter tile, as most mockup entries do; other standard icons show a symbol.
- The code ring is 16 points with its stroke; the mockup's is 20.
- Entry text and background colours (the mockup's row tints) are not applied yet.
- The vault switcher and sort menus are native macOS menus, not the mockup's drawn popovers.
- The offscreen render has no window frame: no traffic lights and square corners; the running app has the system's.

Search timing on big-10000 (FEA-01.34, under 50 ms):
- Rust, through the session, rows included (`cargo test -p app-ffi --test session fea01_34`): 2 to 5 ms per query in the debug build, 1 to 3 ms in release; all 10,000 rows in 4 ms (3 ms release).
- Screen layer, Rust call plus sort plus month sections (Swift test `FEA-01.34`): 3.4 to 15.8 ms for the five test queries; 36 ms for `e`, which matches all 10,000 entries.
- In the running app (log line "Search updated the list"): 5.6 ms for `Entry 0999`.

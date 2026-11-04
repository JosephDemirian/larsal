# E5-S3 Unlock screen: screenshots

Made by `qa/scripts/snapshots.sh` with no window on screen: the debug App runs hidden (`APP_TEST_HIDDEN`: no window, never the active app, its own instance folder), renders its real main window view offscreen at 1180 × 740 points and writes the PNG (`macos/App/Snapshot.swift`, debug builds only). Demo vault `testdata/rich-v4.appvault`, opened as a file argument; the wrong password came through F06 (`printf 'wrong\n' | App --password-stdin …`), never through a debug setting. Appearance from the debug-only `APP_DEBUG_APPEARANCE`; the system setting was not touched. Mockup renders: `mockup-*.png`, from design/mockup.html in a throwaway WebKit snapshot tool whose window is never shown.

| Screenshot | Mockup |
|---|---|
| `app-start-dark.png`: no vault open, "Open Vault…" | none (the mockup has no start view) |
| `app-unlock-empty-dark.png` | `mockup-unlock-dark.png` |
| `app-unlock-empty-light.png` | `mockup-unlock-light.png` |
| `app-unlock-wrong-password-dark.png`: M06-06 | `mockup-unlock-error-dark.png` (the mockup's error is M06-05) |
| `app-unlock-wrong-password-light.png`: M06-06 | none |

Visible differences from the mockup:
- Name and path are the real file's: "rich-v4" and its path (APP-06.2 uses the file name); the mockup shows its sample "Personal".
- Icons are SF Symbols, not the mockup's own line drawings: the key in the password field stands upright, the eye is heavier.
- The background glow is a circle, slightly wider than the mockup's ellipse.
- The offscreen render has no window frame: no traffic lights and square corners. In the running app the system draws them (a few points higher than the mockup's drawn ones).
- "Use a security key" is dimmed: security keys come with E10. The mockup shows it as an active link.
- No Touch ID form: quick unlock comes with E6-S3, so APP-04.9 shows the password form.
- The vault switcher opens a native macOS menu, not the mockup's drawn popover.
- The start view (no vault open) is App's own; the mockup starts at an unlock screen.

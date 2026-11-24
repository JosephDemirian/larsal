# E15-S3 Coordinated file access and "Still downloading": screenshots

Made by the test `stillDownloadingShots` (`macos/LarsalTests/FileAccessTests.swift`, APP-05.30 Mac QA) with no window on screen: the test host runs hidden (`LARSAL_TEST_HIDDEN`), renders the real main window view at 1320 × 820 points in a borderless window placed far off screen and never ordered front, and writes the PNG. Demo vault: the option-a demo copy `Personal.larsalvault` in its test folder. The test seam (`FileAccess.files`) reports that file as dataless, so Larsal shows the state; no cloud service took part. Appearance from the offscreen window's own appearance; the system setting was not touched.

| Screenshot | What it shows |
|---|---|
| `larsal-vault-still-downloading-light.png`, `larsal-vault-still-downloading-dark.png` | An open vault whose file on disk turned dataless: the notice "Still downloading." and the file name at the bottom of the window. The open copy stays usable. |
| `larsal-unlock-still-downloading-light.png`, `larsal-unlock-still-downloading-dark.png` | The unlock form of a dataless vault: the grey line "Still downloading. “Personal.larsalvault” opens when the download ends." under the form. |

Notes:
- The path line shows the test's own folder, not a cloud folder.
- No mockup: design/mockup.html has no download state.
- The offscreen render has no window frame: no traffic lights and square corners.

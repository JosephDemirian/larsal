# Option A: build it exactly, prove it frame by frame

The owner locked Option A on 2026-10-27. It is the look of the Mac app and the browser extension.
Every builder copies it. Every screen is proven against it before its story is Done (AGENTS.md rule 8).

## What is the source of truth

| File | What it holds |
|---|---|
| `mockup.html` + `mockup.js` | All 91 frames, light and dark. Open `mockup.html` in a browser; Light/Dark at the top switches every frame. |
| `manifest.json` | One record per frame: `id`, section, title, size, and every visible string, accessible name and placeholder (3,708 strings). |
| `reference/light/<id>.png`, `reference/dark/<id>.png` | The reference image of each frame at 2× scale. |
| `tools/export-reference.mjs` | Rebuilds `manifest.json` and `reference/` from the mockup. Run it after any change to the mockup: `node design/option-a/tools/export-reference.mjs` (headless, opens no window). |
| `vendor/` | The exact assets: IBM Plex Sans and Mono (OFL), Phosphor icons regular and fill (MIT), Simple Icons brand logos (CC0). |
| `first-draft.html` | History only. Not a reference. |

Order when sources disagree:
1. **Looks** (layout, sizes, colours, type, icons, text on screen): the mockup wins.
2. **Behaviour** (what a control does, rules, messages, limits): the spec card wins (`spec/`). If the mockup shows text that a card words differently, use the card's words and record it as a known difference in the parity report.
3. **Where both are silent:** the design skills below decide, then the lead.

Later additions (new windows, new extension screens) go into this same `mockup.html` file as new frames; run the export again so `manifest.json` lists them.

## Native mapping (Mac app, SwiftUI over the Rust core)

| Mockup | Larsal |
|---|---|
| CSS custom properties in `.win.light` and `.win.dark` (`mockup.html`) | One colour asset per property with Any and Dark appearances, same names, same hex values. No other colours in the app. |
| Sidebar tile colours `--blue` … `--graphite` in `:root` | Same hex values, same in both appearances. |
| IBM Plex Sans 400/500/600, IBM Plex Mono 400/500 | Bundled fonts from `vendor/fonts`, registered in the app. Mono only for secrets, codes, keys, paths and placeholders as the mockup shows. |
| Phosphor `ph-*` (regular) and `ph-fill ph-*` | The same Phosphor glyphs (font or SVG assets from the same version, 2.1.2), same names, same sizes. |
| Simple Icons logos (`vendor/simple-icons/brands.js`) | The same SVG paths and official hex colours as vector assets; dark marks turn to the text colour in dark mode. Entries with no logo get the lettered tile. |
| Sizes | Window 1320 × 820 default; sidebar 248; top bar 52; sheet inset 8, radius 12; list rows 56; detail rail 368; gaps 16 and 24; type 22 / 18 / 16 / 15 / 14 / 13 / 12. Read every other value from `mockup.html`. |

The browser extension (`extension/`, E7-S7) is web code: it may reuse the mockup's CSS and tokens directly.

## The design skills (installed in `~/.claude/skills/`)

| Skill | Use it for |
|---|---|
| `design-taste-frontend` | `references/larsal-screens.md` whole: spacing, density, tables, states, data honesty; its `lint.mjs` and `inspect.mjs --app` on the extension. |
| `web-design-guidelines` | Fetch the current rules; apply accessibility, focus, forms, number formatting, motion and copy rules (their native equal in SwiftUI). |
| `ui-ux-pro-max` | The pre-delivery checklist and the priority 1–3 rules (accessibility, interaction, layout); search `--stack swiftui` where it helps. |
| `awesome-design-md` | Craft reference only. Never copy another brand's look. |

The mockup already applies these skills. The owner's taste overrides a skill where they differ (for example the coloured sidebar tiles): follow the mockup.

---

## Prompt for builders

```text
You build Larsal screens for story <STORY-ID>. The look is locked: design/option-a/mockup.html.

Read first, in full:
1. AGENTS.md (all rules; clean room; secrets stay in Rust; never take over the owner's screen).
2. design/option-a/BUILD-AND-VERIFY.md (this brief).
3. The spec cards your story names in plan/epics.md.
4. The skills: ~/.claude/skills/design-taste-frontend/SKILL.md and references/larsal-screens.md,
   ~/.claude/skills/web-design-guidelines/SKILL.md (fetch its rules),
   ~/.claude/skills/ui-ux-pro-max/SKILL.md (checklists), ~/.claude/skills/awesome-design-md/SKILL.md.

Then:
- List every frame id in design/option-a/manifest.json that your story covers. Build all of them, light and dark.
- Copy the mockup exactly: same layout, sizes, spacing, radii, colours (by token name), fonts, icons
  (same Phosphor glyph names, same brand logos), text, order of elements, states, menus and shortcuts.
  Do not "improve", restyle, rename or skip anything. If something cannot be built as drawn, stop and
  write it down for the lead with the frame id and the reason; do not substitute.
- Every string in the frame's manifest record must appear in the app with the same words, except live
  values (one-time codes, countdown seconds, generated passwords), which must match the format.
- Behaviour comes from the spec card. Where the card's words differ from the mockup's, use the card
  and list the frame id and both texts in your report.
- For every frame you build, add an offscreen snapshot test that renders that exact state at the
  frame's size in light and dark and writes target/larsal-shots/<light|dark>/<frame-id>.png. Render offscreen in
  the test process; never open a visible window (AGENTS.md rule 10).
- Apply the skill checklists: keyboard and VoiceOver labels on every control, visible focus, contrast
  at 4.5:1 for text, tabular figures for numbers, no layout shift on state change, reduced motion.

Report (AGENTS.md "How to report"): story id, files changed, the frame ids built, the snapshot test
names and their output paths, commands run with results, every known difference with its frame id.
```

## Prompt for the Verify fleet

```text
You are a Verify agent for design parity. You check section <SECTION> of design/option-a/mockup.html
(frame ids: every manifest.json record with "section": "<SECTION>"). You did not build these screens.
One Verify agent runs at a time; the lead queues the sections.

Read first: AGENTS.md, design/option-a/BUILD-AND-VERIFY.md, and the four skills listed there.

Inputs:
- Reference: design/option-a/reference/<light|dark>/<frame-id>.png and manifest.json.
  Run `node design/option-a/tools/export-reference.mjs` first so the reference matches the current mockup.
- Larsal: build the app, run the snapshot tests offscreen, and collect target/larsal-shots/<light|dark>/<frame-id>.png.
  Never open a visible window or take focus. Stop only processes you started, by PID.

For every frame, in light and in dark, check and record:
1. Present: the app has this frame's state. A missing frame is a FAIL.
2. Text: every string in texts, accessibleNames and placeholders is present with the same words
   (read the app's accessibility tree in the snapshot test). List missing, extra and changed strings.
   Live values (codes, countdowns, generated passwords) match the format only.
3. Tokens: every colour used matches its token's hex for that theme; fonts are IBM Plex at the same
   size and weight; icons are the same Phosphor glyph or brand logo.
4. Geometry: the main boxes (window, sidebar, top bar, sheet, rail, rows, dialogs, popovers) are within
   2 pt of the reference in position and size; radii and gaps equal.
5. Pixels: a diff image of reference against app (pixelmatch threshold 0.1, anti-aliasing ignored),
   with the percentage of changed pixels. Over 3 % is a FAIL unless every changed area is explained by
   items 2–4 and accepted by the lead.
6. Behaviour: every control the mockup makes clickable does the same thing in the app (selecting rows,
   tabs, sidebar items, reveal, copy with the clipboard notice, menus, sort, editor pages, generator
   modes and slider, settings pages, dialogs open and close).
7. Accessibility: keyboard reachability, VoiceOver names, focus ring, contrast.

Write the parity report:
- design/parity/<SECTION>/report.html: for each frame and theme, mockup | app | diff side by side,
  then the findings for checks 1–7 and a PASS or FAIL verdict.
- design/parity/<SECTION>/report.md: a summary table (frame id, light, dark, pixel %, missing strings,
  token mismatches, verdict) and the exact commands you ran with their output.
- No claim without proof: every PASS cites its images, its numbers and the command that produced them.

End with AGENTS.md "How to report": section, frames checked, frames passed, every FAIL with frame id
and the smallest fix, open issues, next step.
```

## The full parity report

When every section is checked, the lead merges the section reports into `design/parity/report.html`: one row per frame and theme (91 × 2), sorted by section, with its verdict and links. Story E5-S12 (and E7-S7 for the extension) is Done only when every row is PASS or an accepted, written difference.

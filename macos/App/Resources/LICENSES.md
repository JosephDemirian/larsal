# Licenses of the bundled design assets

The Mac app ships these files unchanged from `design/option-a/vendor` (copied and converted by `scripts/make-option-a-assets.py`), with the license texts in `Licenses/`, which the app bundle carries too.

| Asset | Files in the app | Source | License |
|---|---|---|---|
| IBM Plex Sans 400, 500, 600 and IBM Plex Mono 400, 500 (latin subset) | `Fonts/ibm-plex-*.woff2` | IBM Plex, via Fontsource | SIL Open Font License 1.1: `Licenses/IBM-Plex-OFL.txt` |
| Phosphor Icons 2.1.2, regular and fill | `Fonts/Phosphor.woff2`, `Fonts/Phosphor-Fill.woff2`; the code points in `Glyphs.swift` | Phosphor Icons | MIT: `Licenses/Phosphor-LICENSE.txt` |
| Simple Icons 16.36.0 (subset of 27 brand logos) | `Assets.xcassets/Brands/brand-*.imageset` (the SVG paths and official colours) | Simple Icons | CC0 1.0: `Licenses/Simple-Icons-LICENSE.md`; the brand marks belong to their owners: `Licenses/Simple-Icons-DISCLAIMER.md` |
| Option A colour tokens | `Assets.xcassets/Colors/*.colorset` | `design/option-a/app.css` | App's own design |

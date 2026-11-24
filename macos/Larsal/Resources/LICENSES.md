# Licenses of the bundled design assets

The Mac app uses these assets from `design/option-a/vendor`, copied or converted by `scripts/make-option-a-assets.py`. Font and asset-catalog paths below are relative to `macos/Larsal/Resources`. In the built app, fonts and license texts are directly in `Contents/Resources`; Xcode compiles the asset catalogs into `Assets.car`.

| Asset | Source asset files | Source | License and bundled text |
|---|---|---|---|
| IBM Plex Sans 400, 500, 600 and IBM Plex Mono 400, 500 (latin subset) | `Fonts/ibm-plex-*.woff2` | IBM Plex, via Fontsource | SIL Open Font License 1.1: `IBM-Plex-OFL.txt` |
| Phosphor Icons 2.1.2, regular and fill | `Fonts/Phosphor.woff2`, `Fonts/Phosphor-Fill.woff2`; the code points in `Glyphs.swift` | Phosphor Icons | MIT: `Phosphor-LICENSE.txt` |
| Simple Icons 16.36.0 (subset of 27 brand logos) | `Assets.xcassets/Brands/brand-*.imageset` (the SVG paths and official colours) | Simple Icons | CC0 1.0: `Simple-Icons-LICENSE.md`; the brand marks belong to their owners: `Simple-Icons-DISCLAIMER.md` |
| Option A colour tokens | `Assets.xcassets/Colors/*.colorset` | `design/option-a/app.css` | Larsal's own design |

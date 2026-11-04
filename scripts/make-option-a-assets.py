#!/usr/bin/env python3
"""Makes the Mac app's Option A assets from design/option-a (LD-162).

- Colour sets: one per CSS custom property of `.win.light` and `.win.dark`
  in app.css (Any and Dark appearances, same names, same hex values),
  the sidebar tile colours of `:root` (same in both), and the few literal
  colours the mockup's rules use (named below).
- Brand logos: one vector image set per Simple Icons path in brands.js, in
  its official colour; dark marks take the dark theme's text colour in Dark
  (mockup.js `brandSvg`).
- Fonts: IBM Plex Sans and Mono, Phosphor regular and fill, copied as they
  are (Core Text reads WOFF2), and their license texts (Resources/Licenses).
- macos/Larsal/Glyphs.swift: the Phosphor code points of the glyph names Larsal
  uses.

Run from anywhere: scripts/make-option-a-assets.py
"""
import json
import pathlib
import re
import shutil

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "design/option-a"
OUT = ROOT / "macos/Larsal/Resources"
CATALOG = OUT / "Assets.xcassets"

# Literal colours of the mockup's rules, as (light, dark) hex.
LITERALS = {
    "sidebar-hover": ("e9ecec", None),  # .win.light .si:hover; dark keeps --hover
    "menu": (None, "1c1c1f"),  # .menu, .tips; light keeps --surface
    "menu-rule": (None, "2a2a2e"),  # .msep; light keeps --rule
    "on-accent": ("ffffff", "06181d"),  # .mi:hover, .btn.accent
    "on-danger": ("ffffff", "1a0405"),  # .btn.danger
    "pressed": (None, "2e2e33"),  # .segc button[aria-pressed]; light keeps --surface
    "badge-ink": ("ffffff", "ffffff"),  # .si .badge
    "light-red": ("ff5f57", "ff5f57"),  # .lights i
    "light-yellow": ("febc2e", "febc2e"),
    "light-green": ("28c840", "28c840"),
    "toast-ink": ("ffffff", "131315"),  # .toast; its fill is --primary
    "toast-icon": ("6fd3ab", "1e7b4f"),  # .toast .ph
    "dialog": (None, "1a1a1d"),  # .dlg; light keeps --surface
    "srow-rule": (None, "232327"),  # .srow + .srow; light keeps --border
    "range-track": ("efefef", "3b3b3b"),  # .range: the browser's track, as drawn
    "range-edge": ("b2b2b2", "858585"),  # .range: the track's 1-point edge
}

GLYPHS = """
app-window archive archive-box arrow-clockwise arrow-left arrow-right arrow-square-out
arrows-clockwise article bank book-open briefcase calendar-blank camera caret-down caret-left
caret-right caret-up-down certificate check check-circle circle clipboard-text clock
clock-countdown clock-counter-clockwise copy copy-simple cpu currency-dollar desktop
device-mobile disc dots-three download-simple envelope-simple eye eye-slash feather file
file-lock file-plus file-text fingerprint flag floppy-disk folder-open folder-simple gear-six
globe globe-simple hammer hard-drive hard-drives heart house-line identification-card image info
key keyboard keyhole lightning link linux-logo list-bullets lock-key lock-open lock-simple
magnifying-glass minus monitor music-notes note note-pencil package paperclip password pencil-simple
pen plug plus plus-circle printer push-pin qr-code scan shield-check shield-warning
shopping-bag sidebar-simple sliders-horizontal sort-descending squares-four star
terminal terminal-window trash tray user user-circle users-three warning warning-circle
wifi-high wrench x x-circle apple-logo play
image-square upload-simple credit-card game-controller film-strip airplane car student
chat-circle database cloud minus-circle suitcase map-pin train boat
command share-network power
pause pause-circle
""".split()


def rgba(text):
    """'#rrggbb' or 'rgba(r, g, b, a)' to sRGB components."""
    text = text.strip()
    if text.startswith("#"):
        h = text[1:]
        return [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)] + [1.0]
    r, g, b, a = [float(x) for x in re.findall(r"[\d.]+", text)]
    return [r / 255, g / 255, b / 255, a]


def colour(c):
    return {
        "color-space": "srgb",
        "components": {k: f"{v:.3f}" for k, v in zip(("red", "green", "blue", "alpha"), c)},
    }


def colourset(name, light, dark):
    folder = CATALOG / "Colors" / f"{name}.colorset"
    folder.mkdir(parents=True, exist_ok=True)
    colors = [{"idiom": "universal", "color": colour(light)}]
    colors.append({
        "idiom": "universal",
        "appearances": [{"appearance": "luminosity", "value": "dark"}],
        "color": colour(dark),
    })
    (folder / "Contents.json").write_text(json.dumps({"colors": colors, "info": INFO}, indent=2) + "\n")


INFO = {"author": "xcode", "version": 1}


def block(css, selector):
    body = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", css).group(1)
    return {k: v for k, v in re.findall(r"--([a-z-]+):\s*([^;]+);", body)}


def main():
    if CATALOG.exists():
        shutil.rmtree(CATALOG)
    CATALOG.mkdir(parents=True)
    (CATALOG / "Contents.json").write_text(json.dumps({"info": INFO}, indent=2) + "\n")
    for sub in ("Colors", "Brands"):
        (CATALOG / sub).mkdir()
        (CATALOG / sub / "Contents.json").write_text(json.dumps({"info": INFO}, indent=2) + "\n")

    css = (SRC / "app.css").read_text()
    light, dark = block(css, ".win.light"), block(css, ".win.dark")
    for name, value in light.items():
        if name.endswith("shadow"):
            continue
        colourset(name, rgba(value), rgba(dark[name]))
    for name, value in block(css, ":root").items():
        colourset(name, rgba(value), rgba(value))
    for name, (lo, hi) in LITERALS.items():
        base = {"sidebar-hover": "hover", "menu": "surface", "menu-rule": "rule", "pressed": "surface",
                "dialog": "surface", "srow-rule": "border"}.get(name)
        lc = rgba("#" + lo) if lo else rgba(light[base])
        dc = rgba("#" + hi) if hi else rgba(dark[base])
        colourset(name, lc, dc)

    text = (SRC / "vendor/simple-icons/brands.js").read_text()
    brands = json.loads(text[text.index("{"):text.rindex("}") + 1])
    for key, b in brands.items():
        folder = CATALOG / "Brands" / f"brand-{key}.imageset"
        folder.mkdir()
        n = int(b["hex"], 16)
        lum = 0.2126 * (n >> 16) / 255 + 0.7152 * ((n >> 8) & 255) / 255 + 0.0722 * (n & 255) / 255
        svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="#{}" d="{}"/></svg>\n'
        (folder / f"{key}.svg").write_text(svg.format(b["hex"].lower(), b["path"]))
        images = [{"filename": f"{key}.svg", "idiom": "universal"}]
        if lum < 0.18:
            (folder / f"{key}-dark.svg").write_text(svg.format(dark["text"].lstrip("#"), b["path"]))
            images.append({
                "filename": f"{key}-dark.svg",
                "idiom": "universal",
                "appearances": [{"appearance": "luminosity", "value": "dark"}],
            })
        contents = {"images": images, "info": INFO, "properties": {"preserves-vector-representation": True}}
        (folder / "Contents.json").write_text(json.dumps(contents, indent=2) + "\n")

    fonts = OUT / "Fonts"
    fonts.mkdir(parents=True, exist_ok=True)
    for f in sorted((SRC / "vendor/fonts").glob("*.woff2")) + sorted((SRC / "vendor/phosphor").glob("*.woff2")):
        shutil.copyfile(f, fonts / f.name)

    licenses = OUT / "Licenses"
    licenses.mkdir(exist_ok=True)
    for source, name in [
        ("vendor/fonts/OFL.txt", "IBM-Plex-OFL.txt"),
        ("vendor/phosphor/LICENSE", "Phosphor-LICENSE.txt"),
        ("vendor/simple-icons/LICENSE.md", "Simple-Icons-LICENSE.md"),
        ("vendor/simple-icons/DISCLAIMER.md", "Simple-Icons-DISCLAIMER.md"),
    ]:
        shutil.copyfile(SRC / source, licenses / name)

    phosphor = (SRC / "vendor/phosphor/regular.css").read_text()
    points = dict(re.findall(r'\.ph\.ph-([a-z0-9-]+):before\s*\{\s*content:\s*"\\([0-9a-f]+)"', phosphor))
    lines = [
        "// Made by scripts/make-option-a-assets.py from Phosphor 2.1.2",
        "// (design/option-a/vendor/phosphor, MIT). Do not edit by hand.",
        "",
        "/// Phosphor code points by glyph name; regular and fill share them.",
        "enum Glyphs {",
        "    static let points: [String: UInt32] = [",
    ]
    for name in sorted(set(GLYPHS)):
        lines.append(f'        "{name}": 0x{points[name].upper()},')
    lines += ["    ]", "}", ""]
    (ROOT / "macos/Larsal/Glyphs.swift").write_text("\n".join(lines))


if __name__ == "__main__":
    main()

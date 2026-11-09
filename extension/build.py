"""Builds a package of Larsal's browser extension (INT-11.2, research B2; stories E7-S7c, E7-S7d).

Python 3 standard library only. Run:

    python3 -I extension/build.py chrome OUT [--dev]

It makes the new folder OUT with the browser's manifest.json, written from
manifest.json.in, and the files the package uses, each copied as written: no
bundler, no minifier, nothing generated but the manifest and words.txt (INT-11.39: the
word column of Larsal's built-in list, checked against FEA-03's check value). --dev adds the
development `key`, so an unpacked build keeps one id for the `allowed_origins`
of Larsal's debug setup files (INT-11.2, INT-11.4); a store package has none.
E7-S7e, E7-S7j and E7-S7l add the Safari, Firefox and Edge builds.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
# Every file a package ships besides its manifest and words.txt (INT-11.2: only the files it uses).
FILES = (
    "background.js", "channel.js", "idkey.js", "routes.js", "wire.js", "words.js", "_locales/en/messages.json",
    "popup/popup.html", "popup/popup.css", "popup/popup.js", "popup/state.js",
    "popup/fonts/ibm-plex-sans-latin-400-normal.woff2", "popup/fonts/ibm-plex-sans-latin-500-normal.woff2",
    "popup/fonts/ibm-plex-sans-latin-600-normal.woff2", "popup/fonts/ibm-plex-mono-latin-400-normal.woff2",
    "popup/fonts/Phosphor.woff2", "popup/fonts/Phosphor-Fill.woff2",
)
# The fonts' licences (OFL 1.1 and MIT ask that each copy carries them).
LICENCES = ("popup/fonts/IBM-Plex-OFL.txt", "popup/fonts/Phosphor-LICENSE.txt")
# INT-11.39: Larsal's built-in word list (FEA-03) and its check value: SHA-256 of the 7,776 words, each and LF.
WORD_LIST = os.path.join(HERE, os.pardir, "crates", "larsal-core", "src", "generator", "eff_large_wordlist.txt")
WORDS_SHA256 = "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522"
# Each browser's own members (INT-11.2; INT-11 "Minimum browser versions").
BROWSERS = {"chrome": {"minimum_chrome_version": "133"}}
# The public half of the development key (INT-11.4): a demo RSA-2048 key made for
# this; its private half was never kept, so it signs no package. Its id is DEV_ID.
DEV_KEY = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz1KAUjvu2c2XJn7RpDZOskn9tmbb6VbRxTyDI+im/T+JM3uIQNn1F3DMqY4J"
    "hMohvNlDV1BA0OSliKlmOHKMWqZ7VmNPGe+mfFAhM6SjaezHV6Yq+RwXxWC6orOmWey0mcvMpX4PqMtOVSUxJT6In7awladlcNg+rsra"
    "asrkvg44Z0PjnM1InLW7WxNZk99zS13x5bBf/udkFhQaJmBV0av1CXXKEdOXUjwWTZWYDtGPNPKd8cBBYWl0oo9o4N8c1irPQJbUybwn"
    "D1v8DPWq0dCTk8fLLJzSXzsakRBN+OCXkJdH10ZYgZFfqd5tJHhZg3HQXFGLR8lvWIrhDTMprQIDAQAB"
)


def extension_id(key):
    """Chrome's id for a manifest `key`: the first 32 hex digits of SHA-256 over the
    key's bytes, each digit written as a letter from a (0) to p (15)."""
    digest = hashlib.sha256(base64.b64decode(key, validate=True)).hexdigest()[:32]
    return "".join(chr(ord("a") + int(d, 16)) for d in digest)


DEV_ID = extension_id(DEV_KEY)


def larsal_version():
    """Larsal's version: the workspace version in Cargo.toml."""
    with open(os.path.join(HERE, os.pardir, "Cargo.toml")) as f:
        found = re.search(r'^\[workspace\.package\][^\[]*?^version = "([0-9.]+)"$', f.read(), re.M | re.S)
    if not found:
        raise SystemExit("build.py: no [workspace.package] version in Cargo.toml")
    return found.group(1)


def words():
    """words.txt (INT-11.39): the word column of Larsal's list, one word and one LF per line; refuses a
    list whose words do not give FEA-03's check value."""
    with open(WORD_LIST, encoding="ascii") as f:
        text = "".join(line.rstrip("\n").split("\t")[1] + "\n" for line in f)
    if hashlib.sha256(text.encode("ascii")).hexdigest() != WORDS_SHA256 or text.count("\n") != 7776:
        raise SystemExit("build.py: the word list is not FEA-03's (INT-11.39)")
    return text


def manifest(browser, dev=False):
    """The manifest of one browser's build, as a dict."""
    with open(os.path.join(HERE, "manifest.json.in")) as f:
        built = json.loads(f.read().replace("@VERSION@", larsal_version()))
    built.update(BROWSERS[browser])
    if dev:
        built["key"] = DEV_KEY
    return built


def build(browser, out, dev=False):
    """Writes the package into the new folder `out` and returns `out`."""
    os.makedirs(out)  # a new folder: a build never writes over another one
    for name in FILES + LICENCES:
        target = os.path.join(out, name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(os.path.join(HERE, name), target)
    with open(os.path.join(out, "words.txt"), "w", encoding="ascii", newline="\n") as f:
        f.write(words())
    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump(manifest(browser, dev), f, indent=2)
        f.write("\n")
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build one package of Larsal's browser extension.")
    parser.add_argument("browser", choices=sorted(BROWSERS))
    parser.add_argument("out", help="a new folder for the package")
    parser.add_argument("--dev", action="store_true", help="add the development key (unpacked builds only)")
    args = parser.parse_args()
    print(build(args.browser, args.out, args.dev))

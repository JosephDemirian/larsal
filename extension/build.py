"""Builds a package of Larsal's browser extension (INT-11.2, research B2; story E7-S7c).

Python 3 standard library only. Run:

    python3 -I extension/build.py chrome OUT [--dev]

It makes the new folder OUT with the browser's manifest.json, written from
manifest.json.in, and the files the package uses, each copied as written: no
bundler, no minifier, nothing generated but the manifest. --dev adds the
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
# Every file a package ships besides its manifest (INT-11.2: only the files it uses).
FILES = ("background.js", "channel.js", "idkey.js", "routes.js", "wire.js", "_locales/en/messages.json")
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
    for name in FILES:
        target = os.path.join(out, name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(os.path.join(HERE, name), target)
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

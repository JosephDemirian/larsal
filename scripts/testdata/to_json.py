#!/usr/bin/env python3
"""Turn an XML export made by the reference CLI into expected-content JSON.

    to_json.py EXPORT.xml OUT.json

- An element with no attributes and no child elements becomes its text
  ("" when empty).
- Any other element becomes an object: "@name" for each attribute, "#text"
  for the text of an element without child elements, and one key per child
  tag: the child's value when the tag appears once, a list in document order
  when it appears more than once.
- The top level is {root element name: object}.
- Meta/Generator (the creator) is dropped.
- CustomData items are sorted by Key (the CLI writes them in a different
  order each run), and the items the CLI rewrites on every save keep their
  Key but their other fields become "normalized".
- Any key or string that holds a banned word becomes "hex:" + its UTF-8 hex.
  The words are read from the name guard (scripts/check-names.sh), so there
  is one list.
- Keys sorted, two-space indent, UTF-8.
"""
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter

# The name guard's list. No match raises, so a changed guard fails loudly.
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "check-names.sh")) as f:
    BANNED = [bytes.fromhex(h).decode()
              for h in re.search(r'^WORDS_HEX="([0-9a-f ]+)"$', f.read(), re.M).group(1).split()]


def volatile(key):
    """Rewritten on every save: a save time stamp, and a random value (any
    item whose key ends in "_RANDOM_SLUG"; today only on the database)."""
    return key == "_LAST_MODIFIED" or key.endswith("_RANDOM_SLUG")


def normalize(root):
    meta = root.find("Meta")
    meta.remove(meta.find("Generator"))
    for cd in root.iter("CustomData"):
        items = sorted(cd, key=lambda item: item.findtext("Key"))
        for item in items:
            cd.remove(item)
            cd.append(item)
            if volatile(item.findtext("Key")):
                for field in item:
                    if field.tag != "Key":
                        field.text = "normalized"


def convert(el):
    kids = list(el)
    if not el.attrib and not kids:
        return el.text or ""
    obj = {"@" + k: v for k, v in el.attrib.items()}
    if not kids:
        obj["#text"] = el.text or ""
    count = Counter(kid.tag for kid in kids)
    for kid in kids:
        if count[kid.tag] > 1:
            obj.setdefault(kid.tag, []).append(convert(kid))
        else:
            obj[kid.tag] = convert(kid)
    return obj


def clean(x):
    if isinstance(x, dict):
        return {clean(k): clean(v) for k, v in x.items()}
    if isinstance(x, list):
        return [clean(v) for v in x]
    if any(w in x.lower() for w in BANNED):
        return "hex:" + x.encode().hex()
    return x


def main(src, dst):
    root = ET.parse(src).getroot()
    normalize(root)
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(clean({root.tag: convert(root)}), f, indent=2, sort_keys=True,
                  ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main(*sys.argv[1:3])

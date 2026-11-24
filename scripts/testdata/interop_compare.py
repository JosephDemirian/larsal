#!/usr/bin/env python3
"""Compare a vault and Larsal's copy of it through the reference CLI (G4).

    REF_CLI=<reference CLI> [INTEROP_PASSWORD=<password>] \
        interop_compare.py ORIGINAL COPY [KEY FILE [COPY KEY FILE]]

No INTEROP_PASSWORD means "no password" (--no-password); an empty one is the
empty password. COPY KEY FILE is for a copy that needs another key file than
the original (default: the same one).

1. The reference CLI exports both files as XML. Both exports go through the
   normalizing of to_json.py (the creator dropped, custom data sorted, the
   items the CLI rewrites on every save normalized), then through the
   version-form rules below, then are compared field by field: every group,
   entry, history item, string and its protection flag, attachment name,
   custom data item, icon and deleted object.
2. The bytes of every attachment of every current entry are exported from both
   files with the CLI's attachment-export (to a file) and compared. (A version 4 XML
   export holds no attachment bytes, and history attachments cannot be
   exported, so history attachments are compared by name only.)

Version-form rules (Larsal always writes version 4; FMT-16.18):
- Times are compared as seconds since year 1, whatever form the export used
  (text in version 3, base64 in version 4; FMT-12).
- Meta/Binaries (the version 3 attachment pool) is dropped and attachment Ref
  numbers are ignored: both are file-local; step 2 checks the content.
- Meta/SettingsChanged is ignored when the original has none (version 3
  files never do; Larsal writes the open time, FMT-10.10 row 25).

Save rules (true of every save, Larsal's and the reference's):
- The random padding item of CRY-03.7 (custom data key ending in
  "_RANDOM_SLUG") is new on every save, so it is left out of both exports.
  Adding it stamps the vault's "_LAST_MODIFIED" item; a vault custom data
  block that then holds only that item counts as empty (FMT-14.18).
- A time the original file does not hold is filled at load: by the reference
  with the current time, by Larsal with its open time, which Larsal then writes
  (FMT-10.10). Such a time is "now" in both exports; two times that are both
  within 10 minutes of this run's start compare equal.

The CLI runs with HOME set to a temp folder, so it never touches the
reference app's own settings. Prints PASS or FAIL with the differences; exit 1 on any difference.
"""
import base64
import datetime
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import to_json  # noqa: E402

CLI = os.environ["REF_CLI"]
PASSWORD = os.environ.get("INTEROP_PASSWORD")
EPOCH = datetime.datetime(1, 1, 1, tzinfo=datetime.timezone.utc)
NOW = int((datetime.datetime.now(datetime.timezone.utc) - EPOCH).total_seconds())
TIMES = {"CreationTime", "LastModificationTime", "LastAccessTime", "ExpiryTime",
         "LocationChanged", "DeletionTime", "DatabaseNameChanged",
         "DatabaseDescriptionChanged", "DefaultUserNameChanged", "MasterKeyChanged",
         "RecycleBinChanged", "EntryTemplatesGroupChanged", "SettingsChanged"}


def cli(home, args, vault, key):
    # No -q: it also hides the CLI's error text. Prompts go to stderr.
    cmd = [CLI] + args[:1] + (["--no-password"] if PASSWORD is None else [])
    cmd += (["-k", key] if key else []) + [vault] + args[1:]
    r = subprocess.run(cmd, input=((PASSWORD or "") + "\n").encode(), capture_output=True,
                       env=dict(os.environ, HOME=home))
    if r.returncode != 0:
        last = (r.stderr.decode(errors="replace").strip().splitlines() or [""])[-1]
        raise RuntimeError(f"reference CLI {args[0]} failed: {last}")
    return r.stdout


def export_attachment(home, path, name, vault, key):
    out = os.path.join(home, "attachment.out")
    if os.path.exists(out):
        os.remove(out)
    cli(home, ["attachment-export", path, name, out], vault, key)
    with open(out, "rb") as f:
        return f.read()


def seconds(text):
    text = text or ""
    n = None
    try:
        t = datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        n = int((t - EPOCH).total_seconds())
    except ValueError:
        try:
            raw = base64.b64decode(text, validate=True)
            if len(raw) == 8:
                n = int.from_bytes(raw, "little", signed=True)
        except ValueError:
            pass
    if n is None:
        return text
    return "t:now" if abs(n - NOW) <= 600 else "t:%d" % n


def version_form(root, has_settings_changed):
    meta = root.find("Meta")
    for name in ["Binaries"] + ([] if has_settings_changed else ["SettingsChanged"]):
        for el in meta.findall(name):
            meta.remove(el)
    for el in root.iter():
        if el.tag in TIMES:
            el.text = seconds(el.text)
    for cd in meta.findall("CustomData"):
        for item in cd.findall("Item"):
            if (item.findtext("Key") or "").endswith("_RANDOM_SLUG"):
                cd.remove(item)
        if all(item.findtext("Key") == "_LAST_MODIFIED" for item in cd.findall("Item")):
            meta.remove(cd)
    for binary in root.iter("Binary"):
        for value in binary.findall("Value"):
            value.attrib.pop("Ref", None)


def tree(xml_bytes, has_settings_changed):
    root = ET.fromstring(xml_bytes)
    version_form(root, has_settings_changed)
    to_json.normalize(root)
    return to_json.clean(to_json.convert(root))


def diffs(a, b, path, out):
    if type(a) is not type(b):
        out.append(f"{path}: {str(a)[:80]!r} != {str(b)[:80]!r}")
    elif isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}/{k}: only in {'copy' if k not in a else 'original'}")
            else:
                diffs(a[k], b[k], f"{path}/{k}", out)
    elif isinstance(a, list):
        if len(a) != len(b):
            out.append(f"{path}: {len(a)} items != {len(b)} items")
        for i, (x, y) in enumerate(zip(a, b)):
            diffs(x, y, f"{path}[{i}]", out)
    elif a != b:
        out.append(f"{path}: {a[:80]!r} != {b[:80]!r}")


def attachments(root):
    """(entry path, attachment name) of every current entry, history skipped,
    and the entry paths that more than one entry has (the CLI finds an entry
    by its path, so those cannot be exported reliably)."""
    out, seen, shared = [], set(), set()

    def walk(group, parts):
        for entry in group.findall("Entry"):
            title = next((s.findtext("Value") or "" for s in entry.findall("String")
                          if s.findtext("Key") == "Title"), "")
            path = "/".join(parts + [title])
            (shared if path in seen else seen).add(path)
            for b in entry.findall("Binary"):
                out.append((path, b.findtext("Key") or ""))
        for child in group.findall("Group"):
            walk(child, parts + [child.findtext("Name") or ""])

    walk(root.find("Root").find("Group"), [])
    return out, shared


def counts(root):
    entries = sum(1 for g in root.iter("Group") for _ in g.findall("Entry"))
    history = sum(len(h.findall("Entry")) for h in root.iter("History"))
    return entries, history


def main(original, copy, key=None, copy_key=None):
    copy_key = copy_key or key
    label = os.path.basename(original)
    with tempfile.TemporaryDirectory() as home:
        try:
            xa = cli(home, ["export", "-f", "xml"], original, key)
            xb = cli(home, ["export", "-f", "xml"], copy, copy_key)
        except RuntimeError as e:
            print(f"FAIL {label}: {e}")
            return 1
        ra, rb = ET.fromstring(xa), ET.fromstring(xb)
        has_sc = ra.find("Meta").find("SettingsChanged") is not None
        problems = []
        diffs(tree(xa, has_sc), tree(xb, has_sc), "", problems)
        att, shared = attachments(ra)
        if att != attachments(rb)[0]:
            problems.append("current-entry attachment list differs")
        same = skipped = 0
        for path, name in att:
            if path in shared:
                skipped += 1
                continue
            # To a file: the CLI's --stdout output goes through a text
            # conversion that changes binary content.
            try:
                a = export_attachment(home, path, name, original, key)
                b = export_attachment(home, path, name, copy, copy_key)
            except RuntimeError as e:
                problems.append(f"attachment {path!r} {name!r}: {e}")
                continue
            if a != b:
                problems.append(f"attachment {path!r} {name!r}: bytes differ")
            else:
                same += 1
    entries, history = counts(ra)
    if problems:
        print(f"FAIL {label}: {len(problems)} differences")
        for p in problems[:20]:
            print("    " + p)
        return 1
    print(f"PASS {label}: export equal ({entries} entries, {history} history items), "
          f"{same} of {len(att)} attachments byte-equal"
          + (f" ({skipped} on entries whose path is not unique, not exported)" if skipped else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:5]))

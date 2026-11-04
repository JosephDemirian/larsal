#!/usr/bin/env python3
"""Write the demo XML documents and the fixed demo key files.

    make_inputs.py XML_DIR KEY_DIR

XML documents (basic, rich-v3, rich-v4, big) go to XML_DIR, a temp folder:
they are never stored in the project. Fixed key files go to KEY_DIR, and for
every key file a "<name>.raw" twin goes to XML_DIR: the 32 key bytes the
reference CLI should derive from it. Every attachment's bytes also go to
XML_DIR as "att-<name>", and each document's attachment list as
"<document>.attachments", so the script can compare what the CLI reads back.
Same input, same bytes, every run.

Rules of the import (learned from the reference CLI):
- values must not carry Protected="True" (the import has no inner stream);
  ProtectInMemory="True" marks a protected field instead;
- every group and entry needs Times, or the import stamps the current time.
"""
import base64
import hashlib
import os
import sys
import xml.etree.ElementTree as ET

# The format's root element name holds a banned word, so it is built from bytes.
ROOT_TAG = bytes.fromhex("4b65655061737346696c65").decode()

T0 = "2024-01-01T00:00:00Z"
T1 = "2024-02-01T00:00:00Z"
T2 = "2024-03-01T00:00:00Z"
T3 = "2024-04-01T00:00:00Z"

# 1x1 PNG, used as the custom icon.
PNG = ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"
       "+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")

# Attachment pool of the rich documents: name -> bytes. Pool IDs follow this order.
ATTACHMENTS = {"notes.txt": b"demo attachment one\n", "empty.bin": b"",
               "shared.txt": b"shared demo content\n", "bytes.bin": bytes(range(256))}


def b64(data):
    return base64.b64encode(data).decode()


def uid(n):
    return b64(n.to_bytes(16, "big"))


def sub(parent, tag, text=None, **attrs):
    e = ET.SubElement(parent, tag, attrs)
    if text is not None:
        e.text = text
    return e


def times(parent, t=T0, expiry=None):
    ts = sub(parent, "Times")
    sub(ts, "LastModificationTime", t)
    sub(ts, "CreationTime", t)
    sub(ts, "LastAccessTime", t)
    sub(ts, "ExpiryTime", expiry or t)
    sub(ts, "Expires", "True" if expiry else "False")
    sub(ts, "UsageCount", "0")
    sub(ts, "LocationChanged", t)


def group(parent, n, name, t=T0):
    g = sub(parent, "Group")
    sub(g, "UUID", uid(n))
    sub(g, "Name", name)
    times(g, t)
    return g


def entry(parent, n, strings, protect=("Password",), t=T0, expiry=None):
    e = sub(parent, "Entry")
    sub(e, "UUID", uid(n))
    times(e, t, expiry)
    for key, value in strings.items():
        s = sub(e, "String")
        sub(s, "Key", key)
        if key in protect:
            sub(s, "Value", value, ProtectInMemory="True")
        else:
            sub(s, "Value", value)
    return e


def custom_data(parent, key, value):
    cd = sub(parent, "CustomData")
    item = sub(cd, "Item")
    sub(item, "Key", key)
    sub(item, "Value", value)
    sub(item, "LastModificationTime", T0)


def attach(e, name, ref):
    b = sub(e, "Binary")
    sub(b, "Key", name)
    sub(b, "Value", Ref=str(ref))


def document(name, description=""):
    root = ET.Element(ROOT_TAG)
    meta = sub(root, "Meta")
    sub(meta, "DatabaseName", name)
    sub(meta, "DatabaseNameChanged", T0)
    sub(meta, "DatabaseDescription", description)
    sub(meta, "DatabaseDescriptionChanged", T0)
    sub(meta, "DefaultUserName", "")
    sub(meta, "DefaultUserNameChanged", T0)
    sub(meta, "MasterKeyChanged", T0)
    sub(meta, "RecycleBinChanged", T0)
    sub(meta, "EntryTemplatesGroupChanged", T0)
    sub(meta, "SettingsChanged", T0)
    return root, meta, sub(root, "Root")


def basic():
    root, _, r = document("Demo")
    g = group(r, 1, "Demo")
    entry(g, 2, {"Title": "Demo login", "UserName": "demo-user",
                 "Password": "demo-entry-pass-1", "URL": "https://example.com/login",
                 "Notes": "A demo entry."})
    return root


def big(count=10000):
    root, _, r = document("Big demo")
    g = group(r, 1, "Big demo")
    for i in range(1, count + 1):
        entry(g, 100 + i, {"Title": "Entry %05d" % i, "UserName": "user%05d" % i,
                           "Password": "demo-pw-%05d" % i})
    return root


def rich(v4):
    """v4=False keeps to fields a 3.1 file holds, so the reference CLI writes a
    3.1 file and its XML export carries the attachment bytes. v4=True adds
    fields only 4.x holds; the CLI then writes a 4.1 file."""
    root, meta, r = document("Rich demo", "Demo vault with every feature.")
    meta.find("DefaultUserName").text = "demo-user"
    sub(meta, "Color", "#3366CC")
    sub(meta, "MaintenanceHistoryDays", "30")
    sub(meta, "HistoryMaxItems", "10")
    sub(meta, "HistoryMaxSize", "6291456")
    icons = sub(meta, "CustomIcons")
    icon = sub(icons, "Icon")
    sub(icon, "UUID", uid(800))
    sub(icon, "Data", PNG)
    if v4:
        sub(icon, "Name", "Demo icon")
        sub(icon, "LastModificationTime", T0)
    sub(meta, "RecycleBinEnabled", "True")
    sub(meta, "RecycleBinUUID", uid(90))
    pool = sub(meta, "Binaries")
    for i, data in enumerate(ATTACHMENTS.values()):
        sub(pool, "Binary", b64(data) or None, ID=str(i))
    custom_data(meta, "demo-meta-key", "demo-meta-value")

    top = group(r, 1, "Rich demo")
    sub(top, "Notes", "Root group notes.")
    if v4:
        custom_data(top, "demo-group-key", "demo-group-value")

    # Every field and feature on one entry.
    e = entry(top, 10, {
        "Title": "Full demo entry",
        "UserName": "demo-user",
        "Password": "demo-entry-pass-2",
        "URL": "https://example.com/full",
        "Notes": "Line one\nLine two\n\nLine four after an empty line",
        "Demo PIN": "0000",
        "Demo hint": "not protected",
        "otp": "otpauth://totp/Demo:demo-user?secret=JBSWY3DPEHPK3PXP"
               "&period=30&digits=6&issuer=Demo",
        "Empty custom field": "",
        "Spaces": "  leading and trailing  ",
    }, protect=("Password", "Demo PIN", "otp"), expiry="2025-06-30T12:00:00Z")
    sub(e, "IconID", "1")
    sub(e, "CustomIconUUID", uid(800))
    sub(e, "ForegroundColor", "#AA0000")
    sub(e, "BackgroundColor", "#00AA00")
    sub(e, "OverrideURL", "https://override.example.com")
    sub(e, "Tags", "demo;work")
    if v4:
        sub(e, "QualityCheck", "False")
    attach(e, "notes.txt", 0)
    attach(e, "empty.bin", 1)
    attach(e, "bytes.bin", 3)
    at = sub(e, "AutoType")
    sub(at, "Enabled", "True")
    sub(at, "DataTransferObfuscation", "0")
    sub(at, "DefaultSequence", "{USERNAME}{TAB}{PASSWORD}{ENTER}")
    assoc = sub(at, "Association")
    sub(assoc, "Window", "Demo Login - Browser")
    sub(assoc, "KeystrokeSequence", "{PASSWORD}{ENTER}")
    if v4:
        custom_data(e, "demo-entry-key", "demo-entry-value")
    hist = sub(e, "History")
    for n, (t, pw) in enumerate([(T1, "demo-old-pass-1"), (T2, "demo-old-pass-2"),
                                 (T3, "demo-old-pass-3")], 1):
        entry(hist, 10, {"Title": "Full demo entry v%d" % n, "UserName": "demo-user",
                         "Password": pw}, t=t)

    # Two entries share the same attachment content.
    for n in (11, 12):
        e = entry(top, n, {"Title": "Shared attachment %d" % (n - 10), "Password": ""})
        attach(e, "shared.txt", 2)

    entry(top, 13, {"Title": "Grüße · Ελληνικά · Русский · עברית · العربية · हिन्दी"
                             " · 日本語 · 한국어 · 中文 · 🔑",
                    "UserName": "Zoë Ñúñez", "Password": "пароль-密码-🔑"})
    entry(top, 14, {"Title": "Specials <tag> & \"quotes\" 'apos' ]]>",
                    "Password": "p&ss<w>rd\"'", "Notes": "a < b && c > d"})
    entry(top, 15, {"Title": "", "UserName": "", "Password": "", "URL": "", "Notes": ""})

    work = group(top, 2, "Work")
    sub(work, "IconID", "48")
    sub(work, "CustomIconUUID", uid(800))
    if v4:
        sub(work, "Tags", "demo-group-tag")
    sub(work, "IsExpanded", "False")
    sub(work, "DefaultAutoTypeSequence", "{PASSWORD}{ENTER}")
    sub(work, "EnableAutoType", "false")
    sub(work, "EnableSearching", "false")
    servers = group(work, 3, "Servers")
    entry(servers, 20, {"Title": "Server login", "UserName": "admin",
                        "Password": "demo-server-pass"})
    old = group(servers, 4, "Old servers")
    entry(old, 21, {"Title": "Old server", "Password": "demo-old-server-pass"})
    group(top, 5, "Personal")

    bin_ = group(top, 90, "Recycle Bin")
    sub(bin_, "IconID", "43")
    sub(bin_, "EnableAutoType", "false")
    sub(bin_, "EnableSearching", "false")
    e = entry(bin_, 30, {"Title": "Deleted demo entry", "Password": "demo-deleted-pass"})
    if v4:
        sub(e, "PreviousParentGroup", uid(2))
    dg = group(bin_, 91, "Deleted demo group")
    if v4:
        sub(dg, "PreviousParentGroup", uid(1))
    entry(dg, 31, {"Title": "Entry in deleted group", "Password": "demo-deleted-pass-2"})

    gone = sub(r, "DeletedObjects")
    d = sub(gone, "DeletedObject")
    sub(d, "UUID", uid(99))
    sub(d, "DeletionTime", T1)
    return root


def key_files():
    """Fixed demo key files: name -> (file bytes, the 32 key bytes it stands for)."""
    raw = hashlib.sha256(b"demo key binary 32").digest()
    hexkey = hashlib.sha256(b"demo key hex 64").digest()
    hashed = b"This is a demo key file. Any file that is not one of the other kinds is hashed.\n"
    v1 = hashlib.sha256(b"demo key xml v1").digest()
    v2 = hashlib.sha256(b"demo key xml v2").digest()
    words = [v2[i:i + 4].hex().upper() for i in range(0, 32, 4)]
    xml_v1 = ('<?xml version="1.0" encoding="utf-8"?>\n<KeyFile>\n\t<Meta>\n'
              '\t\t<Version>1.00</Version>\n\t</Meta>\n\t<Key>\n'
              '\t\t<Data>%s</Data>\n\t</Key>\n</KeyFile>\n' % b64(v1))
    xml_v2 = ('<?xml version="1.0" encoding="utf-8"?>\n<KeyFile>\n\t<Meta>\n'
              '\t\t<Version>2.0</Version>\n\t</Meta>\n\t<Key>\n'
              '\t\t<Data Hash="%s">\n\t\t\t%s\n\t\t\t%s\n\t\t</Data>\n\t</Key>\n</KeyFile>\n'
              % (hashlib.sha256(v2).digest()[:4].hex().upper(),
                 " ".join(words[:4]), " ".join(words[4:])))
    return {
        "key-binary32.larsalkey": (raw, raw),
        "key-hex64.larsalkey": (hexkey.hex().encode(), hexkey),  # exactly 64 bytes, no newline
        "key-hashed.larsalkey": (hashed, hashlib.sha256(hashed).digest()),
        "key-xml-v1.larsalkey": (xml_v1.encode(), v1),
        "key-xml-v2.larsalkey": (xml_v2.encode(), v2),
    }


def attachment_list(root):
    """One "entry title|attachment name" line per attachment, history left out."""
    lines = []
    for g in root.iter("Group"):
        for e in g.findall("Entry"):
            title = next(s.findtext("Value") for s in e.findall("String")
                         if s.findtext("Key") == "Title")
            lines += ["%s|%s\n" % (title, b.findtext("Key")) for b in e.findall("Binary")]
    return "".join(lines)


def main(xml_dir, key_dir):
    for name, root in (("basic", basic()), ("rich-v3", rich(False)), ("rich-v4", rich(True)),
                       ("big", big())):
        ET.ElementTree(root).write(os.path.join(xml_dir, name + ".xml"),
                                   encoding="utf-8", xml_declaration=True)
        with open(os.path.join(xml_dir, name + ".attachments"), "w", encoding="utf-8") as f:
            f.write(attachment_list(root))
    for name, (data, raw) in key_files().items():
        with open(os.path.join(key_dir, name), "wb") as f:
            f.write(data)
        with open(os.path.join(xml_dir, name + ".raw"), "wb") as f:
            f.write(raw)
    for name, data in ATTACHMENTS.items():
        with open(os.path.join(xml_dir, "att-" + name), "wb") as f:
            f.write(data)


if __name__ == "__main__":
    main(*sys.argv[1:3])

#!/usr/bin/env python3
"""Makes the import samples of the FEA-08 tests (story E4-S13) in
crates/larsal-core/tests/data/, from public standards only: PBKDF2 (RFC 8018)
from hashlib, HKDF-Expand (RFC 5869) and HMAC-SHA-256 from hmac, AES-256
in CBC and ECB mode from the `openssl enc` command, ZIP from Python's
zipfile module. None of it uses Larsal's code, so the tests check Larsal's
readers against independent writers.

Files: the two password-protected JSON exports (part 1); part 2:
demo.1pux, demo.opvault/ (password `demo-opv-pass`), and version 1 files
v1-*.bin with their key files v1-*.larsalkey (passwords below).

Demo data only. Fixed IVs, so a re-run gives the same files.

  python3 -I scripts/testdata/make_import_samples.py

Argon2id: this Mac has no independent Argon2 tool, so K for the Argon2id
sample is given below; it was computed with larsal-crypto's import_argon2id
(RFC 9106 vectors checked in crates/larsal-crypto/src/kdf.rs). Everything
after K (HKDF, HMAC, AES) is computed here.
"""
import base64
import hashlib
import hmac
import json
import pathlib
import subprocess

OUT = pathlib.Path(__file__).resolve().parents[2] / "crates" / "larsal-core" / "tests" / "data"
IV_CHECK = bytes(range(0, 16))
IV_DATA = bytes(range(16, 32))
VALIDATION = b"demo-validation-value"
PLAIN = json.dumps(
    {
        "encrypted": False,
        "folders": [{"id": "f-1", "name": "Demo Folder"}],
        "items": [
            {
                "id": "i-1",
                "folderId": "f-1",
                "type": 1,
                "name": "Encrypted demo login",
                "notes": "demo note",
                "favorite": False,
                "login": {
                    "username": "enc-user",
                    "password": "enc-demo-pw",
                    "totp": None,
                    "uris": [{"match": None, "uri": "https://example.com/"}],
                },
                "creationDate": "2026-01-02T03:04:05.000Z",
                "revisionDate": "2026-02-03T04:05:06.000Z",
            }
        ],
    },
    indent=2,
).encode()
ARGON2_K = bytes.fromhex("596782fbb7cb6466823b8893d23d0b7660d248f38d25ab0dd92a5d1886848746")


def hkdf_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def openssl(args, data):
    return subprocess.run(["openssl", "enc", *args], input=data, capture_output=True, check=True).stdout


def seal(enc, mac, iv, plain):
    ct = openssl(["-aes-256-cbc", "-K", enc.hex(), "-iv", iv.hex()], plain)
    back = openssl(["-d", "-aes-256-cbc", "-K", enc.hex(), "-iv", iv.hex()], ct)
    assert back == plain
    tag = hmac.new(mac, iv + ct, hashlib.sha256).digest()
    b64 = lambda b: base64.b64encode(b).decode()
    return "2." + b64(iv) + "|" + b64(ct) + "|" + b64(tag)


def sample(name, k, header):
    enc, mac = hkdf_expand(k, b"enc", 32), hkdf_expand(k, b"mac", 32)
    doc = dict(header)
    doc["encKeyValidation_DO_NOT_EDIT"] = seal(enc, mac, IV_CHECK, VALIDATION)
    doc["data"] = seal(enc, mac, IV_DATA, PLAIN)
    (OUT / name).write_text(json.dumps(doc, indent=2) + "\n")
    print(name, "K", k.hex(), "enc", enc.hex(), "mac", mac.hex())


OUT.mkdir(parents=True, exist_ok=True)
salt = "c2FsdA=="
sample(
    "bw-encrypted-pbkdf2.json",
    hashlib.pbkdf2_hmac("sha256", b"demo-pass", salt.encode(), 5000, 32),
    {"encrypted": True, "passwordProtected": True, "salt": salt, "kdfType": 0,
     "kdfIterations": 5000, "kdfMemory": None, "kdfParallelism": None},
)
sample(
    "bw-encrypted-argon2.json",
    ARGON2_K,
    {"encrypted": True, "passwordProtected": True, "salt": "ZGVtby1hcmdvbi1zYWx0", "kdfType": 1,
     "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4},
)


# ---------------------------------------------------------------------------
# Part 2: .1pux (FEA-08 section C).

import struct
import zipfile

AVATAR = b"\x89PNG\r\n\x1a\n" + b"demo-avatar"
EXPORT_DATA = {
    "accounts": [
        {
            "attrs": {"accountName": "Demo", "name": "Demo Person"},
            "vaults": [
                {
                    "attrs": {"uuid": "v1", "name": "Personal", "avatar": "avatar.png"},
                    "items": [
                        {
                            "uuid": "i1", "favIndex": 1, "createdAt": 1700000000, "updatedAt": 1700000100,
                            "state": "active",
                            "overview": {
                                "title": "Login", "url": "https://example.com/",
                                "urls": [{"label": "", "url": "https://example.com/"},
                                         {"label": "", "url": "https://example.org/"}],
                                "tags": ["work", 7],
                            },
                            "details": {
                                "loginFields": [
                                    {"value": "demo-user@example.com", "designation": "username"},
                                    {"value": "password", "designation": "Password"},
                                    {"value": "x", "designation": "other"},
                                ],
                                "notesPlain": "Note to self", "password": "not-used",
                                "sections": [
                                    {"title": "", "fields": [
                                        {"title": "one-time password", "id": "t1",
                                         "value": {"totp": "otpauth://totp/demo?secret=JBSWY3DPEHPK3PXP"}},
                                        {"title": "second", "id": "t2", "value": {"totp": "JBSWY3DP"}},
                                        {"title": "", "id": "pin", "value": {"concealed": "1234"}},
                                    ]},
                                    {"title": "More", "fields": [
                                        {"title": "born", "id": "b", "value": {"date": 1700000000}},
                                        {"title": "mail", "id": "e",
                                         "value": {"email": {"email_address": "a@example.com", "provider": None}}},
                                        {"title": "home", "id": "h", "value": {"address": {
                                            "street": "1 Demo St", "city": "Demo City", "state": "DC",
                                            "zip": "00000", "country": "Demoland"}}},
                                        {"title": "until", "id": "m", "value": {"monthYear": 202206}},
                                        {"title": "doc", "id": "f",
                                         "value": {"file": {"documentId": "doc1", "fileName": "note.txt"}}},
                                        {"title": "obj", "id": "o", "value": {"string": {"a": 1}}},
                                        {"title": "zero", "id": "z", "value": {"b": "x", "a": ""}},
                                    ]},
                                ],
                                "documentAttributes": {"documentId": "doc2", "fileName": "note.txt"},
                            },
                        },
                        {"uuid": "i2", "state": "archived", "createdAt": 1600000000, "updatedAt": 1600000000,
                         "overview": {"title": "Login Archived"}, "details": {"password": "uuid005password"}},
                        {"uuid": "i3", "overview": {"title": "No times"},
                         "details": {"documentAttributes": {"documentId": "missing", "fileName": "gone.txt"}}},
                    ],
                },
                {"attrs": {"uuid": "v2", "name": "Shared"}, "items": []},
                {"attrs": {"uuid": "v3", "name": "No items"}},
            ],
        },
        {"attrs": {"name": "Second"},
         "vaults": [{"attrs": {"name": "Other"}, "items": [{"overview": {"title": "dropped"}}]}]},
    ]
}

with zipfile.ZipFile(OUT / "demo.1pux", "w") as z:
    z.writestr("export.attributes", '{"version":3,"description":"demo"}', zipfile.ZIP_STORED)
    z.writestr("export.data", json.dumps(EXPORT_DATA, indent=1), zipfile.ZIP_DEFLATED)
    z.writestr("files/avatar.png", AVATAR, zipfile.ZIP_STORED)
    z.writestr("files/doc1__note.txt", b"attachment one\n", zipfile.ZIP_DEFLATED)
    z.writestr("files/doc2__note.txt", b"attachment two\n", zipfile.ZIP_STORED)
print("demo.1pux")

# ---------------------------------------------------------------------------
# Part 2: OPVault (FEA-08 section D).

OPV_PASSWORD = b"demo-opv-pass"


def cbc_nopad(key, iv, data):
    return openssl(["-aes-256-cbc", "-nopad", "-K", key.hex(), "-iv", iv.hex()], data)


def opdata01(plain, enc, mac, iv):
    p = 16 - (len(plain) % 16)
    head = b"opdata01" + struct.pack("<Q", len(plain)) + iv
    body = head + cbc_nopad(enc, iv, bytes(range(p)) + plain)
    return body + hmac.new(mac, body, hashlib.sha256).digest()


def b64(b):
    return base64.b64encode(b).decode()


def iv_of(n):
    return bytes([n & 0xFF] * 16)


opv_salt = bytes(range(100, 116))
derived = hashlib.pbkdf2_hmac("sha512", OPV_PASSWORD, opv_salt, 1000, 64)
d_enc, d_mac = derived[:32], derived[32:]
master_raw, overview_raw = bytes(range(256)), bytes(range(64, 128))
m = hashlib.sha512(master_raw).digest()
m_enc, m_mac = m[:32], m[32:]
o = hashlib.sha512(overview_raw).digest()
o_enc, o_mac = o[:32], o[32:]


def item_check_value(item):
    msg = b""
    for k in sorted(item):
        if k == "hmac":
            continue
        v = item[k]
        if isinstance(v, bool):
            t = "1" if v else "0"
        elif isinstance(v, int):
            t = str(v)
        else:
            t = v
        msg += k.encode() + t.encode()
    return b64(hmac.new(o_mac, msg, hashlib.sha256).digest())


def item(uuid, n, category, overview, details, k_len=112, trashed=None, tamper=False):
    keys = bytes([(n * 7 + i) & 0xFF for i in range(64)])
    kiv = iv_of(0x40 + n)
    kct = cbc_nopad(m_enc, kiv, keys)
    k = kiv + kct + hmac.new(m_mac, kiv + kct, hashlib.sha256).digest()
    k = k[:k_len]
    it = {
        "uuid": uuid, "category": category, "created": 1600000000 + n, "updated": 1600000100 + n,
        "tx": 1600000200, "k": b64(k),
        "o": b64(opdata01(json.dumps(overview).encode(), o_enc, o_mac, iv_of(0x60 + n))),
        "d": b64(opdata01(json.dumps(details).encode(), keys[:32], keys[32:], iv_of(0x80 + n))),
    }
    if trashed is not None:
        it["trashed"] = trashed
    it["hmac"] = item_check_value(it)
    if tamper:
        it["hmac"] = b64(bytes(32))
    return it, keys


ID1 = "00000000000000000000000000000001"
items = {}
login, login_keys = item(ID1, 1, "001",
    {"title": "Demo login", "url": "https://example.com",
     "URLs": [{"u": "https://example.com"}, {"u": "https://example.org"}], "tags": ["demo"]},
    {"notesPlain": "demo note", "password": "opvault",
     "fields": [{"designation": "username", "value": "demo-user", "name": "username", "type": "T"}],
     "sections": [
         {"title": "", "fields": [
             {"n": "TOTP_a", "k": "concealed", "t": "one-time", "v": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"},
             {"n": "TOTP_b", "k": "concealed", "t": "second", "v": "JBSWY3DP"},
             {"n": "password", "k": "concealed", "t": "", "v": "s3"}]},
         {"title": "Extra", "fields": [
             {"n": "pin", "k": "string", "t": "PIN", "v": "1"},
             {"n": "born", "k": "date", "t": "born", "v": 1700000000},
             {"n": "home", "k": "address", "t": "home", "v": {"street": "1 Demo St", "city": "Demo City"}}]}]})
items[ID1] = login
items["A2"] = item("00000000000000000000000000000002", 2, "002", {"title": "My Credit Card"},
    {"sections": [
        {"title": "", "fields": [{"n": "cardholder", "k": "string", "t": "cardholder name", "v": "Demo Person"}]},
        {"title": "Additional Details", "fields": [{"n": "pin", "k": "concealed", "t": "PIN", "v": "1234"}]}]})[0]
items["A3"] = item("00000000-0000-0000-0000-000000000003", 3, "005", {"title": "Complex Password"},
    {"sections": [{"title": "", "fields": [
        {"n": "TOTP_c", "k": "concealed", "t": "", "v": "otpauth://totp/c?secret=JBSWY3DPEHPK3PXP&digits=8&period=45"}]}]})[0]
items["A4"] = item("00000000000000000000000000000004", 4, "001", {"title": "Expired Login"},
    {"sections": [{"title": "", "fields": [{"n": "expiry", "k": "monthYear", "t": "expiry date", "v": 202506},
                                          {"n": "url", "k": "date", "t": "", "v": 1700000000}]}]})[0]
items["A5"] = item("00000000000000000000000000000005", 5, "005", {"title": "Trashed Password"}, {}, trashed=True)[0]
items["A6"] = item("00000000000000000000000000000006", 6, "001", {"title": "Bad check"}, {}, tamper=True)[0]
items["A7"] = item("00000000000000000000000000000007", 7, "001", {"title": "Short k"}, {}, k_len=111)[0]
items["A8"] = item("0000000000000000000000000000008", 8, "001", {"title": "Short uuid"}, {})[0]
items["A9"] = item("00000000000000000000000000000009", 9, "999", {"title": "Unknown category"}, {})[0]
band5 = {"B1": item("0000000000000000000000000000000B", 11, "003", {"title": "Second band"},
                    {"notesPlain": "in band 5"})[0]}


def attachment_file(meta, icon, content, keys):
    icon_blob = opdata01(icon, keys[:32], keys[32:], iv_of(0xA0)) if icon else b""
    content_blob = opdata01(content, keys[:32], keys[32:], iv_of(0xA1))
    mb = json.dumps(meta).encode()
    return b"OPCLDAT" + bytes([1]) + struct.pack("<HHI", len(mb), 0, len(icon_blob)) + mb + icon_blob + content_blob


opv = OUT / "demo.opvault" / "default"
opv.mkdir(parents=True, exist_ok=True)
for f in opv.iterdir():
    f.unlink()
profile = {
    "lastUpdatedBy": "Demo", "updatedAt": 1587218950, "profileName": "default", "salt": b64(opv_salt),
    "passwordHint": "", "masterKey": b64(opdata01(master_raw, d_enc, d_mac, iv_of(1))), "iterations": 1000,
    "uuid": "E4F7000000000000000000000000A4EE",
    "overviewKey": b64(opdata01(overview_raw, d_enc, d_mac, iv_of(2))), "createdAt": 1587218949,
}
(opv / "profile.js").write_text("var profile=" + json.dumps(profile) + ";\n")
folders = {
    "F0000000000000000000000000000001": {
        "uuid": "F0000000000000000000000000000001", "created": 1587218949, "updated": 1587218949, "tx": 1,
        "overview": b64(opdata01(json.dumps({"title": "F"}).encode(), o_enc, o_mac, iv_of(3)))},
    "F0000000000000000000000000000002": {
        "uuid": "F0000000000000000000000000000002", "created": 1587218949, "updated": 1587218949, "tx": 1,
        "smart": True, "predicate_b64": "AQID",
        "overview": b64(opdata01(json.dumps({"title": "Smart"}).encode(), o_enc, o_mac, iv_of(4)))},
}
(opv / "folders.js").write_text("loadFolders(" + json.dumps(folders) + ");")
(opv / "band_0.js").write_text("ld(" + json.dumps(items) + ");\n")
(opv / "band_5.js").write_text("ld(" + json.dumps(band5) + ");")
att_overview = b64(opdata01(json.dumps({"filename": "attachment.txt"}).encode(), o_enc, o_mac, iv_of(5)))
(opv / (ID1 + "_AAAABBBBCCCCDDDDEEEEFFFF00001111.attachment")).write_bytes(attachment_file(
    {"itemUUID": ID1, "contentsSize": 10, "external": False, "overview": att_overview, "trashed": False},
    b"icon", b"attachment", login_keys))
(opv / (ID1 + "_AAAABBBBCCCCDDDDEEEEFFFF00002222.attachment")).write_bytes(attachment_file(
    {"itemUUID": ID1, "overview": att_overview, "trashed": True}, b"", b"gone", login_keys))
bad = bytearray(attachment_file({"itemUUID": ID1, "trashed": False}, b"", b"damaged", login_keys))
bad[-40] ^= 1
(opv / (ID1 + "_AAAABBBBCCCCDDDDEEEEFFFF00003333.attachment")).write_bytes(bytes(bad))
print("demo.opvault")

# ---------------------------------------------------------------------------
# Part 2: version 1 (FEA-08 section G).


def pack_time(y, mo, d, h, mi, s):
    return bytes([y >> 6, ((y & 63) << 2) | (mo >> 2), ((mo & 3) << 6) | (d << 1) | (h >> 4),
                  ((h & 15) << 4) | (mi >> 2), ((mi & 3) << 6) | s])


def field(kind, data):
    return struct.pack("<HI", kind, len(data)) + data


def txt(s):
    return s.encode() + b"\0"


END = struct.pack("<HI", 0xFFFF, 0)
T0 = pack_time(2012, 1, 2, 3, 4, 5)


def group_rec(gid, name, level, icon=48):
    return (field(1, struct.pack("<I", gid)) + field(2, txt(name)) + field(3, T0) + field(4, T0) + field(5, T0)
            + field(6, bytes([0x2E, 0xDF, 0x39, 0x7E, 0xFB])) + field(7, struct.pack("<I", icon))
            + field(8, struct.pack("<H", level)) + field(9, struct.pack("<I", 0)) + END)


def entry_rec(fid, gid, title, user="", url="", pw="", notes="", icon=0, att=None, expiry=None):
    r = (field(1, bytes([fid] * 16)) + field(2, struct.pack("<I", gid)) + field(3, struct.pack("<I", icon))
         + field(4, txt(title)) + field(5, txt(url)) + field(6, txt(user)) + field(7, txt(pw)) + field(8, txt(notes))
         + field(9, T0) + field(10, T0) + field(11, T0)
         + field(12, expiry or bytes([0x2E, 0xDF, 0x39, 0x7E, 0xFB])))
    if att:
        r += field(13, txt(att[0])) + field(14, att[1])
    else:
        r += field(13, b"\0") + field(14, b"")
    return r + END


V1_PNG = b"\x89PNG\r\n\x1a\n" + b"demo-v1-icon"
TREE_STATE = bytes.fromhex("4B5058 5F47524F55505F545245455F5354415445".replace(" ", ""))
CUSTOM_ICONS = bytes.fromhex("4B50585F435553544F4D5F49434F4E535F34")
groups_v1 = [group_rec(1, "Internet", 0, 1), group_rec(2, "Subgroup 1", 1), group_rec(3, "Unexpanded", 2),
             group_rec(4, "Subgroup 2", 1), group_rec(5, "eMail", 0, 19), group_rec(6, "Backup", 0)]
tree = struct.pack("<I", 3) + struct.pack("<IB", 1, 1) + struct.pack("<IB", 2, 1) + struct.pack("<IB", 3, 0)
icons = (struct.pack("<III", 1, 1, 1) + struct.pack("<I", len(V1_PNG)) + V1_PNG
         + bytes([0x0C] * 16) + struct.pack("<I", 0) + struct.pack("<II", 5, 0))
entries_v1 = [
    entry_rec(0x0A, 1, "Test entry", "I", "http://example.com/", "secretpassword", "Lorem ipsum\ndolor sit amet",
              att=("attachment.txt", b"hello world\n"), expiry=bytes([0x1F, 0x71, 0x52, 0xA8, 0x00])),
    entry_rec(0x0B, 1, ""),
    entry_rec(0x0C, 1, "Custom Icon", "u", "", "p"),
    entry_rec(0x0D, 2, "Auto 1", notes="Auto-Type: {USERNAME}{ENTER}\r\nAuto-Type-Window: W0\nAuto-Type-1: {PASSWORD}\nAuto-Type-Window-1: W1\nlast line"),
    entry_rec(0x0E, 2, "Auto 2", notes="start line\nAuto-Type: x\n\nend line\nsee Auto-Type: y"),
    entry_rec(0x0F, 5, "Mail entry", icon=99),
    entry_rec(0x10, 999, "Lost group"),
    entry_rec(0x11, 0, "Meta-Info", "SYSTEM", "$", "", TREE_STATE.decode(), att=("bin-stream", tree)),
    entry_rec(0x12, 0, "Meta-Info", "SYSTEM", "$", "", CUSTOM_ICONS.decode(), att=("bin-stream", icons)),
]
V1_PLAIN = b"".join(groups_v1) + b"".join(entries_v1)


def aes_kdf(raw, seed, rounds):
    key = raw
    for _ in range(rounds):
        key = openssl(["-aes-256-ecb", "-nopad", "-K", seed.hex()], key)
    return hashlib.sha256(key).digest()


def v1_file(name, raw, rounds=50, flags=2):
    master, iv, seed = bytes(range(16)), bytes(range(16, 32)), bytes(range(32, 64))
    key = hashlib.sha256(master + aes_kdf(raw, seed, rounds)).digest()
    content = openssl(["-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex()], V1_PLAIN)
    header = (bytes([0x03, 0xD9, 0xA2, 0x9A, 0x65, 0xFB, 0x4B, 0xB5]) + struct.pack("<II", flags, 0x00030004)
              + master + iv + struct.pack("<II", len(groups_v1), len(entries_v1))
              + hashlib.sha256(V1_PLAIN).digest() + seed + struct.pack("<I", rounds))
    (OUT / name).write_bytes(header + content)
    print(name, "final key", key.hex()[:16])


sha = lambda b: hashlib.sha256(b).digest()
hex_key = bytes(range(0xA0, 0xC0))
(OUT / "v1-hex.larsalkey").write_text(hex_key.hex())
bin_key = bytes(range(0xC0, 0xE0))
(OUT / "v1-binary.larsalkey").write_bytes(bin_key)
hashed_key = b"demo key file of another length, not 32 or 64 bytes\n"
(OUT / "v1-hashed.larsalkey").write_bytes(hashed_key)
v1_file("v1-aes.bin", sha(b"demo-v1-pass"))
v1_file("v1-keyfile-hex.bin", hex_key)
v1_file("v1-composite.bin", sha(sha(b"demo-v1-pass") + bin_key))
v1_file("v1-keyfile-hashed.bin", sha(hashed_key))
v1_file("v1-cp1252.bin", sha("„password”".encode("cp1252")))

#!/usr/bin/env python3
"""Makes testdata/derived/: demo vectors for the runner in src/tests/vectors.rs.

A second, separate writing of the file format, from its public text and the
RFC text of each primitive, in Python's standard library only and without any
Larsal code. It first proves its own primitives on the RFC vectors (RFC 8439,
RFC 7748, RFC 5869, RFC 7914) and stops if one fails. Every random value is a
hash of the vector's name, so a run gives the same bytes every time.

Each file has the published test file form: `key: value` lines, a blank line,
then the bytes of the file. Demo keys and passphrases only.

Run with -B -I, with the output folder as its one argument.
"""
import base64
import hashlib
import hmac
import struct
import sys
import zlib
from pathlib import Path

# RFC 8439


def rotl32(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = rotl32(s[b] ^ s[c], 7)


def chacha_block(key, counter, nonce):
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state += [counter]
    state += list(struct.unpack("<3I", nonce))
    w = state[:]
    for _ in range(10):
        quarter(w, 0, 4, 8, 12)
        quarter(w, 1, 5, 9, 13)
        quarter(w, 2, 6, 10, 14)
        quarter(w, 3, 7, 11, 15)
        quarter(w, 0, 5, 10, 15)
        quarter(w, 1, 6, 11, 12)
        quarter(w, 2, 7, 8, 13)
        quarter(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(w, state)])


def chacha_xor(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i : i + 64], block))
    return bytes(out)


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    a = 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i : i + 16] + b"\x01", "little")
        a = (a + n) * r % p
    return ((a + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def pad16(b):
    return b"\0" * ((16 - len(b) % 16) % 16)


def aead_seal(key, nonce, plain, aad=b""):
    otk = chacha_block(key, 0, nonce)[:32]
    ct = chacha_xor(key, 1, nonce, plain)
    mac_data = aad + pad16(aad) + ct + pad16(ct)
    mac_data += struct.pack("<QQ", len(aad), len(ct))
    return ct + poly1305(otk, mac_data)


# RFC 7748

P = 2**255 - 19


def x25519(k, u):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    u = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        if swap ^ bit:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def x25519_public(k):
    return x25519(k, (9).to_bytes(32, "little"))


# RFC 5869


def hkdf(ikm, salt, info, n=32):
    prk = hmac.new(salt if salt else b"\0" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


# RFC 7914


def salsa20_8(b):
    x = list(struct.unpack("<16I", b))
    s = x[:]

    def r(a, c, d, n):
        x[a] ^= rotl32((x[c] + x[d]) & 0xFFFFFFFF, n)

    for _ in range(4):
        r(4, 0, 12, 7), r(8, 4, 0, 9), r(12, 8, 4, 13), r(0, 12, 8, 18)
        r(9, 5, 1, 7), r(13, 9, 5, 9), r(1, 13, 9, 13), r(5, 1, 13, 18)
        r(14, 10, 6, 7), r(2, 14, 10, 9), r(6, 2, 14, 13), r(10, 6, 2, 18)
        r(3, 15, 11, 7), r(7, 3, 15, 9), r(11, 7, 3, 13), r(15, 11, 7, 18)
        r(1, 0, 3, 7), r(2, 1, 0, 9), r(3, 2, 1, 13), r(0, 3, 2, 18)
        r(6, 5, 4, 7), r(7, 6, 5, 9), r(4, 7, 6, 13), r(5, 4, 7, 18)
        r(11, 10, 9, 7), r(8, 11, 10, 9), r(9, 8, 11, 13), r(10, 9, 8, 18)
        r(12, 15, 14, 7), r(13, 12, 15, 9), r(14, 13, 12, 13), r(15, 14, 13, 18)
    return struct.pack("<16I", *[(a + c) & 0xFFFFFFFF for a, c in zip(x, s)])


def block_mix(b, r):
    x = b[-64:]
    out = [b""] * (2 * r)
    for i in range(2 * r):
        x = salsa20_8(bytes(a ^ c for a, c in zip(x, b[i * 64 : i * 64 + 64])))
        out[i] = x
    return b"".join(out[0::2]) + b"".join(out[1::2])


def scrypt(password, salt, log_n, r, p, n):
    big = 1 << log_n
    bs = hashlib.pbkdf2_hmac("sha256", password, salt, 1, p * 128 * r)
    res = b""
    for i in range(p):
        x = bs[i * 128 * r : (i + 1) * 128 * r]
        v = []
        for _ in range(big):
            v.append(x)
            x = block_mix(x, r)
        for _ in range(big):
            j = int.from_bytes(x[-64:-56], "little") % big
            x = block_mix(bytes(a ^ c for a, c in zip(x, v[j])), r)
        res += x
    return hashlib.pbkdf2_hmac("sha256", password, res, 1, n)


def prove_primitives():
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    want = (
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
        "1ae10b594f09e26a7e902ecbd0600691"
    )
    assert aead_seal(key, nonce, pt, aad).hex() == want, "RFC 8439 2.8.2"
    k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    want = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    assert x25519(k, u).hex() == want, "RFC 7748 5.2"
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    want = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert x25519_public(a).hex() == want, "RFC 7748 6.1 public"
    want = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert x25519(a, x25519_public(b)).hex() == want, "RFC 7748 6.1 shared"
    got = hkdf(b"\x0b" * 22, bytes.fromhex("000102030405060708090a0b0c"), bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    want = (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert got.hex() == want, "RFC 5869 A.1"
    want = (
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
        "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
    )
    assert scrypt(b"", b"", 4, 1, 1, 64).hex() == want, "RFC 7914 N=16"
    want = (
        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162"
        "2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
    )
    assert scrypt(b"password", b"NaCl", 10, 8, 16, 64).hex() == want, "RFC 7914 N=1024"


# The Bech32 of BIP-173, for the demo keys.

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (b >> i) & 1 else 0
    return chk


def bech32_encode(hrp, data, constant=1, pad_bits=0):
    bits, acc, five = 0, 0, []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            five.append((acc >> bits) & 31)
    if bits:
        five.append(((acc << (5 - bits)) & 31) | (pad_bits & ((1 << (5 - bits)) - 1)))
    hrp = hrp.lower()
    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    pm = bech32_polymod(expand + five + [0] * 6) ^ constant
    check = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in five + check)


# The file format.

VERSION = b"age-encryption.org/v1\n"
X_LABEL = b"age-encryption.org/v1/X25519"
S_LABEL = b"age-encryption.org/v1/scrypt"
PASSPHRASE = "demo passphrase"
ID_A = bytes(range(1, 33))
ID_B = bytes(range(33, 65))
PUB_A = x25519_public(ID_A)
PUB_B = x25519_public(ID_B)
TEXT_A = bech32_encode("AGE-SECRET-KEY-", ID_A).upper()
TEXT_B = bech32_encode("AGE-SECRET-KEY-", ID_B).upper()
PLAIN = b"demo payload for the file vectors\n"
CHUNK = 65536
ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64(b):
    return base64.b64encode(b).rstrip(b"=")


def rnd(name, what, n):
    return hashlib.sha256(name.encode() + b"/" + what).digest()[:n]


def wrapped_lines(body):
    t = b64(body)
    lines = [t[i : i + 64] for i in range(0, len(t), 64)]
    if not lines or len(lines[-1]) == 64:
        lines.append(b"")
    return b"\n".join(lines) + b"\n"


def stanza(args, body):
    return b"-> " + b" ".join(args) + b"\n" + wrapped_lines(body)


def x_stanza(name, tag, pub, file_key):
    eph = rnd(name, b"eph" + tag, 32)
    share = x25519_public(eph)
    wrap = hkdf(x25519(eph, pub), share + pub, X_LABEL)
    return stanza([b"X25519", b64(share)], aead_seal(wrap, b"\0" * 12, file_key))


def s_stanza(name, file_key, log_n=4, passphrase=PASSPHRASE, tag=b""):
    salt = rnd(name, b"salt" + tag, 16)
    wrap = kdf(passphrase.encode(), S_LABEL + salt, log_n)
    return stanza([b"scrypt", b64(salt), str(log_n).encode()], aead_seal(wrap, b"\0" * 12, file_key))


def kdf(password, salt, log_n):
    return scrypt(password, salt, log_n, 8, 1, 32)


def seal_header(file_key, stanzas):
    head = VERSION + stanzas + b"---"
    tag = hmac.new(hkdf(file_key, b"", b"header"), head, hashlib.sha256).digest()
    return head + b" " + b64(tag) + b"\n"


def chunk(key, counter, last, plain):
    nonce = b"\0" * 3 + counter.to_bytes(8, "big") + (b"\x01" if last else b"\0")
    return aead_seal(key, nonce, plain)


def chunks_of(plain):
    if not plain:
        return [b""]
    return [plain[i : i + CHUNK] for i in range(0, len(plain), CHUNK)]


def payload(file_key, nonce, plain):
    key = hkdf(file_key, nonce, b"payload")
    parts = chunks_of(plain)
    return nonce + b"".join(chunk(key, i, i == len(parts) - 1, p) for i, p in enumerate(parts))


def armor(data, eol=b"\n", before=b"", after=b""):
    t = base64.b64encode(data)
    lines = [t[i : i + 64] for i in range(0, len(t), 64)]
    body = [b"-----BEGIN AGE ENCRYPTED FILE-----"] + lines + [b"-----END AGE ENCRYPTED FILE-----"]
    return before + eol.join(body) + eol + after


class Out:
    def __init__(self, folder):
        self.folder = folder
        self.count = 0

    def put(self, name, expect, data, plain=None, file_key=None, identity=(TEXT_A,), passphrase=None, armored=False, compressed=False, comment=None):
        meta = ["expect: " + expect]
        if plain is not None:
            meta.append("payload: " + hashlib.sha256(plain).hexdigest())
        if file_key is not None:
            meta.append("file key: " + file_key.hex())
        if passphrase is not None:
            meta.append("passphrase: " + passphrase)
        else:
            meta += ["identity: " + t for t in identity]
        if armored:
            meta.append("armored: yes")
        if compressed:
            meta.append("compressed: zlib")
            data = zlib.compress(data, 9)
        if comment:
            meta.append("comment: " + comment)
        (self.folder / name).write_bytes("\n".join(meta).encode() + b"\n\n" + data)
        self.count += 1


def fk(name):
    return rnd(name, b"file key", 16)


def nonce(name):
    return rnd(name, b"nonce", 16)


def x_file(name, plain=PLAIN, extra=b""):
    key = fk(name)
    head = seal_header(key, x_stanza(name, b"", PUB_A, key) + extra)
    return head + payload(key, nonce(name), plain)


def successes(o):
    n = "x25519_basic"
    o.put(n, "success", x_file(n), PLAIN, fk(n))
    n = "x25519_two_recipients"
    k = fk(n)
    o.put(n, "success", seal_header(k, x_stanza(n, b"b", PUB_B, k) + x_stanza(n, b"a", PUB_A, k)) + payload(k, nonce(n), PLAIN), PLAIN, k)
    n = "x25519_second_identity"
    o.put(n, "success", x_file(n), PLAIN, fk(n), identity=(TEXT_B, TEXT_A))
    n = "x25519_unknown_stanza"
    o.put(n, "success", x_file(n, extra=stanza([b"demo-grease", b"!\"#$", b"~"], rnd(n, b"g", 20))), PLAIN, fk(n))
    n = "x25519_unknown_long_body"
    o.put(n, "success", x_file(n, extra=stanza([b"demo"], rnd(n, b"g", 32) * 5)), PLAIN, fk(n))
    n = "x25519_unknown_body_full_line"
    o.put(n, "success", x_file(n, extra=stanza([b"demo"], b"\7" * 48)), PLAIN, fk(n))
    n = "x25519_unknown_empty_body"
    o.put(n, "success", x_file(n, extra=stanza([b"demo"], b"")), PLAIN, fk(n))
    n = "x25519_lowercase_type_is_unknown"
    o.put(n, "success", x_file(n, extra=stanza([b"x25519", b"demo"], b"\7" * 32)), PLAIN, fk(n))
    n = "scrypt_basic"
    k = fk(n)
    o.put(n, "success", seal_header(k, s_stanza(n, k)) + payload(k, nonce(n), PLAIN), PLAIN, k, passphrase=PASSPHRASE)
    for size in (0, 1, 65535, 65536, 65537, 131072):
        n = "payload_%d" % size
        plain = bytes(i % 251 for i in range(size))
        o.put(n, "success", x_file(n, plain), plain, fk(n))
    n = "armor_basic"
    o.put(n, "success", armor(x_file(n)), PLAIN, fk(n), armored=True)
    n = "armor_crlf"
    o.put(n, "success", armor(x_file(n), b"\r\n"), PLAIN, fk(n), armored=True)
    n = "armor_outer_space"
    o.put(n, "success", armor(x_file(n), before=b" \t\r\n", after=b"\n \t\r\n"), PLAIN, fk(n), armored=True)
    n = "armor_space_at_limit"
    o.put(n, "success", armor(x_file(n), before=b" " * 16384, after=b"\n" * 16384), PLAIN, fk(n), armored=True)
    n = "armor_no_final_eol"
    o.put(n, "success", armor(x_file(n))[:-1], PLAIN, fk(n), armored=True)
    n = "armor_full_last_line"
    data = x_file(n, PLAIN + b"." * (48 - (len(x_file(n)) % 48)))
    assert len(data) % 48 == 0
    plain = PLAIN + b"." * (48 - (len(x_file(n)) % 48))
    o.put(n, "success", armor(data), plain, fk(n), armored=True)
    n = "compressed_zlib"
    o.put(n, "success", x_file(n), PLAIN, fk(n), compressed=True)


def header_failures(o):
    def bad(name, text, **kw):
        o.put(name, "header failure", text, **kw)

    def x(name, mutate):
        return mutate(x_file(name))

    n = "version_wrong"
    bad(n, x(n, lambda d: d.replace(b"v1\n", b"v2\n", 1)))
    n = "version_crlf"
    bad(n, x(n, lambda d: d.replace(b"v1\n", b"v1\r\n", 1)))
    n = "version_only"
    bad(n, VERSION)
    bad("empty_file", b"")
    n = "stanza_crlf"
    bad(n, x(n, lambda d: d.replace(b"\n", b"\r\n", 2).replace(b"v1\r\n", b"v1\n", 1)))

    def with_stanza(name, raw):
        key = fk(name)
        return seal_header(key, x_stanza(name, b"", PUB_A, key) + raw) + payload(key, nonce(name), PLAIN)

    for name, raw in [
        ("stanza_no_type", b"->\n\n"),
        ("stanza_empty_type", b"-> \n\n"),
        ("stanza_empty_argument", b"-> demo  arg\n\n"),
        ("stanza_trailing_space", b"-> demo \n\n"),
        ("stanza_bad_character", b"-> demo \x7f\n\n"),
        ("stanza_bad_start", b"-* demo\n\n"),
        ("stanza_missing_body", b"-> demo\n"),
        ("stanza_padded_body", b"-> demo\nQQ==\n"),
        ("stanza_noncanonical_body", b"-> demo\nQR\n"),
        ("stanza_long_line", b"-> demo\n" + b"A" * 68 + b"\n\n"),
        ("stanza_missing_final_line", b"-> demo\n" + b"A" * 64 + b"\n"),
        ("stanza_space_in_body", b"-> demo\nAA AA\n"),
    ]:
        bad(name, with_stanza(name, raw))

    n = "footer_missing"
    bad(n, x(n, lambda d: d[: d.index(b"---")]))
    n = "footer_no_space"
    bad(n, x(n, lambda d: d.replace(b"--- ", b"---", 1)))
    n = "footer_two_spaces"
    bad(n, x(n, lambda d: d.replace(b"--- ", b"---  ", 1)))
    n = "footer_trailing_space"
    d = x_file(n)
    at = d.index(b"\n", d.index(b"---"))
    bad(n, d[:at] + b" " + d[at:])
    n = "footer_short_mac"
    d = x_file(n)
    at = d.index(b"\n", d.index(b"---"))
    bad(n, d[: at - 1] + d[at:])
    n = "footer_noncanonical_mac"
    d = x_file(n)
    at = d.index(b"\n", d.index(b"---"))
    last = bytes([ALPHABET[ALPHABET.index(d[at - 1]) | 1]])
    bad(n, d[: at - 1] + last + d[at:])

    def x_shape(name, args, body):
        key = fk(name)
        return seal_header(key, stanza([b"X25519"] + args, body)) + payload(key, nonce(name), PLAIN)

    share = b64(x25519_public(rnd("shape", b"e", 32)))
    body = rnd("shape", b"b", 32)
    bad("x25519_extra_argument", x_shape("x25519_extra_argument", [share, b"extra"], body))
    bad("x25519_no_share", x_shape("x25519_no_share", [], body))
    bad("x25519_short_share", x_shape("x25519_short_share", [b64(b"\7" * 31)], body))
    bad("x25519_long_share", x_shape("x25519_long_share", [b64(b"\7" * 33)], body))
    bad("x25519_noncanonical_share", x_shape("x25519_noncanonical_share", [share[:-1] + b"B"], body))
    bad("x25519_body_31", x_shape("x25519_body_31", [share], body[:31]))
    bad("x25519_body_33", x_shape("x25519_body_33", [share], body + b"\0"))
    n = "x25519_low_order_share"
    bad(n, x_shape(n, [b64(b"\0" * 32)], body))

    n = "scrypt_and_x25519"
    k = fk(n)
    both = s_stanza(n, k) + x_stanza(n, b"", PUB_A, k)
    bad(n, seal_header(k, both) + payload(k, nonce(n), PLAIN))
    bad(n + "_with_passphrase", seal_header(k, both) + payload(k, nonce(n), PLAIN), passphrase=PASSPHRASE)
    n = "scrypt_two_stanzas"
    k = fk(n)
    two = s_stanza(n, k) + s_stanza(n, k, tag=b"2")
    bad(n, seal_header(k, two) + payload(k, nonce(n), PLAIN), passphrase=PASSPHRASE)
    n = "scrypt_and_unknown"
    k = fk(n)
    bad(n, seal_header(k, s_stanza(n, k) + stanza([b"demo"], b"")) + payload(k, nonce(n), PLAIN), passphrase=PASSPHRASE)

    def s_shape(name, args, body_bytes=None):
        key = fk(name)
        body_bytes = rnd(name, b"b", 32) if body_bytes is None else body_bytes
        return seal_header(key, stanza([b"scrypt"] + args, body_bytes)) + payload(key, nonce(name), PLAIN)

    salt = b64(b"\7" * 16)
    for name, args in [
        ("scrypt_no_salt", []),
        ("scrypt_no_cost", [salt]),
        ("scrypt_extra_argument", [salt, b"4", b"extra"]),
        ("scrypt_short_salt", [b64(b"\7" * 15), b"4"]),
        ("scrypt_long_salt", [b64(b"\7" * 17), b"4"]),
        ("scrypt_noncanonical_salt", [salt[:-1] + b"R", b"4"]),
        ("scrypt_cost_zero", [salt, b"0"]),
        ("scrypt_cost_leading_zero", [salt, b"04"]),
        ("scrypt_cost_plus", [salt, b"+4"]),
        ("scrypt_cost_negative", [salt, b"-4"]),
        ("scrypt_cost_hex", [salt, b"0x4"]),
        ("scrypt_cost_garbage", [salt, b"4x"]),
        ("scrypt_cost_21", [salt, b"21"]),
        ("scrypt_cost_huge", [salt, b"340282366920938463463374607431768211456"]),
    ]:
        bad(name, s_shape(name, args), passphrase=PASSPHRASE)
    bad("scrypt_body_31", s_shape("scrypt_body_31", [salt, b"4"], b"\7" * 31), passphrase=PASSPHRASE)
    bad("scrypt_body_33", s_shape("scrypt_body_33", [salt, b"4"], b"\7" * 33), passphrase=PASSPHRASE)


def mac_failures(o):
    n = "mac_flip"
    d = x_file(n)
    at = d.index(b"--- ") + 4
    flip = b"B" if d[at] != ord("B") else b"C"
    o.put(n, "HMAC failure", d[:at] + flip + d[at + 1 :])
    n = "mac_covers_unknown_stanza"
    d = x_file(n, extra=stanza([b"demo"], b"\7" * 8))
    o.put(n, "HMAC failure", d.replace(b"-> demo\n", b"-> dema\n", 1))
    n = "mac_covers_version_footer_dashes"
    k = fk(n)
    head = VERSION + x_stanza(n, b"", PUB_A, k) + b"--- "
    wrong = hmac.new(hkdf(k, b"", b"other"), head[:-1], hashlib.sha256).digest()
    o.put(n, "HMAC failure", head + b64(wrong) + b"\n" + payload(k, nonce(n), PLAIN))
    n = "mac_over_the_space_too"
    k = fk(n)
    head = VERSION + x_stanza(n, b"", PUB_A, k) + b"--- "
    wrong = hmac.new(hkdf(k, b"", b"header"), head, hashlib.sha256).digest()
    o.put(n, "HMAC failure", head + b64(wrong) + b"\n" + payload(k, nonce(n), PLAIN))


def no_match(o):
    n = "x25519_wrong_identity"
    o.put(n, "no match", x_file(n), identity=(TEXT_B,))
    n = "x25519_bad_tag"
    k = fk(n)
    eph = rnd(n, b"eph", 32)
    share = x25519_public(eph)
    wrap = hkdf(x25519(eph, PUB_A), share + PUB_A, X_LABEL)
    body = bytearray(aead_seal(wrap, b"\0" * 12, k))
    body[31] ^= 1
    o.put(n, "no match", seal_header(k, stanza([b"X25519", b64(share)], bytes(body))) + payload(k, nonce(n), PLAIN))
    n = "x25519_wrong_info_label"
    k = fk(n)
    eph = rnd(n, b"eph", 32)
    share = x25519_public(eph)
    wrap = hkdf(x25519(eph, PUB_A), share + PUB_A, b"demo other label")
    o.put(n, "no match", seal_header(k, stanza([b"X25519", b64(share)], aead_seal(wrap, b"\0" * 12, k))) + payload(k, nonce(n), PLAIN))
    n = "unknown_only"
    k = fk(n)
    o.put(n, "no match", seal_header(k, stanza([b"demo"], b"\7" * 32)) + payload(k, nonce(n), PLAIN))
    n = "native_pq_only"
    k = fk(n)
    o.put(n, "success", seal_header(k, stanza([b"mlkem768x25519", b"demo"], b"\7" * 32)) + payload(k, nonce(n), PLAIN), PLAIN, k, comment="An unsupported recipient type: refused, never an interoperability pass.")
    n = "scrypt_wrong_passphrase"
    k = fk(n)
    o.put(n, "no match", seal_header(k, s_stanza(n, k)) + payload(k, nonce(n), PLAIN), passphrase="other demo passphrase")
    n = "scrypt_with_identity"
    k = fk(n)
    o.put(n, "no match", seal_header(k, s_stanza(n, k)) + payload(k, nonce(n), PLAIN))
    n = "x25519_with_passphrase"
    o.put(n, "no match", x_file(n), passphrase=PASSPHRASE)


def payload_failures(o):
    def head(name):
        k = fk(name)
        return k, seal_header(k, x_stanza(name, b"", PUB_A, k)), nonce(name), hkdf(k, nonce(name), b"payload")

    full = bytes(i % 251 for i in range(CHUNK))

    def put(name, build, prefix=b""):
        k, h, no, key = head(name)
        o.put(name, "payload failure", h + build(no, key), prefix, k)

    # A missing or short nonce is the header stage, as the published files say.
    for name, cut in (("nonce_missing", 0), ("nonce_short", 15)):
        k, h, no, key = head(name)
        o.put(name, "header failure", h + no[:cut], None, k)
    put("no_chunks", lambda no, key: no)
    put("chunk_shorter_than_tag", lambda no, key: no + b"\7" * 15)
    put("bad_tag_only_chunk", lambda no, key: no + chunk(key, 0, True, PLAIN)[:-1] + b"\7")
    put("bad_tag_second_chunk", lambda no, key: no + chunk(key, 0, False, full) + chunk(key, 1, True, PLAIN)[:-1] + b"\7", full)
    put("no_final_flag", lambda no, key: no + chunk(key, 0, False, PLAIN))
    # A full chunk that opens only under the other flag is counted in the hash.
    put("no_final_flag_full", lambda no, key: no + chunk(key, 0, False, full), full)
    put("no_final_flag_two_chunks", lambda no, key: no + chunk(key, 0, False, full) + chunk(key, 1, False, PLAIN), full)
    put("empty_payload_no_flag", lambda no, key: no + chunk(key, 0, False, b""))
    put("empty_last_chunk", lambda no, key: no + chunk(key, 0, False, full) + chunk(key, 1, True, b""), full)
    put("short_chunk_with_more_after", lambda no, key: no + chunk(key, 0, False, PLAIN) + chunk(key, 1, True, PLAIN))
    put("final_flag_then_more", lambda no, key: no + chunk(key, 0, True, full) + chunk(key, 1, True, PLAIN), full)
    put("trailing_one_byte", lambda no, key: no + chunk(key, 0, True, PLAIN) + b"\0")
    put("trailing_tag_size", lambda no, key: no + chunk(key, 0, True, PLAIN) + b"\0" * 16)
    put("trailing_long", lambda no, key: no + chunk(key, 0, True, PLAIN) + b"\0" * 70000)
    put("trailing_after_full_last", lambda no, key: no + chunk(key, 0, True, full) + b"\0", full)
    put("swapped_chunks", lambda no, key: no + chunk(key, 1, False, full) + chunk(key, 0, False, full) + chunk(key, 2, True, PLAIN))
    put("repeated_chunk", lambda no, key: no + chunk(key, 0, False, full) + chunk(key, 0, False, full) + chunk(key, 1, True, PLAIN), full)
    put("skipped_counter", lambda no, key: no + chunk(key, 0, False, full) + chunk(key, 2, True, PLAIN), full)
    other = hkdf(fk("other file"), nonce("other file"), b"payload")
    put("cross_file_chunk", lambda no, key: no + chunk(key, 0, False, full) + chunk(other, 1, True, PLAIN), full)
    n = "second_file_appended"
    k, h, no, key = head(n)
    o.put(n, "payload failure", h + no + chunk(key, 0, True, PLAIN) + x_file("another file"), b"", k)


def armor_failures(o):
    def bad(name, text):
        o.put(name, "armor failure", text, armored=True)

    def good(name):
        return armor(x_file(name))

    n = "armor_no_end"
    bad(n, good(n).split(b"-----END")[0])
    n = "armor_no_begin_after_space"
    bad(n, b"\n" + good(n).split(b"\n", 1)[1])
    n = "armor_junk_after_space"
    bad(n, b"\njunk\n" + good(n))
    n = "armor_junk_after_end"
    bad(n, good(n) + b"junk\n")
    n = "armor_second_block"
    bad(n, good(n) + good(n))
    n = "armor_blank_interior"
    d = good(n)
    bad(n, d.replace(b"-----\n", b"-----\n\n", 1))
    n = "armor_blank_before_end"
    d = good(n)
    bad(n, d.replace(b"\n-----END", b"\n\n-----END", 1))
    n = "armor_short_interior_line"
    d = good(n).split(b"\n")
    d[1] = d[1][:60] + b"\n" + d[1][60:]
    bad(n, b"\n".join(d))
    n = "armor_long_line"
    d = good(n).split(b"\n")
    d[1:3] = [d[1] + d[2][:4], d[2][4:]]
    bad(n, b"\n".join(d))
    def padded(name, pad):
        # 1 byte over a group gives two "=", 2 bytes one "=".
        for extra in range(3):
            plain = PLAIN + b"." * extra
            data = x_file(name, plain)
            if len(data) % 3 == (1 if pad == 2 else 2):
                return armor(data)
        raise AssertionError("no length gives this padding")

    n = "armor_no_padding"
    bad(n, padded(n, 1).replace(b"=", b""))
    n = "armor_too_much_padding"
    bad(n, padded(n, 1).replace(b"=\n", b"==\n"))
    n = "armor_noncanonical_body"
    t = padded(n, 2)
    at = t.index(b"==\n") - 1
    bad(n, t[:at] + bytes([ALPHABET[ALPHABET.index(t[at]) ^ 1]]) + t[at + 1 :])
    n = "armor_lowercase_label"
    bad(n, good(n).replace(b"AGE ENCRYPTED", b"age encrypted"))
    n = "armor_wrong_label"
    bad(n, good(n).replace(b"AGE ENCRYPTED", b"DEMO ENCRYPTED"))
    n = "armor_space_in_body"
    d = good(n).split(b"\n")
    d[1] = b" " + d[1]
    bad(n, b"\n".join(d))
    n = "armor_space_at_line_end"
    d = good(n).split(b"\n")
    d[1] += b" "
    bad(n, b"\n".join(d))
    n = "armor_bad_character"
    d = good(n).split(b"\n")
    d[1] = b"*" + d[1][1:]
    bad(n, b"\n".join(d))
    # An armor with nothing in it is good armor round an empty file: the published
    # armor_empty row says so.
    o.put("armor_empty_body", "header failure", b"-----BEGIN AGE ENCRYPTED FILE-----\n-----END AGE ENCRYPTED FILE-----\n", armored=True)
    n = "armor_too_much_space_before"
    bad(n, b" " * 16385 + good(n))
    n = "armor_too_much_space_after"
    bad(n, good(n) + b"\n" * 16385)
    n = "armor_only_space"
    bad(n, b"   \n")
    o.put("armor_junk_before_begin", "armor failure", b"junk\n" + good("armor_junk_before_begin"), armored=True)


def key_table():
    bech32m = 0x2BC830A3
    return [
        ("recipient lower", bech32_encode("age", PUB_A)),
        ("recipient upper", bech32_encode("age", PUB_A).upper()),
        ("recipient bech32m", bech32_encode("age", PUB_A, bech32m)),
        ("recipient 31 bytes", bech32_encode("age", PUB_A[:31])),
        ("recipient 33 bytes", bech32_encode("age", PUB_A + b"\0")),
        ("recipient wrong prefix", bech32_encode("demo", PUB_A)),
        ("recipient nonzero padding", bech32_encode("age", PUB_A, 1, 1)),
        ("identity upper", TEXT_A),
        ("identity lower", TEXT_A.lower()),
        ("identity bech32m", bech32_encode("AGE-SECRET-KEY-", ID_A, bech32m).upper()),
        ("identity 33 bytes", bech32_encode("AGE-SECRET-KEY-", ID_A + b"\0").upper()),
        ("identity b", TEXT_B),
        ("demo nonzero padding", bech32_encode("demo-", b"\x07" * 32, 1, 1)),
        ("demo valid", bech32_encode("demo-", b"\x07" * 32)),
    ]


def main():
    prove_primitives()
    for name, text in key_table():
        print(name + ": " + text)
    folder = Path(sys.argv[1])
    folder.mkdir(parents=True, exist_ok=True)
    o = Out(folder)
    successes(o)
    header_failures(o)
    mac_failures(o)
    no_match(o)
    payload_failures(o)
    armor_failures(o)
    print("wrote", o.count, "vectors; primitives proven on RFC 8439, 7748, 5869, 7914")


if __name__ == "__main__":
    main()

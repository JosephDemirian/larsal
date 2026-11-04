#!/bin/sh
# Name guard (story E0-S3, check AT-J06).
# Fails when a banned word appears in a file or folder name, a symlink target,
# a zip member name, an extended attribute, or the bytes of any file. The words
# are stored as hex so this file itself stays clean. Every file is read in full
# and matched as:
#   - raw bytes with NUL bytes and Latin-1 soft hyphens removed (binary files;
#     ASCII in UTF-16/32; 8-bit text),
#   - UTF-8 text, UTF-16 text at both alignments, and UTF-32 text at every
#     alignment when the file holds a NUL,
#   - that text again as it is shown: HTML entities, HTML tags, Markdown
#     emphasis and code marks (* ` ~) and terminal escape codes and control
#     strings (7-bit and 8-bit forms, read as a VT parser reads them) removed,
#     and \u{..} \u.... \x.. \ooo \N{name} %xx escapes decoded,
#   - when it holds a backspace or a lone carriage return, that shown text
#     also drawn as a terminal draws it (the cursor moves back, text overwrites,
#     controls that take no column are dropped),
# each after NFKD, case folding, deleting invisible characters (format,
# combining and control characters, and spaces narrower than a quarter em) and
# mapping lookalikes (Cyrillic and Greek letters; Latin small capitals, letters
# with a hook, stroke or other mark, dotless and script letters, alpha, iota).
# gzip, bzip2, xz and zip contents (also zip data after a prefix), zlib streams
# anywhere in a file, a file that is one raw deflate stream, base64 data: URI
# payloads (spaces and line breaks allowed) and base64 runs of 40 or more
# characters (also wrapped over lines) are unpacked, one at a time and each at
# most 16 MB, and matched the same way. Anything it cannot read or unpack
# fails the guard: so do zstd data, *.br files and WOFF2 fonts (Brotli, which
# python3 cannot unpack) other than the fonts allowed below.
# File names are printed with control characters escaped (\x1b), as ls -b does.
# Skips only the root build and git folders (real folders, not files or
# links): ./target, ./fuzz/target, ./.git.
# Random bytes give false hits (a 4-letter word about once per 25 MB), so:
#  - a *.appvault file that starts with the vault signature (03 D9 A2 9A
#    67 FB 4B B5, spec FMT-01) is encrypted: its name is checked, its bytes
#    are not, and the summary counts it as name-only. Any other *.appvault
#    file is matched like every other file.
#  - a PNG is matched chunk by chunk (type and data; zTXt, iCCP and
#    compressed iTXt also inflated), except the pixel data (IDAT), which must
#    be one clean zlib stream. A JPEG is matched segment by segment, except
#    the entropy-coded data after each SOS. An image that does not parse
#    cleanly (bad signature, length, CRC or zlib stream, data after the end)
#    is matched in full.
# The default root is the folder above this script after links are resolved;
# it must hold AGENTS.md. A scan that reads 0 files fails.
# Python runs with an empty environment (env -i), so DEVELOPER_DIR, PYTHON*
# and the like cannot swap the interpreter or its modules. Run the guard
# through its #!/bin/sh line: under an explicit "bash scripts/check-names.sh"
# a hostile BASH_ENV or exported function runs before this file can act.
# Known limits: raw deflate data that does not start the file (outside zip
# members), zlib streams with an unusual header byte, a Brotli stream outside
# a WOFF2 font or *.br file (Brotli has no magic number), and other compressed
# streams inside other formats are not unpacked; compressed formats other than
# gzip, bzip2, xz, zip, zlib and raw deflate (legacy .lzma, 7z, lz4, lzfse, .Z)
# are matched raw, not failed (LD-236); base64 wrapped at a width under 40 or
# not a multiple of 4, or with escaped line breaks or slashes (as JSON writes
# them), is not joined over lines, a percent-encoded data: URI payload is not
# decoded, and base64url (- and _) is not decoded; lookalikes outside the sets
# above are not mapped;
# words drawn as pixels or hidden in PNG pixel data or JPEG entropy-coded data
# are not found; APNG frame data (fdAT) is matched raw; whatever follows the
# vault signature in a *.appvault file is not matched.
# Known limits of the terminal view (LD-229): a raw single C1 byte in non-UTF-8
# text, a C1 code point inside a 7-bit code (terminals disagree on it), a tab
# (one column) and a carriage return inside a file name are not followed as a
# terminal would, and cursor moves other than backspace and carriage return
# are removed, not followed.
#
#   scripts/check-names.sh             scan the project folder
#   scripts/check-names.sh <root>      scan another folder (one root at most)
#   scripts/check-names.sh --self-test
#
WORDS_HEX="6b656570617373 6b6565706173737863 6b646278 6b657978 6b65657368617265 6b707863 787265626f6f74 72656963686c 3170617373776f7264"
# Absolute paths (no PATH lookup). env -i: an empty environment (F-017).
# -I: ignore user site packages and the current folder. No python3 means exit 127.
exec /usr/bin/env -i /usr/bin/python3 -I - "$WORDS_HEX" "$0" "$@" <<'PY'
import binascii, bz2, contextlib, ctypes, gzip, hashlib, html, io, lzma, os, random, re, shutil, stat, sys
import tempfile, time, tracemalloc, unicodedata, zipfile, zlib

sys.stdout.reconfigure(errors='backslashreplace')
WORDS = [bytes.fromhex(h).decode() for h in sys.argv[1].split()]

# Deleted before matching: format characters (U+200B, U+00AD, U+FEFF ...),
# combining marks, unassigned code points (U+2065, U+E0080 ...), the Hangul
# fillers, and control characters other than tab and line breaks.
TABLE = {c: None for c in range(0x110000)
         if unicodedata.category(chr(c)) in ('Cf', 'Mn', 'Cc', 'Cn') and c not in (9, 10, 13)}
TABLE.update(dict.fromkeys((0x115f, 0x1160, 0x3164, 0xffa0)))
# Lower-case Cyrillic, then Greek, letters that look like Latin ones.
TABLE.update(str.maketrans(
    '\u0430\u0432\u0441\u0501\u0435\u04bb\u0456\u043a\u04cf\u043e\u0440\u0455\u0442\u051d\u0445\u0443'
    '\u03b1\u03b2\u03f2\u03b5\u03b7\u03b9\u03ba\u03bf\u03c1\u03c4\u03c7\u03c5',
    'abcdehiklopstwxy' 'abcehikoptxy'))
# Latin letters NFKD leaves alone, by name (F-019): small capitals, letters
# with a hook, stroke or other mark, dotless and script letters, alpha, iota.
LATIN = re.compile(r'LATIN (?:SMALL |CAPITAL )*LETTER (?:SMALL CAPITAL |DOTLESS |SCRIPT )?(ALPHA|IOTA|[A-Z])(?: WITH .*)?')
for c in range(0x80, 0x20000):
    m = LATIN.fullmatch(unicodedata.name(chr(c), ''))
    if m:
        TABLE.setdefault(c, {'ALPHA': 'a', 'IOTA': 'i'}.get(m[1], m[1].lower()))
# Removed before NFKD (which turns them into plain spaces): spaces narrower
# than a quarter em, such as the hair space U+200A (F-015).
NARROW = re.compile('[\u2006\u2009\u200a\u202f\u205f]')
# Escapes: \u{..} \u.... \x.. \ooo (octal) and \N{name} (F-019).
ESC = re.compile(r'\\(?:u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|([0-7]{3})|N\{([^}]{1,90})\})')
PERCENT = re.compile('(?:%[0-9a-fA-F]{2})+')  # read as UTF-8, like a browser (F-019)
TAG = re.compile(r'<[^<>]*>')
MARK = re.compile('[*`~]')  # Markdown emphasis, code and strike marks (F-016)
# Terminal escape codes (ECMA-48: CSI, two-byte forms, and the OSC, DCS,
# SOS, PM and APC strings, whose body a terminal does not show, group s), in
# 7-bit and 8-bit (C1) form, as a VT parser reads them (the DEC parser model)
# (F-015): BEL ends only OSC; strings end at ST, whose 7-bit form ESC \ the
# last part removes; CAN, SUB or ESC end any code; C0 controls inside a CSI or
# ESC code run without ending it (kept, so the terminal view sees a backspace
# or carriage return there); DEL there is ignored.
C0 = '\x00-\x17\x19\x1c-\x1f\x7f'
# C0 right after ESC runs too and the code goes on (ESC BEL [ is a CSI). Such a
# run is moved in front of the ESC, after an ESC \ that ends a control string
# the ESC would have ended, so the run is not taken into the string's body.
ESC_C0 = re.compile('\x1b([%s]+)' % C0)
STILL = re.compile('[\x00-\x07\x0b\x0c\x0e-\x1f\x7f-\x9f]')  # controls that do not move the cursor
TERM = re.compile('(?P<s>(?:\x1b\\]|\x9d)[^\x07\x18\x1a\x1b\x9c]*[\x07\x9c]?|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f])[^\x18\x1a\x1b\x9c]*\x9c?)'
                  '|(?:\x1b\\[|\x9b)[%s -?]*[@-~]?|\x1b[%s -/]*[0-~]?' % (C0, C0))
MOVE = re.compile('\b|\r(?!\n)')  # a backspace, or a carriage return that does not end a line
MOVES = re.compile('([\b\r])')
ZLIB_HEAD = re.compile(rb'\x78[\x01\x5e\x9c\xda]')  # the usual zlib headers (F-020)
UNPACK = ((b'\x1f\x8b', gzip.open), (b'BZh', bz2.open), (b'\xfd7zXZ\0', lzma.open))
CAP = 1 << 24  # 16 MB: the most any one packed part may unpack to (F-031, F-119)
# A data: URI payload (the ;base64, marker in any case, with spaces after the ;
# and before the comma; spaces and line breaks in the payload; as browsers read
# them), a run wrapped over lines as MIME, PEM and base64 -b write it (every
# line but the last whole 4-character groups, so a line before the run or a
# padded line is never joined to it), or a long run on one line (F-115).
B64 = re.compile(rb';\s*(?i:b\s*a\s*s\s*e\s*6\s*4)\s*,([A-Za-z0-9+/\s]+={0,2})'
                 rb'|(?:[A-Za-z0-9+/]{4}){10,}(?:[ \t]*\r?\n[ \t]*(?:[A-Za-z0-9+/]{4})+)*[ \t]*\r?\n[ \t]*[A-Za-z0-9+/]+={0,2}'
                 rb'|[A-Za-z0-9+/]{40,}={0,2}')
# WOFF2 fonts are Brotli inside, which python3 cannot unpack, so a WOFF2 font
# fails the guard unless its SHA-256 is here (F-115). These are the fonts in
# design/option-a/vendor (copied to macos/App/Resources/Fonts), each unpacked
# and found clean by the E13-S2 red team (security/parity/E13-S2-AT-J.md).
WOFF2_OK = {
    'c2ea45ea05ff5c7df1936770c104725f2a68f43fd343f35f3da23a30b27de32a': 'Phosphor.woff2',
    '660bd6045c0e0d9756cddb8ba2ece3aad855df7d4a170ef23f7b1c0bf511c430': 'Phosphor-Fill.woff2',
    '08949f728dc52d528e69b1667d15c89a5686a4ee9a296ff90983985f99c380f7': 'ibm-plex-mono-latin-400-normal.woff2',
    '01d285447409c8a588692162439a038b8cbd7871309ee20267b0d2d91c6e8e22': 'ibm-plex-mono-latin-500-normal.woff2',
    '3b646991d30055a93a4ecc499713d4347953a74a947ecab435ab72070cbdab0e': 'ibm-plex-sans-latin-400-normal.woff2',
    '0717336fb31fcdcde4b8deb3675bb4a0f7f6d484864afcd6751ac29975962203': 'ibm-plex-sans-latin-500-normal.woff2',
    '8960851d691c054ed38e259bdcf1a6190d157b4203ed5bb32c632a863fb8ec2f': 'ibm-plex-sans-latin-600-normal.woff2',
}
CONTROL = re.compile('[\x00-\x1f\x7f-\x9f\\\\]')  # C0, DEL, C1 and the backslash: escaped when printed (F-121)
VAULT_SIG = bytes.fromhex('03d9a29a67fb4bb5')  # spec FMT-01.3
PNG_SIG = b'\x89PNG\r\n\x1a\n'
JPEG_DATA_END = re.compile(rb'\xff[^\x00\xd0-\xd7]')  # a marker other than stuffing or RSTn
# Speed only: BMP characters that norm keeps but that hold no ASCII letter or
# digit (most CJK, for example) can never be part of a word, so norm folds
# runs of them to one space before its slow per-character steps.
INERT = re.compile('[%s]+' % ''.join(
    ch for ch in map(chr, range(0x80, 0x10000)) if not '\ud800' <= ch <= '\udfff' and not NARROW.match(ch)
    and re.fullmatch('[^a-z0-9]+', unicodedata.normalize('NFKD', ch).casefold().translate(TABLE).lower())))


def inflates(z):
    # True when z is one whole zlib stream with nothing after it. The output
    # is made 1 MB at a time and dropped, so a small bomb cannot fill memory.
    d = zlib.decompressobj()
    try:
        while not d.eof and d.decompress(z, 1 << 20):
            z = d.unconsumed_tail
    except zlib.error:
        return False
    return d.eof and not d.unused_data


def inflate_text(z):
    # A compressed PNG text chunk, at most 16 MB unpacked; more raises, so
    # the image gets a 'cannot unpack' hit instead of filling memory.
    d = zlib.decompressobj()
    out = d.decompress(z, CAP + 1)
    if len(out) > CAP or not d.eof:
        raise ValueError('text chunk too large or cut off')
    return out


def streams(data):
    # Every whole zlib stream in data (one that ends with a good checksum),
    # and a raw deflate stream that is the whole of data (F-020). Each is at
    # most 16 MB unpacked; more raises, so the file gets a 'cannot unpack' hit.
    for i in [m.start() for m in ZLIB_HEAD.finditer(data)] + [-1]:
        d = zlib.decompressobj(-15 if i < 0 else 15)
        try:
            out = d.decompress(memoryview(data)[max(i, 0):], CAP + 1)
        except zlib.error:
            continue
        if len(out) > CAP:
            raise ValueError('stream unpacks past 16 MB')
        if d.eof and (i >= 0 or not d.unused_data):
            yield out


def png_parts(data):
    # (label, bytes) to match for every chunk but IDAT, or None when the PNG
    # does not parse cleanly. A text chunk that cannot be unpacked raises.
    parts, idat, p = [], [], 8
    while True:
        n = int.from_bytes(data[p:p + 4], 'big')
        t, end = data[p + 4:p + 8], p + 12 + n
        if (len(data) < end or n > 0x7fffffff or len(t) < 4 or not t.isalpha()
                or zlib.crc32(data[p + 4:end - 4]) != int.from_bytes(data[end - 4:end], 'big')):
            return None
        body, label = data[p + 8:end - 4], 'png chunk ' + t.decode()
        p = end
        if t == b'IDAT':
            idat.append(body)
            continue
        parts.append((label, t + body))
        if t in (b'zTXt', b'iCCP'):  # keyword NUL method stream
            parts.append((label + ' inflated', inflate_text(body.split(b'\0', 1)[1][1:])))
        elif t == b'iTXt' and body.split(b'\0', 1)[1][0]:  # keyword NUL flag method lang NUL keyword NUL text
            parts.append((label + ' inflated', inflate_text(body.split(b'\0', 1)[1][2:].split(b'\0', 2)[2])))
        if t == b'IEND':
            # Also all chunks joined, so a word split across two chunks is seen.
            joined = ('png chunks joined', b''.join(b for label, b in parts if not label.endswith('inflated')))
            return parts + [joined] if p == len(data) and inflates(b''.join(idat)) else None


def jpeg_parts(data):
    # (label, bytes) for every marker segment, skipping the entropy-coded data
    # after each SOS, or None when the JPEG does not parse cleanly.
    parts, p, n = [], 2, len(data)
    while p < n and data[p] == 0xff:
        while p < n and data[p] == 0xff:  # fill bytes
            p += 1
        m, p = data[p] if p < n else 0, p + 1
        if m == 0xd9:  # EOI
            return parts if p == n else None
        if m == 0x01 or 0xd0 <= m <= 0xd7:  # no length
            continue
        size = int.from_bytes(data[p:p + 2], 'big')
        if m in (0x00, 0xd8) or size < 2 or p + size > n:
            return None
        parts.append(('jpeg marker %02X' % m, data[p + 2:p + size]))
        p += size
        if m == 0xda:  # SOS
            e = JPEG_DATA_END.search(data, p)
            if not e:
                return None
            p = e.start()
    return None


def norm(s):
    if not s.isascii():
        s = unicodedata.normalize('NFKD', INERT.sub(' ', NARROW.sub('', s))).casefold()
    return s.translate(TABLE).lower()


def unesc(s):
    def one(m):
        if m.group(5):
            try:
                return unicodedata.lookup(m.group(5))
            except KeyError:
                return m.group(0)
        v = int(m.group(4), 8) if m.group(4) else int(m.group(1) or m.group(2) or m.group(3), 16)
        return chr(v) if v < 0x110000 else ''
    return ESC.sub(one, s)


def overstrike(line):
    # One line as a terminal draws it (F-015): a backspace moves the cursor one
    # column back, a carriage return to column 0, and other text overwrites
    # the columns it lands on. Linear: text goes in whole runs.
    if '\b' not in line and '\r' not in line.rstrip('\r'):
        return line
    buf, pos = [], 0
    for i, s in enumerate(MOVES.split(line)):
        if i % 2:
            pos = 0 if s == '\r' else max(0, pos - 1)
        else:
            buf[pos:pos + len(s)] = s
            pos += len(s)
    return ''.join(buf)


def shown(t):
    # t as a browser, a Markdown viewer or a terminal shows it, with escapes
    # and percent-encoding (F-019) decoded: one view, or two when a terminal
    # would also move the cursor back (the first view is kept for browsers).
    t = PERCENT.sub(lambda m: bytes.fromhex(m[0].replace('%', '')).decode('utf-8', 'replace'), html.unescape(t))
    t = unesc(t)
    t = ESC_C0.sub(lambda m: '\x1b\\' + m[1] + '\x1b', TAG.sub('', t))
    t = MARK.sub('', TERM.sub(lambda m: '' if m['s'] else re.sub('[^\b\r\n\t]', '', m[0]), t))
    # The terminal view drops controls that take no column (BEL, DEL, C1 ...).
    return [t, '\n'.join(map(overstrike, STILL.sub('', t).split('\n')))] if MOVE.search(t) else [t]


def views(data):
    yield data.replace(b'\0', b'').replace(b'\xad', b'').lower().decode('latin-1')  # \xad: soft hyphen (F-013)
    codecs = [('utf-16-le', 2), ('utf-16-be', 2)]  # UTF-16 text need not hold a NUL or a BOM (F-014)
    if b'\0' in data:  # every UTF-32 character holds one
        codecs += [('utf-32-le', 4), ('utf-32-be', 4)]
    texts = [data.decode('utf-8', 'replace')] + [data[i:].decode(e, 'ignore') for e, n in codecs for i in range(n)]
    for t in texts:
        yield norm(t)
        yield from map(norm, shown(t))


def name_hits(name, path, hits, what='name'):
    name = name.translate({9: None, 10: None, 13: None})
    v = '\0'.join(map(norm, [name] + shown(name)))
    hits += [(path, '%s holds word %d' % (what, i + 1)) for i, w in enumerate(WORDS) if w in v]


def content_hits(data, path, hits, inside='', depth=0):
    try:
        parts = None if depth >= 8 else png_parts(data) if data[:8] == PNG_SIG else (
            jpeg_parts(data) if data[:3] == b'\xff\xd8\xff' else None)
    except Exception as e:
        hits.append((path, '%scannot unpack image (%s: %s)' % (inside, type(e).__name__, e)))
        return
    if parts is not None:
        for label, part in parts:
            content_hits(part, path, hits, '%s%s: ' % (inside, label), depth + 1)
        return
    found = set()
    for v in views(data):
        for i, w in enumerate(WORDS):
            p = v.find(w)
            if p >= 0 and i not in found:
                found.add(i)
                hits.append((path, '%scontent holds word %d near line %d' % (inside, i + 1, v.count('\n', 0, p) + 1)))
    try:
        for kind, part in unpacked(data, path, hits, inside):
            if depth >= 8:
                raise ValueError('nested too deep')
            content_hits(part, path, hits, '%sunpacked %s: ' % (inside, kind), depth + 1)
    except Exception as e:
        hits.append((path, '%scannot unpack (%s: %s)' % (inside, type(e).__name__, e)))


def unpacked(data, path, hits, inside):
    # (kind, bytes) for each part packed in data, each made only after the one
    # before it is matched, so parts are not all held at once (F-120). Zip
    # member names are matched here too.
    if (data[:4] == b'(\xb5/\xfd' or not inside and path.endswith('.br')
            or data[:4] == b'wOF2' and hashlib.sha256(data).hexdigest() not in WOFF2_OK):
        raise ValueError('zstd or Brotli data, which python3 cannot unpack (F-115)')
    for m, f in UNPACK:
        if data.startswith(m):
            yield 'stream', capped(f(io.BytesIO(data)))
    for s in streams(data):
        yield 'stream', s
    if data[:4] in (b'PK\3\4', b'PK\5\6') or zipfile.is_zipfile(io.BytesIO(data)):  # also after a prefix (F-020)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for n in z.namelist():
                name_hits(n, path, hits, inside + 'zip member name')
            for n in z.namelist():
                yield 'member', capped(z.open(n))
    for m in B64.finditer(data):  # padding is optional, as for browsers; a lone last character is dropped
        s = re.sub(rb'\s', b'', m[1] or m[0]).rstrip(b'=')
        yield 'base64', binascii.a2b_base64(s[:len(s) - (len(s) % 4 == 1)] + b'==')


def capped(f):
    # What the open packed file f unpacks to, read in one bounded call: past
    # 16 MB it raises, so the file gets a 'cannot unpack' hit (F-119, as F-031).
    with f:
        out = f.read(CAP + 1)
    if len(out) > CAP:
        raise ValueError('unpacks past 16 MB')
    return out


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.listxattr.restype = LIBC.getxattr.restype = ctypes.c_ssize_t
LIBC.listxattr.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int)
LIBC.getxattr.argtypes = LIBC.setxattr.argtypes = (
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int)


def xattrs(p):
    # (name, value) of each extended attribute of p, links not followed
    # (macOS calls, XATTR_NOFOLLOW = 1) (F-018). Raises OSError on failure.
    def call(f, *args):
        n = f(*args)
        if n < 0:
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
        return n
    p = os.fsencode(p)
    names = ctypes.create_string_buffer(call(LIBC.listxattr, p, None, 0, 1))
    n = call(LIBC.listxattr, p, names, len(names), 1)
    for name in names.raw[:n].split(b'\0')[:-1]:
        value = ctypes.create_string_buffer(call(LIBC.getxattr, p, name, None, 0, 0, 1))
        n = call(LIBC.getxattr, p, name, value, len(value), 0, 1)
        yield name, value.raw[:n]


def scan(root):
    """Returns (hits, files read, vault files name-only). A hit is (path, message)."""
    os.chdir(root)
    hits, n, v = [], 0, 0
    for d, dirs, files in os.walk('.', onerror=lambda e: hits.append((e.filename, 'cannot read (%s)' % e.strerror))):
        if d in ('.', './fuzz'):
            dirs[:] = [x for x in dirs if not (x in (('target', '.git') if d == '.' else ('target',))
                                               and not os.path.islink(os.path.join(d, x)))]
        for x in dirs + files:
            p = os.path.join(d, x)
            name_hits(x, p, hits)
            try:
                for a, value in xattrs(p):
                    name_hits(a.decode('utf-8', 'replace'), p, hits, 'xattr name')
                    content_hits(value, p, hits, 'xattr value: ')
                mode = os.lstat(p).st_mode
                if stat.S_ISLNK(mode):
                    name_hits(os.readlink(p), p, hits, 'link target')
                elif stat.S_ISREG(mode):
                    with open(p, 'rb') as f:
                        data = f.read()
                    if x.endswith('.appvault') and data.startswith(VAULT_SIG):
                        v += 1
                    else:
                        n += 1
                        content_hits(data, p, hits)
            except OSError as e:
                hits.append((p, 'cannot read (%s)' % e.strerror))
    return hits, n, v


def report(root):
    try:
        hits, n, v = scan(root)
    except OSError as e:
        print('names: FAIL (cannot open %s: %s)' % (root, e.strerror))
        return 1
    for p, m in hits:
        print(CONTROL.sub(lambda c: '\\x%02x' % ord(c[0]), '%s: %s' % (p, m)))  # as ls -b does (F-121)
    if hits or n == 0:
        print('names: FAIL (%d hits, %d files scanned, %d vault files name-only)' % (len(hits), n, v))
        return 1
    print('names: PASS (%d files scanned, %d vault files name-only)' % (n, v))
    return 0


def self_test():
    w = WORDS
    t = tempfile.mkdtemp()

    def put(rel, data):
        p = os.path.join(t, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as f:
            f.write(data if isinstance(data, bytes) else data.encode())

    raw = zlib.compressobj(wbits=-15)

    def zipped(member, text):
        b = io.BytesIO()
        with zipfile.ZipFile(b, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr(member, text * 20)
        return b.getvalue()

    b64 = lambda s: binascii.b2a_base64(s.encode(), newline=False).decode()
    rnd = random.Random(1)  # fixed seed: the same bytes on every run

    def chunk(typ, body, crc=None):
        crc = zlib.crc32(typ + body) if crc is None else crc
        return len(body).to_bytes(4, 'big') + typ + body + crc.to_bytes(4, 'big')

    def png(*chunks):  # 256 x 256 8-bit grey; chunks go between IHDR and IEND
        ihdr = (b'IHDR', (256).to_bytes(4, 'big') * 2 + bytes([8, 0, 0, 0, 0]))
        return PNG_SIG + b''.join(chunk(*c) for c in (ihdr,) + chunks + ((b'IEND', b''),))

    def pixels(first=b''):  # random rows, filter 0, stored (level 0): the bytes stay as they are
        px = first + rnd.randbytes((1 << 16) - len(first))
        return b'IDAT', zlib.compress(b''.join(b'\0' + px[i:i + 256] for i in range(0, 1 << 16, 256)), 0)

    def jpeg(*segs, data=b'', end=b'\xff\xd9'):  # segments, one SOS, entropy-coded data, EOI
        seg = lambda m, b: bytes([0xff, m]) + (len(b) + 2).to_bytes(2, 'big') + b
        return (b'\xff\xd8' + b''.join(seg(*x) for x in segs + ((0xda, b'\1\1\0\0\x3f\0'),))
                + data.replace(b'\xff', b'\xff\0') + end)

    k = w[0]
    cases = [  # (label, path that must get a hit, content)
        ('mixed case in a hidden folder', '.hidden dir/notes.txt',
         'clean line\nsee %s here\n' % ''.join(c if i % 2 else c.upper() for i, c in enumerate(k))),
        ('upper case file name with quotes', 'odd \'name\' "%s".txt' % w[1].upper(), 'clean'),
        ('nested folder named target', 'sub/target/x.txt', w[3]),
        ('F-001 NUL byte first', 'nul1.txt', b'\0see ' + k.encode()),
        ('F-001 NUL byte after', 'nul2.txt', ('see %s\n' % k).encode() + b'\0'),
        ('F-001 binary header', 'bin.png', b'\x89PNG\r\n\x1a\n' + bytes(range(256)) * 2 + b'tEXt' + w[2].encode()),
        ('F-002 UTF-16 with BOM', 'u16.txt', ('see %s\n' % w[1]).encode('utf-16')),
        ('F-002 UTF-16BE, no BOM', 'u16be.txt', ('see %s\n' % w[1]).encode('utf-16-be')),
        ('F-002 UTF-32', 'u32.txt', ('see %s\n' % w[1]).encode('utf-32')),
        ('F-002 UTF-16 lookalike', 'u16c.txt', ('\u212a' + k[1:]).encode('utf-16-le')),
        ('F-005 zero-width space', 'zw.md', k[:3] + '\u200b' + k[3:]),
        ('F-005 soft hyphen', 'shy.md', k[:3] + '\u00ad' + k[3:]),
        ('F-005 Hangul filler', 'hf.md', k[:3] + '\u3164' + k[3:]),
        ('F-005 unassigned U+2065', 'cn.md', k[:3] + '\u2065' + k[3:]),
        ('F-005 Hangul filler in a name', k[:3] + '\u115f' + k[3:] + '.md', 'clean'),
        ('F-006 root file named target', 'target', k),
        ('F-006 file fuzz/target', 'fuzz/target', k),
        ('vault name still checked', w[2] + '.appvault', VAULT_SIG + b'\0'),
        ('F-011 text file named *.appvault', 'notes.appvault', 'see %s\n' % k),
        ('F-007 Kelvin sign', 'kelvin.md', '\u212a' + k[1:]),
        ('F-007 Cyrillic letters', 'cyr.md', k.replace('e', '\u0435').replace('a', '\u0430')),
        ('F-007 fullwidth letters', 'full.md', ''.join(chr(ord(c) + 0xfee0) for c in k)),
        ('F-007 HTML entity', 'ent.html', '<p>&#%d;%s</p>' % (ord(k[0]), k[1:])),
        ('F-007 HTML tag inside', 'span.html', '<p>%s<span></span>%s</p>' % (k[:3], k[3:])),
        ('F-007 Rust escape', 'esc.rs', 'let s = "\\u{%x}%s";' % (ord(k[0]), k[1:])),
        ('F-007 newline in a file name', k[:3] + '\n' + k[3:] + '.md', 'clean'),
        ('F-008 gzip content', 'g.txt.gz', gzip.compress((w[2] + '\n').encode() * 20)),
        ('F-008 zip member content', 'c.zip', zipped('inner.txt', w[1] + '\n')),
        ('F-008 zip member name', 'n.zip', zipped(w[6] + '.txt', 'clean\n')),
        ('symlink target', 'link', None),
        ('F-003 folder that can be read but not entered', 'locked', None),
        ('broken archive', 'bad.gz', b'\x1f\x8b broken'),
        ('F-012 PNG tEXt', 'text.png', png((b'tEXt', b'Comment\0see ' + k.encode()), pixels())),
        ('F-012 PNG zTXt', 'ztext.png', png((b'zTXt', b'Comment\0\0' + zlib.compress(('see ' + w[2]).encode())), pixels())),
        ('F-012 PNG compressed iTXt', 'itext.png', png((b'iTXt', b'Comment\0\1\0en\0\0' + zlib.compress(w[1].encode())), pixels())),
        ('F-012 PNG unknown chunk', 'private.png', png((b'prVt', ('see ' + w[3]).encode()), pixels())),
        ('F-012 PNG zTXt that does not inflate', 'badz.png', png((b'zTXt', b'Comment\0\0broken'), pixels())),
        ('F-012 PNG bad CRC, word in IDAT', 'crc.png', png(pixels(k.encode()) + (0,))),  # only the CRC is wrong
        ('F-012 PNG word in IDAT that is not zlib', 'notz.png', png((b'IDAT', ('see ' + k).encode()))),
        ('F-012 PNG data after IEND', 'tail.png', png(pixels()) + ('see ' + w[4]).encode()),
        ('PNG word split across two chunks', 'split.png', png((b'tEXt', b'Comment\0' + k[:3].encode()), (k[3:7].encode(), b''), pixels())),
        ('PNG pixel data with text after the zlib stream', 'ztail.png', png((b'IDAT', pixels()[1] + ('see ' + k).encode()))),
        ('PNG pixel data cut off inside a stored stream', 'zcut.png', png((b'IDAT', zlib.compress(('see ' + k).encode() * 64, 0)[:-8]))),
        ('PNG zTXt that unpacks past 16 MB', 'zbomb.png', png((b'zTXt', b'Comment\0\0' + zlib.compress(bytes(1 << 25), 9)), pixels())),
        ('F-012 JPEG comment', 'com.jpg', jpeg((0xfe, ('see ' + w[3]).encode()), data=rnd.randbytes(4096))),
        ('F-012 JPEG with no EOI, word in data', 'noend.jpg', jpeg(data=('see ' + k).encode(), end=b'')),
        ('F-012 JPEG data after EOI', 'eoi.jpg', jpeg(data=rnd.randbytes(512)) + ('see ' + w[5]).encode()),
        ('F-013 Latin-1 soft hyphen byte', 'shy8.md', k[:3].encode() + b'\xad' + k[3:].encode()),
        ('F-014 UTF-16 fullwidth letters, no NUL or BOM', 'u16fw.txt',
         ''.join(chr(ord(c) + 0xfee0) for c in k).encode('utf-16-le')),
        ('F-014 UTF-16BE at an odd offset', 'u16odd.txt',  # one plain letter, so byte order and offset both count
         b'x' + (k[0] + ''.join(chr(ord(c) + 0xfee0) for c in k[1:])).encode('utf-16-be')),
        ('F-015 terminal color code', 'ansi.txt', k[:3] + '\x1b[1;31m' + k[3:]),
        ('F-015 backspace overstrike', 'bs.txt', k[:3] + 'x\b' + k[3:]),
        ('F-015 typo fixed with backspaces', 'typo.txt', k[0] + 'X' + k[2:] + '\b' * (len(k) - 1) + k[1]),
        ('F-015 carriage return overwrite', 'cr.txt', 'XXX' + k[3:] + '\r' + k[:3]),
        ('F-015 shown view kept beside the terminal view', 'cr.html', '<p>&#%d;%s</p>\r%s' % (ord(k[0]), k[1:], 'x' * 40)),
        ('F-015 terminal control string', 'dcs.txt', k[:3] + '\x1bPjunk\x1b\\' + k[3:]),
        ('F-015 BEL inside a control string', 'apc.txt', k[:3] + '\x1b_junk\x07junk\x1b\\' + k[3:5] + '\x1b]0;x\x07' + k[5:]),
        ('F-015 8-bit terminal codes', 'c1.txt',
         k[:1] + '\x9b1m' + k[1:2] + '\x9d0;x\x9c' + k[2:3] + '\x90junk\x07junk\x9c' + k[3:4] + '\x98a\x9c' + k[4:5]
         + '\x9eb\x9c' + k[5:6] + '\x9fc\x9c' + k[6:]),
        ('F-015 C0, CAN and SUB inside terminal codes', 'can.txt', k[0] + '\x1b[\x071\x7fm' + k[1] + '\x1b(\x07B' + k[2]
         + '\x1b]0;x\x18' + k[3] + '\x1bP\x1a' + k[4] + '\x1b[1\x18' + k[5] + '\x1b[ 1m' + k[6:]),
        ('F-015 SUB ends an OSC', 'oscsub.txt', k[:3] + '\x1b]0;x\x1a' + k[3:]),
        ('F-015 CAN ends DCS, SOS, PM and APC', 'strcan.txt',
         k[:1] + '\x1bPj\x18' + k[1:2] + '\x1bXj\x18' + k[2:3] + '\x1b^j\x18' + k[3:4] + '\x1b_j\x18' + k[4:]),
        ('F-015 ESC with no final byte', 'escnofinal.txt', k[:3] + '\x1b(\x1b[1m' + k[3:]),
        ('F-015 carriage return inside a terminal code', 'csicr.txt', 'XXX' + k[3:] + '\x1b[\r1m' + k[:3]),
        ('F-015 C0 or DEL between ESC and the next byte', 'escc0.txt', k[:2] + '\x1b\x07[1m' + k[2:4] + '\x1b\x7f]0;x\x07'
         + k[4:5] + '\x1b\x00Pjunk\x1b\\' + k[5:]),
        ('F-015 carriage return between ESC and [', 'esccr.txt', 'XXX' + k[3:] + '\x1b\r[1m' + k[:3]),
        ('F-015 carriage return between ESC and [ after a control string', 'strcr.txt',
         'XXX' + k[3:] + '\x1bPj\x1b\r[1m' + k[:3]),
        ('F-015 two controls between ESC and [', 'escc0two.txt', k[:3] + '\x1b\x07\x7f[1m' + k[3:]),
        ('F-015 BEL, DEL and C1 before a backspace', 'belbs.txt', k[:3] + 'x\x07\x7f\x80\b' + k[3:]),
        ('F-015 terminal color code in a file name', k[:3] + '\x1b[1m' + k[3:] + '.txt', 'clean'),
        ('F-015 hair space', 'hair.md', k[:3] + '\u200a' + k[3:]),
        ('F-016 Markdown emphasis inside the word', 'em.md', '%s**%s**' % (k[:3], k[3:])),
        ('F-016 Markdown code mark inside the word', 'code.md', '%s`%s`' % (k[:3], k[3:])),
        ('F-016 Markdown strike inside the word', 'strike.md', '%s~~%s~~' % (k[:3], k[3:])),
        ('F-018 xattr value', 'xv.txt', 'clean'),
        ('F-018 xattr name', 'xn.txt', 'clean'),
        ('F-018 xattr on a link, not followed', 'xlink', None),
        ('F-019 percent-encoding', 'pct.txt', '%s%%%02x%s' % (k[:2], ord(k[2]), k[3:])),
        ('F-019 octal escape', 'oct.sh', 'printf "\\%o%s"' % (ord(k[0]), k[1:])),
        ('F-019 Python \\N{} name', 'uname.py', 's = "\\N{LATIN SMALL LETTER %s}%s"' % (k[0].upper(), k[1:])),
        ('F-019 small capitals', 'smcap.md', ''.join(unicodedata.lookup('LATIN LETTER SMALL CAPITAL ' + c.upper()) for c in k)),
        ('F-019 Latin alpha', 'alpha.md', k.replace('a', '\u0251')),
        ('F-019 Latin letter with a stroke', 'stroke.md', unicodedata.lookup('LATIN SMALL LETTER %s WITH STROKE' % k[0].upper()) + k[1:]),
        ('F-020 zlib stream', 'z.bin', zlib.compress(('see ' + w[3]).encode())),
        ('F-020 raw deflate stream', 'raw.bin', raw.compress(('see ' + w[2]).encode()) + raw.flush()),
        ('F-020 zlib stream inside a file', 'mid.pdf',
         b'%PDF-1.4\nstream\n' + zlib.compress(('see ' + w[5]).encode()) + b'\nendstream\n'),
        ('F-020 zip after a prefix', 'sfx.bin', b'#!/bin/sh\nexit 0\n' + zipped('inner.txt', w[1] + '\n')),
        ('F-115 base64 data: URI', 'uri.html', '<img src="data:text/plain;base64,%s">' % b64(w[3])),
        ('F-115 base64 run', 'b64.json', '{"blob": "%s"}' % b64(('see %s\n' % w[2]) * 4)),
        ('F-115 WOFF2 font not allowed', 'font.woff2', b'wOF2\0\1\0\0' + rnd.randbytes(64)),
        ('F-115 zstd data', 'z.zst', bytes.fromhex('28b52ffd') + rnd.randbytes(64)),
        ('F-115 Brotli file', 'page.html.br', rnd.randbytes(64)),
        ('F-115 base64 wrapped at 76 columns', 'mime.txt', re.sub('(.{76})', '\\1\n', b64('x' * 54 + k + 'y' * 60))),
        ('F-115 base64 line after a padded line', 'pad.txt',
         b64('x' * 30) + '\n' + b64('x' * 31) + '\n' + b64(('see %s\n' % w[2]) * 4)),
        ('F-115 base64 line after a line of odd length', 'odd.txt', 'x' * 41 + '\n' + b64(('see %s\n' % w[2]) * 4)),
        ('F-115 data: URI with a line break', 'urinl.html',
         '<img src="data:text/plain;base64,%s\n%s">' % (b64('see ' + w[3])[:5], b64('see ' + w[3])[5:])),
        ('F-115 WOFF2 font in a CSS data: URI', 'font.css',
         '@font-face{src:url(data:font/woff2;base64,%s)}' % binascii.b2a_base64(b'wOF2' + bytes(60), newline=False).decode()),
        ('F-115 data: URI with spaces', 'urisp.css',
         'a{background:url(data:text/plain;base64,%s)}' % ' '.join(re.findall('.{1,4}', b64('see ' + w[3])))),
        ('F-115 base64 wrapped with CRLF and trailing blanks', 'crlf.txt',
         re.sub('(.{76})', '\\1 \r\n', b64('x' * 54 + k + 'y' * 60))),
        ('F-115 zstd data in a gzip file', 'zst.gz', gzip.compress(bytes.fromhex('28b52ffd') + bytes(60))),
        ('F-115 data: URI marker in upper case between spaces', 'uriuc.html',
         '<img src="data:text/plain; BASE64 ,%s">' % b64('see ' + w[3])),
        ('F-115 unpadded base64', 'nopad.html', '<img src="data:text/plain;base64,%s">' % b64('see ' + w[3]).rstrip('=')),
        ('F-115 data: URI marker split by a tab and line breaks', 'urisplit.html',
         '<img src="data:text/plain;\tba\nse64\r\n,%s">' % b64('see ' + w[3])),
        ('F-121 DEL and C1 in a file name', k[:3] + '\x7f\x9b' + k[3:] + '.txt', 'clean'),
        ('F-121 backslash in a file name', k + '\\x1b.txt', 'clean'),
    ]
    clean = {'space "quote".txt': 'clean', 'clean.bin': b'\0\1\2 clean \xff',
             'clean16.txt': 'clean text\n'.encode('utf-16'), 'clean.gz': gzip.compress(b'clean'),
             'clean.b64': re.sub('(.{76})', '\\1\n', b64('clean ' * 30)),  # wrapped base64 decodes cleanly
             '.git/HEAD': k,  # .git is skipped
             'v.appvault': VAULT_SIG + ('see %s\n' % k).encode(),  # vault signature first: content skipped
             'pixels.png': png((b'tEXt', b'Comment\0clean'), pixels(k.encode())),  # IDAT is skipped
             'photo.jpg': jpeg((0xe0, b'JFIF\0\1\1\0\0\1\0\1\0\0'),  # entropy-coded data is skipped
                               data=rnd.randbytes(4096) + k.encode() + rnd.randbytes(4096))}
    for rel, data in clean.items():
        put(rel, data)
    for _, rel, data in cases:
        if data is not None:
            put(rel, data)
    os.symlink('gone/' + w[4], os.path.join(t, 'link'))
    for rel, a, value in (('xv.txt', b'user.note', ('see ' + w[4]).encode()), ('xn.txt', ('user.' + w[5]).encode(), b'1')):
        LIBC.setxattr(os.fsencode(os.path.join(t, rel)), a, value, len(value), 0, 0)
    os.symlink('clean.bin', os.path.join(t, 'xlink'))  # the value is on the link; its clean target has none
    value = ('see ' + w[4]).encode()
    LIBC.setxattr(os.fsencode(os.path.join(t, 'xlink')), b'user.note', value, len(value), 0, 1)  # XATTR_NOFOLLOW
    put('locked/a.md', w[5])
    put('locked/%s.md' % w[7], 'clean')
    os.chmod(os.path.join(t, 'locked'), 0o444)
    if os.geteuid() == 0:  # root can enter any folder
        cases = [c for c in cases if c[1] != 'locked']

    ok = True
    try:
        hits, _, _ = scan(t)
        print('self-test step 1 (expect FAIL): %d hits' % len(hits))
        paths = {p for p, _ in hits}
        covers = lambda rel, p: p == './' + rel or p.startswith('./' + rel + '/')
        for label, rel, _ in cases:
            if not any(covers(rel, p) for p in paths):
                print('self-test: missed case: ' + label)
                ok = False
        if any(not any(covers(rel, p) for _, rel, _ in cases) for p in paths):
            print('self-test: hit on a clean or skipped path')
            ok = False
        out = io.StringIO()  # the hit lines as printed: no raw control character in them
        with contextlib.redirect_stdout(out):
            report(t)
        if re.search('[\x00-\x09\x0b-\x1f\x7f-\x9f]', out.getvalue()):
            print('self-test: missed case: F-121 control characters in a printed file name')
            ok = False
        if '\\x5cx1b.txt' not in out.getvalue():  # a backslash in a name is escaped too
            print('self-test: missed case: F-121 backslash in a printed file name')
            ok = False

        os.chmod(os.path.join(t, 'locked'), 0o755)
        for _, rel, _ in cases:
            p = os.path.join(t, rel)
            shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.unlink(p)
        put('target/x.txt', k)       # root build output: skipped
        put('fuzz/target/x.txt', k)  # fuzz build output: skipped
        hits, n, v = scan(t)
        print('self-test step 2 (expect PASS): %d hits, %d files scanned, %d name-only' % (len(hits), n, v))
        if hits or (n, v) != (7, 1):
            print('self-test: expected PASS, 7 files scanned, 1 name-only')
            ok = False
        print('self-test step 3 (expect PASS for one root, then FAIL for two):')
        if main([t]) != 0 or main([t, t]) != 1:
            print('self-test: missed case: F-010 two roots')
            ok = False
        mb = bytes(1 << 20)  # 64 MB of zeros: as pixel data, a zlib stream inside a file and in each format
        c = zlib.compressobj(9)
        bomb = b''.join(c.compress(mb) for _ in range(64)) + c.flush()
        zipbomb = io.BytesIO()
        with zipfile.ZipFile(zipbomb, 'w', zipfile.ZIP_DEFLATED) as z, z.open('zeros', 'w') as f:
            for _ in range(64):
                f.write(mb)
        for label, data, limit, hit in (
                ('F-031 pixel data unpacked in 1 MB steps', png((b'IDAT', bomb)), 16 << 20, False),
                ('F-031 zlib stream inside a file stops at 16 MB', b'junk\n' + bomb + b'\njunk', 32 << 20, True),
                ('F-119 gzip stops at 16 MB', gzip.compress(mb) * 64, 32 << 20, True),  # 64 members
                ('F-119 bzip2 stops at 16 MB', bz2.compress(mb) * 64, 32 << 20, True),
                ('F-119 xz stops at 16 MB', lzma.compress(mb) * 64, 32 << 20, True),
                ('F-119 zip member stops at 16 MB', zipbomb.getvalue(), 32 << 20, True),
                ('F-120 zlib streams matched one at a time', b'junk\n' + (zlib.compress(b' ' * (1 << 15)) + b'\n') * 64, 1 << 20, False)):
            found = []
            tracemalloc.start()
            content_hits(data, 'bomb', found)
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            print('self-test step 4 (%s): peak %.1f MB' % (label, peak / 1e6))
            if peak > limit or hit != any('cannot unpack' in m for _, m in found):
                print('self-test: missed case: ' + label)
                ok = False
        start = time.process_time()  # long lines, one with a backspace: well under 1 s when linear
        shown('x' * 40000 + '\n\b' + 'x' * (1 << 20) + '\b')
        if time.process_time() - start > 2:
            print('self-test: missed case: F-015 terminal view in linear time')
            ok = False
        if {'PATH', 'HOME', 'DEVELOPER_DIR'} & set(os.environ):
            print('self-test: missed case: F-017 environment not cleared')
            ok = False
        shutil.rmtree(t)
        os.mkdir(t)
        if report(t) != 1:
            print('self-test: expected FAIL on a folder with 0 files')
            ok = False
    finally:
        os.chdir('/')
        os.chmod(os.path.join(t, 'locked'), 0o755) if os.path.isdir(os.path.join(t, 'locked')) else None
        shutil.rmtree(t)
    print('self-test: ' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


def main(args):
    if args == ['--self-test']:
        return self_test()
    if len(args) > 1:
        print('names: FAIL (%d arguments given, one root at most)\nusage: %s [<root> | --self-test]' % (len(args), sys.argv[2]))
        return 1
    if not args:
        args = [os.path.dirname(os.path.dirname(os.path.realpath(sys.argv[2])))]
        if not os.path.isfile(os.path.join(args[0], 'AGENTS.md')):
            print('names: FAIL (no AGENTS.md in %s; pass the project folder)' % args[0])
            return 1
    return report(args[0])


sys.exit(main(sys.argv[3:]))
PY

//! A reader of QR symbols for these tests only, written from ISO/IEC 18004
//! (QR Code model 2), for an error-free symbol at level H. It checks the
//! quiet zone and every function pattern, reads both format copies and both
//! version copies, removes the mask, takes the codewords in placement order,
//! splits the blocks, checks every error correction codeword, and parses the
//! data: ECI designators and byte segments, then the terminator, the zero bits
//! to the codeword boundary and the pad codewords. Any difference from a
//! well-formed symbol is an error, so a symbol a scanner would only read after
//! correcting it never passes. Also: the printed block characters of
//! `larsal show --qr` turned back into the module matrix.

/// One data segment, in symbol order.
#[derive(Debug, PartialEq, Eq)]
pub enum Segment {
    /// An ECI designator (§7.4.2).
    Eci(u32),
    /// A byte mode segment (§7.4.5).
    Bytes(Vec<u8>),
}

/// A read symbol.
#[derive(Debug)]
pub struct Symbol {
    pub version: usize,
    pub mask: u8,
    pub segments: Vec<Segment>,
}

/// §7.5.1 Table 9, error correction level H: codewords per block and blocks,
/// versions 1 to 40.
const EC_H: [usize; 40] = [
    17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30,
    30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
];
const BLOCKS_H: [usize; 40] = [
    1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37,
    40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81,
];

/// What a module of the symbol is (§6.3).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    Data,
    /// A finder, separator, timing or alignment module, or the dark module.
    Fixed(bool),
    Format,
    Version,
}

struct Layout {
    n: usize,
    parts: Vec<Part>,
}

impl Layout {
    fn set(&mut self, x: usize, y: usize, p: Part) {
        self.parts[y * self.n + x] = p;
    }

    fn part(&self, x: usize, y: usize) -> Part {
        self.parts[y * self.n + x]
    }
}

/// Annex E: the row and column centres of the alignment patterns, the first
/// 6, the last n − 7, the others at one even step (26 at version 32).
fn alignment(version: usize) -> Vec<usize> {
    if version == 1 {
        return Vec::new();
    }
    let count = version / 7 + 2;
    let step = if version == 32 {
        26
    } else {
        (version * 4 + count * 2 + 1) / (count * 2 - 2) * 2
    };
    let last = 17 + 4 * version - 7;
    let mut out: Vec<usize> = (0..count - 1).map(|i| last - i * step).collect();
    out.push(6);
    out.reverse();
    out
}

/// The function patterns and the reserved areas of `version` (§6.3.2 to
/// §6.3.6, §7.9, §7.10).
fn layout(version: usize) -> Layout {
    let n = 17 + 4 * version;
    let mut l = Layout {
        n,
        parts: vec![Part::Data; n * n],
    };
    for i in 0..n {
        l.set(6, i, Part::Fixed(i.is_multiple_of(2)));
        l.set(i, 6, Part::Fixed(i.is_multiple_of(2)));
    }
    for (fx, fy) in [(0, 0), (n - 7, 0), (0, n - 7)] {
        for dy in -1..=7_isize {
            for dx in -1..=7_isize {
                let (Some(x), Some(y)) = (fx.checked_add_signed(dx), fy.checked_add_signed(dy))
                else {
                    continue;
                };
                if x >= n || y >= n {
                    continue;
                }
                let d = (dx - 3).abs().max((dy - 3).abs());
                l.set(x, y, Part::Fixed(d != 2 && d != 4));
            }
        }
    }
    let centres = alignment(version);
    let last = centres.len().saturating_sub(1);
    for (i, &cy) in centres.iter().enumerate() {
        for (j, &cx) in centres.iter().enumerate() {
            if (i, j) == (0, 0) || (i, j) == (0, last) || (i, j) == (last, 0) {
                continue;
            }
            for dy in -2..=2_isize {
                for dx in -2..=2_isize {
                    let d = dx.abs().max(dy.abs());
                    l.set(
                        cx.wrapping_add_signed(dx),
                        cy.wrapping_add_signed(dy),
                        Part::Fixed(d != 1),
                    );
                }
            }
        }
    }
    for i in 0..15 {
        let (a, b) = format_cells(n, i);
        l.set(a.0, a.1, Part::Format);
        l.set(b.0, b.1, Part::Format);
    }
    l.set(8, n - 8, Part::Fixed(true));
    if version >= 7 {
        for i in 0..18 {
            let (a, b) = version_cells(n, i);
            l.set(a.0, a.1, Part::Version);
            l.set(b.0, b.1, Part::Version);
        }
    }
    l
}

/// §7.9.1: the two places (x, y) of format bit `i`, 0 the least significant.
fn format_cells(n: usize, i: usize) -> ((usize, usize), (usize, usize)) {
    let first = match i {
        0..=5 => (8, i),
        6 => (8, 7),
        7 => (8, 8),
        8 => (7, 8),
        _ => (14 - i, 8),
    };
    let second = if i < 8 {
        (n - 1 - i, 8)
    } else {
        (8, n - 15 + i)
    };
    (first, second)
}

/// §7.10: the two places (x, y) of version bit `i`, 0 the least significant.
fn version_cells(n: usize, i: usize) -> ((usize, usize), (usize, usize)) {
    let (a, b) = (n - 11 + i % 3, i / 3);
    ((a, b), (b, a))
}

/// Annex C: the 15-bit format code of 5 data bits.
fn format_code(data: u32) -> u32 {
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    ((data << 10) | rem) ^ 0x5412
}

/// Annex D: the 18-bit version code.
fn version_code(version: u32) -> u32 {
    let mut rem = version;
    for _ in 0..12 {
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
    }
    (version << 12) | rem
}

/// §7.8.2 Table 10: the mask condition at row `i`, column `j`.
fn mask_bit(mask: u8, i: usize, j: usize) -> bool {
    match mask {
        0 => (i + j).is_multiple_of(2),
        1 => i.is_multiple_of(2),
        2 => j.is_multiple_of(3),
        3 => (i + j).is_multiple_of(3),
        4 => (i / 2 + j / 3).is_multiple_of(2),
        5 => (i * j) % 2 + (i * j) % 3 == 0,
        6 => ((i * j) % 2 + (i * j) % 3).is_multiple_of(2),
        _ => ((i + j) % 2 + (i * j) % 3).is_multiple_of(2),
    }
}

/// GF(256) with the field polynomial 0x11D (§7.5.2).
fn gf_mul(x: u8, y: u8) -> u8 {
    let mut z: u16 = 0;
    for i in (0..8).rev() {
        z = (z << 1) ^ ((z >> 7) * 0x11D);
        z ^= u16::from((y >> i) & 1) * u16::from(x);
    }
    u8::try_from(z).unwrap()
}

/// The error correction codewords of `data`: the remainder of data · x^ec
/// by the generator Π (x − α^i), i = 0 … ec − 1 (§7.5.2).
fn error_correction(data: &[u8], ec: usize) -> Vec<u8> {
    let mut g = vec![0u8; ec];
    g[ec - 1] = 1;
    let mut root = 1u8;
    for _ in 0..ec {
        for j in 0..ec {
            g[j] = gf_mul(g[j], root);
            if j + 1 < ec {
                g[j] ^= g[j + 1];
            }
        }
        root = gf_mul(root, 2);
    }
    let mut r = vec![0u8; ec];
    for &b in data {
        let factor = b ^ r.remove(0);
        r.push(0);
        for (k, c) in g.iter().enumerate() {
            r[k] ^= gf_mul(*c, factor);
        }
    }
    r
}

/// The data codewords of `version` at level H.
pub fn data_codewords(version: usize) -> usize {
    let l = layout(version);
    let modules = l.parts.iter().filter(|p| **p == Part::Data).count();
    modules / 8 - EC_H[version - 1] * BLOCKS_H[version - 1]
}

/// Reads a `size × size` matrix (1 dark) with its 4-module quiet zone.
pub fn read(size: usize, m: &[u8]) -> Result<Symbol, String> {
    if m.len() != size * size || m.iter().any(|v| *v > 1) {
        return Err("not a square of 0 and 1".into());
    }
    let n = size.checked_sub(8).ok_or("too small")?;
    for y in 0..size {
        for x in 0..size {
            let inside = (4..size - 4).contains(&x) && (4..size - 4).contains(&y);
            if !inside && m[y * size + x] != 0 {
                return Err(format!("a dark module in the quiet zone at {x},{y}"));
            }
        }
    }
    if n < 21 || !(n - 17).is_multiple_of(4) || (n - 17) / 4 > 40 {
        return Err(format!("{n} is not a symbol size"));
    }
    let version = (n - 17) / 4;
    let dark = |x: usize, y: usize| m[(y + 4) * size + x + 4] == 1;
    let l = layout(version);
    for y in 0..n {
        for x in 0..n {
            if let Part::Fixed(want) = l.part(x, y)
                && dark(x, y) != want
            {
                return Err(format!("function pattern wrong at {x},{y}"));
            }
        }
    }
    let (mut first, mut second) = (0u32, 0u32);
    for i in 0..15 {
        let (a, b) = format_cells(n, i);
        first |= u32::from(dark(a.0, a.1)) << i;
        second |= u32::from(dark(b.0, b.1)) << i;
    }
    if first != second {
        return Err("the format copies differ".into());
    }
    let data = (0..32)
        .find(|d| format_code(*d) == first)
        .ok_or("no format code matches")?;
    if data >> 3 != 0b10 {
        return Err(format!("level bits {:02b}, not H", data >> 3));
    }
    let mask = u8::try_from(data & 7).unwrap();
    if version >= 7 {
        let want = version_code(u32::try_from(version).unwrap());
        for i in 0..18 {
            let (a, b) = version_cells(n, i);
            let bit = (want >> i) & 1 == 1;
            if dark(a.0, a.1) != bit || dark(b.0, b.1) != bit {
                return Err("version information wrong".into());
            }
        }
    }
    // §7.7.3: two-module columns from the right, up then down, column 6 skipped.
    let mut bits = Vec::new();
    let mut right = n - 1;
    loop {
        if right == 6 {
            right = 5;
        }
        let upward = (right + 1) & 2 == 0;
        for vert in 0..n {
            let y = if upward { n - 1 - vert } else { vert };
            for x in [right, right - 1] {
                if l.part(x, y) == Part::Data {
                    bits.push(dark(x, y) ^ mask_bit(mask, y, x));
                }
            }
        }
        if right < 2 {
            break;
        }
        right -= 2;
    }
    let total = bits.len() / 8;
    if bits[total * 8..].iter().any(|b| *b) {
        return Err("a remainder bit is not 0".into());
    }
    let codewords: Vec<u8> = bits[..total * 8]
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |a, b| (a << 1) | u8::from(*b)))
        .collect();
    // §7.6: the blocks, the shorter ones first.
    let (ec, blocks) = (EC_H[version - 1], BLOCKS_H[version - 1]);
    let long = total % blocks;
    let short_data = total / blocks - ec;
    let len = |b: usize| short_data + usize::from(b >= blocks - long);
    let mut data_blocks = vec![Vec::new(); blocks];
    let mut k = 0;
    for i in 0..=short_data {
        for (b, block) in data_blocks.iter_mut().enumerate() {
            if i < len(b) {
                block.push(codewords[k]);
                k += 1;
            }
        }
    }
    let mut ec_blocks = vec![Vec::new(); blocks];
    for _ in 0..ec {
        for block in &mut ec_blocks {
            block.push(codewords[k]);
            k += 1;
        }
    }
    if k != total {
        return Err("the codeword count is wrong".into());
    }
    for (d, e) in data_blocks.iter().zip(&ec_blocks) {
        if error_correction(d, ec) != *e {
            return Err("an error correction codeword is wrong".into());
        }
    }
    let stream: Vec<u8> = data_blocks.concat();
    let segments = segments(&stream, version)?;
    Ok(Symbol {
        version,
        mask,
        segments,
    })
}

struct Bits<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn left(&self) -> usize {
        self.bytes.len() * 8 - self.pos
    }

    fn take(&mut self, n: usize) -> Result<u32, String> {
        if n > self.left() {
            return Err("the data ends inside a segment".into());
        }
        let mut v = 0;
        for _ in 0..n {
            let bit = (self.bytes[self.pos / 8] >> (7 - self.pos % 8)) & 1;
            v = (v << 1) | u32::from(bit);
            self.pos += 1;
        }
        Ok(v)
    }
}

/// §7.4: the segments, then the terminator (shorter or none at the very
/// end), zero bits to the codeword boundary, and pad codewords 0xEC 0x11.
pub fn segments(stream: &[u8], version: usize) -> Result<Vec<Segment>, String> {
    let mut r = Bits {
        bytes: stream,
        pos: 0,
    };
    let mut out = Vec::new();
    loop {
        if r.left() < 4 {
            if r.take(r.left())? != 0 {
                return Err("a short terminator is not 0".into());
            }
            break;
        }
        match r.take(4)? {
            0 => break,
            0b0111 => {
                let first = r.take(8)?;
                // §7.4.2: one byte for 0 to 127, two for 128 to 16,383,
                // three above (26 is one byte, never 0x80 0x1A).
                let (value, least) = if first & 0x80 == 0 {
                    (first, 0)
                } else if first & 0xC0 == 0x80 {
                    (((first & 0x3F) << 8) | r.take(8)?, 128)
                } else if first & 0xE0 == 0xC0 {
                    (((first & 0x1F) << 16) | r.take(16)?, 16_384)
                } else {
                    return Err("a bad ECI designator".into());
                };
                if value < least {
                    return Err(format!("ECI {value} in a longer designator than it needs"));
                }
                out.push(Segment::Eci(value));
            }
            0b0100 => {
                let count = r.take(if version <= 9 { 8 } else { 16 })?;
                let mut bytes = Vec::new();
                for _ in 0..count {
                    bytes.push(u8::try_from(r.take(8)?).unwrap());
                }
                out.push(Segment::Bytes(bytes));
            }
            other => return Err(format!("mode {other:04b} is not read here")),
        }
    }
    let fill = (8 - r.pos % 8) % 8;
    if r.take(fill.min(r.left()))? != 0 {
        return Err("a fill bit is not 0".into());
    }
    for (i, b) in stream[r.pos.div_ceil(8)..].iter().enumerate() {
        if *b != [0xEC, 0x11][i % 2] {
            return Err("a pad codeword is wrong".into());
        }
    }
    Ok(out)
}

/// The module matrix of printed QR rows: each line N cells of space, U+2580,
/// U+2584 or U+2588 (upper and lower module), ended by LF; with `sgr` each
/// line also between the fixed colours. ceil(N/2) lines; with N odd the
/// lower half of the last line must be white.
pub fn from_cells(text: &str, sgr: bool) -> Result<(usize, Vec<u8>), String> {
    let body = text.strip_suffix('\n').ok_or("no final LF")?;
    let mut rows = Vec::new();
    for line in body.split('\n') {
        let cells = if sgr {
            line.strip_prefix("\x1b[30;47m")
                .and_then(|l| l.strip_suffix("\x1b[0m"))
                .ok_or_else(|| format!("a line without the fixed colours: {line:?}"))?
        } else {
            line
        };
        let row: Result<Vec<(u8, u8)>, String> = cells
            .chars()
            .map(|c| match c {
                ' ' => Ok((0, 0)),
                '\u{2580}' => Ok((1, 0)),
                '\u{2584}' => Ok((0, 1)),
                '\u{2588}' => Ok((1, 1)),
                other => Err(format!("{other:?} is not a block cell")),
            })
            .collect();
        rows.push(row?);
    }
    let size = rows[0].len();
    if rows.iter().any(|r| r.len() != size) || rows.len() != size.div_ceil(2) {
        return Err(format!("{} lines of {size} cells", rows.len()));
    }
    let mut m = vec![0u8; size * size];
    for (t, row) in rows.iter().enumerate() {
        for (x, (top, bottom)) in row.iter().enumerate() {
            m[2 * t * size + x] = *top;
            if 2 * t + 1 < size {
                m[(2 * t + 1) * size + x] = *bottom;
            } else if *bottom != 0 {
                return Err("the padding half row is not white".into());
            }
        }
    }
    Ok((size, m))
}

/// The value of printed rows: exactly one ECI 26 and one byte segment, at
/// the smallest version that holds them at level H.
pub fn value(text: &str, sgr: bool) -> Vec<u8> {
    let (size, m) = from_cells(text, sgr).unwrap_or_else(|e| panic!("{e}: {text:?}"));
    let s = read(size, &m).unwrap();
    let [Segment::Eci(26), Segment::Bytes(bytes)] = s.segments.as_slice() else {
        panic!("not one ECI 26 and one byte segment: {:?}", s.segments);
    };
    assert_eq!(s.version, smallest(bytes.len()), "the smallest version");
    bytes.clone()
}

/// The smallest version at H whose data holds ECI 26 and `len` bytes.
pub fn smallest(len: usize) -> usize {
    (1..=40)
        .find(|v| {
            let count = if *v <= 9 { 8 } else { 16 };
            4 + 8 + 4 + count + 8 * len <= data_codewords(*v) * 8
        })
        .unwrap_or(41)
}

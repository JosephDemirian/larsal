//! Icons (MOD-06): the standard set, which icon an item shows, the custom
//! icon list (add with de-duplication, remove, purge), applying a group's
//! icon to its children, and the guard in front of image decoding.
//!
//! Decoding uses `png` for PNG and Larsal's own reader for ICO (LD-109; E0-S7
//! R10): only PNG and ICO are accepted; JPEG and every other format count
//! as unsupported. Before any decode the byte and pixel limits are checked
//! from the header, and an ICO's directory is checked so nothing is
//! allocated beyond the input and the limits.
//! Scaling is Larsal's own (an alpha-weighted box filter), and the result is
//! always re-encoded as PNG (LD-65).
//!
//! Guarantees: stored icon bytes are never changed; a decode failure never
//! stops anything; removing an icon records a deleted object (MOD-06.14).

use crate::edit::{change_entry, edit_group};
use crate::{Error, tree};
use larsal_model::{CustomIcon, DeletedObject, Entry, Icon, Time, Uuid, Vault};
use std::collections::HashSet;

/// Standard icon numbers run from 0 to 68 (MOD-06.1).
pub const STANDARD_COUNT: i32 = 69;
/// The icon of a new entry (MOD-06.2).
pub const ENTRY_DEFAULT: i32 = 0;
/// The icon of a new group and of an old recycle bin (MOD-06.2).
pub const GROUP_DEFAULT: i32 = 48;
/// The icon of an entry or group the browser bridge makes (MOD-06.2).
pub const BROWSER: i32 = 1;
/// The icon of a passkey entry and its group (MOD-06.2).
pub const PASSKEY: i32 = 13;
/// The edge of a stored custom icon (MOD-06.8).
pub const MAX_EDGE: u32 = 128;
/// Failed file names listed after adding (MOD-06.6).
pub const FAILED_SHOWN: usize = 8;

/// Larsal's input limits for every decode (MOD-06.7, D-06-3). Tests lower
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Input bytes.
    pub bytes: usize,
    /// Pixels on each side.
    pub pixels: u32,
}

impl Limits {
    /// 16 MiB and 4,096 pixels.
    pub const DEFAULT: Self = Self {
        bytes: 16 << 20,
        pixels: 4096,
    };
}

/// The image decoder: turns checked PNG or ICO bytes into PNG bytes. It
/// enforces `limits` again on what it decodes (an ICO can hold a PNG).
/// [`Images`] is Larsal's icon decoder and keeps at most 128 × 128 pixels
/// (MOD-06.8: larger images become exactly 128 × 128, smaller ones keep
/// their size); [`FullSize`] keeps the image's own size for the attachment
/// preview. Tests may give their own.
pub trait Codec {
    /// The PNG bytes, or `None` when the image cannot be decoded.
    fn to_png(&self, data: &[u8], format: Format, limits: &Limits) -> Option<Vec<u8>>;
}

/// The accepted image formats (LD-109).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// PNG.
    Png,
    /// ICO.
    Ico,
}

/// The format from the first bytes; `None` (unsupported) for anything
/// else, JPEG included (LD-109).
#[must_use]
pub fn format(data: &[u8]) -> Option<Format> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(Format::Png)
    } else if data.starts_with(b"\x00\x00\x01\x00") {
        Some(Format::Ico)
    } else {
        None
    }
}

fn be32(d: &[u8], at: usize) -> Option<u32> {
    let b: [u8; 4] = d.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(b))
}

/// The pixel size the header declares, without decoding any pixel.
#[must_use]
pub fn header_size(data: &[u8], f: Format) -> Option<(u32, u32)> {
    match f {
        Format::Png => (data.get(12..16)? == b"IHDR").then_some((be32(data, 16)?, be32(data, 20)?)),
        Format::Ico => {
            let count = usize::from(*data.get(4)?) | usize::from(*data.get(5)?) << 8;
            let edge = |b: u8| if b == 0 { 256 } else { u32::from(b) };
            (0..count)
                .try_fold((0u32, 0u32), |(w, h), i| {
                    let at = i.checked_mul(16)?.checked_add(6)?;
                    Some((
                        w.max(edge(*data.get(at)?)),
                        h.max(edge(*data.get(at.checked_add(1)?)?)),
                    ))
                })
                .filter(|_| count > 0)
        }
    }
}

/// The guard before any decode (MOD-06.7, MOD-06.19): input within the byte
/// limit, PNG or ICO, and a declared size within the pixel limit.
#[must_use]
pub fn check(data: &[u8], limits: &Limits) -> Option<Format> {
    if data.len() > limits.bytes {
        return None;
    }
    let f = format(data)?;
    let (w, h) = header_size(data, f)?;
    (w > 0 && h > 0 && w <= limits.pixels && h <= limits.pixels).then_some(f)
}

/// Checks, then decodes, scales and encodes PNG (MOD-06.6 steps 1 and 2).
#[must_use]
pub fn decode(data: &[u8], codec: &dyn Codec, limits: &Limits) -> Option<Vec<u8>> {
    let f = check(data, limits)?;
    codec.to_png(data, f, limits)
}

/// Larsal's image decoder (LD-109): PNG with `png`, ICO with Larsal's own reader;
/// Larsal's own scaling; PNG out.
#[derive(Debug, Clone, Copy)]
pub struct Images;

impl Codec for Images {
    fn to_png(&self, data: &[u8], format: Format, limits: &Limits) -> Option<Vec<u8>> {
        let (w, h, rgba) = match format {
            Format::Png => decode_png(data, limits)?,
            Format::Ico => decode_ico(data, limits)?,
        };
        let (w, h, rgba) = scale(w, h, rgba)?;
        encode_png(w, h, &rgba)
    }
}

/// The attachment preview's decoder (MOD-05.9, LD-65): the same checks and
/// decoders as [`Images`], re-encoded as PNG at the image's own size (no
/// MOD-06.8 scaling, so the shape stays; the pixel limit bounds it).
#[derive(Debug, Clone, Copy)]
pub struct FullSize;

impl Codec for FullSize {
    fn to_png(&self, data: &[u8], format: Format, limits: &Limits) -> Option<Vec<u8>> {
        let (w, h, rgba) = match format {
            Format::Png => decode_png(data, limits)?,
            Format::Ico => decode_ico(data, limits)?,
        };
        encode_png(w, h, &rgba)
    }
}

/// Whether a PNG's chunks keep the PNG standard's size rules, checked by
/// Larsal before the crate reads them (LD-117, F-044): every chunk inside the
/// file, `IHDR` first and exactly 13 bytes, `PLTE` 3 to 768 bytes in
/// threes, `tRNS` within its size for the colour type (2 bytes for grey, 6
/// for RGB, at most one per palette entry, none with alpha), and an `IEND`.
fn png_chunks_ok(data: &[u8]) -> bool {
    let mut at = 8usize;
    let (mut color, mut palette, mut first) = (None, None, true);
    loop {
        let Some(len) = be32(data, at).and_then(|l| usize::try_from(l).ok()) else {
            return false;
        };
        let Some(kind) = data.get(at.saturating_add(4)..at.saturating_add(8)) else {
            return false;
        };
        let end = at
            .checked_add(12)
            .and_then(|x| x.checked_add(len))
            .filter(|&e| e <= data.len());
        let Some(end) = end else { return false };
        let body = data.get(at.saturating_add(8)..end.saturating_sub(4));
        match kind {
            b"IHDR" if first && len == 13 => color = body.and_then(|b| b.get(9)).copied(),
            _ if first => return false,
            b"IHDR" => return false,
            b"PLTE" if (3..=768).contains(&len) && len % 3 == 0 && palette.is_none() => {
                palette = Some(len / 3);
            }
            b"PLTE" => return false,
            b"tRNS" => {
                let fits = match color {
                    Some(0) => len == 2,
                    Some(2) => len == 6,
                    Some(3) => palette.is_some_and(|n| len <= n),
                    _ => false,
                };
                if !fits {
                    return false;
                }
            }
            b"IEND" => return true,
            _ => {}
        }
        first = false;
        at = end;
    }
}

/// Decodes a PNG to 8-bit RGBA, within the pixel limit and a memory budget
/// of 8 bytes per allowed pixel (16-bit RGBA at most); the crate checks
/// CRCs and stops at the declared size, so trailing compressed data is
/// never inflated. The chunk structure is checked first (LD-117).
fn decode_png(data: &[u8], limits: &Limits) -> Option<(u32, u32, Vec<u8>)> {
    if !png_chunks_ok(data) {
        return None;
    }
    let edge = usize::try_from(limits.pixels).ok()?;
    let budget = png::Limits {
        bytes: edge.checked_mul(edge)?.checked_mul(8)?,
    };
    let mut d = png::Decoder::new_with_limits(std::io::Cursor::new(data), budget);
    d.set_transformations(png::Transformations::normalize_to_color8());
    let mut r = d.read_info().ok()?;
    let (w, h) = r.info().size();
    if w == 0 || h == 0 || w > limits.pixels || h > limits.pixels {
        return None;
    }
    let mut buf = vec![0u8; r.output_buffer_size()?];
    let out = r.next_frame(&mut buf).ok()?;
    let px = buf.get(..out.buffer_size())?;
    let rgba: Vec<u8> = match out.color_type {
        png::ColorType::Rgba => px.to_vec(),
        png::ColorType::Rgb => px
            .as_chunks::<3>()
            .0
            .iter()
            .flat_map(|&[r, g, b]| [r, g, b, 255])
            .collect(),
        png::ColorType::GrayscaleAlpha => px
            .as_chunks::<2>()
            .0
            .iter()
            .flat_map(|&[g, a]| [g, g, g, a])
            .collect(),
        png::ColorType::Grayscale => px.iter().flat_map(|&g| [g, g, g, 255]).collect(),
        png::ColorType::Indexed => return None,
    };
    let want = usize::try_from(w)
        .ok()?
        .checked_mul(usize::try_from(h).ok()?)?
        .checked_mul(4)?;
    (rgba.len() == want).then_some((w, h, rgba))
}

fn le32(d: &[u8], at: usize) -> Option<usize> {
    let b: [u8; 4] = d.get(at..at.checked_add(4)?)?.try_into().ok()?;
    usize::try_from(u32::from_le_bytes(b)).ok()
}

/// The most images one ICO may list (the format allows 65,535; a site
/// icon has a few). An ICO that lists more is refused.
pub const MAX_ICO_IMAGES: usize = 256;

fn le16(d: &[u8], at: usize) -> Option<u16> {
    let b: [u8; 2] = d.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(b))
}

fn le_i32(d: &[u8], at: usize) -> Option<i32> {
    let b: [u8; 4] = d.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(i32::from_le_bytes(b))
}

/// Decodes the largest image of an ICO with Larsal's own reader (E0-S7 R10,
/// in place of `ico`). The directory is checked first: at most
/// [`MAX_ICO_IMAGES`] images, each with a zero reserved byte and its data
/// inside the input, and all the data together no larger than the input.
/// Each image's size is read from its own header (a PNG of 8 bits per
/// channel, or a BMP), else the directory's bytes count (0 is 256). The
/// largest image, the last of equals, must be within the pixel limit; a PNG
/// then goes through [`check`] and [`decode_png`] with the same limits, a
/// BMP through [`decode_bmp`].
fn decode_ico(data: &[u8], limits: &Limits) -> Option<(u32, u32, Vec<u8>)> {
    let count = usize::from(le16(data, 4)?);
    if count > MAX_ICO_IMAGES {
        return None;
    }
    let mut total = 0usize;
    let mut largest: Option<(u64, &[u8], u32, u32)> = None;
    for i in 0..count {
        let at = i.checked_mul(16)?.checked_add(6)?;
        let entry = data.get(at..at.checked_add(16)?)?;
        let (size, offset) = (le32(entry, 8)?, le32(entry, 12)?);
        total = total.checked_add(size)?;
        if *entry.get(3)? != 0 || total > data.len() {
            return None;
        }
        let image = data.get(offset..offset.checked_add(size)?)?;
        let edge = |b: u8| if b == 0 { 256 } else { u32::from(b) };
        let (w, h) = image_size(image).unwrap_or((edge(*entry.first()?), edge(*entry.get(1)?)));
        let area = u64::from(w).saturating_mul(u64::from(h));
        if largest.is_none_or(|(most, ..)| area >= most) {
            largest = Some((area, image, w, h));
        }
    }
    let (_, image, w, h) = largest?;
    if w > limits.pixels || h > limits.pixels {
        return None;
    }
    if image.starts_with(b"\x89PNG") {
        return check(image, limits)
            .filter(|f| *f == Format::Png)
            .and_then(|_| decode_png(image, limits));
    }
    decode_bmp(image)
}

/// An ICO image's size from its own header: a PNG's (8 bits per channel
/// only), or a BMP's (a 40-byte header, width at least 1, the height field
/// even and its half at least 1: it counts the colour rows and the mask's).
fn image_size(image: &[u8]) -> Option<(u32, u32)> {
    if image.starts_with(b"\x89PNG") {
        let r = png::Decoder::new(std::io::Cursor::new(image))
            .read_info()
            .ok()?;
        let info = r.info();
        return (info.width >= 1 && info.height >= 1 && info.bit_depth == png::BitDepth::Eight)
            .then_some((info.width, info.height));
    }
    if le32(image, 0)? != 40 {
        return None;
    }
    let w = u32::try_from(le_i32(image, 4)?).ok().filter(|&w| w >= 1)?;
    let h = le_i32(image, 8)?;
    if h % 2 != 0 {
        return None;
    }
    let h = u32::try_from(h / 2).ok().filter(|&h| h >= 1)?;
    Some((w, h))
}

/// Decodes an ICO's BMP image (the Windows icon form of a device
/// independent bitmap): a 40-byte header, a colour table for 1, 4 and 8
/// bits per pixel (always the full 2, 16 or 256 colours), the colour rows
/// from the bottom up, each padded to 4 bytes, then for every depth but 32
/// the transparency mask (1 bit per pixel, set is transparent) in rows of
/// the same kind. 16 bits are 5 bits each of red, green and blue; 32 bits
/// carry their own alpha. Compression is not read. Refused: another depth,
/// data that ends early, and (F-043) a palette image whose "colours used"
/// is set and smaller than its depth allows. Never reads or writes past
/// its input: a pixel value without a colour is refused too.
fn decode_bmp(d: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let (w, h) = image_size(d)?;
    let bits = le16(d, 14)?;
    let used = le32(d, 32)?;
    let colours = match bits {
        1 => 2,
        4 => 16,
        8 => 256,
        16 | 24 | 32 => 0,
        _ => return None,
    };
    if colours > 0 && used != 0 && used < colours {
        return None;
    }
    let (wu, hu) = (usize::try_from(w).ok()?, usize::try_from(h).ok()?);
    let table_end = colours.checked_mul(4)?.checked_add(40)?;
    let table = d.get(40..table_end)?.as_chunks::<4>().0;
    let row = wu
        .checked_mul(usize::from(bits))?
        .div_ceil(8)
        .checked_next_multiple_of(4)?;
    let colour_end = hu.checked_mul(row)?.checked_add(table_end)?;
    let rows = d.get(table_end..colour_end)?;
    let mut rgba = vec![255u8; wu.checked_mul(hu)?.checked_mul(4)?];
    let width = wu.checked_mul(4)?;
    let (shifts, mask): (&[u8], u8) = match bits {
        1 => (&[7, 6, 5, 4, 3, 2, 1, 0], 1),
        4 => (&[4, 0], 15),
        _ => (&[0], 255),
    };
    for (out, line) in rgba
        .chunks_exact_mut(width)
        .rev()
        .zip(rows.chunks_exact(row))
    {
        let out = out.as_chunks_mut::<4>().0;
        match bits {
            1 | 4 | 8 => {
                let indexes = line
                    .iter()
                    .flat_map(|&b| shifts.iter().map(move |&s| usize::from((b >> s) & mask)));
                for (px, i) in out.iter_mut().zip(indexes) {
                    let &[b, g, r, _] = table.get(i)?;
                    *px = [r, g, b, 255];
                }
            }
            16 => {
                let five =
                    |c: u16| u8::try_from((c & 31).saturating_mul(255).saturating_add(15) / 31);
                for (px, v) in out.iter_mut().zip(line.as_chunks::<2>().0) {
                    let v = u16::from_le_bytes(*v);
                    *px = [five(v >> 10).ok()?, five(v >> 5).ok()?, five(v).ok()?, 255];
                }
            }
            24 => {
                for (px, &[b, g, r]) in out.iter_mut().zip(line.as_chunks::<3>().0) {
                    *px = [r, g, b, 255];
                }
            }
            _ => {
                for (px, &[b, g, r, a]) in out.iter_mut().zip(line.as_chunks::<4>().0) {
                    *px = [r, g, b, a];
                }
            }
        }
    }
    if bits != 32 {
        let mask_row = wu.div_ceil(8).checked_next_multiple_of(4)?;
        let mask_end = hu.checked_mul(mask_row)?.checked_add(colour_end)?;
        let masks = d.get(colour_end..mask_end)?;
        for (out, line) in rgba
            .chunks_exact_mut(width)
            .rev()
            .zip(masks.chunks_exact(mask_row))
        {
            let clear = line
                .iter()
                .flat_map(|&b| (0..8).rev().map(move |s| (b >> s) & 1 == 1));
            for (px, clear) in out.as_chunks_mut::<4>().0.iter_mut().zip(clear) {
                if clear {
                    px[3] = 0;
                }
            }
        }
    }
    Some((w, h, rgba))
}

/// MOD-06.8 with a smooth filter: wider or taller than 128 becomes exactly
/// 128 × 128, each pixel the alpha-weighted mean of the source box it
/// covers (at least one source pixel); smaller images stay as they are.
fn scale(w: u32, h: u32, rgba: Vec<u8>) -> Option<(u32, u32, Vec<u8>)> {
    let (tw, th) = scaled_size(w, h);
    if (tw, th) == (w, h) {
        return Some((w, h, rgba));
    }
    let (sw, sh) = (usize::try_from(w).ok()?, usize::try_from(h).ok()?);
    let (tw_, th_) = (usize::try_from(tw).ok()?, usize::try_from(th).ok()?);
    let span = |t: usize, src: usize, dst: usize| -> Option<(usize, usize)> {
        let a = t.checked_mul(src)?.checked_div(dst)?;
        let b = t.checked_add(1)?.checked_mul(src)?.checked_div(dst)?;
        Some((a, b.max(a.checked_add(1)?).min(src)))
    };
    let mut out = Vec::with_capacity(tw_.checked_mul(th_)?.checked_mul(4)?);
    for ty in 0..th_ {
        let (y0, y1) = span(ty, sh, th_)?;
        for tx in 0..tw_ {
            let (x0, x1) = span(tx, sw, tw_)?;
            let (mut rgb, mut alpha, mut n) = ([0u64; 3], 0u64, 0u64);
            for y in y0..y1 {
                for x in x0..x1 {
                    let i = y.checked_mul(sw)?.checked_add(x)?.checked_mul(4)?;
                    let p = rgba.get(i..i.checked_add(4)?)?;
                    let a = u64::from(*p.get(3)?);
                    for (sum, &c) in rgb.iter_mut().zip(p) {
                        *sum = sum.saturating_add(u64::from(c).saturating_mul(a));
                    }
                    alpha = alpha.saturating_add(a);
                    n = n.saturating_add(1);
                }
            }
            for sum in rgb {
                out.push(u8::try_from(sum.checked_div(alpha).unwrap_or(0)).unwrap_or(255));
            }
            out.push(u8::try_from(alpha.checked_div(n).unwrap_or(0)).unwrap_or(255));
        }
    }
    Some((tw, th, out))
}

/// 8-bit RGBA as PNG bytes; the same pixels always give the same bytes, so
/// de-duplication by bytes works (MOD-06.9).
fn encode_png(w: u32, h: u32, rgba: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut e = png::Encoder::new(&mut out, w, h);
    e.set_color(png::ColorType::Rgba);
    e.set_depth(png::BitDepth::Eight);
    let mut writer = e.write_header().ok()?;
    writer.write_image_data(rgba).ok()?;
    writer.finish().ok()?;
    Some(out)
}

/// The stored size of an image (MOD-06.8): exactly 128 × 128 when wider or
/// taller than 128, else unchanged.
#[must_use]
pub fn scaled_size(w: u32, h: u32) -> (u32, u32) {
    if w > MAX_EDGE || h > MAX_EDGE {
        (MAX_EDGE, MAX_EDGE)
    } else {
        (w, h)
    }
}

// ---------------------------------------------------------------------------
// What an item shows (MOD-06.4, MOD-06.16, MOD-06.19).

/// Entry or group: their default icons differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An entry (default 0).
    Entry,
    /// A group (default 48).
    Group,
}

impl Kind {
    fn default_icon(self) -> i32 {
        match self {
            Self::Entry => ENTRY_DEFAULT,
            Self::Group => GROUP_DEFAULT,
        }
    }
}

/// The picture an item shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shown {
    /// A standard icon, 0 to 68.
    Standard(i32),
    /// A custom icon that decodes.
    Custom(Uuid),
}

/// The icon an item shows (MOD-06.4, MOD-06.16): a standard number outside
/// 0 to 68 shows icon 0; a custom icon whose id names no icon, or whose
/// bytes do not decode, shows the default icon of the item's kind. The
/// stored value is never changed (D-06-1).
#[must_use]
pub fn shown(vault: &Vault, icon: Icon, kind: Kind, codec: &dyn Codec, limits: &Limits) -> Shown {
    match icon {
        Icon::Standard(n) if (0..STANDARD_COUNT).contains(&n) => Shown::Standard(n),
        Icon::Standard(_) => Shown::Standard(ENTRY_DEFAULT),
        Icon::Custom(id) => match screen_png(vault, id, codec, limits) {
            Some(_) => Shown::Custom(id),
            None => Shown::Standard(kind.default_icon()),
        },
    }
}

/// The PNG bytes the screen layer gets for custom icon `id` (MOD-06.19,
/// LD-65): always re-encoded, never the stored bytes; `None` (the default
/// icon) when the id names no icon or the bytes fail the guard or the
/// decode. The vault's bytes stay as they are.
#[must_use]
pub fn screen_png(vault: &Vault, id: Uuid, codec: &dyn Codec, limits: &Limits) -> Option<Vec<u8>> {
    let icon = vault.meta.custom_icons.iter().find(|i| i.uuid == id)?;
    decode(&icon.data, codec, limits)
}

// ---------------------------------------------------------------------------
// The custom icon list (MOD-06.5, MOD-06.9, MOD-06.10).

/// The first icon in stored order whose bytes equal `png` (MOD-06.9).
#[must_use]
pub fn find_png(vault: &Vault, png: &[u8]) -> Option<Uuid> {
    vault
        .meta
        .custom_icons
        .iter()
        .find(|i| i.data == png)
        .map(|i| i.uuid)
}

/// Adds PNG bytes to the custom icon list at once, as its own change
/// (MOD-06.10): an icon with equal bytes is used instead (MOD-06.9);
/// otherwise a new icon with a fresh id goes at the end (MOD-06.5). Returns
/// the icon's id and whether it was added.
///
/// # Errors
/// `RandomSource`.
pub fn add_png(
    vault: &mut Vault,
    png: Vec<u8>,
    name: String,
    time: Option<Time>,
) -> Result<(Uuid, bool), Error> {
    if let Some(id) = find_png(vault, &png) {
        return Ok((id, false));
    }
    let taken: HashSet<Uuid> = vault.meta.custom_icons.iter().map(|i| i.uuid).collect();
    let id = tree::fresh_id(|u| taken.contains(&u))?;
    vault.meta.custom_icons.push(CustomIcon {
        uuid: id,
        name,
        last_modified: time,
        data: png,
        unknown: Vec::new(),
    });
    Ok((id, true))
}

/// The icon name from a file name (MOD-06.6): up to its first dot.
#[must_use]
pub fn icon_name(file: &str) -> String {
    file.split('.').next().unwrap_or("").to_owned()
}

/// What adding files did (MOD-06.6), for `msg.icons_added`,
/// `msg.icons_exist` and `msg.icons_failed`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Added {
    /// Files picked.
    pub picked: usize,
    /// New icons.
    pub added: usize,
    /// Files whose icon already existed.
    pub existing: usize,
    /// Names of failed files, at most the first 8.
    pub failed: Vec<String>,
    /// The icon of the last file that did not fail: the picker's selection.
    pub selected: Option<Uuid>,
}

/// Adds custom icons from picked files, in order (MOD-06.6): decode, scale,
/// de-duplicate, else add with the name up to the first dot and the time
/// `now`.
///
/// # Errors
/// `RandomSource` (icons added before it stay, as each joins at once).
pub fn add_files(
    vault: &mut Vault,
    files: &[(&str, &[u8])],
    codec: &dyn Codec,
    limits: &Limits,
    now: Time,
) -> Result<Added, Error> {
    let mut out = Added {
        picked: files.len(),
        ..Added::default()
    };
    for (file, data) in files {
        let Some(png) = decode(data, codec, limits) else {
            if out.failed.len() < FAILED_SHOWN {
                out.failed.push((*file).to_owned());
            }
            continue;
        };
        let (id, added) = add_png(vault, png, icon_name(file), Some(now))?;
        if added {
            out.added = out.added.saturating_add(1);
        } else {
            out.existing = out.existing.saturating_add(1);
        }
        out.selected = Some(id);
    }
    Ok(out)
}

/// An icon downloaded for one entry on its edit screen (MOD-06.11):
/// decoded and de-duplicated; a new icon gets an empty name and the time
/// `now`. `None` when the download gives nothing usable; else the id and
/// whether it is new.
///
/// # Errors
/// `RandomSource`.
pub fn add_download(
    vault: &mut Vault,
    data: &[u8],
    codec: &dyn Codec,
    limits: &Limits,
    now: Time,
) -> Result<Option<(Uuid, bool)>, Error> {
    match decode(data, codec, limits) {
        Some(png) => add_png(vault, png, String::new(), Some(now)).map(Some),
        None => Ok(None),
    }
}

/// A bulk download for the selected entries of one site (MOD-06.11): a new
/// icon gets no name and no time; the icon is set on every given entry as
/// one change batch (modification times move, no history item). Returns
/// the icon's id, or `None` when the download gives nothing usable.
///
/// # Errors
/// `NoSuchEntry` for any id (nothing changes then); `RandomSource`.
pub fn apply_bulk_download(
    vault: &mut Vault,
    entries: &[Uuid],
    data: &[u8],
    codec: &dyn Codec,
    limits: &Limits,
    now: Time,
) -> Result<Option<Uuid>, Error> {
    if entries.iter().any(|&id| tree::entry(vault, id).is_none()) {
        return Err(Error::NoSuchEntry);
    }
    let Some(png) = decode(data, codec, limits) else {
        return Ok(None);
    };
    let (icon, _) = add_png(vault, png, String::new(), None)?;
    for &id in entries {
        change_entry(vault, id, now, |e| e.icon = Icon::Custom(icon))?;
    }
    Ok(Some(icon))
}

/// The picker's choice on an edit screen (MOD-06.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// A standard icon number.
    Standard(i32),
    /// "Custom", with the selected custom icon, if any.
    Custom(Option<Uuid>),
}

/// The icon a choice stores (MOD-06.12): "custom" with nothing selected
/// gives the item's default icon.
#[must_use]
pub fn picked(choice: Choice, kind: Kind) -> Icon {
    match choice {
        Choice::Standard(n) => Icon::Standard(n),
        Choice::Custom(Some(id)) => Icon::Custom(id),
        Choice::Custom(None) => Icon::Standard(kind.default_icon()),
    }
}

/// Applies group `id`'s icon to its children (MOD-06.13), after the
/// group's own save: `groups` = every group below it, `entries` = every
/// live entry in it and below it (history items untouched). Each item that
/// really changes gets a new modification time, no history item. Returns
/// how many items changed.
///
/// # Errors
/// `NoSuchGroup`.
pub fn apply_to_children(
    vault: &mut Vault,
    id: Uuid,
    groups: bool,
    entries: bool,
    now: Time,
) -> Result<usize, Error> {
    let g = tree::group(vault, id).ok_or(Error::NoSuchGroup)?;
    let icon = g.icon;
    let sub = g.subtree();
    let group_ids: Vec<Uuid> = sub.iter().skip(1).map(|x| x.uuid).collect();
    let entry_ids: Vec<Uuid> = sub
        .iter()
        .flat_map(|x| x.entries.iter().map(|e| e.uuid))
        .collect();
    let mut changed = 0usize;
    if groups {
        for gid in group_ids {
            let did = edit_group(vault, gid, now, |x| x.icon = icon)?;
            changed = changed.saturating_add(usize::from(did));
        }
    }
    if entries {
        for eid in entry_ids {
            let did = change_entry(vault, eid, now, |e| e.icon = icon)?;
            changed = changed.saturating_add(usize::from(did));
        }
    }
    Ok(changed)
}

// ---------------------------------------------------------------------------
// Removing and purging (MOD-06.14, MOD-06.15).

/// The icons used by live entries (the recycle bin included) and groups.
fn used(vault: &Vault) -> HashSet<Uuid> {
    let mut out = HashSet::new();
    for g in vault.root.subtree() {
        if let Icon::Custom(id) = g.icon {
            out.insert(id);
        }
        for e in &g.entries {
            if let Icon::Custom(id) = e.icon {
                out.insert(id);
            }
        }
    }
    out
}

/// Whether any of the selected icons has uses (MOD-06.14): then the screen
/// asks once, Delete or Skip.
#[must_use]
pub fn in_use(vault: &Vault, ids: &[Uuid]) -> bool {
    let u = used(vault);
    ids.iter().any(|id| u.contains(id))
}

/// Takes the icons in `gone` out of the vault (MOD-06.14, MOD-06.15): live
/// entries using one get icon 0 and groups 48, each with a new
/// modification time and no history item; history items get icon 0 with
/// their times unchanged; each icon is removed and recorded as a deleted
/// object at `now`. One change batch. Returns how many icons went.
fn take_out(vault: &mut Vault, gone: &HashSet<Uuid>, now: Time) -> usize {
    let hit = |i: Icon| matches!(i, Icon::Custom(id) if gone.contains(&id));
    let groups: Vec<Uuid> = vault
        .root
        .subtree()
        .iter()
        .filter(|g| hit(g.icon))
        .map(|g| g.uuid)
        .collect();
    let entries: Vec<Uuid> = vault
        .root
        .subtree()
        .iter()
        .flat_map(|g| g.entries.iter())
        .filter(|e| hit(e.icon))
        .map(|e| e.uuid)
        .collect();
    for id in groups {
        let _ = edit_group(vault, id, now, |g| g.icon = Icon::Standard(GROUP_DEFAULT));
    }
    for id in entries {
        let _ = change_entry(vault, id, now, |e| e.icon = Icon::Standard(ENTRY_DEFAULT));
    }
    let mut stack = vec![&mut vault.root];
    while let Some(g) = stack.pop() {
        for h in g
            .entries
            .iter_mut()
            .flat_map(|e: &mut Entry| e.history.iter_mut())
        {
            if hit(h.icon) {
                h.icon = Icon::Standard(ENTRY_DEFAULT);
            }
        }
        stack.extend(g.groups.iter_mut());
    }
    let before = vault.meta.custom_icons.len();
    let mut removed = Vec::new();
    vault.meta.custom_icons.retain(|i| {
        let go = gone.contains(&i.uuid);
        if go {
            removed.push(i.uuid);
        }
        !go
    });
    for uuid in removed {
        vault.deleted_objects.push(DeletedObject {
            uuid,
            deleted_at: now,
            unknown: Vec::new(),
        });
    }
    before.saturating_sub(vault.meta.custom_icons.len())
}

/// Removes the selected custom icons (MOD-06.14): icons without uses go;
/// icons with uses go only when the user answered Delete
/// (`delete_in_use`), else they stay. Returns how many icons went.
pub fn remove(vault: &mut Vault, ids: &[Uuid], delete_in_use: bool, now: Time) -> usize {
    let u = used(vault);
    let gone: HashSet<Uuid> = ids
        .iter()
        .copied()
        .filter(|id| delete_in_use || !u.contains(id))
        .collect();
    take_out(vault, &gone, now)
}

/// Purges every custom icon no live entry and no group uses (MOD-06.15),
/// icons used only by history items included. Returns how many went: 0
/// means `msg.icons_all_in_use`, else `msg.icons_purged`.
pub fn purge(vault: &mut Vault, now: Time) -> usize {
    let u = used(vault);
    let gone: HashSet<Uuid> = vault
        .meta
        .custom_icons
        .iter()
        .map(|i| i.uuid)
        .filter(|id| !u.contains(id))
        .collect();
    take_out(vault, &gone, now)
}

/// The addresses a website icon download asks, in order (APP-01.21,
/// LD-64, SN-02; F-094): with `service` (S-PRIV-01) the icon service for
/// the host, then for its base domain; then `/favicon.ico` at the root of
/// the host, then of the base domain, with the entry URL's scheme and
/// port. Text without a scheme gets `https`; a scheme other than `http`
/// and `https`, or no valid host, gives none. No address holds the URL's
/// user name, password, path, query or fragment.
#[must_use]
pub fn download_addresses(entry_url: &str, service: bool) -> Vec<String> {
    let url = entry_url.trim();
    let typed = if url.contains("://") {
        url.to_owned()
    } else {
        // `mailto:x` has a scheme; `example.com:8443` has a port.
        let head = url.split('/').next().unwrap_or("");
        if let Some((_, after)) = head.split_once(':')
            && !after.bytes().all(|b| b.is_ascii_digit())
        {
            return Vec::new();
        }
        format!("https://{url}")
    };
    let p = crate::url::parse(&typed);
    let scheme = p.scheme.as_str();
    let host = p.host.as_str().trim_end_matches('.');
    if !matches!(scheme, "http" | "https") || host.is_empty() || p.without_scheme.is_empty() {
        return Vec::new();
    }
    let mut hosts = vec![host.to_owned()];
    hosts.extend(base_domain(host));
    let port = if p.port >= 0 {
        format!(":{}", p.port)
    } else {
        String::new()
    };
    let mut out = Vec::new();
    if service {
        out.extend(
            hosts
                .iter()
                .map(|h| format!("https://icons.duckduckgo.com/ip3/{h}.ico")),
        );
    }
    for h in &hosts {
        let h = if h.contains(':') {
            format!("[{h}]")
        } else {
            h.clone()
        };
        out.push(format!("{scheme}://{h}{port}/favicon.ico"));
    }
    out
}

/// The base domain of `host` when it differs from it: the last two labels,
/// or three under a two-letter country code with a second label of at most
/// three letters (`example.co.uk`); `None` for an IP address.
/// ponytail: no public suffix list, so `login.web.de` gets no base domain
/// try; take the list's rule if users miss icons there.
fn base_domain(host: &str) -> Option<String> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let keep = match labels.as_slice() {
        [.., second, top] if top.len() == 2 && second.len() <= 3 => 3,
        _ => 2,
    };
    let start = labels.len().checked_sub(keep).filter(|&n| n > 0)?;
    labels.get(start..).map(|l| l.join("."))
}

#[cfg(test)]
mod tests {
    use super::png_chunks_ok;

    /// F-094 (APP-01.21 a, e; LD-64): the addresses of an icon download.
    #[test]
    fn f_094_download_addresses_follow_the_row() {
        use super::download_addresses as addresses;
        assert_eq!(
            addresses(
                "https://alice:demo-pw@login.example.com:8443/acct/home?q=1#x",
                false
            ),
            [
                "https://login.example.com:8443/favicon.ico",
                "https://example.com:8443/favicon.ico"
            ]
        );
        assert_eq!(
            addresses("https://login.example.com/a?q=1", true),
            [
                "https://icons.duckduckgo.com/ip3/login.example.com.ico",
                "https://icons.duckduckgo.com/ip3/example.com.ico",
                "https://login.example.com/favicon.ico",
                "https://example.com/favicon.ico"
            ]
        );
        assert_eq!(
            addresses("example.com/path", false),
            ["https://example.com/favicon.ico"]
        );
        assert_eq!(
            addresses("example.com:8443", false),
            ["https://example.com:8443/favicon.ico"]
        );
        assert_eq!(
            addresses("http://www.example.co.uk", false),
            [
                "http://www.example.co.uk/favicon.ico",
                "http://example.co.uk/favicon.ico"
            ]
        );
        assert_eq!(
            addresses("http://127.0.0.1:8080/x", false),
            ["http://127.0.0.1:8080/favicon.ico"]
        );
        assert_eq!(
            addresses("http://[::1]/", false),
            ["http://[::1]/favicon.ico"]
        );
        for none in [
            "",
            "mailto:a@b.example",
            "ftp://example.com",
            "cmd://ls",
            "https://",
        ] {
            assert!(addresses(none, false).is_empty(), "{none}");
        }
    }

    /// A chunk with a given length field and body (the walk reads no CRC,
    /// so it is zero).
    fn chunk(len: u32, kind: &[u8], body: &[u8]) -> Vec<u8> {
        [&len.to_be_bytes()[..], kind, body, &[0; 4]].concat()
    }

    fn png(chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut d = b"\x89PNG\r\n\x1a\n".to_vec();
        for c in chunks {
            d.extend(c);
        }
        d
    }

    fn ihdr(len: u32, color: u8) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 4, 0, 0, 0, 4, 8, color, 0, 0, 0];
        body.resize(len as usize, 0);
        chunk(len, b"IHDR", &body)
    }

    /// LD-117: the chunk rules, each alone.
    #[test]
    fn png_chunk_walk() {
        let iend = chunk(0, b"IEND", &[]);
        assert!(png_chunks_ok(&png(&[ihdr(13, 6), iend.clone()])));
        assert!(
            !png_chunks_ok(&png(&[ihdr(14, 6), iend.clone()])),
            "IHDR 14 bytes"
        );
        assert!(!png_chunks_ok(&png(&[ihdr(13, 6)])), "no IEND");
        assert!(
            !png_chunks_ok(&png(std::slice::from_ref(&iend))),
            "IHDR not first"
        );
        let plte = |n: u32| chunk(n, b"PLTE", &vec![0; n as usize]);
        assert!(png_chunks_ok(&png(&[ihdr(13, 3), plte(768), iend.clone()])));
        assert!(
            !png_chunks_ok(&png(&[ihdr(13, 3), plte(771), iend.clone()])),
            "PLTE 771"
        );
        assert!(
            !png_chunks_ok(&png(&[ihdr(13, 3), plte(3), plte(3), iend.clone()])),
            "two PLTE"
        );
        // An IEND whose length runs past the end of the file.
        assert!(!png_chunks_ok(&png(&[
            ihdr(13, 6),
            [&10u32.to_be_bytes()[..], b"IEND"].concat()
        ])));
    }
}

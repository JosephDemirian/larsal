//! A test encoder for ICO files (E0-S7 R10): the bytes the `ico` 0.6 crate
//! wrote, so the tests and the fuzz seeds keep their files. One image per
//! entry. [`ico`] stores an image with partial alpha or more than 64 × 64
//! pixels as a PNG (RGB, or RGBA with any alpha), else as a BMP; [`bmp`]
//! always as a BMP. A BMP takes 32 bits for partial alpha; else 1, 4 or 8
//! bits for at most 2, 16 or 256 colours (the colour table sorted, padded
//! with zeros to its full size; 24 bits for over 16 colours in fewer than
//! 512 pixels), else 24 bits; then the mask (fully transparent pixels).

use std::collections::BTreeSet;

/// An image: width, height and RGBA rows from the top.
pub type Image<'a> = (u32, u32, &'a [u8]);

/// An ICO of `images`, each as a PNG or a BMP, as the crate chose.
pub fn ico(images: &[Image]) -> Vec<u8> {
    file(images, false)
}

/// An ICO of `images`, each as a BMP.
pub fn bmp(images: &[Image]) -> Vec<u8> {
    file(images, true)
}

fn file(images: &[Image], only_bmp: bool) -> Vec<u8> {
    let entries: Vec<(u32, u32, u8, u16, u16, Vec<u8>)> = images
        .iter()
        .map(|&(w, h, rgba)| {
            let partial = rgba.chunks(4).any(|p| p[3] != 0 && p[3] != 255);
            let (colours, planes, bits, data) = if !only_bmp && (partial || w * h > 64 * 64) {
                let alpha = rgba.chunks(4).any(|p| p[3] != 255);
                (0, 0, if alpha { 32 } else { 24 }, png(w, h, rgba, alpha))
            } else {
                let (bits, data) = bmp_data(w, h, rgba, partial);
                let colours = match bits {
                    1 => 2,
                    4 => 16,
                    _ => 0,
                };
                (colours, 1, bits, data)
            };
            (w, h, colours, planes, bits, data)
        })
        .collect();
    let mut out = vec![0, 0, 1, 0];
    out.extend((entries.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * entries.len() as u32;
    for (w, h, colours, planes, bits, data) in &entries {
        let edge = |n: u32| if n > 255 { 0 } else { n as u8 };
        out.extend([edge(*w), edge(*h), *colours, 0]);
        out.extend(planes.to_le_bytes());
        out.extend(bits.to_le_bytes());
        out.extend((data.len() as u32).to_le_bytes());
        out.extend(offset.to_le_bytes());
        offset += data.len() as u32;
    }
    for e in &entries {
        out.extend(&e.5);
    }
    out
}

fn png(w: u32, h: u32, rgba: &[u8], alpha: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = png::Encoder::new(&mut out, w, h);
    e.set_depth(png::BitDepth::Eight);
    e.set_color(if alpha {
        png::ColorType::Rgba
    } else {
        png::ColorType::Rgb
    });
    let mut wr = e.write_header().unwrap();
    if alpha {
        wr.write_image_data(rgba).unwrap();
    } else {
        let rgb: Vec<u8> = rgba.chunks(4).flat_map(|p| [p[0], p[1], p[2]]).collect();
        wr.write_image_data(&rgb).unwrap();
    }
    wr.finish().unwrap();
    out
}

/// The bits per pixel and the BMP data.
fn bmp_data(w: u32, h: u32, rgba: &[u8], partial: bool) -> (u16, Vec<u8>) {
    let colours: BTreeSet<[u8; 3]> = rgba.chunks(4).map(|p| [p[0], p[1], p[2]]).collect();
    let bits: u16 = match colours.len() {
        _ if partial => 32,
        0..=2 => 1,
        3..=16 => 4,
        17..=256 if w * h >= 512 => 8,
        _ => 24,
    };
    let table: Vec<[u8; 3]> = if bits <= 8 {
        colours.into_iter().collect()
    } else {
        Vec::new()
    };
    let mut d = Vec::new();
    for v in [40, w, 2 * h] {
        d.extend(v.to_le_bytes());
    }
    d.extend(1u16.to_le_bytes());
    d.extend(bits.to_le_bytes());
    d.extend([0; 24]);
    if bits <= 8 {
        for i in 0..1usize << bits {
            let [r, g, b] = table.get(i).copied().unwrap_or([0; 3]);
            d.extend([b, g, r, 0]);
        }
    }
    let row = |bits: usize| (w as usize * bits).div_ceil(8).next_multiple_of(4);
    for y in (0..h as usize).rev() {
        let line = &rgba[y * w as usize * 4..][..w as usize * 4];
        let mut out = vec![0u8; row(usize::from(bits))];
        for (x, p) in line.chunks(4).enumerate() {
            match bits {
                1 | 4 | 8 => {
                    let i = table.iter().position(|c| *c == [p[0], p[1], p[2]]).unwrap() as u8;
                    let bit = x * usize::from(bits);
                    out[bit / 8] |= i << (8 - usize::from(bits) - bit % 8);
                }
                24 => out[x * 3..x * 3 + 3].copy_from_slice(&[p[2], p[1], p[0]]),
                _ => out[x * 4..x * 4 + 4].copy_from_slice(&[p[2], p[1], p[0], p[3]]),
            }
        }
        d.extend(out);
    }
    for y in (0..h as usize).rev() {
        let line = &rgba[y * w as usize * 4..][..w as usize * 4];
        let mut out = vec![0u8; row(1)];
        for (x, p) in line.chunks(4).enumerate() {
            if p[3] == 0 {
                out[x / 8] |= 0x80 >> (x % 8);
            }
        }
        d.extend(out);
    }
    (bits, d)
}

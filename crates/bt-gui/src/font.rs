//! From-scratch TrueType loader + anti-aliased rasteriser.
//!
//! Supports TrueType outlines (`glyf`), `.ttc` collections, cmap formats 4/12,
//! composite glyphs and the `kern` table (format 0). CFF (`OTTO`) fonts are
//! rejected. If no system font is found, a built-in 5x7 bitmap font is used.

use crate::canvas::{Canvas, Color};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

pub struct GlyphBitmap {
    pub w: usize,
    pub h: usize,
    /// Offset of the bitmap's left column from the pen position (px).
    pub left: i32,
    /// Offset of the bitmap's top row from the baseline (px, y-down; usually negative).
    pub top: i32,
    pub data: Vec<u8>,
}

#[inline]
fn rd16(d: &[u8], o: usize) -> u16 {
    match d.get(o..o + 2) {
        Some(b) => u16::from_be_bytes([b[0], b[1]]),
        None => 0,
    }
}
#[inline]
fn rdi16(d: &[u8], o: usize) -> i16 {
    rd16(d, o) as i16
}
#[inline]
fn rd32(d: &[u8], o: usize) -> u32 {
    match d.get(o..o + 4) {
        Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

struct Ttf {
    data: Vec<u8>,
    upem: f32,
    ascender: f32,
    descender: f32,
    line_gap: f32,
    num_hmetrics: usize,
    num_glyphs: usize,
    loca_long: bool,
    loca: usize,
    glyf: usize,
    glyf_len: usize,
    hmtx: usize,
    cmap: usize,
    cmap_fmt: u16,
    kern: HashMap<u32, i16>,
}

#[derive(Clone, Copy)]
struct Pt {
    x: f32,
    y: f32,
    on: bool,
}

impl Ttf {
    fn parse(data: Vec<u8>, index: usize) -> Option<Ttf> {
        let mut off = 0usize;
        if data.get(0..4)? == b"ttcf" {
            let n = rd32(&data, 8) as usize;
            if index >= n {
                return None;
            }
            off = rd32(&data, 12 + 4 * index) as usize;
        }
        let ver = rd32(&data, off);
        if ver != 0x0001_0000 && ver != 0x7472_7565 {
            return None; // OTTO (CFF) or garbage
        }
        let nt = rd16(&data, off + 4) as usize;
        let mut tables: HashMap<[u8; 4], (usize, usize)> = HashMap::new();
        for i in 0..nt {
            let r = off + 12 + 16 * i;
            let tag: [u8; 4] = data.get(r..r + 4)?.try_into().ok()?;
            tables.insert(tag, (rd32(&data, r + 8) as usize, rd32(&data, r + 12) as usize));
        }
        let head = tables.get(b"head")?.0;
        let hhea = tables.get(b"hhea")?.0;
        let maxp = tables.get(b"maxp")?.0;
        let (hmtx, _) = *tables.get(b"hmtx")?;
        let (loca, _) = *tables.get(b"loca")?;
        let (glyf, glyf_len) = *tables.get(b"glyf")?;
        let (cmap_t, _) = *tables.get(b"cmap")?;
        let upem = rd16(&data, head + 18) as f32;
        if upem == 0.0 || glyf + glyf_len > data.len() {
            return None;
        }
        // pick cmap subtable
        let n = rd16(&data, cmap_t + 2) as usize;
        let mut best: Option<(u32, usize, u16)> = None; // (priority, offset, format)
        for i in 0..n {
            let r = cmap_t + 4 + 8 * i;
            let (pid, eid) = (rd16(&data, r), rd16(&data, r + 2));
            let so = cmap_t + rd32(&data, r + 4) as usize;
            let fmt = rd16(&data, so);
            let pri = match (pid, eid, fmt) {
                (3, 10, 12) => 5,
                (0, _, 12) => 4,
                (3, 1, 4) => 3,
                (0, _, 4) => 2,
                _ => 0,
            };
            if pri > 0 && best.map_or(true, |b| pri > b.0) {
                best = Some((pri, so, fmt));
            }
        }
        let (_, cmap, cmap_fmt) = best?;
        let mut kern = HashMap::new();
        if let Some(&(k, _)) = tables.get(b"kern") {
            if rd16(&data, k) == 0 {
                let ntab = rd16(&data, k + 2) as usize;
                let mut p = k + 4;
                for _ in 0..ntab {
                    let len = rd16(&data, p + 2) as usize;
                    let cov = rd16(&data, p + 4);
                    if cov >> 8 == 0 && cov & 1 == 1 {
                        let np = rd16(&data, p + 6) as usize;
                        for j in 0..np {
                            let e = p + 14 + 6 * j;
                            let key = (rd16(&data, e) as u32) << 16 | rd16(&data, e + 2) as u32;
                            kern.insert(key, rdi16(&data, e + 4));
                        }
                    }
                    p += len.max(6);
                }
            }
        }
        Some(Ttf {
            upem,
            ascender: rdi16(&data, hhea + 4) as f32,
            descender: rdi16(&data, hhea + 6) as f32,
            line_gap: rdi16(&data, hhea + 8) as f32,
            num_hmetrics: rd16(&data, hhea + 34) as usize,
            num_glyphs: rd16(&data, maxp + 4) as usize,
            loca_long: rdi16(&data, head + 50) != 0,
            loca,
            glyf,
            glyf_len,
            hmtx,
            cmap,
            cmap_fmt,
            kern,
            data,
        })
    }

    fn mac_style(data: &[u8], index: usize) -> Option<u16> {
        let mut off = 0usize;
        if data.get(0..4)? == b"ttcf" {
            if index >= rd32(data, 8) as usize {
                return None;
            }
            off = rd32(data, 12 + 4 * index) as usize;
        }
        let nt = rd16(data, off + 4) as usize;
        for i in 0..nt {
            let r = off + 12 + 16 * i;
            if data.get(r..r + 4)? == b"head" {
                return Some(rd16(data, rd32(data, r + 8) as usize + 44));
            }
        }
        None
    }

    fn glyph_index(&self, c: u32) -> u16 {
        let d = &self.data;
        let t = self.cmap;
        if self.cmap_fmt == 4 {
            if c > 0xFFFF {
                return 0;
            }
            let segx2 = rd16(d, t + 6) as usize;
            let ends = t + 14;
            let starts = ends + segx2 + 2;
            let deltas = starts + segx2;
            let ranges = deltas + segx2;
            // binary search first end >= c
            let (mut lo, mut hi) = (0usize, segx2 / 2);
            while lo < hi {
                let mid = (lo + hi) / 2;
                if (rd16(d, ends + 2 * mid) as u32) < c {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            if lo >= segx2 / 2 {
                return 0;
            }
            let i = lo;
            let start = rd16(d, starts + 2 * i) as u32;
            if start > c {
                return 0;
            }
            let delta = rd16(d, deltas + 2 * i) as u32;
            let ro = rd16(d, ranges + 2 * i) as usize;
            if ro == 0 {
                return (c.wrapping_add(delta) & 0xFFFF) as u16;
            }
            let addr = ranges + 2 * i + ro + 2 * (c - start) as usize;
            let g = rd16(d, addr) as u32;
            if g == 0 {
                0
            } else {
                (g.wrapping_add(delta) & 0xFFFF) as u16
            }
        } else {
            let n = rd32(d, t + 12) as usize;
            let (mut lo, mut hi) = (0usize, n);
            while lo < hi {
                let mid = (lo + hi) / 2;
                let g = t + 16 + 12 * mid;
                if rd32(d, g + 4) < c {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            if lo >= n {
                return 0;
            }
            let g = t + 16 + 12 * lo;
            let start = rd32(d, g);
            if start > c {
                return 0;
            }
            (rd32(d, g + 8) + (c - start)) as u16
        }
    }

    fn advance(&self, g: u16) -> f32 {
        let g = (g as usize).min(self.num_hmetrics.saturating_sub(1));
        rd16(&self.data, self.hmtx + 4 * g) as f32
    }

    fn glyph_range(&self, g: u16) -> Option<(usize, usize)> {
        let g = g as usize;
        if g >= self.num_glyphs {
            return None;
        }
        let (a, b) = if self.loca_long {
            (rd32(&self.data, self.loca + 4 * g) as usize, rd32(&self.data, self.loca + 4 * g + 4) as usize)
        } else {
            (rd16(&self.data, self.loca + 2 * g) as usize * 2, rd16(&self.data, self.loca + 2 * g + 2) as usize * 2)
        };
        if b <= a || b > self.glyf_len {
            return None;
        }
        Some((self.glyf + a, self.glyf + b))
    }

    /// Append contours of glyph `g` transformed by `xf` = [a,b,c,d,e,f].
    fn contours(&self, g: u16, xf: [f32; 6], depth: u32, out: &mut Vec<Vec<Pt>>) {
        if depth > 8 {
            return;
        }
        let Some((start, end)) = self.glyph_range(g) else { return };
        let d = &self.data[..end];
        let nc = rdi16(d, start);
        let tx = |x: f32, y: f32| (xf[0] * x + xf[2] * y + xf[4], xf[1] * x + xf[3] * y + xf[5]);
        if nc >= 0 {
            let nc = nc as usize;
            let mut p = start + 10;
            let mut ends = Vec::with_capacity(nc);
            for i in 0..nc {
                ends.push(rd16(d, p + 2 * i) as usize);
            }
            p += 2 * nc;
            let npts = ends.last().map_or(0, |e| e + 1);
            if npts == 0 || npts > 65536 {
                return;
            }
            p += 2 + rd16(d, p) as usize;
            let mut flags = Vec::with_capacity(npts);
            while flags.len() < npts {
                let f = *d.get(p).unwrap_or(&0);
                p += 1;
                flags.push(f);
                if f & 8 != 0 {
                    let rep = *d.get(p).unwrap_or(&0);
                    p += 1;
                    for _ in 0..rep {
                        if flags.len() < npts {
                            flags.push(f);
                        }
                    }
                }
            }
            let mut xs = Vec::with_capacity(npts);
            let mut v = 0i32;
            for &f in &flags {
                if f & 2 != 0 {
                    let b = *d.get(p).unwrap_or(&0) as i32;
                    p += 1;
                    v += if f & 16 != 0 { b } else { -b };
                } else if f & 16 == 0 {
                    v += rdi16(d, p) as i32;
                    p += 2;
                }
                xs.push(v);
            }
            let mut ys = Vec::with_capacity(npts);
            v = 0;
            for &f in &flags {
                if f & 4 != 0 {
                    let b = *d.get(p).unwrap_or(&0) as i32;
                    p += 1;
                    v += if f & 32 != 0 { b } else { -b };
                } else if f & 32 == 0 {
                    v += rdi16(d, p) as i32;
                    p += 2;
                }
                ys.push(v);
            }
            let mut s = 0;
            for &e in &ends {
                if e < s || e >= npts {
                    break;
                }
                let c: Vec<Pt> = (s..=e)
                    .map(|i| {
                        let (x, y) = tx(xs[i] as f32, ys[i] as f32);
                        Pt { x, y, on: flags[i] & 1 != 0 }
                    })
                    .collect();
                out.push(c);
                s = e + 1;
            }
        } else {
            let mut p = start + 10;
            loop {
                let flags = rd16(d, p);
                let gi = rd16(d, p + 2);
                p += 4;
                let (a1, a2) = if flags & 1 != 0 {
                    let r = (rdi16(d, p) as f32, rdi16(d, p + 2) as f32);
                    p += 4;
                    r
                } else {
                    let r = (*d.get(p).unwrap_or(&0) as i8 as f32, *d.get(p + 1).unwrap_or(&0) as i8 as f32);
                    p += 2;
                    r
                };
                let f2 = |o: usize| rdi16(d, o) as f32 / 16384.0;
                let (mut a, mut b, mut c, mut dd) = (1.0, 0.0, 0.0, 1.0);
                if flags & 8 != 0 {
                    a = f2(p);
                    dd = a;
                    p += 2;
                } else if flags & 0x40 != 0 {
                    a = f2(p);
                    dd = f2(p + 2);
                    p += 4;
                } else if flags & 0x80 != 0 {
                    a = f2(p);
                    b = f2(p + 2);
                    c = f2(p + 4);
                    dd = f2(p + 6);
                    p += 8;
                }
                let (e, f) = if flags & 2 != 0 { (a1, a2) } else { (0.0, 0.0) };
                // compose parent ∘ component
                let nx = [
                    xf[0] * a + xf[2] * b,
                    xf[1] * a + xf[3] * b,
                    xf[0] * c + xf[2] * dd,
                    xf[1] * c + xf[3] * dd,
                    xf[0] * e + xf[2] * f + xf[4],
                    xf[1] * e + xf[3] * f + xf[5],
                ];
                self.contours(gi, nx, depth + 1, out);
                if flags & 0x20 == 0 || p >= end {
                    break;
                }
            }
        }
    }
}

/// Signed-area accumulation rasteriser.
struct Raster {
    w: usize,
    h: usize,
    acc: Vec<f32>,
}

impl Raster {
    fn new(w: usize, h: usize) -> Raster {
        Raster { w, h, acc: vec![0.0; w * h + 1] }
    }

    #[inline]
    fn cov_integral(v: f32) -> f32 {
        // ∫0^v clamp(t,0,1) dt
        if v <= 0.0 {
            0.0
        } else if v < 1.0 {
            0.5 * v * v
        } else {
            v - 0.5
        }
    }

    fn row(&mut self, y: usize, xa: f32, xb: f32, d: f32) {
        let row = y * self.w;
        let w = self.w as i32;
        let i0 = xa.floor() as i32;
        let i1 = xb.floor() as i32 + 1;
        let span = xb - xa;
        let mut prev = 0.0f32;
        for i in i0..=i1 {
            let cov = if span < 1e-4 {
                d * ((i + 1) as f32 - 0.5 * (xa + xb)).clamp(0.0, 1.0)
            } else {
                d * (Self::cov_integral((i + 1) as f32 - xa) - Self::cov_integral((i + 1) as f32 - xb)) / span
            };
            if i >= w {
                break;
            }
            let idx = row + i.max(0) as usize;
            self.acc[idx] += cov - prev;
            prev = cov;
        }
    }

    fn line(&mut self, x0: f32, y0: f32, x1: f32, y1: f32) {
        if (y0 - y1).abs() < 1e-6 {
            return;
        }
        let (dir, x0, y0, x1, y1) = if y0 < y1 { (1.0, x0, y0, x1, y1) } else { (-1.0, x1, y1, x0, y0) };
        let dxdy = (x1 - x0) / (y1 - y0);
        let ys = y0.max(0.0);
        let ye = y1.min(self.h as f32);
        if ys >= ye {
            return;
        }
        let mut x = x0 + (ys - y0) * dxdy;
        let mut yi = ys.floor() as usize;
        while (yi as f32) < ye && yi < self.h {
            let top = (yi as f32).max(ys);
            let bot = ((yi + 1) as f32).min(ye);
            let dy = bot - top;
            if dy > 0.0 {
                let xn = x + dxdy * dy;
                let (a, b) = if x < xn { (x, xn) } else { (xn, x) };
                self.row(yi, a, b, dy * dir);
                x = xn;
            }
            yi += 1;
        }
    }

    fn finish(self, lut: &[u8; 256]) -> Vec<u8> {
        let mut out = vec![0u8; self.w * self.h];
        for y in 0..self.h {
            let mut s = 0.0f32;
            for x in 0..self.w {
                s += self.acc[y * self.w + x];
                let c = s.abs().min(1.0);
                out[y * self.w + x] = lut[(c * 255.0 + 0.5) as usize];
            }
        }
        out
    }
}

// Built-in fallback: classic 5x7 column-encoded bitmap font for ASCII 32..126.
#[rustfmt::skip]
const FALLBACK: [u8; 95 * 5] = [
    0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x5F,0x00,0x00, 0x00,0x07,0x00,0x07,0x00, 0x14,0x7F,0x14,0x7F,0x14,
    0x24,0x2A,0x7F,0x2A,0x12, 0x23,0x13,0x08,0x64,0x62, 0x36,0x49,0x55,0x22,0x50, 0x00,0x05,0x03,0x00,0x00,
    0x00,0x1C,0x22,0x41,0x00, 0x00,0x41,0x22,0x1C,0x00, 0x08,0x2A,0x1C,0x2A,0x08, 0x08,0x08,0x3E,0x08,0x08,
    0x00,0x50,0x30,0x00,0x00, 0x08,0x08,0x08,0x08,0x08, 0x00,0x60,0x60,0x00,0x00, 0x20,0x10,0x08,0x04,0x02,
    0x3E,0x51,0x49,0x45,0x3E, 0x00,0x42,0x7F,0x40,0x00, 0x42,0x61,0x51,0x49,0x46, 0x21,0x41,0x45,0x4B,0x31,
    0x18,0x14,0x12,0x7F,0x10, 0x27,0x45,0x45,0x45,0x39, 0x3C,0x4A,0x49,0x49,0x30, 0x01,0x71,0x09,0x05,0x03,
    0x36,0x49,0x49,0x49,0x36, 0x06,0x49,0x49,0x29,0x1E, 0x00,0x36,0x36,0x00,0x00, 0x00,0x56,0x36,0x00,0x00,
    0x08,0x14,0x22,0x41,0x00, 0x14,0x14,0x14,0x14,0x14, 0x00,0x41,0x22,0x14,0x08, 0x02,0x01,0x51,0x09,0x06,
    0x32,0x49,0x79,0x41,0x3E, 0x7E,0x11,0x11,0x11,0x7E, 0x7F,0x49,0x49,0x49,0x36, 0x3E,0x41,0x41,0x41,0x22,
    0x7F,0x41,0x41,0x22,0x1C, 0x7F,0x49,0x49,0x49,0x41, 0x7F,0x09,0x09,0x09,0x01, 0x3E,0x41,0x49,0x49,0x7A,
    0x7F,0x08,0x08,0x08,0x7F, 0x00,0x41,0x7F,0x41,0x00, 0x20,0x40,0x41,0x3F,0x01, 0x7F,0x08,0x14,0x22,0x41,
    0x7F,0x40,0x40,0x40,0x40, 0x7F,0x02,0x0C,0x02,0x7F, 0x7F,0x04,0x08,0x10,0x7F, 0x3E,0x41,0x41,0x41,0x3E,
    0x7F,0x09,0x09,0x09,0x06, 0x3E,0x41,0x51,0x21,0x5E, 0x7F,0x09,0x19,0x29,0x46, 0x46,0x49,0x49,0x49,0x31,
    0x01,0x01,0x7F,0x01,0x01, 0x3F,0x40,0x40,0x40,0x3F, 0x1F,0x20,0x40,0x20,0x1F, 0x3F,0x40,0x38,0x40,0x3F,
    0x63,0x14,0x08,0x14,0x63, 0x07,0x08,0x70,0x08,0x07, 0x61,0x51,0x49,0x45,0x43, 0x00,0x7F,0x41,0x41,0x00,
    0x02,0x04,0x08,0x10,0x20, 0x00,0x41,0x41,0x7F,0x00, 0x04,0x02,0x01,0x02,0x04, 0x40,0x40,0x40,0x40,0x40,
    0x00,0x01,0x02,0x04,0x00, 0x20,0x54,0x54,0x54,0x78, 0x7F,0x48,0x44,0x44,0x38, 0x38,0x44,0x44,0x44,0x20,
    0x38,0x44,0x44,0x48,0x7F, 0x38,0x54,0x54,0x54,0x18, 0x08,0x7E,0x09,0x01,0x02, 0x0C,0x52,0x52,0x52,0x3E,
    0x7F,0x08,0x04,0x04,0x78, 0x00,0x44,0x7D,0x40,0x00, 0x20,0x40,0x44,0x3D,0x00, 0x7F,0x10,0x28,0x44,0x00,
    0x00,0x41,0x7F,0x40,0x00, 0x7C,0x04,0x18,0x04,0x78, 0x7C,0x08,0x04,0x04,0x78, 0x38,0x44,0x44,0x44,0x38,
    0x7C,0x14,0x14,0x14,0x08, 0x08,0x14,0x14,0x18,0x7C, 0x7C,0x08,0x04,0x04,0x08, 0x48,0x54,0x54,0x54,0x20,
    0x04,0x3F,0x44,0x40,0x20, 0x3C,0x40,0x40,0x20,0x7C, 0x1C,0x20,0x40,0x20,0x1C, 0x3C,0x40,0x30,0x40,0x3C,
    0x44,0x28,0x10,0x28,0x44, 0x0C,0x50,0x50,0x50,0x3C, 0x44,0x64,0x54,0x4C,0x44, 0x00,0x08,0x36,0x41,0x00,
    0x00,0x00,0x7F,0x00,0x00, 0x00,0x41,0x36,0x08,0x00, 0x08,0x04,0x08,0x10,0x08,
];

/// A font face: TrueType if available, otherwise the built-in bitmap font.
pub struct Font {
    ttf: Option<Ttf>,
    pub name: String,
    glyph_cache: RefCell<HashMap<(u16, u32), Rc<GlyphBitmap>>>,
    char_cache: RefCell<HashMap<char, u16>>,
    lut: [u8; 256],
}

impl Font {
    fn make(ttf: Option<Ttf>, name: String) -> Font {
        let mut lut = [0u8; 256];
        for (i, v) in lut.iter_mut().enumerate() {
            // Slight contrast boost: unhinted text otherwise looks washed out.
            *v = ((i as f32 / 255.0).powf(0.8) * 255.0 + 0.5) as u8;
        }
        Font { ttf, name, glyph_cache: RefCell::new(HashMap::new()), char_cache: RefCell::new(HashMap::new()), lut }
    }

    /// Parse a TrueType font (face `index` within a collection).
    pub fn from_bytes(data: Vec<u8>, index: usize) -> Option<Font> {
        Ttf::parse(data, index).map(|t| Font::make(Some(t), String::new()))
    }

    /// Load a font file. In a `.ttc`, picks the first face whose bold flag matches.
    pub fn load(path: &Path, bold: bool) -> Option<Font> {
        let data = std::fs::read(path).ok()?;
        let mut index = 0;
        if data.get(0..4) == Some(b"ttcf") {
            let n = rd32(&data, 8) as usize;
            index = (0..n)
                .find(|&i| Ttf::mac_style(&data, i).map_or(false, |s| (s & 1 != 0) == bold && s & 2 == 0))
                .unwrap_or(0);
        }
        let mut f = Font::from_bytes(data, index)?;
        f.name = path.display().to_string();
        Some(f)
    }

    /// The built-in bitmap font (ASCII only).
    pub fn fallback() -> Font {
        Font::make(None, "builtin-5x7".into())
    }

    pub fn is_fallback(&self) -> bool {
        self.ttf.is_none()
    }

    fn glyph(&self, c: char) -> u16 {
        if let Some(&g) = self.char_cache.borrow().get(&c) {
            return g;
        }
        let g = match &self.ttf {
            Some(t) => t.glyph_index(c as u32),
            None => {
                let c = match c {
                    '…' | '·' => '.',
                    '•' => '*',
                    '“' | '”' | '„' => '"',
                    '‘' | '’' => '\'',
                    '—' | '–' | '−' => '-',
                    '✓' => 'v',
                    '\u{a0}' => ' ',
                    c => c,
                };
                let u = c as u32;
                if (32..127).contains(&u) {
                    (u - 32) as u16
                } else {
                    ('?' as u32 - 32) as u16
                }
            }
        };
        self.char_cache.borrow_mut().insert(c, g);
        g
    }

    /// Ascent above the baseline at `size` (logical px).
    pub fn ascent(&self, size: f32) -> f32 {
        match &self.ttf {
            Some(t) => t.ascender / t.upem * size,
            None => size * 0.8,
        }
    }
    /// Descent below the baseline (negative).
    pub fn descent(&self, size: f32) -> f32 {
        match &self.ttf {
            Some(t) => t.descender / t.upem * size,
            None => -size * 0.25,
        }
    }
    /// Height of a text line box (ascent - descent).
    pub fn text_height(&self, size: f32) -> f32 {
        self.ascent(size) - self.descent(size)
    }
    pub fn line_height(&self, size: f32) -> f32 {
        let gap = self.ttf.as_ref().map_or(0.0, |t| t.line_gap / t.upem * size);
        (self.text_height(size) + gap).max(size * 1.2)
    }

    fn advance_g(&self, g: u16, size: f32) -> f32 {
        match &self.ttf {
            Some(t) => t.advance(g) / t.upem * size,
            None => size * 0.66,
        }
    }
    fn kern_g(&self, a: u16, b: u16, size: f32) -> f32 {
        match &self.ttf {
            Some(t) if !t.kern.is_empty() => {
                t.kern.get(&((a as u32) << 16 | b as u32)).map_or(0.0, |&k| k as f32 / t.upem * size)
            }
            _ => 0.0,
        }
    }

    /// Width of `text` at `size` (logical px).
    pub fn measure(&self, text: &str, size: f32) -> f32 {
        *self.caret_positions(text, size).last().unwrap()
    }

    /// x offsets of each char boundary (len = chars + 1).
    pub fn caret_positions(&self, text: &str, size: f32) -> Vec<f32> {
        let mut v = Vec::with_capacity(text.len() + 1);
        let mut pen = 0.0;
        let mut prev: Option<u16> = None;
        v.push(0.0);
        for c in text.chars() {
            let g = self.glyph(c);
            if let Some(p) = prev {
                pen += self.kern_g(p, g, size);
            }
            pen += self.advance_g(g, size);
            v.push(pen);
            prev = Some(g);
        }
        v
    }

    /// Rasterise glyph `g` at `px` physical pixels (cached).
    pub fn rasterize(&self, g: u16, px: f32) -> Rc<GlyphBitmap> {
        let key = (g, (px * 8.0).round() as u32);
        if let Some(b) = self.glyph_cache.borrow().get(&key) {
            return b.clone();
        }
        let bm = Rc::new(self.render(g, px));
        let mut cache = self.glyph_cache.borrow_mut();
        if cache.len() > 4096 {
            cache.clear();
        }
        cache.insert(key, bm.clone());
        bm
    }

    fn render(&self, g: u16, px: f32) -> GlyphBitmap {
        let empty = GlyphBitmap { w: 0, h: 0, left: 0, top: 0, data: Vec::new() };
        let Some(t) = &self.ttf else {
            // bitmap fallback, integer scaled
            let k = ((px / 9.0).round() as usize).max(1);
            let (w, h) = (5 * k, 7 * k);
            let mut data = vec![0u8; w * h];
            for col in 0..5 {
                let bits = FALLBACK[g as usize * 5 + col];
                for row in 0..7 {
                    if bits >> row & 1 != 0 {
                        for dy in 0..k {
                            for dx in 0..k {
                                data[(row * k + dy) * w + col * k + dx] = 255;
                            }
                        }
                    }
                }
            }
            let top = -((px * 0.75).round() as i32);
            return GlyphBitmap { w, h, left: (px * 0.05) as i32, top, data };
        };
        let s = px / t.upem;
        let mut cs = Vec::new();
        t.contours(g, [s, 0.0, 0.0, -s, 0.0, 0.0], 0, &mut cs);
        let (mut minx, mut miny, mut maxx, mut maxy) = (f32::MAX, f32::MAX, f32::MIN, f32::MIN);
        for c in &cs {
            for p in c {
                minx = minx.min(p.x);
                maxx = maxx.max(p.x);
                miny = miny.min(p.y);
                maxy = maxy.max(p.y);
            }
        }
        if cs.is_empty() || minx > maxx || maxx - minx > 4096.0 || maxy - miny > 4096.0 {
            return empty;
        }
        let left = minx.floor() as i32;
        let top = miny.floor() as i32;
        let w = (maxx.ceil() as i32 - left + 2) as usize;
        let h = (maxy.ceil() as i32 - top + 1) as usize;
        let (ox, oy) = (left as f32, top as f32);
        let mut r = Raster::new(w, h);
        for c in &cs {
            let n = c.len();
            if n < 2 {
                continue;
            }
            // find a starting on-curve point
            let start_idx = (0..n).find(|&i| c[i].on);
            let (start, first) = match start_idx {
                Some(i) => ((c[i].x, c[i].y), i),
                None => (((c[0].x + c[n - 1].x) * 0.5, (c[0].y + c[n - 1].y) * 0.5), n - 1),
            };
            let mut cur = start;
            let mut ctrl: Option<(f32, f32)> = None;
            let mut emit_line = |r: &mut Raster, a: (f32, f32), b: (f32, f32)| r.line(a.0 - ox, a.1 - oy, b.0 - ox, b.1 - oy);
            let quad = |r: &mut Raster, a: (f32, f32), c1: (f32, f32), b: (f32, f32), emit: &mut dyn FnMut(&mut Raster, (f32, f32), (f32, f32))| {
                let dd = ((a.0 - 2.0 * c1.0 + b.0).powi(2) + (a.1 - 2.0 * c1.1 + b.1).powi(2)).sqrt();
                let steps = ((dd * 2.0).sqrt().ceil() as usize).clamp(1, 24);
                let mut prev = a;
                for i in 1..=steps {
                    let t = i as f32 / steps as f32;
                    let mt = 1.0 - t;
                    let p = (
                        mt * mt * a.0 + 2.0 * mt * t * c1.0 + t * t * b.0,
                        mt * mt * a.1 + 2.0 * mt * t * c1.1 + t * t * b.1,
                    );
                    emit(r, prev, p);
                    prev = p;
                }
            };
            for k in 1..=n {
                let p = c[(first + k) % n];
                let pp = (p.x, p.y);
                if p.on {
                    match ctrl.take() {
                        Some(cp) => quad(&mut r, cur, cp, pp, &mut emit_line),
                        None => emit_line(&mut r, cur, pp),
                    }
                    cur = pp;
                } else {
                    if let Some(cp) = ctrl {
                        let mid = ((cp.0 + pp.0) * 0.5, (cp.1 + pp.1) * 0.5);
                        quad(&mut r, cur, cp, mid, &mut emit_line);
                        cur = mid;
                    }
                    ctrl = Some(pp);
                }
            }
            // close back to start
            match ctrl.take() {
                Some(cp) => quad(&mut r, cur, cp, start, &mut emit_line),
                None => {
                    if cur != start {
                        emit_line(&mut r, cur, start)
                    }
                }
            }
        }
        let data = r.finish(&self.lut);
        GlyphBitmap { w, h, left, top, data }
    }

    /// Draw `text` with its line box's top at `y` (logical). Returns the advance width.
    pub fn draw(&self, canvas: &mut Canvas, x: f32, y: f32, size: f32, text: &str, color: Color) -> f32 {
        let s = canvas.scale;
        let px = size * s;
        let baseline = ((y + self.ascent(size)) * s).round() as i32;
        let mut pen = 0.0;
        let mut prev: Option<u16> = None;
        for c in text.chars() {
            let g = self.glyph(c);
            if let Some(p) = prev {
                pen += self.kern_g(p, g, size);
            }
            if !c.is_whitespace() {
                let bm = self.rasterize(g, px);
                if bm.w > 0 {
                    let gx = ((x + pen) * s).round() as i32 + bm.left;
                    canvas.draw_mask(gx, baseline + bm.top, bm.w, bm.h, &bm.data, color);
                }
            }
            pen += self.advance_g(g, size);
            prev = Some(g);
        }
        pen
    }
}

/// The UI font set.
pub struct Fonts {
    pub regular: Font,
    pub bold: Font,
}

impl Fonts {
    /// Load the best available system UI fonts (falls back to the bitmap font).
    pub fn load_system() -> Fonts {
        let (reg, bold) = candidates();
        let pick = |list: &[PathBuf], b: bool| list.iter().find_map(|p| Font::load(p, b));
        let regular = pick(&reg, false).unwrap_or_else(Font::fallback);
        let bold = pick(&bold, true).or_else(|| pick(&reg, false)).unwrap_or_else(Font::fallback);
        Fonts { regular, bold }
    }
    pub fn get(&self, bold: bool) -> &Font {
        if bold {
            &self.bold
        } else {
            &self.regular
        }
    }
}

#[cfg(target_os = "windows")]
fn candidates() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let dir = PathBuf::from(std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into())).join("Fonts");
    let f = |n: &[&str]| n.iter().map(|x| dir.join(x)).collect::<Vec<_>>();
    (f(&["segoeui.ttf", "arial.ttf", "tahoma.ttf"]), f(&["seguisb.ttf", "segoeuib.ttf", "arialbd.ttf", "tahomabd.ttf"]))
}

#[cfg(target_os = "macos")]
fn candidates() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let p = |n: &[&str]| n.iter().map(PathBuf::from).collect::<Vec<_>>();
    (
        p(&[
            "/System/Library/Fonts/HelveticaNeue.ttc",
            "/System/Library/Fonts/Helvetica.ttc",
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/Library/Fonts/Arial.ttf",
            "/System/Library/Fonts/Geneva.ttf",
        ]),
        p(&[
            "/System/Library/Fonts/HelveticaNeue.ttc",
            "/System/Library/Fonts/Helvetica.ttc",
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
            "/Library/Fonts/Arial Bold.ttf",
        ]),
    )
}

#[cfg(all(unix, not(target_os = "macos")))]
fn candidates() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut dirs = vec![PathBuf::from("/usr/share/fonts"), PathBuf::from("/usr/local/share/fonts")];
    if let Some(h) = std::env::var_os("HOME") {
        let h = PathBuf::from(h);
        dirs.push(h.join(".local/share/fonts"));
        dirs.push(h.join(".fonts"));
    }
    let mut found: HashMap<String, PathBuf> = HashMap::new();
    fn walk(d: &Path, depth: u32, found: &mut HashMap<String, PathBuf>) {
        if depth > 6 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, depth + 1, found);
            } else if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                if n.ends_with(".ttf") || n.ends_with(".ttc") {
                    found.entry(n.to_string()).or_insert(p.clone());
                }
            }
        }
    }
    for d in &dirs {
        walk(d, 0, &mut found);
    }
    let pick = |names: &[&str]| names.iter().filter_map(|n| found.get(*n).cloned()).collect::<Vec<_>>();
    (
        pick(&[
            "Inter-Regular.ttf",
            "NotoSans-Regular.ttf",
            "Ubuntu-R.ttf",
            "OpenSans-Regular.ttf",
            "LiberationSans-Regular.ttf",
            "DejaVuSans.ttf",
            "FreeSans.ttf",
            "Arial.ttf",
            "arial.ttf",
        ]),
        pick(&[
            "Inter-SemiBold.ttf",
            "NotoSans-SemiBold.ttf",
            "NotoSans-Bold.ttf",
            "Ubuntu-M.ttf",
            "Ubuntu-B.ttf",
            "OpenSans-SemiBold.ttf",
            "LiberationSans-Bold.ttf",
            "DejaVuSans-Bold.ttf",
            "FreeSansBold.ttf",
            "Arial_Bold.ttf",
            "arialbd.ttf",
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fallback_measures() {
        let f = Font::fallback();
        assert!(f.measure("abc", 14.0) > 20.0);
        let mut c = Canvas::new(60, 20, 1.0);
        f.draw(&mut c, 2.0, 2.0, 14.0, "Hi", Color::WHITE);
        assert!(c.pixels.iter().any(|&p| p != 0));
    }
    #[test]
    fn system_font_renders() {
        let fonts = Fonts::load_system();
        if fonts.regular.is_fallback() {
            return; // no fonts on this machine
        }
        let f = &fonts.regular;
        let w = f.measure("Hello", 16.0);
        assert!(w > 25.0 && w < 60.0, "{w}");
        let bm = f.rasterize(f.glyph('O'), 32.0);
        assert!(bm.w > 10 && bm.h > 15);
        // the middle of an 'O' is empty, the ring is ink
        let mid = bm.data[(bm.h / 2) * bm.w + bm.w / 2];
        assert!(mid < 30, "center {mid}");
        let ink: u32 = bm.data.iter().map(|&v| v as u32).sum();
        assert!(ink > 255 * 40);
    }
}

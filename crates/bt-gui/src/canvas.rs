//! CPU framebuffer with anti-aliased primitives.
//!
//! All public drawing functions take *logical* coordinates; they are multiplied
//! by `scale` internally, so the UI code is DPI-independent.

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

impl Rect {
    pub const fn new(x: f32, y: f32, w: f32, h: f32) -> Rect {
        Rect { x, y, w, h }
    }
    pub fn right(&self) -> f32 {
        self.x + self.w
    }
    pub fn bottom(&self) -> f32 {
        self.y + self.h
    }
    pub fn center(&self) -> (f32, f32) {
        (self.x + self.w * 0.5, self.y + self.h * 0.5)
    }
    pub fn contains(&self, x: f32, y: f32) -> bool {
        x >= self.x && x < self.right() && y >= self.y && y < self.bottom()
    }
    pub fn shrink(&self, d: f32) -> Rect {
        self.shrink2(d, d)
    }
    pub fn shrink2(&self, dx: f32, dy: f32) -> Rect {
        Rect::new(self.x + dx, self.y + dy, (self.w - 2.0 * dx).max(0.0), (self.h - 2.0 * dy).max(0.0))
    }
    pub fn expand(&self, d: f32) -> Rect {
        Rect::new(self.x - d, self.y - d, self.w + 2.0 * d, self.h + 2.0 * d)
    }
    pub fn translate(&self, dx: f32, dy: f32) -> Rect {
        Rect::new(self.x + dx, self.y + dy, self.w, self.h)
    }
    pub fn intersect(&self, o: &Rect) -> Rect {
        let x0 = self.x.max(o.x);
        let y0 = self.y.max(o.y);
        let x1 = self.right().min(o.right());
        let y1 = self.bottom().min(o.bottom());
        Rect::new(x0, y0, (x1 - x0).max(0.0), (y1 - y0).max(0.0))
    }
    pub fn is_empty(&self) -> bool {
        self.w <= 0.0 || self.h <= 0.0
    }
    /// Split off `w` from the left: (left, rest).
    pub fn split_left(&self, w: f32) -> (Rect, Rect) {
        let w = w.min(self.w);
        (Rect::new(self.x, self.y, w, self.h), Rect::new(self.x + w, self.y, self.w - w, self.h))
    }
    /// Split off `h` from the top: (top, rest).
    pub fn split_top(&self, h: f32) -> (Rect, Rect) {
        let h = h.min(self.h);
        (Rect::new(self.x, self.y, self.w, h), Rect::new(self.x, self.y + h, self.w, self.h - h))
    }
}

/// 0xAARRGGBB colour (non-premultiplied).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color(pub u32);

impl Color {
    pub const WHITE: Color = Color(0xFFFF_FFFF);
    pub const BLACK: Color = Color(0xFF00_0000);
    pub const TRANSPARENT: Color = Color(0);

    /// Opaque colour from 0xRRGGBB.
    pub const fn hex(rgb: u32) -> Color {
        Color(0xFF00_0000 | (rgb & 0xFF_FFFF))
    }
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Color {
        Color((a as u32) << 24 | (r as u32) << 16 | (g as u32) << 8 | b as u32)
    }
    pub const fn rgb(r: u8, g: u8, b: u8) -> Color {
        Color::rgba(r, g, b, 255)
    }
    pub fn a(self) -> u8 {
        (self.0 >> 24) as u8
    }
    pub fn r(self) -> u8 {
        (self.0 >> 16) as u8
    }
    pub fn g(self) -> u8 {
        (self.0 >> 8) as u8
    }
    pub fn b(self) -> u8 {
        self.0 as u8
    }
    pub fn with_alpha(self, a: u8) -> Color {
        Color(self.0 & 0xFF_FFFF | (a as u32) << 24)
    }
    /// Multiply alpha by `f` (0..1).
    pub fn fade(self, f: f32) -> Color {
        self.with_alpha((self.a() as f32 * f.clamp(0.0, 1.0)).round() as u8)
    }
    pub fn lerp(self, o: Color, t: f32) -> Color {
        let t = t.clamp(0.0, 1.0);
        let m = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * t).round() as u8;
        Color::rgba(m(self.r(), o.r()), m(self.g(), o.g()), m(self.b(), o.b()), m(self.a(), o.a()))
    }
}

#[derive(Clone, Copy, Debug)]
struct IRect {
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
}

pub struct Canvas {
    pub width: u32,
    pub height: u32,
    /// 0x00RRGGBB per pixel (alpha ignored), row-major, top-down.
    pub pixels: Vec<u32>,
    pub scale: f32,
    clip: IRect,
    clip_stack: Vec<IRect>,
}

#[inline]
fn blend(dst: u32, c: u32, a: u32) -> u32 {
    if a == 0 {
        return dst;
    }
    if a >= 255 {
        return c & 0xFF_FFFF;
    }
    let inv = 255 - a;
    let ch = |s: u32| -> u32 {
        let v = ((c >> s) & 255) * a + ((dst >> s) & 255) * inv + 128;
        ((v + (v >> 8)) >> 8) << s
    };
    ch(16) | ch(8) | ch(0)
}

#[inline]
fn sd_round_box(px: f32, py: f32, cx: f32, cy: f32, hw: f32, hh: f32, r: f32) -> f32 {
    let qx = (px - cx).abs() - (hw - r);
    let qy = (py - cy).abs() - (hh - r);
    let ox = qx.max(0.0);
    let oy = qy.max(0.0);
    (ox * ox + oy * oy).sqrt() + qx.max(qy).min(0.0) - r
}

impl Canvas {
    pub fn new(width: u32, height: u32, scale: f32) -> Canvas {
        let mut c = Canvas {
            width: 0,
            height: 0,
            pixels: Vec::new(),
            scale: 1.0,
            clip: IRect { x0: 0, y0: 0, x1: 0, y1: 0 },
            clip_stack: Vec::new(),
        };
        c.resize(width, height, scale);
        c
    }

    pub fn resize(&mut self, width: u32, height: u32, scale: f32) {
        self.scale = if scale > 0.0 { scale } else { 1.0 };
        if width != self.width || height != self.height {
            self.width = width;
            self.height = height;
            self.pixels = vec![0; width as usize * height as usize];
        }
        self.reset_clip();
    }

    pub fn reset_clip(&mut self) {
        self.clip_stack.clear();
        self.clip = IRect { x0: 0, y0: 0, x1: self.width as i32, y1: self.height as i32 };
    }

    /// Logical size of the canvas.
    pub fn logical_size(&self) -> (f32, f32) {
        (self.width as f32 / self.scale, self.height as f32 / self.scale)
    }

    pub fn push_clip(&mut self, r: Rect) {
        self.clip_stack.push(self.clip);
        let s = self.scale;
        let n = IRect {
            x0: ((r.x * s).round() as i32).max(self.clip.x0),
            y0: ((r.y * s).round() as i32).max(self.clip.y0),
            x1: ((r.right() * s).round() as i32).min(self.clip.x1),
            y1: ((r.bottom() * s).round() as i32).min(self.clip.y1),
        };
        self.clip = n;
    }

    pub fn pop_clip(&mut self) {
        if let Some(c) = self.clip_stack.pop() {
            self.clip = c;
        }
    }

    /// Current clip rectangle in logical coordinates.
    pub fn clip_rect(&self) -> Rect {
        let s = self.scale;
        Rect::new(
            self.clip.x0 as f32 / s,
            self.clip.y0 as f32 / s,
            (self.clip.x1 - self.clip.x0).max(0) as f32 / s,
            (self.clip.y1 - self.clip.y0).max(0) as f32 / s,
        )
    }

    pub fn clear(&mut self, c: Color) {
        let v = c.0 & 0xFF_FFFF;
        self.pixels.iter_mut().for_each(|p| *p = v);
    }

    #[inline]
    fn put(&mut self, x: i32, y: i32, c: u32, a: u32) {
        let i = y as usize * self.width as usize + x as usize;
        self.pixels[i] = blend(self.pixels[i], c, a);
    }

    fn span(&mut self, y: i32, x0: i32, x1: i32, c: u32, a: u32) {
        let x0 = x0.max(self.clip.x0);
        let x1 = x1.min(self.clip.x1);
        if y < self.clip.y0 || y >= self.clip.y1 || x0 >= x1 {
            return;
        }
        let row = y as usize * self.width as usize;
        let px = &mut self.pixels[row + x0 as usize..row + x1 as usize];
        if a >= 255 {
            let v = c & 0xFF_FFFF;
            px.iter_mut().for_each(|p| *p = v);
        } else {
            px.iter_mut().for_each(|p| *p = blend(*p, c, a));
        }
    }

    /// Fill an axis-aligned rectangle (edges snapped to pixels).
    pub fn fill_rect(&mut self, r: Rect, color: Color) {
        let a = color.a() as u32;
        if a == 0 {
            return;
        }
        let s = self.scale;
        let x0 = (r.x * s).round() as i32;
        let x1 = (r.right() * s).round() as i32;
        let y0 = ((r.y * s).round() as i32).max(self.clip.y0);
        let y1 = ((r.bottom() * s).round() as i32).min(self.clip.y1);
        for y in y0..y1 {
            self.span(y, x0, x1, color.0, a);
        }
    }

    /// Generic signed-distance rasteriser over a physical bounding box.
    fn raster_sdf(&mut self, bx0: f32, by0: f32, bx1: f32, by1: f32, color: Color, f: impl Fn(f32, f32) -> f32) {
        let a = color.a() as f32;
        if a == 0.0 {
            return;
        }
        let x0 = (bx0.floor() as i32).max(self.clip.x0);
        let y0 = (by0.floor() as i32).max(self.clip.y0);
        let x1 = (bx1.ceil() as i32).min(self.clip.x1);
        let y1 = (by1.ceil() as i32).min(self.clip.y1);
        for y in y0..y1 {
            for x in x0..x1 {
                let cov = f(x as f32 + 0.5, y as f32 + 0.5);
                if cov > 0.0 {
                    self.put(x, y, color.0, (cov.min(1.0) * a + 0.5) as u32);
                }
            }
        }
    }

    fn phys_rect(&self, r: Rect) -> (f32, f32, f32, f32) {
        let s = self.scale;
        ((r.x * s).round(), (r.y * s).round(), (r.right() * s).round(), (r.bottom() * s).round())
    }

    /// Anti-aliased filled rounded rectangle.
    pub fn fill_rounded_rect(&mut self, r: Rect, radius: f32, color: Color) {
        let a = color.a() as u32;
        if a == 0 {
            return;
        }
        let (x0, y0, x1, y1) = self.phys_rect(r);
        if x1 <= x0 || y1 <= y0 {
            return;
        }
        let rad = (radius * self.scale).min((x1 - x0) * 0.5).min((y1 - y0) * 0.5).max(0.0);
        if rad < 0.5 {
            return self.fill_rect(r, color);
        }
        let (cx, cy, hw, hh) = ((x0 + x1) * 0.5, (y0 + y1) * 0.5, (x1 - x0) * 0.5, (y1 - y0) * 0.5);
        let iy0 = (y0 as i32).max(self.clip.y0);
        let iy1 = (y1 as i32).min(self.clip.y1);
        let ix0 = (x0 as i32).max(self.clip.x0);
        let ix1 = (x1 as i32).min(self.clip.x1);
        let cl = (x0 + rad).ceil() as i32; // first column outside left corner zone
        let cr = (x1 - rad).floor() as i32; // first column of right corner zone
        for y in iy0..iy1 {
            let fy = y as f32 + 0.5;
            if fy > y0 + rad && fy < y1 - rad {
                self.span(y, ix0, ix1, color.0, a);
                continue;
            }
            for x in ix0..ix1 {
                if x >= cl && x < cr {
                    // straight top/bottom edge region: fully covered (edges are pixel aligned)
                    self.put(x, y, color.0, a);
                    continue;
                }
                let d = sd_round_box(x as f32 + 0.5, fy, cx, cy, hw, hh, rad);
                let cov = (0.5 - d).clamp(0.0, 1.0);
                if cov > 0.0 {
                    self.put(x, y, color.0, (cov * a as f32 + 0.5) as u32);
                }
            }
        }
    }

    /// Anti-aliased rounded-rectangle outline, stroke drawn *inside* `r`.
    pub fn stroke_rounded_rect(&mut self, r: Rect, radius: f32, width: f32, color: Color) {
        let a = color.a() as f32;
        if a == 0.0 {
            return;
        }
        let (x0, y0, x1, y1) = self.phys_rect(r);
        if x1 <= x0 || y1 <= y0 {
            return;
        }
        let w = (width * self.scale).max(1.0);
        let rad = (radius * self.scale).min((x1 - x0) * 0.5).min((y1 - y0) * 0.5).max(0.0);
        let (cx, cy, hw, hh) = ((x0 + x1) * 0.5, (y0 + y1) * 0.5, (x1 - x0) * 0.5, (y1 - y0) * 0.5);
        let band = rad.max(w) + 1.0;
        let iy0 = (y0 as i32).max(self.clip.y0);
        let iy1 = (y1 as i32).min(self.clip.y1);
        let ix0 = (x0 as i32).max(self.clip.x0);
        let ix1 = (x1 as i32).min(self.clip.x1);
        let lb = ((x0 + band).ceil() as i32).min(ix1);
        let rb = ((x1 - band).floor() as i32).max(lb);
        for y in iy0..iy1 {
            let fy = y as f32 + 0.5;
            let full_row = fy < y0 + band || fy > y1 - band;
            let mut x = ix0;
            while x < ix1 {
                if !full_row && x == lb {
                    x = rb.max(x);
                    if x >= ix1 {
                        break;
                    }
                }
                let d = sd_round_box(x as f32 + 0.5, fy, cx, cy, hw, hh, rad);
                let cov = (0.5 - d).clamp(0.0, 1.0) - (0.5 - (d + w)).clamp(0.0, 1.0);
                if cov > 0.0 {
                    self.put(x, y, color.0, (cov * a + 0.5) as u32);
                }
                x += 1;
            }
        }
    }

    /// Soft shadow under a rounded rect. Only the area *outside* `r - blur` is
    /// painted (the interior is expected to be covered by the shape itself).
    pub fn shadow(&mut self, r: Rect, radius: f32, blur: f32, color: Color) {
        let s = self.scale;
        let (x0, y0, x1, y1) = self.phys_rect(r);
        let b = (blur * s).max(1.0);
        let rad = (radius * s).min((x1 - x0) * 0.5).min((y1 - y0) * 0.5).max(0.0);
        let (cx, cy, hw, hh) = ((x0 + x1) * 0.5, (y0 + y1) * 0.5, (x1 - x0) * 0.5, (y1 - y0) * 0.5);
        let inner_skip = (x0 + rad + b, y0 + rad + b, x1 - rad - b, y1 - rad - b);
        self.raster_sdf(x0 - b, y0 - b, x1 + b, y1 + b, color, |px, py| {
            if px > inner_skip.0 && px < inner_skip.2 && py > inner_skip.1 && py < inner_skip.3 {
                return 0.0;
            }
            let d = sd_round_box(px, py, cx, cy, hw, hh, rad);
            let t = (0.5 - d / (2.0 * b)).clamp(0.0, 1.0);
            t * t * (3.0 - 2.0 * t)
        });
    }

    pub fn fill_circle(&mut self, cx: f32, cy: f32, r: f32, color: Color) {
        let s = self.scale;
        let (cx, cy, r) = (cx * s, cy * s, r * s);
        self.raster_sdf(cx - r - 1.0, cy - r - 1.0, cx + r + 1.0, cy + r + 1.0, color, |x, y| {
            let d = ((x - cx) * (x - cx) + (y - cy) * (y - cy)).sqrt() - r;
            (0.5 - d).clamp(0.0, 1.0)
        });
    }

    /// Circle outline centred on radius `r`.
    pub fn stroke_circle(&mut self, cx: f32, cy: f32, r: f32, width: f32, color: Color) {
        let s = self.scale;
        let (cx, cy, r, hw) = (cx * s, cy * s, r * s, (width * s).max(1.0) * 0.5);
        let e = r + hw + 1.0;
        self.raster_sdf(cx - e, cy - e, cx + e, cy + e, color, |x, y| {
            let d = (((x - cx) * (x - cx) + (y - cy) * (y - cy)).sqrt() - r).abs() - hw;
            (0.5 - d).clamp(0.0, 1.0)
        });
    }

    /// Anti-aliased line with round caps.
    pub fn line(&mut self, x0: f32, y0: f32, x1: f32, y1: f32, width: f32, color: Color) {
        let s = self.scale;
        let (ax, ay, bx, by) = (x0 * s, y0 * s, x1 * s, y1 * s);
        let hw = (width * s).max(1.0) * 0.5;
        let (dx, dy) = (bx - ax, by - ay);
        let len2 = (dx * dx + dy * dy).max(1e-6);
        self.raster_sdf(
            ax.min(bx) - hw - 1.0,
            ay.min(by) - hw - 1.0,
            ax.max(bx) + hw + 1.0,
            ay.max(by) + hw + 1.0,
            color,
            |x, y| {
                let t = (((x - ax) * dx + (y - ay) * dy) / len2).clamp(0.0, 1.0);
                let (qx, qy) = (ax + dx * t - x, ay + dy * t - y);
                let d = (qx * qx + qy * qy).sqrt() - hw;
                (0.5 - d).clamp(0.0, 1.0)
            },
        );
    }

    /// Polyline through logical points (round joins via round caps).
    pub fn polyline(&mut self, pts: &[(f32, f32)], closed: bool, width: f32, color: Color) {
        for w in pts.windows(2) {
            self.line(w[0].0, w[0].1, w[1].0, w[1].1, width, color);
        }
        if closed && pts.len() > 2 {
            let (a, b) = (pts[pts.len() - 1], pts[0]);
            self.line(a.0, a.1, b.0, b.1, width, color);
        }
    }

    /// Blend an 8-bit coverage mask at a *physical* position.
    pub fn draw_mask(&mut self, x: i32, y: i32, w: usize, h: usize, mask: &[u8], color: Color) {
        let a = color.a() as u32;
        if a == 0 {
            return;
        }
        let ys = y.max(self.clip.y0);
        let ye = (y + h as i32).min(self.clip.y1);
        let xs = x.max(self.clip.x0);
        let xe = (x + w as i32).min(self.clip.x1);
        for py in ys..ye {
            let mrow = (py - y) as usize * w;
            let prow = py as usize * self.width as usize;
            for px in xs..xe {
                let m = mask[mrow + (px - x) as usize] as u32;
                if m != 0 {
                    let i = prow + px as usize;
                    self.pixels[i] = blend(self.pixels[i], color.0, (m * a + 127) / 255);
                }
            }
        }
    }

    /// Copy an image (0x00RRGGBB / 0xAARRGGBB with alpha) at a physical position.
    pub fn blit_argb(&mut self, x: i32, y: i32, w: usize, h: usize, src: &[u32]) {
        for sy in 0..h as i32 {
            let py = y + sy;
            if py < self.clip.y0 || py >= self.clip.y1 {
                continue;
            }
            for sx in 0..w as i32 {
                let px = x + sx;
                if px < self.clip.x0 || px >= self.clip.x1 {
                    continue;
                }
                let c = src[sy as usize * w + sx as usize];
                self.put(px, py, c, c >> 24);
            }
        }
    }

    /// Write the canvas as a binary PPM (handy for tests / screenshots).
    pub fn to_ppm(&self) -> Vec<u8> {
        let mut out = format!("P6\n{} {}\n255\n", self.width, self.height).into_bytes();
        for &p in &self.pixels {
            out.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, p as u8]);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blend_extremes() {
        assert_eq!(blend(0x000000, 0xFFFFFF, 255), 0xFFFFFF);
        assert_eq!(blend(0x123456, 0xFFFFFF, 0), 0x123456);
        let m = blend(0x000000, 0xFFFFFF, 128);
        assert!(((m >> 16) & 255) >= 127 && ((m >> 16) & 255) <= 129);
    }
    #[test]
    fn rounded_rect_inside_and_corner() {
        let mut c = Canvas::new(40, 40, 1.0);
        c.clear(Color::BLACK);
        c.fill_rounded_rect(Rect::new(0.0, 0.0, 40.0, 40.0), 10.0, Color::WHITE);
        assert_eq!(c.pixels[20 * 40 + 20], 0xFFFFFF);
        assert_eq!(c.pixels[0], 0x000000); // corner cut off
        assert_eq!(c.pixels[20 * 40], 0xFFFFFF); // left edge middle
    }
    #[test]
    fn clipping() {
        let mut c = Canvas::new(10, 10, 1.0);
        c.push_clip(Rect::new(2.0, 2.0, 3.0, 3.0));
        c.fill_rect(Rect::new(0.0, 0.0, 10.0, 10.0), Color::WHITE);
        c.pop_clip();
        assert_eq!(c.pixels.iter().filter(|&&p| p == 0xFFFFFF).count(), 9);
    }
}

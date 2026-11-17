//! X11 backend speaking the core X11 wire protocol directly over a socket.

use super::WindowOptions;
use crate::canvas::Canvas;
use crate::event::{CursorIcon, Event, Key, Mods, MouseButton};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

enum Stream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl Stream {
    fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        match self {
            Stream::Unix(s) => s.set_read_timeout(t),
            Stream::Tcp(s) => s.set_read_timeout(t),
        }
    }
    fn set_nonblocking(&self, b: bool) -> io::Result<()> {
        match self {
            Stream::Unix(s) => s.set_nonblocking(b),
            Stream::Tcp(s) => s.set_nonblocking(b),
        }
    }
}
impl Read for Stream {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Unix(s) => s.read(b),
            Stream::Tcp(s) => s.read(b),
        }
    }
}
impl Write for Stream {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Unix(s) => s.write(b),
            Stream::Tcp(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Wait {
    Block,
    Poll,
    Timeout(Duration),
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn other(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.into())
}

/// Request builder (little-endian, padded, length filled in).
struct Req(Vec<u8>);
impl Req {
    fn new(op: u8, data: u8) -> Req {
        Req(vec![op, data, 0, 0])
    }
    fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }
    fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn bytes(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }
    fn pad(mut self) -> Self {
        while self.0.len() % 4 != 0 {
            self.0.push(0);
        }
        self
    }
    fn done(self) -> Vec<u8> {
        let mut v = self.pad().0;
        let n = (v.len() / 4) as u16;
        v[2..4].copy_from_slice(&n.to_le_bytes());
        v
    }
}

struct Conn {
    s: Stream,
    seq: u16,
    pending: VecDeque<Vec<u8>>,
    id_base: u32,
    id_mask: u32,
    next_id: u32,
    max_req_bytes: usize,
    mode: Option<Wait>,
}

impl Conn {
    fn alloc_id(&mut self) -> u32 {
        self.next_id += 1;
        self.id_base | (self.next_id & self.id_mask)
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        // writes must block: the socket may have been left non-blocking by a poll
        self.set_mode(Wait::Block)?;
        self.s.write_all(data)
    }

    fn send(&mut self, data: &[u8]) -> io::Result<u16> {
        self.write_all(data)?;
        self.seq = self.seq.wrapping_add(1);
        Ok(self.seq)
    }

    fn set_mode(&mut self, w: Wait) -> io::Result<()> {
        if self.mode == Some(w) {
            return Ok(());
        }
        match w {
            Wait::Block => {
                self.s.set_nonblocking(false)?;
                self.s.set_read_timeout(None)?;
            }
            Wait::Poll => self.s.set_nonblocking(true)?,
            Wait::Timeout(d) => {
                self.s.set_nonblocking(false)?;
                self.s.set_read_timeout(Some(d.max(Duration::from_millis(1))))?;
            }
        }
        self.mode = Some(w);
        Ok(())
    }

    /// Read one packet (event, reply or error). `Ok(None)` if nothing arrived in time.
    fn read_packet(&mut self, w: Wait) -> io::Result<Option<Vec<u8>>> {
        let mut head = vec![0u8; 32];
        self.set_mode(w)?;
        let n = match self.s.read(&mut head) {
            Ok(0) => return Err(other("X server closed the connection")),
            Ok(n) => n,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };
        self.set_mode(Wait::Block)?;
        self.s.read_exact(&mut head[n..])?;
        if head[0] == 1 {
            let extra = le32(&head, 4) as usize * 4;
            if extra > 0 {
                head.resize(32 + extra, 0);
                self.s.read_exact(&mut head[32..])?;
            }
        }
        Ok(Some(head))
    }

    fn reply(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let seq = self.send(data)?;
        loop {
            let p = self.read_packet(Wait::Block)?.ok_or_else(|| other("no reply"))?;
            let pseq = le16(&p, 2);
            match p[0] {
                1 if pseq == seq => return Ok(p),
                0 if pseq == seq => return Err(other(format!("X error {} for request {}", p[1], p[10]))),
                0 | 1 => {}
                _ => self.pending.push_back(p),
            }
        }
    }

    fn intern(&mut self, name: &str) -> io::Result<u32> {
        let r = Req::new(16, 0).u16(name.len() as u16).u16(0).bytes(name.as_bytes()).done();
        Ok(le32(&self.reply(&r)?, 8))
    }

    fn change_property(&mut self, win: u32, prop: u32, ty: u32, format: u8, data: &[u8]) -> io::Result<()> {
        let n = data.len() as u32 / (format as u32 / 8);
        let r = Req::new(18, 0).u32(win).u32(prop).u32(ty).u8(format).bytes(&[0, 0, 0]).u32(n).bytes(data).done();
        self.send(&r).map(|_| ())
    }

    /// GetProperty → (type, format, data)
    fn get_property(&mut self, win: u32, prop: u32, delete: bool) -> io::Result<(u32, u8, Vec<u8>)> {
        let r = Req::new(20, delete as u8).u32(win).u32(prop).u32(0).u32(0).u32(0x0400_0000).done();
        let p = self.reply(&r)?;
        let fmt = p[1];
        let ty = le32(&p, 8);
        let n = le32(&p, 16) as usize * (fmt as usize / 8).max(1);
        Ok((ty, fmt, p.get(32..32 + n).unwrap_or(&[]).to_vec()))
    }
}

struct Atoms {
    wm_protocols: u32,
    wm_delete: u32,
    net_wm_name: u32,
    utf8: u32,
    clipboard: u32,
    targets: u32,
    bt_sel: u32,
    net_wm_icon: u32,
    net_wm_pid: u32,
    incr: u32,
}

const XA_ATOM: u32 = 4;
const XA_CARDINAL: u32 = 6;
const XA_STRING: u32 = 31;
const XA_WM_NAME: u32 = 39;
const XA_WM_NORMAL_HINTS: u32 = 40;
const XA_WM_SIZE_HINTS: u32 = 41;
const XA_WM_CLASS: u32 = 67;
const XA_RESOURCE_MANAGER: u32 = 23;

pub struct Window {
    c: Conn,
    win: u32,
    gc: u32,
    root: u32,
    depth: u8,
    width: u32,
    height: u32,
    scale: f32,
    atoms: Atoms,
    min_keycode: u8,
    max_keycode: u8,
    syms_per: usize,
    keysyms: Vec<u32>,
    queue: VecDeque<Event>,
    cursors: [u32; 3],
    cursor: CursorIcon,
    clip_owned: Option<String>,
    mods: Mods,
    dead: bool,
}

fn read_xauth(display: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let path = std::env::var_os("XAUTHORITY")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".Xauthority")))?;
    let data = std::fs::read(path).ok()?;
    let mut p = 0;
    let rd = |p: &mut usize| -> Option<Vec<u8>> {
        let n = u16::from_be_bytes([*data.get(*p)?, *data.get(*p + 1)?]) as usize;
        let v = data.get(*p + 2..*p + 2 + n)?.to_vec();
        *p += 2 + n;
        Some(v)
    };
    let mut fallback = None;
    while p + 2 <= data.len() {
        p += 2; // family
        let _addr = rd(&mut p)?;
        let num = rd(&mut p)?;
        let name = rd(&mut p)?;
        let auth = rd(&mut p)?;
        if name == b"MIT-MAGIC-COOKIE-1" {
            if num == display.as_bytes() {
                return Some((name, auth));
            }
            if num.is_empty() && fallback.is_none() {
                fallback = Some((name, auth));
            }
        }
    }
    fallback
}

impl Window {
    pub fn new(opts: &WindowOptions) -> io::Result<Window> {
        let disp = std::env::var("DISPLAY").map_err(|_| other("DISPLAY is not set (no X11 display)"))?;
        let (host, rest) = disp.rsplit_once(':').ok_or_else(|| other("bad DISPLAY"))?;
        let num = rest.split('.').next().unwrap_or("0").to_string();
        let stream = if host.is_empty() || host == "unix" {
            let path = format!("/tmp/.X11-unix/X{num}");
            match UnixStream::connect(&path) {
                Ok(s) => Stream::Unix(s),
                Err(e) => {
                    #[cfg(target_os = "linux")]
                    {
                        use std::os::linux::net::SocketAddrExt;
                        let addr = std::os::unix::net::SocketAddr::from_abstract_name(path.as_bytes())?;
                        Stream::Unix(UnixStream::connect_addr(&addr).map_err(|_| e)?)
                    }
                    #[cfg(not(target_os = "linux"))]
                    return Err(e);
                }
            }
        } else {
            let port: u16 = 6000 + num.parse::<u16>().unwrap_or(0);
            let s = TcpStream::connect((host, port))?;
            s.set_nodelay(true).ok();
            Stream::Tcp(s)
        };
        let mut c = Conn {
            s: stream,
            seq: 0,
            pending: VecDeque::new(),
            id_base: 0,
            id_mask: 0,
            next_id: 0,
            max_req_bytes: 0,
            mode: None,
        };
        // --- connection setup ---
        let (an, ad) = read_xauth(&num).unwrap_or_default();
        let setup = Req(vec![b'l', 0])
            .u16(11)
            .u16(0)
            .u16(an.len() as u16)
            .u16(ad.len() as u16)
            .u16(0)
            .bytes(&an)
            .pad()
            .bytes(&ad)
            .pad()
            .0;
        c.s.write_all(&setup)?;
        let mut h = [0u8; 8];
        c.s.read_exact(&mut h)?;
        let extra = le16(&h, 6) as usize * 4;
        let mut d = vec![0u8; extra];
        c.s.read_exact(&mut d)?;
        if h[0] != 1 {
            let reason = String::from_utf8_lossy(&d[..(h[1] as usize).min(d.len())]).to_string();
            return Err(other(format!("X11 connection refused: {reason}")));
        }
        c.id_base = le32(&d, 4);
        c.id_mask = le32(&d, 8);
        let vendor_len = le16(&d, 16) as usize;
        c.max_req_bytes = le16(&d, 18) as usize * 4;
        let nscreens = d[20];
        let nformats = d[21] as usize;
        if nscreens == 0 {
            return Err(other("X server has no screens"));
        }
        let mut p = 32 + ((vendor_len + 3) & !3);
        let mut bpp_for_depth = [0u8; 33];
        for _ in 0..nformats {
            let (depth, bpp) = (d[p] as usize, d[p + 1]);
            if depth <= 32 {
                bpp_for_depth[depth] = bpp;
            }
            p += 8;
        }
        let root = le32(&d, p);
        let root_visual = le32(&d, p + 32);
        let depth = d[p + 38];
        if bpp_for_depth[depth as usize] != 32 {
            return Err(other(format!("unsupported X visual: depth {depth} needs 32 bpp")));
        }

        let mut atoms = Atoms {
            wm_protocols: 0,
            wm_delete: 0,
            net_wm_name: 0,
            utf8: 0,
            clipboard: 0,
            targets: 0,
            bt_sel: 0,
            net_wm_icon: 0,
            net_wm_pid: 0,
            incr: 0,
        };
        atoms.wm_protocols = c.intern("WM_PROTOCOLS")?;
        atoms.wm_delete = c.intern("WM_DELETE_WINDOW")?;
        atoms.net_wm_name = c.intern("_NET_WM_NAME")?;
        atoms.utf8 = c.intern("UTF8_STRING")?;
        atoms.clipboard = c.intern("CLIPBOARD")?;
        atoms.targets = c.intern("TARGETS")?;
        atoms.bt_sel = c.intern("BT_GUI_SELECTION")?;
        atoms.net_wm_icon = c.intern("_NET_WM_ICON")?;
        atoms.net_wm_pid = c.intern("_NET_WM_PID")?;
        atoms.incr = c.intern("INCR")?;

        // DPI from Xft.dpi in RESOURCE_MANAGER
        let mut scale = 1.0;
        if let Ok((_, _, data)) = c.get_property(root, XA_RESOURCE_MANAGER, false) {
            let s = String::from_utf8_lossy(&data);
            for line in s.lines() {
                if let Some(v) = line.strip_prefix("Xft.dpi:") {
                    if let Ok(dpi) = v.trim().parse::<f32>() {
                        scale = (dpi / 96.0).clamp(1.0, 4.0);
                    }
                }
            }
        }
        if let Some(s) = super::env_scale() {
            scale = s;
        }
        let width = (opts.width as f32 * scale).round() as u32;
        let height = (opts.height as f32 * scale).round() as u32;

        let win = c.alloc_id();
        let event_mask: u32 = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x8000 | 0x20000 | 0x200000;
        // value-mask: bit-gravity(0x10), event-mask(0x800)
        let r = Req::new(1, depth)
            .u32(win)
            .u32(root)
            .u16(0)
            .u16(0)
            .u16(width as u16)
            .u16(height as u16)
            .u16(0)
            .u16(1)
            .u32(root_visual)
            .u32(0x10 | 0x800)
            .u32(1)
            .u32(event_mask)
            .done();
        c.send(&r)?;
        let gc = c.alloc_id();
        c.send(&Req::new(55, 0).u32(gc).u32(win).u32(0x10000).u32(0).done())?; // graphics-exposures off

        c.change_property(win, atoms.wm_protocols, XA_ATOM, 32, &atoms.wm_delete.to_le_bytes())?;
        let class = format!("{}\0{}\0", opts.app_id, opts.app_id);
        c.change_property(win, XA_WM_CLASS, XA_STRING, 8, class.as_bytes())?;
        c.change_property(win, atoms.net_wm_pid, XA_CARDINAL, 32, &std::process::id().to_le_bytes())?;
        let mut hints = [0u32; 18];
        hints[0] = 16; // PMinSize
        hints[5] = (opts.min_width as f32 * scale) as u32;
        hints[6] = (opts.min_height as f32 * scale) as u32;
        let hb: Vec<u8> = hints.iter().flat_map(|v| v.to_le_bytes()).collect();
        c.change_property(win, XA_WM_NORMAL_HINTS, XA_WM_SIZE_HINTS, 32, &hb)?;
        if let Some((w, h, px)) = &opts.icon {
            let mut v: Vec<u8> = Vec::with_capacity(8 + px.len() * 4);
            v.extend_from_slice(&w.to_le_bytes());
            v.extend_from_slice(&h.to_le_bytes());
            for p in px {
                v.extend_from_slice(&p.to_le_bytes());
            }
            c.change_property(win, atoms.net_wm_icon, XA_CARDINAL, 32, &v)?;
        }

        // cursors from the "cursor" font: left_ptr=68, hand2=60, xterm=152
        let font = c.alloc_id();
        c.send(&Req::new(45, 0).u32(font).u16(6).u16(0).bytes(b"cursor").done())?;
        let mut cursors = [0u32; 3];
        for (i, g) in [68u16, 60, 152].iter().enumerate() {
            let id = c.alloc_id();
            let r = Req::new(94, 0)
                .u32(id)
                .u32(font)
                .u32(font)
                .u16(*g)
                .u16(*g + 1)
                .u16(0)
                .u16(0)
                .u16(0)
                .u16(0xFFFF)
                .u16(0xFFFF)
                .u16(0xFFFF)
                .done();
            c.send(&r)?;
            cursors[i] = id;
        }

        let mut w = Window {
            c,
            win,
            gc,
            root,
            depth,
            width,
            height,
            scale,
            atoms,
            min_keycode: d[26],
            max_keycode: d[27],
            syms_per: 1,
            keysyms: Vec::new(),
            queue: VecDeque::new(),
            cursors,
            cursor: CursorIcon::Arrow,
            clip_owned: None,
            mods: Mods::default(),
            dead: false,
        };
        w.set_title(&opts.title);
        w.c.send(&Req::new(2, 0).u32(win).u32(0x4000).u32(cursors[0]).done())?;
        w.load_keymap()?;
        w.c.send(&Req::new(8, 0).u32(win).done())?; // MapWindow
        let _ = w.root;
        Ok(w)
    }

    fn load_keymap(&mut self) -> io::Result<()> {
        let count = (self.max_keycode as u16 + 1).saturating_sub(self.min_keycode as u16).min(255) as u8;
        let r = Req::new(101, 0).u8(self.min_keycode).u8(count).u16(0).done();
        let p = self.c.reply(&r)?;
        self.syms_per = (p[1] as usize).max(1);
        let n = le32(&p, 4) as usize;
        self.keysyms = (0..n).map(|i| le32(&p, 32 + 4 * i)).collect();
        Ok(())
    }

    fn keysym(&self, code: u8, idx: usize) -> u32 {
        if code < self.min_keycode {
            return 0;
        }
        let base = (code - self.min_keycode) as usize * self.syms_per;
        if idx >= self.syms_per {
            return 0;
        }
        *self.keysyms.get(base + idx).unwrap_or(&0)
    }

    fn mods_from_state(state: u16) -> Mods {
        Mods { shift: state & 1 != 0, ctrl: state & 4 != 0, alt: state & 8 != 0, logo: state & 0x40 != 0 }
    }

    fn handle_key(&mut self, code: u8, state: u16, press: bool) {
        let ks0 = self.keysym(code, 0);
        let mut ks1 = self.keysym(code, 1);
        if ks1 == 0 {
            ks1 = ks0;
        }
        let mut mods = Self::mods_from_state(state);
        // the state is from *before* this event; apply modifier key changes
        match ks0 {
            0xffe1 | 0xffe2 => mods.shift = press,
            0xffe3 | 0xffe4 => mods.ctrl = press,
            0xffe9 | 0xffea => mods.alt = press,
            0xffeb | 0xffec => mods.logo = press,
            _ => {}
        }
        self.mods = mods;
        let key = match ks0 {
            0xff08 => Key::Backspace,
            0xff09 | 0xfe20 => Key::Tab,
            0xff0d | 0xff8d => Key::Enter,
            0xff1b => Key::Escape,
            0xffff | 0xff9f => Key::Delete,
            0xff50 | 0xff95 => Key::Home,
            0xff51 | 0xff96 => Key::Left,
            0xff52 | 0xff97 => Key::Up,
            0xff53 | 0xff98 => Key::Right,
            0xff54 | 0xff99 => Key::Down,
            0xff55 | 0xff9a => Key::PageUp,
            0xff56 | 0xff9b => Key::PageDown,
            0xff57 | 0xff9c => Key::End,
            0xff63 | 0xff9e => Key::Insert,
            0x20 => Key::Space,
            0xffbe..=0xffc9 => Key::F((ks0 - 0xffbe + 1) as u8),
            k => match keysym_char(k) {
                Some(ch) => Key::Char(ch.to_ascii_lowercase()),
                None => Key::Unknown,
            },
        };
        if !press {
            self.queue.push_back(Event::KeyUp { key, mods });
            return;
        }
        self.queue.push_back(Event::KeyDown { key, mods });
        if mods.ctrl || mods.alt || mods.logo {
            return;
        }
        let caps = state & 2 != 0;
        let numlock = state & 0x10 != 0;
        let is_letter = keysym_char(ks0).map_or(false, |c| c.is_alphabetic());
        let sym = if (0xff80..=0xffbd).contains(&ks1) && numlock {
            ks1
        } else if mods.shift ^ (caps && is_letter) {
            ks1
        } else {
            ks0
        };
        let mut ch = keysym_char(sym);
        if caps && is_letter && !mods.shift {
            ch = ch.map(|c| c.to_uppercase().next().unwrap_or(c));
        }
        if let Some(ch) = ch {
            if !ch.is_control() {
                self.queue.push_back(Event::Text(ch.to_string()));
            }
        }
    }

    fn handle_packet(&mut self, p: &[u8]) {
        let code = p[0] & 0x7f;
        match code {
            2 | 3 => self.handle_key(p[1], le16(p, 28), code == 2),
            4 | 5 => {
                let (x, y) = (le16(p, 24) as i16 as f32, le16(p, 26) as i16 as f32);
                let state = le16(p, 28);
                self.mods = Self::mods_from_state(state);
                let press = code == 4;
                let button = match p[1] {
                    1 => MouseButton::Left,
                    2 => MouseButton::Middle,
                    3 => MouseButton::Right,
                    4..=7 => {
                        if press {
                            let (dx, dy) = match p[1] {
                                4 => (0.0, 1.0),
                                5 => (0.0, -1.0),
                                6 => (1.0, 0.0),
                                _ => (-1.0, 0.0),
                            };
                            self.queue.push_back(Event::Scroll { dx, dy });
                        }
                        return;
                    }
                    _ => return,
                };
                self.queue.push_back(if press { Event::MouseDown { x, y, button } } else { Event::MouseUp { x, y, button } });
            }
            6 => {
                let (x, y) = (le16(p, 24) as i16 as f32, le16(p, 26) as i16 as f32);
                if let Some(Event::MouseMove { .. }) = self.queue.back() {
                    self.queue.pop_back(); // coalesce motion
                }
                self.queue.push_back(Event::MouseMove { x, y });
            }
            7 => {
                let (x, y) = (le16(p, 24) as i16 as f32, le16(p, 26) as i16 as f32);
                self.queue.push_back(Event::MouseMove { x, y });
            }
            8 => {
                if p[30] == 0 {
                    // NotifyNormal (not a grab)
                    self.queue.push_back(Event::MouseLeft);
                }
            }
            9 => self.queue.push_back(Event::Focus(true)),
            10 => self.queue.push_back(Event::Focus(false)),
            12 => {
                if le16(p, 16) == 0 && !self.queue.iter().any(|e| *e == Event::Redraw) {
                    self.queue.push_back(Event::Redraw);
                }
            }
            22 => {
                let (w, h) = (le16(p, 20) as u32, le16(p, 22) as u32);
                if le32(p, 8) == self.win && (w != self.width || h != self.height) {
                    self.width = w;
                    self.height = h;
                    self.queue.retain(|e| !matches!(e, Event::Resized { .. }));
                    self.queue.push_back(Event::Resized { w, h });
                }
            }
            29 => {
                if le32(p, 12) == self.atoms.clipboard {
                    self.clip_owned = None;
                }
            }
            30 => self.answer_selection_request(p),
            33 => {
                if le32(p, 8) == self.atoms.wm_protocols && le32(p, 12) == self.atoms.wm_delete {
                    self.queue.push_back(Event::CloseRequested);
                }
            }
            34 => {
                let _ = self.load_keymap();
            }
            _ => {}
        }
    }

    fn answer_selection_request(&mut self, p: &[u8]) {
        let time = le32(p, 4);
        let requestor = le32(p, 12);
        let selection = le32(p, 16);
        let target = le32(p, 20);
        let mut property = le32(p, 24);
        if property == 0 {
            property = target;
        }
        let ok = match &self.clip_owned {
            Some(text) if selection == self.atoms.clipboard => {
                let text = text.clone();
                if target == self.atoms.targets {
                    let list: Vec<u8> =
                        [self.atoms.targets, self.atoms.utf8, XA_STRING].iter().flat_map(|a| a.to_le_bytes()).collect();
                    self.c.change_property(requestor, property, XA_ATOM, 32, &list).is_ok()
                } else if target == self.atoms.utf8 || target == XA_STRING {
                    self.c.change_property(requestor, property, target, 8, text.as_bytes()).is_ok()
                } else {
                    false
                }
            }
            _ => false,
        };
        let mut ev = vec![31u8, 0, 0, 0];
        ev.extend_from_slice(&time.to_le_bytes());
        ev.extend_from_slice(&requestor.to_le_bytes());
        ev.extend_from_slice(&selection.to_le_bytes());
        ev.extend_from_slice(&target.to_le_bytes());
        ev.extend_from_slice(&(if ok { property } else { 0 }).to_le_bytes());
        ev.resize(32, 0);
        let r = Req::new(25, 0).u32(requestor).u32(0).bytes(&ev).done();
        let _ = self.c.send(&r);
    }

    pub fn next_event(&mut self, timeout: Option<Duration>) -> Option<Event> {
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            if let Some(e) = self.queue.pop_front() {
                return Some(e);
            }
            if self.dead {
                return Some(Event::CloseRequested);
            }
            if let Some(p) = self.c.pending.pop_front() {
                self.handle_packet(&p);
                continue;
            }
            let wait = match deadline {
                None => Wait::Block,
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        Wait::Poll
                    } else {
                        Wait::Timeout(d - now)
                    }
                }
            };
            match self.c.read_packet(wait) {
                Ok(Some(p)) => {
                    if p[0] > 1 {
                        self.handle_packet(&p);
                    } else if p[0] == 0 && std::env::var_os("BT_GUI_DEBUG").is_some() {
                        eprintln!("X error {} (major {})", p[1], p[10]);
                    }
                }
                Ok(None) => {
                    if wait == Wait::Poll {
                        return None;
                    }
                }
                Err(e) => {
                    eprintln!("bt-gui: X11 connection lost: {e}");
                    self.dead = true;
                }
            }
        }
    }

    pub fn present(&mut self, canvas: &Canvas) {
        let w = canvas.width as usize;
        let h = canvas.height as usize;
        if w == 0 || h == 0 {
            return;
        }
        let bytes: &[u8] = unsafe { std::slice::from_raw_parts(canvas.pixels.as_ptr() as *const u8, w * h * 4) };
        let max = if self.c.max_req_bytes > 0 { self.c.max_req_bytes } else { 262140 };
        let rows_per = ((max - 24) / (w * 4)).max(1);
        let mut y = 0;
        while y < h {
            let rows = rows_per.min(h - y);
            let len = 24 + rows * w * 4;
            let mut hdr = Vec::with_capacity(24);
            hdr.extend_from_slice(&[72, 2]);
            hdr.extend_from_slice(&((len / 4) as u16).to_le_bytes());
            hdr.extend_from_slice(&self.win.to_le_bytes());
            hdr.extend_from_slice(&self.gc.to_le_bytes());
            hdr.extend_from_slice(&(w as u16).to_le_bytes());
            hdr.extend_from_slice(&(rows as u16).to_le_bytes());
            hdr.extend_from_slice(&0i16.to_le_bytes());
            hdr.extend_from_slice(&(y as i16).to_le_bytes());
            hdr.extend_from_slice(&[0, self.depth, 0, 0]);
            if let Err(e) = self.c.write_all(&hdr).and_then(|_| self.c.write_all(&bytes[y * w * 4..(y + rows) * w * 4])) {
                eprintln!("bt-gui: X11 write failed: {e}");
                self.dead = true;
                return;
            }
            self.c.seq = self.c.seq.wrapping_add(1);
            y += rows;
        }
    }

    pub fn physical_size(&self) -> (u32, u32) {
        (self.width, self.height)
    }
    pub fn scale_factor(&self) -> f32 {
        self.scale
    }

    pub fn set_title(&mut self, title: &str) {
        let _ = self.c.change_property(self.win, self.atoms.net_wm_name, self.atoms.utf8, 8, title.as_bytes());
        let latin: Vec<u8> = title.chars().map(|c| if (c as u32) < 256 { c as u8 } else { b'?' }).collect();
        let _ = self.c.change_property(self.win, XA_WM_NAME, XA_STRING, 8, &latin);
    }

    pub fn set_cursor(&mut self, c: CursorIcon) {
        if c == self.cursor {
            return;
        }
        self.cursor = c;
        let id = self.cursors[match c {
            CursorIcon::Arrow => 0,
            CursorIcon::Hand => 1,
            CursorIcon::Text => 2,
        }];
        let _ = self.c.send(&Req::new(2, 0).u32(self.win).u32(0x4000).u32(id).done());
    }

    pub fn clipboard_set(&mut self, text: &str) {
        self.clip_owned = Some(text.to_string());
        let _ = self.c.send(&Req::new(22, 0).u32(self.win).u32(self.atoms.clipboard).u32(0).done());
    }

    pub fn clipboard_get(&mut self) -> Option<String> {
        // ask the owner; if it's us, answer locally
        let owner = self.c.reply(&Req::new(23, 0).u32(self.atoms.clipboard).done()).ok().map(|p| le32(&p, 8))?;
        if owner == self.win {
            return self.clip_owned.clone();
        }
        if owner == 0 {
            return None;
        }
        for target in [self.atoms.utf8, XA_STRING] {
            let r = Req::new(24, 0).u32(self.win).u32(self.atoms.clipboard).u32(target).u32(self.atoms.bt_sel).u32(0).done();
            self.c.send(&r).ok()?;
            let deadline = Instant::now() + Duration::from_millis(1500);
            let mut prop = None;
            while Instant::now() < deadline {
                let left = deadline - Instant::now();
                match self.c.read_packet(Wait::Timeout(left)) {
                    Ok(Some(p)) => {
                        if p[0] & 0x7f == 31 && le32(&p, 12) == self.atoms.clipboard {
                            prop = Some(le32(&p, 20));
                            break;
                        } else if p[0] > 1 {
                            self.c.pending.push_back(p);
                        }
                    }
                    Ok(None) => {}
                    Err(_) => return None,
                }
            }
            match prop {
                Some(0) | None => continue,
                Some(pr) => {
                    let (ty, _, data) = self.c.get_property(self.win, pr, true).ok()?;
                    if ty == self.atoms.incr {
                        return None; // large incremental transfers not supported
                    }
                    return Some(if target == XA_STRING {
                        data.iter().map(|&b| b as char).collect()
                    } else {
                        String::from_utf8_lossy(&data).into_owned()
                    });
                }
            }
        }
        None
    }
}

/// Map an X keysym to a Unicode character.
fn keysym_char(k: u32) -> Option<char> {
    match k {
        0x20..=0x7e | 0xa0..=0xff => char::from_u32(k),
        0x0100_0000..=0x0110_ffff => char::from_u32(k - 0x0100_0000),
        0xffb0..=0xffb9 => char::from_u32(k - 0xffb0 + '0' as u32),
        0xffaa => Some('*'),
        0xffab => Some('+'),
        0xffad => Some('-'),
        0xffae => Some('.'),
        0xffaf => Some('/'),
        0xff80 => Some(' '),
        0x20ac => Some('€'),
        _ => None,
    }
}

pub fn native_folder_picker_available() -> bool {
    which("zenity").is_some() || which("kdialog").is_some()
}

fn which(cmd: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?.to_str()?.split(':').map(|d| PathBuf::from(d).join(cmd)).find(|p| p.is_file())
}

pub fn pick_folder(title: &str) -> Option<PathBuf> {
    use std::process::Command;
    let out = if which("zenity").is_some() {
        Command::new("zenity").args(["--file-selection", "--directory", "--title", title]).output().ok()?
    } else if which("kdialog").is_some() {
        Command::new("kdialog").args(["--getexistingdirectory", ".", "--title", title]).output().ok()?
    } else {
        return None;
    };
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim_end_matches('\n').to_string();
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

pub fn open(target: &str) {
    let _ = std::process::Command::new("xdg-open").arg(target).spawn();
}

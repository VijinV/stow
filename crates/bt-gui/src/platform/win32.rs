//! Win32 backend: raw FFI to user32 / gdi32 / kernel32 / shell32 / ole32.
#![allow(non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]

use super::WindowOptions;
use crate::canvas::Canvas;
use crate::event::{CursorIcon, Event, Key, Mods, MouseButton};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

type HWND = *mut c_void;
type HANDLE = *mut c_void;
type HDC = *mut c_void;
type HINSTANCE = *mut c_void;
type HCURSOR = *mut c_void;
type HICON = *mut c_void;
type HBITMAP = *mut c_void;
type WPARAM = usize;
type LPARAM = isize;
type LRESULT = isize;
type BOOL = i32;
type WNDPROC = unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT;

#[repr(C)]
struct WNDCLASSEXW {
    cbSize: u32,
    style: u32,
    lpfnWndProc: Option<WNDPROC>,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: HINSTANCE,
    hIcon: HICON,
    hCursor: HCURSOR,
    hbrBackground: HANDLE,
    lpszMenuName: *const u16,
    lpszClassName: *const u16,
    hIconSm: HICON,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct POINT {
    x: i32,
    y: i32,
}
#[repr(C)]
struct MSG {
    hwnd: HWND,
    message: u32,
    wParam: WPARAM,
    lParam: LPARAM,
    time: u32,
    pt: POINT,
    lPrivate: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RECT {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}
#[repr(C)]
struct PAINTSTRUCT {
    hdc: HDC,
    fErase: BOOL,
    rcPaint: RECT,
    fRestore: BOOL,
    fIncUpdate: BOOL,
    rgbReserved: [u8; 32],
}
#[repr(C)]
struct BITMAPINFOHEADER {
    biSize: u32,
    biWidth: i32,
    biHeight: i32,
    biPlanes: u16,
    biBitCount: u16,
    biCompression: u32,
    biSizeImage: u32,
    biXPelsPerMeter: i32,
    biYPelsPerMeter: i32,
    biClrUsed: u32,
    biClrImportant: u32,
}
#[repr(C)]
struct BITMAPINFO {
    bmiHeader: BITMAPINFOHEADER,
    bmiColors: [u32; 1],
}
#[repr(C)]
struct MINMAXINFO {
    ptReserved: POINT,
    ptMaxSize: POINT,
    ptMaxPosition: POINT,
    ptMinTrackSize: POINT,
    ptMaxTrackSize: POINT,
}
#[repr(C)]
struct TRACKMOUSEEVENT {
    cbSize: u32,
    dwFlags: u32,
    hwndTrack: HWND,
    dwHoverTime: u32,
}
#[repr(C)]
struct ICONINFO {
    fIcon: BOOL,
    xHotspot: u32,
    yHotspot: u32,
    hbmMask: HBITMAP,
    hbmColor: HBITMAP,
}
#[repr(C)]
struct GUID {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}

#[link(name = "user32")]
extern "system" {
    fn RegisterClassExW(c: *const WNDCLASSEXW) -> u16;
    fn CreateWindowExW(ex: u32, class: *const u16, name: *const u16, style: u32, x: i32, y: i32, w: i32, h: i32, parent: HWND, menu: HANDLE, inst: HINSTANCE, param: *mut c_void) -> HWND;
    fn DefWindowProcW(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> LRESULT;
    fn ShowWindow(h: HWND, cmd: i32) -> BOOL;
    fn UpdateWindow(h: HWND) -> BOOL;
    fn PeekMessageW(m: *mut MSG, h: HWND, a: u32, b: u32, remove: u32) -> BOOL;
    fn TranslateMessage(m: *const MSG) -> BOOL;
    fn DispatchMessageW(m: *const MSG) -> LRESULT;
    fn MsgWaitForMultipleObjects(n: u32, handles: *const HANDLE, all: BOOL, ms: u32, mask: u32) -> u32;
    fn GetClientRect(h: HWND, r: *mut RECT) -> BOOL;
    fn BeginPaint(h: HWND, ps: *mut PAINTSTRUCT) -> HDC;
    fn EndPaint(h: HWND, ps: *const PAINTSTRUCT) -> BOOL;
    fn GetDC(h: HWND) -> HDC;
    fn ReleaseDC(h: HWND, dc: HDC) -> i32;
    fn SetWindowTextW(h: HWND, s: *const u16) -> BOOL;
    fn LoadCursorW(inst: HINSTANCE, name: *const u16) -> HCURSOR;
    fn SetCursor(c: HCURSOR) -> HCURSOR;
    fn SetWindowPos(h: HWND, after: HWND, x: i32, y: i32, cx: i32, cy: i32, flags: u32) -> BOOL;
    fn AdjustWindowRectEx(r: *mut RECT, style: u32, menu: BOOL, ex: u32) -> BOOL;
    fn OpenClipboard(h: HWND) -> BOOL;
    fn CloseClipboard() -> BOOL;
    fn EmptyClipboard() -> BOOL;
    fn GetClipboardData(fmt: u32) -> HANDLE;
    fn SetClipboardData(fmt: u32, h: HANDLE) -> HANDLE;
    fn GetKeyState(vk: i32) -> i16;
    fn SetCapture(h: HWND) -> HWND;
    fn ReleaseCapture() -> BOOL;
    fn SendMessageW(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> LRESULT;
    fn CreateIconIndirect(i: *const ICONINFO) -> HICON;
    fn TrackMouseEvent(t: *mut TRACKMOUSEEVENT) -> BOOL;
    fn SetProcessDPIAware() -> BOOL;
}
#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> HINSTANCE;
    fn GetProcAddress(m: HINSTANCE, name: *const u8) -> *mut c_void;
    fn GlobalAlloc(flags: u32, bytes: usize) -> HANDLE;
    fn GlobalLock(h: HANDLE) -> *mut c_void;
    fn GlobalUnlock(h: HANDLE) -> BOOL;
    fn GlobalFree(h: HANDLE) -> HANDLE;
}
#[link(name = "gdi32")]
extern "system" {
    fn StretchDIBits(dc: HDC, xd: i32, yd: i32, wd: i32, hd: i32, xs: i32, ys: i32, ws: i32, hs: i32, bits: *const c_void, bmi: *const BITMAPINFO, usage: u32, rop: u32) -> i32;
    fn CreateBitmap(w: i32, h: i32, planes: u32, bpp: u32, bits: *const c_void) -> HBITMAP;
    fn DeleteObject(o: HANDLE) -> BOOL;
    fn GetDeviceCaps(dc: HDC, idx: i32) -> i32;
}
#[link(name = "shell32")]
extern "system" {
    fn ShellExecuteW(h: HWND, op: *const u16, file: *const u16, params: *const u16, dir: *const u16, show: i32) -> HINSTANCE;
}
#[link(name = "ole32")]
extern "system" {
    fn CoInitializeEx(r: *mut c_void, flags: u32) -> i32;
    fn CoCreateInstance(clsid: *const GUID, outer: *mut c_void, ctx: u32, iid: *const GUID, out: *mut *mut c_void) -> i32;
    fn CoTaskMemFree(p: *mut c_void);
}

const WM_DESTROY: u32 = 0x0002;
const WM_SIZE: u32 = 0x0005;
const WM_SETFOCUS: u32 = 0x0007;
const WM_KILLFOCUS: u32 = 0x0008;
const WM_PAINT: u32 = 0x000F;
const WM_CLOSE: u32 = 0x0010;
const WM_QUIT: u32 = 0x0012;
const WM_ERASEBKGND: u32 = 0x0014;
const WM_SETCURSOR: u32 = 0x0020;
const WM_GETMINMAXINFO: u32 = 0x0024;
const WM_SETICON: u32 = 0x0080;
const WM_KEYDOWN: u32 = 0x0100;
const WM_KEYUP: u32 = 0x0101;
const WM_CHAR: u32 = 0x0102;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_SYSKEYUP: u32 = 0x0105;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_RBUTTONDOWN: u32 = 0x0204;
const WM_RBUTTONUP: u32 = 0x0205;
const WM_MBUTTONDOWN: u32 = 0x0207;
const WM_MBUTTONUP: u32 = 0x0208;
const WM_MOUSEWHEEL: u32 = 0x020A;
const WM_MOUSEHWHEEL: u32 = 0x020E;
const WM_MOUSELEAVE: u32 = 0x02A3;
const WM_DPICHANGED: u32 = 0x02E0;
const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
const CW_USEDEFAULT: i32 = 0x8000_0000u32 as i32;
const CF_UNICODETEXT: u32 = 13;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct Shared {
    hwnd: HWND,
    queue: VecDeque<Event>,
    width: u32,
    height: u32,
    scale: f32,
    pixels: Vec<u32>,
    pw: u32,
    ph: u32,
    cursor: HCURSOR,
    min: (u32, u32),
    surrogate: u16,
    tracking: bool,
}

thread_local! {
    static SHARED: RefCell<Shared> = RefCell::new(Shared {
        hwnd: null_mut(),
        queue: VecDeque::new(),
        width: 0,
        height: 0,
        scale: 1.0,
        pixels: Vec::new(),
        pw: 0,
        ph: 0,
        cursor: null_mut(),
        min: (0, 0),
        surrogate: 0,
        tracking: false,
    });
}

fn push(e: Event) {
    SHARED.with(|s| s.borrow_mut().queue.push_back(e));
}

fn mods() -> Mods {
    unsafe {
        Mods {
            shift: GetKeyState(0x10) < 0,
            ctrl: GetKeyState(0x11) < 0,
            alt: GetKeyState(0x12) < 0,
            logo: GetKeyState(0x5B) < 0 || GetKeyState(0x5C) < 0,
        }
    }
}

fn vk_key(vk: usize) -> Key {
    match vk {
        0x08 => Key::Backspace,
        0x09 => Key::Tab,
        0x0D => Key::Enter,
        0x1B => Key::Escape,
        0x20 => Key::Space,
        0x21 => Key::PageUp,
        0x22 => Key::PageDown,
        0x23 => Key::End,
        0x24 => Key::Home,
        0x25 => Key::Left,
        0x26 => Key::Up,
        0x27 => Key::Right,
        0x28 => Key::Down,
        0x2D => Key::Insert,
        0x2E => Key::Delete,
        0x30..=0x39 => Key::Char((vk as u8) as char),
        0x41..=0x5A => Key::Char((vk as u8 + 32) as char),
        0x70..=0x7B => Key::F((vk - 0x70 + 1) as u8),
        _ => Key::Unknown,
    }
}

unsafe fn blit(hdc: HDC, s: &Shared) {
    if s.pw == 0 || s.ph == 0 {
        return;
    }
    let bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: s.pw as i32,
            biHeight: -(s.ph as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: 0,
            biSizeImage: 0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        },
        bmiColors: [0],
    };
    StretchDIBits(hdc, 0, 0, s.pw as i32, s.ph as i32, 0, 0, s.pw as i32, s.ph as i32, s.pixels.as_ptr() as *const c_void, &bmi, 0, 0x00CC_0020);
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let xy = || ((lp & 0xFFFF) as i16 as f32, ((lp >> 16) & 0xFFFF) as i16 as f32);
    match msg {
        WM_CLOSE => {
            push(Event::CloseRequested);
            0
        }
        WM_DESTROY => 0,
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let dc = BeginPaint(hwnd, &mut ps);
            SHARED.with(|s| blit(dc, &s.borrow()));
            EndPaint(hwnd, &ps);
            SHARED.with(|s| {
                let mut s = s.borrow_mut();
                if !s.queue.iter().any(|e| *e == Event::Redraw) {
                    s.queue.push_back(Event::Redraw);
                }
            });
            0
        }
        WM_SIZE => {
            if wp != 1 {
                let (w, h) = ((lp & 0xFFFF) as u32, ((lp >> 16) & 0xFFFF) as u32);
                SHARED.with(|s| {
                    let mut s = s.borrow_mut();
                    if (w, h) != (s.width, s.height) {
                        s.width = w;
                        s.height = h;
                        s.queue.retain(|e| !matches!(e, Event::Resized { .. }));
                        s.queue.push_back(Event::Resized { w, h });
                    }
                });
            }
            0
        }
        WM_GETMINMAXINFO => {
            let (mw, mh, scale) = SHARED.with(|s| {
                let s = s.borrow();
                (s.min.0, s.min.1, s.scale)
            });
            if mw > 0 {
                let mut r = RECT { left: 0, top: 0, right: (mw as f32 * scale) as i32, bottom: (mh as f32 * scale) as i32 };
                AdjustWindowRectEx(&mut r, WS_OVERLAPPEDWINDOW, 0, 0);
                let mmi = lp as *mut MINMAXINFO;
                (*mmi).ptMinTrackSize = POINT { x: r.right - r.left, y: r.bottom - r.top };
            }
            0
        }
        WM_DPICHANGED => {
            let dpi = (wp & 0xFFFF) as f32;
            let scale = (dpi / 96.0).max(0.5);
            SHARED.with(|s| s.borrow_mut().scale = scale);
            push(Event::ScaleChanged(scale));
            let r = &*(lp as *const RECT);
            SetWindowPos(hwnd, null_mut(), r.left, r.top, r.right - r.left, r.bottom - r.top, 0x0014);
            0
        }
        WM_SETCURSOR => {
            if lp & 0xFFFF == 1 {
                let c = SHARED.with(|s| s.borrow().cursor);
                SetCursor(c);
                1
            } else {
                DefWindowProcW(hwnd, msg, wp, lp)
            }
        }
        WM_SETFOCUS => {
            push(Event::Focus(true));
            0
        }
        WM_KILLFOCUS => {
            push(Event::Focus(false));
            0
        }
        WM_MOUSEMOVE => {
            let (x, y) = xy();
            let need_track = SHARED.with(|s| {
                let mut s = s.borrow_mut();
                if let Some(Event::MouseMove { .. }) = s.queue.back() {
                    s.queue.pop_back();
                }
                s.queue.push_back(Event::MouseMove { x, y });
                let t = !s.tracking;
                s.tracking = true;
                t
            });
            if need_track {
                let mut t = TRACKMOUSEEVENT { cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32, dwFlags: 2, hwndTrack: hwnd, dwHoverTime: 0 };
                TrackMouseEvent(&mut t);
            }
            0
        }
        WM_MOUSELEAVE => {
            SHARED.with(|s| s.borrow_mut().tracking = false);
            push(Event::MouseLeft);
            0
        }
        WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_MBUTTONDOWN => {
            let (x, y) = xy();
            let button = match msg {
                WM_LBUTTONDOWN => MouseButton::Left,
                WM_RBUTTONDOWN => MouseButton::Right,
                _ => MouseButton::Middle,
            };
            SetCapture(hwnd);
            push(Event::MouseDown { x, y, button });
            0
        }
        WM_LBUTTONUP | WM_RBUTTONUP | WM_MBUTTONUP => {
            let (x, y) = xy();
            let button = match msg {
                WM_LBUTTONUP => MouseButton::Left,
                WM_RBUTTONUP => MouseButton::Right,
                _ => MouseButton::Middle,
            };
            ReleaseCapture();
            push(Event::MouseUp { x, y, button });
            0
        }
        WM_MOUSEWHEEL | WM_MOUSEHWHEEL => {
            let d = ((wp >> 16) & 0xFFFF) as i16 as f32 / 120.0;
            push(if msg == WM_MOUSEWHEEL { Event::Scroll { dx: 0.0, dy: d } } else { Event::Scroll { dx: -d, dy: 0.0 } });
            0
        }
        WM_KEYDOWN | WM_SYSKEYDOWN | WM_KEYUP | WM_SYSKEYUP => {
            let key = vk_key(wp);
            let m = mods();
            if msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN {
                push(Event::KeyDown { key, mods: m });
            } else {
                push(Event::KeyUp { key, mods: m });
            }
            if msg == WM_SYSKEYDOWN || msg == WM_SYSKEYUP {
                DefWindowProcW(hwnd, msg, wp, lp) // keep Alt+F4 etc.
            } else {
                0
            }
        }
        WM_CHAR => {
            let u = wp as u32;
            SHARED.with(|s| {
                let mut s = s.borrow_mut();
                let ch = if (0xD800..0xDC00).contains(&u) {
                    s.surrogate = u as u16;
                    None
                } else if (0xDC00..0xE000).contains(&u) {
                    let hi = std::mem::take(&mut s.surrogate);
                    char::decode_utf16([hi, u as u16]).next().and_then(|r| r.ok())
                } else {
                    char::from_u32(u)
                };
                if let Some(c) = ch {
                    if !c.is_control() {
                        // Ctrl+letter arrives as control chars (filtered); AltGr = Ctrl+Alt gives real chars.
                        s.queue.push_back(Event::Text(c.to_string()));
                    }
                }
            });
            0
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

unsafe fn proc_addr(dll: &str, name: &str) -> *mut c_void {
    let m = GetModuleHandleW(wide(dll).as_ptr());
    if m.is_null() {
        return null_mut();
    }
    let n: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
    GetProcAddress(m, n.as_ptr())
}

unsafe fn enable_dpi_awareness() {
    let f = proc_addr("user32.dll", "SetProcessDpiAwarenessContext");
    if !f.is_null() {
        let f: unsafe extern "system" fn(HANDLE) -> BOOL = std::mem::transmute(f);
        if f(-4isize as HANDLE) != 0 {
            return;
        }
    }
    SetProcessDPIAware();
}

unsafe fn window_dpi(hwnd: HWND) -> u32 {
    let f = proc_addr("user32.dll", "GetDpiForWindow");
    if !f.is_null() {
        let f: unsafe extern "system" fn(HWND) -> u32 = std::mem::transmute(f);
        let d = f(hwnd);
        if d > 0 {
            return d;
        }
    }
    let dc = GetDC(hwnd);
    let d = GetDeviceCaps(dc, 88);
    ReleaseDC(hwnd, dc);
    if d > 0 {
        d as u32
    } else {
        96
    }
}

pub struct Window {
    hwnd: HWND,
    cursors: [HCURSOR; 3],
    cur: CursorIcon,
}

impl Window {
    pub fn new(opts: &WindowOptions) -> std::io::Result<Window> {
        unsafe {
            enable_dpi_awareness();
            let inst = GetModuleHandleW(null());
            let class = wide(&format!("{}-window", opts.app_id));
            let arrow = LoadCursorW(null_mut(), 32512 as *const u16);
            let wc = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: 0x0003, // CS_HREDRAW | CS_VREDRAW
                lpfnWndProc: Some(wndproc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: inst,
                hIcon: null_mut(),
                hCursor: arrow,
                hbrBackground: null_mut(),
                lpszMenuName: null(),
                lpszClassName: class.as_ptr(),
                hIconSm: null_mut(),
            };
            RegisterClassExW(&wc);
            SHARED.with(|s| {
                let mut s = s.borrow_mut();
                s.cursor = arrow;
                s.min = (opts.min_width, opts.min_height);
            });
            let title = wide(&opts.title);
            let hwnd = CreateWindowExW(0, class.as_ptr(), title.as_ptr(), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, null_mut(), null_mut(), inst, null_mut());
            if hwnd.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let mut scale = window_dpi(hwnd) as f32 / 96.0;
            if let Some(s) = super::env_scale() {
                scale = s;
            }
            SHARED.with(|s| {
                let mut s = s.borrow_mut();
                s.hwnd = hwnd;
                s.scale = scale;
            });
            let mut r = RECT { left: 0, top: 0, right: (opts.width as f32 * scale) as i32, bottom: (opts.height as f32 * scale) as i32 };
            AdjustWindowRectEx(&mut r, WS_OVERLAPPEDWINDOW, 0, 0);
            SetWindowPos(hwnd, null_mut(), 0, 0, r.right - r.left, r.bottom - r.top, 0x0016); // NOMOVE|NOZORDER|NOACTIVATE
            if let Some((w, h, px)) = &opts.icon {
                let color = CreateBitmap(*w as i32, *h as i32, 1, 32, px.as_ptr() as *const c_void);
                let mask_bytes = vec![0u8; ((*w as usize + 15) / 16 * 2) * *h as usize];
                let mask = CreateBitmap(*w as i32, *h as i32, 1, 1, mask_bytes.as_ptr() as *const c_void);
                let ii = ICONINFO { fIcon: 1, xHotspot: 0, yHotspot: 0, hbmMask: mask, hbmColor: color };
                let icon = CreateIconIndirect(&ii);
                DeleteObject(color);
                DeleteObject(mask);
                if !icon.is_null() {
                    SendMessageW(hwnd, WM_SETICON, 1, icon as isize);
                    SendMessageW(hwnd, WM_SETICON, 0, icon as isize);
                }
            }
            ShowWindow(hwnd, 5);
            UpdateWindow(hwnd);
            let mut cr = RECT::default();
            GetClientRect(hwnd, &mut cr);
            SHARED.with(|s| {
                let mut s = s.borrow_mut();
                s.width = cr.right as u32;
                s.height = cr.bottom as u32;
            });
            let cursors = [arrow, LoadCursorW(null_mut(), 32649 as *const u16), LoadCursorW(null_mut(), 32513 as *const u16)];
            Ok(Window { hwnd, cursors, cur: CursorIcon::Arrow })
        }
    }

    pub fn next_event(&mut self, timeout: Option<Duration>) -> Option<Event> {
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            if let Some(e) = SHARED.with(|s| s.borrow_mut().queue.pop_front()) {
                return Some(e);
            }
            unsafe {
                let mut msg: MSG = std::mem::zeroed();
                while PeekMessageW(&mut msg, null_mut(), 0, 0, 1) != 0 {
                    if msg.message == WM_QUIT {
                        push(Event::CloseRequested);
                    }
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            if let Some(e) = SHARED.with(|s| s.borrow_mut().queue.pop_front()) {
                return Some(e);
            }
            let ms = match deadline {
                None => 0xFFFF_FFFF,
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        return None;
                    }
                    ((d - now).as_micros().div_ceil(1000)) as u32
                }
            };
            unsafe {
                MsgWaitForMultipleObjects(0, null(), 0, ms, 0x04FF);
            }
        }
    }

    pub fn present(&mut self, canvas: &Canvas) {
        SHARED.with(|s| {
            let mut s = s.borrow_mut();
            s.pixels.clear();
            s.pixels.extend_from_slice(&canvas.pixels);
            s.pw = canvas.width;
            s.ph = canvas.height;
            unsafe {
                let dc = GetDC(self.hwnd);
                blit(dc, &s);
                ReleaseDC(self.hwnd, dc);
            }
        });
    }

    pub fn physical_size(&self) -> (u32, u32) {
        SHARED.with(|s| {
            let s = s.borrow();
            (s.width, s.height)
        })
    }

    pub fn scale_factor(&self) -> f32 {
        SHARED.with(|s| s.borrow().scale)
    }

    pub fn set_title(&mut self, title: &str) {
        let t = wide(title);
        unsafe {
            SetWindowTextW(self.hwnd, t.as_ptr());
        }
    }

    pub fn set_cursor(&mut self, c: CursorIcon) {
        if c == self.cur {
            return;
        }
        self.cur = c;
        let h = self.cursors[match c {
            CursorIcon::Arrow => 0,
            CursorIcon::Hand => 1,
            CursorIcon::Text => 2,
        }];
        SHARED.with(|s| s.borrow_mut().cursor = h);
        unsafe {
            SetCursor(h);
        }
    }

    pub fn clipboard_get(&mut self) -> Option<String> {
        unsafe {
            let mut opened = false;
            for _ in 0..10 {
                if OpenClipboard(self.hwnd) != 0 {
                    opened = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if !opened {
                return None;
            }
            let mut out = None;
            let h = GetClipboardData(CF_UNICODETEXT);
            if !h.is_null() {
                let p = GlobalLock(h) as *const u16;
                if !p.is_null() {
                    let mut n = 0;
                    while *p.add(n) != 0 {
                        n += 1;
                    }
                    out = Some(String::from_utf16_lossy(std::slice::from_raw_parts(p, n)));
                    GlobalUnlock(h);
                }
            }
            CloseClipboard();
            out
        }
    }

    pub fn clipboard_set(&mut self, text: &str) {
        let w = wide(text);
        unsafe {
            if OpenClipboard(self.hwnd) == 0 {
                return;
            }
            EmptyClipboard();
            let h = GlobalAlloc(0x0002, w.len() * 2);
            if !h.is_null() {
                let p = GlobalLock(h) as *mut u16;
                if !p.is_null() {
                    std::ptr::copy_nonoverlapping(w.as_ptr(), p, w.len());
                    GlobalUnlock(h);
                    if SetClipboardData(CF_UNICODETEXT, h).is_null() {
                        GlobalFree(h);
                    }
                }
            }
            CloseClipboard();
        }
    }
}

pub fn native_folder_picker_available() -> bool {
    true
}

/// IFileOpenDialog with FOS_PICKFOLDERS, via raw COM vtables.
pub fn pick_folder(title: &str) -> Option<PathBuf> {
    unsafe {
        CoInitializeEx(null_mut(), 0x2 | 0x4);
        let clsid = GUID { d1: 0xDC1C5A9C, d2: 0xE88A, d3: 0x4DDE, d4: [0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7] };
        let iid = GUID { d1: 0xD57C7288, d2: 0xD4AD, d3: 0x4768, d4: [0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60] };
        let mut dlg: *mut c_void = null_mut();
        if CoCreateInstance(&clsid, null_mut(), 1, &iid, &mut dlg) < 0 || dlg.is_null() {
            return None;
        }
        let vt = *(dlg as *const *const usize);
        let f = |i: usize| *vt.add(i);
        let release: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(f(2));
        let show: unsafe extern "system" fn(*mut c_void, HWND) -> i32 = std::mem::transmute(f(3));
        let set_options: unsafe extern "system" fn(*mut c_void, u32) -> i32 = std::mem::transmute(f(9));
        let get_options: unsafe extern "system" fn(*mut c_void, *mut u32) -> i32 = std::mem::transmute(f(10));
        let set_title: unsafe extern "system" fn(*mut c_void, *const u16) -> i32 = std::mem::transmute(f(17));
        let get_result: unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> i32 = std::mem::transmute(f(20));
        let mut o = 0u32;
        get_options(dlg, &mut o);
        set_options(dlg, o | 0x20 | 0x40); // FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM
        let t = wide(title);
        set_title(dlg, t.as_ptr());
        let owner = SHARED.with(|s| s.borrow().hwnd);
        let mut out = None;
        if show(dlg, owner) >= 0 {
            let mut item: *mut c_void = null_mut();
            if get_result(dlg, &mut item) >= 0 && !item.is_null() {
                let ivt = *(item as *const *const usize);
                let get_name: unsafe extern "system" fn(*mut c_void, u32, *mut *mut u16) -> i32 = std::mem::transmute(*ivt.add(5));
                let irelease: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(*ivt.add(2));
                let mut name: *mut u16 = null_mut();
                if get_name(item, 0x8005_8000, &mut name) >= 0 && !name.is_null() {
                    let mut n = 0;
                    while *name.add(n) != 0 {
                        n += 1;
                    }
                    out = Some(PathBuf::from(String::from_utf16_lossy(std::slice::from_raw_parts(name, n))));
                    CoTaskMemFree(name as *mut c_void);
                }
                irelease(item);
            }
        }
        release(dlg);
        out
    }
}

pub fn open(target: &str) {
    let op = wide("open");
    let t = wide(target);
    unsafe {
        ShellExecuteW(null_mut(), op.as_ptr(), t.as_ptr(), null(), null(), 1);
    }
}

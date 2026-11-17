//! macOS backend via the Objective-C runtime (AppKit) and CoreGraphics C APIs.
//!
//! NOTE: written and type-checked on Linux (`cargo check --target
//! aarch64-apple-darwin / x86_64-apple-darwin`); it could not be run here.
#![allow(non_upper_case_globals, clippy::missing_safety_doc)]

use super::WindowOptions;
use crate::canvas::Canvas;
use crate::event::{CursorIcon, Event, Key, Mods, MouseButton};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::{c_char, c_void, CStr, CString};
use std::path::PathBuf;
use std::ptr::null_mut;
use std::sync::Once;
use std::time::{Duration, Instant};

type Id = *mut c_void;
type Sel = *const c_void;
type Class = *mut c_void;
/// Objective-C BOOL: `signed char` on x86_64, `bool` on arm64 — both one byte.
type BOOL = i8;
const YES: BOOL = 1;
const NO: BOOL = 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NSPoint {
    x: f64,
    y: f64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NSSize {
    w: f64,
    h: f64,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct NSRect {
    origin: NSPoint,
    size: NSSize,
}

#[link(name = "objc", kind = "dylib")]
extern "C" {
    fn objc_getClass(name: *const c_char) -> Class;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_msgSend();
    #[cfg(target_arch = "x86_64")]
    fn objc_msgSend_stret();
    fn objc_allocateClassPair(sup: Class, name: *const c_char, extra: usize) -> Class;
    fn objc_registerClassPair(cls: Class);
    fn class_addMethod(cls: Class, sel: Sel, imp: *const c_void, types: *const c_char) -> BOOL;
    fn objc_autoreleasePoolPush() -> *mut c_void;
    fn objc_autoreleasePoolPop(p: *mut c_void);
}
#[link(name = "Foundation", kind = "framework")]
extern "C" {
    static NSDefaultRunLoopMode: Id;
}
#[link(name = "AppKit", kind = "framework")]
extern "C" {
    static NSPasteboardTypeString: Id;
}
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGColorSpaceCreateDeviceRGB() -> *mut c_void;
    fn CGColorSpaceRelease(cs: *mut c_void);
    fn CGDataProviderCreateWithData(
        info: *mut c_void,
        data: *const c_void,
        size: usize,
        release: Option<extern "C" fn(*mut c_void, *const c_void, usize)>,
    ) -> *mut c_void;
    fn CGDataProviderRelease(p: *mut c_void);
    fn CGImageCreate(
        w: usize,
        h: usize,
        bpc: usize,
        bpp: usize,
        bpr: usize,
        cs: *mut c_void,
        info: u32,
        provider: *mut c_void,
        decode: *const f64,
        interpolate: bool,
        intent: i32,
    ) -> *mut c_void;
    fn CGImageRelease(i: *mut c_void);
    fn CGContextDrawImage(ctx: *mut c_void, r: NSRect, img: *mut c_void);
    fn CGContextSaveGState(ctx: *mut c_void);
    fn CGContextRestoreGState(ctx: *mut c_void);
    fn CGContextTranslateCTM(ctx: *mut c_void, tx: f64, ty: f64);
    fn CGContextScaleCTM(ctx: *mut c_void, sx: f64, sy: f64);
    fn CGContextSetInterpolationQuality(ctx: *mut c_void, q: i32);
}

unsafe fn sel(name: &str) -> Sel {
    let c = CString::new(name).unwrap();
    sel_registerName(c.as_ptr())
}
unsafe fn class(name: &str) -> Class {
    let c = CString::new(name).unwrap();
    objc_getClass(c.as_ptr())
}

/// `msg!(RetType; receiver, "selector:with:", arg1; T1, arg2; T2)`
macro_rules! msg {
    ($ret:ty; $obj:expr, $sel:expr $(, $arg:expr ; $t:ty)*) => {{
        let f: unsafe extern "C" fn(Id, Sel $(, $t)*) -> $ret =
            std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
        f($obj as Id, sel($sel) $(, $arg)*)
    }};
}

/// Messages returning NSRect (struct return: stret on x86_64).
unsafe fn msg_rect(obj: Id, s: &str) -> NSRect {
    #[cfg(target_arch = "x86_64")]
    let f: unsafe extern "C" fn(Id, Sel) -> NSRect = std::mem::transmute(objc_msgSend_stret as unsafe extern "C" fn());
    #[cfg(not(target_arch = "x86_64"))]
    let f: unsafe extern "C" fn(Id, Sel) -> NSRect = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
    f(obj, sel(s))
}

unsafe fn nsstring(s: &str) -> Id {
    let obj: Id = msg!(Id; class("NSString"), "alloc");
    let obj: Id = msg!(Id; obj, "initWithBytes:length:encoding:", s.as_ptr() as *const c_void; *const c_void, s.len(); usize, 4usize; usize);
    msg!(Id; obj, "autorelease")
}

unsafe fn from_nsstring(s: Id) -> Option<String> {
    if s.is_null() {
        return None;
    }
    let p: *const c_char = msg!(*const c_char; s, "UTF8String");
    if p.is_null() {
        return None;
    }
    Some(CStr::from_ptr(p).to_string_lossy().into_owned())
}

struct Shared {
    queue: VecDeque<Event>,
    view: Id,
    window: Id,
    scale: f32,
    width: u32,
    height: u32,
    pixels: Vec<u32>,
    pw: u32,
    ph: u32,
}

thread_local! {
    static SHARED: RefCell<Shared> = RefCell::new(Shared {
        queue: VecDeque::new(),
        view: null_mut(),
        window: null_mut(),
        scale: 1.0,
        width: 0,
        height: 0,
        pixels: Vec::new(),
        pw: 0,
        ph: 0,
    });
}

fn push(e: Event) {
    SHARED.with(|s| s.borrow_mut().queue.push_back(e));
}

unsafe fn mods_from_flags(f: u64) -> Mods {
    Mods { shift: f & (1 << 17) != 0, ctrl: f & (1 << 18) != 0, alt: f & (1 << 19) != 0, logo: f & (1 << 20) != 0 }
}

unsafe fn event_pos(view: Id, ev: Id) -> (f32, f32) {
    let p: NSPoint = msg!(NSPoint; ev, "locationInWindow");
    let q: NSPoint = msg!(NSPoint; view, "convertPoint:fromView:", p; NSPoint, null_mut(); Id);
    let s = SHARED.with(|s| s.borrow().scale);
    ((q.x as f32) * s, (q.y as f32) * s)
}

/// Refresh the cached size/scale from the view; emit events on change.
unsafe fn update_size(emit: bool) {
    let (view, window) = SHARED.with(|s| {
        let s = s.borrow();
        (s.view, s.window)
    });
    if view.is_null() || window.is_null() {
        return;
    }
    let scale: f64 = msg!(f64; window, "backingScaleFactor");
    let b = msg_rect(view, "bounds");
    let scale = super::env_scale().unwrap_or(scale as f32).max(0.5);
    let (w, h) = ((b.size.w * scale as f64).round() as u32, (b.size.h * scale as f64).round() as u32);
    SHARED.with(|s| {
        let mut s = s.borrow_mut();
        if emit && (s.scale - scale).abs() > 0.001 {
            s.queue.push_back(Event::ScaleChanged(scale));
        }
        s.scale = scale;
        if emit && (w, h) != (s.width, s.height) {
            s.queue.retain(|e| !matches!(e, Event::Resized { .. }));
            s.queue.push_back(Event::Resized { w, h });
        }
        s.width = w;
        s.height = h;
    });
}

// ---------------------------------------------------------------- view methods

extern "C" fn yes(_: Id, _: Sel) -> BOOL {
    YES
}
extern "C" fn yes1(_: Id, _: Sel, _: Id) -> BOOL {
    YES
}

extern "C" fn draw_rect(this: Id, _: Sel, _dirty: NSRect) {
    unsafe {
        let gc: Id = msg!(Id; class("NSGraphicsContext"), "currentContext");
        if gc.is_null() {
            return;
        }
        let ctx: *mut c_void = msg!(*mut c_void; gc, "CGContext");
        if ctx.is_null() {
            return;
        }
        let (copy, pw, ph) = SHARED.with(|s| {
            let s = s.borrow();
            (s.pixels.clone(), s.pw, s.ph)
        });
        if pw == 0 || ph == 0 || copy.len() < (pw * ph) as usize {
            return;
        }
        extern "C" fn release(info: *mut c_void, _: *const c_void, _: usize) {
            unsafe { drop(Box::from_raw(info as *mut Vec<u32>)) };
        }
        let boxed = Box::new(copy);
        let ptr = boxed.as_ptr() as *const c_void;
        let len = boxed.len() * 4;
        let info = Box::into_raw(boxed) as *mut c_void;
        let provider = CGDataProviderCreateWithData(info, ptr, len, Some(release));
        let cs = CGColorSpaceCreateDeviceRGB();
        // 32-bit little-endian words 0x00RRGGBB: kCGBitmapByteOrder32Little | kCGImageAlphaNoneSkipFirst
        let img = CGImageCreate(pw as usize, ph as usize, 8, 32, pw as usize * 4, cs, (2 << 12) | 6, provider, std::ptr::null(), false, 0);
        let b = msg_rect(this, "bounds");
        CGContextSaveGState(ctx);
        CGContextSetInterpolationQuality(ctx, 1); // none
        // the view is flipped; CGImage drawing expects y-up
        CGContextTranslateCTM(ctx, 0.0, b.size.h);
        CGContextScaleCTM(ctx, 1.0, -1.0);
        let scale = SHARED.with(|s| s.borrow().scale) as f64;
        let r = NSRect { origin: NSPoint { x: 0.0, y: b.size.h - ph as f64 / scale }, size: NSSize { w: pw as f64 / scale, h: ph as f64 / scale } };
        CGContextDrawImage(ctx, r, img);
        CGContextRestoreGState(ctx);
        CGImageRelease(img);
        CGColorSpaceRelease(cs);
        CGDataProviderRelease(provider);
    }
}

unsafe fn mouse(this: Id, ev: Id, down: Option<bool>, button: MouseButton) {
    let (x, y) = event_pos(this, ev);
    push(match down {
        Some(true) => Event::MouseDown { x, y, button },
        Some(false) => Event::MouseUp { x, y, button },
        None => Event::MouseMove { x, y },
    });
}

extern "C" fn mouse_down(this: Id, _: Sel, ev: Id) {
    unsafe { mouse(this, ev, Some(true), MouseButton::Left) }
}
extern "C" fn mouse_up(this: Id, _: Sel, ev: Id) {
    unsafe { mouse(this, ev, Some(false), MouseButton::Left) }
}
extern "C" fn right_down(this: Id, _: Sel, ev: Id) {
    unsafe { mouse(this, ev, Some(true), MouseButton::Right) }
}
extern "C" fn right_up(this: Id, _: Sel, ev: Id) {
    unsafe { mouse(this, ev, Some(false), MouseButton::Right) }
}
extern "C" fn other_down(this: Id, _: Sel, ev: Id) {
    unsafe { mouse(this, ev, Some(true), MouseButton::Middle) }
}
extern "C" fn other_up(this: Id, _: Sel, ev: Id) {
    unsafe { mouse(this, ev, Some(false), MouseButton::Middle) }
}
extern "C" fn mouse_moved(this: Id, _: Sel, ev: Id) {
    unsafe { mouse(this, ev, None, MouseButton::Left) }
}
extern "C" fn mouse_exited(_: Id, _: Sel, _: Id) {
    push(Event::MouseLeft);
}
extern "C" fn scroll_wheel(_: Id, _: Sel, ev: Id) {
    unsafe {
        let dx: f64 = msg!(f64; ev, "scrollingDeltaX");
        let dy: f64 = msg!(f64; ev, "scrollingDeltaY");
        let precise: BOOL = msg!(BOOL; ev, "hasPreciseScrollingDeltas");
        let k = if precise != NO { 1.0 / 40.0 } else { 1.0 };
        push(Event::Scroll { dx: (dx * k) as f32, dy: (dy * k) as f32 });
    }
}

fn keycode_key(code: u16) -> Option<Key> {
    Some(match code {
        51 => Key::Backspace,
        117 => Key::Delete,
        36 | 76 => Key::Enter,
        48 => Key::Tab,
        53 => Key::Escape,
        49 => Key::Space,
        123 => Key::Left,
        124 => Key::Right,
        125 => Key::Down,
        126 => Key::Up,
        115 => Key::Home,
        119 => Key::End,
        116 => Key::PageUp,
        121 => Key::PageDown,
        122 => Key::F(1),
        120 => Key::F(2),
        99 => Key::F(3),
        118 => Key::F(4),
        96 => Key::F(5),
        97 => Key::F(6),
        98 => Key::F(7),
        100 => Key::F(8),
        101 => Key::F(9),
        109 => Key::F(10),
        103 => Key::F(11),
        111 => Key::F(12),
        _ => return None,
    })
}

unsafe fn key_event(ev: Id, down: bool) {
    let code: u16 = msg!(u16; ev, "keyCode");
    let flags: u64 = msg!(u64; ev, "modifierFlags");
    let mods = mods_from_flags(flags);
    let key = keycode_key(code).unwrap_or_else(|| {
        let s: Id = msg!(Id; ev, "charactersIgnoringModifiers");
        from_nsstring(s)
            .and_then(|s| s.chars().next())
            .filter(|c| !c.is_control() && !('\u{F700}'..='\u{F8FF}').contains(c))
            .map(|c| Key::Char(c.to_ascii_lowercase()))
            .unwrap_or(Key::Unknown)
    });
    if !down {
        push(Event::KeyUp { key, mods });
        return;
    }
    push(Event::KeyDown { key, mods });
    if mods.logo || mods.ctrl {
        return;
    }
    let s: Id = msg!(Id; ev, "characters");
    if let Some(t) = from_nsstring(s) {
        let t: String = t.chars().filter(|c| !c.is_control() && !('\u{F700}'..='\u{F8FF}').contains(c)).collect();
        if !t.is_empty() {
            push(Event::Text(t));
        }
    }
}

extern "C" fn key_down(_: Id, _: Sel, ev: Id) {
    unsafe { key_event(ev, true) }
}
extern "C" fn key_up(_: Id, _: Sel, ev: Id) {
    unsafe { key_event(ev, false) }
}
extern "C" fn flags_changed(_: Id, _: Sel, ev: Id) {
    unsafe {
        let flags: u64 = msg!(u64; ev, "modifierFlags");
        push(Event::KeyDown { key: Key::Unknown, mods: mods_from_flags(flags) });
    }
}
extern "C" fn quit_action(_: Id, _: Sel, _: Id) {
    push(Event::CloseRequested);
}

// ---------------------------------------------------------------- delegate methods

extern "C" fn should_close(_: Id, _: Sel, _: Id) -> BOOL {
    push(Event::CloseRequested);
    NO
}
extern "C" fn did_resize(_: Id, _: Sel, _: Id) {
    unsafe { update_size(true) }
}
extern "C" fn did_become_key(_: Id, _: Sel, _: Id) {
    push(Event::Focus(true));
}
extern "C" fn did_resign_key(_: Id, _: Sel, _: Id) {
    push(Event::Focus(false));
}

static REGISTER: Once = Once::new();

unsafe fn register_classes() {
    REGISTER.call_once(|| {
        let add = |cls: Class, name: &str, imp: *const c_void, types: &str| {
            let t = CString::new(types).unwrap();
            class_addMethod(cls, sel(name), imp, t.as_ptr());
        };
        let name = CString::new("BtGuiView").unwrap();
        let v = objc_allocateClassPair(class("NSView"), name.as_ptr(), 0);
        type M = extern "C" fn(Id, Sel, Id);
        add(v, "isFlipped", yes as extern "C" fn(Id, Sel) -> BOOL as *const c_void, "c@:");
        add(v, "acceptsFirstResponder", yes as extern "C" fn(Id, Sel) -> BOOL as *const c_void, "c@:");
        add(v, "acceptsFirstMouse:", yes1 as extern "C" fn(Id, Sel, Id) -> BOOL as *const c_void, "c@:@");
        add(v, "drawRect:", draw_rect as extern "C" fn(Id, Sel, NSRect) as *const c_void, "v@:{CGRect={CGPoint=dd}{CGSize=dd}}");
        for (n, f) in [
            ("mouseDown:", mouse_down as M),
            ("mouseUp:", mouse_up as M),
            ("rightMouseDown:", right_down as M),
            ("rightMouseUp:", right_up as M),
            ("otherMouseDown:", other_down as M),
            ("otherMouseUp:", other_up as M),
            ("mouseMoved:", mouse_moved as M),
            ("mouseDragged:", mouse_moved as M),
            ("rightMouseDragged:", mouse_moved as M),
            ("otherMouseDragged:", mouse_moved as M),
            ("mouseExited:", mouse_exited as M),
            ("scrollWheel:", scroll_wheel as M),
            ("keyDown:", key_down as M),
            ("keyUp:", key_up as M),
            ("flagsChanged:", flags_changed as M),
            ("btQuit:", quit_action as M),
        ] {
            add(v, n, f as *const c_void, "v@:@");
        }
        objc_registerClassPair(v);

        let name = CString::new("BtGuiDelegate").unwrap();
        let d = objc_allocateClassPair(class("NSObject"), name.as_ptr(), 0);
        add(d, "windowShouldClose:", should_close as extern "C" fn(Id, Sel, Id) -> BOOL as *const c_void, "c@:@");
        add(d, "windowDidResize:", did_resize as M as *const c_void, "v@:@");
        add(d, "windowDidChangeBackingProperties:", did_resize as M as *const c_void, "v@:@");
        add(d, "windowDidBecomeKey:", did_become_key as M as *const c_void, "v@:@");
        add(d, "windowDidResignKey:", did_resign_key as M as *const c_void, "v@:@");
        objc_registerClassPair(d);
    });
}

unsafe fn ns_app() -> Id {
    msg!(Id; class("NSApplication"), "sharedApplication")
}

pub struct Window {
    window: Id,
    view: Id,
    cursor: CursorIcon,
}

impl Window {
    pub fn new(opts: &WindowOptions) -> std::io::Result<Window> {
        unsafe {
            let pool = objc_autoreleasePoolPush();
            register_classes();
            let app = ns_app();
            let _: BOOL = msg!(BOOL; app, "setActivationPolicy:", 0i64; i64);

            let rect = NSRect { origin: NSPoint::default(), size: NSSize { w: opts.width as f64, h: opts.height as f64 } };
            let style: u64 = 1 | 2 | 4 | 8; // titled | closable | miniaturizable | resizable
            let win: Id = msg!(Id; class("NSWindow"), "alloc");
            let win: Id = msg!(Id; win, "initWithContentRect:styleMask:backing:defer:", rect; NSRect, style; u64, 2u64; u64, NO; BOOL);
            if win.is_null() {
                objc_autoreleasePoolPop(pool);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "NSWindow creation failed"));
            }
            let _: () = msg!((); win, "setReleasedWhenClosed:", NO; BOOL);
            let _: () = msg!((); win, "setTitle:", nsstring(&opts.title); Id);
            let view: Id = msg!(Id; class("BtGuiView"), "alloc");
            let view: Id = msg!(Id; view, "initWithFrame:", rect; NSRect);
            let delegate: Id = msg!(Id; class("BtGuiDelegate"), "new");
            let _: () = msg!((); win, "setContentView:", view; Id);
            let _: () = msg!((); win, "setDelegate:", delegate; Id);
            let _: () = msg!((); win, "setAcceptsMouseMovedEvents:", YES; BOOL);
            let _: () = msg!((); win, "setContentMinSize:", NSSize { w: opts.min_width as f64, h: opts.min_height as f64 }; NSSize);
            // mouse-exit tracking: EnteredAndExited | MouseMoved | ActiveInKeyWindow | InVisibleRect
            let ta: Id = msg!(Id; class("NSTrackingArea"), "alloc");
            let ta: Id = msg!(Id; ta, "initWithRect:options:owner:userInfo:", rect; NSRect, 0x223u64; u64, view; Id, null_mut(); Id);
            let _: () = msg!((); view, "addTrackingArea:", ta; Id);

            // menu bar with Quit (Cmd+Q)
            let menubar: Id = msg!(Id; class("NSMenu"), "new");
            let app_item: Id = msg!(Id; class("NSMenuItem"), "new");
            let _: () = msg!((); menubar, "addItem:", app_item; Id);
            let app_menu: Id = msg!(Id; class("NSMenu"), "new");
            let quit: Id = msg!(Id; class("NSMenuItem"), "alloc");
            let quit: Id = msg!(Id; quit, "initWithTitle:action:keyEquivalent:", nsstring(&format!("Quit {}", opts.title)); Id, sel("btQuit:"); Sel, nsstring("q"); Id);
            let _: () = msg!((); quit, "setTarget:", view; Id);
            let _: () = msg!((); app_menu, "addItem:", quit; Id);
            let _: () = msg!((); app_item, "setSubmenu:", app_menu; Id);
            let _: () = msg!((); app, "setMainMenu:", menubar; Id);

            let _: () = msg!((); win, "center");
            let _: () = msg!((); win, "makeKeyAndOrderFront:", null_mut(); Id);
            let _: BOOL = msg!(BOOL; win, "makeFirstResponder:", view; Id);
            let _: () = msg!((); app, "finishLaunching");
            let _: () = msg!((); app, "activateIgnoringOtherApps:", YES; BOOL);
            SHARED.with(|s| {
                let mut s = s.borrow_mut();
                s.view = view;
                s.window = win;
            });
            update_size(false);
            objc_autoreleasePoolPop(pool);
            Ok(Window { window: win, view, cursor: CursorIcon::Arrow })
        }
    }

    pub fn next_event(&mut self, timeout: Option<Duration>) -> Option<Event> {
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            if let Some(e) = SHARED.with(|s| s.borrow_mut().queue.pop_front()) {
                return Some(e);
            }
            unsafe {
                let pool = objc_autoreleasePoolPush();
                let app = ns_app();
                let until: Id = match deadline {
                    None => msg!(Id; class("NSDate"), "distantFuture"),
                    Some(d) => {
                        let secs = d.saturating_duration_since(Instant::now()).as_secs_f64();
                        msg!(Id; class("NSDate"), "dateWithTimeIntervalSinceNow:", secs; f64)
                    }
                };
                let mut until = until;
                loop {
                    let ev: Id = msg!(Id; app, "nextEventMatchingMask:untilDate:inMode:dequeue:",
                        u64::MAX; u64, until; Id, NSDefaultRunLoopMode; Id, YES; BOOL);
                    if ev.is_null() {
                        break;
                    }
                    let _: () = msg!((); app, "sendEvent:", ev; Id);
                    until = msg!(Id; class("NSDate"), "distantPast");
                }
                let _: () = msg!((); app, "updateWindows");
                objc_autoreleasePoolPop(pool);
            }
            if let Some(e) = SHARED.with(|s| s.borrow_mut().queue.pop_front()) {
                return Some(e);
            }
            if deadline.map_or(false, |d| Instant::now() >= d) {
                return None;
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
        });
        unsafe {
            let pool = objc_autoreleasePoolPush();
            let _: () = msg!((); self.view, "setNeedsDisplay:", YES; BOOL);
            let _: () = msg!((); self.view, "displayIfNeeded");
            objc_autoreleasePoolPop(pool);
        }
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
        unsafe {
            let pool = objc_autoreleasePoolPush();
            let _: () = msg!((); self.window, "setTitle:", nsstring(title); Id);
            objc_autoreleasePoolPop(pool);
        }
    }

    pub fn set_cursor(&mut self, c: CursorIcon) {
        if c == self.cursor {
            return;
        }
        self.cursor = c;
        unsafe {
            let name = match c {
                CursorIcon::Arrow => "arrowCursor",
                CursorIcon::Hand => "pointingHandCursor",
                CursorIcon::Text => "IBeamCursor",
            };
            let cur: Id = msg!(Id; class("NSCursor"), name);
            let _: () = msg!((); cur, "set");
        }
    }

    pub fn clipboard_get(&mut self) -> Option<String> {
        unsafe {
            let pool = objc_autoreleasePoolPush();
            let pb: Id = msg!(Id; class("NSPasteboard"), "generalPasteboard");
            let s: Id = msg!(Id; pb, "stringForType:", NSPasteboardTypeString; Id);
            let out = from_nsstring(s);
            objc_autoreleasePoolPop(pool);
            out
        }
    }

    pub fn clipboard_set(&mut self, text: &str) {
        unsafe {
            let pool = objc_autoreleasePoolPush();
            let pb: Id = msg!(Id; class("NSPasteboard"), "generalPasteboard");
            let _: i64 = msg!(i64; pb, "clearContents");
            let _: BOOL = msg!(BOOL; pb, "setString:forType:", nsstring(text); Id, NSPasteboardTypeString; Id);
            objc_autoreleasePoolPop(pool);
        }
    }
}

pub fn native_folder_picker_available() -> bool {
    true
}

pub fn pick_folder(title: &str) -> Option<PathBuf> {
    unsafe {
        let pool = objc_autoreleasePoolPush();
        let panel: Id = msg!(Id; class("NSOpenPanel"), "openPanel");
        let _: () = msg!((); panel, "setCanChooseFiles:", NO; BOOL);
        let _: () = msg!((); panel, "setCanChooseDirectories:", YES; BOOL);
        let _: () = msg!((); panel, "setAllowsMultipleSelection:", NO; BOOL);
        let _: () = msg!((); panel, "setCanCreateDirectories:", YES; BOOL);
        let _: () = msg!((); panel, "setMessage:", nsstring(title); Id);
        let _: () = msg!((); panel, "setPrompt:", nsstring("Choose"); Id);
        let r: i64 = msg!(i64; panel, "runModal");
        let mut out = None;
        if r == 1 {
            let url: Id = msg!(Id; panel, "URL");
            if !url.is_null() {
                let path: Id = msg!(Id; url, "path");
                out = from_nsstring(path).map(PathBuf::from);
            }
        }
        objc_autoreleasePoolPop(pool);
        out
    }
}

pub fn open(target: &str) {
    let _ = std::process::Command::new("open").arg(target).spawn();
}

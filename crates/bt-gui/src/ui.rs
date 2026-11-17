//! Immediate-mode UI on top of [`Canvas`] + [`Window`].
//!
//! Every frame the application calls widget functions (`ui.button(..)`,
//! `ui.text_input(..)`, …) which lay themselves out, draw, and report
//! interaction through a [`Response`]. Coordinates are logical pixels.

use crate::canvas::{Canvas, Color, Rect};
use crate::event::{CursorIcon, Event, Key, Mods, MouseButton};
use crate::font::{Font, Fonts};
use crate::icons::{draw_icon, Icon};
use crate::platform::{Window, WindowOptions};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

pub type Id = u64;

/// Colours and metrics.
#[derive(Clone, Debug)]
pub struct Theme {
    pub bg: Color,
    pub surface: Color,
    pub surface_alt: Color,
    pub sidebar: Color,
    pub border: Color,
    pub border_strong: Color,
    pub text: Color,
    pub text_muted: Color,
    pub text_faint: Color,
    pub accent: Color,
    pub accent_hover: Color,
    pub accent_pressed: Color,
    pub accent_soft: Color,
    pub on_accent: Color,
    pub danger: Color,
    pub danger_hover: Color,
    pub danger_soft: Color,
    pub success: Color,
    pub success_soft: Color,
    pub warning: Color,
    pub warning_soft: Color,
    pub info: Color,
    pub info_soft: Color,
    pub hover: Color,
    pub selection: Color,
    pub font_size: f32,
    pub small_size: f32,
    pub heading_size: f32,
    pub title_size: f32,
    pub radius: f32,
    pub control_height: f32,
    pub spacing: f32,
    pub padding: f32,
}

impl Theme {
    pub fn light() -> Theme {
        Theme {
            bg: Color::hex(0xF4F6FA),
            surface: Color::hex(0xFFFFFF),
            surface_alt: Color::hex(0xF8FAFC),
            sidebar: Color::hex(0xFFFFFF),
            border: Color::hex(0xE2E8F0),
            border_strong: Color::hex(0xCBD5E1),
            text: Color::hex(0x0F172A),
            text_muted: Color::hex(0x64748B),
            text_faint: Color::hex(0x94A3B8),
            accent: Color::hex(0x2563EB),
            accent_hover: Color::hex(0x1D4ED8),
            accent_pressed: Color::hex(0x1E40AF),
            accent_soft: Color::hex(0xEFF4FF),
            on_accent: Color::WHITE,
            danger: Color::hex(0xDC2626),
            danger_hover: Color::hex(0xB91C1C),
            danger_soft: Color::hex(0xFEF2F2),
            success: Color::hex(0x16A34A),
            success_soft: Color::hex(0xF0FDF4),
            warning: Color::hex(0xD97706),
            warning_soft: Color::hex(0xFFFBEB),
            info: Color::hex(0x2563EB),
            info_soft: Color::hex(0xEFF6FF),
            hover: Color::hex(0xF1F5F9),
            selection: Color::rgba(37, 99, 235, 60),
            font_size: 14.0,
            small_size: 12.0,
            heading_size: 22.0,
            title_size: 16.0,
            radius: 8.0,
            control_height: 36.0,
            spacing: 10.0,
            padding: 20.0,
        }
    }
}

/// What happened to a widget this frame.
#[derive(Clone, Copy, Debug, Default)]
pub struct Response {
    pub rect: Rect,
    pub hovered: bool,
    /// Mouse button went down on it this frame.
    pub pressed: bool,
    /// Held down (mouse captured by this widget).
    pub active: bool,
    pub clicked: bool,
    pub double_clicked: bool,
    pub secondary_clicked: bool,
    /// The value changed (inputs, checkboxes, selects…).
    pub changed: bool,
    /// Enter pressed in a text input.
    pub submitted: bool,
    pub focused: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonKind {
    Primary,
    Secondary,
    Danger,
    Ghost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Info,
    Success,
    Warning,
    Danger,
}

/// Text style for labels.
#[derive(Clone, Copy, Debug)]
pub struct TextStyle {
    pub size: f32,
    pub color: Option<Color>,
    pub bold: bool,
    pub wrap: bool,
}

impl TextStyle {
    pub fn body() -> Self {
        TextStyle { size: 14.0, color: None, bold: false, wrap: false }
    }
    pub fn size(mut self, s: f32) -> Self {
        self.size = s;
        self
    }
    pub fn color(mut self, c: Color) -> Self {
        self.color = Some(c);
        self
    }
    pub fn bold(mut self) -> Self {
        self.bold = true;
        self
    }
    pub fn wrap(mut self) -> Self {
        self.wrap = true;
        self
    }
}

#[derive(Clone, Debug)]
pub struct TextInputOptions<'a> {
    pub placeholder: &'a str,
    pub password: bool,
    /// `None` = fill available width.
    pub width: Option<f32>,
    pub enabled: bool,
    /// Optional leading icon.
    pub icon: Option<Icon>,
}

impl<'a> Default for TextInputOptions<'a> {
    fn default() -> Self {
        TextInputOptions { placeholder: "", password: false, width: None, enabled: true, icon: None }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Dir {
    Down,
    Right,
    Left,
}

#[derive(Clone, Copy, Debug)]
struct Layout {
    rect: Rect,
    cursor: f32,
    start: f32,
    cross: f32,
    dir: Dir,
    spacing: f32,
    row_h: f32,
    items: u32,
}

impl Layout {
    fn new(rect: Rect, dir: Dir, spacing: f32, row_h: f32) -> Layout {
        let start = match dir {
            Dir::Down => rect.y,
            Dir::Right => rect.x,
            Dir::Left => rect.right(),
        };
        Layout { rect, cursor: start, start, cross: 0.0, dir, spacing, row_h, items: 0 }
    }
    fn used_main(&self) -> f32 {
        let gap = if self.items > 0 { self.spacing } else { 0.0 };
        ((self.cursor - self.start).abs() - gap).max(0.0)
    }
}

#[derive(Clone, Debug, Default)]
struct TextState {
    cursor: usize,
    anchor: usize,
    scroll: f32,
}

#[derive(Clone, Copy, Debug, Default)]
struct ScrollState {
    offset: f32,
    content: f32,
    grab: Option<f32>,
}

struct Toast {
    tone: Tone,
    text: String,
    until: Instant,
}

type Deferred = Box<dyn FnOnce(&mut Canvas, &Fonts, &Theme)>;

/// Result of [`Ui::modal`].
#[derive(Clone, Copy, Debug, Default)]
pub struct ModalResponse {
    /// The user pressed Escape or the close button.
    pub close_requested: bool,
}

pub struct Ui {
    pub theme: Theme,
    pub fonts: Fonts,
    pub canvas: Canvas,
    // input
    mouse: (f32, f32),
    mouse_down: bool,
    pressed: bool,
    released: bool,
    right_pressed: bool,
    double: bool,
    scroll: (f32, f32),
    keys: Vec<(Key, Mods)>,
    text_in: String,
    mods: Mods,
    clip_in: Option<String>,
    clip_out: Option<String>,
    close_req: bool,
    quit: bool,
    last_press: Option<(Instant, f32, f32)>,
    pending: VecDeque<Event>,
    // identity / interaction
    id_stack: Vec<u64>,
    id_counts: HashMap<u64, u32>,
    active: Option<Id>,
    focus: Option<Id>,
    focus_claimed: bool,
    focus_list: Vec<Id>,
    tab: Option<bool>,
    // layout
    layouts: Vec<Layout>,
    // memory
    text_state: HashMap<Id, TextState>,
    scroll_state: HashMap<Id, ScrollState>,
    heights: HashMap<Id, f32>,
    open_popup: Option<Id>,
    // layers
    layer: u32,
    block_prev: Vec<(u32, Rect)>,
    block_cur: Vec<(u32, Rect)>,
    deferred: Vec<Deferred>,
    toasts: Vec<Toast>,
    cursor: CursorIcon,
    repaint_now: bool,
    repaint_at: Option<Instant>,
    now: Instant,
    start: Instant,
    size: (f32, f32),
    frame: u64,
}

const SUPPRESS: Id = u64::MAX;

fn hash_of(parent: u64, v: impl Hash) -> u64 {
    let mut h = DefaultHasher::new();
    parent.hash(&mut h);
    v.hash(&mut h);
    h.finish()
}

fn byte_idx(s: &str, ci: usize) -> usize {
    s.char_indices().nth(ci).map_or(s.len(), |(b, _)| b)
}

impl Ui {
    pub fn new(theme: Theme) -> Ui {
        Ui::with_fonts(theme, Fonts::load_system())
    }

    pub fn with_fonts(theme: Theme, fonts: Fonts) -> Ui {
        let now = Instant::now();
        Ui {
            theme,
            fonts,
            canvas: Canvas::new(1, 1, 1.0),
            mouse: (-1e6, -1e6),
            mouse_down: false,
            pressed: false,
            released: false,
            right_pressed: false,
            double: false,
            scroll: (0.0, 0.0),
            keys: Vec::new(),
            text_in: String::new(),
            mods: Mods::default(),
            clip_in: None,
            clip_out: None,
            close_req: false,
            quit: false,
            last_press: None,
            pending: VecDeque::new(),
            id_stack: vec![0],
            id_counts: HashMap::new(),
            active: None,
            focus: None,
            focus_claimed: false,
            focus_list: Vec::new(),
            tab: None,
            layouts: Vec::new(),
            text_state: HashMap::new(),
            scroll_state: HashMap::new(),
            heights: HashMap::new(),
            open_popup: None,
            layer: 0,
            block_prev: Vec::new(),
            block_cur: Vec::new(),
            deferred: Vec::new(),
            toasts: Vec::new(),
            cursor: CursorIcon::Arrow,
            repaint_now: true,
            repaint_at: None,
            now,
            start: now,
            size: (1.0, 1.0),
            frame: 0,
        }
    }

    // ------------------------------------------------------------------ frame

    /// How long the event loop may sleep before the next frame is needed.
    pub fn wait_timeout(&self) -> Option<Duration> {
        if self.repaint_now || !self.pending.is_empty() {
            return Some(Duration::ZERO);
        }
        self.repaint_at.map(|t| t.saturating_duration_since(Instant::now()))
    }

    /// True if a frame should be drawn even without new events.
    pub fn repaint_due(&self) -> bool {
        self.repaint_now || !self.pending.is_empty() || self.repaint_at.map_or(false, |t| Instant::now() >= t)
    }

    pub fn request_repaint(&mut self) {
        self.repaint_now = true;
    }

    pub fn request_repaint_after(&mut self, d: Duration) {
        let t = Instant::now() + d;
        if self.repaint_at.map_or(true, |o| t < o) {
            self.repaint_at = Some(t);
        }
    }

    /// Start a frame: feed the events received since the previous frame.
    pub fn begin_frame(&mut self, win: &mut Window, events: Vec<Event>) {
        let scale = win.scale_factor();
        let size = win.physical_size();
        self.begin_frame_raw(size, scale, events, &mut || win.clipboard_get());
    }

    /// Window-less variant of [`begin_frame`](Self::begin_frame) (tests, offscreen rendering).
    pub fn begin_frame_raw(
        &mut self,
        (pw, ph): (u32, u32),
        scale: f32,
        events: Vec<Event>,
        clipboard_get: &mut dyn FnMut() -> Option<String>,
    ) {
        self.now = Instant::now();
        self.frame += 1;
        self.repaint_now = false;
        if self.repaint_at.map_or(false, |t| self.now >= t) {
            self.repaint_at = None;
        }
        self.canvas.resize(pw.max(1), ph.max(1), scale);
        self.size = self.canvas.logical_size();

        self.pressed = false;
        self.released = false;
        self.right_pressed = false;
        self.double = false;
        self.scroll = (0.0, 0.0);
        self.keys.clear();
        self.text_in.clear();
        self.clip_in = None;
        self.close_req = false;

        let mut evs: VecDeque<Event> = std::mem::take(&mut self.pending);
        evs.extend(events);
        while let Some(e) = evs.pop_front() {
            match e {
                Event::MouseMove { x, y } => self.mouse = (x / scale, y / scale),
                Event::MouseDown { x, y, button } => {
                    if button == MouseButton::Left && (self.pressed || self.released) {
                        evs.push_front(Event::MouseDown { x, y, button });
                        break;
                    }
                    self.mouse = (x / scale, y / scale);
                    match button {
                        MouseButton::Left => {
                            self.pressed = true;
                            self.mouse_down = true;
                            if let Some((t, px, py)) = self.last_press {
                                if self.now.duration_since(t) < Duration::from_millis(450)
                                    && (px - self.mouse.0).abs() < 5.0
                                    && (py - self.mouse.1).abs() < 5.0
                                {
                                    self.double = true;
                                }
                            }
                            self.last_press = if self.double { None } else { Some((self.now, self.mouse.0, self.mouse.1)) };
                        }
                        MouseButton::Right => self.right_pressed = true,
                        _ => {}
                    }
                }
                Event::MouseUp { x, y, button } => {
                    if button == MouseButton::Left {
                        if self.released {
                            evs.push_front(Event::MouseUp { x, y, button });
                            break;
                        }
                        self.mouse = (x / scale, y / scale);
                        self.released = true;
                        self.mouse_down = false;
                    }
                }
                Event::MouseLeft => {
                    if !self.mouse_down {
                        self.mouse = (-1e6, -1e6)
                    }
                }
                Event::Scroll { dx, dy } => {
                    self.scroll.0 += dx;
                    self.scroll.1 += dy;
                }
                Event::KeyDown { key, mods } => {
                    self.mods = mods;
                    if key != Key::Unknown {
                        if mods.command() && key == Key::Char('v') && self.clip_in.is_none() {
                            self.clip_in = clipboard_get();
                        }
                        if key == Key::Tab {
                            self.tab = Some(mods.shift);
                        }
                        self.keys.push((key, mods));
                    }
                }
                Event::KeyUp { mods, .. } => self.mods = mods,
                Event::Text(s) => self.text_in.push_str(&s),
                Event::CloseRequested => self.close_req = true,
                Event::Focus(false) => {
                    self.mods = Mods::default();
                }
                _ => {}
            }
        }
        if !evs.is_empty() {
            self.pending = evs;
        }

        self.block_prev = std::mem::take(&mut self.block_cur);
        self.layer = 0;
        self.focus_list.clear();
        self.focus_claimed = false;
        self.id_counts.clear();
        self.id_stack.truncate(1);
        self.cursor = CursorIcon::Arrow;
        self.deferred.clear();
        self.layouts.clear();
        let full = Rect::new(0.0, 0.0, self.size.0, self.size.1);
        self.layouts.push(Layout::new(full, Dir::Down, self.theme.spacing, 0.0));
        self.canvas.clear(self.theme.bg);
        self.toasts.retain(|t| t.until > self.now);
    }

    /// Finish the frame and show it.
    pub fn end_frame(&mut self, win: &mut Window) {
        let (cursor, clip) = self.end_frame_raw();
        if let Some(t) = clip {
            win.clipboard_set(&t);
        }
        win.set_cursor(cursor);
        win.present(&self.canvas);
    }

    /// Window-less variant of [`end_frame`](Self::end_frame): finishes painting into
    /// `self.canvas` and returns (cursor to show, text to put on the clipboard).
    pub fn end_frame_raw(&mut self) -> (CursorIcon, Option<String>) {
        for f in std::mem::take(&mut self.deferred) {
            self.canvas.reset_clip();
            f(&mut self.canvas, &self.fonts, &self.theme);
        }
        self.canvas.reset_clip();
        self.paint_toasts();

        if let Some(back) = self.tab.take() {
            if !self.focus_list.is_empty() {
                let n = self.focus_list.len();
                let idx = self.focus.and_then(|f| self.focus_list.iter().position(|&x| x == f));
                let next = match (idx, back) {
                    (Some(i), false) => (i + 1) % n,
                    (Some(i), true) => (i + n - 1) % n,
                    (None, false) => 0,
                    (None, true) => n - 1,
                };
                let id = self.focus_list[next];
                self.focus = Some(id);
                if let Some(st) = self.text_state.get_mut(&id) {
                    st.anchor = 0;
                    st.cursor = usize::MAX; // select all, clamped on next frame
                }
                self.repaint_now = true;
            }
        }
        if self.pressed && !self.focus_claimed && self.focus.is_some() {
            self.focus = None;
            self.repaint_now = true;
        }
        if !self.mouse_down {
            self.active = None;
        }
        if self.focus.is_some() {
            self.request_repaint_after(Duration::from_millis(530)); // caret blink
        }
        // Input may change app state after the widgets that display it were
        // drawn; one follow-up frame makes the screen consistent.
        if self.pressed || self.released || !self.keys.is_empty() || !self.text_in.is_empty() || self.scroll != (0.0, 0.0) {
            self.repaint_now = true;
        }
        (self.cursor, self.clip_out.take())
    }

    /// The user tried to close the window this frame.
    pub fn close_requested(&self) -> bool {
        self.close_req
    }

    /// Ask [`run`] to exit after this frame.
    pub fn quit(&mut self) {
        self.quit = true;
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// Logical window size.
    pub fn screen_size(&self) -> (f32, f32) {
        self.size
    }

    pub fn time(&self) -> f32 {
        self.now.duration_since(self.start).as_secs_f32()
    }

    pub fn mouse_pos(&self) -> (f32, f32) {
        self.mouse
    }

    /// Keys pressed this frame (not consumed by widgets — check `ui.has_focus()`).
    pub fn keys_pressed(&self) -> &[(Key, Mods)] {
        &self.keys
    }

    pub fn key_pressed(&self, key: Key) -> bool {
        self.keys.iter().any(|(k, _)| *k == key)
    }

    /// Whether a text input currently has keyboard focus.
    pub fn has_focus(&self) -> bool {
        self.focus.is_some()
    }

    /// Put text on the system clipboard at the end of the frame.
    pub fn copy_to_clipboard(&mut self, text: &str) {
        self.clip_out = Some(text.to_string());
    }

    // ------------------------------------------------------------------ ids

    fn parent_id(&self) -> u64 {
        *self.id_stack.last().unwrap()
    }

    /// A stable id for `src` in the current id scope (unique per occurrence).
    pub fn make_id(&mut self, src: impl Hash) -> Id {
        let base = hash_of(self.parent_id(), src);
        let n = self.id_counts.entry(base).or_insert(0);
        *n += 1;
        if *n == 1 {
            base
        } else {
            hash_of(base, *n)
        }
    }

    pub fn push_id(&mut self, src: impl Hash) {
        let id = hash_of(self.parent_id(), src);
        self.id_stack.push(id);
    }

    pub fn pop_id(&mut self) {
        if self.id_stack.len() > 1 {
            self.id_stack.pop();
        }
    }

    /// Run `f` inside an id scope (use in loops: `ui.with_id(item.key, |ui| ...)`).
    pub fn with_id<R>(&mut self, src: impl Hash, f: impl FnOnce(&mut Ui) -> R) -> R {
        self.push_id(src);
        let r = f(self);
        self.pop_id();
        r
    }

    // ------------------------------------------------------------------ input helpers

    fn blocked(&self, x: f32, y: f32) -> bool {
        self.block_prev.iter().any(|(l, r)| *l > self.layer && r.contains(x, y))
    }

    /// Is the mouse over `r` (respecting clipping and overlays)?
    pub fn mouse_over(&self, r: Rect) -> bool {
        let (x, y) = self.mouse;
        r.contains(x, y) && self.canvas.clip_rect().contains(x, y) && !self.blocked(x, y)
    }

    /// Generic click interaction for a custom widget.
    pub fn interact(&mut self, rect: Rect, id: Id, enabled: bool) -> Response {
        let over = enabled && self.mouse_over(rect);
        let hovered = over && (self.active.is_none() || self.active == Some(id));
        let mut r = Response { rect, hovered, ..Default::default() };
        if hovered {
            self.cursor = CursorIcon::Hand;
        }
        if over && self.pressed {
            self.active = Some(id);
            r.pressed = true;
            r.double_clicked = self.double;
        }
        if self.released && self.active == Some(id) && over {
            r.clicked = true;
        }
        if over && self.right_pressed {
            r.secondary_clicked = true;
        }
        r.active = self.active == Some(id) && self.mouse_down;
        r
    }

    // ------------------------------------------------------------------ layout

    fn top(&mut self) -> &mut Layout {
        self.layouts.last_mut().unwrap()
    }

    /// Remaining free region of the current layout.
    pub fn available_rect(&self) -> Rect {
        let l = self.layouts.last().unwrap();
        match l.dir {
            Dir::Down => Rect::new(l.rect.x, l.cursor, l.rect.w, (l.rect.bottom() - l.cursor).max(0.0)),
            Dir::Right => Rect::new(l.cursor, l.rect.y, (l.rect.right() - l.cursor).max(0.0), l.rect.h),
            Dir::Left => Rect::new(l.rect.x, l.rect.y, (l.cursor - l.rect.x).max(0.0), l.rect.h),
        }
    }

    pub fn available_width(&self) -> f32 {
        self.available_rect().w
    }

    /// Reserve space. `w = None` fills the available width.
    pub fn allocate(&mut self, w: Option<f32>, h: f32) -> Rect {
        let l = self.top();
        l.items += 1;
        match l.dir {
            Dir::Down => {
                let w = w.unwrap_or(l.rect.w).min(l.rect.w.max(0.0));
                let r = Rect::new(l.rect.x, l.cursor, w, h);
                l.cursor += h + l.spacing;
                l.cross = l.cross.max(w);
                r
            }
            Dir::Right => {
                let w = w.unwrap_or((l.rect.right() - l.cursor).max(0.0));
                let rh = l.row_h.max(h);
                let r = Rect::new(l.cursor, l.rect.y + ((rh - h) * 0.5).max(0.0).round(), w, h);
                l.cursor += w + l.spacing;
                l.cross = l.cross.max(h);
                r
            }
            Dir::Left => {
                let w = w.unwrap_or((l.cursor - l.rect.x).max(0.0));
                let rh = l.row_h.max(h);
                let r = Rect::new(l.cursor - w, l.rect.y + ((rh - h) * 0.5).max(0.0).round(), w, h);
                l.cursor -= w + l.spacing;
                l.cross = l.cross.max(h);
                r
            }
        }
    }

    /// Empty space along the layout direction.
    pub fn space(&mut self, amount: f32) {
        let l = self.top();
        match l.dir {
            Dir::Down => l.cursor += amount,
            Dir::Right => l.cursor += amount,
            Dir::Left => l.cursor -= amount,
        }
    }

    fn run_child<R>(&mut self, lay: Layout, f: impl FnOnce(&mut Ui) -> R) -> (R, Layout) {
        self.layouts.push(lay);
        let r = f(self);
        let l = self.layouts.pop().unwrap();
        (r, l)
    }

    /// Lay out children left-to-right in a row of `control_height`.
    pub fn horizontal<R>(&mut self, f: impl FnOnce(&mut Ui) -> R) -> R {
        let h = self.theme.control_height;
        self.horizontal_sized(h, f)
    }

    pub fn horizontal_sized<R>(&mut self, row_h: f32, f: impl FnOnce(&mut Ui) -> R) -> R {
        let avail = self.available_rect();
        let sp = self.theme.spacing;
        let (r, l) = self.run_child(Layout::new(Rect::new(avail.x, avail.y, avail.w, row_h), Dir::Right, sp, row_h), f);
        let used_w = l.used_main();
        let h = l.cross.max(row_h);
        let w = if self.top().dir == Dir::Down { None } else { Some(used_w) };
        self.allocate(w, h);
        r
    }

    /// Row laid out from the right edge leftwards (e.g. dialog buttons).
    pub fn right_to_left<R>(&mut self, f: impl FnOnce(&mut Ui) -> R) -> R {
        let avail = self.available_rect();
        let row_h = {
            let t = self.layouts.last().unwrap();
            if t.dir == Dir::Down { self.theme.control_height } else { t.row_h.max(self.theme.control_height) }
        };
        let sp = self.theme.spacing;
        let (r, l) = self.run_child(Layout::new(Rect::new(avail.x, avail.y, avail.w, row_h), Dir::Left, sp, row_h), f);
        let h = l.cross.max(row_h);
        self.allocate(None, h);
        r
    }

    /// Vertical sub-layout of a fixed width (inside a row) or full width.
    pub fn vertical<R>(&mut self, width: Option<f32>, f: impl FnOnce(&mut Ui) -> R) -> R {
        let avail = self.available_rect();
        let w = width.unwrap_or(avail.w).max(0.0);
        let sp = self.theme.spacing;
        let (in_row, row_h) = {
            let t = self.layouts.last().unwrap();
            (t.dir != Dir::Down, t.row_h)
        };
        // Inside a row, centre vertically using last frame's measured height.
        let id = self.make_id("vertical");
        let y_off = if in_row { self.heights.get(&id).map_or(0.0, |h| ((row_h - h) * 0.5).max(0.0).round()) } else { 0.0 };
        let (r, l) = self.run_child(Layout::new(Rect::new(avail.x, avail.y + y_off, w, 1e7), Dir::Down, sp, 0.0), f);
        let h = l.used_main();
        if in_row && self.heights.get(&id).map_or(true, |p| (p - h).abs() > 0.5) {
            self.heights.insert(id, h);
            self.request_repaint();
        }
        self.allocate(Some(w), h);
        r
    }

    /// Lay out widgets vertically inside an absolute rectangle (no space is
    /// reserved in the parent). Use for sidebars, headers, panes.
    pub fn with_rect<R>(&mut self, rect: Rect, f: impl FnOnce(&mut Ui) -> R) -> R {
        let sp = self.theme.spacing;
        self.run_child(Layout::new(rect, Dir::Down, sp, 0.0), f).0
    }

    /// Change spacing between items of the current layout.
    pub fn set_spacing(&mut self, s: f32) {
        self.top().spacing = s;
    }

    /// Equal-width columns. `f(ui, column_index)` is called for each column.
    pub fn columns(&mut self, n: usize, mut f: impl FnMut(&mut Ui, usize)) {
        let avail = self.available_rect();
        let gap = self.theme.spacing * 1.6;
        let cw = (avail.w - gap * (n as f32 - 1.0)) / n as f32;
        let sp = self.theme.spacing;
        let mut maxh: f32 = 0.0;
        for i in 0..n {
            let r = Rect::new(avail.x + i as f32 * (cw + gap), avail.y, cw, 1e7);
            let (_, l) = self.run_child(Layout::new(r, Dir::Down, sp, 0.0), |ui| f(ui, i));
            maxh = maxh.max(l.used_main());
        }
        self.allocate(None, maxh);
    }

    /// Indent contents by `pad` on every side.
    pub fn padded<R>(&mut self, pad: f32, f: impl FnOnce(&mut Ui) -> R) -> R {
        let avail = self.available_rect();
        let sp = self.theme.spacing;
        let inner = Rect::new(avail.x + pad, avail.y + pad, (avail.w - 2.0 * pad).max(0.0), 1e7);
        let (r, l) = self.run_child(Layout::new(inner, Dir::Down, sp, 0.0), f);
        let h = l.used_main() + 2.0 * pad;
        self.allocate(None, h);
        r
    }

    // ------------------------------------------------------------------ painting helpers

    pub fn font(&self, bold: bool) -> &Font {
        self.fonts.get(bold)
    }

    pub fn measure(&self, text: &str, size: f32, bold: bool) -> f32 {
        self.fonts.get(bold).measure(text, size)
    }

    /// Draw text with its line box top at (x, y).
    pub fn paint_text(&mut self, x: f32, y: f32, text: &str, size: f32, color: Color, bold: bool) -> f32 {
        self.fonts.get(bold).draw(&mut self.canvas, x, y, size, text, color)
    }

    /// Draw text vertically centred in `r`, left aligned, ellipsised to fit.
    pub fn paint_text_in(&mut self, r: Rect, text: &str, size: f32, color: Color, bold: bool) {
        paint_text_in(&mut self.canvas, &self.fonts, r, text, size, color, bold, false)
    }

    /// Draw text centred in `r`.
    pub fn paint_text_centered(&mut self, r: Rect, text: &str, size: f32, color: Color, bold: bool) {
        paint_text_in(&mut self.canvas, &self.fonts, r, text, size, color, bold, true)
    }

    pub fn paint_icon(&mut self, icon: Icon, x: f32, y: f32, size: f32, color: Color) {
        draw_icon(&mut self.canvas, icon, x, y, size, color);
    }

    /// Paint a surface card background (shadow + border) — for custom layouts.
    pub fn paint_card(&mut self, r: Rect) {
        let t = &self.theme;
        let (rad, surf, border) = (t.radius + 2.0, t.surface, t.border);
        self.canvas.shadow(r.translate(0.0, 1.0), rad, 4.0, Color::rgba(15, 23, 42, 14));
        self.canvas.fill_rounded_rect(r, rad, surf);
        self.canvas.stroke_rounded_rect(r, rad, 1.0, border);
    }

    /// Defer painting until after all widgets (for overlays).
    pub fn paint_overlay(&mut self, f: impl FnOnce(&mut Canvas, &Fonts, &Theme) + 'static) {
        self.deferred.push(Box::new(f));
    }

    // ------------------------------------------------------------------ text widgets

    /// Label with a style.
    pub fn text(&mut self, text: &str, style: TextStyle) -> Response {
        let color = style.color.unwrap_or(self.theme.text);
        let font = self.fonts.get(style.bold);
        let lh = font.line_height(style.size);
        let avail_w = self.available_width();
        if style.wrap {
            let lines = wrap_text(font, text, style.size, avail_w.max(10.0));
            let h = lh * lines.len().max(1) as f32;
            let w = lines.iter().map(|l| font.measure(l, style.size)).fold(0.0, f32::max);
            let th = font.text_height(style.size);
            let r = self.allocate(Some(w.min(avail_w)), h);
            for (i, l) in lines.iter().enumerate() {
                let y = r.y + i as f32 * lh + (lh - th) * 0.5;
                self.fonts.get(style.bold).draw(&mut self.canvas, r.x, y, style.size, l, color);
            }
            Response { rect: r, hovered: self.mouse_over(r), ..Default::default() }
        } else {
            let w = font.measure(text, style.size).ceil();
            let _ = font;
            let r = self.allocate(Some(w.min(avail_w.max(0.0))), lh);
            paint_text_in(&mut self.canvas, &self.fonts, r, text, style.size, color, style.bold, false);
            Response { rect: r, hovered: self.mouse_over(r), ..Default::default() }
        }
    }

    pub fn label(&mut self, text: &str) -> Response {
        let s = self.theme.font_size;
        self.text(text, TextStyle::body().size(s))
    }

    pub fn label_muted(&mut self, text: &str) -> Response {
        let (s, c) = (self.theme.font_size, self.theme.text_muted);
        self.text(text, TextStyle::body().size(s).color(c))
    }

    pub fn label_wrapped(&mut self, text: &str) -> Response {
        let (s, c) = (self.theme.font_size, self.theme.text_muted);
        self.text(text, TextStyle::body().size(s).color(c).wrap())
    }

    pub fn small(&mut self, text: &str) -> Response {
        let (s, c) = (self.theme.small_size, self.theme.text_muted);
        self.text(text, TextStyle::body().size(s).color(c))
    }

    pub fn heading(&mut self, text: &str) -> Response {
        let s = self.theme.heading_size;
        self.text(text, TextStyle::body().size(s).bold())
    }

    pub fn subheading(&mut self, text: &str) -> Response {
        let s = self.theme.title_size;
        self.text(text, TextStyle::body().size(s).bold())
    }

    /// Field caption (small, bold, muted) used above inputs.
    pub fn field_label(&mut self, text: &str) -> Response {
        let c = Color::hex(0x334155);
        self.text(text, TextStyle::body().size(13.0).bold().color(c))
    }

    pub fn separator(&mut self) {
        let r = self.allocate(None, 1.0);
        let c = self.theme.border;
        self.canvas.fill_rect(r, c);
    }

    /// Small coloured pill.
    pub fn badge(&mut self, text: &str, tone: Tone) -> Response {
        let size = 12.0;
        let w = self.measure(text, size, true) + 20.0;
        let r = self.allocate(Some(w), 22.0);
        let (bg, fg) = tone_colors(&self.theme, tone);
        self.canvas.fill_rounded_rect(r, 11.0, bg);
        self.canvas.fill_circle(r.x + 9.0, r.y + 11.0, 0.0, fg);
        paint_text_in(&mut self.canvas, &self.fonts, r, text, size, fg, true, true);
        Response { rect: r, hovered: self.mouse_over(r), ..Default::default() }
    }

    /// An icon on its own.
    pub fn icon(&mut self, icon: Icon, size: f32, color: Color) -> Response {
        let r = self.allocate(Some(size), size);
        draw_icon(&mut self.canvas, icon, r.x, r.y, size, color);
        Response { rect: r, hovered: self.mouse_over(r), ..Default::default() }
    }

    /// Coloured callout box with an icon and wrapped text.
    pub fn callout(&mut self, tone: Tone, text: &str) {
        let avail = self.available_width();
        let size = 13.0;
        let font = self.fonts.get(false);
        let lines = wrap_text(font, text, size, (avail - 52.0).max(20.0));
        let lh = font.line_height(size);
        let h = (lines.len() as f32 * lh + 22.0).max(42.0);
        let r = self.allocate(None, h);
        let (bg, fg) = tone_colors(&self.theme, tone);
        self.canvas.fill_rounded_rect(r, self.theme.radius, bg);
        self.canvas.stroke_rounded_rect(r, self.theme.radius, 1.0, fg.with_alpha(50));
        let icon = match tone {
            Tone::Success => Icon::Success,
            Tone::Warning => Icon::Warning,
            Tone::Danger => Icon::Error,
            _ => Icon::Info,
        };
        draw_icon(&mut self.canvas, icon, r.x + 14.0, r.y + 11.0 + (lh - 18.0) * 0.5, 18.0, fg);
        let th = self.fonts.regular.text_height(size);
        for (i, l) in lines.iter().enumerate() {
            let y = r.y + 11.0 + i as f32 * lh + (lh - th) * 0.5;
            self.fonts.regular.draw(&mut self.canvas, r.x + 42.0, y, size, l, self.theme.text);
        }
    }

    // ------------------------------------------------------------------ buttons

    pub fn button(&mut self, text: &str) -> Response {
        self.button_ex(text, ButtonKind::Secondary, None, true)
    }

    pub fn primary_button(&mut self, text: &str) -> Response {
        self.button_ex(text, ButtonKind::Primary, None, true)
    }

    pub fn danger_button(&mut self, text: &str) -> Response {
        self.button_ex(text, ButtonKind::Danger, None, true)
    }

    /// Full-featured button.
    pub fn button_ex(&mut self, text: &str, kind: ButtonKind, icon: Option<Icon>, enabled: bool) -> Response {
        let size = self.theme.font_size;
        let tw = self.measure(text, size, true);
        let iw = if icon.is_some() { if text.is_empty() { 18.0 } else { 26.0 } } else { 0.0 };
        let pad = if text.is_empty() { 9.0 } else { 16.0 };
        let w = (tw + iw + 2.0 * pad).ceil();
        let h = self.theme.control_height;
        let r = self.allocate(Some(w), h);
        let id = self.make_id(("button", text, icon.map(|i| i as u32)));
        let resp = self.interact(r, id, enabled);
        let t = &self.theme;
        let (bg, fg, border) = match kind {
            ButtonKind::Primary => {
                let bg = if resp.active { t.accent_pressed } else if resp.hovered { t.accent_hover } else { t.accent };
                (bg, t.on_accent, None)
            }
            ButtonKind::Danger => {
                let bg = if resp.hovered { t.danger_hover } else { t.danger };
                (bg, Color::WHITE, None)
            }
            ButtonKind::Secondary => {
                let bg = if resp.active { Color::hex(0xE2E8F0) } else if resp.hovered { t.hover } else { t.surface };
                (bg, t.text, Some(t.border_strong))
            }
            ButtonKind::Ghost => {
                let bg = if resp.active { Color::hex(0xE2E8F0) } else if resp.hovered { t.hover } else { Color::TRANSPARENT };
                (bg, t.text_muted, None)
            }
        };
        let (bg, fg) = if enabled { (bg, fg) } else { (bg.lerp(t.bg, 0.55), fg.lerp(t.bg, 0.5)) };
        let radius = t.radius;
        if kind == ButtonKind::Primary && enabled {
            self.canvas.shadow(r.translate(0.0, 1.0), radius, 2.0, Color::rgba(37, 99, 235, 40));
        }
        self.canvas.fill_rounded_rect(r, radius, bg);
        if let Some(b) = border {
            self.canvas.stroke_rounded_rect(r, radius, 1.0, b);
        }
        let mut x = r.x + pad;
        if let Some(ic) = icon {
            draw_icon(&mut self.canvas, ic, x, r.y + (h - 18.0) * 0.5, 18.0, fg);
            x += iw;
        }
        if !text.is_empty() {
            let tr = Rect::new(x, r.y, tw + 2.0, h);
            paint_text_in(&mut self.canvas, &self.fonts, tr, text, size, fg, true, false);
        }
        resp
    }

    /// Square ghost button with an icon.
    pub fn icon_button(&mut self, icon: Icon) -> Response {
        self.icon_button_ex(icon, 32.0, None)
    }

    pub fn icon_button_ex(&mut self, icon: Icon, size: f32, color: Option<Color>) -> Response {
        let r = self.allocate(Some(size), size);
        let id = self.make_id(("icon_button", icon as u32));
        let resp = self.interact(r, id, true);
        if resp.hovered {
            let c = if resp.active { Color::hex(0xE2E8F0) } else { self.theme.hover };
            self.canvas.fill_rounded_rect(r, 6.0, c);
        }
        let s = (size * 0.56).round();
        let col = color.unwrap_or(if resp.hovered { self.theme.text } else { self.theme.text_muted });
        draw_icon(&mut self.canvas, icon, r.x + (size - s) * 0.5, r.y + (size - s) * 0.5, s, col);
        resp
    }

    /// Text styled as a link.
    pub fn link(&mut self, text: &str) -> Response {
        let size = self.theme.font_size;
        let w = self.measure(text, size, false);
        let lh = self.fonts.regular.line_height(size);
        let r = self.allocate(Some(w), lh);
        let id = self.make_id(("link", text));
        let resp = self.interact(r, id, true);
        let c = if resp.hovered { self.theme.accent_hover } else { self.theme.accent };
        paint_text_in(&mut self.canvas, &self.fonts, r, text, size, c, false, false);
        if resp.hovered {
            self.canvas.fill_rect(Rect::new(r.x, r.bottom() - 2.0, w, 1.0), c);
        }
        resp
    }

    /// Tooltip shown while `resp` is hovered.
    pub fn tooltip(&mut self, resp: &Response, text: &str) {
        if !resp.hovered || self.mouse_down {
            return;
        }
        let text = text.to_string();
        let (mx, my) = self.mouse;
        let (sw, sh) = self.size;
        self.paint_overlay(move |c, fonts, _t| {
            let size = 12.0;
            let w = fonts.regular.measure(&text, size) + 16.0;
            let h = 26.0;
            let x = (mx + 12.0).min(sw - w - 4.0).max(4.0);
            let y = if my + 22.0 + h > sh { my - h - 6.0 } else { my + 22.0 };
            let r = Rect::new(x, y, w, h);
            c.shadow(r, 6.0, 4.0, Color::rgba(0, 0, 0, 40));
            c.fill_rounded_rect(r, 6.0, Color::hex(0x1E293B));
            paint_text_in(c, fonts, r, &text, size, Color::WHITE, false, true);
        });
    }

    // ------------------------------------------------------------------ toggles

    pub fn checkbox(&mut self, value: &mut bool, label: &str) -> Response {
        let size = self.theme.font_size;
        let tw = if label.is_empty() { 0.0 } else { self.measure(label, size, false) + 10.0 };
        let r = self.allocate(Some(18.0 + tw), 24.0);
        let id = self.make_id(("checkbox", label));
        let mut resp = self.interact(r, id, true);
        if resp.clicked {
            *value = !*value;
            resp.changed = true;
        }
        let b = Rect::new(r.x, r.y + 3.0, 18.0, 18.0);
        let t = &self.theme;
        if *value {
            let c = if resp.hovered { t.accent_hover } else { t.accent };
            self.canvas.fill_rounded_rect(b, 5.0, c);
            draw_icon(&mut self.canvas, Icon::Check, b.x + 1.5, b.y + 1.5, 15.0, Color::WHITE);
        } else {
            self.canvas.fill_rounded_rect(b, 5.0, t.surface);
            let bc = if resp.hovered { t.accent } else { t.border_strong };
            self.canvas.stroke_rounded_rect(b, 5.0, 1.5, bc);
        }
        if !label.is_empty() {
            let tc = self.theme.text;
            paint_text_in(&mut self.canvas, &self.fonts, Rect::new(r.x + 28.0, r.y, tw, r.h), label, size, tc, false, false);
        }
        resp
    }

    pub fn toggle(&mut self, value: &mut bool, label: &str) -> Response {
        let size = self.theme.font_size;
        let tw = if label.is_empty() { 0.0 } else { self.measure(label, size, false) + 12.0 };
        let r = self.allocate(Some(38.0 + tw), 24.0);
        let id = self.make_id(("toggle", label));
        let mut resp = self.interact(r, id, true);
        if resp.clicked {
            *value = !*value;
            resp.changed = true;
        }
        let tr = Rect::new(r.x, r.y + 2.0, 38.0, 20.0);
        let t = &self.theme;
        let c = if *value { t.accent } else if resp.hovered { Color::hex(0xB8C2D0) } else { t.border_strong };
        self.canvas.fill_rounded_rect(tr, 10.0, c);
        let kx = if *value { tr.right() - 10.0 } else { tr.x + 10.0 };
        self.canvas.fill_circle(kx, tr.y + 10.0 + 0.5, 8.5, Color::rgba(0, 0, 0, 30));
        self.canvas.fill_circle(kx, tr.y + 10.0, 8.0, Color::WHITE);
        if !label.is_empty() {
            let tc = self.theme.text;
            paint_text_in(&mut self.canvas, &self.fonts, Rect::new(r.x + 50.0, r.y, tw, r.h), label, size, tc, false, false);
        }
        resp
    }

    /// Group of mutually exclusive pills.
    pub fn segmented(&mut self, selected: &mut usize, options: &[&str]) -> Response {
        let size = 13.0;
        let widths: Vec<f32> = options.iter().map(|o| self.measure(o, size, true) + 28.0).collect();
        let total: f32 = widths.iter().sum::<f32>() + 8.0;
        let r = self.allocate(Some(total), 34.0);
        let mut out = Response { rect: r, ..Default::default() };
        self.canvas.fill_rounded_rect(r, 9.0, Color::hex(0xE9EDF3));
        let mut x = r.x + 4.0;
        for (i, o) in options.iter().enumerate() {
            let br = Rect::new(x, r.y + 4.0, widths[i], 26.0);
            let id = self.make_id(("segment", i, *o));
            let resp = self.interact(br, id, true);
            if resp.clicked && *selected != i {
                *selected = i;
                out.changed = true;
            }
            out.hovered |= resp.hovered;
            if *selected == i {
                self.canvas.shadow(br, 6.0, 2.0, Color::rgba(15, 23, 42, 25));
                self.canvas.fill_rounded_rect(br, 6.0, Color::WHITE);
            }
            let c = if *selected == i { self.theme.text } else { self.theme.text_muted };
            paint_text_in(&mut self.canvas, &self.fonts, br, o, size, c, true, true);
            x += widths[i];
        }
        out
    }

    // ------------------------------------------------------------------ text input

    /// Single-line text field. `id_src` must be stable across frames.
    pub fn text_input(&mut self, id_src: &str, value: &mut String, opts: &TextInputOptions) -> Response {
        let h = self.theme.control_height;
        let r = self.allocate(opts.width, h);
        let id = self.make_id(("text_input", id_src));
        if opts.enabled {
            self.focus_list.push(id);
        }
        let size = self.theme.font_size;
        let over = opts.enabled && self.mouse_over(r);
        let mut resp = Response { rect: r, hovered: over, ..Default::default() };
        if over {
            self.cursor = CursorIcon::Text;
        }
        let left_pad = if opts.icon.is_some() { 36.0 } else { 12.0 };
        let inner = Rect::new(r.x + left_pad, r.y, (r.w - left_pad - 12.0).max(1.0), r.h);
        let mut st = self.text_state.remove(&id).unwrap_or_default();
        let nchars = value.chars().count();
        st.cursor = st.cursor.min(nchars);
        st.anchor = st.anchor.min(nchars);
        let display = |v: &str| -> String {
            if opts.password {
                "•".repeat(v.chars().count())
            } else {
                v.to_string()
            }
        };
        let font = &self.fonts.regular;
        let disp = display(value);
        let pos = font.caret_positions(&disp, size);
        let hit = |mx: f32, pos: &[f32], scroll: f32| -> usize {
            let x = mx - inner.x + scroll;
            let mut best = 0;
            let mut bd = f32::MAX;
            for (i, &p) in pos.iter().enumerate() {
                let d = (p - x).abs();
                if d < bd {
                    bd = d;
                    best = i;
                }
            }
            best
        };
        if over && self.pressed {
            self.focus_claimed = true;
            let first_focus = self.focus != Some(id);
            self.focus = Some(id);
            self.active = Some(id);
            let c = hit(self.mouse.0, &pos, st.scroll);
            if self.double {
                st.anchor = 0;
                st.cursor = nchars;
            } else {
                st.cursor = c;
                if !self.mods.shift || first_focus {
                    st.anchor = c;
                }
            }
        } else if self.active == Some(id) && self.mouse_down {
            st.cursor = hit(self.mouse.0, &pos, st.scroll);
            self.cursor = CursorIcon::Text;
        }
        let focused = self.focus == Some(id) && opts.enabled;
        if focused && self.pressed && over {
            self.focus_claimed = true;
        }
        if focused {
            let old = value.clone();
            let sel = |st: &TextState| (st.cursor.min(st.anchor), st.cursor.max(st.anchor));
            let delete_sel = |value: &mut String, st: &mut TextState| -> bool {
                let (a, b) = sel(st);
                if a == b {
                    return false;
                }
                let (ba, bb) = (byte_idx(value, a), byte_idx(value, b));
                value.replace_range(ba..bb, "");
                st.cursor = a;
                st.anchor = a;
                true
            };
            let insert = |value: &mut String, st: &mut TextState, s: &str| {
                delete_sel(value, st);
                let clean: String = s.chars().filter(|c| !c.is_control()).collect();
                let bi = byte_idx(value, st.cursor);
                value.insert_str(bi, &clean);
                st.cursor += clean.chars().count();
                st.anchor = st.cursor;
            };
            let keys = self.keys.clone();
            for (key, mods) in keys {
                let n = value.chars().count();
                let cmd = mods.command();
                match key {
                    Key::Left => {
                        if !mods.shift && st.cursor != st.anchor {
                            st.cursor = sel(&st).0;
                        } else if st.cursor > 0 {
                            st.cursor = if cmd || mods.alt { word_left(value, st.cursor) } else { st.cursor - 1 };
                        }
                        if !mods.shift {
                            st.anchor = st.cursor;
                        }
                    }
                    Key::Right => {
                        if !mods.shift && st.cursor != st.anchor {
                            st.cursor = sel(&st).1;
                        } else if st.cursor < n {
                            st.cursor = if cmd || mods.alt { word_right(value, st.cursor) } else { st.cursor + 1 };
                        }
                        if !mods.shift {
                            st.anchor = st.cursor;
                        }
                    }
                    Key::Home | Key::Up => {
                        st.cursor = 0;
                        if !mods.shift {
                            st.anchor = 0;
                        }
                    }
                    Key::End | Key::Down => {
                        st.cursor = n;
                        if !mods.shift {
                            st.anchor = n;
                        }
                    }
                    Key::Backspace => {
                        if !delete_sel(value, &mut st) && st.cursor > 0 {
                            let from = if cmd || mods.alt { word_left(value, st.cursor) } else { st.cursor - 1 };
                            let (a, b) = (byte_idx(value, from), byte_idx(value, st.cursor));
                            value.replace_range(a..b, "");
                            st.cursor = from;
                            st.anchor = from;
                        }
                    }
                    Key::Delete => {
                        if !delete_sel(value, &mut st) && st.cursor < n {
                            let (a, b) = (byte_idx(value, st.cursor), byte_idx(value, st.cursor + 1));
                            value.replace_range(a..b, "");
                        }
                    }
                    Key::Enter => resp.submitted = true,
                    Key::Escape => {
                        self.focus = None;
                    }
                    Key::Char('a') if cmd => {
                        st.anchor = 0;
                        st.cursor = n;
                    }
                    Key::Char('c') | Key::Char('x') if cmd => {
                        let (a, b) = sel(&st);
                        if a != b && !opts.password {
                            let s: String = value.chars().skip(a).take(b - a).collect();
                            self.clip_out = Some(s);
                            if key == Key::Char('x') {
                                delete_sel(value, &mut st);
                            }
                        }
                    }
                    Key::Char('v') if cmd => {
                        if let Some(c) = self.clip_in.clone() {
                            let one_line = c.replace(['\r', '\n'], " ");
                            insert(value, &mut st, one_line.trim_end());
                        }
                    }
                    _ => {}
                }
            }
            if !self.text_in.is_empty() && !self.mods.command() {
                let t = self.text_in.clone();
                insert(value, &mut st, &t);
            }
            if *value != old {
                resp.changed = true;
            }
        }
        // ----- paint
        let t = &self.theme;
        let bg = if opts.enabled { t.surface } else { t.surface_alt };
        if focused {
            self.canvas.fill_rounded_rect(r.expand(3.0), t.radius + 3.0, t.accent.with_alpha(40));
        }
        self.canvas.fill_rounded_rect(r, t.radius, bg);
        let bc = if focused { t.accent } else if over { Color::hex(0x94A3B8) } else { t.border_strong };
        self.canvas.stroke_rounded_rect(r, t.radius, if focused { 1.5 } else { 1.0 }, bc);
        if let Some(ic) = opts.icon {
            let c = t.text_faint;
            draw_icon(&mut self.canvas, ic, r.x + 11.0, r.y + (h - 17.0) * 0.5, 17.0, c);
        }
        let disp = display(value);
        let font = &self.fonts.regular;
        let pos = font.caret_positions(&disp, size);
        let cx = pos[st.cursor.min(pos.len() - 1)];
        // keep caret visible
        if cx - st.scroll > inner.w - 2.0 {
            st.scroll = cx - inner.w + 2.0;
        }
        if cx - st.scroll < 0.0 {
            st.scroll = cx;
        }
        let total = *pos.last().unwrap();
        st.scroll = st.scroll.min((total - inner.w + 2.0).max(0.0)).max(0.0);
        let ty = r.y + (h - font.text_height(size)) * 0.5;
        self.canvas.push_clip(inner.expand(1.0));
        if focused && st.cursor != st.anchor {
            let (a, b) = (st.cursor.min(st.anchor), st.cursor.max(st.anchor));
            let sr = Rect::new(inner.x + pos[a] - st.scroll, r.y + 8.0, pos[b] - pos[a], h - 16.0);
            self.canvas.fill_rect(sr, t.selection);
        }
        if disp.is_empty() {
            if !opts.placeholder.is_empty() {
                font.draw(&mut self.canvas, inner.x, ty, size, opts.placeholder, t.text_faint);
            }
        } else {
            let col = if opts.enabled { t.text } else { t.text_muted };
            font.draw(&mut self.canvas, inner.x - st.scroll, ty, size, &disp, col);
        }
        if focused {
            let blink_on = ((self.now.duration_since(self.start).as_millis() / 530) % 2 == 0) || resp.changed;
            if blink_on {
                let x = (inner.x + cx - st.scroll).round();
                self.canvas.fill_rect(Rect::new(x, r.y + 9.0, 1.5, h - 18.0), t.text);
            }
        }
        self.canvas.pop_clip();
        resp.focused = focused;
        self.text_state.insert(id, st);
        resp
    }

    /// Give keyboard focus to the text input with this `id_src` (in the current scope) next frame.
    pub fn focus_text_input(&mut self, id_src: &str) {
        let id = hash_of(self.parent_id(), ("text_input", id_src));
        self.focus = Some(id);
        self.repaint_now = true;
    }

    // ------------------------------------------------------------------ number / select

    /// `[-] value [+]` stepper.
    pub fn number_stepper(&mut self, id_src: &str, value: &mut i64, min: i64, max: i64, step: i64, suffix: &str) -> Response {
        let size = self.theme.font_size;
        let label = format!("{value}{suffix}");
        let vw = (self.measure(&format!("{max}{suffix}"), size, true) + 24.0).max(60.0);
        let h = self.theme.control_height;
        let r = self.allocate(Some(vw + 2.0 * h), h);
        let mut out = Response { rect: r, ..Default::default() };
        let t = self.theme.clone();
        self.canvas.fill_rounded_rect(r, t.radius, t.surface);
        self.canvas.stroke_rounded_rect(r, t.radius, 1.0, t.border_strong);
        let minus = Rect::new(r.x, r.y, h, h);
        let plus = Rect::new(r.right() - h, r.y, h, h);
        let idm = self.make_id(("stepper-", id_src));
        let idp = self.make_id(("stepper+", id_src));
        let rm = self.interact(minus, idm, *value > min);
        let rp = self.interact(plus, idp, *value < max);
        if rm.clicked {
            *value = (*value - step).max(min);
            out.changed = true;
        }
        if rp.clicked {
            *value = (*value + step).min(max);
            out.changed = true;
        }
        for (rr, resp, icon, en) in [(minus, rm, Icon::Minus, *value > min), (plus, rp, Icon::Plus, *value < max)] {
            if resp.hovered {
                self.canvas.fill_rounded_rect(rr.shrink(3.0), 6.0, t.hover);
            }
            let c = if en { t.text } else { t.text_faint };
            draw_icon(&mut self.canvas, icon, rr.x + (h - 16.0) * 0.5, rr.y + (h - 16.0) * 0.5, 16.0, c);
        }
        self.canvas.fill_rect(Rect::new(minus.right(), r.y + 1.0, 1.0, h - 2.0), t.border);
        self.canvas.fill_rect(Rect::new(plus.x - 1.0, r.y + 1.0, 1.0, h - 2.0), t.border);
        let label = if out.changed { format!("{value}{suffix}") } else { label };
        paint_text_in(&mut self.canvas, &self.fonts, Rect::new(minus.right(), r.y, vw, h), &label, size, t.text, true, true);
        out
    }

    /// Dropdown select. `width = None` fills the available width.
    pub fn select(&mut self, id_src: &str, selected: &mut usize, options: &[&str], width: Option<f32>) -> Response {
        let h = self.theme.control_height;
        let r = self.allocate(width, h);
        let id = self.make_id(("select", id_src));
        let mut resp = self.interact(r, id, true);
        let open = self.open_popup == Some(id);
        if resp.clicked && !open {
            self.open_popup = Some(id);
        }
        let t = self.theme.clone();
        let size = t.font_size;
        let is_open = self.open_popup == Some(id);
        if is_open {
            self.canvas.fill_rounded_rect(r.expand(3.0), t.radius + 3.0, t.accent.with_alpha(40));
        }
        self.canvas.fill_rounded_rect(r, t.radius, t.surface);
        let bc = if is_open { t.accent } else if resp.hovered { Color::hex(0x94A3B8) } else { t.border_strong };
        self.canvas.stroke_rounded_rect(r, t.radius, 1.0, bc);
        let cur = options.get(*selected).copied().unwrap_or("");
        paint_text_in(&mut self.canvas, &self.fonts, Rect::new(r.x + 12.0, r.y, r.w - 44.0, h), cur, size, t.text, false, false);
        draw_icon(&mut self.canvas, Icon::ChevronDown, r.right() - 30.0, r.y + (h - 18.0) * 0.5, 18.0, t.text_muted);

        if is_open && open {
            let item_h = 34.0;
            let (sw, sh) = self.size;
            let max_h = 320.0f32.min(sh - 16.0);
            let content_h = options.len() as f32 * item_h + 8.0;
            let ph = content_h.min(max_h);
            let mut py = r.bottom() + 4.0;
            if py + ph > sh - 8.0 && r.y - ph - 4.0 > 8.0 {
                py = r.y - ph - 4.0;
            }
            let pr = Rect::new(r.x, py, r.w, ph);
            let layer = self.layer + 1;
            self.block_cur.push((layer, Rect::new(0.0, 0.0, sw, sh)));
            let st = self.scroll_state.entry(id).or_default();
            let max_off = (content_h - ph).max(0.0);
            if pr.contains(self.mouse.0, self.mouse.1) && self.scroll.1 != 0.0 {
                st.offset = (st.offset - self.scroll.1 * 40.0).clamp(0.0, max_off);
                self.scroll.1 = 0.0;
            }
            let off = st.offset.min(max_off);
            let (mx, my) = self.mouse;
            let hovered_item = if pr.shrink2(0.0, 4.0).contains(mx, my) {
                let i = ((my - pr.y - 4.0 + off) / item_h).floor() as isize;
                if i >= 0 && (i as usize) < options.len() {
                    Some(i as usize)
                } else {
                    None
                }
            } else {
                None
            };
            if hovered_item.is_some() {
                self.cursor = CursorIcon::Hand;
            }
            if self.pressed {
                if let Some(i) = hovered_item {
                    if *selected != i {
                        *selected = i;
                        resp.changed = true;
                    }
                }
                if hovered_item.is_some() || !pr.contains(mx, my) {
                    self.open_popup = None;
                    self.active = Some(SUPPRESS);
                }
            }
            if self.keys.iter().any(|(k, _)| *k == Key::Escape) {
                self.open_popup = None;
            }
            if self.open_popup == Some(id) {
                let opts: Vec<String> = options.iter().map(|s| s.to_string()).collect();
                let sel = *selected;
                self.paint_overlay(move |c, fonts, t| {
                    c.shadow(pr.translate(0.0, 4.0), 10.0, 12.0, Color::rgba(15, 23, 42, 40));
                    c.fill_rounded_rect(pr, 10.0, t.surface);
                    c.stroke_rounded_rect(pr, 10.0, 1.0, t.border);
                    c.push_clip(pr.shrink(1.0));
                    for (i, o) in opts.iter().enumerate() {
                        let ir = Rect::new(pr.x + 4.0, pr.y + 4.0 + i as f32 * item_h - off, pr.w - 8.0, item_h);
                        if ir.bottom() < pr.y || ir.y > pr.bottom() {
                            continue;
                        }
                        if Some(i) == hovered_item {
                            c.fill_rounded_rect(ir, 6.0, t.hover);
                        }
                        let col = if i == sel { t.accent } else { t.text };
                        paint_text_in(c, fonts, Rect::new(ir.x + 10.0, ir.y, ir.w - 40.0, ir.h), o, 14.0, col, i == sel, false);
                        if i == sel {
                            draw_icon(c, Icon::Check, ir.right() - 26.0, ir.y + 8.0, 18.0, t.accent);
                        }
                    }
                    c.pop_clip();
                });
            }
            self.request_repaint();
        }
        resp
    }

    // ------------------------------------------------------------------ progress / nav / rows

    /// Progress bar; `fraction = None` shows an animated indeterminate bar.
    pub fn progress_bar(&mut self, fraction: Option<f32>, height: f32) -> Response {
        let r = self.allocate(None, height);
        let t = &self.theme;
        let rad = height * 0.5;
        self.canvas.fill_rounded_rect(r, rad, Color::hex(0xE2E8F0));
        let accent = t.accent;
        match fraction {
            Some(f) => {
                let w = (r.w * f.clamp(0.0, 1.0)).max(if f > 0.0 { height } else { 0.0 });
                if w > 0.0 {
                    self.canvas.fill_rounded_rect(Rect::new(r.x, r.y, w, r.h), rad, accent);
                }
            }
            None => {
                let phase = (self.time() * 0.8).fract();
                let bw = r.w * 0.3;
                let x = r.x - bw + (r.w + bw) * phase;
                self.canvas.push_clip(r);
                self.canvas.fill_rounded_rect(Rect::new(x, r.y, bw, r.h), rad, accent);
                self.canvas.pop_clip();
                self.request_repaint_after(Duration::from_millis(16));
            }
        }
        Response { rect: r, hovered: self.mouse_over(r), ..Default::default() }
    }

    /// Sidebar navigation entry.
    pub fn nav_item(&mut self, icon: Icon, label: &str, selected: bool) -> Response {
        let r = self.allocate(None, 40.0);
        let id = self.make_id(("nav", label));
        let resp = self.interact(r, id, true);
        let t = &self.theme;
        if selected {
            self.canvas.fill_rounded_rect(r, t.radius, t.accent_soft);
        } else if resp.hovered {
            self.canvas.fill_rounded_rect(r, t.radius, t.hover);
        }
        let c = if selected { t.accent } else { Color::hex(0x334155) };
        draw_icon(&mut self.canvas, icon, r.x + 12.0, r.y + 11.0, 18.0, c);
        paint_text_in(&mut self.canvas, &self.fonts, Rect::new(r.x + 42.0, r.y, r.w - 50.0, r.h), label, 14.0, c, selected, false);
        resp
    }

    /// Clickable row of `height`; children are laid out horizontally inside
    /// (padding 12). Returns the row's response (child widgets take precedence).
    pub fn row(&mut self, id_src: impl Hash, height: f32, selected: bool, f: impl FnOnce(&mut Ui)) -> Response {
        let r = self.allocate(None, height);
        let id = self.make_id(("row", id_src));
        let resp = self.interact(r, id, true);
        if resp.hovered {
            self.cursor = CursorIcon::Arrow;
        }
        let t = &self.theme;
        if selected {
            self.canvas.fill_rounded_rect(r, t.radius, t.accent_soft);
            self.canvas.stroke_rounded_rect(r, t.radius, 1.0, t.accent.with_alpha(90));
        } else if resp.hovered {
            self.canvas.fill_rounded_rect(r, t.radius, t.hover);
        }
        let inner = r.shrink2(12.0, 0.0);
        let sp = self.theme.spacing;
        self.run_child(Layout::new(inner, Dir::Right, sp, height), f);
        resp
    }

    /// A standard list entry: icon, title, optional subtitle.
    pub fn list_item(&mut self, icon: Option<Icon>, title: &str, subtitle: Option<&str>, selected: bool) -> Response {
        let h = if subtitle.is_some() { 54.0 } else { 40.0 };
        let r = self.allocate(None, h);
        let id = self.make_id(("list_item", title, subtitle));
        let resp = self.interact(r, id, true);
        let t = self.theme.clone();
        if selected {
            self.canvas.fill_rounded_rect(r, t.radius, t.accent_soft);
        } else if resp.hovered {
            self.canvas.fill_rounded_rect(r, t.radius, t.hover);
        }
        let mut x = r.x + 12.0;
        if let Some(ic) = icon {
            let c = if selected { t.accent } else { t.text_muted };
            draw_icon(&mut self.canvas, ic, x, r.y + (h - 20.0) * 0.5, 20.0, c);
            x += 32.0;
        }
        let w = r.right() - x - 12.0;
        match subtitle {
            Some(s) => {
                paint_text_in(&mut self.canvas, &self.fonts, Rect::new(x, r.y + 8.0, w, 20.0), title, 14.0, t.text, true, false);
                paint_text_in(&mut self.canvas, &self.fonts, Rect::new(x, r.y + 28.0, w, 18.0), s, 12.0, t.text_muted, false, false);
            }
            None => paint_text_in(&mut self.canvas, &self.fonts, Rect::new(x, r.y, w, h), title, 14.0, t.text, false, false),
        }
        resp
    }

    // ------------------------------------------------------------------ containers

    /// White card with padding; height adapts to its content.
    pub fn card<R>(&mut self, f: impl FnOnce(&mut Ui) -> R) -> R {
        let pad = self.theme.padding;
        self.card_padded(pad, f)
    }

    pub fn card_padded<R>(&mut self, pad: f32, f: impl FnOnce(&mut Ui) -> R) -> R {
        let id = self.make_id("card");
        let avail = self.available_rect();
        let prev_h = self.heights.get(&id).copied();
        if let Some(h) = prev_h {
            self.paint_card(Rect::new(avail.x, avail.y, avail.w, h));
        }
        let sp = self.theme.spacing;
        let inner = Rect::new(avail.x + pad, avail.y + pad, (avail.w - 2.0 * pad).max(0.0), 1e7);
        let (r, l) = self.run_child(Layout::new(inner, Dir::Down, sp, 0.0), f);
        let h = l.used_main() + 2.0 * pad;
        if prev_h.map_or(true, |p| (p - h).abs() > 0.5) {
            self.heights.insert(id, h);
            self.request_repaint();
        }
        self.allocate(None, h);
        r
    }

    /// Vertically scrolling region. `height = None` fills the remaining height.
    pub fn scroll_area<R>(&mut self, id_src: &str, height: Option<f32>, f: impl FnOnce(&mut Ui) -> R) -> R {
        let id = self.make_id(("scroll", id_src));
        let avail = self.available_rect();
        let h = height.unwrap_or(avail.h.min(1e6)).max(20.0);
        let rect = self.allocate(None, h);
        let mut st = self.scroll_state.get(&id).copied().unwrap_or_default();
        let bar = 8.0;
        let has_bar = st.content > rect.h + 0.5;
        let content_w = rect.w - if has_bar { bar + 6.0 } else { 0.0 };
        self.canvas.push_clip(rect);
        let sp = self.theme.spacing;
        let (r, l) = self.run_child(Layout::new(Rect::new(rect.x, rect.y - st.offset, content_w, 1e7), Dir::Down, sp, 0.0), f);
        self.canvas.pop_clip();
        let content = l.used_main();
        let max_off = (content - rect.h).max(0.0);
        let old = st;
        if self.mouse_over(rect) && self.scroll.1 != 0.0 {
            st.offset -= self.scroll.1 * 48.0;
            self.scroll.1 = 0.0;
        }
        if content > rect.h + 0.5 {
            let track = Rect::new(rect.right() - bar - 1.0, rect.y + 2.0, bar, rect.h - 4.0);
            let thumb_h = (track.h * rect.h / content).max(28.0).min(track.h);
            let ty = track.y + (track.h - thumb_h) * if max_off > 0.0 { st.offset.clamp(0.0, max_off) / max_off } else { 0.0 };
            let thumb = Rect::new(track.x, ty, bar, thumb_h);
            let tid = hash_of(id, "thumb");
            let tr = self.interact(track, tid, true);
            if tr.pressed {
                let g = if thumb.contains(self.mouse.0, self.mouse.1) { self.mouse.1 - thumb.y } else { thumb_h * 0.5 };
                st.grab = Some(g);
            }
            if tr.active {
                if let Some(g) = st.grab {
                    let frac = ((self.mouse.1 - g - track.y) / (track.h - thumb_h).max(1.0)).clamp(0.0, 1.0);
                    st.offset = frac * max_off;
                }
            } else {
                st.grab = None;
            }
            let c = if tr.active { Color::hex(0x94A3B8) } else if tr.hovered { Color::hex(0xA8B3C2) } else { Color::hex(0xCBD5E1) };
            self.canvas.fill_rounded_rect(Rect::new(thumb.x, ty, bar, thumb_h), bar * 0.5, c);
        }
        st.offset = st.offset.clamp(0.0, max_off);
        st.content = content;
        if (st.offset - old.offset).abs() > 0.01 || (st.content - old.content).abs() > 0.5 {
            self.request_repaint();
        }
        self.scroll_state.insert(id, st);
        r
    }

    /// Scroll a scroll area back to the top.
    pub fn scroll_to_top(&mut self, id_src: &str) {
        let id = hash_of(self.parent_id(), ("scroll", id_src));
        if let Some(s) = self.scroll_state.get_mut(&id) {
            s.offset = 0.0;
        }
    }

    /// Modal dialog. Call it *after* the rest of the frame's widgets so it
    /// paints on top. Everything underneath is blocked while it is shown.
    pub fn modal(&mut self, id_src: &str, title: &str, width: f32, f: impl FnOnce(&mut Ui)) -> ModalResponse {
        let id = self.make_id(("modal", id_src));
        self.layer += 1;
        let layer = self.layer;
        let (sw, sh) = self.size;
        self.block_cur.push((layer, Rect::new(0.0, 0.0, sw, sh)));
        self.canvas.reset_clip();
        self.canvas.fill_rect(Rect::new(0.0, 0.0, sw, sh), Color::rgba(15, 23, 42, 100));
        let prev_h = self.heights.get(&id).copied();
        let h = prev_h.unwrap_or(200.0).min(sh - 32.0);
        let w = width.min(sw - 32.0);
        let r = Rect::new(((sw - w) * 0.5).round(), ((sh - h) * 0.5).max(16.0).round(), w, h);
        let mut out = ModalResponse::default();
        if prev_h.is_some() {
            self.canvas.shadow(r.translate(0.0, 8.0), 14.0, 24.0, Color::rgba(15, 23, 42, 70));
            self.canvas.fill_rounded_rect(r, 14.0, self.theme.surface);
        }
        let tc = self.theme.text;
        self.paint_text(r.x + 24.0, r.y + 22.0, title, 17.0, tc, true);
        let saved = std::mem::take(&mut self.layouts);
        self.layouts.push(Layout::new(Rect::new(r.right() - 48.0, r.y + 16.0, 32.0, 32.0), Dir::Down, 0.0, 0.0));
        if self.icon_button(Icon::Close).clicked {
            out.close_requested = true;
        }
        self.layouts.clear();
        let sp = self.theme.spacing;
        self.layouts.push(Layout::new(Rect::new(r.x + 24.0, r.y + 64.0, w - 48.0, 1e7), Dir::Down, sp, 0.0));
        self.canvas.push_clip(r);
        f(self);
        self.canvas.pop_clip();
        let l = self.layouts.pop().unwrap();
        self.layouts = saved;
        let nh = 64.0 + l.used_main() + 24.0;
        if prev_h.map_or(true, |p| (p - nh).abs() > 0.5) {
            self.heights.insert(id, nh);
            self.request_repaint();
        }
        if self.keys.iter().any(|(k, _)| *k == Key::Escape) && self.open_popup.is_none() {
            out.close_requested = true;
        }
        self.layer -= 1;
        out
    }

    // ------------------------------------------------------------------ toasts

    /// Show a transient notification in the bottom-right corner (4 s).
    pub fn toast(&mut self, tone: Tone, text: &str) {
        self.toast_for(tone, text, Duration::from_secs(4));
    }

    pub fn toast_for(&mut self, tone: Tone, text: &str, d: Duration) {
        let until = Instant::now() + d;
        self.toasts.push(Toast { tone, text: text.to_string(), until });
        if self.toasts.len() > 4 {
            self.toasts.remove(0);
        }
        self.request_repaint();
    }

    fn paint_toasts(&mut self) {
        if self.toasts.is_empty() {
            return;
        }
        let (sw, sh) = self.size;
        let mut y = sh - 20.0;
        let now = self.now;
        let mut next: Option<Instant> = None;
        for i in (0..self.toasts.len()).rev() {
            let (tone, text, until) = (self.toasts[i].tone, self.toasts[i].text.clone(), self.toasts[i].until);
            let size = 13.5;
            let font = &self.fonts.regular;
            let maxw = 380.0f32.min(sw - 40.0);
            let lines = wrap_text(font, &text, size, maxw - 60.0);
            let lh = font.line_height(size);
            let h = lines.len() as f32 * lh + 26.0;
            let w = (lines.iter().map(|l| font.measure(l, size)).fold(0.0, f32::max) + 64.0).min(maxw);
            y -= h;
            let left = until.saturating_duration_since(now).as_secs_f32();
            let alpha = (left / 0.3).min(1.0);
            let r = Rect::new(sw - 20.0 - w, y, w, h);
            self.canvas.shadow(r.translate(0.0, 4.0), 10.0, 14.0, Color::rgba(15, 23, 42, (60.0 * alpha) as u8));
            self.canvas.fill_rounded_rect(r, 10.0, Color::hex(0x1E293B).fade(alpha));
            let (_, fg) = tone_colors(&self.theme, tone);
            let ic = match tone {
                Tone::Success => (Icon::Success, Color::hex(0x4ADE80)),
                Tone::Danger => (Icon::Error, Color::hex(0xF87171)),
                Tone::Warning => (Icon::Warning, Color::hex(0xFBBF24)),
                _ => (Icon::Info, Color::hex(0x93C5FD)),
            };
            let _ = fg;
            draw_icon(&mut self.canvas, ic.0, r.x + 14.0, r.y + 13.0 + (lh - 18.0) * 0.5, 18.0, ic.1.fade(alpha));
            let th = self.fonts.regular.text_height(size);
            for (j, l) in lines.iter().enumerate() {
                let ly = r.y + 13.0 + j as f32 * lh + (lh - th) * 0.5;
                self.fonts.regular.draw(&mut self.canvas, r.x + 42.0, ly, size, l, Color::WHITE.fade(alpha));
            }
            y -= 10.0;
            let fade_start = until - Duration::from_millis(300);
            let wake = if now < fade_start { fade_start } else { now + Duration::from_millis(16) };
            next = Some(next.map_or(wake, |n: Instant| n.min(wake)));
        }
        if let Some(n) = next {
            self.request_repaint_after(n.saturating_duration_since(Instant::now()));
        }
    }
}

fn tone_colors(t: &Theme, tone: Tone) -> (Color, Color) {
    match tone {
        Tone::Neutral => (Color::hex(0xF1F5F9), Color::hex(0x475569)),
        Tone::Info => (Color::hex(0xDBEAFE), Color::hex(0x1D4ED8)),
        Tone::Success => (Color::hex(0xDCFCE7), Color::hex(0x15803D)),
        Tone::Warning => (Color::hex(0xFEF3C7), Color::hex(0xB45309)),
        Tone::Danger => (Color::hex(0xFEE2E2), t.danger_hover),
    }
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn word_left(s: &str, cursor: usize) -> usize {
    let cs: Vec<char> = s.chars().collect();
    let mut i = cursor.min(cs.len());
    while i > 0 && !is_word(cs[i - 1]) {
        i -= 1;
    }
    while i > 0 && is_word(cs[i - 1]) {
        i -= 1;
    }
    i
}

fn word_right(s: &str, cursor: usize) -> usize {
    let cs: Vec<char> = s.chars().collect();
    let mut i = cursor;
    while i < cs.len() && !is_word(cs[i]) {
        i += 1;
    }
    while i < cs.len() && is_word(cs[i]) {
        i += 1;
    }
    i
}

/// Greedy word wrap.
pub fn wrap_text(font: &Font, text: &str, size: f32, width: f32) -> Vec<String> {
    let mut out = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split(' ') {
            let cand = if line.is_empty() { word.to_string() } else { format!("{line} {word}") };
            if font.measure(&cand, size) <= width || line.is_empty() {
                line = cand;
                // hard-break a single over-long word
                while font.measure(&line, size) > width && line.chars().count() > 1 {
                    let pos = font.caret_positions(&line, size);
                    let cut = pos.iter().rposition(|&p| p <= width).unwrap_or(1).max(1);
                    let head: String = line.chars().take(cut).collect();
                    let tail: String = line.chars().skip(cut).collect();
                    out.push(head);
                    line = tail;
                }
            } else {
                out.push(std::mem::take(&mut line));
                line = word.to_string();
            }
        }
        out.push(line);
    }
    out
}

/// Text ellipsised to `width`.
pub fn ellipsize(font: &Font, text: &str, size: f32, width: f32) -> String {
    if font.measure(text, size) <= width {
        return text.to_string();
    }
    let ell = font.measure("…", size);
    let pos = font.caret_positions(text, size);
    let n = pos.iter().rposition(|&p| p + ell <= width).unwrap_or(0);
    let mut s: String = text.chars().take(n).collect();
    s.push('…');
    s
}

/// Paint single-line text vertically centred in `r` (ellipsised).
pub fn paint_text_in(c: &mut Canvas, fonts: &Fonts, r: Rect, text: &str, size: f32, color: Color, bold: bool, center: bool) {
    let font = fonts.get(bold);
    let s = ellipsize(font, text, size, r.w.max(0.0) + 0.5);
    let w = font.measure(&s, size);
    let x = if center { r.x + ((r.w - w) * 0.5).max(0.0) } else { r.x };
    let y = r.y + (r.h - font.text_height(size)) * 0.5;
    font.draw(c, x, y, size, &s, color);
}

/// Convenience event loop: opens a window and calls `frame` whenever
/// something changed. Returns when the window is closed (unless the frame
/// handles `ui.close_requested()` itself and doesn't call `ui.quit()` —
/// see `intercept_close`).
pub fn run<S>(opts: WindowOptions, theme: Theme, mut state: S, mut frame: impl FnMut(&mut Ui, &mut S)) -> std::io::Result<()> {
    run_ex(opts, theme, false, &mut state, &mut frame)
}

/// Like [`run`]; with `intercept_close = true` a close request only sets
/// `ui.close_requested()` and the app must call `ui.quit()` to exit.
pub fn run_ex<S>(
    opts: WindowOptions,
    theme: Theme,
    intercept_close: bool,
    state: &mut S,
    frame: &mut impl FnMut(&mut Ui, &mut S),
) -> std::io::Result<()> {
    let mut win = Window::with_options(&opts)?;
    let mut ui = Ui::new(theme);
    loop {
        let mut events = Vec::new();
        if let Some(e) = win.next_event(ui.wait_timeout()) {
            events.push(e);
        }
        while let Some(e) = win.next_event(Some(Duration::ZERO)) {
            events.push(e);
            if events.len() > 512 {
                break;
            }
        }
        if events.is_empty() && !ui.repaint_due() {
            continue;
        }
        let close = events.iter().any(|e| *e == Event::CloseRequested);
        ui.begin_frame(&mut win, events);
        frame(&mut ui, state);
        ui.end_frame(&mut win);
        if ui.should_quit() || (close && !intercept_close) {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::font::Font;
    use std::cell::Cell;

    fn ui() -> Ui {
        Ui::with_fonts(Theme::light(), Fonts { regular: Font::fallback(), bold: Font::fallback() })
    }

    /// Run one offscreen frame.
    fn frame(ui: &mut Ui, events: Vec<Event>, clip: Option<&str>, f: &mut dyn FnMut(&mut Ui)) -> Option<String> {
        let c = clip.map(|s| s.to_string());
        ui.begin_frame_raw((800, 600), 1.0, events, &mut || c.clone());
        f(ui);
        ui.end_frame_raw().1
    }

    fn click(x: f32, y: f32) -> Vec<Event> {
        vec![
            Event::MouseMove { x, y },
            Event::MouseDown { x, y, button: MouseButton::Left },
            Event::MouseUp { x, y, button: MouseButton::Left },
        ]
    }

    #[test]
    fn button_click_and_layout() {
        let mut ui = ui();
        let rect = Cell::new(Rect::default());
        let clicks = Cell::new(0);
        let mut build = |ui: &mut Ui| {
            ui.label("hello");
            let r = ui.button("Press me");
            rect.set(r.rect);
            if r.clicked {
                clicks.set(clicks.get() + 1);
            }
        };
        frame(&mut ui, vec![], None, &mut build);
        let r = rect.get();
        assert!(r.y > 10.0 && r.w > 40.0, "{r:?}");
        let (cx, cy) = r.center();
        frame(&mut ui, click(cx, cy), None, &mut build);
        assert_eq!(clicks.get(), 1);
        frame(&mut ui, click(700.0, 500.0), None, &mut build);
        assert_eq!(clicks.get(), 1);
    }

    #[test]
    fn text_input_typing_editing_and_clipboard() {
        let mut ui = ui();
        let value = std::cell::RefCell::new(String::from("ab"));
        let rect = Cell::new(Rect::default());
        let mut build = |ui: &mut Ui| {
            rect.set(ui.text_input("t", &mut value.borrow_mut(), &TextInputOptions::default()).rect);
        };
        frame(&mut ui, vec![], None, &mut build);
        let r = rect.get();
        let (cx, cy) = (r.right() - 5.0, r.center().1);
        frame(&mut ui, click(cx, cy), None, &mut build);
        frame(&mut ui, vec![Event::Text("cdé".into())], None, &mut build);
        assert_eq!(*value.borrow(), "abcdé");
        let k = |key, shift| Event::KeyDown { key, mods: Mods { shift, ..Default::default() } };
        frame(&mut ui, vec![k(Key::Left, false), k(Key::Backspace, false)], None, &mut build);
        assert_eq!(*value.borrow(), "abcé");
        let cmd = Mods { ctrl: !cfg!(target_os = "macos"), logo: cfg!(target_os = "macos"), ..Default::default() };
        let out = frame(
            &mut ui,
            vec![Event::KeyDown { key: Key::Char('a'), mods: cmd }, Event::KeyDown { key: Key::Char('c'), mods: cmd }],
            None,
            &mut build,
        );
        assert_eq!(out.as_deref(), Some("abcé"));
        frame(&mut ui, vec![Event::KeyDown { key: Key::Char('v'), mods: cmd }], Some("x\ny"), &mut build);
        assert_eq!(*value.borrow(), "x y");
        frame(&mut ui, vec![k(Key::Home, true), Event::Text("Z".into())], None, &mut build);
        assert_eq!(*value.borrow(), "Z");
        frame(&mut ui, click(700.0, 550.0), None, &mut build);
        frame(&mut ui, vec![Event::Text("q".into())], None, &mut build);
        assert_eq!(*value.borrow(), "Z");
    }

    #[test]
    fn modal_blocks_widgets_underneath() {
        let mut ui = ui();
        let rect = Cell::new(Rect::default());
        let clicks = Cell::new(0);
        let mut build = |ui: &mut Ui| {
            let r = ui.button("Under");
            rect.set(r.rect);
            if r.clicked {
                clicks.set(clicks.get() + 1);
            }
            ui.modal("m", "Dialog", 300.0, |ui| {
                ui.label("content");
            });
        };
        for _ in 0..2 {
            frame(&mut ui, vec![], None, &mut build);
        }
        let (cx, cy) = rect.get().center();
        frame(&mut ui, click(cx, cy), None, &mut build);
        assert_eq!(clicks.get(), 0);
    }

    #[test]
    fn select_picks_option() {
        let mut ui = ui();
        let sel = Cell::new(0usize);
        let rect = Cell::new(Rect::default());
        let opts = ["one", "two", "three"];
        let mut build = |ui: &mut Ui| {
            let mut s = sel.get();
            rect.set(ui.select("s", &mut s, &opts, Some(200.0)).rect);
            sel.set(s);
        };
        frame(&mut ui, vec![], None, &mut build);
        let r = rect.get();
        let (cx, cy) = r.center();
        frame(&mut ui, click(cx, cy), None, &mut build);
        frame(&mut ui, vec![], None, &mut build);
        let y = r.bottom() + 4.0 + 4.0 + 34.0 * 2.0 + 10.0;
        frame(&mut ui, click(cx, y), None, &mut build);
        assert_eq!(sel.get(), 2);
    }

    #[test]
    fn checkbox_and_scroll_area() {
        let mut ui = ui();
        let on = Cell::new(false);
        let cb = Cell::new(Rect::default());
        let last = Cell::new(Rect::default());
        let mut build = |ui: &mut Ui| {
            let mut v = on.get();
            cb.set(ui.checkbox(&mut v, "Enable").rect);
            on.set(v);
            ui.scroll_area("list", Some(100.0), |ui| {
                for i in 0..50 {
                    last.set(ui.label(&format!("item {i}")).rect);
                }
            });
        };
        frame(&mut ui, vec![], None, &mut build);
        let c = cb.get();
        frame(&mut ui, click(c.x + 5.0, c.center().1), None, &mut build);
        assert!(on.get());
        let before = last.get().y;
        frame(&mut ui, vec![Event::MouseMove { x: 50.0, y: 80.0 }, Event::Scroll { dx: 0.0, dy: -3.0 }], None, &mut build);
        frame(&mut ui, vec![], None, &mut build);
        assert!(last.get().y < before - 100.0, "scrolled: {before} -> {}", last.get().y);
    }

    #[test]
    fn wrap_and_ellipsis() {
        let f = Font::fallback();
        let lines = wrap_text(&f, "one two three four five six", 14.0, 60.0);
        assert!(lines.len() > 2);
        for l in &lines {
            assert!(f.measure(l, 14.0) <= 60.0 + 0.01 || !l.contains(' '));
        }
        let e = ellipsize(&f, "a very long piece of text", 14.0, 50.0);
        assert!(e.ends_with('…') && f.measure(&e, 14.0) <= 50.5);
    }
}

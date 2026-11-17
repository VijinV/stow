//! Platform-independent input events. All coordinates are in *physical* pixels.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// Modifier keys held at the time of the event (after the event's own change).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mods {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    /// Windows key / Command key.
    pub logo: bool,
}

impl Mods {
    /// The platform "command" modifier: Cmd on macOS, Ctrl elsewhere.
    pub fn command(&self) -> bool {
        if cfg!(target_os = "macos") {
            self.logo
        } else {
            self.ctrl
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Backspace,
    Delete,
    Enter,
    Tab,
    Escape,
    Space,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    F(u8),
    /// A character key, lower-case / unshifted (e.g. `Char('a')` for A).
    Char(char),
    /// Modifier keys and anything unmapped.
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorIcon {
    Arrow,
    Hand,
    Text,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    MouseMove { x: f32, y: f32 },
    MouseDown { x: f32, y: f32, button: MouseButton },
    MouseUp { x: f32, y: f32, button: MouseButton },
    /// The pointer left the window.
    MouseLeft,
    /// Positive `dy` = wheel up (scroll content towards the top). Units: wheel "lines".
    Scroll { dx: f32, dy: f32 },
    KeyDown { key: Key, mods: Mods },
    KeyUp { key: Key, mods: Mods },
    /// Typed text (already shifted / composed). Never contains control characters.
    Text(String),
    /// New physical size of the drawable area.
    Resized { w: u32, h: u32 },
    ScaleChanged(f32),
    CloseRequested,
    Focus(bool),
    /// The OS asks for the window contents to be redrawn.
    Redraw,
}

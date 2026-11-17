//! From-scratch windowing + software-rendered immediate-mode GUI.
//!
//! No third-party crates: the platform layers talk to the OS directly
//! (X11 wire protocol over a socket on Linux, Win32 via FFI on Windows,
//! the Objective-C runtime + CoreGraphics on macOS). Everything is drawn
//! by the CPU into a [`Canvas`] and blitted to the window.
//!
//! See `API.md` for a guide.

pub mod canvas;
pub mod event;
pub mod folder_browser;
pub mod font;
pub mod icons;
pub mod platform;
pub mod ui;

pub use canvas::{Canvas, Color, Rect};
pub use event::{CursorIcon, Event, Key, Mods, MouseButton};
pub use folder_browser::{FolderBrowser, FolderBrowserResult};
pub use font::{Font, Fonts};
pub use icons::Icon;
pub use platform::{native_folder_picker_available, open_path, open_url, pick_folder, Window, WindowOptions};
pub use ui::*;

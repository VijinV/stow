//! Native window backends.
use crate::canvas::Canvas;
use crate::event::{CursorIcon, Event};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as imp;
#[cfg(target_os = "windows")]
mod win32;
#[cfg(target_os = "windows")]
use win32 as imp;
#[cfg(all(unix, not(target_os = "macos")))]
mod x11;
#[cfg(all(unix, not(target_os = "macos")))]
use x11 as imp;

#[derive(Clone, Debug)]
pub struct WindowOptions {
    pub title: String,
    /// Initial logical size.
    pub width: u32,
    pub height: u32,
    /// Minimum logical size.
    pub min_width: u32,
    pub min_height: u32,
    /// Application id (X11 WM_CLASS, Windows class name).
    pub app_id: String,
    /// Optional window icon: (width, height, 0xAARRGGBB pixels).
    pub icon: Option<(u32, u32, Vec<u32>)>,
}

impl Default for WindowOptions {
    fn default() -> Self {
        WindowOptions {
            title: "App".into(),
            width: 960,
            height: 640,
            min_width: 480,
            min_height: 360,
            app_id: "bt-gui".into(),
            icon: None,
        }
    }
}

/// A native top-level window that displays a [`Canvas`].
pub struct Window {
    inner: imp::Window,
}

impl Window {
    pub fn new(title: &str, width: u32, height: u32) -> std::io::Result<Window> {
        Self::with_options(&WindowOptions { title: title.into(), width, height, ..Default::default() })
    }
    pub fn with_options(opts: &WindowOptions) -> std::io::Result<Window> {
        Ok(Window { inner: imp::Window::new(opts)? })
    }
    /// Next event, waiting at most `timeout` (`None` = wait forever, `Some(ZERO)` = poll).
    pub fn next_event(&mut self, timeout: Option<Duration>) -> Option<Event> {
        self.inner.next_event(timeout)
    }
    /// Show the canvas (physical pixels).
    pub fn present(&mut self, canvas: &Canvas) {
        self.inner.present(canvas)
    }
    pub fn physical_size(&self) -> (u32, u32) {
        self.inner.physical_size()
    }
    pub fn scale_factor(&self) -> f32 {
        self.inner.scale_factor()
    }
    pub fn set_title(&mut self, title: &str) {
        self.inner.set_title(title)
    }
    pub fn set_cursor(&mut self, c: CursorIcon) {
        self.inner.set_cursor(c)
    }
    pub fn clipboard_get(&mut self) -> Option<String> {
        self.inner.clipboard_get()
    }
    pub fn clipboard_set(&mut self, text: &str) {
        self.inner.clipboard_set(text)
    }
}

/// Native "choose folder" dialog. Returns `None` when cancelled *or* when no
/// native dialog is available (Linux without zenity/kdialog) — use
/// [`crate::FolderBrowser`] as the in-app fallback, see [`native_folder_picker_available`].
pub fn pick_folder(title: &str) -> Option<PathBuf> {
    imp::pick_folder(title)
}

/// Whether [`pick_folder`] can show a native dialog on this system.
pub fn native_folder_picker_available() -> bool {
    imp::native_folder_picker_available()
}

pub fn open_url(url: &str) {
    imp::open(url)
}

pub fn open_path(path: &Path) {
    imp::open(&path.to_string_lossy())
}

/// Scale override for testing: `BT_GUI_SCALE=2`.
pub(crate) fn env_scale() -> Option<f32> {
    std::env::var("BT_GUI_SCALE").ok()?.parse().ok().filter(|s: &f32| *s >= 0.5 && *s <= 4.0)
}

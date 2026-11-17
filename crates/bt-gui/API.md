# bt-gui — API guide

A zero-dependency, software-rendered, immediate-mode GUI. Platform layers:

| OS | Backend | Status |
|---|---|---|
| Linux / BSD | X11 wire protocol over `/tmp/.X11-unix/X<n>` (or TCP), no libX11 | run & tested (Xvnc) |
| Windows | Win32 via `user32/gdi32/kernel32/shell32/ole32` FFI | run & tested under Wine 10 |
| macOS | Objective-C runtime + AppKit + CoreGraphics FFI | type-checked only (`aarch64`/`x86_64-apple-darwin`) |

Wayland-only Linux sessions work through XWayland (present on all mainstream desktops).

## Minimal app

```rust
use bt_gui::*;

struct App { name: String, on: bool, region: usize }

fn main() -> std::io::Result<()> {
    let opts = WindowOptions {
        title: "Backup Taker".into(), width: 1000, height: 680,
        min_width: 760, min_height: 520, app_id: "backup-taker".into(),
        icon: None, // Some((w, h, argb_pixels)) sets the window icon (X11 + Windows)
    };
    let app = App { name: String::new(), on: false, region: 0 };
    run(opts, Theme::light(), app, |ui, app| {
        ui.with_rect(Rect::new(0.0, 0.0, ui.screen_size().0, ui.screen_size().1).shrink(24.0), |ui| {
            ui.heading("Hello");
            ui.card(|ui| {
                ui.field_label("Name");
                ui.text_input("name", &mut app.name, &TextInputOptions { placeholder: "Your name", ..Default::default() });
                ui.checkbox(&mut app.on, "Enabled");
                ui.select("region", &mut app.region, &["us-east-1", "eu-west-1"], Some(240.0));
                if ui.primary_button("Save").clicked { ui.toast(Tone::Success, "Saved"); }
            });
        });
    })
}
```

`run` redraws only when there is input, a timer you requested, or an animation
— idle CPU is zero. Use `run_ex(opts, theme, true, &mut state, &mut frame)` to
intercept the close button (`ui.close_requested()` then `ui.quit()`).

### Background work / live progress
The loop sleeps when idle. While something changes outside the UI (e.g. a
backup thread), call `ui.request_repaint_after(Duration::from_millis(200))`
each frame; the frame fn then re-reads shared state (`Arc<Mutex<..>>`).

### Manual loop
```rust
let mut win = Window::with_options(&opts)?;
let mut ui = Ui::new(Theme::light());
loop {
    let mut evs = Vec::new();
    if let Some(e) = win.next_event(ui.wait_timeout()) { evs.push(e); }
    while let Some(e) = win.next_event(Some(Duration::ZERO)) { evs.push(e); }
    if evs.is_empty() && !ui.repaint_due() { continue; }
    let close = evs.contains(&Event::CloseRequested);
    ui.begin_frame(&mut win, evs);
    /* widgets */
    ui.end_frame(&mut win);
    if close { break; }
}
```
`begin_frame_raw` / `end_frame_raw` do the same without a window (tests,
offscreen PPM snapshots via `ui.canvas.to_ppm()`).

## Layout
All coordinates are logical pixels (the canvas multiplies by the DPI scale).

- The root layout is the whole window, vertical. Each widget *allocates* space
  in the current layout; vertical layouts give widgets the full width unless
  the widget has a natural width (buttons, labels, badges).
- `ui.with_rect(rect, |ui| ..)` — absolute region (sidebar, content pane).
- `ui.horizontal(|ui| ..)` — row of height `theme.control_height` (36);
  `ui.horizontal_sized(h, ..)` for other heights. Items are vertically centred.
- `ui.right_to_left(|ui| ..)` — row filled from the right (dialog buttons; call
  order = right to left).
- `ui.vertical(Some(w), |ui| ..)` — column inside a row (centred in the row).
- `ui.columns(n, |ui, i| ..)` — equal columns.
- `ui.padded(p, ..)`, `ui.space(px)`, `ui.set_spacing(px)`,
  `ui.available_rect()`, `ui.available_width()`, `ui.allocate(Some(w)|None, h)`.
- Containers: `ui.card(|ui| ..)` (white panel, auto height),
  `ui.scroll_area("id", Some(h) | None /*fill*/, |ui| ..)` (wheel + draggable bar),
  `ui.modal("id", "Title", width, |ui| ..) -> ModalResponse { close_requested }`
  — call modals **after** the rest of the frame; they block input underneath.
- In loops wrap items with `ui.with_id(key, |ui| ..)` so ids stay unique.

## Widgets (all return `Response { rect, hovered, pressed, active, clicked, double_clicked, secondary_clicked, changed, submitted, focused }`)

| Call | Notes |
|---|---|
| `label`, `label_muted`, `label_wrapped`, `small`, `heading`, `subheading`, `field_label`, `text(s, TextStyle::body().size(13.0).bold().color(c).wrap())` | single-line labels ellipsise |
| `button`, `primary_button`, `danger_button`, `button_ex(text, ButtonKind::{Primary,Secondary,Danger,Ghost}, Some(Icon::Plus), enabled)` | |
| `icon_button(Icon::Trash)`, `icon_button_ex(icon, size, color)`, `link(text)`, `tooltip(&resp, text)` | |
| `text_input("id", &mut String, &TextInputOptions { placeholder, password, width, enabled, icon })` | caret, mouse/shift selection, double-click select-all, Ctrl/Cmd+A/C/X/V, word jumps (Ctrl/Alt+arrows), Home/End, Tab/Shift+Tab focus cycling, Enter → `submitted`, Esc unfocus; passwords show `•` and refuse copy |
| `focus_text_input("id")` | focus programmatically |
| `checkbox(&mut bool, label)`, `toggle(&mut bool, label)`, `segmented(&mut usize, &[..])` | |
| `select("id", &mut usize, &[&str], width)` | popup overlay with scrolling, Esc closes |
| `number_stepper("id", &mut i64, min, max, step, suffix)` | |
| `progress_bar(Some(0.4) /* or None = animated */, height)` | |
| `badge(text, Tone::{Neutral,Info,Success,Warning,Danger})`, `callout(tone, text)`, `separator()`, `icon(Icon, size, color)` | |
| `nav_item(Icon, label, selected)` | sidebar entry |
| `list_item(Some(icon), title, Some(subtitle), selected)` | |
| `row(key, height, selected, |ui| ..)` | clickable row hosting a horizontal layout of child widgets (child buttons win clicks) |
| `toast(Tone, text)` / `toast_for(tone, text, dur)` | bottom-right, auto-dismiss |

Painting helpers for custom widgets: `ui.interact(rect, id, enabled)`,
`ui.make_id(src)`, `ui.paint_text(x, y, s, size, color, bold)`,
`ui.paint_text_in(rect, ..)`, `ui.paint_text_centered(rect, ..)`,
`ui.paint_icon(icon, x, y, size, color)`, `ui.paint_card(rect)`,
`ui.paint_overlay(|canvas, fonts, theme| ..)`, and the raw `ui.canvas`
(`fill_rect`, `fill_rounded_rect`, `stroke_rounded_rect`, `shadow`,
`fill_circle`, `stroke_circle`, `line`, `polyline`, `push_clip`/`pop_clip`).
Keyboard shortcuts: `ui.keys_pressed()`, `ui.key_pressed(Key::Escape)`,
`ui.has_focus()` (skip shortcuts while typing). `ui.copy_to_clipboard(text)`.

Icons (`Icon::`): Check, Close, Plus, Minus, Chevron{Down,Up,Left,Right}, Folder,
File, Trash, Cloud, Upload, Download, Gear, Warning, Info, Error, Success,
Refresh, Clock, Home, Drive, Play, Stop, Pause, Key, Search, ArrowUp, ArrowLeft,
Eye, Server, Menu, Calendar, Shield, Edit.

## Folder picking
```rust
if native_folder_picker_available() {           // Windows/macOS always; Linux if zenity/kdialog exists
    if let Some(p) = pick_folder("Choose a folder") { .. }   // blocks while the dialog is open
} else {
    state.browser = Some(FolderBrowser::new("Choose a folder", None));
}
// every frame, after other widgets:
if let Some(b) = &mut state.browser {
    match b.show(ui) {
        FolderBrowserResult::Open => {}
        FolderBrowserResult::Cancelled => state.browser = None,
        FolderBrowserResult::Selected(p) => { /* use p */ state.browser = None; }
    }
}
```
`FolderBrowser` has places (Home, Desktop, Documents, Downloads, drives / `/`),
an editable path, Up, double-click to enter, hidden-folder toggle.

`open_url(url)` / `open_path(path)` open in the default browser / file manager.

## Fonts
`Fonts::load_system()` (done by `Ui::new`) picks: Linux — Inter/Noto Sans/
Ubuntu/Open Sans/Liberation Sans/DejaVu Sans (searched under
`/usr/share/fonts`, `~/.local/share/fonts`, …); Windows — Segoe UI (+ Semibold),
Arial, Tahoma; macOS — Helvetica Neue / Helvetica `.ttc`, Arial, Geneva.
TrueType outlines only (CFF `.otf` is skipped). Without any usable font a
built-in 5×7 bitmap font is used (ASCII only).

## Environment
- `BT_GUI_SCALE=1.5` — force the UI scale (otherwise Xft.dpi on X11, per-monitor DPI on Windows, backingScaleFactor on macOS).
- `BT_GUI_DEBUG=1` — print X11 protocol errors.

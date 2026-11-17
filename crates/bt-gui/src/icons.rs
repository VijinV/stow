//! Procedural line icons drawn on a 24x24 design grid.
use crate::canvas::{Canvas, Color};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Icon {
    Check,
    Close,
    Plus,
    Minus,
    ChevronDown,
    ChevronUp,
    ChevronLeft,
    ChevronRight,
    Folder,
    File,
    Trash,
    Cloud,
    Upload,
    Download,
    Gear,
    Warning,
    Info,
    Error,
    Success,
    Refresh,
    Clock,
    Home,
    Drive,
    Play,
    Stop,
    Pause,
    Key,
    Search,
    ArrowUp,
    ArrowLeft,
    Eye,
    Server,
    Menu,
    Calendar,
    Shield,
    Edit,
}

fn arc(cx: f32, cy: f32, r: f32, a0: f32, a1: f32) -> Vec<(f32, f32)> {
    let n = (((a1 - a0).abs() / 12.0).ceil() as usize).max(2);
    (0..=n)
        .map(|i| {
            let a = (a0 + (a1 - a0) * i as f32 / n as f32).to_radians();
            (cx + r * a.cos(), cy + r * a.sin())
        })
        .collect()
}

/// Draw `icon` centred in a square of `size` logical px at (x, y) top-left.
pub fn draw_icon(c: &mut Canvas, icon: Icon, x: f32, y: f32, size: f32, color: Color) {
    let k = size / 24.0;
    let sw = (1.9 * k).max(1.2);
    let p = |px: f32, py: f32| (x + px * k, y + py * k);
    let pl = |c: &mut Canvas, pts: &[(f32, f32)], closed: bool| {
        let v: Vec<(f32, f32)> = pts.iter().map(|&(a, b)| p(a, b)).collect();
        c.polyline(&v, closed, sw, color);
    };
    let ln = |c: &mut Canvas, a: f32, b: f32, cc: f32, d: f32| {
        let (x0, y0) = p(a, b);
        let (x1, y1) = p(cc, d);
        c.line(x0, y0, x1, y1, sw, color);
    };
    let circ = |c: &mut Canvas, cx: f32, cy: f32, r: f32| {
        let (px, py) = p(cx, cy);
        c.stroke_circle(px, py, r * k, sw, color);
    };
    let dot = |c: &mut Canvas, cx: f32, cy: f32| {
        let (px, py) = p(cx, cy);
        c.fill_circle(px, py, sw * 0.65, color);
    };
    let arcp = |c: &mut Canvas, cx: f32, cy: f32, r: f32, a0: f32, a1: f32| {
        let v: Vec<(f32, f32)> = arc(cx, cy, r, a0, a1).into_iter().map(|(a, b)| p(a, b)).collect();
        c.polyline(&v, false, sw, color);
    };
    match icon {
        Icon::Check => pl(c, &[(5.0, 12.5), (10.0, 17.5), (19.0, 7.0)], false),
        Icon::Close => {
            ln(c, 6.0, 6.0, 18.0, 18.0);
            ln(c, 18.0, 6.0, 6.0, 18.0);
        }
        Icon::Plus => {
            ln(c, 12.0, 5.0, 12.0, 19.0);
            ln(c, 5.0, 12.0, 19.0, 12.0);
        }
        Icon::Minus => ln(c, 5.0, 12.0, 19.0, 12.0),
        Icon::ChevronDown => pl(c, &[(6.0, 9.0), (12.0, 15.0), (18.0, 9.0)], false),
        Icon::ChevronUp => pl(c, &[(6.0, 15.0), (12.0, 9.0), (18.0, 15.0)], false),
        Icon::ChevronLeft => pl(c, &[(15.0, 6.0), (9.0, 12.0), (15.0, 18.0)], false),
        Icon::ChevronRight => pl(c, &[(9.0, 6.0), (15.0, 12.0), (9.0, 18.0)], false),
        Icon::Folder => pl(c, &[(3.0, 6.0), (9.5, 6.0), (11.5, 8.5), (21.0, 8.5), (21.0, 19.0), (3.0, 19.0)], true),
        Icon::File => {
            pl(c, &[(6.0, 3.0), (14.0, 3.0), (19.0, 8.0), (19.0, 21.0), (6.0, 21.0)], true);
            pl(c, &[(14.0, 3.0), (14.0, 8.0), (19.0, 8.0)], false);
        }
        Icon::Trash => {
            ln(c, 4.0, 6.5, 20.0, 6.5);
            pl(c, &[(9.0, 6.5), (9.0, 3.5), (15.0, 3.5), (15.0, 6.5)], false);
            pl(c, &[(6.0, 6.5), (7.0, 20.5), (17.0, 20.5), (18.0, 6.5)], false);
            ln(c, 10.0, 10.5, 10.0, 16.5);
            ln(c, 14.0, 10.5, 14.0, 16.5);
        }
        Icon::Cloud => {
            arcp(c, 7.5, 14.5, 4.0, 90.0, 250.0);
            arcp(c, 13.0, 11.0, 5.5, 205.0, 335.0);
            arcp(c, 17.5, 15.0, 3.5, 285.0, 450.0);
            ln(c, 7.5, 18.5, 17.5, 18.5);
        }
        Icon::Upload => {
            ln(c, 12.0, 15.0, 12.0, 4.0);
            pl(c, &[(7.0, 9.0), (12.0, 4.0), (17.0, 9.0)], false);
            pl(c, &[(4.0, 15.0), (4.0, 20.0), (20.0, 20.0), (20.0, 15.0)], false);
        }
        Icon::Download => {
            ln(c, 12.0, 4.0, 12.0, 15.0);
            pl(c, &[(7.0, 10.0), (12.0, 15.0), (17.0, 10.0)], false);
            pl(c, &[(4.0, 15.0), (4.0, 20.0), (20.0, 20.0), (20.0, 15.0)], false);
        }
        Icon::Gear => {
            circ(c, 12.0, 12.0, 3.0);
            circ(c, 12.0, 12.0, 7.0);
            for i in 0..8 {
                let a = (i as f32 * 45.0).to_radians();
                ln(c, 12.0 + 7.0 * a.cos(), 12.0 + 7.0 * a.sin(), 12.0 + 9.5 * a.cos(), 12.0 + 9.5 * a.sin());
            }
        }
        Icon::Warning => {
            pl(c, &[(12.0, 3.5), (21.5, 20.0), (2.5, 20.0)], true);
            ln(c, 12.0, 9.5, 12.0, 14.0);
            dot(c, 12.0, 17.0);
        }
        Icon::Info => {
            circ(c, 12.0, 12.0, 9.0);
            ln(c, 12.0, 11.0, 12.0, 16.5);
            dot(c, 12.0, 7.8);
        }
        Icon::Error => {
            circ(c, 12.0, 12.0, 9.0);
            ln(c, 9.0, 9.0, 15.0, 15.0);
            ln(c, 15.0, 9.0, 9.0, 15.0);
        }
        Icon::Success => {
            circ(c, 12.0, 12.0, 9.0);
            pl(c, &[(8.0, 12.5), (11.0, 15.5), (16.0, 9.5)], false);
        }
        Icon::Refresh => {
            arcp(c, 12.0, 12.0, 8.0, 30.0, 320.0);
            // arrow head at the 320° end, pointing along the arc direction
            let a = 320f32.to_radians();
            let (ex, ey) = (12.0 + 8.0 * a.cos(), 12.0 + 8.0 * a.sin());
            pl(c, &[(ex - 4.5, ey - 0.5), (ex, ey), (ex + 0.5, ey + 4.5)], false);
        }
        Icon::Clock => {
            circ(c, 12.0, 12.0, 9.0);
            pl(c, &[(12.0, 7.0), (12.0, 12.0), (15.5, 14.0)], false);
        }
        Icon::Home => {
            pl(c, &[(3.0, 11.0), (12.0, 3.5), (21.0, 11.0)], false);
            pl(c, &[(5.5, 9.0), (5.5, 20.5), (18.5, 20.5), (18.5, 9.0)], false);
        }
        Icon::Drive => {
            pl(c, &[(3.0, 13.0), (21.0, 13.0), (21.0, 20.0), (3.0, 20.0)], true);
            pl(c, &[(3.0, 13.0), (6.0, 5.0), (18.0, 5.0), (21.0, 13.0)], false);
            dot(c, 17.0, 16.5);
        }
        Icon::Play => pl(c, &[(8.0, 5.0), (19.0, 12.0), (8.0, 19.0)], true),
        Icon::Stop => pl(c, &[(6.5, 6.5), (17.5, 6.5), (17.5, 17.5), (6.5, 17.5)], true),
        Icon::Pause => {
            ln(c, 9.0, 6.0, 9.0, 18.0);
            ln(c, 15.0, 6.0, 15.0, 18.0);
        }
        Icon::Key => {
            circ(c, 8.0, 16.0, 4.0);
            ln(c, 11.0, 13.0, 20.0, 4.0);
            ln(c, 16.5, 7.5, 19.0, 10.0);
            ln(c, 14.5, 9.5, 16.5, 11.5);
        }
        Icon::Search => {
            circ(c, 10.5, 10.5, 6.5);
            ln(c, 15.5, 15.5, 20.5, 20.5);
        }
        Icon::ArrowUp => {
            ln(c, 12.0, 19.0, 12.0, 5.0);
            pl(c, &[(6.0, 11.0), (12.0, 5.0), (18.0, 11.0)], false);
        }
        Icon::ArrowLeft => {
            ln(c, 19.0, 12.0, 5.0, 12.0);
            pl(c, &[(11.0, 6.0), (5.0, 12.0), (11.0, 18.0)], false);
        }
        Icon::Eye => {
            arcp(c, 12.0, 20.0, 12.0, 215.0, 325.0);
            arcp(c, 12.0, 4.0, 12.0, 35.0, 145.0);
            circ(c, 12.0, 12.0, 3.0);
        }
        Icon::Server => {
            pl(c, &[(3.5, 4.0), (20.5, 4.0), (20.5, 10.5), (3.5, 10.5)], true);
            pl(c, &[(3.5, 13.5), (20.5, 13.5), (20.5, 20.0), (3.5, 20.0)], true);
            dot(c, 7.0, 7.25);
            dot(c, 7.0, 16.75);
        }
        Icon::Menu => {
            ln(c, 4.0, 7.0, 20.0, 7.0);
            ln(c, 4.0, 12.0, 20.0, 12.0);
            ln(c, 4.0, 17.0, 20.0, 17.0);
        }
        Icon::Calendar => {
            pl(c, &[(3.5, 5.5), (20.5, 5.5), (20.5, 20.5), (3.5, 20.5)], true);
            ln(c, 3.5, 10.0, 20.5, 10.0);
            ln(c, 8.0, 3.0, 8.0, 7.0);
            ln(c, 16.0, 3.0, 16.0, 7.0);
        }
        Icon::Shield => {
            pl(c, &[(12.0, 3.0), (19.5, 6.0), (19.0, 13.0), (12.0, 21.0), (5.0, 13.0), (4.5, 6.0)], true);
        }
        Icon::Edit => {
            pl(c, &[(15.0, 4.5), (19.5, 9.0), (8.5, 20.0), (4.0, 20.0), (4.0, 15.5)], true);
            ln(c, 12.5, 7.0, 17.0, 11.5);
        }
    }
}

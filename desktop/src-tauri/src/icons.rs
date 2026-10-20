//! Tray icons for the seven states (SRS FR-20.2), drawn at start-up so the
//! state is told by shape as well as color. The shapes are those of
//! `docs/design/visual.md` ("Tray states"), the same as the Gateway Status
//! window's: a filled square (healthy), a half-filled square (running, not
//! enforced), a diamond (degraded), a triangle
//! (fail-closed), a triangle with a bar under it (emergency stop), a hollow
//! square (stopped) and a ring (unreachable).

use crate::state::TrayState;

pub const SIZE: u32 = 36;

#[derive(Clone, Copy)]
struct Rgb(u8, u8, u8);

// Mid tones of the --ok, --warn, --bad and --ink-3 tokens that read on both
// light and dark menu bars.
const GREEN: Rgb = Rgb(0x2e, 0x8a, 0x5c);
const AMBER: Rgb = Rgb(0xc2, 0x8a, 0x1e);
const RED: Rgb = Rgb(0xc8, 0x3a, 0x5e);
const GREY: Rgb = Rgb(0x86, 0x8f, 0x89);

/// Coverage-tested shape: returns the color at a point in [-1, 1]², or None.
fn shade(state: TrayState, x: f64, y: f64) -> Option<Rgb> {
    let r = (x * x + y * y).sqrt();
    // Triangle pointing up with its apex at (0, top) and its base at y = base,
    // as wide as it is tall.
    let triangle = |top: f64, base: f64| y <= base && y >= top + 2.0 * x.abs();
    match state {
        TrayState::Healthy => (x.abs() <= 0.62 && y.abs() <= 0.62).then_some(GREEN),
        // Running, not enforced: a square, its left half filled. The
        // Gateway decides and records calls, but servers are not contained.
        TrayState::Running => {
            let outer = x.abs() <= 0.68 && y.abs() <= 0.68;
            let inner = x.abs() < 0.46 && y.abs() < 0.46;
            (outer && (!inner || x <= 0.0)).then_some(GREEN)
        }
        TrayState::Degraded => (x.abs() + y.abs() <= 0.85).then_some(AMBER),
        TrayState::FailClosed => triangle(-0.8, 0.75).then_some(RED),
        TrayState::EmergencyStop => {
            let bar = x.abs() <= 0.8 && (0.62..=0.85).contains(&y);
            (triangle(-0.85, 0.42) || bar).then_some(RED)
        }
        TrayState::Stopped => {
            let outer = x.abs() <= 0.68 && y.abs() <= 0.68;
            let inner = x.abs() < 0.4 && y.abs() < 0.4;
            (outer && !inner).then_some(GREY)
        }
        TrayState::Unreachable => (0.55..=0.8).contains(&r).then_some(GREY),
    }
}

/// The RGBA pixels of a state's icon, SIZE × SIZE, anti-aliased by 4×4
/// supersampling.
pub fn rgba(state: TrayState) -> Vec<u8> {
    let n = SIZE as usize;
    let mut out = vec![0u8; n * n * 4];
    for py in 0..n {
        for px in 0..n {
            let (mut r, mut g, mut b, mut hits) = (0u32, 0u32, 0u32, 0u32);
            for sy in 0..4 {
                for sx in 0..4 {
                    let x = ((px as f64) + (sx as f64 + 0.5) / 4.0) / n as f64 * 2.0 - 1.0;
                    let y = ((py as f64) + (sy as f64 + 0.5) / 4.0) / n as f64 * 2.0 - 1.0;
                    if let Some(Rgb(cr, cg, cb)) = shade(state, x, y) {
                        r += cr as u32;
                        g += cg as u32;
                        b += cb as u32;
                        hits += 1;
                    }
                }
            }
            if hits > 0 {
                let i = (py * n + px) * 4;
                out[i] = (r / hits) as u8;
                out[i + 1] = (g / hits) as u8;
                out[i + 2] = (b / hits) as u8;
                out[i + 3] = (hits * 255 / 16) as u8;
            }
        }
    }
    out
}

/// Whether the tray takes a monochrome template image. The macOS menu bar
/// draws a template image in its own color (light, dark or tinted), so the
/// state is told by silhouette alone; the shapes differ in outline for that
/// reason (docs/design/visual.md). Linux and Windows panels show the
/// colored icon of [`rgba`], whose shapes are the same.
pub const TEMPLATE: bool = cfg!(target_os = "macos");

/// A state's monochrome template image: black, the shape's coverage as
/// alpha, SIZE × SIZE.
pub fn template_rgba(state: TrayState) -> Vec<u8> {
    let mut out = rgba(state);
    for p in out.chunks_mut(4) {
        p[0] = 0;
        p[1] = 0;
        p[2] = 0;
    }
    out
}

/// The tray image of a state for this platform.
pub fn tray_rgba(state: TrayState) -> Vec<u8> {
    if TEMPLATE {
        template_rgba(state)
    } else {
        rgba(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;

    /// With SMCP_ICON_DIR set, writes each icon's raw RGBA pixels there
    /// (`<state>.rgba`, SIZE x SIZE) for review screenshots.
    #[test]
    fn dump_icons_for_review() {
        let Some(dir) = std::env::var_os("SMCP_ICON_DIR") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        for s in TrayState::ALL {
            let name = s.name().replace(' ', "-");
            std::fs::write(dir.join(format!("{name}.rgba")), rgba(s)).unwrap();
            std::fs::write(dir.join(format!("{name}-template.rgba")), template_rgba(s)).unwrap();
        }
    }

    #[test]
    fn distinct_icons() {
        claims::partial(&["FR-20.2"]);
        let icons: Vec<Vec<u8>> = TrayState::ALL.iter().map(|s| rgba(*s)).collect();
        for (i, a) in icons.iter().enumerate() {
            assert_eq!(a.len(), (SIZE * SIZE * 4) as usize);
            assert!(
                a.chunks(4).filter(|p| p[3] > 0).count() > 100,
                "{:?} is almost empty",
                TrayState::ALL[i]
            );
            for (j, b) in icons.iter().enumerate().skip(i + 1) {
                // Each pair differs in shape or in a mark, not only in hue:
                // count pixels whose coverage differs or whose brightness
                // differs strongly (a white mark on a colored disc).
                let luma = |p: &[u8]| (p[0] as i32 * 3 + p[1] as i32 * 6 + p[2] as i32) / 10;
                let differ = a
                    .chunks(4)
                    .zip(b.chunks(4))
                    .filter(|(p, q)| (p[3] > 127) != (q[3] > 127) || (p[3] > 127 && (luma(p) - luma(q)).abs() > 80))
                    .count();
                assert!(
                    differ > 20,
                    "{:?} and {:?} look nearly the same",
                    TrayState::ALL[i],
                    TrayState::ALL[j]
                );
            }
        }
    }

    /// The macOS template images: black only, and every pair of states
    /// differs in silhouette (coverage alone), since the menu bar recolors
    /// them and color carries nothing.
    #[test]
    fn template_icons_differ_by_silhouette() {
        claims::partial(&["FR-20.2"]);
        let icons: Vec<Vec<u8>> = TrayState::ALL.iter().map(|s| template_rgba(*s)).collect();
        for (i, a) in icons.iter().enumerate() {
            assert!(
                a.chunks(4).all(|p| p[0] == 0 && p[1] == 0 && p[2] == 0),
                "{:?}",
                TrayState::ALL[i]
            );
            assert_eq!(
                a.chunks(4).map(|p| p[3]).collect::<Vec<_>>(),
                rgba(TrayState::ALL[i]).chunks(4).map(|p| p[3]).collect::<Vec<_>>(),
                "the template has the colored icon's shape"
            );
            for (j, b) in icons.iter().enumerate().skip(i + 1) {
                let differ = a
                    .chunks(4)
                    .zip(b.chunks(4))
                    .filter(|(p, q)| (p[3] > 127) != (q[3] > 127))
                    .count();
                assert!(
                    differ > 20,
                    "{:?} and {:?} have nearly the same silhouette",
                    TrayState::ALL[i],
                    TrayState::ALL[j]
                );
            }
        }
        assert_eq!(
            tray_rgba(TrayState::Healthy) == template_rgba(TrayState::Healthy),
            TEMPLATE
        );
    }
}

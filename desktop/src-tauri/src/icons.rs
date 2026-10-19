//! Tray icons for the six states (SRS FR-20.2), drawn at start-up so the
//! state is told by shape as well as color: a green disc (healthy), an
//! amber triangle (degraded), a red no-entry disc (fail-closed), a red
//! octagon (emergency stop), a grey square (stopped) and a grey ring
//! (unreachable).

use crate::state::TrayState;

pub const SIZE: u32 = 36;

#[derive(Clone, Copy)]
struct Rgb(u8, u8, u8);

const GREEN: Rgb = Rgb(0x2e, 0x9d, 0x57);
const AMBER: Rgb = Rgb(0xd9, 0x8e, 0x04);
const RED: Rgb = Rgb(0xd1, 0x34, 0x2f);
const GREY: Rgb = Rgb(0x86, 0x8b, 0x94);
const WHITE: Rgb = Rgb(0xff, 0xff, 0xff);

/// Coverage-tested shape: returns the color at a point in [-1, 1]², or None.
fn shade(state: TrayState, x: f64, y: f64) -> Option<Rgb> {
    let r = (x * x + y * y).sqrt();
    match state {
        TrayState::Healthy => (r <= 0.8).then_some(GREEN),
        TrayState::Degraded => {
            // Triangle pointing up, with a white bar as an exclamation.
            // Apex (0, -0.8), base y = 0.75 from x = -0.9 to 0.9.
            if !(y <= 0.75 && y >= -0.8 + (1.55 / 0.9) * x.abs()) {
                return None;
            }
            let bar = x.abs() <= 0.09 && ((-0.35..=0.3).contains(&y) || (0.45..=0.6).contains(&y));
            Some(if bar { WHITE } else { AMBER })
        }
        TrayState::FailClosed => {
            if r > 0.8 {
                return None;
            }
            Some(if x.abs() <= 0.5 && y.abs() <= 0.13 { WHITE } else { RED })
        }
        TrayState::EmergencyStop => {
            // Regular octagon: |x|, |y| and |x|±|y| bounds.
            let k = 0.8;
            let inside = x.abs() <= k && y.abs() <= k && (x.abs() + y.abs()) <= k * 1.414;
            inside.then_some(RED)
        }
        TrayState::Stopped => (x.abs() <= 0.62 && y.abs() <= 0.62).then_some(GREY),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;

    #[test]
    fn six_distinct_icons() {
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
}

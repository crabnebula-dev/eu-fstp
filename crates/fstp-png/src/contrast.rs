//! An integer estimate of a logo's contrast on a background colour
//! (ADR-031 row "Contrast", I-70).
//!
//! Luminance uses the lower and upper bounds of
//! [`fstp_creator::linear_bounds`], the same bounds and weights as
//! [`fstp_creator::meets_aa`]. A ratio is therefore never overstated,
//! and [`ratio_x100`] reaches 450 exactly when `meets_aa` passes.

use fstp_creator::{Rgb, linear_bounds};

use crate::image::{Image, blend};

/// 0.05 in luminance units of 10^16, as in `fstp_creator`.
const OFFSET: i64 = 500_000_000_000_000;

/// The WCAG weights of red, green and blue, scaled by 10^4.
const WEIGHTS: [i64; 3] = [2126, 7152, 722];

/// The highest ratio, 21:1, in hundredths.
const MAX_RATIO: u32 = 2100;

/// The luminance bound of `c` plus 0.05, scaled by 10^16: the lower
/// bound, or the upper one when `upper`.
fn luminance(c: Rgb, upper: bool) -> i64 {
    let pick = |v: u8| {
        let (lo, hi) = linear_bounds(v);
        if upper { hi } else { lo }
    };
    let [wr, wg, wb] = WEIGHTS;
    wr.saturating_mul(pick(c.r))
        .saturating_add(wg.saturating_mul(pick(c.g)))
        .saturating_add(wb.saturating_mul(pick(c.b)))
        .saturating_add(OFFSET)
}

/// `floor(100 * lighter / darker)`, clamped to 1:1 and 21:1.
fn ratio(lighter_low: i64, darker_high: i64) -> u32 {
    let r = lighter_low
        .saturating_mul(100)
        .checked_div(darker_high)
        .unwrap_or(i64::from(MAX_RATIO));
    u32::try_from(r.clamp(100, i64::from(MAX_RATIO))).unwrap_or(MAX_RATIO)
}

/// The WCAG contrast ratio of two colours in hundredths, from 100 (1:1)
/// to 2100 (21:1), rounded down from the conservative bounds. It is at
/// least 450 exactly when [`fstp_creator::meets_aa`] passes.
pub fn ratio_x100(a: Rgb, b: Rgb) -> u32 {
    ratio(luminance(a, false), luminance(b, true))
        .max(ratio(luminance(b, false), luminance(a, true)))
}

/// The contrast estimate of a logo on a background.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Contrast {
    /// The ratio, in hundredths, that at least half of the logo's ink
    /// reaches. Ink is weighted by opacity.
    pub median_x100: u32,
    /// The share of ink under 3:1, in thousandths, rounded down.
    pub under_3_per_mille: u32,
    /// The total ink: the sum of the alpha of every pixel.
    pub ink: u64,
}

/// The contrast of `img` on `background`. Each pixel with any opacity is
/// composited over the background as a browser does, and the ratio of the
/// result against the background is weighted by the pixel's alpha. `None`
/// when every pixel is fully transparent.
pub fn contrast(img: &Image, background: Rgb) -> Option<Contrast> {
    let bg_low = luminance(background, false);
    let bg_high = luminance(background, true);
    let mut hist = vec![0u64; usize::try_from(MAX_RATIO).unwrap_or(0).saturating_add(1)];
    let mut last: Option<([u8; 4], usize)> = None;
    for p in img.rgba().chunks_exact(4) {
        let px = [
            p.first().copied().unwrap_or(0),
            p.get(1).copied().unwrap_or(0),
            p.get(2).copied().unwrap_or(0),
            p.get(3).copied().unwrap_or(0),
        ];
        let [r, g, b, a] = px;
        if a == 0 {
            continue;
        }
        let slot = match last {
            Some((q, s)) if q == px => s,
            _ => {
                let c = Rgb {
                    r: blend(r, background.r, a),
                    g: blend(g, background.g, a),
                    b: blend(b, background.b, a),
                };
                let x = ratio(luminance(c, false), bg_high).max(ratio(bg_low, luminance(c, true)));
                let s = usize::try_from(x).unwrap_or(0);
                last = Some((px, s));
                s
            }
        };
        if let Some(h) = hist.get_mut(slot) {
            *h = h.saturating_add(u64::from(a));
        }
    }
    let ink = hist.iter().fold(0u64, |s, h| s.saturating_add(*h));
    if ink == 0 {
        return None;
    }
    let mut acc = 0u64;
    let mut median = 100u32;
    for (q, h) in hist.iter().enumerate().rev() {
        acc = acc.saturating_add(*h);
        if acc.saturating_mul(2) >= ink {
            median = u32::try_from(q).unwrap_or(100);
            break;
        }
    }
    let under = hist
        .iter()
        .take(300)
        .fold(0u64, |s, h| s.saturating_add(*h));
    let per_mille = under.saturating_mul(1000).checked_div(ink).unwrap_or(0);
    Some(Contrast {
        median_x100: median,
        under_3_per_mille: u32::try_from(per_mille).unwrap_or(1000),
        ink,
    })
}

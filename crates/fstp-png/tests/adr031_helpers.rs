//! Alpha flattening, the PDF streams and the contrast estimate of
//! `fstp-png` (ADR-031 rows "PDF helpers" and "Contrast").
//!
//! I-70: the contrast estimate uses the integer luminance bounds behind
//! `fstp_creator::meets_aa`, so its 4.5:1 answer equals `meets_aa`.
//! R-WL-03: branding cannot break contrast unnoticed.

#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

mod common;

use common::{apply_filter, paeth, rgba_pattern};
use fstp_creator::{Rgb, meets_aa};
use fstp_png::{Image, contrast, flatten, pdf_alpha, pdf_rgb, ratio_x100, zlib_decompress};
use fstp_prop::{Config, check_with, prop_assert, prop_assert_eq};

const WHITE: Rgb = Rgb::hex(0xFF_FF_FF);
const BLACK: Rgb = Rgb::hex(0);

fn solid(w: u32, h: u32, px: [u8; 4]) -> Image {
    Image::new(w, h, px.repeat((w * h) as usize)).unwrap()
}

/// Undoes the PNG filters of a PDF predictor stream.
fn unfilter(data: &[u8], width: usize, colours: usize) -> Vec<u8> {
    let row = width * colours;
    let mut prev = vec![0u8; row];
    let mut out = Vec::new();
    for line in data.chunks(row + 1) {
        let ft = line[0];
        let mut cur = vec![0u8; row];
        for i in 0..row {
            let a = if i >= colours { cur[i - colours] } else { 0 };
            let b = prev[i];
            let c = if i >= colours { prev[i - colours] } else { 0 };
            let pred = match ft {
                0 => 0,
                1 => a,
                2 => b,
                3 => ((u16::from(a) + u16::from(b)) / 2) as u8,
                4 => paeth(a, b, c),
                _ => panic!("filter {ft}"),
            };
            cur[i] = line[1 + i].wrapping_add(pred);
        }
        out.extend(&cur);
        prev = cur;
    }
    // The helper of `common` is the inverse of this one.
    let _ = apply_filter;
    out
}

/// R-WL-03: flattening composites over the background with rounding.
#[test]
fn r_wl_03_flatten_composites_over_the_background() {
    let bg = Rgb::hex(0x10_20_30);
    let img = Image::new(
        4,
        1,
        vec![
            255, 0, 0, 255, // opaque red stays
            255, 0, 0, 0, // clear shows the background
            255, 255, 255, 128, // half white
            0, 0, 0, 1, // nearly clear black
        ],
    )
    .unwrap();
    let blend = |f: u32, b: u32, a: u32| ((f * a + b * (255 - a) + 127) / 255) as u8;
    assert_eq!(
        flatten(&img, bg),
        vec![
            255,
            0,
            0,
            0x10,
            0x20,
            0x30,
            blend(255, 0x10, 128),
            blend(255, 0x20, 128),
            blend(255, 0x30, 128),
            blend(0, 0x10, 1),
            blend(0, 0x20, 1),
            blend(0, 0x30, 1),
        ]
    );
}

/// R-WL-03: the PDF RGB stream is zlib with one PNG filter byte a row,
/// and it holds the flattened pixels; the alpha stream holds the alpha
/// plane, and an opaque logo has none.
#[test]
fn r_wl_03_pdf_streams_hold_flattened_pixels_and_alpha() {
    let img = rgba_pattern(37, 23, 7);
    let s = pdf_rgb(&img, WHITE);
    assert_eq!((s.width, s.height, s.colours), (37, 23, 3));
    let rows = zlib_decompress(&s.data, 23 * (1 + 37 * 3)).unwrap();
    assert_eq!(unfilter(&rows, 37, 3), flatten(&img, WHITE));
    let a = pdf_alpha(&img).unwrap();
    assert_eq!((a.width, a.height, a.colours), (37, 23, 1));
    let rows = zlib_decompress(&a.data, 23 * (1 + 37)).unwrap();
    let alpha: Vec<u8> = img.rgba().chunks(4).map(|p| p[3]).collect();
    assert_eq!(unfilter(&rows, 37, 1), alpha);
    assert!(pdf_alpha(&solid(4, 4, [1, 2, 3, 255])).is_none());
}

/// I-70: the ratio is symmetric, 1:1 for equal colours, 21:1 at most,
/// and passes 4.5:1 exactly when `meets_aa` does.
#[test]
fn i70_ratio_agrees_with_meets_aa() {
    assert_eq!(ratio_x100(WHITE, WHITE), 100);
    let bw = ratio_x100(BLACK, WHITE);
    assert!((2090..=2100).contains(&bw), "{bw}");
    // #767676 on white is the darkest grey that passes AA, #777777 fails.
    assert!(ratio_x100(Rgb::hex(0x76_76_76), WHITE) >= 450);
    assert!(ratio_x100(Rgb::hex(0x77_77_77), WHITE) < 450);
    check_with(
        "i70_ratio_agrees_with_meets_aa",
        Config::default().with_cases(2000),
        |g| {
            let a = Rgb::hex(g.u32_in(0..=0xFF_FF_FF));
            let b = Rgb::hex(g.u32_in(0..=0xFF_FF_FF));
            let r = ratio_x100(a, b);
            prop_assert_eq!(r, ratio_x100(b, a));
            prop_assert!((100..=2100).contains(&r));
            prop_assert_eq!(r >= 450, meets_aa(a, b));
            Ok(())
        },
    );
}

/// R-WL-03, I-70: the contrast estimate of simple logos.
#[test]
fn r_wl_03_contrast_estimate_of_simple_logos() {
    // Black ink on white: high, nothing under 3:1.
    let ink = contrast(&solid(16, 16, [0, 0, 0, 255]), WHITE).unwrap();
    assert_eq!(ink.median_x100, ratio_x100(BLACK, WHITE));
    assert_eq!(ink.under_3_per_mille, 0);
    assert_eq!(ink.ink, 16 * 16 * 255);
    // White ink on white: invisible.
    let ghost = contrast(&solid(16, 16, [255, 255, 255, 255]), WHITE).unwrap();
    assert_eq!(ghost.median_x100, 100);
    assert_eq!(ghost.under_3_per_mille, 1000);
    // Fully transparent: no estimate.
    assert!(contrast(&solid(16, 16, [0, 0, 0, 0]), WHITE).is_none());
    // A logo three quarters white and one quarter black on white: the
    // median ink is invisible, and 750 per mille is under 3:1.
    let mut px = Vec::new();
    for i in 0..64 {
        px.extend(if i % 4 == 0 { [0, 0, 0, 255] } else { [255; 4] });
    }
    let mixed = contrast(&Image::new(8, 8, px).unwrap(), WHITE).unwrap();
    assert_eq!(mixed.median_x100, 100);
    assert_eq!(mixed.under_3_per_mille, 750);
    // The same logo on a black header: the white ink now carries it.
    let dark = contrast(&Image::new(8, 8, mixed_px()).unwrap(), BLACK).unwrap();
    assert_eq!(dark.median_x100, ratio_x100(WHITE, BLACK));
    assert_eq!(dark.under_3_per_mille, 250);
    // Half-transparent black on white composites to grey first.
    let half = contrast(&solid(16, 16, [0, 0, 0, 128]), WHITE).unwrap();
    let grey = Rgb::hex(0x7F_7F_7F);
    assert_eq!(half.median_x100, ratio_x100(grey, WHITE));
    assert_eq!(half.ink, 16 * 16 * 128);
}

fn mixed_px() -> Vec<u8> {
    let mut px = Vec::new();
    for i in 0..64 {
        px.extend(if i % 4 == 0 { [0, 0, 0, 255] } else { [255; 4] });
    }
    px
}

/// R-WL-03: the median is the ratio that at least half the ink reaches,
/// for any logo, and the share under 3:1 is a share.
#[test]
fn r_wl_03_contrast_median_is_a_weighted_median() {
    check_with(
        "r_wl_03_contrast_median_is_a_weighted_median",
        Config::default().with_cases(200),
        |g| {
            let w = g.u32_in(1..=12);
            let h = g.u32_in(1..=12);
            let px = g.bytes((w * h * 4) as usize..=(w * h * 4) as usize);
            let img = Image::new(w, h, px).unwrap();
            let bg = Rgb::hex(g.u32_in(0..=0xFF_FF_FF));
            let Some(c) = contrast(&img, bg) else {
                prop_assert!(img.rgba().chunks(4).all(|p| p[3] == 0));
                return Ok(());
            };
            let flat = flatten(&img, bg);
            let mut at_least = 0u64;
            let mut total = 0u64;
            let mut under = 0u64;
            for (p, f) in img.rgba().chunks(4).zip(flat.chunks(3)) {
                let a = u64::from(p[3]);
                if a == 0 {
                    continue;
                }
                let r = ratio_x100(
                    Rgb {
                        r: f[0],
                        g: f[1],
                        b: f[2],
                    },
                    bg,
                );
                total += a;
                if r >= c.median_x100 {
                    at_least += a;
                }
                if r < 300 {
                    under += a;
                }
            }
            prop_assert_eq!(total, c.ink);
            prop_assert!(at_least * 2 >= total);
            prop_assert_eq!(c.under_3_per_mille as u64, under * 1000 / total);
            Ok(())
        },
    );
}

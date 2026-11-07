//! Tests of the tenant brand tokens (M9 design section 3, lane B1).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use fstp_brand::{
    BrandTokens, ColourKey, MAX_NAME_BYTES, Pair, PairSet, Palette, canonical, failing_pairs, parse,
};
use fstp_creator::{Rgb, ThemeMode, meets_aa};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

fn hex(c: Rgb) -> String {
    format!("#{:02x}{:02x}{:02x}", c.r, c.g, c.b)
}

fn palette_json(p: &Palette) -> String {
    let members: Vec<String> = ColourKey::ALL
        .iter()
        .map(|k| format!("\"{}\":\"{}\"", k.name(), hex(p.get(*k))))
        .collect();
    format!("{{{}}}", members.join(","))
}

fn tokens_json(name: &str, light: &Palette, dark: &Palette) -> String {
    format!(
        "{{\"dark\":{},\"light\":{},\"name\":\"{}\",\"typography\":\"system\"}}",
        palette_json(dark),
        palette_json(light),
        name
    )
}

fn rgb(g: &mut Gen) -> Rgb {
    // Half the draws come near the platform defaults, so that both
    // accepted and refused sets occur often.
    if g.bool() {
        Rgb {
            r: g.u8(),
            g: g.u8(),
            b: g.u8(),
        }
    } else {
        let base = *g.pick(&[
            Rgb::hex(0x1E_40_AF),
            Rgb::hex(0xFF_FF_FF),
            Rgb::hex(0x25_63_EB),
            Rgb::hex(0x0F_17_2A),
            Rgb::hex(0x93_C5_FD),
            Rgb::hex(0x60_A5_FA),
        ]);
        let d = g.u8_in(0..=40);
        Rgb {
            r: base.r.saturating_sub(d),
            g: base.g.saturating_add(d / 2),
            b: base.b.saturating_sub(d / 3),
        }
    }
}

fn palette(g: &mut Gen) -> Palette {
    Palette {
        brand: rgb(g),
        brand_hover: rgb(g),
        brand_text: rgb(g),
        on_brand: rgb(g),
        focus: rgb(g),
    }
}

fn tokens(g: &mut Gen) -> BrandTokens {
    let light = palette(g);
    let dark = palette(g);
    parse(tokens_json("Harbour Fund", &light, &dark).as_bytes())
        .map_err(|e| e.to_string())
        .unwrap_or_else(|e| panic!("generated tokens must parse: {e}"))
}

/// I-70: a token set is accepted exactly when every pair of the table
/// meets AA in both modes, and a refusal lists exactly the failing pairs
/// (`i70_accepted_iff_all_pairs_pass`, M9 design section 3).
#[test]
fn i70_accepted_iff_all_pairs_pass() {
    check("i70_accepted_iff_all_pairs_pass", |g| {
        let t = tokens(g);
        let failing = failing_pairs(&t);
        let mut expected = PairSet::EMPTY;
        for p in Pair::ALL {
            let (text, bg) = p.colours(&t);
            if !meets_aa(text, bg) {
                expected = expected.with(p);
            }
        }
        g.note("failing", &failing);
        prop_assert_eq!(failing, expected);
        prop_assert_eq!(failing.is_empty(), t.accepted());
        Ok(())
    });
}

/// I-70: the table covers both modes, and the platform defaults pass.
#[test]
fn i70_pair_table_covers_light_and_dark() {
    let modes: Vec<ThemeMode> = Pair::ALL.iter().map(|p| p.mode).collect();
    assert!(modes.contains(&ThemeMode::Light));
    assert!(modes.contains(&ThemeMode::Dark));
    assert_eq!(Pair::ALL.len(), 10);
    let t = BrandTokens::platform("Platform").unwrap_or_else(|| panic!("platform name"));
    assert!(failing_pairs(&t).is_empty());
}

/// I-70: a known failing set lists the exact pairs. White on yellow fails
/// in light mode on both brand fills.
#[test]
fn i70_refusal_lists_failing_pairs() {
    let mut light = Palette::PLATFORM_LIGHT;
    light.brand = Rgb::hex(0xFF_EB_3B);
    light.brand_hover = Rgb::hex(0xFF_EE_58);
    let src = tokens_json("Yellow", &light, &Palette::PLATFORM_DARK);
    let t = parse(src.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    let failing: Vec<String> = failing_pairs(&t).iter().map(|p| p.name()).collect();
    assert_eq!(
        failing,
        vec![
            "light.on-brand/brand".to_owned(),
            "light.on-brand/brand-hover".to_owned()
        ]
    );
}

/// I-68: every accepted input is typed data, and its canonical text
/// parses back to the same tokens, byte for byte.
#[test]
fn i68_parse_canonical_round_trip() {
    check("i68_parse_canonical_round_trip", |g| {
        let t = tokens(g);
        let text = canonical(&t);
        let back = parse(text.as_bytes()).map_err(|e| e.to_string())?;
        prop_assert_eq!(&back, &t);
        prop_assert_eq!(canonical(&back), text);
        Ok(())
    });
}

/// I-68: random bytes are refused or yield typed tokens whose canonical
/// text holds only the closed key list, hex colours and the name.
#[test]
fn i68_fuzzed_branding_is_data() {
    check("i68_fuzzed_branding_is_data", |g| {
        let bytes = if g.bool() {
            g.bytes(0..=200)
        } else {
            let mut b = canonical(&tokens(g)).into_bytes();
            let n = b.len();
            if n > 0 {
                let i = g.usize_in(0..=n - 1);
                if let Some(x) = b.get_mut(i) {
                    *x = g.u8();
                }
            }
            b
        };
        if let Ok(t) = parse(&bytes) {
            let name = t.name.as_str();
            prop_assert!(!name.contains('<') && !name.contains('>'));
            prop_assert!(!name.chars().any(char::is_control));
            prop_assert!(!name.is_empty() && name.len() <= MAX_NAME_BYTES);
        }
        Ok(())
    });
}

/// I-68: the parser refuses each kind of malformed token.
#[test]
fn i68_parser_refuses_malformed_tokens() {
    let l = Palette::PLATFORM_LIGHT;
    let d = Palette::PLATFORM_DARK;
    let good = tokens_json("Harbour", &l, &d);
    assert!(parse(good.as_bytes()).is_ok());
    let bad = [
        // Not JSON, or not an object.
        String::new(),
        "[]".to_owned(),
        // Markup, control characters, empty and long names.
        tokens_json("<script>", &l, &d),
        tokens_json("a>b", &l, &d),
        tokens_json("tab\\there", &l, &d),
        tokens_json("", &l, &d),
        tokens_json(" lead", &l, &d),
        tokens_json(&"x".repeat(MAX_NAME_BYTES + 1), &l, &d),
        // Colour spellings other than #rrggbb in lower case.
        good.replacen("#1e40af", "#1E40AF", 1),
        good.replacen("#1e40af", "#1e40a", 1),
        good.replacen("#1e40af", "1e40af", 1),
        good.replacen("#1e40af", "#1e40afff", 1),
        good.replacen("#1e40af", "red", 1),
        good.replacen("#1e40af", "#1e40ag", 1),
        // Typography is closed (D2).
        good.replacen("\"system\"", "\"Comic Sans\"", 1),
        // Unknown, missing and duplicate members.
        good.replacen("\"name\"", "\"css\":\"x\",\"name\"", 1),
        good.replacen("\"typography\":\"system\"", "\"typography\":null", 1),
        good.replacen(",\"typography\":\"system\"", "", 1),
        good.replacen("\"brand\":", "\"logo\":", 1),
        good.replacen("\"name\"", "\"name\":\"a\",\"name\"", 1),
    ];
    for b in bad {
        assert!(parse(b.as_bytes()).is_err(), "accepted: {b}");
    }
    let huge = format!("{}{}", " ".repeat(fstp_brand::MAX_INPUT_BYTES), good);
    assert!(parse(huge.as_bytes()).is_err());
}

/// The pair set keeps only bits of the table.
#[test]
fn i70_pair_set_bits_round_trip() {
    let all = Pair::ALL.iter().fold(PairSet::EMPTY, |s, p| s.with(*p));
    assert_eq!(PairSet::from_bits(all.bits()), Some(all));
    assert_eq!(PairSet::from_bits(1 << 10), None);
    assert_eq!(all.iter().count(), 10);
}

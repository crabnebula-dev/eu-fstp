//! The generated stylesheet of the brand tokens (M9 design section 2.3,
//! lane B2; I-68).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use fstp_brand::{BrandTokens, ColourKey, Palette, colour_hex, css, parse};
use fstp_creator::Rgb;
use fstp_prop::{Gen, check, prop_assert_eq};

fn rgb(g: &mut Gen) -> Rgb {
    Rgb {
        r: g.u8(),
        g: g.u8(),
        b: g.u8(),
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

fn members(p: &Palette) -> String {
    let m: Vec<String> = ColourKey::ALL
        .iter()
        .map(|k| format!("\"{}\":\"{}\"", k.name(), colour_hex(p.get(*k))))
        .collect();
    format!("{{{}}}", m.join(","))
}

/// Tokens with a name full of CSS metacharacters.
fn tokens(g: &mut Gen) -> BrandTokens {
    let name = *g.pick(&[
        "Harbour Fund",
        "a};body{display:none}/*",
        "x\\\\22 url(//evil)",
        "q\\\"{;}",
        "@import 'x'",
    ]);
    let src = format!(
        "{{\"dark\":{},\"light\":{},\"name\":\"{}\",\"typography\":\"system\"}}",
        members(&palette(g)),
        members(&palette(g)),
        name
    );
    parse(src.as_bytes())
        .map_err(|e| e.to_string())
        .unwrap_or_else(|e| panic!("generated tokens must parse: {e}"))
}

fn decls(p: &Palette) -> String {
    ColourKey::ALL
        .iter()
        .map(|k| format!("--color-{}:{};", k.name(), colour_hex(p.get(*k))))
        .collect()
}

/// I-68: the CSS of any tokens is exactly the grammar of section 2.3
/// (as amended by lane B2 so the dark family wins over the platform
/// sheet), byte for byte, and holds neither the name nor any other free
/// text.
#[test]
fn i68_css_holds_only_token_values() {
    check("i68_css_holds_only_token_values", |g| {
        let t = tokens(g);
        let want = format!(
            ":root{{{l}}}@media (prefers-color-scheme: dark){{:root:not([data-theme=\"light\"]){{{d}}}}}:root[data-theme=\"dark\"]{{{d}}}",
            l = decls(&t.light),
            d = decls(&t.dark)
        );
        let got = css(&t);
        prop_assert_eq!(&got, &want);
        prop_assert_eq!(got.contains(t.name.as_str()), false);
        Ok(())
    });
}

/// I-68: the stylesheet is plain ASCII with no URL, import or comment.
#[test]
fn i68_css_has_no_url_import_or_comment() {
    check("i68_css_has_no_url_import_or_comment", |g| {
        let got = css(&tokens(g));
        prop_assert_eq!(got.is_ascii(), true);
        for bad in ["url(", "@import", "/*", "expression", "\\"] {
            prop_assert_eq!(got.contains(bad), false);
        }
        Ok(())
    });
}

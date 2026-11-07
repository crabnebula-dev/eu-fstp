//! The stylesheet of a token set (M9 design section 2.3, lane B2).

use crate::{BrandTokens, ColourKey, Palette, colour_hex};

fn declarations(out: &mut String, p: &Palette) {
    for k in ColourKey::ALL {
        out.push_str("--color-");
        out.push_str(k.name());
        out.push(':');
        out.push_str(&colour_hex(p.get(k)));
        out.push(';');
    }
}

/// The CSS of `t` (I-68): the closed key list with hex digits from
/// [`fstp_creator::Rgb`], and nothing else. The name never appears.
///
/// The light family sets `:root`. The dark family is set under the same
/// selectors that `web/src/site/tokens.css` uses for dark, so that it
/// wins over the platform sheet at equal order (interim, pending Daniel:
/// section 2.3 names bare `:root` inside the media block, which the
/// platform sheet's `:root:not([data-theme="light"])` would outrank).
pub fn css(t: &BrandTokens) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str(":root{");
    declarations(&mut out, &t.light);
    out.push_str("}@media (prefers-color-scheme: dark){:root:not([data-theme=\"light\"]){");
    declarations(&mut out, &t.dark);
    out.push_str("}}:root[data-theme=\"dark\"]{");
    declarations(&mut out, &t.dark);
    out.push('}');
    out
}

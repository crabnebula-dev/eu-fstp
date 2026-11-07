//! Tenant brand tokens (M9 design lane B1, decisions D1 and D2).
//!
//! The crate is pure. It holds:
//!
//! - the typed tokens: the tenant name and the brand colour family
//!   `brand`, `brand-hover`, `brand-text`, `on-brand` and `focus`, in
//!   light and dark. Typography is closed to `system` (D2);
//! - the strict parser of the token text, fuzzed as `branding_parse`. No
//!   token holds CSS, markup, a URL or a script (I-68);
//! - the I-70 pair table and its check, through the integer WCAG test
//!   [`fstp_creator::meets_aa`]. No float appears;
//! - the canonical text of a token set, from which the shell computes the
//!   tokens digest.
//!
//! Interim, pending Daniel: the platform surfaces the pairs are checked
//! against are those of `web/src/site/tokens.css`. The focus ring is held
//! to the 4.5:1 text bound, which is stricter than the 3:1 non-text bound.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

use std::fmt;

use fstp_json::{Object, ParseLimits, Value, parse_with, to_canonical};

pub use fstp_creator::{Rgb, ThemeMode, meets_aa};

/// The longest tenant name, in bytes.
pub const MAX_NAME_BYTES: usize = 80;

/// The longest token text the parser reads, in bytes.
pub const MAX_INPUT_BYTES: usize = 4096;

/// Why a token text was refused. The message is fixed and never quotes
/// the input (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BrandError(pub &'static str);

impl fmt::Display for BrandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for BrandError {}

type R<T> = Result<T, BrandError>;

/// The tenant name: 1 to [`MAX_NAME_BYTES`] bytes, no control character,
/// no angle bracket, and no leading or trailing white space. It reaches
/// pages only as an escaped text node (I-68).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BrandName(String);

impl BrandName {
    /// The name, if `s` is a valid one.
    pub fn new(s: &str) -> Option<BrandName> {
        let ok = !s.is_empty()
            && s.len() <= MAX_NAME_BYTES
            && !s.chars().any(|c| c.is_control() || c == '<' || c == '>')
            && s.trim() == s;
        ok.then(|| BrandName(s.to_owned()))
    }

    /// The name's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The typography token. Closed to one value in M9 (D2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Typography {
    /// The platform's system font stack.
    System,
}

impl Typography {
    /// The token's spelling.
    pub const fn name(self) -> &'static str {
        match self {
            Typography::System => "system",
        }
    }
}

/// One colour token of the brand family (D1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ColourKey {
    /// `brand`: fills such as the primary button.
    Brand,
    /// `brand-hover`: the hovered fill.
    BrandHover,
    /// `brand-text`: links and active navigation text.
    BrandText,
    /// `on-brand`: text on brand fills.
    OnBrand,
    /// `focus`: the focus ring.
    Focus,
}

impl ColourKey {
    /// Every key, in the order of the generated CSS.
    pub const ALL: [ColourKey; 5] = [
        ColourKey::Brand,
        ColourKey::BrandHover,
        ColourKey::BrandText,
        ColourKey::OnBrand,
        ColourKey::Focus,
    ];

    /// The key's spelling, which is also its CSS custom property suffix.
    pub const fn name(self) -> &'static str {
        match self {
            ColourKey::Brand => "brand",
            ColourKey::BrandHover => "brand-hover",
            ColourKey::BrandText => "brand-text",
            ColourKey::OnBrand => "on-brand",
            ColourKey::Focus => "focus",
        }
    }
}

/// The brand colour family of one mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Palette {
    /// `brand`.
    pub brand: Rgb,
    /// `brand-hover`.
    pub brand_hover: Rgb,
    /// `brand-text`.
    pub brand_text: Rgb,
    /// `on-brand`.
    pub on_brand: Rgb,
    /// `focus`.
    pub focus: Rgb,
}

impl Palette {
    /// The platform's light brand family (`web/src/site/tokens.css`).
    pub const PLATFORM_LIGHT: Palette = Palette {
        brand: Rgb::hex(0x25_63_EB),
        brand_hover: Rgb::hex(0x1D_4E_D8),
        brand_text: Rgb::hex(0x1E_40_AF),
        on_brand: Rgb::hex(0xFF_FF_FF),
        focus: Rgb::hex(0x25_63_EB),
    };

    /// The platform's dark brand family (`web/src/site/tokens.css`).
    pub const PLATFORM_DARK: Palette = Palette {
        brand: Rgb::hex(0x3B_82_F6),
        brand_hover: Rgb::hex(0x60_A5_FA),
        brand_text: Rgb::hex(0x93_C5_FD),
        on_brand: Rgb::hex(0x0F_17_2A),
        focus: Rgb::hex(0x60_A5_FA),
    };

    /// The colour of `key`.
    pub const fn get(&self, key: ColourKey) -> Rgb {
        match key {
            ColourKey::Brand => self.brand,
            ColourKey::BrandHover => self.brand_hover,
            ColourKey::BrandText => self.brand_text,
            ColourKey::OnBrand => self.on_brand,
            ColourKey::Focus => self.focus,
        }
    }

    fn set(&mut self, key: ColourKey, c: Rgb) {
        match key {
            ColourKey::Brand => self.brand = c,
            ColourKey::BrandHover => self.brand_hover = c,
            ColourKey::BrandText => self.brand_text = c,
            ColourKey::OnBrand => self.on_brand = c,
            ColourKey::Focus => self.focus = c,
        }
    }
}

/// A tenant's brand tokens. Typed values only (I-68).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BrandTokens {
    /// The tenant name.
    pub name: BrandName,
    /// The typography token.
    pub typography: Typography,
    /// The light brand family.
    pub light: Palette,
    /// The dark brand family.
    pub dark: Palette,
}

impl BrandTokens {
    /// The platform brand family under the tenant name `name`, if valid.
    pub fn platform(name: &str) -> Option<BrandTokens> {
        Some(BrandTokens {
            name: BrandName::new(name)?,
            typography: Typography::System,
            light: Palette::PLATFORM_LIGHT,
            dark: Palette::PLATFORM_DARK,
        })
    }

    /// The brand family of `mode`.
    pub const fn palette(&self, mode: ThemeMode) -> &Palette {
        match mode {
            ThemeMode::Light => &self.light,
            ThemeMode::Dark => &self.dark,
        }
    }

    /// Whether every pair of the table passes (I-70).
    pub fn accepted(&self) -> bool {
        failing_pairs(self).is_empty()
    }
}

/// A platform surface a brand colour is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Surface {
    /// `surface-0`, the page.
    Surface0,
    /// `surface-1`, cards, header and sidebar.
    Surface1,
}

impl Surface {
    /// The surface's colour in `mode` (`web/src/site/tokens.css`).
    pub const fn colour(self, mode: ThemeMode) -> Rgb {
        match (self, mode) {
            (Surface::Surface0, ThemeMode::Light) => Rgb::hex(0xFF_FF_FF),
            (Surface::Surface1, ThemeMode::Light) => Rgb::hex(0xF8_FA_FC),
            (Surface::Surface0, ThemeMode::Dark) => Rgb::hex(0x0F_17_2A),
            (Surface::Surface1, ThemeMode::Dark) => Rgb::hex(0x1E_29_3B),
        }
    }
}

/// What a checked pair is, in one mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PairKind {
    /// Links on the page: `brand-text` on `surface-0`. The platform
    /// attribution uses this pair (I-69).
    BrandTextOnSurface0,
    /// Links and active navigation on cards and the sidebar.
    BrandTextOnSurface1,
    /// Primary button text: `on-brand` on `brand`.
    OnBrandOnBrand,
    /// Hovered primary button text: `on-brand` on `brand-hover`.
    OnBrandOnBrandHover,
    /// The focus ring on the page: `focus` on `surface-0`.
    FocusOnSurface0,
}

impl PairKind {
    /// Every kind, in table order.
    pub const ALL: [PairKind; 5] = [
        PairKind::BrandTextOnSurface0,
        PairKind::BrandTextOnSurface1,
        PairKind::OnBrandOnBrand,
        PairKind::OnBrandOnBrandHover,
        PairKind::FocusOnSurface0,
    ];

    const fn name(self) -> &'static str {
        match self {
            PairKind::BrandTextOnSurface0 => "brand-text/surface-0",
            PairKind::BrandTextOnSurface1 => "brand-text/surface-1",
            PairKind::OnBrandOnBrand => "on-brand/brand",
            PairKind::OnBrandOnBrandHover => "on-brand/brand-hover",
            PairKind::FocusOnSurface0 => "focus/surface-0",
        }
    }
}

/// One checked colour pair of the I-70 table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pair {
    /// The mode.
    pub mode: ThemeMode,
    /// The pair.
    pub kind: PairKind,
}

const fn pair(mode: ThemeMode, kind: PairKind) -> Pair {
    Pair { mode, kind }
}

impl Pair {
    /// The table: every kind in light, then every kind in dark.
    pub const ALL: [Pair; 10] = [
        pair(ThemeMode::Light, PairKind::BrandTextOnSurface0),
        pair(ThemeMode::Light, PairKind::BrandTextOnSurface1),
        pair(ThemeMode::Light, PairKind::OnBrandOnBrand),
        pair(ThemeMode::Light, PairKind::OnBrandOnBrandHover),
        pair(ThemeMode::Light, PairKind::FocusOnSurface0),
        pair(ThemeMode::Dark, PairKind::BrandTextOnSurface0),
        pair(ThemeMode::Dark, PairKind::BrandTextOnSurface1),
        pair(ThemeMode::Dark, PairKind::OnBrandOnBrand),
        pair(ThemeMode::Dark, PairKind::OnBrandOnBrandHover),
        pair(ThemeMode::Dark, PairKind::FocusOnSurface0),
    ];

    /// The pair's position in [`Pair::ALL`].
    pub fn index(self) -> u32 {
        let mut i = 0u32;
        for p in Pair::ALL {
            if p == self {
                return i;
            }
            i = i.saturating_add(1);
        }
        i
    }

    /// The text and background colours of the pair in `t`.
    pub const fn colours(self, t: &BrandTokens) -> (Rgb, Rgb) {
        let p = t.palette(self.mode);
        match self.kind {
            PairKind::BrandTextOnSurface0 => (p.brand_text, Surface::Surface0.colour(self.mode)),
            PairKind::BrandTextOnSurface1 => (p.brand_text, Surface::Surface1.colour(self.mode)),
            PairKind::OnBrandOnBrand => (p.on_brand, p.brand),
            PairKind::OnBrandOnBrandHover => (p.on_brand, p.brand_hover),
            PairKind::FocusOnSurface0 => (p.focus, Surface::Surface0.colour(self.mode)),
        }
    }

    /// The pair's stable name, such as `light.on-brand/brand`.
    pub fn name(self) -> String {
        let mode = match self.mode {
            ThemeMode::Light => "light",
            ThemeMode::Dark => "dark",
        };
        format!("{mode}.{}", self.kind.name())
    }
}

/// A set of pairs of the table, one bit per [`Pair::index`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PairSet(u16);

impl PairSet {
    /// No pair.
    pub const EMPTY: PairSet = PairSet(0);

    const MASK: u16 = (1 << 10) - 1;

    /// The set with `p` added.
    pub fn with(self, p: Pair) -> PairSet {
        PairSet(self.0 | 1u16.checked_shl(p.index()).unwrap_or(0))
    }

    /// Whether `p` is in the set.
    pub fn contains(self, p: Pair) -> bool {
        self.0 & 1u16.checked_shl(p.index()).unwrap_or(0) != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The bits of the set.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// The set of `bits`, if every bit names a pair of the table.
    pub const fn from_bits(bits: u16) -> Option<PairSet> {
        if bits & !PairSet::MASK == 0 {
            Some(PairSet(bits))
        } else {
            None
        }
    }

    /// The pairs of the set, in table order.
    pub fn iter(self) -> impl Iterator<Item = Pair> {
        Pair::ALL.into_iter().filter(move |p| self.contains(*p))
    }
}

/// The pairs of the table that fail WCAG 2.2 AA in `t` (I-70). An empty
/// set means the tokens are accepted.
pub fn failing_pairs(t: &BrandTokens) -> PairSet {
    Pair::ALL
        .into_iter()
        .filter(|p| {
            let (text, bg) = p.colours(t);
            !meets_aa(text, bg)
        })
        .fold(PairSet::EMPTY, PairSet::with)
}

// ---------------------------------------------------------------- parsing

fn limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(MAX_INPUT_BYTES)
        .with_max_depth(3)
        .with_max_string_bytes(256)
        .with_max_container_len(8)
        .with_max_nodes(64)
        .with_max_memory_bytes(1 << 16)
}

/// Parses a token text: an I-JSON object with exactly the members
/// `name`, `typography`, `light` and `dark`. Each palette holds exactly
/// the five colour keys, each spelt `#rrggbb` in lower case. Fuzzed
/// (`branding_parse`). Contrast is not checked here: see
/// [`failing_pairs`].
pub fn parse(bytes: &[u8]) -> R<BrandTokens> {
    let v = parse_with(bytes, &limits()).map_err(|e| BrandError(e.kind().message()))?;
    from_value(&v)
}

fn exact<'a>(v: &'a Value, keys: &[&str]) -> R<&'a Object> {
    let o = v.as_object().ok_or(BrandError("expected an object"))?;
    if o.len() != keys.len() || !keys.iter().all(|k| o.contains_key(k)) {
        return Err(BrandError("unknown or missing member"));
    }
    Ok(o)
}

fn member<'a>(o: &'a Object, key: &str) -> R<&'a Value> {
    o.get(key).ok_or(BrandError("missing member"))
}

fn text<'a>(o: &'a Object, key: &str) -> R<&'a str> {
    member(o, key)?
        .as_str()
        .ok_or(BrandError("expected a string"))
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a').and_then(|x| x.checked_add(10)),
        _ => None,
    }
}

fn byte(hi: u8, lo: u8) -> Option<u8> {
    let h = nibble(hi)?;
    let l = nibble(lo)?;
    h.checked_mul(16).and_then(|x| x.checked_add(l))
}

/// The colour spelt `#rrggbb` in lower case.
pub fn colour(s: &str) -> Option<Rgb> {
    match s.as_bytes() {
        [b'#', r1, r2, g1, g2, b1, b2] => Some(Rgb {
            r: byte(*r1, *r2)?,
            g: byte(*g1, *g2)?,
            b: byte(*b1, *b2)?,
        }),
        _ => None,
    }
}

fn palette(v: &Value) -> R<Palette> {
    let keys: Vec<&str> = ColourKey::ALL.iter().map(|k| k.name()).collect();
    let o = exact(v, &keys)?;
    let mut p = Palette::PLATFORM_LIGHT;
    for k in ColourKey::ALL {
        let c = colour(text(o, k.name())?).ok_or(BrandError("colour is not #rrggbb"))?;
        p.set(k, c);
    }
    Ok(p)
}

/// The tokens of a parsed value, by the rules of [`parse`].
pub fn from_value(v: &Value) -> R<BrandTokens> {
    let o = exact(v, &["name", "typography", "light", "dark"])?;
    let name = BrandName::new(text(o, "name")?).ok_or(BrandError("invalid tenant name"))?;
    let typography = match text(o, "typography")? {
        "system" => Typography::System,
        _ => return Err(BrandError("unknown typography")),
    };
    Ok(BrandTokens {
        name,
        typography,
        light: palette(member(o, "light")?)?,
        dark: palette(member(o, "dark")?)?,
    })
}

// ---------------------------------------------------------------- writing

/// The colour's spelling, `#rrggbb` in lower case.
pub fn colour_hex(c: Rgb) -> String {
    format!("#{:02x}{:02x}{:02x}", c.r, c.g, c.b)
}

fn palette_value(p: &Palette) -> Value {
    let mut o = Object::with_capacity(ColourKey::ALL.len());
    for k in ColourKey::ALL {
        o.insert(k.name(), Value::String(colour_hex(p.get(k))));
    }
    Value::Object(o)
}

/// The value of `t`, in the shape [`parse`] reads.
pub fn to_value(t: &BrandTokens) -> Value {
    let mut o = Object::with_capacity(4);
    o.insert("name", Value::String(t.name.as_str().to_owned()));
    o.insert("typography", Value::String(t.typography.name().to_owned()));
    o.insert("light", palette_value(&t.light));
    o.insert("dark", palette_value(&t.dark));
    Value::Object(o)
}

/// The canonical text of `t` (RFC 8785). The shell digests it for the
/// `BrandingSet` record and the CSS route. A value of strings and objects
/// always has a canonical text, so the fallback is never taken.
pub fn canonical(t: &BrandTokens) -> String {
    to_canonical(&to_value(t)).unwrap_or_default()
}

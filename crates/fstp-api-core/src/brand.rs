//! The tenant's logos and each person's theme as the web adapter, the
//! public pages, emails and PDFs use them (ADR-030; I-68, R-WL-03).
//!
//! - A logo reaches a page only as a same-origin path that names its
//!   digest ([`fstp_brand::image::logo_path`]). Its bytes are served only
//!   for a digest a current slot names, with the content type of its
//!   checked format.
//! - The tenant's logo in dark mode falls back to its light logo, and a
//!   programme's likewise (ADR-030 section 2).

use fstp_brand::ThemeMode;
use fstp_brand::image::logo_path;

/// The logo formats, the path grammar and the EU emblem slot, for the
/// web adapter (ADR-030).
pub use fstp_brand::emblem::{EU_EMBLEM_PNG, FUNDING_ACKNOWLEDGEMENT};
/// The funding card of ADR-034: its logo, labels and colours.
pub use fstp_brand::funding;
pub use fstp_brand::image::{LogoFormat, logo_path_digest};
use fstp_domain::id::ProgrammeId;
use fstp_json::{Object, ToJson, Value};
/// A person's theme choice as the web adapter writes it (ADR-030
/// section 1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ThemeChoice {
    /// Follow the device. The default.
    #[default]
    System,
    /// Always light.
    Light,
    /// Always dark.
    Dark,
}

impl From<fstp_tenant::Theme> for ThemeChoice {
    fn from(t: fstp_tenant::Theme) -> ThemeChoice {
        match t {
            fstp_tenant::Theme::System => ThemeChoice::System,
            fstp_tenant::Theme::Light => ThemeChoice::Light,
            fstp_tenant::Theme::Dark => ThemeChoice::Dark,
        }
    }
}
use fstp_tenant::{LogoOwner, LogoRef, LogoSlot, TenantState};

/// The served bytes of one logo, with its checked format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogoAsset {
    /// The format, which fixes the content type.
    pub format: LogoFormat,
    /// The stored bytes.
    pub bytes: Vec<u8>,
}

/// The paths of one owner's logos in light and dark. Dark falls back to
/// light.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogoPaths {
    /// The light logo's path.
    pub light: Option<String>,
    /// The dark logo's path, or the light one's when none is set.
    pub dark: Option<String>,
}

impl LogoPaths {
    /// Whether neither mode has a logo.
    pub fn is_empty(&self) -> bool {
        self.light.is_none() && self.dark.is_none()
    }
}

fn path(l: &LogoRef) -> String {
    logo_path(&l.digest.bytes(), l.format)
}

/// The logo of `owner` in `mode`, falling back to light for dark.
pub fn logo_of(ts: &TenantState, owner: LogoOwner, mode: ThemeMode) -> Option<LogoRef> {
    let own = ts.logo(LogoSlot { owner, mode }).copied();
    match mode {
        ThemeMode::Light => own,
        ThemeMode::Dark => own.or_else(|| {
            ts.logo(LogoSlot {
                owner,
                mode: ThemeMode::Light,
            })
            .copied()
        }),
    }
}

/// The paths of `owner`'s logos in `ts`.
pub fn paths_of(ts: Option<&TenantState>, owner: LogoOwner) -> LogoPaths {
    let Some(ts) = ts else {
        return LogoPaths::default();
    };
    LogoPaths {
        light: logo_of(ts, owner, ThemeMode::Light).map(|l| path(&l)),
        dark: logo_of(ts, owner, ThemeMode::Dark).map(|l| path(&l)),
    }
}

/// The logo a current slot names by `digest`, if any (ADR-030 section 3).
pub fn current(ts: &TenantState, digest: &[u8; 32]) -> Option<LogoRef> {
    ts.logos()
        .map(|(_, l)| *l)
        .find(|l| &l.digest.bytes() == digest)
}

/// One slot of `tenant.branding.logos`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogoInfo {
    /// The stored logo.
    pub logo: LogoRef,
}

impl ToJson for LogoInfo {
    fn to_json(&self) -> Value {
        let l = &self.logo;
        let mut o = Object::new();
        let _ = o.insert("path", Value::String(path(l)));
        let _ = o.insert("format", Value::String(l.format.name().to_owned()));
        let _ = o.insert("width", Value::String(l.width.to_string()));
        let _ = o.insert("height", Value::String(l.height.to_string()));
        let _ = o.insert("pdf", Value::Bool(l.pdf));
        let _ = o.insert("email", Value::Bool(l.format.in_email()));
        // I-70, ADR-030 lead reading of 2026-11-22: the contrast advice of
        // the slot, never a refusal.
        let _ = o.insert(
            "contrast",
            l.contrast_x100
                .map_or(Value::Null, |c| Value::String(c.to_string())),
        );
        let _ = o.insert(
            "advice",
            Value::Bool(
                l.contrast_x100
                    .is_some_and(|c| c < fstp_brand::image::ADVICE_BELOW_X100),
            ),
        );
        Value::Object(o)
    }
}

fn slot_json(l: Option<LogoRef>) -> Value {
    l.map_or(Value::Null, |logo| LogoInfo { logo }.to_json())
}

/// One programme's row of `tenant.branding.logos`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgrammeLogos {
    /// The programme.
    pub programme: ProgrammeId,
    /// Its display name.
    pub name: String,
    /// Its own light logo, if set.
    pub light: Option<LogoRef>,
    /// Its own dark logo, if set.
    pub dark: Option<LogoRef>,
}

/// The reply of `tenant.branding.logos`: each slot's own logo, with no
/// fallback, so the admin sees what is set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogosView {
    /// The tenant's light logo.
    pub light: Option<LogoRef>,
    /// The tenant's dark logo.
    pub dark: Option<LogoRef>,
    /// Each programme, in programme order.
    pub programmes: Vec<ProgrammeLogos>,
}

impl LogosView {
    /// The view of `ts` for `programmes`, each named by `name`.
    pub fn of(
        ts: Option<&TenantState>,
        programmes: impl IntoIterator<Item = (ProgrammeId, String)>,
    ) -> LogosView {
        let own = |owner: LogoOwner, mode: ThemeMode| {
            ts.and_then(|t| t.logo(LogoSlot { owner, mode }).copied())
        };
        LogosView {
            light: own(LogoOwner::Tenant, ThemeMode::Light),
            dark: own(LogoOwner::Tenant, ThemeMode::Dark),
            programmes: programmes
                .into_iter()
                .map(|(p, name)| ProgrammeLogos {
                    programme: p,
                    name,
                    light: own(LogoOwner::Programme(p), ThemeMode::Light),
                    dark: own(LogoOwner::Programme(p), ThemeMode::Dark),
                })
                .collect(),
        }
    }
}

impl ToJson for LogosView {
    fn to_json(&self) -> Value {
        let mut tenant = Object::new();
        let _ = tenant.insert("light", slot_json(self.light));
        let _ = tenant.insert("dark", slot_json(self.dark));
        let rows = self
            .programmes
            .iter()
            .map(|r| {
                let mut o = Object::new();
                let _ = o.insert("programme", Value::String(r.programme.raw().to_string()));
                let _ = o.insert("name", Value::String(r.name.clone()));
                let _ = o.insert("light", slot_json(r.light));
                let _ = o.insert("dark", slot_json(r.dark));
                Value::Object(o)
            })
            .collect();
        let mut o = Object::new();
        let _ = o.insert("tenant", Value::Object(tenant));
        let _ = o.insert("programmes", Value::Array(rows));
        Value::Object(o)
    }
}

/// The logos a public page of `programme` shows (ADR-030 section 2): the
/// tenant's and the programme's, each dark one only when it differs from
/// the light one, and the platform's EU emblem once it holds the file.
pub fn public_logos(ts: Option<&TenantState>, programme: ProgrammeId) -> fstp_public::PublicLogos {
    let distinct = |p: LogoPaths| {
        let dark = p.dark.filter(|d| p.light.as_ref() != Some(d));
        (p.light, dark)
    };
    let (tenant_light, tenant_dark) = distinct(paths_of(ts, LogoOwner::Tenant));
    let (programme_light, programme_dark) = distinct(paths_of(ts, LogoOwner::Programme(programme)));
    fstp_public::PublicLogos {
        tenant_light,
        tenant_dark,
        programme_light,
        programme_dark,
        // ADR-034: pages show the Funded by the EU logo as SVG.
        emblem: Some(funding::SVG_PATH.to_owned()),
        funding: None,
    }
}

/// The logos of a public page of `programme` with its funding card
/// (ADR-034, I-69).
pub fn public_chrome_logos(
    state: &fstp_engine::EngineState,
    programme: ProgrammeId,
) -> fstp_public::PublicLogos {
    let mut logos = public_logos(state.tenant.state(), programme);
    logos.funding = crate::funding::public_card(state, programme);
    logos
}

/// The plan of a branded message: the colour and the logos with their
/// text alternatives.
pub type MailPlan = ([u8; 3], Vec<(LogoRef, String)>);

/// What a message shows of the tenant (ADR-030 section 5): the brand
/// colour of the light family, as `[r, g, b]`, and the light logos an
/// email can show, the tenant's then the programme's, each with its text
/// alternative. `None` while the tenant set neither tokens nor a logo, so
/// the message keeps the platform look.
pub fn mail_plan(ts: &TenantState, programme: Option<ProgrammeId>) -> Option<MailPlan> {
    let tokens = ts.branding().map(|(t, _)| t);
    let name = tokens
        .map(|t| t.name.as_str().to_owned())
        .unwrap_or_default();
    let mut logos = Vec::new();
    if let Some(l) = logo_of(ts, LogoOwner::Tenant, ThemeMode::Light) {
        logos.push((l, name));
    }
    if let Some(p) = programme
        && let Some(l) = logo_of(ts, LogoOwner::Programme(p), ThemeMode::Light)
    {
        logos.push((l, String::new()));
    }
    logos.retain(|(l, _)| l.format.in_email());
    if tokens.is_none() && logos.is_empty() {
        return None;
    }
    let c = tokens.map_or(fstp_brand::Palette::PLATFORM_LIGHT.brand, |t| t.light.brand);
    Some(([c.r, c.g, c.b], logos))
}

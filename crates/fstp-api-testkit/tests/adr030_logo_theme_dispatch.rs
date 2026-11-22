//! Logos and themes through the one dispatch (ADR-030; I-68, R-WL-03,
//! I-78, R-LG-03).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use std::collections::BTreeSet;

use fstp_api_core::brand::ThemeChoice as Theme;
use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, Credential, Op, OpResult, RequestHead};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::fixture::{self, World};
use fstp_brand::image::{LogoFormat, logo_path, sample_png, to_base64};
use fstp_domain::id::AccountId;
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_engine::{Record, record_from_json_at};
use fstp_json::{Object, ToJson, Value};
use fstp_ledger::{MemStore, RecordStore};
use fstp_rt::future::block_on;

const A1: AccountId = AccountId::from_raw(0x0a01);
const A2: AccountId = AccountId::from_raw(0x0a02);
const OUTSIDER: AccountId = AccountId::from_raw(0x0a99);

/// A self-hosted cell whose tenant admins are A1 and A2, founded when `found`
/// holds (ADR-021).
fn cell(found: bool) -> FakeCell {
    let mut truth = GroundTruth::new();
    for (a, t) in [(A1, 0xa1), (A2, 0xa2), (OUTSIDER, 0xa9)] {
        truth.set_identity(a, IdentityTag::new(t));
        truth.verify(a);
    }
    let mut o = Object::new();
    o.insert("cell", Value::from("self_hosted"));
    o.insert("first_admin", Value::from(A1.raw().to_string()));
    o.insert("kind", Value::from("TenantProvisioned"));
    let mut env = Object::new();
    env.insert("onboarding", Value::Object(o));
    let rec: Record = record_from_json_at(1, &Value::Object(env)).unwrap();
    let mut store = MemStore::new();
    let head = store.head();
    store
        .append(head, 1_000_000, [0x7e; 16], vec![rec])
        .unwrap();
    let invitation = fstp_tenant::InvitationId::from_raw(0x1a2);
    for (n, r) in [
        fstp_tenant::TenantRecord::AdminInvited {
            invitation,
            invitee: A2,
            token_digest: fstp_tenant::TokenDigest::from_bytes([0xd2; 32]),
            by: A1,
        },
        fstp_tenant::TenantRecord::AdminAdded {
            account: A2,
            invitation,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let head = store.head();
        let mut command = [0x7e; 16];
        command[15] = u8::try_from(n).unwrap_or(0).saturating_add(1);
        store
            .append(
                head,
                1_000_000,
                command,
                vec![Record::Tenant(fstp_engine::TenantEntry::Record(r))],
            )
            .unwrap();
    }
    let world = World {
        store,
        truth,
        start: fixture::START,
        admins: [A1].into_iter().collect::<BTreeSet<_>>(),
    };
    let c = FakeCell::from_world(&world).unwrap();
    if found {
        c.found(A1, A2, AccountId::from_raw(0x0f05_1600))
            .unwrap_or_else(|e| panic!("ADR-021: the founding: {e}"));
    }
    c
}

fn set_logo(mode: &str, image: Option<&[u8]>) -> Result<Op, ApiError> {
    let image = image.map_or("null".to_owned(), |b| format!("\"{}\"", to_base64(b)));
    let body = format!(r#"{{"image":{image},"mode":"{mode}","programme":null}}"#);
    decode_route(Method::Put, "/admin/branding/logo", body.as_bytes())
}

fn logos() -> Result<Op, ApiError> {
    decode_route(Method::Get, "/admin/branding/logos", b"")
}

/// Sets a logo as A1 with its step-up.
fn set_with_step_up(c: &FakeCell, mode: &str, image: Option<&[u8]>) {
    let l = c.login(A1, LoginMethod::Passkey);
    let ch = match c.web(&l, set_logo(mode, image)) {
        Ok(OpResult::StepUpRequired(ch)) => ch,
        other => panic!("I-78: set without a proof: {other:?}"),
    };
    c.ports.step_up.approve(l.session, ch.action).unwrap();
    match c.web(&l, set_logo(mode, image)) {
        Ok(OpResult::Done { .. }) => {}
        other => panic!("set with its proof: {other:?}"),
    }
}

/// R-WL-03, I-68, I-78: a tenant admin sets the light logo after a
/// step-up. The read shows it, the core serves its bytes by its digest
/// path with its format, and dark falls back to light. A stale or
/// unknown path serves nothing. Clearing the slot removes it.
#[test]
fn r_wl_03_tenant_logo_is_set_served_and_cleared() {
    let c = cell(false);
    let png = sample_png(64, 32);
    assert!(c.core().tenant_logos().is_empty());
    set_with_step_up(&c, "light", Some(&png));
    let l = c.login(A1, LoginMethod::Passkey);
    let view = match c.web(&l, logos()) {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("logos: {other:?}"),
    };
    let light = view
        .get("tenant")
        .and_then(|t| t.get("light"))
        .expect("light slot");
    let path = logo_path(&fstp_crypto::sha256(&png), LogoFormat::Png);
    assert_eq!(
        light.get("path").and_then(Value::as_str),
        Some(path.as_str())
    );
    assert_eq!(light.get("pdf"), Some(&Value::Bool(true)));
    assert_eq!(light.get("email"), Some(&Value::Bool(true)));
    let paths = c.core().tenant_logos();
    assert_eq!(paths.light.as_deref(), Some(path.as_str()));
    assert_eq!(paths.dark.as_deref(), Some(path.as_str()));
    let asset = block_on(c.core().brand_asset(&path)).expect("served");
    assert_eq!(asset.format, LogoFormat::Png);
    assert_eq!(asset.bytes, png);
    let webp = path.replace(".png", ".webp");
    assert!(block_on(c.core().brand_asset(&webp)).is_none());
    let other = logo_path(&[0x11; 32], LogoFormat::Png);
    assert!(block_on(c.core().brand_asset(&other)).is_none());
    set_with_step_up(&c, "light", None);
    assert!(c.core().tenant_logos().is_empty());
    assert!(block_on(c.core().brand_asset(&path)).is_none());
}

/// I-68: an SVG, markup or a file over the bounds is refused under I-68,
/// before any step-up, and nothing is recorded. An outsider is refused.
#[test]
fn i68_logo_upload_refuses_svg_and_markup() {
    let c = cell(false);
    let l = c.login(A1, LoginMethod::Passkey);
    for bad in [
        b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>x</script></svg>".to_vec(),
        b"<html><body>x</body></html>".to_vec(),
        sample_png(8, 8),
    ] {
        match c.web(&l, set_logo("light", Some(&bad))) {
            Err(ApiError::Refused { rule, .. }) => assert_eq!(rule, "I-68"),
            other => panic!("I-68: {other:?}"),
        }
    }
    assert!(c.ports.engine.appended().is_empty());
    let o = c.login(OUTSIDER, LoginMethod::Passkey);
    assert!(matches!(
        c.web(&o, set_logo("light", Some(&sample_png(64, 32)))),
        Err(ApiError::Refused { .. })
    ));
    assert!(c.core().tenant_logos().is_empty());
}

/// ADR-030 section 1: an account sets its own theme. The core then gives
/// it for that account's session, System for any other, and System with
/// no session. A value outside the closed list is refused at decode.
#[test]
fn adr030_theme_is_kept_per_account() {
    let c = cell(true);
    let head = RequestHead::new();
    let l1 = c.login(A1, LoginMethod::Passkey);
    let l2 = c.login(A2, LoginMethod::Passkey);
    let set = |theme: &str| {
        decode_route(
            Method::Put,
            "/me/theme",
            format!(r#"{{"theme":"{theme}"}}"#).as_bytes(),
        )
    };
    match c.web(&l1, set("dark")) {
        Ok(OpResult::Done { .. }) => {}
        other => panic!("set_theme: {other:?}"),
    }
    let theme = |cred: Credential| block_on(c.core().theme(cred, &head));
    assert_eq!(
        theme(Credential::SessionCookie(l1.cookie.clone())),
        Theme::Dark
    );
    assert_eq!(
        theme(Credential::SessionCookie(l2.cookie.clone())),
        Theme::System
    );
    assert_eq!(theme(Credential::None), Theme::System);
    assert!(set("purple").is_err());
    match c.web(&l1, set("system")) {
        Ok(OpResult::Done { .. }) => {}
        other => panic!("set_theme: {other:?}"),
    }
    assert_eq!(
        theme(Credential::SessionCookie(l1.cookie.clone())),
        Theme::System
    );
}

/// ADR-030 (lead reading of 2026-11-22): the theme is a personal display
/// preference, so the setup gate of ADR-021 lets it through before the
/// organisation is activated.
#[test]
fn adr030_theme_is_set_before_activation() {
    let c = cell(false);
    let l = c.login(A1, LoginMethod::Passkey);
    let set = decode_route(Method::Put, "/me/theme", br#"{"theme":"light"}"#);
    match c.web(&l, set) {
        Ok(OpResult::Done { .. }) => {}
        other => panic!("ADR-021 lets the theme through: {other:?}"),
    }
    let theme = block_on(c.core().theme(
        Credential::SessionCookie(l.cookie.clone()),
        &RequestHead::new(),
    ));
    assert_eq!(theme, Theme::Light);
}

/// ADR-030 (lead reading of 2026-11-22): a programme slot is refused as an
/// actor refusal to an account that is neither a tenant admin nor a
/// programme manager of the programme, and the programme read is closed
/// to it.
#[test]
fn adr030_programme_logo_is_closed_to_outsiders() {
    let c = cell(true);
    let o = c.login(OUTSIDER, LoginMethod::Passkey);
    let body = format!(
        r#"{{"image":"{}","mode":"light","programme":"7"}}"#,
        to_base64(&sample_png(64, 32))
    );
    let set = decode_route(Method::Put, "/admin/branding/logo", body.as_bytes());
    assert!(matches!(c.web(&o, set), Err(ApiError::Refused { .. })));
    let read = decode_route(Method::Get, "/programmes/7/logos", b"");
    assert!(c.web(&o, read).is_err());
}

/// I-70, ADR-030 lead reading of 2026-11-22: a white logo in the light
/// slot is saved, and the read gives its contrast on the light top bar
/// with the advice that it may be hard to see. Advice never refuses.
#[test]
fn i70_contrast_advice_appears_on_save() {
    let c = cell(false);
    let white = fstp_brand::image::png_of(64, 32, vec![0xFF; 64 * 32 * 4]).expect("sizes");
    set_with_step_up(&c, "light", Some(&white));
    let l = c.login(A1, LoginMethod::Passkey);
    let view = match c.web(&l, logos()) {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => panic!("logos: {other:?}"),
    };
    let light = view
        .get("tenant")
        .and_then(|t| t.get("light"))
        .expect("light slot");
    assert_eq!(light.get("advice"), Some(&Value::Bool(true)));
    let c100: u32 = light
        .get("contrast")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .expect("a contrast");
    assert!(c100 < fstp_brand::image::ADVICE_BELOW_X100, "{c100}");
}

/// ADR-030 lead reading of 2026-11-22: the cell takes PNG uploads only. A
/// WebP file is refused in plain terms under I-68, before any step-up.
#[test]
fn adr030_webp_upload_is_refused() {
    let c = cell(false);
    let l = c.login(A1, LoginMethod::Passkey);
    let mut webp = b"RIFF".to_vec();
    let mut body = b"WEBPVP8 ".to_vec();
    let frame = [0x10, 0, 0, 0x9D, 0x01, 0x2A, 64, 0, 32, 0, 1, 2, 3, 4];
    body.extend_from_slice(&u32::try_from(frame.len()).unwrap().to_le_bytes());
    body.extend_from_slice(&frame);
    webp.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
    webp.extend_from_slice(&body);
    match c.web(&l, set_logo("light", Some(&webp))) {
        Err(ApiError::Refused { rule, .. }) => assert_eq!(rule, "I-68"),
        other => panic!("I-68: {other:?}"),
    }
    assert!(c.ports.engine.appended().is_empty());
}

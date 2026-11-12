//! The programme set-up scene of the demo (R-PG-01, R-PG-02; M4 design
//! sections 2.2 J1 and 8.2): programme manager M1 holds a SuperSAFE draft
//! that is fully built, so every creator step validates and the review
//! page shows the final report and its three previews.
//!
//! The draft is built through the API core with the operations the
//! creator pages call, as the persons of journey J1 do, and no ledger row
//! is written by hand:
//!
//! - tenant admin A1 invites a second tenant admin, who takes the
//!   invitation (`tenant.invite_admin`, SoD-07), as in the reset scene;
//! - A1 opens the draft (`creator.open_draft`, with its step-up, I-78)
//!   and grants M1 the programme manager role (core `GrantRole`, as the
//!   other seeds grant roles);
//! - M1 applies the shipped SuperSAFE template (`creator.apply_start`),
//!   accepts each template narrative (`creator.accept_narrative`, TH-49),
//!   saves every value the template leaves unset from the synthetic
//!   SuperSAFE fixture (`creator.save_fields`), and acknowledges each
//!   warning of the report (`creator.acknowledge`, I-66).
//!
//! The programme stays a draft: nobody requests its activation, so the
//! presenter can show the request. The review scenes create their
//! programme through core commands and activate it, so its creator draft
//! is empty. This scene opens a programme of its own instead, and leaves
//! those scenes and their specs unchanged.

use super::*;

use fstp_api_testkit::fake::creator_requests::supersafe_start;

/// The scene name the demo page shows.
pub(crate) const SCENE: &str = "programme_setup";

/// The binding of M1 on the draft.
const M1_BINDING: BindingId = BindingId::from_raw(3_001);

/// The tenant admin who opens the draft and grants M1 (design 2.1, A1).
const OPENER: AccountId = ADMIN;

/// One minute and one second, in microseconds. The seed moves its clock
/// by this much before each creator call, so no call meets the H-07 rate
/// of vault reads per account and minute.
const NEXT_MINUTE: i64 = 61 * SECOND;

/// A JSON string.
fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

/// The head revision of the draft of `p`, in the wire form
/// `"<seq>.<entry>"` that `creator.get_draft` shows.
fn revision(seed: &Seeder<'_>, p: ProgrammeId) -> Result<String, String> {
    let state = seed.inner.ports.engine.state();
    let r = state
        .creator
        .head(p)
        .ok_or_else(|| format!("no draft of programme {}", p.raw()))?;
    Ok(format!("{}.{}", r.seq(), r.entry().raw()))
}

/// The template narratives of the SuperSAFE start that wait for M1's
/// acceptance in the draft of `p` (TH-49): the artefact fields the
/// template sets as narrative text that the start left unset and nobody
/// accepted yet. A policy field such as P-09 is saved with its value.
fn pending_narratives(seed: &Seeder<'_>, p: ProgrammeId) -> Result<Vec<String>, String> {
    use fstp_programme::FieldValue as V;
    let template = fstp_programme::shipped_templates()
        .map_err(|e| format!("templates: {e:?}"))?
        .into_iter()
        .find(|t| t.id == fstp_programme::SUPERSAFE_TEMPLATE && t.version.get() == 1)
        .ok_or("no SuperSAFE template")?;
    let state = seed.inner.ports.engine.state();
    let d = state
        .creator
        .draft(p)
        .ok_or_else(|| format!("no draft of programme {}", p.raw()))?;
    let set = d.set_fields();
    let waits = |v: &V| {
        matches!(
            v,
            V::ActionAcronym(_)
                | V::CoordinatorName(_)
                | V::ProgrammeName(_)
                | V::ProgrammeNarrative(_)
                | V::ProgrammeScope(_)
                | V::PersonsSupported(_)
                | V::Minors(_)
                | V::AmountCriteria(_)
                | V::Faq(_)
                | V::ProgrammeContact(_)
                | V::MessageTemplates(_)
        )
    };
    Ok(fstp_programme::FieldId::ALL
        .iter()
        .filter(|f| f.spec().map(|s| s.kind) == Some(fstp_programme::FieldKind::Artefact))
        .filter(|f| match template.spec.get(**f) {
            fstp_programme::Field::Set(v) => waits(&v),
            fstp_programme::Field::Unset => false,
        })
        .filter(|f| !set.contains(f) && !d.narratives().contains(f))
        .map(|f| f.key())
        .collect())
}

/// The JSON value of the SuperSAFE fixture's field `key`,
/// `"<step>.<member>"`.
fn fixture_value(key: &str) -> Result<Value, String> {
    let v = fstp_json::parse(fstp_programme::SUPERSAFE_FIXTURE.as_bytes())
        .map_err(|e| format!("fixture: {e:?}"))?;
    let (step, member) = key.split_once('.').ok_or("field key")?;
    v.as_object()
        .and_then(|o| o.get("spec"))
        .and_then(Value::as_object)
        .and_then(|o| o.get(step))
        .and_then(Value::as_object)
        .and_then(|o| o.get(member))
        .cloned()
        .ok_or_else(|| format!("the fixture sets no {key}"))
}

/// The P-09 criteria of `value` with each inline wording stored as a
/// public text of `p` first, since no ledger body holds inline text
/// (ADR-007). A stored text is `{digest, text}`.
async fn stored_wording(seed: &Seeder<'_>, p: ProgrammeId, value: &Value) -> Result<Value, String> {
    let items = value.as_array().ok_or("P-09 is not a list")?;
    let mut out = Vec::new();
    for item in items.iter() {
        let mut o = item
            .as_object()
            .ok_or("a P-09 criterion is not an object")?
            .clone();
        if let Some(text) = o.get("text").and_then(Value::as_str).map(str::to_owned) {
            let r = seed
                .inner
                .ports
                .texts
                .put(TextClass::Public, TextOwner::Programme(p), text.as_bytes())
                .await
                .map_err(|e| format!("text: {e:?}"))?;
            let digest = wire::hex(&fstp_crypto::sha256(text.as_bytes()));
            let _ = o.insert(
                "text",
                obj(vec![("digest", s(&digest)), ("text", dec(r.0))]),
            );
        }
        out.push(Value::Object(o));
    }
    Ok(Value::Array(out.into_iter().collect::<Array>()))
}

/// The field edits M1 saves after the start: every value of the
/// SuperSAFE fixture that the draft of `p` still lacks, as the fixture
/// spells it.
async fn missing_fields(seed: &Seeder<'_>, p: ProgrammeId) -> Result<Value, String> {
    let fixture = fstp_programme::supersafe_fixture().map_err(|e| format!("fixture: {e:?}"))?;
    let set = {
        let state = seed.inner.ports.engine.state();
        state
            .creator
            .draft(p)
            .ok_or_else(|| format!("no draft of programme {}", p.raw()))?
            .set_fields()
    };
    let mut out: Vec<Value> = Vec::new();
    for f in fstp_programme::FieldId::ALL.iter() {
        if set.contains(f) {
            continue;
        }
        if let fstp_programme::Field::Set(_) = fixture.spec.get(*f) {
            let key = f.key();
            let mut value = fixture_value(&key)?;
            if *f == fstp_programme::FieldId::P09 {
                value = stored_wording(seed, p, &value).await?;
            }
            out.push(obj(vec![("field", s(&key)), ("value", value)]));
        }
    }
    Ok(Value::Array(out.into_iter().collect::<Array>()))
}

/// The rows of a report reply: check, severity, acknowledged, key.
fn report_rows(report: &Value) -> Vec<(String, String, bool, String)> {
    let Some(rows) = report
        .as_object()
        .and_then(|o| o.get("results"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    rows.iter()
        .map(|r| {
            let o = r.as_object();
            let text = |k: &str| {
                o.and_then(|o| o.get(k))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let ack = o
                .and_then(|o| o.get("acknowledged"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let check = text("check");
            let key = o
                .and_then(|o| o.get("key"))
                .and_then(Value::as_str)
                .map_or_else(|| check.clone(), str::to_owned);
            (check, text("severity"), ack, key)
        })
        .collect()
}

/// A creator call by `account` one minute after the last (H-07).
async fn creator_call(
    seed: &mut Seeder<'_>,
    account: AccountId,
    method: ApiMethod,
    path: &str,
    body: &Value,
) -> Result<Value, String> {
    seed.at(seed.now.saturating_add(NEXT_MINUTE));
    seed.api(account, method, path, body).await
}

/// Builds the draft of `p` as M1 to a report with no failure and every
/// warning acknowledged (module documentation).
async fn build_draft(seed: &mut Seeder<'_>, p: ProgrammeId) -> Result<(), String> {
    let base = format!("/programmes/{}/draft", p.raw());
    let rev = revision(seed, p)?;
    creator_call(
        seed,
        STAFF_PM,
        ApiMethod::Post,
        &format!("{base}/start"),
        &obj(vec![("base", s(&rev)), ("start", supersafe_start())]),
    )
    .await?;
    for key in pending_narratives(seed, p)? {
        let rev = revision(seed, p)?;
        creator_call(
            seed,
            STAFF_PM,
            ApiMethod::Post,
            &format!("{base}/narratives/{key}/acceptance"),
            &obj(vec![("base", s(&rev))]),
        )
        .await?;
    }
    let fields = missing_fields(seed, p).await?;
    if fields.as_array().is_some_and(|a| !a.is_empty()) {
        let rev = revision(seed, p)?;
        creator_call(
            seed,
            STAFF_PM,
            ApiMethod::Put,
            &format!("{base}/fields"),
            &obj(vec![("base", s(&rev)), ("fields", fields)]),
        )
        .await?;
    }
    // A fresh warning can follow an acknowledgement, so the report is
    // read again until it shows none unacknowledged.
    for _ in 0..3 {
        let report = creator_call(
            seed,
            STAFF_PM,
            ApiMethod::Get,
            &format!("{base}/report"),
            &Value::Null,
        )
        .await?;
        let rows = report_rows(&report);
        let failures: Vec<&str> = rows
            .iter()
            .filter(|r| r.1 == "failure")
            .map(|r| r.0.as_str())
            .collect();
        if !failures.is_empty() {
            return Err(format!(
                "the set-up draft keeps report failures: {failures:?}"
            ));
        }
        let open: Vec<String> = rows
            .into_iter()
            .filter(|r| r.1 == "warning" && !r.2)
            .map(|r| r.3)
            .collect();
        if open.is_empty() {
            return Ok(());
        }
        for key in open {
            let rev = revision(seed, p)?;
            creator_call(
                seed,
                STAFF_PM,
                ApiMethod::Post,
                &format!("{base}/acknowledgements"),
                &obj(vec![("revision", s(&rev)), ("warning", s(&key))]),
            )
            .await?;
        }
    }
    Err("the set-up draft keeps unacknowledged warnings".to_owned())
}

/// A1 invites a second tenant admin, who takes the invitation, so the
/// tenant holds the two admins of SoD-07 and one of them did not build
/// the draft (I-67). This is the path of the reset scene: the API core
/// appends the invitation and the cell plays M3's enrolment.
async fn second_admin(seed: &mut Seeder<'_>) -> Result<(), String> {
    let before = seed.inner.ports.engine.appended().len();
    seed.api(
        OPENER,
        ApiMethod::Post,
        "/admin/admins",
        &obj(vec![("email", s(&email("a2")?))]),
    )
    .await?;
    let (invitation, invitee) = crate::onboarding::appended_invitation(seed.inner, before)
        .ok_or("tenant.invite_admin appended no invitation")?;
    crate::onboarding::take(seed.inner, invitee, invitation)
}

/// A fresh state for the scene: the tenant's provisioning record, both
/// tenant admins, and M1 with a login email and a one-time enrolment
/// link. Returns the state and M1's link.
fn fresh(info: &SiteInfo) -> Result<(Inner, String), String> {
    let mut store = MemStore::new();
    crate::onboarding::provision(&mut store, OPENER, T_SETUP)?;
    let world = World {
        store,
        truth: review_truth(),
        start: Timestamp::from_micros(T_SETUP),
        admins: [ADMIN, ADMIN_2].into_iter().collect(),
    };
    let mut auth = AuthState::new(info);
    let (key, pm, label) = PROGRAMME_MANAGER;
    auth.person(&email(key)?, pm);
    let url = auth.invite(pm)?;
    let inner = Inner::new(info, &world, auth, PRIMARY_MODEL)?;
    inner.ports.accounts.name(pm, label);
    Ok((inner, url))
}

/// The programme set-up scene: a fresh cell whose draft M1 has fully
/// built. Returns the state and `{programme, people}`.
pub(crate) async fn build(info: &SiteInfo) -> Result<(Inner, Value), String> {
    let (inner, m1_url) = fresh(info)?;
    let mut seed = Seeder {
        inner: &inner,
        now: T_SETUP,
        command: 0,
        cookies: BTreeMap::new(),
    };
    seed.at(T_SETUP);
    second_admin(&mut seed).await?;
    let opened = seed
        .api(OPENER, ApiMethod::Post, "/programmes", &obj(vec![]))
        .await?;
    let p = opened
        .as_object()
        .and_then(|o| o.get("programme"))
        .and_then(Value::as_str)
        .and_then(|x| x.parse::<u128>().ok())
        .map(ProgrammeId::from_raw)
        .ok_or_else(|| format!("creator.open_draft gave {}", opened.to_compact()))?;
    seed.step(&roster::grant(
        M1_BINDING,
        STAFF_PM,
        p,
        Role::ProgrammeManager,
        seed.next(),
    ))?;
    build_draft(&mut seed, p).await?;
    inner
        .ports
        .clock
        .set(Timestamp::from_micros(T_NOW.max(seed.now)));
    let (key, _, label) = PROGRAMME_MANAGER;
    let mut people = Object::new();
    let _ = people.insert(
        key,
        obj(vec![
            ("invite_url", m1_url.as_str().into()),
            ("label", label.into()),
        ]),
    );
    let v = obj(vec![
        ("programme", dec(p.raw())),
        ("scene", SCENE.into()),
        ("people", Value::Object(people)),
    ]);
    Ok((inner, v))
}

/// A fresh cell in the programme set-up scene, for the demo page.
pub(crate) async fn demo(site: &Site) -> Result<(), String> {
    let (inner, _) = build(&site.info).await?;
    inner.set_scene(SCENE);
    site.replace(inner);
    Ok(())
}

/// `POST /test/scenario/setup`: the programme set-up scene.
pub(crate) async fn control(site: &Site) -> Response {
    match build(&site.info).await {
        Ok((inner, v)) => {
            inner.set_scene(SCENE);
            site.replace(inner);
            wire::json(StatusCode::OK, &v)
        }
        Err(e) => wire::refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fstp_rt::future::block_on;

    fn info() -> SiteInfo {
        SiteInfo {
            name: "a",
            host: "a.fstp.localhost".to_owned(),
            origin: "http://a.fstp.localhost:8640".to_owned(),
            control: "http://127.0.0.1:8641".to_owned(),
            assets: fstp_web_assets::AssetSet::from_files("main.js", &[("main.js", b"export {};")])
                .unwrap(),
            auth_assets: std::sync::Arc::new(crate::assets::AuthAssets::empty()),
            demo_signin: false,
        }
    }

    /// R-PG-01, R-PG-02, I-66: the programme set-up scene builds M1's
    /// draft from the SuperSAFE template through the creator operations.
    /// The draft stays a draft, its report shows no failure and no
    /// unacknowledged warning, and the demo line sends M1 to the set-up.
    #[test]
    fn r_pg_01_setup_scene_builds_a_draft_with_a_clean_report() {
        let (inner, v) = block_on(build(&info())).unwrap();
        let p = ProgrammeId::from_raw(
            v.as_object()
                .and_then(|o| o.get("programme"))
                .and_then(Value::as_str)
                .and_then(|x| x.parse().ok())
                .unwrap(),
        );
        let state = inner.ports.engine.state();
        assert!(state.creator.draft(p).is_some(), "M1's draft exists");
        assert_eq!(
            fstp_domain::programme::programme_status(&state.core, p),
            Some(fstp_domain::programme::ProgrammeStatus::Draft),
            "the programme stays a draft"
        );
        drop(state);
        let line = crate::demo::what_they_can_do(&inner, STAFF_PM);
        assert!(line.contains("set-up"), "{line}");
    }
}

//! The fast-flow scene of the demo (lane m4/fast-flow): the knock-out
//! criteria and the early decision, as one live chain.
//!
//! Daniel asked for "a fast-flow early decision that includes criteria
//! that the coordinator can set up". The spec gives the writing of the
//! criteria to the call drafter and their use to the FSTP coordinator
//! (roles table, SoD-01), and Daniel kept it so on 2026-11-12. The chain:
//!
//! 1. `GET /demo/fast` seeds the SuperSAFE programme, active, with call 1
//!    in DRAFT, drafted by "Call drafter D1". No proposal exists yet.
//! 2. D1 writes the knock-out criteria on "Knock-out criteria" (P-09).
//!    Programme manager M1, another person, approves and publishes the
//!    call, which freezes the criteria D1 wrote (R-PC-03, I-12).
//! 3. `GET /demo/fast/submit` drafts and submits three corpus proposals
//!    to call 1 through the production commands, as each lead, as the
//!    review seeds do. It needs call 1 published, and runs once.
//! 4. Coordinator C1 declares, then checks each proposal against the
//!    criteria D1 wrote (R-CF-02, R-EV-01).
//!
//! Test only: this module lives in `fstp-e2e-cell` and never ships.

use super::*;

use fstp_domain::programme::CallStatus;

/// The scene name the demo page shows.
pub(crate) const SCENE: &str = "fast_flow";

/// The call drafter D1: key, account and label.
const DRAFTER: (&str, AccountId, &str) = ("d1", STAFF_DRAFTER, "Call drafter D1");

/// The opening of call 1, a day after the set-up, so the call is open
/// once published.
const OPENS: i64 = T_SETUP + DAY;

/// The deadline of call 1, 30 days after the demo's clock.
const CLOSES: i64 = T_NOW + 30 * DAY;

/// The proposals the submit control sends: x, z and w.
const SUBMITTED: [&str; 3] = ["x", "z", "w"];

/// The first command number of the submit control, past every number the
/// scene's set-up used, so no two seed commands share an id.
const SUBMIT_COMMANDS: u32 = 10_000;

/// The label of D1, for the demo page.
pub(crate) fn label(account: AccountId) -> Option<&'static str> {
    (account == DRAFTER.1).then_some(DRAFTER.2)
}

/// The demo routes of the scene, or `None` for any other path.
pub(crate) async fn route(site: &Site, req: &Request) -> Option<Response> {
    let done = match req.target.path() {
        "/demo/fast" => demo(site).await,
        "/demo/fast/submit" => submit(site).await,
        _ => return None,
    };
    Some(match done {
        Ok(()) => {
            let mut r = Response::new(StatusCode::SEE_OTHER);
            let _ = r.headers.try_insert("location", "/demo");
            r
        }
        Err(e) => wire::refuse(StatusCode::CONFLICT, &e),
    })
}

/// The scene's line on the demo page, under "Scenes".
pub(crate) fn links_html() -> String {
    "<p id=\"demo-fast-flow\">Fast flow (criteria and the early decision): \
<a href=\"/demo/fast\">fast_flow</a> | \
<a href=\"/demo/fast/submit\">Submit the synthetic proposals to call 1</a> \
<span class=\"muted\">(once a programme manager has published call 1)</span></p>\n"
        .to_owned()
}

/// A fresh cell in the scene: the review cast, M1 and D1, the active
/// programme and call 1 in DRAFT.
async fn demo(site: &Site) -> Result<(), String> {
    let inner = build(&site.info).await?;
    site.replace(inner);
    Ok(())
}

/// The cell state of the scene.
async fn build(info: &SiteInfo) -> Result<Inner, String> {
    let (inner, _, _) = fresh_review(info)?;
    {
        let mut auth = lock_auth(&inner);
        let mail = email(DRAFTER.0)?;
        auth.person(&mail, DRAFTER.1);
        auth.invite(DRAFTER.1)?;
    }
    inner.ports.accounts.name(DRAFTER.1, DRAFTER.2);
    let mut seed = Seeder {
        inner: &inner,
        now: T_SETUP,
        command: 0,
        cookies: BTreeMap::new(),
    };
    set_up(&mut seed).await?;
    inner
        .ports
        .clock
        .set(Timestamp::from_micros(T_NOW.max(seed.now)));
    inner.set_scene(SCENE);
    Ok(inner)
}

/// The programme, its activation, the staff and Judging grants, and call 1
/// drafted by D1, not yet approved.
async fn set_up(seed: &mut Seeder<'_>) -> Result<(), String> {
    seed.at(T_SETUP);
    let policy = supersafe(seed).await?;
    seed.step(&Step::by(
        ADMIN,
        Flags::ADMIN,
        Core::CreateProgramme {
            policy: Box::new(policy),
        },
    ))?;
    seed.step(&fstp_domain_testkit::activation::activation_step(PROGRAMME))?;
    let [pm, drafter] = staff_bindings(PROGRAMME);
    seed.step(&roster::grant(
        pm,
        STAFF_PM,
        PROGRAMME,
        Role::ProgrammeManager,
        seed.next(),
    ))?;
    seed.step(&roster::grant(
        drafter,
        STAFF_DRAFTER,
        PROGRAMME,
        Role::CallDrafter,
        seed.next(),
    ))?;
    for (i, p) in (0u128..).zip(PERSONAS.iter()) {
        let mut step = roster::grant(
            BindingId::from_raw(2_000u128.saturating_add(i)),
            p.account,
            PROGRAMME,
            p.role,
            seed.next(),
        );
        if let Core::GrantRole { organisation, .. } = &mut step.cmd {
            *organisation = p.organisation;
        }
        seed.step(&step)?;
    }
    let zone = ZoneName::new("Europe/Brussels").ok_or("zone")?;
    let text = seed.public_text(CALL_TITLE).await?;
    seed.by(
        STAFF_DRAFTER,
        Core::DraftCall {
            call: CALL,
            programme: PROGRAMME,
            opens: Timestamp::from_micros(OPENS),
            deadline: Timestamp::from_micros(CLOSES),
            deadline_zone: zone,
            budget: NonNegAmount::new(eur(40_000_000)?).map_err(|e| format!("{e:?}"))?,
            text,
        },
    )
}

/// Drafts and submits x, z and w to call 1, each as its lead, and gives
/// each lead a sign-in link on the demo page. Refused before call 1 is
/// published. A second run changes nothing.
async fn submit(site: &Site) -> Result<(), String> {
    submit_on(&site.inner()).await
}

/// [`submit`] on the cell state `inner`.
async fn submit_on(inner: &Inner) -> Result<(), String> {
    if inner.scene() != SCENE {
        return Err("choose the fast_flow scene first".to_owned());
    }
    let published = inner
        .ports
        .engine
        .state()
        .core
        .calls()
        .get(CALL)
        .is_some_and(|c| c.status() == CallStatus::Published);
    if !published {
        return Err(
            "call 1 is not published yet: programme manager M1 approves and publishes it first"
                .to_owned(),
        );
    }
    let which: Vec<Seeded> = SUBMITTED
        .iter()
        .map(|k| proposal(k))
        .collect::<Result<_, _>>()?;
    let core = inner.ports.engine.state().core.clone();
    if which
        .iter()
        .any(|s| fstp_domain::view::proposal_state(&core, s.proposal).is_some())
    {
        return Ok(());
    }
    {
        let mut auth = lock_auth(inner);
        for s in &which {
            auth.invite(s.lead)?;
        }
    }
    let mut seed = Seeder {
        inner,
        now: inner.ports.clock.read().micros(),
        command: SUBMIT_COMMANDS,
        cookies: BTreeMap::new(),
    };
    super::submit(&mut seed, &which).await?;
    inner.ports.clock.set(Timestamp::from_micros(seed.now));
    Ok(())
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

    fn text<'a>(v: &'a Value, key: &str) -> &'a str {
        v.get(key)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no {key} in {}", v.to_compact()))
    }

    /// The criteria Call drafter D1 writes in the demo.
    const WRITTEN: [&str; 2] = [
        "Synthetic: the proposal builds open source software for the Open Internet Stack.",
        "Synthetic: research and development is the primary objective.",
    ];

    /// R-EV-01, R-PC-03, R-CF-02 (lane m4/fast-flow): the whole chain on
    /// one cell state through the API core. D1 writes the knock-out
    /// criteria, M1 approves and publishes call 1, three proposals are
    /// submitted, and C1 checks them against the criteria D1 wrote, by
    /// their text in P-09 order. A failed check needs its reason, makes
    /// the proposal INELIGIBLE, and its lead reads the reason (O-54).
    #[test]
    fn r_ev_01_r_pc_03_fast_flow_chain_checks_the_criteria_the_drafter_wrote() {
        let inner = block_on(build(&info())).unwrap();
        let mut seed = Seeder {
            inner: &inner,
            now: inner.ports.clock.read().micros(),
            command: 20_000,
            cookies: BTreeMap::new(),
        };
        let p = PROGRAMME.raw();
        // The call drafter reads the draft and writes P-09.
        let draft = block_on(seed.api(
            STAFF_DRAFTER,
            ApiMethod::Get,
            &format!("/programmes/{p}/draft"),
            &Value::Null,
        ))
        .unwrap();
        let base = text(&draft, "revision").to_owned();
        let items: Vec<Value> = (1u32..)
            .zip(WRITTEN)
            .map(|(i, t)| {
                obj(vec![
                    ("id", i.to_string().as_str().into()),
                    ("text", t.into()),
                ])
            })
            .collect();
        let save = obj(vec![
            ("base", base.as_str().into()),
            (
                "fields",
                Value::Array(
                    vec![obj(vec![
                        ("field", "evaluation.p09_knock_outs".into()),
                        ("value", Value::Array(items.into_iter().collect())),
                    ])]
                    .into_iter()
                    .collect(),
                ),
            ),
        ]);
        block_on(seed.api(
            STAFF_DRAFTER,
            ApiMethod::Put,
            &format!("/programmes/{p}/draft/fields"),
            &save,
        ))
        .unwrap();
        // The drafter changes no other parameter (roles table).
        let other = obj(vec![
            ("base", base.as_str().into()),
            (
                "fields",
                Value::Array(
                    vec![obj(vec![
                        ("field", "evaluation.p28_rubric_bands".into()),
                        ("value", Value::Bool(false)),
                    ])]
                    .into_iter()
                    .collect(),
                ),
            ),
        ]);
        assert!(
            block_on(seed.api(
                STAFF_DRAFTER,
                ApiMethod::Put,
                &format!("/programmes/{p}/draft/fields"),
                &other
            ))
            .is_err(),
            "a call drafter saves P-09 only"
        );
        // The drafter cannot approve the call (R-PC-03); M1 approves and publishes.
        let c = CALL.raw();
        assert!(
            block_on(seed.api(
                STAFF_DRAFTER,
                ApiMethod::Post,
                &format!("/calls/{c}/approval"),
                &obj(vec![])
            ))
            .is_err()
        );
        block_on(seed.api(
            STAFF_PM,
            ApiMethod::Post,
            &format!("/calls/{c}/approval"),
            &obj(vec![]),
        ))
        .unwrap();
        block_on(seed.api(
            STAFF_PM,
            ApiMethod::Post,
            &format!("/calls/{c}/publication"),
            &obj(vec![]),
        ))
        .unwrap();
        // The proposals arrive through the demo control.
        block_on(submit_on(&inner)).unwrap();
        let mut seed = Seeder {
            inner: &inner,
            now: inner.ports.clock.read().micros(),
            command: 30_000,
            cookies: BTreeMap::new(),
        };
        // The coordinator sees the drafter's criteria, by text, in P-09 order.
        let queue = block_on(seed.api(
            COORDINATOR,
            ApiMethod::Get,
            &format!("/calls/{c}/intake"),
            &Value::Null,
        ))
        .unwrap();
        let criteria = queue.get("knock_out").and_then(Value::as_array).unwrap();
        let shown: Vec<&str> = criteria.iter().map(|k| text(k, "text")).collect();
        assert_eq!(shown, WRITTEN.to_vec());
        let ids: Vec<Value> = criteria
            .iter()
            .map(|k| k.get("id").cloned().unwrap())
            .collect();
        let x = proposal("x").unwrap();
        let z = proposal("z").unwrap();
        for s in [x, z] {
            block_on(seed.api(
                COORDINATOR,
                ApiMethod::Post,
                &format!("/proposals/{}/coordinator-declaration", s.proposal.raw()),
                &obj(vec![
                    ("conflicted", false.into()),
                    ("notifiable", false.into()),
                ]),
            ))
            .unwrap();
        }
        let outcomes = |fail_first: bool| -> Value {
            Value::Array(
                ids.iter()
                    .enumerate()
                    .map(|(i, id)| {
                        obj(vec![
                            ("criterion", id.clone()),
                            ("passed", (!(fail_first && i == 0)).into()),
                        ])
                    })
                    .collect(),
            )
        };
        // R-EV-01: a failed criterion needs its reason.
        assert!(
            block_on(seed.api(
                COORDINATOR,
                ApiMethod::Post,
                &format!("/proposals/{}/knock-out", z.proposal.raw()),
                &obj(vec![("outcomes", outcomes(true))]),
            ))
            .is_err()
        );
        let reason = "Synthetic: the proposal builds a closed protocol bridge.";
        block_on(seed.api(
            COORDINATOR,
            ApiMethod::Post,
            &format!("/proposals/{}/knock-out", z.proposal.raw()),
            &obj(vec![
                ("outcomes", outcomes(true)),
                ("reason", reason.into()),
            ]),
        ))
        .unwrap();
        block_on(seed.api(
            COORDINATOR,
            ApiMethod::Post,
            &format!("/proposals/{}/knock-out", x.proposal.raw()),
            &obj(vec![("outcomes", outcomes(false))]),
        ))
        .unwrap();
        let core = inner.ports.engine.state().core.clone();
        let state = |s: &Seeded| {
            fstp_domain::view::proposal_state(&core, s.proposal).map(|t| t.spec_name())
        };
        assert_eq!(state(&z), Some("INELIGIBLE"));
        assert_eq!(
            state(&x),
            Some("SUBMITTED"),
            "a pass waits for its reviewers (R-EV-02)"
        );
        // O-54: the lead of z reads the recorded reason.
        let mine =
            block_on(seed.api(z.lead, ApiMethod::Get, "/me/proposals", &Value::Null)).unwrap();
        let row = mine
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|r| r.get("proposal").and_then(Value::as_str) == Some("1002"))
            })
            .unwrap_or_else(|| panic!("no row of z in {}", mine.to_compact()));
        assert_eq!(text(row, "state"), "INELIGIBLE");
        assert_eq!(text(row, "knock_out_reason"), reason);
    }
}

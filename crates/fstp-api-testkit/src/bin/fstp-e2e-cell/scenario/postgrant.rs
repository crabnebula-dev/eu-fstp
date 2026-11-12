//! The post-grant seeds of the demo (M5 design section 7 and M6 design
//! section 8, lane L-DEMO), built through the API core and the engine.
//!
//! A seed starts from the `NEGOTIATION` applicant seed: the synthetic
//! SuperSAFE call, proposal x with its lead and its assigned reviewers.
//! It then walks proposal x through the post-grant lifecycle with the
//! operations that the screens call, as the persons of the design do.
//! No seed writes a ledger row by hand. The vault facts of a bank detail
//! write are the one fake: the cell's vault origin has no real page, so a
//! seed that needs a verified bank detail writes it into the synthetic
//! vault the way the vault origin would (M5 design section 7).
//!
//! The scenes, in the order a grant lives:
//!
//! | Scene | What the cell holds |
//! | --- | --- |
//! | `NEGOTIATION_READY` | x in NEGOTIATION, nothing determined yet, every post-grant person enrolled |
//! | `SENT` | amount determined, accepted and approved. Contract drafted, one clause change agreed, sent |
//! | `EFFECTIVE` | the lead and the signatory signed, x is GRANTED |
//! | `IN_EXECUTION` | the clock passed the first milestone start, x is IN_EXECUTION |
//! | `UNDER_REVIEW` | the lead requested payment of milestone 1 with deliverable evidence, the checks passed |
//! | `PAID` | line accepted, approved, released after the bank hold and confirmed paid |
//! | `ALL_CLOSED` | the milestone closed, x COMPLETED, five funder outputs generated and approved |
//! | `HARDSHIP` | x IN_EXECUTION. The lead submitted a hardship request. Finance verifies the evidence on the vault page |
//!
//! Interim readings of this lane, logged in `docs/handoff/m5-demo.md`:
//!
//! - Checks run in the pump of the demo cell (`crate::pump`), which
//!   plays the checks runner against the fake forge.

use super::*;

use fstp_domain::command::{Actor, Ctx, SystemCause, Via};

/// The account of the finance approver.
pub(crate) const FINANCE: AccountId = AccountId::from_raw(601);
/// The account of the payment releaser.
pub(crate) const RELEASER: AccountId = AccountId::from_raw(602);
/// The account of the contract signatory.
pub(crate) const SIGNATORY: AccountId = AccountId::from_raw(603);
/// The account of the auditor.
pub(crate) const AUDITOR: AccountId = AccountId::from_raw(604);
/// The lead of proposal x, who signs in to run the grant.
pub(crate) const LEAD_X: AccountId = L1;
/// The front-door label of that lead.
pub(crate) const LEAD_LABEL: &str = "Lead applicant X";

/// The account of the report approver, the Financial signatory of the
/// tenant (R-RP-03, Q3).
pub(crate) const REPORT_APPROVER: AccountId = AccountId::from_raw(605);

/// The post-grant people with a programme role. They are enrolled in every
/// post-grant scene, and the Playwright speedrun signs them in.
pub(crate) const EXTRAS: [Persona; 4] = [
    Persona {
        key: "fin",
        account: FINANCE,
        role: Role::FinanceApprover,
        organisation: None,
        label: "Finance approver F1",
    },
    Persona {
        key: "rel",
        account: RELEASER,
        role: Role::PaymentReleaser,
        organisation: None,
        label: "Payment releaser P1",
    },
    Persona {
        key: "sig",
        account: SIGNATORY,
        role: Role::ContractSignatory,
        organisation: None,
        label: "Contract signatory S1",
    },
    Persona {
        key: "aud",
        account: AUDITOR,
        role: Role::Auditor,
        organisation: None,
        label: "Auditor A1",
    },
];

/// The Financial signatory, who holds no programme role.
pub(crate) const REPORT_PERSON: (&str, AccountId, &str) = (
    "rep",
    REPORT_APPROVER,
    "Report approver (Financial signatory) F2",
);

/// The label of a post-grant person, such as `Finance approver F1`.
pub(crate) fn label(account: AccountId) -> Option<&'static str> {
    if account == REPORT_PERSON.1 {
        return Some(REPORT_PERSON.2);
    }
    if account == LEAD_X {
        return Some(LEAD_LABEL);
    }
    EXTRAS
        .iter()
        .find(|p| p.account == account)
        .map(|p| p.label)
}

/// The label of the post-grant persona with `key`.
pub(crate) fn label_of_key(key: &str) -> &'static str {
    if key == REPORT_PERSON.0 {
        return REPORT_PERSON.2;
    }
    EXTRAS.iter().find(|p| p.key == key).map_or("", |p| p.label)
}

/// The vault facts of the post-grant people: each holds a verified
/// identity of its own.
pub(crate) fn truth(t: &mut GroundTruth) {
    for account in EXTRAS.iter().map(|p| p.account).chain([REPORT_APPROVER]) {
        t.set_identity(account, tag(account));
        t.verify(account);
    }
}

/// The scenes of `GET /demo/grant?at=`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum GrantAt {
    NegotiationReady,
    Sent,
    Effective,
    InExecution,
    UnderReview,
    Paid,
    AllClosed,
    /// Not on the path to ALL_CLOSED: a branch from IN_EXECUTION.
    Hardship,
}

/// The names of the scenes, in the order a grant lives.
pub(crate) const SCENES: [&str; 8] = [
    "NEGOTIATION_READY",
    "SENT",
    "EFFECTIVE",
    "IN_EXECUTION",
    "UNDER_REVIEW",
    "PAID",
    "ALL_CLOSED",
    "HARDSHIP",
];

impl GrantAt {
    pub(crate) fn parse(s: &str) -> Option<GrantAt> {
        Some(match s {
            "NEGOTIATION_READY" => GrantAt::NegotiationReady,
            "SENT" => GrantAt::Sent,
            "EFFECTIVE" => GrantAt::Effective,
            "IN_EXECUTION" => GrantAt::InExecution,
            "UNDER_REVIEW" => GrantAt::UnderReview,
            "PAID" => GrantAt::Paid,
            "ALL_CLOSED" => GrantAt::AllClosed,
            "HARDSHIP" => GrantAt::Hardship,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        SCENES
            .get(self as usize)
            .copied()
            .unwrap_or("NEGOTIATION_READY")
    }
}

/// The reviewer who determines the amount, from the stage 1 assignments.
const DETERMINER: AccountId = R1;

/// The ids a grant seed leaves behind, for the reply and the specs.
#[derive(Default)]
struct Reached {
    contract: Option<String>,
    request: Option<String>,
    reports: Vec<(String, String)>,
}

/// The hardship evidence reference of grant x. The vault draws it in a
/// production cell. The synthetic vault uses this one, so the seeded
/// request and the vault page agree (R-PR-04).
pub(crate) fn hardship_evidence(x: ProposalId) -> fstp_domain::id::HardshipEvidenceId {
    fstp_domain::id::HardshipEvidenceId::from_raw(x.raw().saturating_add(8_000))
}

/// The first milestone start of proposal x.
fn first_milestone_start() -> i64 {
    DEADLINE.saturating_add(40 * DAY)
}

/// The context of a system command at the cell clock.
fn system_ctx(now: Timestamp, command: CommandId, cause: SystemCause) -> Ctx {
    Ctx {
        now,
        actor: Actor::System(cause),
        command,
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

/// Runs `cmd` as the system `cause` at the next instant of the seed.
fn system(seed: &mut Seeder<'_>, cause: SystemCause, cmd: Core) -> Result<(), String> {
    let kind = cmd.kind();
    let now = seed.tick();
    seed.command = seed.command.saturating_add(1);
    let mut id = *b"fstp:e2e:sys\0\0\0\0";
    for (slot, b) in id.iter_mut().skip(12).zip(seed.command.to_be_bytes()) {
        *slot = b;
    }
    seed.inner
        .ports
        .engine
        .environment(
            fstp_engine::Command::Core(cmd),
            system_ctx(now, CommandId::from_bytes(id), cause),
        )
        .map(|_| ())
        .map_err(|e| format!("{kind:?} by the system: {e}"))
}

/// Runs every sweep command that is due at the seed's clock.
fn sweep(seed: &mut Seeder<'_>) -> Result<(), String> {
    let state = seed.inner.ports.engine.state();
    let due = fstp_engine::sweep::due(&state, Timestamp::from_micros(seed.now))
        .map_err(|e| format!("sweep: {e:?}"))?;
    for cmd in due {
        if let fstp_engine::Command::Core(core) = cmd {
            system(seed, SystemCause::Timeline, core)?;
        }
    }
    Ok(())
}

/// The id of a member of a reply, such as the `determination` of
/// `GET /grants/{x}`.
fn member(v: &Value, key: &str) -> Result<String, String> {
    v.as_object()
        .and_then(|o| wire::str_member(o, key))
        .map(str::to_owned)
        .ok_or_else(|| format!("the reply has no {key}: {}", v.to_compact()))
}

/// Grants the post-grant roles and the Financial signatory.
async fn people(seed: &mut Seeder<'_>) -> Result<(), String> {
    for (i, p) in (0u128..).zip(EXTRAS.iter()) {
        seed.step(&roster::grant(
            BindingId::from_raw(3_000u128.saturating_add(i)),
            p.account,
            PROGRAMME,
            p.role,
            seed.next(),
        ))?;
    }
    seed.api(
        ADMIN,
        ApiMethod::Post,
        "/admin/signatories",
        &obj(vec![
            ("account", dec(REPORT_APPROVER.raw())),
            ("role", "financial_signatory".into()),
        ]),
    )
    .await?;
    Ok(())
}

/// Determination, acceptance and approval of the amount of x (R-NG-03).
async fn amount(seed: &mut Seeder<'_>, x: ProposalId) -> Result<(), String> {
    seed.api(
        DETERMINER,
        ApiMethod::Post,
        &format!("/grants/{}/amount-determination", x.raw()),
        &obj(vec![
            ("agreed", dec(plan_of(x).raw())),
            ("deductions", Value::Array(Array::new())),
            ("currency", "EUR".into()),
        ]),
    )
    .await?;
    let overview = seed
        .api(
            PROPOSALS[0].lead,
            ApiMethod::Get,
            &format!("/grants/{}", x.raw()),
            &Value::Null,
        )
        .await?;
    let det = obj(vec![(
        "determination",
        member(&overview, "determination")?.into(),
    )]);
    seed.api(
        PROPOSALS[0].lead,
        ApiMethod::Post,
        &format!("/grants/{}/acceptance", x.raw()),
        &det,
    )
    .await?;
    seed.api(
        STAFF_PM,
        ApiMethod::Post,
        &format!("/grants/{}/approval", x.raw()),
        &det,
    )
    .await?;
    Ok(())
}

/// The contract of x drafted, one clause change agreed, then sent.
async fn contract_sent(seed: &mut Seeder<'_>, x: ProposalId) -> Result<String, String> {
    let lead = PROPOSALS[0].lead;
    let v = seed
        .api(
            STAFF_PM,
            ApiMethod::Post,
            &format!("/grants/{}/contract", x.raw()),
            &obj(vec![]),
        )
        .await?;
    let k = member(&v, "contract")?;
    seed.api(
        lead,
        ApiMethod::Post,
        &format!("/contracts/{k}/changes"),
        &obj(vec![
            ("clause", wire::int(1)),
            (
                "text",
                "Synthetic change: the milestone report is due in English.".into(),
            ),
        ]),
    )
    .await?;
    seed.api(
        STAFF_PM,
        ApiMethod::Post,
        &format!("/contracts/{k}/changes/1/decision"),
        &obj(vec![("accept", Value::Bool(true))]),
    )
    .await?;
    seed.api(
        STAFF_PM,
        ApiMethod::Post,
        &format!("/contracts/{k}/send"),
        &obj(vec![]),
    )
    .await?;
    Ok(k)
}

/// The lead and the signatory sign, through the fake wallet and QTSP.
async fn contract_signed(seed: &mut Seeder<'_>, k: &str) -> Result<(), String> {
    seed.api(
        PROPOSALS[0].lead,
        ApiMethod::Post,
        &format!("/contracts/{k}/signature"),
        &obj(vec![("route", "wallet_qes".into())]),
    )
    .await?;
    seed.api(
        SIGNATORY,
        ApiMethod::Post,
        &format!("/contracts/{k}/signature"),
        &obj(vec![("route", "qtsp_remote_qes".into())]),
    )
    .await?;
    Ok(())
}

/// The milestone of x.
fn milestone_of(x: ProposalId) -> MilestoneId {
    MilestoneId::from_raw(x.raw().saturating_add(6_000))
}

/// The payment request of milestone 1 of x, with evidence of the fake
/// forge (the `/demo/forge/` release that exists).
pub(crate) fn request_body(x: ProposalId, release: &str) -> Value {
    let line = obj(vec![
        ("milestone", dec(milestone_of(x).raw())),
        ("amount", "60000.00".into()),
        (
            "evidence",
            obj(vec![
                ("location", crate::pump::FORGE_REPO.into()),
                ("release", release.into()),
                ("licence", "MIT".into()),
                (
                    "report",
                    "Synthetic delivery report: the sensor kit shipped.".into(),
                ),
            ]),
        ),
    ]);
    obj(vec![
        ("kind", obj(vec![("type", "Milestone".into())])),
        ("currency", "EUR".into()),
        ("lines", Value::Array(Array::from(vec![line]))),
    ])
}

/// The hardship request of x: the milestone request with the hardship
/// kind and its evidence reference.
pub(crate) fn hardship_body(x: ProposalId, release: &str) -> Value {
    let Value::Object(mut o) = request_body(x, release) else {
        return request_body(x, release);
    };
    let _ = o.insert(
        "kind",
        obj(vec![
            ("type", "Hardship".into()),
            ("evidence", dec(hardship_evidence(x).raw())),
        ]),
    );
    Value::Object(o)
}

/// Seeds `at` and returns what it reached.
async fn seed_grant(seed: &mut Seeder<'_>, at: GrantAt) -> Result<Reached, String> {
    let mut reached = Reached::default();
    let (seeded, _, _) = seed_applicant(seed, At::Negotiation).await?;
    let s = seeded.ok_or("no proposal")?;
    let x = s.proposal;
    people(seed).await?;
    if at == GrantAt::NegotiationReady {
        return Ok(reached);
    }
    amount(seed, x).await?;
    let k = contract_sent(seed, x).await?;
    reached.contract = Some(k.clone());
    if at == GrantAt::Sent {
        return Ok(reached);
    }
    contract_signed(seed, &k).await?;
    if at == GrantAt::Effective {
        return Ok(reached);
    }
    seed.at(first_milestone_start().saturating_add(SECOND));
    sweep(seed)?;
    if at == GrantAt::InExecution {
        return Ok(reached);
    }
    if at == GrantAt::Hardship {
        // R-PR-04: the lead asks for the hardship ticket and files a
        // hardship request that names the evidence. Finance verifies the
        // evidence on the vault page. Only operations run here.
        seed.api(
            s.lead,
            ApiMethod::Post,
            &format!("/grants/{}/hardship-evidence", x.raw()),
            &obj(vec![]),
        )
        .await?;
        let v = seed
            .api(
                s.lead,
                ApiMethod::Post,
                &format!("/grants/{}/payment-requests", x.raw()),
                &hardship_body(x, crate::pump::FORGE_RELEASE),
            )
            .await?;
        reached.request = Some(member(&v, "request")?);
        crate::pump::run_checks_now(seed.inner, Timestamp::from_micros(seed.now))?;
        return Ok(reached);
    }
    let v = seed
        .api(
            s.lead,
            ApiMethod::Post,
            &format!("/grants/{}/payment-requests", x.raw()),
            &request_body(x, crate::pump::FORGE_RELEASE),
        )
        .await?;
    let request = member(&v, "request")?;
    reached.request = Some(request.clone());
    crate::pump::run_checks_now(seed.inner, Timestamp::from_micros(seed.now))?;
    if at == GrantAt::UnderReview {
        return Ok(reached);
    }
    let r: u128 = request.parse().map_err(|_| "request id".to_owned())?;
    let line = seed
        .inner
        .ports
        .engine
        .state()
        .core
        .payments()
        .summaries()
        .filter(|q| q.request.raw() == r)
        .flat_map(|q| q.lines.into_iter().map(|l| l.line))
        .next()
        .ok_or("the request has no line")?;
    seed.api(
        DETERMINER,
        ApiMethod::Post,
        &format!("/payment-requests/{r}/lines/{}/decision", line.raw()),
        &obj(vec![
            ("approved", "60000.00".into()),
            ("currency", "EUR".into()),
        ]),
    )
    .await?;
    seed.api(
        FINANCE,
        ApiMethod::Post,
        &format!("/payment-requests/{r}/approval"),
        &obj(vec![]),
    )
    .await?;
    // I-33: the lead entered the bank details long before, and finance
    // verified them, so the P-36 hold has passed.
    seed.inner.ports.vault.change(|t| {
        t.write_bank(x, Timestamp::from_micros(T_SETUP));
        t.verify_bank(x);
    });
    seed.api(
        RELEASER,
        ApiMethod::Post,
        &format!("/payment-requests/{r}/release"),
        &obj(vec![]),
    )
    .await?;
    seed.api(
        RELEASER,
        ApiMethod::Post,
        &format!("/payment-requests/{r}/payee"),
        &obj(vec![]),
    )
    .await?;
    seed.api(
        FINANCE,
        ApiMethod::Post,
        &format!("/payment-requests/{r}/paid"),
        &obj(vec![]),
    )
    .await?;
    if at == GrantAt::Paid {
        return Ok(reached);
    }
    seed.api(
        STAFF_PM,
        ApiMethod::Post,
        &format!(
            "/grants/{}/milestones/{}/closure",
            x.raw(),
            milestone_of(x).raw()
        ),
        &obj(vec![(
            "reason",
            "Synthetic closure: the milestone was delivered and paid.".into(),
        )]),
    )
    .await?;
    sweep(seed)?;
    reached.reports = reports(seed).await?;
    Ok(reached)
}

/// Generates the five funder outputs the API core builds, and has the
/// Financial signatory approve each (R-RP-04, R-RP-03, I-44).
async fn reports(seed: &mut Seeder<'_>) -> Result<Vec<(String, String)>, String> {
    let from = T_SETUP;
    let to = seed.now.saturating_add(DAY);
    let mut out = Vec::new();
    for kind in [
        "call_publication_record",
        "periodic_reporting_data",
        "audit_file",
        "deliverable_draft",
        "open_call_package",
    ] {
        let mut body = vec![("kind", Value::from(kind)), ("call", dec(CALL.raw()))];
        if kind == "periodic_reporting_data" {
            body.push(("start", from.to_string().as_str().into()));
            body.push(("end", to.to_string().as_str().into()));
        }
        let v = seed
            .api(
                STAFF_PM,
                ApiMethod::Post,
                &format!("/programmes/{}/reports", PROGRAMME.raw()),
                &obj(body),
            )
            .await?;
        let id = member(&v, "report")?;
        seed.api(
            REPORT_APPROVER,
            ApiMethod::Post,
            &format!("/reports/{id}/approval"),
            &obj(vec![]),
        )
        .await?;
        out.push((kind.to_owned(), id));
    }
    Ok(out)
}

/// A fresh cell seeded at `at`, with its front-door reply.
pub(crate) async fn build(info: &SiteInfo, at: GrantAt) -> Result<(Inner, Value), String> {
    let (inner, _people, _canaries) = fresh_review_with(info, true)?;
    {
        let mut auth = lock_auth(&inner);
        let mail = email("lead-x-self")?;
        auth.person(&mail, LEAD_X);
        let _ = auth.invite(LEAD_X)?;
        for p in EXTRAS
            .iter()
            .map(|p| (p.key, p.account, p.label))
            .chain([REPORT_PERSON])
        {
            let mail = email(p.0)?;
            auth.person(&mail, p.1);
            let _ = auth.invite(p.1)?;
        }
    }
    for p in EXTRAS
        .iter()
        .map(|p| (p.account, p.label))
        .chain([(REPORT_PERSON.1, REPORT_PERSON.2)])
    {
        inner.ports.accounts.name(p.0, p.1);
    }
    let mut seed = Seeder {
        inner: &inner,
        now: T_SETUP,
        command: 0,
        cookies: BTreeMap::new(),
    };
    let reached = seed_grant(&mut seed, at).await?;
    inner
        .ports
        .clock
        .set(Timestamp::from_micros(T_NOW.max(seed.now)));
    let reports: Vec<Value> = reached
        .reports
        .iter()
        .map(|(k, id)| {
            obj(vec![
                ("kind", k.as_str().into()),
                ("report", id.as_str().into()),
            ])
        })
        .collect();
    let v = obj(vec![
        ("grant_at", at.name().into()),
        ("programme", dec(PROGRAMME.raw())),
        ("call", dec(CALL.raw())),
        ("proposal", dec(PROPOSALS[0].proposal.raw())),
        ("title", PROPOSALS[0].title.into()),
        ("plan", dec(plan_of(PROPOSALS[0].proposal).raw())),
        ("milestone", dec(milestone_of(PROPOSALS[0].proposal).raw())),
        (
            "contract",
            reached.contract.as_deref().map_or(Value::Null, Value::from),
        ),
        (
            "request",
            reached.request.as_deref().map_or(Value::Null, Value::from),
        ),
        ("reports", Value::Array(reports.into_iter().collect())),
    ]);
    Ok((inner, v))
}

/// `POST /test/scenario/grant {at}`.
pub(crate) async fn control(site: &Site, req: &Request) -> Response {
    let Some(body) = wire::body(req) else {
        return wire::bad("body");
    };
    let name = wire::str_member(&body, "at").unwrap_or_default().to_owned();
    let Some(at) = GrantAt::parse(&name) else {
        return wire::bad("at");
    };
    match build(&site.info, at).await {
        Ok((inner, v)) => {
            inner.set_scene(&name);
            site.replace(inner);
            wire::json(StatusCode::OK, &v)
        }
        Err(e) => wire::refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

/// A fresh cell seeded at `at`, for the demo page.
pub(crate) async fn demo(site: &Site, name: &str) -> Result<(), String> {
    let at = GrantAt::parse(name).ok_or_else(|| "at".to_owned())?;
    let (inner, _) = build(&site.info, at).await?;
    inner.set_scene(name);
    site.replace(inner);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fstp_domain::StateTag;
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

    /// M5 exit "a call cycle runs through to PAID", R-PR-01, R-RP-04, I-05,
    /// I-30, I-31, I-33, I-44: each post-grant scene builds through the
    /// operations and leaves proposal x in the state its name says.
    #[test]
    fn m5_demo_grant_scenes_reach_their_states() {
        let want = [
            (GrantAt::NegotiationReady, StateTag::Negotiation),
            (GrantAt::Sent, StateTag::Negotiation),
            (GrantAt::Effective, StateTag::Granted),
            (GrantAt::InExecution, StateTag::InExecution),
            (GrantAt::UnderReview, StateTag::InExecution),
            (GrantAt::Paid, StateTag::InExecution),
            (GrantAt::AllClosed, StateTag::Completed),
            (GrantAt::Hardship, StateTag::InExecution),
        ];
        for (at, tag) in want {
            let (inner, v) = block_on(build(&info(), at)).unwrap_or_else(|e| panic!("{at:?}: {e}"));
            let state = inner.ports.engine.state();
            let x = PROPOSALS[0].proposal;
            assert_eq!(
                fstp_domain::view::proposal_state(&state.core, x),
                Some(tag),
                "{at:?}: {}",
                v.to_compact()
            );
            let paid = state
                .core
                .payments()
                .summaries()
                .any(|s| s.status == fstp_domain::payment::RequestStatus::Paid);
            assert_eq!(
                paid,
                at >= GrantAt::Paid && at != GrantAt::Hardship,
                "{at:?}"
            );
            // R-PR-04: the hardship scene holds one hardship request, whose
            // evidence the vault has not verified yet.
            let hardship: Vec<_> = state
                .core
                .payments()
                .summaries()
                .filter(|s| s.hardship)
                .collect();
            assert_eq!(
                hardship.len(),
                usize::from(at == GrantAt::Hardship),
                "{at:?}"
            );
            assert!(
                !inner
                    .ports
                    .vault
                    .truth()
                    .hardship_verified(x, hardship_evidence(x)),
                "{at:?}: finance verifies on the vault page"
            );
            let reports = v
                .get("reports")
                .and_then(Value::as_array)
                .map_or(0, |a| a.len());
            assert_eq!(
                reports,
                if at == GrantAt::AllClosed { 5 } else { 0 },
                "{at:?}"
            );
        }
    }
}

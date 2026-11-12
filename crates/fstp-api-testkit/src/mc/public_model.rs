//! M-PUBLIC, the reference filter and the public worlds (M4 design
//! sections 3.10, 8.4 and 8.5). Lane W2c's test author owns this file.
//!
//! # Worlds
//!
//! [`PublicWorld::build`] runs one money setup from genesis through
//! production commands (`fstp_domain_testkit::gen::money`): programme P1,
//! call 1, and four proposals of four leads.
//!
//! - PA, PB: adult leads, plans of 4.00 and 3.00 EUR.
//! - PC: a minor's proposal (R-ID-04) with a verified guardian consent
//!   (I-18), so it can reach GRANTED. It must never appear (I-42).
//! - PD: a draft that is never submitted, so it never reaches GRANTED
//!   (I-41).
//!
//! The worlds are [`Stage`]s in lifecycle order: every submitted proposal
//! in NEGOTIATION; PA granted; PC granted too; PA in execution and PB
//! granted; then PA completed and PB in execution. A stage's
//! [`Stage::with_params`] adds one production `EditPolicy` that sets P-50,
//! P-51, P-52 and P-54 to the [`Params`] given.
//!
//! # The reference filter
//!
//! [`reference`] is written from `SPEC/02-domain/public-transparency.md`
//! and the interim readings of `fstp_public::view`, never from production
//! code. It reads only the facts the setup fixes ([`Facts`]), the
//! parameters, the synthetic choice records and the public texts.
//!
//! # M-PUBLIC
//!
//! [`PublicModel`] explores the stages, the choices of PA, PB and PC, and
//! P-50, P-51 and P-54 at two values each. PD keeps a full choice, so a
//! proposal before GRANTED always has one. Every state checks the
//! production view against the reference.
//!
//! # The Guide world
//!
//! [`guide_world`] runs `SodSetup` on the compiled SuperSAFE policy with
//! call 1 published, then a live edit of P-05 and P-58. The I-51 and I-52
//! suites bind the published Guide over it. Every id and text is
//! synthetic.

use std::collections::BTreeMap;

use fstp_domain::State;
use fstp_domain::id::{AccountId, CallId, PolicyVersionId, ProposalId, TextId};
use fstp_domain::policy::OpaqueValue;
use fstp_domain::rules::{ParamId, StateTag};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::money::{
    LA, LB, LC, MoneyDraft, MoneySetup, MoneyStory, MoneyWorld, PA, PB, PC, complete, milestone_n,
    start_execution,
};
use fstp_domain_testkit::r#gen::roster::{self, P1, T0, call, edit_policy};
use fstp_json::Value;
use fstp_mc::{Model, Property};
use fstp_money::{Amount, Currency};
use fstp_public::{
    GrantChoice, GrantChoices, GrantStatus, Level, ProgrammeIdentity, PublicAggregate, PublicGrant,
    PublicTexts, PublicView,
};

use crate::NotImplemented;

/// The state count of the first exhaustive run: five stages, five choices
/// for each of PA, PB and PC, and two values of each of P-50, P-51 and
/// P-54.
pub const TRIPWIRE: usize = 5_000;

/// The programme of every world.
pub const PROGRAMME: fstp_domain::id::ProgrammeId = P1;
/// The call of every proposal.
pub const CALL: CallId = call(1);
/// The never-submitted draft.
pub const PD: ProposalId = ProposalId::from_raw(14);
/// The lead of [`PD`].
pub const LD: AccountId = AccountId::from_raw(404);
/// The minor's proposal.
pub const MINOR: ProposalId = PC;
/// Every proposal of the worlds, in id order.
pub const PROPOSALS: [ProposalId; 4] = [PA, PB, PC, PD];

/// The plan of each proposal, in cents.
const CENTS: [(ProposalId, i64); 4] = [(PA, 400), (PB, 300), (PC, 200), (PD, 300)];

/// The public identity of P1. Synthetic.
pub fn identity() -> ProgrammeIdentity {
    ProgrammeIdentity {
        slug: "supersafe".to_owned(),
        name: "SuperSAFE Synthetic Programme".to_owned(),
        narrative: "Synthetic narrative. Not a real programme.".to_owned(),
    }
}

/// The money setup of the worlds (module documentation).
pub fn setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 300, 200]);
    s.p05 = 100_000;
    s.shared = Vec::new();
    s.consents = vec![PC];
    for d in &mut s.drafts {
        if d.proposal == PC {
            d.minor = true;
        }
    }
    s.drafts.push(MoneyDraft {
        lead: LD,
        proposal: PD,
        minor: false,
        milestones: vec![(milestone_n(PD, 0), 300, T0)],
        negotiate: false,
    });
    debug_assert!([LA, LB, LC].iter().all(|l| *l != LD));
    s
}

/// What the setup fixes about one proposal at one stage.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Facts {
    /// Its state in the reference views.
    pub state: Option<StateTag>,
    /// Whether its lead is a minor.
    pub minor: bool,
    /// Its plan total in cents, which is the granted amount once granted.
    pub cents: i64,
    /// Its call's public identifier.
    pub call: String,
}

/// One world of the lifecycle.
#[derive(Clone, Debug)]
pub struct Stage {
    /// Its name.
    pub name: &'static str,
    /// The world.
    pub world: MoneyWorld,
    /// The facts of every proposal.
    pub facts: BTreeMap<ProposalId, Facts>,
}

/// The value of one public parameter in a world: decodable, or the
/// setup's `synthetic P-xx` text, which the filter must read as closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Param<T> {
    /// A value the programme spec could hold.
    Set(T),
    /// A value that does not decode.
    Undecodable,
}

/// P-50, P-51, P-52 and P-54 of one world.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Params {
    /// P-50: the funded maximum.
    pub p50: Param<Level>,
    /// P-51: the finished maximum.
    pub p51: Param<Level>,
    /// P-52: the feed.
    pub p52: Param<bool>,
    /// P-54: the aggregate minimum.
    pub p54: Param<u16>,
}

impl Params {
    /// Every parameter at its SuperSAFE value: Full, Full, on, 3.
    pub fn supersafe() -> Params {
        Params {
            p50: Param::Set(Level::Full),
            p51: Param::Set(Level::Full),
            p52: Param::Set(true),
            p54: Param::Set(3),
        }
    }
}

/// The opaque value of the JSON text `json`.
fn opaque_json(json: &str) -> Result<OpaqueValue, String> {
    let v = fstp_json::parse_str(json).map_err(|e| format!("{json}: {e:?}"))?;
    OpaqueValue::from_value(&v).map_err(|e| format!("{json}: {e:?}"))
}

impl Stage {
    /// The world after one production `EditPolicy` that sets the public
    /// parameters to `params`, as version `version` of P1. An
    /// undecodable value keeps the setup's `synthetic P-xx` text.
    pub fn with_params(&self, params: &Params, version: u128) -> Result<MoneyWorld, String> {
        let head = self
            .world
            .head
            .as_deref()
            .ok_or_else(|| format!("{}: no head policy", self.name))?;
        let mut values: Vec<(ParamId, OpaqueValue)> = Vec::new();
        if let Param::Set(l) = params.p50 {
            values.push((
                ParamId::P50,
                OpaqueValue::from_value(&Value::String(l.token().to_owned()))
                    .map_err(|e| format!("P-50: {e:?}"))?,
            ));
        }
        if let Param::Set(l) = params.p51 {
            values.push((
                ParamId::P51,
                OpaqueValue::from_value(&Value::String(l.token().to_owned()))
                    .map_err(|e| format!("P-51: {e:?}"))?,
            ));
        }
        if let Param::Set(b) = params.p52 {
            values.push((ParamId::P52, opaque_json(if b { "true" } else { "false" })?));
        }
        if let Param::Set(n) = params.p54 {
            values.push((ParamId::P54, opaque_json(&n.to_string())?));
        }
        let step = edit_policy(head, PolicyVersionId::from_raw(version), |v| {
            for (p, x) in values {
                v.live.opaque.insert(p, x);
            }
        });
        match self.world.step(&step)? {
            Some((w, _)) => Ok(w),
            None => Err(format!(
                "{}: production and the references refused the P-50 to P-54 edit",
                self.name
            )),
        }
    }
}

/// The production core state of `world`.
pub fn core(world: &MoneyWorld) -> &State {
    &world.life.rev.sod.state
}

/// The lifecycle worlds of the setup.
#[derive(Clone, Debug)]
pub struct PublicWorld {
    /// The stages, in lifecycle order.
    pub stages: Vec<Stage>,
}

impl PublicWorld {
    /// Builds every stage from genesis (module documentation).
    pub fn build() -> Result<PublicWorld, String> {
        let setup = setup();
        let mut story = MoneyStory::new(&setup, roster::Backend::Production)?;
        let mut stages = Vec::new();
        let snap = |name: &'static str, story: &MoneyStory| -> Stage {
            let facts = PROPOSALS
                .iter()
                .map(|p| {
                    let cents = CENTS.iter().find(|(q, _)| q == p).map_or(0, |(_, c)| *c);
                    (
                        *p,
                        Facts {
                            state: story.state(*p),
                            minor: *p == MINOR,
                            cents,
                            call: CALL.raw().to_string(),
                        },
                    )
                })
                .collect();
            Stage {
                name,
                world: story.world.clone(),
                facts,
            }
        };
        stages.push(snap("negotiation", &story));
        story.grant(PA).map_err(|e| format!("grant PA: {e}"))?;
        stages.push(snap("pa_granted", &story));
        story.grant(PC).map_err(|e| format!("grant PC: {e}"))?;
        stages.push(snap("minor_granted", &story));
        story
            .run(&start_execution(PA))
            .map_err(|e| format!("start PA: {e}"))?;
        story.grant(PB).map_err(|e| format!("grant PB: {e}"))?;
        stages.push(snap("executing", &story));
        story
            .close_milestones(PA)
            .map_err(|e| format!("close PA: {e}"))?;
        story
            .run(&complete(PA))
            .map_err(|e| format!("complete PA: {e}"))?;
        story
            .run(&start_execution(PB))
            .map_err(|e| format!("start PB: {e}"))?;
        stages.push(snap("completed", &story));
        Ok(PublicWorld { stages })
    }
}

// ---------------------------------------------------------------------------
// Synthetic choice records and public texts
// ---------------------------------------------------------------------------

/// The approved title, summary and grantee texts of `p`'s synthetic
/// choice record.
pub fn choice_text_ids(p: ProposalId) -> [TextId; 3] {
    let base = p.raw().saturating_mul(10).saturating_add(900_000);
    [
        TextId::from_raw(base.saturating_add(1)),
        TextId::from_raw(base.saturating_add(2)),
        TextId::from_raw(base.saturating_add(3)),
    ]
}

/// The synthetic choice record of `p`.
pub fn choice(p: ProposalId, funded: Level, finished: Level) -> GrantChoice {
    let [title, summary, grantee] = choice_text_ids(p);
    GrantChoice {
        funded,
        finished,
        title,
        summary,
        grantee,
        deliverables: Vec::new(),
    }
}

/// The approved texts of `p`'s choice record. Synthetic.
pub fn choice_texts(p: ProposalId) -> [String; 3] {
    let n = p.raw();
    [
        format!("Synthetic project title {n}"),
        format!("Synthetic public summary {n}, approved by the grantee."),
        format!("Synthetic Grantee {n}"),
    ]
}

/// The public texts of a world: the identity, call 1's text and every
/// proposal's approved choice texts.
pub fn texts() -> PublicTexts {
    let mut t = PublicTexts::new(identity());
    // `SodSetup::steps` drafts call `c` with the text `c + 10 000`.
    t.insert(
        TextId::from_raw(CALL.raw().saturating_add(10_000)),
        "Synthetic Open Call 1",
    );
    for p in PROPOSALS {
        for (id, text) in choice_text_ids(p).into_iter().zip(choice_texts(p)) {
            t.insert(id, &text);
        }
    }
    t
}

// ---------------------------------------------------------------------------
// The reference filter
// ---------------------------------------------------------------------------

/// What the filter must give for one world.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expected {
    /// Whether the feed is on.
    pub feed: bool,
    /// The funded grants.
    pub funded: Vec<PublicGrant>,
    /// The finished grants.
    pub finished: Vec<PublicGrant>,
    /// The aggregates.
    pub aggregates: Vec<PublicAggregate>,
}

/// `cents` as an ADR-006 EUR amount string.
fn amount(cents: i64) -> Option<String> {
    Amount::from_minor(cents, Currency::Eur)
        .ok()
        .map(|a| a.to_string())
}

/// The reference filter over `facts` (module documentation and the
/// interim readings of `fstp_public::view`).
pub fn reference(
    facts: &BTreeMap<ProposalId, Facts>,
    params: &Params,
    choices: &GrantChoices,
    texts: &PublicTexts,
) -> Expected {
    let max = |p: Param<Level>| match p {
        Param::Set(l) => l,
        Param::Undecodable => Level::Hidden,
    };
    let mut funded = Vec::new();
    let mut finished = Vec::new();
    // Per call: the grants shown, those with a hidden amount, and cents.
    let mut by_call: BTreeMap<String, (u32, u32, i64)> = BTreeMap::new();
    for (p, f) in facts {
        // I-41: only from GRANTED on. TERMINATED shows nowhere.
        let (status, finished_phase) = match f.state {
            Some(StateTag::Granted) => (GrantStatus::Granted, false),
            Some(StateTag::InExecution) => (GrantStatus::InExecution, false),
            Some(StateTag::Completed) => (GrantStatus::Completed, true),
            _ => continue,
        };
        // I-42: no minor, at any level.
        if f.minor {
            continue;
        }
        // I-43: hidden with no choice, else the lower of maximum and choice.
        let Some(c) = choices.get(*p) else {
            continue;
        };
        let level = if finished_phase {
            max(params.p51).min(c.finished)
        } else {
            max(params.p50).min(c.funded)
        };
        if level == Level::Hidden {
            continue;
        }
        let (Some(title), Some(summary)) = (texts.text(c.title), texts.text(c.summary)) else {
            continue;
        };
        let grantee = if level >= Level::ProjectAndGrantee {
            match texts.text(c.grantee) {
                Some(g) => Some(g.to_owned()),
                None => continue,
            }
        } else {
            None
        };
        let shown_amount = if level == Level::Full {
            match amount(f.cents) {
                Some(a) => Some(a),
                None => continue,
            }
        } else {
            None
        };
        let g = PublicGrant {
            call: f.call.clone(),
            level,
            status,
            title: title.to_owned(),
            summary: summary.to_owned(),
            grantee,
            amount: shown_amount,
            deliverables: Vec::new(),
        };
        let e = by_call.entry(f.call.clone()).or_insert((0, 0, 0));
        e.0 = e.0.saturating_add(1);
        if level != Level::Full {
            e.1 = e.1.saturating_add(1);
        }
        e.2 = e.2.saturating_add(f.cents);
        if finished_phase {
            finished.push(g);
        } else {
            funded.push(g);
        }
    }
    // R-PB-05, Q27: only over the grants shown, and only at P-54 or more.
    // I-43: never when the hidden amounts it counts number from 1 to
    // max(P-54, 2) - 1, since the total less the shown amounts is their sum.
    let aggregates = match params.p54 {
        Param::Set(min) => by_call
            .into_iter()
            .filter(|(_, (n, _, _))| *n >= u32::from(min))
            .filter(|(_, (_, hidden, _))| *hidden == 0 || *hidden >= u32::from(min.max(2)))
            .filter_map(|(call, (n, _, cents))| {
                amount(cents).map(|total| PublicAggregate {
                    call,
                    grants: n,
                    total,
                })
            })
            .collect(),
        Param::Undecodable => Vec::new(),
    };
    Expected {
        feed: params.p52 == Param::Set(true),
        funded,
        finished,
        aggregates,
    }
}

/// `Ok` when the filter part of `view` equals `want` and the programme
/// part shows the identity of `texts`.
pub fn compare(view: &PublicView, want: &Expected, texts: &PublicTexts) -> Result<(), String> {
    let id = texts.identity();
    let mut diffs = Vec::new();
    if view.programme.slug != id.slug
        || view.programme.name != id.name
        || view.programme.narrative != id.narrative
    {
        diffs.push(format!("programme {:?}", view.programme));
    }
    if view.programme.feed != want.feed {
        diffs.push(format!(
            "P-52: feed {} for {}",
            view.programme.feed, want.feed
        ));
    }
    if view.funded != want.funded {
        diffs.push(format!("funded {:?}, want {:?}", view.funded, want.funded));
    }
    if view.finished != want.finished {
        diffs.push(format!(
            "finished {:?}, want {:?}",
            view.finished, want.finished
        ));
    }
    if view.aggregates != want.aggregates {
        diffs.push(format!(
            "aggregates {:?}, want {:?}",
            view.aggregates, want.aggregates
        ));
    }
    if diffs.is_empty() {
        Ok(())
    } else {
        Err(diffs.join("; "))
    }
}

/// Direct predicates on a filter outcome, independent of the reference:
/// no minor's text, no text of a proposal before GRANTED, and no level
/// above its maximum or its choice.
pub fn direct_predicates(
    facts: &BTreeMap<ProposalId, Facts>,
    params: &Params,
    choices: &GrantChoices,
    funded: &[PublicGrant],
    finished: &[PublicGrant],
) -> Result<(), String> {
    let shown: Vec<&PublicGrant> = funded.iter().chain(finished).collect();
    for (p, f) in facts {
        let [title, ..] = choice_texts(*p);
        let named = shown.iter().any(|g| g.title == title);
        if named && f.minor {
            return Err(format!("I-42: the minor's proposal {p:?} appears"));
        }
        let granted = matches!(
            f.state,
            Some(StateTag::Granted | StateTag::InExecution | StateTag::Completed)
        );
        if named && !granted {
            return Err(format!("I-41: {p:?} in {:?} appears", f.state));
        }
        if named && choices.get(*p).is_none() {
            return Err(format!("I-43: {p:?} appears with no choice"));
        }
    }
    let cap = |p: Param<Level>| match p {
        Param::Set(l) => l,
        Param::Undecodable => Level::Hidden,
    };
    if let Some(g) = funded.iter().find(|g| g.level > cap(params.p50)) {
        return Err(format!("I-43: a funded grant above P-50: {g:?}"));
    }
    if let Some(g) = finished.iter().find(|g| g.level > cap(params.p51)) {
        return Err(format!("I-43: a finished grant above P-51: {g:?}"));
    }
    Ok(())
}

/// Direct predicates on the aggregates of a filter outcome, independent
/// of the reference (R-PB-05, I-43, Q27): each counts at least P-54 of
/// the grants shown for its call, and no reader can infer one hidden
/// amount from it. Its total less the amounts shown is the sum of the
/// hidden amounts it counts, so those number 0 or at least
/// `max(P-54, 2)`.
pub fn aggregate_predicates(
    params: &Params,
    funded: &[PublicGrant],
    finished: &[PublicGrant],
    aggregates: &[PublicAggregate],
) -> Result<(), String> {
    let Param::Set(min) = params.p54 else {
        return match aggregates.first() {
            Some(a) => Err(format!("R-PB-05: {a:?} with an undecodable P-54")),
            None => Ok(()),
        };
    };
    let min = u32::from(min);
    for a in aggregates {
        let in_call: Vec<&PublicGrant> = funded
            .iter()
            .chain(finished)
            .filter(|g| g.call == a.call)
            .collect();
        let shown = u32::try_from(in_call.len()).unwrap_or(u32::MAX);
        if a.grants != shown || a.grants < min {
            return Err(format!(
                "R-PB-05: {a:?} over {shown} grants shown, P-54 {min}"
            ));
        }
        let hidden = in_call.iter().filter(|g| g.amount.is_none()).count();
        let hidden = u32::try_from(hidden).unwrap_or(u32::MAX);
        if hidden >= 1 && hidden < min.max(2) {
            return Err(format!(
                "I-43, R-PB-05: {a:?} counts {hidden} hidden amounts, P-54 {min}"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// M-PUBLIC
// ---------------------------------------------------------------------------

/// Which side the model checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// The production view against the reference.
    Production,
    /// The reference alone, against the direct predicates.
    Reference,
}

/// The choices one proposal takes in the model: none, or the same level
/// for both phases.
pub const MODEL_CHOICES: [Option<Level>; 5] = [
    None,
    Some(Level::Hidden),
    Some(Level::Project),
    Some(Level::ProjectAndGrantee),
    Some(Level::Full),
];

/// The two values of P-50 in the model.
pub const MODEL_P50: [Level; 2] = [Level::Project, Level::Full];
/// The two values of P-51 in the model.
pub const MODEL_P51: [Level; 2] = [Level::Hidden, Level::Full];
/// The two values of P-54 in the model.
pub const MODEL_P54: [u16; 2] = [1, 2];

/// A state of M-PUBLIC: the stage, the choice index of PA, PB and PC, and
/// the index of P-50, P-51 and P-54.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicState {
    /// The stage index.
    pub stage: u8,
    /// The index into [`MODEL_CHOICES`] of PA, PB and PC.
    pub choices: [u8; 3],
    /// The index into [`MODEL_P50`], [`MODEL_P51`] and [`MODEL_P54`].
    pub params: [u8; 3],
}

/// An action of M-PUBLIC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicAction {
    /// The lifecycle moves to the next stage.
    Advance,
    /// A grantee sets, narrows or withdraws a choice (R-PB-02).
    Choose {
        /// 0, 1 or 2: PA, PB or PC.
        who: u8,
        /// The index into [`MODEL_CHOICES`].
        choice: u8,
    },
    /// The programme manager edits one public parameter.
    Param {
        /// 0, 1 or 2: P-50, P-51 or P-54.
        which: u8,
        /// The value index.
        value: u8,
    },
}

/// The M-PUBLIC model.
#[derive(Debug)]
pub struct PublicModel {
    backend: Backend,
    /// The facts per stage.
    facts: Vec<BTreeMap<ProposalId, Facts>>,
    /// The production core state per stage and parameter index, keyed by
    /// `(stage, params)`.
    states: BTreeMap<(u8, [u8; 3]), State>,
    /// The instant of each stage.
    now: Vec<Timestamp>,
    texts: PublicTexts,
}

impl PublicModel {
    /// Builds the model. The production backend runs one `EditPolicy` per
    /// stage and parameter combination.
    pub fn new(backend: Backend) -> Result<PublicModel, NotImplemented> {
        let world = PublicWorld::build().map_err(|_| {
            NotImplemented::new("fstp_api_testkit::mc::public_model: the public worlds")
        })?;
        let mut states = BTreeMap::new();
        let mut facts = Vec::new();
        let mut now = Vec::new();
        let mut version = 70_000_u128;
        for (si, stage) in world.stages.iter().enumerate() {
            let s = u8::try_from(si).map_err(|_| NotImplemented::new("stage count"))?;
            facts.push(stage.facts.clone());
            now.push(stage.world.now());
            if backend == Backend::Reference {
                continue;
            }
            for a in 0..2_u8 {
                for b in 0..2_u8 {
                    for c in 0..2_u8 {
                        let params = model_params([a, b, c]);
                        version = version.saturating_add(1);
                        let w = stage.with_params(&params, version).map_err(|_| {
                            NotImplemented::new(
                                "fstp_api_testkit::mc::public_model: the P-50 to P-54 edit",
                            )
                        })?;
                        states.insert((s, [a, b, c]), core(&w).clone());
                    }
                }
            }
        }
        Ok(PublicModel {
            backend,
            facts,
            states,
            now,
            texts: texts(),
        })
    }

    /// The backend.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// The choice records of `s`. PD always holds a full choice.
    pub fn choices(&self, s: &PublicState) -> GrantChoices {
        let mut out = GrantChoices::none();
        for (p, i) in [PA, PB, PC].into_iter().zip(s.choices) {
            if let Some(Some(l)) = MODEL_CHOICES.get(usize::from(i)) {
                out.insert(p, choice(p, *l, *l));
            }
        }
        out.insert(PD, choice(PD, Level::Full, Level::Full));
        out
    }

    /// The reference outcome of `s`.
    pub fn expected(&self, s: &PublicState) -> Result<Expected, String> {
        let facts = self
            .facts
            .get(usize::from(s.stage))
            .ok_or_else(|| format!("no stage {}", s.stage))?;
        Ok(reference(
            facts,
            &model_params(s.params),
            &self.choices(s),
            &self.texts,
        ))
    }

    /// The production view of `s`.
    pub fn view(&self, s: &PublicState) -> Result<PublicView, String> {
        let core = self
            .states
            .get(&(s.stage, s.params))
            .ok_or_else(|| format!("no production state for {s:?}"))?;
        let now = self
            .now
            .get(usize::from(s.stage))
            .copied()
            .ok_or_else(|| format!("no stage {}", s.stage))?;
        fstp_public::public_view_with(core, PROGRAMME, &self.texts, &self.choices(s), now)
            .map_err(|e| e.to_string())
    }

    /// `Ok` when `s` meets the filter: the production view equals the
    /// reference, or on the reference backend the reference meets the
    /// direct predicates.
    pub fn holds(&self, s: &PublicState) -> Result<(), String> {
        let want = self.expected(s)?;
        let facts = self
            .facts
            .get(usize::from(s.stage))
            .ok_or_else(|| format!("no stage {}", s.stage))?;
        let params = model_params(s.params);
        direct_predicates(
            facts,
            &params,
            &self.choices(s),
            &want.funded,
            &want.finished,
        )?;
        aggregate_predicates(&params, &want.funded, &want.finished, &want.aggregates)?;
        if self.backend == Backend::Production {
            let view = self.view(s)?;
            compare(&view, &want, &self.texts)?;
        }
        Ok(())
    }
}

/// The parameters of the index triple `i`. P-52 stays on.
pub fn model_params(i: [u8; 3]) -> Params {
    let [a, b, c] = i;
    Params {
        p50: Param::Set(
            MODEL_P50
                .get(usize::from(a))
                .copied()
                .unwrap_or(Level::Hidden),
        ),
        p51: Param::Set(
            MODEL_P51
                .get(usize::from(b))
                .copied()
                .unwrap_or(Level::Hidden),
        ),
        p52: Param::Set(true),
        p54: Param::Set(MODEL_P54.get(usize::from(c)).copied().unwrap_or(u16::MAX)),
    }
}

impl Model for PublicModel {
    type State = PublicState;
    type Action = PublicAction;

    fn init(&self) -> Vec<PublicState> {
        vec![PublicState {
            stage: 0,
            choices: [0, 0, 0],
            params: [0, 0, 0],
        }]
    }

    fn actions(&self, _state: &PublicState, actions: &mut Vec<PublicAction>) {
        actions.push(PublicAction::Advance);
        for who in 0..3_u8 {
            for choice in 0..5_u8 {
                actions.push(PublicAction::Choose { who, choice });
            }
        }
        for which in 0..3_u8 {
            for value in 0..2_u8 {
                actions.push(PublicAction::Param { which, value });
            }
        }
    }

    fn step(&self, state: &PublicState, action: &PublicAction) -> Option<PublicState> {
        let mut next = *state;
        match *action {
            PublicAction::Advance => {
                let s = state.stage.checked_add(1)?;
                if usize::from(s) >= self.facts.len() {
                    return None;
                }
                next.stage = s;
            }
            PublicAction::Choose { who, choice } => {
                let slot = next.choices.get_mut(usize::from(who))?;
                if *slot == choice {
                    return None;
                }
                *slot = choice;
            }
            PublicAction::Param { which, value } => {
                let slot = next.params.get_mut(usize::from(which))?;
                if *slot == value {
                    return None;
                }
                *slot = value;
            }
        }
        Some(next)
    }

    fn is_terminal(&self, _state: &PublicState) -> bool {
        true
    }
}

/// The properties of M-PUBLIC over `model`: the filter in every state,
/// and the witnesses of design section 8.5, a full-level finished grant
/// and an aggregate at exactly P-54.
pub fn m_public_properties(model: &PublicModel) -> Vec<Property<'_, PublicModel>> {
    vec![
        Property::always_with("I-87 M-PUBLIC filter", move |s: &PublicState| {
            model.holds(s)
        }),
        Property::reachable("full-level finished grant", move |s: &PublicState| {
            model
                .expected(s)
                .is_ok_and(|e| e.finished.iter().any(|g| g.level == Level::Full))
        }),
        Property::reachable("aggregate at exactly P-54", move |s: &PublicState| {
            let min = u32::from(model_params(s.params).p54_value());
            model
                .expected(s)
                .is_ok_and(|e| e.aggregates.iter().any(|a| a.grants == min))
        }),
    ]
}

impl Params {
    /// The P-54 value, or `u16::MAX` when it does not decode.
    pub fn p54_value(&self) -> u16 {
        match self.p54 {
            Param::Set(n) => n,
            Param::Undecodable => u16::MAX,
        }
    }
}

// ---------------------------------------------------------------------------
// The Guide world (I-51, I-52, R-GA-01)
// ---------------------------------------------------------------------------

/// The published call of the Guide world.
pub const GUIDE_CALL: CallId = call(1);
/// A drafted and approved call of the Guide world that is not published.
pub const UNPUBLISHED_CALL: CallId = call(2);

/// A programme on the compiled SuperSAFE policy with call 1 published,
/// before and after a live edit of P-05 and P-58 (NOTE 7, I-51).
#[derive(Clone, Debug)]
pub struct GuideWorld {
    /// The compiled SuperSAFE fixture spec, as the creator would hold it.
    pub compiled: fstp_programme::Compiled,
    /// The core state right after the publication of call 1.
    pub published: State,
    /// The core state after a live edit raised P-05 and P-58 to
    /// [`EDITED_P05`].
    pub edited: State,
}

/// P-05 and P-58 after the live edit, an ADR-006 string. The SuperSAFE
/// value at publication is `400000.00`.
pub const EDITED_P05: &str = "450000.00";

/// Builds the Guide world from genesis through production commands.
///
/// The setup of `SodSetup` runs with the compiled SuperSAFE policy in
/// place of `base_version`, except P-21, which names the inference model
/// the setup's publication pins. Call 1 is published and call 2 only
/// approved. Then the staff programme manager raises P-05 and P-58 to
/// [`EDITED_P05`], a live loosening that needs no corrigendum.
pub fn guide_world() -> Result<GuideWorld, String> {
    use fstp_domain_testkit::r#gen::policy::eur;
    use fstp_domain_testkit::r#gen::review::run_on;
    use fstp_domain_testkit::r#gen::roster::{K1, SodSetup, sod_truth};
    use fstp_domain_testkit::scenario::Scenario;

    let fixture = fstp_programme::supersafe_fixture().map_err(|e| format!("fixture: {e:?}"))?;
    let compiled = fstp_programme::compile(
        &fixture.spec,
        &fstp_programme::FunderProfile::horizon_europe(),
        fstp_programme::CompileIds::new(P1, PolicyVersionId::from_raw(P1.raw()), None),
    )
    .map_err(|e| format!("compile: {e:?}"))?;
    let setup = SodSetup {
        programmes: vec![P1],
        p12: 0,
        p13: [K1].into_iter().collect(),
        calls: vec![(P1, GUIDE_CALL), (P1, UNPUBLISHED_CALL)],
        published: vec![GUIDE_CALL],
    };
    let mut steps = setup.steps()?;
    for s in &mut steps {
        if let fstp_domain::Command::CreateProgramme { policy } = &mut s.cmd {
            let p21 = policy.frozen.p21.clone();
            let mut v = compiled.policy.clone();
            v.frozen.p21 = p21;
            **policy = v;
        }
    }
    let mut scenario = Scenario::new(sod_truth()).map_err(|e| format!("open: {e:?}"))?;
    for step in &steps {
        run_on(&mut scenario, step, T0)
            .map_err(|e| format!("setup step {:?}: {e:?}", step.cmd.kind()))?;
    }
    let published = scenario.state().core.clone();
    let head = fstp_domain::policy::head(&published, P1)
        .cloned()
        .ok_or("no head policy after the setup")?;
    let raised = eur(45_000_000)?;
    let edit = edit_policy(&head, PolicyVersionId::from_raw(9_001), |v| {
        v.live.p05 = raised;
        v.live.p58 = Some(raised);
    });
    run_on(&mut scenario, &edit, T0).map_err(|e| format!("the live P-05 edit: {e:?}"))?;
    let edited = scenario.state().core.clone();
    Ok(GuideWorld {
        compiled,
        published,
        edited,
    })
}

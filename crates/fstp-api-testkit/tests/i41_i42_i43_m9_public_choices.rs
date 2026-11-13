//! The public filter over real grantee choice records (I-41, I-42, I-43,
//! R-PB-02, R-PB-05; M9 design section 3, lane P3).
//!
//! The worlds are the M4 public worlds (`fstp_api_testkit::mc::public_model`):
//! one programme, call 1 and four proposals walked through production
//! commands from NEGOTIATION to COMPLETED. PA and PB are adults' grants,
//! PC a minor's grant, PD a draft that never reaches GRANTED.
//!
//! The choices are no longer synthetic. Each property runs generated
//! `SetPublicChoice` and `WithdrawPublicChoice` commands of the leads
//! through production `decide` and `apply` (`fstp_domain_testkit::publicity`),
//! then builds the view with `fstp_public::grant_choices` over the folded
//! state. Every command outcome is predicted from the facts first: I-41
//! refuses a choice outside its states, I-42 refuses a minor's level
//! above hidden. To test the filter on its own, the I-41 and I-42
//! properties also fold choice records that the commands refuse, as a
//! stored log could hold them.
//!
//! The expected view is the M4 reference filter of `public_model`, fed
//! with choices this test derives from its own model of the accepted
//! commands, never from production state.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use fstp_api_testkit::mc::public_model::{
    CALL, Facts, LD, MINOR, PD, PROGRAMME, PROPOSALS, Param, Params, PublicWorld, Stage,
    aggregate_predicates, compare, core, identity, reference,
};
use fstp_domain::State;
use fstp_domain::command::Command;
use fstp_domain::id::{AccountId, ContentDigest, ProposalId, TextId, TextRef};
use fstp_domain::publicity::{PublicLevel, PublicPhase};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::money::{LA, LB, LC, PA, PB, PC};
use fstp_domain_testkit::publicity::{ChoiceDriver, choice_text_ids, choice_texts, set_choice};
use fstp_prop::{Gen, check};
use fstp_public::{
    Chrome, GrantChoice, GrantChoices, Level, PublicPage, PublicPart, PublicQuery, PublicTexts,
    PublicView, grant_choices, public_view_with, render_html,
};

/// The worlds, built once per test binary.
fn world() -> &'static PublicWorld {
    static WORLD: OnceLock<PublicWorld> = OnceLock::new();
    WORLD.get_or_init(|| PublicWorld::build().unwrap_or_else(|e| panic!("the public worlds: {e}")))
}

fn stage(name: &str) -> &'static Stage {
    world()
        .stages
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no stage {name}"))
}

/// The lead of each proposal of the worlds.
fn lead(p: ProposalId) -> AccountId {
    match p {
        x if x == PA => LA,
        x if x == PB => LB,
        x if x == PC => LC,
        _ => LD,
    }
}

/// The accepted choices as this test models them: level per grant and phase.
type Model = BTreeMap<(ProposalId, PublicPhase), PublicLevel>;

/// One generated choice action.
#[derive(Clone, Debug)]
enum Action {
    Set(ProposalId, PublicPhase, PublicLevel),
    Withdraw(ProposalId, PublicPhase),
}

impl Action {
    fn command(&self) -> Command {
        match self {
            Action::Set(p, ph, l) => set_choice(*p, *ph, *l, BTreeSet::new()),
            Action::Withdraw(p, ph) => Command::WithdrawPublicChoice {
                proposal: *p,
                phase: *ph,
            },
        }
    }

    fn proposal(&self) -> ProposalId {
        match self {
            Action::Set(p, ..) | Action::Withdraw(p, _) => *p,
        }
    }
}

fn gen_action(g: &mut Gen) -> Action {
    let p = *g.pick(&PROPOSALS);
    let phase = *g.pick(&PublicPhase::ALL);
    if g.u8_in(0..=3) == 0 {
        Action::Withdraw(p, phase)
    } else {
        Action::Set(p, phase, *g.pick(&PublicLevel::ALL))
    }
}

/// The states a choice of `phase` may be set in (I-41), from the spec:
/// funded from GRANTED on, finished once COMPLETED, never TERMINATED.
fn settable(phase: PublicPhase, s: Option<StateTag>) -> bool {
    match phase {
        PublicPhase::Funded => matches!(
            s,
            Some(StateTag::Granted | StateTag::InExecution | StateTag::Completed)
        ),
        PublicPhase::Finished => s == Some(StateTag::Completed),
    }
}

/// The predicted outcome of `a` by its lead: `None` when accepted, else
/// the rule that refuses it.
fn predict(facts: &BTreeMap<ProposalId, Facts>, model: &Model, a: &Action) -> Option<RuleRef> {
    let f = &facts[&a.proposal()];
    match a {
        Action::Set(_, phase, level) => {
            if !settable(*phase, f.state) {
                Some(RuleRef::I41)
            } else if f.minor && *level != PublicLevel::Hidden {
                Some(RuleRef::I42)
            } else {
                None
            }
        }
        Action::Withdraw(p, phase) => (!model.contains_key(&(*p, *phase))).then_some(RuleRef::I41),
    }
}

/// Runs `a` through production and checks its outcome against the
/// prediction. The model takes the accepted ones.
fn run(
    d: &mut ChoiceDriver,
    facts: &BTreeMap<ProposalId, Facts>,
    model: &mut Model,
    a: &Action,
) -> Result<(), String> {
    let want = predict(facts, model, a);
    let got = d.exec(lead(a.proposal()), &a.command())?;
    match (want, got) {
        (None, Ok(_)) => {
            match a {
                Action::Set(p, ph, l) => {
                    model.insert((*p, *ph), *l);
                }
                Action::Withdraw(p, ph) => {
                    model.remove(&(*p, *ph));
                }
            }
            Ok(())
        }
        (Some(rule), Err(r)) if r.rule == rule => Ok(()),
        (want, got) => Err(format!("{a:?}: predicted {want:?}, production {got:?}")),
    }
}

/// A choice record as a stored log could hold it, with no decision.
fn raw_choice(p: ProposalId, phase: PublicPhase, level: PublicLevel) -> Record {
    let [title, summary, grantee] =
        choice_text_ids(p, phase).map(|id| TextRef::new(id, ContentDigest::from_bytes([9; 32])));
    Record::PublicChoiceSet {
        proposal: p,
        phase,
        level,
        title,
        summary,
        grantee,
        deliverables: BTreeSet::new(),
        by: lead(p),
    }
}

/// The choices the reference reads, derived from `model` alone: each
/// phase's level, or hidden, and the texts of the phase the grant's
/// state is in, else of the other phase.
fn reference_choices(facts: &BTreeMap<ProposalId, Facts>, model: &Model) -> GrantChoices {
    let mut out = GrantChoices::none();
    let level = |p: ProposalId, ph: PublicPhase| {
        model
            .get(&(p, ph))
            .map_or(Level::Hidden, |l| Level::from_domain(*l))
    };
    for p in PROPOSALS {
        let has = |ph| model.contains_key(&(p, ph));
        if !has(PublicPhase::Funded) && !has(PublicPhase::Finished) {
            continue;
        }
        let current = if facts[&p].state == Some(StateTag::Completed) {
            PublicPhase::Finished
        } else {
            PublicPhase::Funded
        };
        let texts_of = if has(current) {
            current
        } else if current == PublicPhase::Funded {
            PublicPhase::Finished
        } else {
            PublicPhase::Funded
        };
        let [title, summary, grantee] = choice_text_ids(p, texts_of);
        out.insert(
            p,
            GrantChoice {
                funded: level(p, PublicPhase::Funded),
                finished: level(p, PublicPhase::Finished),
                title,
                summary,
                grantee,
                deliverables: Vec::new(),
            },
        );
    }
    out
}

/// The public texts: the identity, call 1's text and every choice text.
fn texts() -> PublicTexts {
    let mut t = PublicTexts::new(identity());
    t.insert(
        TextId::from_raw(CALL.raw().saturating_add(10_000)),
        "Synthetic Open Call 1",
    );
    for p in PROPOSALS {
        for ph in PublicPhase::ALL {
            for (id, text) in choice_text_ids(p, ph).into_iter().zip(choice_texts(p, ph)) {
                t.insert(id, &text);
            }
        }
    }
    t
}

fn gen_level(g: &mut Gen) -> Param<Level> {
    if g.u8_in(0..=5) == 0 {
        Param::Undecodable
    } else {
        Param::Set(*g.pick(&Level::ALL))
    }
}

fn gen_params(g: &mut Gen) -> Params {
    Params {
        p50: gen_level(g),
        p51: gen_level(g),
        p52: Param::Set(g.bool()),
        p54: if g.u8_in(0..=5) == 0 {
            Param::Undecodable
        } else {
            Param::Set(g.u16_in(1..=4))
        },
    }
}

/// A fresh policy version id for each edit.
fn version(n: u32) -> u128 {
    81_000 + u128::from(n)
}

/// A driver over `stage` with the public parameters `params`.
fn driver(stage: &Stage, params: &Params, n: u32) -> Result<ChoiceDriver, String> {
    let w = stage.with_params(params, version(n))?;
    Ok(ChoiceDriver::new(core(&w), w.now()))
}

fn view_of(state: &State, now: Timestamp) -> Result<PublicView, String> {
    let choices = grant_choices(state);
    public_view_with(state, PROGRAMME, &texts(), &choices, now).map_err(|e| e.to_string())
}

/// Every public output of `view`: the pages, the feed when P-52 is on,
/// and the public tool answers.
fn outputs(view: &PublicView) -> Result<Vec<String>, String> {
    let chrome = Chrome {
        stylesheet: None,
        funder: None,
    };
    let mut out = Vec::new();
    for page in [
        PublicPage::Programme,
        PublicPage::Funded,
        PublicPage::Finished,
    ] {
        let doc = render_html(view, &page, &chrome).map_err(|e| format!("{page:?}: {e}"))?;
        out.push(doc.as_str().to_owned());
    }
    if view.programme.feed {
        let feed = fstp_public::feed::feed(view).map_err(|e| format!("feed: {e}"))?;
        out.push(feed.to_compact());
    }
    for part in [
        PublicPart::Programme,
        PublicPart::Funded,
        PublicPart::Finished,
    ] {
        let v = fstp_public::tools::select(view, &PublicQuery { part, search: None })
            .map_err(|e| format!("select: {e}"))?;
        out.push(v.to_compact());
    }
    Ok(out)
}

/// `Err` when any output holds any text of `p`'s choices.
fn never_named(outputs: &[String], p: ProposalId, rule: &str) -> Result<(), String> {
    for ph in PublicPhase::ALL {
        for t in choice_texts(p, ph) {
            if let Some(o) = outputs.iter().find(|o| o.contains(&t)) {
                return Err(format!("{rule}: {p:?}'s text {t:?} reached {o}"));
            }
        }
    }
    Ok(())
}

/// I-41: in every stage, under generated parameters, generated choice
/// commands and folded choice records for every proposal that never
/// reached GRANTED, no page, feed item or public tool answer names such
/// a proposal. Every choice command on one is refused under I-41.
#[test]
fn i41_never_granted_never_public() {
    check("i41_never_granted_never_public", |g| {
        let stages = &world().stages;
        let s = &stages[g.usize_in(0..=stages.len() - 1)];
        let mut params = gen_params(g);
        params.p52 = Param::Set(true);
        g.note("stage", &s.name);
        g.note("params", &params);
        let mut d = driver(s, &params, 1)?;
        let mut model = Model::new();
        for _ in 0..g.usize_in(0..=8) {
            let a = gen_action(g);
            g.note("action", &a);
            run(&mut d, &s.facts, &mut model, &a)?;
        }
        let never: Vec<ProposalId> = PROPOSALS
            .into_iter()
            .filter(|p| {
                !matches!(
                    s.facts[p].state,
                    Some(StateTag::Granted | StateTag::InExecution | StateTag::Completed)
                )
            })
            .collect();
        for p in &never {
            for ph in PublicPhase::ALL {
                let level = *g.pick(&PublicLevel::ALL);
                d.fold(&raw_choice(*p, ph, level))?;
            }
        }
        let out = outputs(&view_of(&d.state, d.now)?)?;
        for p in never {
            never_named(&out, p, "I-41")?;
        }
        Ok(())
    });
}

/// I-42, D4: in each stage where the minor's proposal is granted, every
/// level above hidden is refused for it under I-42, and folded choice
/// records at every level never put its title, summary or grantee name
/// on any page, feed item or tool answer.
#[test]
fn i42_minor_never_named() {
    check("i42_minor_never_named", |g| {
        let names = ["minor_granted", "executing", "completed"];
        let s = stage(names[g.usize_in(0..=names.len() - 1)]);
        assert!(s.facts[&MINOR].minor);
        let mut params = gen_params(g);
        params.p52 = Param::Set(true);
        g.note("stage", &s.name);
        g.note("params", &params);
        let mut d = driver(s, &params, 2)?;
        let mut model = Model::new();
        for _ in 0..g.usize_in(0..=4) {
            let a = gen_action(g);
            g.note("action", &a);
            run(&mut d, &s.facts, &mut model, &a)?;
        }
        let level = *g.pick(&[
            PublicLevel::Project,
            PublicLevel::ProjectAndGrantee,
            PublicLevel::Full,
        ]);
        let a = Action::Set(MINOR, PublicPhase::Funded, level);
        if settable(PublicPhase::Funded, s.facts[&MINOR].state) {
            match d.exec(LC, &a.command())? {
                Err(r) if r.rule == RuleRef::I42 => {}
                other => return Err(format!("I-42: {a:?} gave {other:?}")),
            }
        }
        for ph in PublicPhase::ALL {
            d.fold(&raw_choice(MINOR, ph, *g.pick(&PublicLevel::ALL)))?;
        }
        let out = outputs(&view_of(&d.state, d.now)?)?;
        never_named(&out, MINOR, "I-42")
    });
}

/// I-43: under generated P-50 and P-51 and generated choice commands, the
/// view over the folded records equals the reference filter fed with this
/// test's own model of the accepted choices. So each grant shows exactly
/// the fields of `min(max, choice)`, and none without a choice record.
#[test]
fn i43_lower_of_max_and_choice() {
    check("i43_lower_of_max_and_choice", |g| {
        let stages = &world().stages;
        let s = &stages[g.usize_in(0..=stages.len() - 1)];
        let params = gen_params(g);
        g.note("stage", &s.name);
        g.note("params", &params);
        let mut d = driver(s, &params, 3)?;
        let mut model = Model::new();
        for _ in 0..g.usize_in(0..=10) {
            let a = gen_action(g);
            g.note("action", &a);
            run(&mut d, &s.facts, &mut model, &a)?;
        }
        let t = texts();
        let want = reference(&s.facts, &params, &reference_choices(&s.facts, &model), &t);
        let view = view_of(&d.state, d.now)?;
        compare(&view, &want, &t)?;
        let cap = |p: Param<Level>| match p {
            Param::Set(l) => l,
            Param::Undecodable => Level::Hidden,
        };
        for gr in view.funded.iter() {
            if gr.level > cap(params.p50) {
                return Err(format!("I-43: above P-50: {gr:?}"));
            }
        }
        for gr in view.finished.iter() {
            if gr.level > cap(params.p51) {
                return Err(format!("I-43: above P-51: {gr:?}"));
            }
        }
        Ok(())
    });
}

/// I-43, R-PB-02: after a withdrawal, or after P-50 or P-51 is lowered,
/// the very next view no longer shows the grant above the new bound. The
/// stored choice is unchanged by a lower maximum, and the filter applies
/// the lower of the two at read time.
#[test]
fn i43_withdrawal_and_narrowing_immediate() {
    check("i43_withdrawal_and_narrowing_immediate", |g| {
        let names = ["pa_granted", "executing", "completed"];
        let s = stage(names[g.usize_in(0..=names.len() - 1)]);
        g.note("stage", &s.name);
        let full = Params::supersafe();
        let lowered = Params {
            p50: Param::Set(*g.pick(&Level::ALL)),
            p51: Param::Set(*g.pick(&Level::ALL)),
            ..full
        };
        g.note("lowered", &lowered);
        // Every adult grant chooses Full for the phase it is in.
        let mut actions = Vec::new();
        for p in [PA, PB] {
            let phase = match s.facts[&p].state {
                Some(StateTag::Completed) => PublicPhase::Finished,
                Some(StateTag::Granted | StateTag::InExecution) => PublicPhase::Funded,
                _ => continue,
            };
            actions.push(Action::Set(p, phase, PublicLevel::Full));
        }
        let mut d = driver(s, &full, 4)?;
        let mut model = Model::new();
        for a in &actions {
            run(&mut d, &s.facts, &mut model, a)?;
        }
        let before = view_of(&d.state, d.now)?;
        let shown = before.funded.len() + before.finished.len();
        if shown != actions.len() {
            return Err(format!(
                "R-PB-02: {shown} grants for {actions:?}: {before:?}"
            ));
        }
        // Withdraw one: the next view lacks it, and only it.
        let pick = &actions[g.usize_in(0..=actions.len() - 1)];
        let Action::Set(p, phase, _) = pick else {
            unreachable!()
        };
        run(&mut d, &s.facts, &mut model, &Action::Withdraw(*p, *phase))?;
        let after = view_of(&d.state, d.now)?;
        let [title, ..] = choice_texts(*p, *phase);
        let out = outputs(&after)?;
        if out.iter().any(|o| o.contains(&title)) {
            return Err(format!("I-43: {p:?} still shows after its withdrawal"));
        }
        if after.funded.len() + after.finished.len() != shown - 1 {
            return Err(format!(
                "I-43: the withdrawal changed other grants: {after:?}"
            ));
        }
        // Lower P-50 and P-51: the same choices show at most the new bound.
        let mut low = driver(s, &lowered, 5)?;
        let mut low_model = Model::new();
        for a in &actions {
            run(&mut low, &s.facts, &mut low_model, a)?;
        }
        // A lower maximum refuses no choice: each is stored as chosen.
        if low_model.len() != actions.len() {
            return Err(format!("the lowered world refused a choice: {low_model:?}"));
        }
        let narrowed = view_of(&low.state, low.now)?;
        let bound = |ph: Param<Level>| match ph {
            Param::Set(l) => l,
            Param::Undecodable => Level::Hidden,
        };
        for gr in &narrowed.funded {
            if gr.level > bound(lowered.p50) {
                return Err(format!("I-43: above the lowered P-50: {gr:?}"));
            }
        }
        for gr in &narrowed.finished {
            if gr.level > bound(lowered.p51) {
                return Err(format!("I-43: above the lowered P-51: {gr:?}"));
            }
        }
        let t = texts();
        let want = reference(
            &s.facts,
            &lowered,
            &reference_choices(&s.facts, &low_model),
            &t,
        );
        compare(&narrowed, &want, &t)
    });
}

/// R-PB-05, I-43, Q27: over real choice records, every aggregate counts
/// at least P-54 of the grants shown for its call, and none lets a reader
/// infer a hidden amount. The aggregates equal the reference's.
#[test]
fn r_pb_05_p54_aggregates_withheld_over_real_records() {
    check("r_pb_05_p54_aggregates_withheld_over_real_records", |g| {
        let names = ["pa_granted", "minor_granted", "executing", "completed"];
        let s = stage(names[g.usize_in(0..=names.len() - 1)]);
        let mut params = gen_params(g);
        params.p54 = Param::Set(g.u16_in(1..=3));
        g.note("stage", &s.name);
        g.note("params", &params);
        let mut d = driver(s, &params, 6)?;
        let mut model = Model::new();
        for p in [PA, PB, PC, PD] {
            for ph in PublicPhase::ALL {
                if g.bool() {
                    let a = Action::Set(p, ph, *g.pick(&PublicLevel::ALL));
                    run(&mut d, &s.facts, &mut model, &a)?;
                }
            }
        }
        let view = view_of(&d.state, d.now)?;
        aggregate_predicates(&params, &view.funded, &view.finished, &view.aggregates)?;
        let t = texts();
        let want = reference(&s.facts, &params, &reference_choices(&s.facts, &model), &t);
        if view.aggregates != want.aggregates {
            return Err(format!(
                "R-PB-05: aggregates {:?}, want {:?}",
                view.aggregates, want.aggregates
            ));
        }
        Ok(())
    });
}

/// I-41: PD never reaches GRANTED in any stage, so every choice command
/// of its lead is refused under I-41 in every stage.
#[test]
fn i41_choice_commands_on_a_draft_are_refused_in_every_stage() {
    for s in &world().stages {
        let mut d = driver(s, &Params::supersafe(), 7).unwrap_or_else(|e| panic!("{e}"));
        for ph in PublicPhase::ALL {
            for cmd in [
                set_choice(PD, ph, PublicLevel::Full, BTreeSet::new()),
                Command::WithdrawPublicChoice {
                    proposal: PD,
                    phase: ph,
                },
            ] {
                match d.exec(LD, &cmd).unwrap_or_else(|e| panic!("{e}")) {
                    Err(r) => assert_eq!(r.rule, RuleRef::I41, "{}: {cmd:?}", s.name),
                    Ok(r) => panic!("I-41: {}: {cmd:?} accepted with {r:?}", s.name),
                }
            }
        }
    }
}

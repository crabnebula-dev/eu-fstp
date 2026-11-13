//! The public view filter over generated states (I-41, I-42, I-43,
//! R-PB-02, R-PB-03, R-PB-05, Q11, Q27; M4 design sections 3.10 and 8.4).
//!
//! The worlds come from `fstp_api_testkit::mc::public_model`: one
//! programme, call 1 and four proposals walked from genesis through
//! production commands, from NEGOTIATION to COMPLETED, one of them a
//! minor's and one a draft that never reaches GRANTED. The grantee choice
//! records are synthetic, since the record arrives with M9 (Q11). The
//! reference filter is written from `public-transparency.md`.
//!
//! I-41 to I-43 are supporting properties in M4. M9 claims them.
//!
//! Status: red. The W0 stub of `fstp_public::public_view_with` refuses
//! with `PublicError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::sync::OnceLock;

use fstp_api_testkit::mc::public_model::{
    CALL, MINOR, PD, PROGRAMME, PROPOSALS, Param, Params, PublicWorld, Stage, aggregate_predicates,
    choice, choice_text_ids, choice_texts, compare, core, direct_predicates, reference, texts,
};
use fstp_domain::id::TextId;
use fstp_domain_testkit::r#gen::money::{PA, PB};
use fstp_json::Value;
use fstp_prop::check;
use fstp_public::{
    Chrome, GrantChoices, Level, PublicPage, PublicPart, PublicQuery, PublicTexts, PublicView,
    public_view, public_view_with, render_html,
};

/// The worlds, built once per test binary.
fn world() -> &'static PublicWorld {
    static WORLD: OnceLock<PublicWorld> = OnceLock::new();
    WORLD.get_or_init(|| PublicWorld::build().unwrap_or_else(|e| panic!("the public worlds: {e}")))
}

/// The stage named `name`.
fn stage(name: &str) -> &'static Stage {
    world()
        .stages
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no stage {name}"))
}

/// A fresh policy version id for each edit of one test.
fn version(n: u32) -> u128 {
    80_000 + u128::from(n)
}

/// The production view of `stage` under `params` and `choices`.
fn view_of(
    stage: &Stage,
    params: &Params,
    choices: &GrantChoices,
    texts: &PublicTexts,
    n: u32,
) -> Result<PublicView, String> {
    let w = stage.with_params(params, version(n))?;
    public_view_with(core(&w), PROGRAMME, texts, choices, w.now()).map_err(|e| e.to_string())
}

/// Full choices for every proposal.
fn all_full() -> GrantChoices {
    let mut c = GrantChoices::none();
    for p in PROPOSALS {
        c.insert(p, choice(p, Level::Full, Level::Full));
    }
    c
}

/// A generated parameter value.
fn gen_level(g: &mut fstp_prop::Gen) -> Param<Level> {
    if g.u8_in(0..=4) == 0 {
        Param::Undecodable
    } else {
        Param::Set(*g.pick(&Level::ALL))
    }
}

/// I-41, I-42, I-43, R-PB-05: in every stage, under generated P-50, P-51,
/// P-52 and P-54, generated choice records and some missing approved
/// texts, the view equals the reference filter.
#[test]
fn i41_i42_i43_p54_public_view_filters_hold_in_every_state() {
    check(
        "i41_i42_i43_p54_public_view_filters_hold_in_every_state",
        |g| {
            let stages = &world().stages;
            let s = &stages[g.usize_in(0..=stages.len() - 1)];
            let params = Params {
                p50: gen_level(g),
                p51: gen_level(g),
                p52: if g.u8_in(0..=4) == 0 {
                    Param::Undecodable
                } else {
                    Param::Set(g.bool())
                },
                p54: if g.u8_in(0..=4) == 0 {
                    Param::Undecodable
                } else {
                    Param::Set(g.u16_in(1..=4))
                },
            };
            let mut choices = GrantChoices::none();
            for p in PROPOSALS {
                if g.bool() {
                    choices.insert(p, choice(p, *g.pick(&Level::ALL), *g.pick(&Level::ALL)));
                }
            }
            let mut t = texts();
            for p in PROPOSALS {
                for id in choice_text_ids(p) {
                    if g.u8_in(0..=9) == 0 {
                        t = without(&t, id);
                    }
                }
            }
            g.note("stage", &s.name);
            g.note("params", &params);
            g.note("choices", &choices);
            let want = reference(&s.facts, &params, &choices, &t);
            direct_predicates(&s.facts, &params, &choices, &want.funded, &want.finished)
                .map_err(|e| format!("the reference itself: {e}"))?;
            let view = view_of(s, &params, &choices, &t, 1)?;
            compare(&view, &want, &t)
        },
    );
}

/// `texts` without the text `id`.
fn without(texts: &PublicTexts, id: TextId) -> PublicTexts {
    let mut out = PublicTexts::new(texts.identity().clone());
    let call_text = TextId::from_raw(CALL.raw() + 10_000);
    if let Some(t) = texts.text(call_text) {
        out.insert(call_text, t);
    }
    for p in PROPOSALS {
        for x in choice_text_ids(p) {
            if x != id
                && let Some(t) = texts.text(x)
            {
                out.insert(x, t);
            }
        }
    }
    out
}

/// I-41: a proposal that never reached GRANTED never appears, whatever
/// its choice record says, in funded, finished or an aggregate.
#[test]
fn i41_proposal_before_granted_never_appears() {
    let s = stage("negotiation");
    let mut params = Params::supersafe();
    params.p54 = Param::Set(1);
    let view = view_of(s, &params, &all_full(), &texts(), 2).unwrap_or_else(|e| panic!("{e}"));
    assert!(view.funded.is_empty(), "{:?}", view.funded);
    assert!(view.finished.is_empty(), "{:?}", view.finished);
    assert!(view.aggregates.is_empty(), "{:?}", view.aggregates);
}

/// I-42: the minor's granted proposal never appears at any level, while
/// the adult's granted proposal of the same stage does.
#[test]
fn i42_minor_grant_never_appears() {
    let s = stage("minor_granted");
    assert_eq!(
        s.facts[&MINOR].state,
        Some(fstp_domain::StateTag::Granted),
        "the stage grants the minor's proposal"
    );
    for level in [Level::Project, Level::ProjectAndGrantee, Level::Full] {
        let mut choices = GrantChoices::none();
        choices.insert(MINOR, choice(MINOR, level, level));
        choices.insert(PA, choice(PA, level, level));
        let view = view_of(s, &Params::supersafe(), &choices, &texts(), 3)
            .unwrap_or_else(|e| panic!("{level:?}: {e}"));
        let titles: Vec<&str> = view.funded.iter().map(|g| g.title.as_str()).collect();
        let [minor_title, ..] = choice_texts(MINOR);
        let [pa_title, ..] = choice_texts(PA);
        assert!(
            !titles.contains(&minor_title.as_str()),
            "{level:?}: {titles:?}"
        );
        assert!(titles.contains(&pa_title.as_str()), "{level:?}: {titles:?}");
    }
}

/// I-43, Q11: a granted proposal with no choice record is hidden, so a
/// cell without choice records, every M4 cell, publishes no grant and no
/// aggregate in any stage.
#[test]
fn i43_q11_grant_without_choice_is_hidden_in_every_stage() {
    let mut params = Params::supersafe();
    params.p54 = Param::Set(1);
    for (i, s) in world().stages.iter().enumerate() {
        let w = s
            .with_params(&params, version(10 + u32::try_from(i).unwrap()))
            .unwrap_or_else(|e| panic!("{e}"));
        let view = public_view(core(&w), PROGRAMME, &texts(), w.now())
            .unwrap_or_else(|e| panic!("{}: {e}", s.name));
        assert!(
            view.funded.is_empty() && view.finished.is_empty() && view.aggregates.is_empty(),
            "{}: {view:?}",
            s.name
        );
    }
}

/// I-43, R-PB-02: a funded grant shows at the lower of P-50 and the
/// grantee's choice, and a finished grant at the lower of P-51 and the
/// choice. The lower level hides the fields of the higher ones.
#[test]
fn i43_grant_shows_at_the_lower_of_maximum_and_choice() {
    let s = stage("completed");
    let mut n = 20;
    for max in Level::ALL {
        for chosen in Level::ALL {
            n += 1;
            let params = Params {
                p50: Param::Set(max),
                p51: Param::Set(max),
                ..Params::supersafe()
            };
            let mut choices = GrantChoices::none();
            choices.insert(PA, choice(PA, chosen, chosen));
            choices.insert(PB, choice(PB, chosen, chosen));
            let view = view_of(s, &params, &choices, &texts(), n)
                .unwrap_or_else(|e| panic!("{max:?} {chosen:?}: {e}"));
            let want = max.min(chosen);
            for (list, phase) in [(&view.funded, "funded"), (&view.finished, "finished")] {
                if want == Level::Hidden {
                    assert!(list.is_empty(), "{max:?} {chosen:?} {phase}: {list:?}");
                    continue;
                }
                assert_eq!(list.len(), 1, "{max:?} {chosen:?} {phase}: {list:?}");
                let g = &list[0];
                assert_eq!(g.level, want, "{phase}");
                assert_eq!(
                    g.grantee.is_some(),
                    want >= Level::ProjectAndGrantee,
                    "{phase}"
                );
                assert_eq!(g.amount.is_some(), want == Level::Full, "{phase}");
            }
        }
    }
}

/// R-PB-05, Q27: an aggregate counts the grants the view shows and
/// appears only when it counts at least P-54. In the executing stage two
/// adult grants show; the minor's grant never counts.
#[test]
fn r_pb_05_aggregate_appears_only_at_p54() {
    let s = stage("executing");
    for (n, (min, shown)) in [(1_u16, true), (2, true), (3, false)]
        .into_iter()
        .enumerate()
    {
        let params = Params {
            p54: Param::Set(min),
            ..Params::supersafe()
        };
        let view = view_of(
            s,
            &params,
            &all_full(),
            &texts(),
            40 + u32::try_from(n).unwrap(),
        )
        .unwrap_or_else(|e| panic!("P-54 {min}: {e}"));
        let call = CALL.raw().to_string();
        let got: Vec<(String, u32, String)> = view
            .aggregates
            .iter()
            .map(|a| (a.call.clone(), a.grants, a.total.clone()))
            .collect();
        let want = if shown {
            vec![(call, 2, "7.00".to_owned())]
        } else {
            Vec::new()
        };
        assert_eq!(got, want, "P-54 {min}");
    }
}

/// R-PB-02 AC: a narrowed choice shows less on the next view, and a
/// withdrawn choice removes the grant from the next view.
#[test]
fn r_pb_02_narrowed_or_withdrawn_choice_leaves_the_next_view() {
    let s = stage("pa_granted");
    let w = s
        .with_params(&Params::supersafe(), version(50))
        .unwrap_or_else(|e| panic!("{e}"));
    let t = texts();
    let mut choices = GrantChoices::none();
    choices.insert(PA, choice(PA, Level::Full, Level::Full));
    let full = public_view_with(core(&w), PROGRAMME, &t, &choices, w.now())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(full.funded.len(), 1, "{full:?}");
    assert!(full.funded[0].amount.is_some(), "{full:?}");
    choices.insert(PA, choice(PA, Level::Project, Level::Project));
    let narrow = public_view_with(core(&w), PROGRAMME, &t, &choices, w.now())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(narrow.funded.len(), 1, "{narrow:?}");
    assert_eq!(narrow.funded[0].grantee, None, "{narrow:?}");
    assert_eq!(narrow.funded[0].amount, None, "{narrow:?}");
    choices.remove(PA);
    let gone = public_view_with(core(&w), PROGRAMME, &t, &choices, w.now())
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(gone.funded.is_empty(), "{gone:?}");
}

/// The canary of the text `id`.
fn canary(id: u128) -> String {
    format!("PROPOSAL-CANARY-{id}-SYNTHETIC")
}

/// Every string of `v`.
fn strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        Value::Object(o) => o.iter().for_each(|(k, x)| {
            out.push(k.to_owned());
            strings(x, out);
        }),
        _ => {}
    }
}

/// R-PB-03, I-41: a canary text under every text id the records of the
/// worlds can name, other than the call text, the P-09 wording and the
/// approved choice texts, never reaches a page, the feed or a tool answer, while the
/// approved texts do.
#[test]
fn r_pb_03_proposal_text_never_reaches_a_public_output() {
    let s = stage("completed");
    let mut t = texts();
    let allowed: BTreeSet<TextId> = PROPOSALS
        .iter()
        .flat_map(|p| choice_text_ids(*p))
        .chain([TextId::from_raw(CALL.raw() + 10_000)])
        // The P-09 wording of `base_version`, a public text of a published call.
        .chain((1_000..=1_002).map(TextId::from_raw))
        .collect();
    for id in 1..=100_000_u128 {
        if !allowed.contains(&TextId::from_raw(id)) {
            t.insert(TextId::from_raw(id), &canary(id));
        }
    }
    let w = s
        .with_params(&Params::supersafe(), version(60))
        .unwrap_or_else(|e| panic!("{e}"));
    let view = public_view_with(core(&w), PROGRAMME, &t, &all_full(), w.now())
        .unwrap_or_else(|e| panic!("{e}"));
    let mut outputs: Vec<String> = Vec::new();
    let chrome = Chrome {
        stylesheet: None,
        funder: None,
    };
    let mut pages = vec![
        PublicPage::Programme,
        PublicPage::Funded,
        PublicPage::Finished,
    ];
    pages.extend(
        view.open_calls
            .iter()
            .map(|c| PublicPage::Call(c.id.clone())),
    );
    for p in pages {
        let doc = render_html(&view, &p, &chrome).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        outputs.push(doc.as_str().to_owned());
    }
    let feed = fstp_public::feed::feed(&view).unwrap_or_else(|e| panic!("feed: {e}"));
    let mut feed_strings = Vec::new();
    strings(&feed, &mut feed_strings);
    outputs.extend(feed_strings);
    for part in [
        PublicPart::Programme,
        PublicPart::OpenCalls,
        PublicPart::Deadlines,
        PublicPart::Eligibility,
        PublicPart::Funded,
        PublicPart::Finished,
    ] {
        let v = fstp_public::tools::select(&view, &PublicQuery { part, search: None })
            .unwrap_or_else(|e| panic!("select: {e}"));
        let mut s = Vec::new();
        strings(&v, &mut s);
        outputs.extend(s);
    }
    for o in &outputs {
        assert!(!o.contains("PROPOSAL-CANARY-"), "a canary reached {o}");
    }
    let [pa_title, ..] = choice_texts(PA);
    assert!(
        outputs.iter().any(|o| o.contains(&pa_title)),
        "the approved title of PA does not appear"
    );
    let _ = PD;
}

/// R-PB-05, I-43, Q27: in every stage, under generated P-50, P-51 and
/// P-54 and generated choice records, no aggregate of the production
/// view lets a reader infer one amount the view hides. The hidden
/// amounts an aggregate counts number 0 or at least `max(P-54, 2)`.
#[test]
fn r_pb_05_i43_aggregate_never_reveals_a_hidden_amount() {
    check("r_pb_05_i43_aggregate_never_reveals_a_hidden_amount", |g| {
        let stages = &world().stages;
        let s = &stages[g.usize_in(0..=stages.len() - 1)];
        let params = Params {
            p50: gen_level(g),
            p51: gen_level(g),
            p54: Param::Set(g.u16_in(1..=4)),
            ..Params::supersafe()
        };
        let mut choices = GrantChoices::none();
        for p in PROPOSALS {
            if g.u8_in(0..=4) != 0 {
                choices.insert(p, choice(p, *g.pick(&Level::ALL), *g.pick(&Level::ALL)));
            }
        }
        g.note("stage", &s.name);
        g.note("params", &params);
        g.note("choices", &choices);
        let view = view_of(s, &params, &choices, &texts(), 70)?;
        aggregate_predicates(&params, &view.funded, &view.finished, &view.aggregates)
    });
}

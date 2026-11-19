//! Tests of the public text class (R-PB-03, I-53, I-87; Daniel's "copy
//! at publication" of 2026-11-17). Each runs production commands from
//! genesis through `fstp_domain_testkit`, over a synthetic vault: P1 with
//! call 1 published and call 2 approved only. Every text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

use fstp_domain::id::{CallId, ProgrammeId, TextId, TextRef};
use fstp_domain_testkit::r#gen::roster::{K1, P1, SodSetup, T0, edit_policy, sod_truth};
use fstp_domain_testkit::scenario::Scenario;
use fstp_engine::EngineState;

use super::*;

/// The published call.
const PUBLISHED: CallId = CallId::from_raw(1);
/// The approved call that is not published.
const APPROVED: CallId = CallId::from_raw(2);
/// A text the store holds that no call names: it stands for proposal text.
const PROPOSAL_TEXT: TextId = TextId::from_raw(77_777);
/// The stored description a corrigendum of P1 is worded from.
const CORRIGENDUM_TEXT: TextId = TextId::from_raw(88_001);

/// The world: P1 with call 1 published and call 2 approved, from genesis.
fn world() -> Scenario {
    let setup = SodSetup {
        programmes: vec![P1],
        p12: 0,
        p13: [K1].into_iter().collect(),
        calls: vec![(P1, PUBLISHED), (P1, APPROVED)],
        published: vec![PUBLISHED],
    };
    let mut s = Scenario::new(sod_truth()).unwrap();
    for step in setup.steps().unwrap() {
        run(&mut s, &step);
    }
    s
}

/// Runs `step` at [`T0`] with its attestations.
fn run(s: &mut Scenario, step: &fstp_domain_testkit::r#gen::roster::Step) {
    let mut ctx = s.ctx(T0, step.actor);
    ctx.tenant_admin = step.flags.tenant_admin;
    ctx.second_tenant_admin = step.flags.second_admin;
    ctx.binds_tenant_admin = step.flags.binds_tenant_admin;
    s.run_core(&step.cmd, ctx)
        .unwrap_or_else(|e| panic!("step {:?}: {e:?}", step.cmd.kind()));
}

/// The title and P-09 wording ids of `call`, from the core state.
fn call_texts(state: &EngineState, call: CallId) -> BTreeSet<TextId> {
    let v = state.core.calls().get(call).unwrap();
    let mut ids: BTreeSet<TextId> = [v.text().id()].into_iter().collect();
    if let Some(f) = v.frozen() {
        ids.extend(f.values().p09.0.iter().map(|k| k.text.id()));
    }
    ids
}

/// The synthetic text the store holds for `id`.
fn synthetic(id: TextId) -> String {
    format!("Synthetic public text {}", id.raw())
}

/// The cell text store of a test: a text per id, which a test may erase.
#[derive(Default)]
struct Store(Mutex<BTreeMap<TextId, String>>);

impl Store {
    /// A store that holds a synthetic text for each of `ids`.
    fn holding(ids: impl IntoIterator<Item = TextId>) -> Store {
        let s = Store::default();
        for id in ids {
            s.0.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id, synthetic(id));
        }
        s
    }

    /// Erases text `id`.
    fn erase(&self, id: TextId) {
        let _ = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
    }
}

impl TextOpener for Store {
    fn open(&self, id: TextId) -> PublicTextFuture<'_> {
        let t = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned();
        Box::pin(std::future::ready(t))
    }
}

/// Runs `f` to completion. Every future here is ready at its first poll,
/// so a pending one is a test failure.
fn block_on<T>(f: impl Future<Output = T>) -> T {
    use std::task::{Context, Poll, Waker};
    let mut f = std::pin::pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("a future of the test was not ready"),
    }
}

/// No corrigenda texts: the reading of a programme without a draft.
fn no_corrigenda(_: ProgrammeId) -> Option<Vec<TextRef>> {
    None
}

/// The page or JSON body of `op` on P1 at [`T0`] over `source`.
fn answer(state: &EngineState, source: &dyn PublicTextSource, op: PublicOp) -> String {
    let call = matches!(op, PublicOp::Call).then_some("1");
    match block_on(read(state, source, T0, op, "1", call)) {
        Ok(PublicAnswer::Page(p) | PublicAnswer::Json(p)) => p,
        Err(r) => panic!("{op:?} refused: {r:?}"),
    }
}

/// R-PB-03, I-87: the class answers a text only under the call it was
/// copied for. The same text id under another call, an id it never
/// copied and a call it holds nothing for are all refused.
#[test]
fn r_pb_03_public_class_answers_only_the_copy_of_its_own_call() {
    let w = world();
    let title = w.state().core.calls().get(PUBLISHED).unwrap().text().id();
    let store = Store::holding(call_texts(w.state(), PUBLISHED));
    let class = PublicClass::default();
    block_on(copy_with(w.state(), &class, &store, &no_corrigenda));
    assert_eq!(
        block_on(class.get_public(PUBLISHED, title)),
        Some(synthetic(title))
    );
    assert_eq!(block_on(class.get_public(APPROVED, title)), None);
    assert_eq!(block_on(class.get_public(CallId::from_raw(9), title)), None);
    assert_eq!(block_on(class.get_public(PUBLISHED, PROPOSAL_TEXT)), None);
}

/// R-PB-03: the copy at publication takes exactly the title and the P-09
/// wording of each published call. A text no call names, such as a
/// proposal text, and the texts of a call that is not published, are
/// never copied, though the store holds them.
#[test]
fn r_pb_03_copy_takes_only_the_texts_a_published_call_names() {
    let w = world();
    let published = call_texts(w.state(), PUBLISHED);
    let approved = call_texts(w.state(), APPROVED);
    assert!(published.len() > 1, "non-vacuity: call 1 has P-09 wording");
    let store = Store::holding(
        published
            .iter()
            .chain(approved.iter())
            .copied()
            .chain([PROPOSAL_TEXT]),
    );
    let class = PublicClass::default();
    block_on(copy_with(w.state(), &class, &store, &no_corrigenda));
    let copied: BTreeSet<TextId> = class.copy_of(PUBLISHED).into_keys().collect();
    assert_eq!(copied, published);
    assert!(class.copy_of(APPROVED).is_empty());
    for call in [PUBLISHED, APPROVED] {
        assert!(!class.copy_of(call).contains_key(&PROPOSAL_TEXT));
    }
}

/// R-PB-03, I-87: the public view reads only the class. While the store
/// holds the call's texts and the class holds none, no page or
/// tool shows the call's title. After the copy they all do.
#[test]
fn r_pb_03_public_view_reads_only_the_class() {
    let w = world();
    let title = w.state().core.calls().get(PUBLISHED).unwrap().text().id();
    let store = Store::holding(call_texts(w.state(), PUBLISHED));
    let class = PublicClass::default();
    // P-52 is off in this programme, so its feed is not public.
    let ops = [PublicOp::Programme, PublicOp::OpenCalls];
    for op in ops {
        assert!(
            !answer(w.state(), &class, op).contains(&synthetic(title)),
            "{op:?} shows a text the class does not hold"
        );
    }
    block_on(copy_with(w.state(), &class, &store, &no_corrigenda));
    for op in ops.into_iter().chain([PublicOp::Call]) {
        assert!(
            answer(w.state(), &class, op).contains(&synthetic(title)),
            "{op:?} does not show the copied title"
        );
    }
}

/// R-PB-03, "copy at publication": the copy is taken once. A text erased
/// from the store after the copy stays in the class, and a text erased
/// before it is never copied, so its call is not shown.
#[test]
fn r_pb_03_copy_is_taken_once_at_publication() {
    let w = world();
    let title = w.state().core.calls().get(PUBLISHED).unwrap().text().id();
    let store = Store::holding(call_texts(w.state(), PUBLISHED));
    let class = PublicClass::default();
    block_on(copy_with(w.state(), &class, &store, &no_corrigenda));
    store.erase(title);
    block_on(copy_with(w.state(), &class, &store, &no_corrigenda));
    assert_eq!(
        class.copy_of(PUBLISHED).get(&title),
        Some(&synthetic(title))
    );
    let late = PublicClass::default();
    block_on(copy_with(w.state(), &late, &store, &no_corrigenda));
    assert!(!late.copy_of(PUBLISHED).contains_key(&title));
    assert!(!answer(w.state(), &late, PublicOp::Programme).contains(&synthetic(title)));
}

/// I-53, R-PB-03: a corrigendum recorded after publication reaches the
/// copy. Its stored text is copied at the next copy after the record,
/// under the call it corrects, and not before the record exists.
#[test]
fn i53_corrigenda_after_publication_reach_the_copy() {
    let mut w = world();
    let corrigenda = |_: ProgrammeId| {
        Some(vec![TextRef::new(
            CORRIGENDUM_TEXT,
            fstp_domain::id::ContentDigest::from_bytes([7; 32]),
        )])
    };
    let store = Store::holding(
        call_texts(w.state(), PUBLISHED)
            .into_iter()
            .chain([CORRIGENDUM_TEXT]),
    );
    let class = PublicClass::default();
    block_on(copy_with(w.state(), &class, &store, &corrigenda));
    assert!(!class.copy_of(PUBLISHED).contains_key(&CORRIGENDUM_TEXT));
    // A lower live P-05 tightens the published call: one corrigendum.
    let head = fstp_domain::policy::head(&w.state().core, P1)
        .cloned()
        .unwrap();
    let lower = fstp_money::Amount::from_minor(
        head.live.p05.amount().minor() / 2,
        head.live.p05.amount().currency(),
    )
    .ok()
    .and_then(|a| fstp_money::NonNegAmount::new(a).ok())
    .unwrap();
    let step = edit_policy(
        &head,
        fstp_domain::id::PolicyVersionId::from_raw(9_301),
        |v| v.live.p05 = lower,
    );
    run(&mut w, &step);
    let tightenings = fstp_domain::programme::effective_limits(&w.state().core, PUBLISHED)
        .map_or(0, |l| l.tightenings().len());
    assert_eq!(
        tightenings, 1,
        "non-vacuity: the edit records a corrigendum"
    );
    block_on(copy_with(w.state(), &class, &store, &corrigenda));
    assert_eq!(
        class.copy_of(PUBLISHED).get(&CORRIGENDUM_TEXT),
        Some(&synthetic(CORRIGENDUM_TEXT))
    );
    assert!(class.copy_of(APPROVED).is_empty());
}

/// I-87, TH-06: two cells hold two classes. The same call and text id
/// copied in each answers each cell's own text only.
#[test]
fn i87_two_classes_never_cross() {
    let w = world();
    let title = w.state().core.calls().get(PUBLISHED).unwrap().text().id();
    let a = Store::holding(call_texts(w.state(), PUBLISHED));
    let b = Store::default();
    for id in call_texts(w.state(), PUBLISHED) {
        b.0.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, format!("Other cell text {}", id.raw()));
    }
    let (ca, cb) = (PublicClass::default(), PublicClass::default());
    block_on(copy_with(w.state(), &ca, &a, &no_corrigenda));
    block_on(copy_with(w.state(), &cb, &b, &no_corrigenda));
    assert_eq!(
        block_on(ca.get_public(PUBLISHED, title)),
        Some(synthetic(title))
    );
    assert_eq!(
        block_on(cb.get_public(PUBLISHED, title)),
        Some(format!("Other cell text {}", title.raw()))
    );
}

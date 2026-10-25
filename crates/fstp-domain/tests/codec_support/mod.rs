//! Shared support for the codec tests of lane L-CODEC (design sections 2.1,
//! 2.3, 2.10, 5.1 and 7).
//!
//! # The codec probe
//!
//! The codec is the `fstp_json::ToJson` and `fstp_json::FromJson` impls for
//! `Command`, `Record` and `PolicyVersion`. The tests are written before
//! those impls exist. [`codec_for!`] picks the real impls when both traits
//! are implemented for the type, and a stub that reports "codec missing"
//! otherwise. It does this by method resolution on a concrete type, so the
//! tests compile now and fail at run time for the right reason. Once the
//! impls land, the same tests run against them with no change.
//!
//! # Generators
//!
//! The generators build values from the public constructors only, with
//! synthetic numeric ids. They cover the whole domain of each type, not only
//! values a guard would accept. The codec is structural, so it must keep
//! every value the type can hold. One exception keeps generated values
//! inside the representable domain, and the test report records it:
//!
//! - `Timestamp` values stay within `fstp_ledger::MAX_AT` in magnitude, as
//!   the entry codec requires for `at`.
//!
//! A signed amount, such as `CutOffRecorded::remaining_budget`, spans the
//! whole range of `Amount`. A negative one encodes as a `shortfall` object.
//!
//! Generated strings that are not ids, amounts or percentages always start
//! with a letter. A string that matches the amount grammar is therefore an
//! amount or a percentage, which the ADR-006 tests rely on.
//!
//! Helpers return `Result` with a message and never panic. Only the test
//! functions assert.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32};

use fstp_domain::amendment::AmendmentRoute;
use fstp_domain::assignment::{AssignmentKind, ReleaseCause};
use fstp_domain::command::{
    Actor, Command, CommandKind, ContractEvent, DeclarationSubject, KnockOutResult, SystemCause,
};
use fstp_domain::decision::{Ballot, IrcVerdict, NegotiationFailure, Vote};
use fstp_domain::grant::IneligibleCost;
use fstp_domain::id::{
    AccountId, ActivityTypeId, AmendmentId, AssignmentId, BindingId, CallId, CallSeq, ClassId,
    ContentDigest, ContractId, CriterionId, DecisionId, DeliverableId, Handle, KnockOutCriterionId,
    LineId, LlmConfigId, MilestoneId, OrganisationId, PlanVersionId, PolicyVersionId, ProgrammeId,
    ProposalId, ProximityListId, RequestId, TextId, TextRef, VaultEpoch,
};
use fstp_domain::oracle::QueryKind;
use fstp_domain::payment::PaymentLine;
use fstp_domain::policy::{
    EffectiveScoreRule, ExclusionClasses, FrozenValues, FunderProfileRef, InferenceBinding,
    IrcExemptions, KnockOutCriteria, KnockOutCriterion, LicenceSet, LiveValues, McpBindingActions,
    ModelRef, OpaqueValue, ParamId, PolicyVersion, ProximityLists, ReadAccess, ReviewerAnonymity,
    SpdxId, TieBreakRule, VotingRules,
};
use fstp_domain::proposal::{
    EthicsDeclaration, Milestone, NoticeVersion, PlanOrigin, ReentryStage, Task,
};
use fstp_domain::record::{
    Assigned, AssignmentReleased, BindingEnded, BindingGranted, BindingReinstated,
    BindingSuspended, BindingVoided, ConflictDeclared, ConflictDetected, ContentRead,
    CutOffRecorded, Declared, DeliverableRecorded, OutboxEvent, PlanVersionRecorded, Record,
    RulesVersion, ScoreRecorded, ScoreVoided, Transitioned,
};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::{BindingScope, CoolingOff, Role};
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::scoring::{Criteria, Criterion, ScoreKey, ScoreVector, Stage, VoidCause};
use fstp_domain::time::{Timestamp, ZONE_NAME_MAX, ZoneName};
use fstp_json::{FromJson, FromJsonError, Number, Object, ToJson, Value, parse, to_canonical};
use fstp_ledger::{MAX_AT, Seq};
use fstp_money::{Amount, AmountRange, Currency, NonNegAmount, Percent, PosAmount};
use fstp_prop::Gen;

/// A helper result with a failure message.
pub(crate) type G<T> = Result<T, String>;

// ---------------------------------------------------------------------------
// The codec probe
// ---------------------------------------------------------------------------

/// The marker for a type that has no codec yet.
#[derive(Debug)]
pub(crate) struct Missing;

/// A zero-sized handle on the codec of `T`.
pub(crate) struct Probe<T>(PhantomData<T>);

impl<T> Probe<T> {
    /// The probe for `T`.
    pub(crate) const fn new() -> Probe<T> {
        Probe(PhantomData)
    }
}

/// The real codec. Method resolution prefers it when `T` has both impls.
pub(crate) trait Present {
    /// The value type.
    type Item;
    /// Encodes through `ToJson`.
    fn encode_item(&self, t: &Self::Item) -> Result<Value, Missing>;
    /// Decodes through `FromJson`.
    fn decode_item(&self, v: &Value) -> Result<Result<Self::Item, FromJsonError>, Missing>;
}

impl<T: ToJson + FromJson> Present for Probe<T> {
    type Item = T;
    fn encode_item(&self, t: &T) -> Result<Value, Missing> {
        Ok(t.to_json())
    }
    fn decode_item(&self, v: &Value) -> Result<Result<T, FromJsonError>, Missing> {
        Ok(T::from_json(v))
    }
}

/// The fallback when `T` lacks `ToJson` or `FromJson`.
pub(crate) trait Absent {
    /// The value type.
    type Item;
    /// Always reports a missing codec.
    fn encode_item(&self, t: &Self::Item) -> Result<Value, Missing>;
    /// Always reports a missing codec.
    fn decode_item(&self, v: &Value) -> Result<Result<Self::Item, FromJsonError>, Missing>;
}

impl<T> Absent for &Probe<T> {
    type Item = T;
    fn encode_item(&self, _t: &T) -> Result<Value, Missing> {
        Err(Missing)
    }
    fn decode_item(&self, _v: &Value) -> Result<Result<T, FromJsonError>, Missing> {
        Err(Missing)
    }
}

/// The codec of one type, as two function pointers chosen by [`codec_for!`].
pub(crate) struct Codec<T> {
    /// The type name, for messages.
    pub(crate) name: &'static str,
    /// The encoder.
    pub(crate) enc: fn(&T) -> Result<Value, Missing>,
    /// The decoder.
    pub(crate) dec: fn(&Value) -> Result<Result<T, FromJsonError>, Missing>,
}

/// The codec of a concrete type. It must be called with a concrete type,
/// never a generic parameter, so that method resolution can see the impls.
macro_rules! codec_for {
    ($t:ty) => {{
        #[allow(unused_imports)]
        use crate::codec_support::{Absent as _, Present as _};
        crate::codec_support::Codec::<$t> {
            name: stringify!($t),
            enc: |t| (&crate::codec_support::Probe::<$t>::new()).encode_item(t),
            dec: |v| (&crate::codec_support::Probe::<$t>::new()).decode_item(v),
        }
    }};
}
pub(crate) use codec_for;

/// A member name that no schema defines and no map key can parse as.
pub(crate) const UNKNOWN: &str = "zz-unknown-member";

/// Input content that must never appear in an error value (R-NF-02).
pub(crate) const MARKER: &str = "QZXJ-input-content-7c1f";

impl<T: PartialEq + Debug> Codec<T> {
    fn missing(&self) -> String {
        format!(
            "no JSON codec for {}: ToJson and FromJson are not implemented yet (lane L-CODEC)",
            self.name
        )
    }

    /// Encodes `t`.
    pub(crate) fn encode(&self, t: &T) -> G<Value> {
        (self.enc)(t).map_err(|_| self.missing())
    }

    /// Decodes `v`. The outer error means the codec is missing.
    pub(crate) fn decode(&self, v: &Value) -> G<Result<T, FromJsonError>> {
        (self.dec)(v).map_err(|_| self.missing())
    }

    /// The RFC 8785 text of the encoding of `t`.
    pub(crate) fn canonical(&self, t: &T) -> G<String> {
        let v = self.encode(t)?;
        to_canonical(&v).map_err(|e| format!("the encoding has no RFC 8785 form: {e}"))
    }

    /// Checks the round trip of `t` and returns its canonical text.
    ///
    /// - The encoding has an RFC 8785 form.
    /// - The canonical text parses and decodes to a value equal to `t`.
    /// - Encoding the decoded value gives the same canonical bytes.
    /// - Encoding `t` twice gives the same canonical bytes.
    pub(crate) fn round_trip(&self, t: &T) -> G<String> {
        let text = self.canonical(t)?;
        let parsed =
            parse(text.as_bytes()).map_err(|e| format!("canonical text does not parse: {e}"))?;
        let back = self
            .decode(&parsed)?
            .map_err(|e| format!("canonical encoding does not decode: {e}\n  text: {text}"))?;
        if &back != t {
            return Err(format!(
                "decode(encode(v)) differs from v\n  v:    {t:?}\n  back: {back:?}\n  text: {text}"
            ));
        }
        let again = self.canonical(&back)?;
        if again != text {
            return Err(format!(
                "canonical bytes changed after a round trip\n  first:  {text}\n  second: {again}"
            ));
        }
        let twice = self.canonical(t)?;
        if twice != text {
            return Err(format!(
                "encoding is not deterministic\n  first:  {text}\n  second: {twice}"
            ));
        }
        Ok(text)
    }

    /// Whether the codec refuses `v`. The outer error means the codec is missing.
    pub(crate) fn refuses(&self, v: &Value) -> G<bool> {
        Ok(self.decode(v)?.is_err())
    }

    /// Checks that adding an unknown member to any object of the encoding of
    /// `t` makes the decoder refuse it (design sections 5.1 and 7).
    pub(crate) fn rejects_unknown_members(&self, t: &T) -> G<()> {
        let v = self.encode(t)?;
        if v.as_object().is_none() {
            return Err(format!(
                "the top-level encoding is not an object: {}",
                v.to_compact()
            ));
        }
        for path in object_paths(&v) {
            for extra in [
                Value::Null,
                Value::String("x".to_owned()),
                Value::Bool(true),
            ] {
                let mut m = v.clone();
                insert_member(&mut m, &path, UNKNOWN, extra)?;
                if !self.refuses(&m)? {
                    return Err(format!(
                        "an unknown member at {path:?} was accepted\n  input: {}",
                        m.to_compact()
                    ));
                }
            }
        }
        Ok(())
    }

    /// Checks that `e` holds no part of [`MARKER`] in its display, debug or
    /// full path forms (R-NF-02).
    pub(crate) fn error_holds_no_marker(e: &FromJsonError, context: &str) -> G<()> {
        let forms = [
            ("Display", format!("{e}")),
            ("Debug", format!("{e:?}")),
            ("path", e.path().full()),
        ];
        for (label, text) in forms {
            if text.contains("QZXJ") || text.contains("7c1f") {
                return Err(format!(
                    "the error {label} form holds input content ({context}): {text}"
                ));
            }
        }
        Ok(())
    }

    /// Checks R-NF-02 over the encoding of `t`:
    ///
    /// - an unknown member named with input content, at every object, is
    ///   refused with an error that does not hold the name;
    /// - each string value replaced by input content, when refused, gives an
    ///   error that does not hold the content;
    /// - each string value replaced by an object keyed by input content,
    ///   when refused, gives an error that does not hold the key.
    pub(crate) fn errors_hold_no_input_content(&self, t: &T) -> G<()> {
        let v = self.encode(t)?;
        for path in object_paths(&v) {
            let mut m = v.clone();
            insert_member(&mut m, &path, MARKER, Value::Null)?;
            match self.decode(&m)? {
                Ok(_) => return Err(format!("a member named {MARKER} at {path:?} was accepted")),
                Err(e) => Self::error_holds_no_marker(&e, "unknown member name")?,
            }
        }
        for (path, _) in string_leaves(&v) {
            let mut m = v.clone();
            set_at(&mut m, &path, Value::String(MARKER.to_owned()))?;
            if let Err(e) = self.decode(&m)? {
                Self::error_holds_no_marker(&e, "string value")?;
            }
            let mut o = v.clone();
            let mut keyed = Object::new();
            keyed.insert(MARKER, Value::Null);
            set_at(&mut o, &path, Value::Object(keyed))?;
            // An opaque parameter value may legally hold an object, so only
            // a refusal is checked.
            if let Err(e) = self.decode(&o)? {
                Self::error_holds_no_marker(&e, "object in place of a string")?;
            }
        }
        Ok(())
    }

    /// The encoding of `t` and the paths of its amount and percentage
    /// strings. At least one must exist, so a check over them is never
    /// vacuous. A value that holds amounts but encodes none as a string fails
    /// here, which also catches amounts written as JSON numbers.
    fn amount_leaves(&self, t: &T) -> G<(Value, Vec<Leaf>)> {
        let v = self.encode(t)?;
        let leaves: Vec<Leaf> = string_leaves(&v)
            .into_iter()
            .filter(|(_, s)| is_amount_text(s))
            .collect();
        if leaves.is_empty() {
            return Err(format!(
                "no ADR-006 amount string in the encoding of a value that holds amounts: {}",
                v.to_compact()
            ));
        }
        Ok((v, leaves))
    }

    /// Checks ADR-006 over the encoding of `t`: a JSON number in place of
    /// any amount or percentage string is refused.
    pub(crate) fn rejects_number_amounts(&self, t: &T) -> G<()> {
        let (v, leaves) = self.amount_leaves(t)?;
        for (path, s) in &leaves {
            let number = Number::from_lexeme(s).map_err(|e| format!("lexeme {s}: {e}"))?;
            let mut m = v.clone();
            set_at(&mut m, path, Value::Number(number))?;
            if !self.refuses(&m)? {
                return Err(format!(
                    "the JSON number {s} was accepted in place of an amount string at {path:?}"
                ));
            }
        }
        Ok(())
    }

    /// Checks ADR-006 over the encoding of `t`: every other spelling of an
    /// amount or percentage string is refused, never normalised.
    pub(crate) fn rejects_other_amount_spellings(&self, t: &T) -> G<()> {
        let (v, leaves) = self.amount_leaves(t)?;
        for (path, s) in &leaves {
            for other in other_amount_spellings(s) {
                let mut m = v.clone();
                set_at(&mut m, path, Value::String(other.clone()))?;
                if !self.refuses(&m)? {
                    return Err(format!(
                        "the spelling {other:?} was accepted in place of {s:?} at {path:?}"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Checks design section 2.1 over the encoding of `t`, drawn with a
    /// marked [`Draw`]: every u128 id and every `Seq` appears as a decimal
    /// string or a member name, and has exactly one spelling.
    pub(crate) fn ids_are_decimal_strings(&self, t: &T, d: &Draw) -> G<()> {
        let v = self.encode(t)?;
        let leaves = string_leaves(&v);
        let keys = member_names(&v);
        let wanted: BTreeSet<String> = d
            .ids
            .iter()
            .map(u128::to_string)
            .chain(d.seqs.iter().map(u64::to_string))
            .collect();
        for decimal in &wanted {
            let at_leaves: Vec<&Vec<Step>> = leaves
                .iter()
                .filter(|(_, s)| s == decimal)
                .map(|(p, _)| p)
                .collect();
            let at_keys: Vec<&(Vec<Step>, String)> =
                keys.iter().filter(|(_, k)| k == decimal).collect();
            if at_leaves.is_empty() && at_keys.is_empty() {
                return Err(format!(
                    "the id {decimal} is not a decimal string in the encoding: {}",
                    v.to_compact()
                ));
            }
            // A member name is always a string, so only values can be
            // swapped for a JSON number.
            for path in at_leaves {
                let number =
                    Number::from_lexeme(decimal).map_err(|e| format!("lexeme {decimal}: {e}"))?;
                let mut m = v.clone();
                set_at(&mut m, path, Value::Number(number))?;
                if !self.refuses(&m)? {
                    return Err(format!(
                        "the JSON number {decimal} was accepted in place of an id string"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Checks that each marked id or `Seq` has one spelling: a leading zero,
    /// a plus sign, surrounding space or a hex form is refused, as a string
    /// value and as a member name. The decoder never normalises, so the
    /// canonical bytes of a record are unique (ADR-007).
    pub(crate) fn ids_have_one_spelling(&self, t: &T, d: &Draw) -> G<()> {
        let v = self.encode(t)?;
        let wanted: BTreeSet<String> = d
            .ids
            .iter()
            .map(u128::to_string)
            .chain(d.seqs.iter().map(u64::to_string))
            .collect();
        let mut checked = 0usize;
        for (path, s) in string_leaves(&v) {
            if !wanted.contains(&s) {
                continue;
            }
            checked = checked.saturating_add(1);
            for other in other_id_spellings(&s) {
                let mut m = v.clone();
                set_at(&mut m, &path, Value::String(other.clone()))?;
                if !self.refuses(&m)? {
                    return Err(format!(
                        "the id spelling {other:?} was accepted in place of {s:?} at {path:?}"
                    ));
                }
            }
        }
        for (path, k) in member_names(&v) {
            if !wanted.contains(&k) {
                continue;
            }
            checked = checked.saturating_add(1);
            for other in other_id_spellings(&k) {
                let mut m = v.clone();
                rename_member(&mut m, &path, &k, &other)?;
                if !self.refuses(&m)? {
                    return Err(format!(
                        "the id member name {other:?} was accepted in place of {k:?} at {path:?}"
                    ));
                }
            }
        }
        if checked == 0 && !wanted.is_empty() {
            return Err("no marked id appears as a decimal string".to_owned());
        }
        Ok(())
    }
}

/// Whether `s` matches the EUR amount grammar of ADR-006, which percentages
/// share: `(0|[1-9][0-9]*)\.[0-9]{2}`.
pub(crate) fn is_amount_text(s: &str) -> bool {
    let Some((int, frac)) = s.split_once('.') else {
        return false;
    };
    let int_ok = int == "0"
        || (!int.is_empty() && !int.starts_with('0') && int.bytes().all(|b| b.is_ascii_digit()));
    int_ok && frac.len() == 2 && frac.bytes().all(|b| b.is_ascii_digit())
}

/// Other spellings of the canonical amount text `s`, each of which ADR-006
/// rejects on input.
pub(crate) fn other_amount_spellings(s: &str) -> Vec<String> {
    let mut out = vec![
        format!("{s}0"),
        format!("+{s}"),
        format!("-{s}"),
        format!("0{s}"),
        format!(" {s}"),
        format!("{s} "),
        s.replace('.', ","),
    ];
    if let Some(short) = s.strip_suffix(|c: char| c.is_ascii_digit()) {
        out.push(short.to_owned());
    }
    if let Some((int, _)) = s.split_once('.') {
        out.push(int.to_owned());
        out.push(format!("{int}."));
    }
    out
}

/// Other spellings of the decimal id text `s`, each of which must be refused.
pub(crate) fn other_id_spellings(s: &str) -> Vec<String> {
    let mut out = vec![
        format!("0{s}"),
        format!("+{s}"),
        format!(" {s}"),
        format!("{s} "),
        format!("{s}.0"),
        format!("-{s}"),
    ];
    if let Ok(n) = s.parse::<u128>() {
        out.push(format!("0x{n:x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// JSON tree helpers
// ---------------------------------------------------------------------------

/// A path in a JSON value and the string found there.
pub(crate) type Leaf = (Vec<Step>, String);

/// One step from a JSON value to a child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// A member of an object.
    Key(String),
    /// An element of an array.
    Index(usize),
}

fn child<'a>(v: &'a Value, s: &Step) -> Option<&'a Value> {
    match (v, s) {
        (Value::Object(o), Step::Key(k)) => o.get(k),
        (Value::Array(a), Step::Index(i)) => a.get(*i),
        _ => None,
    }
}

fn child_mut<'a>(v: &'a mut Value, s: &Step) -> Option<&'a mut Value> {
    match (v, s) {
        (Value::Object(o), Step::Key(k)) => o.get_mut(k),
        (Value::Array(a), Step::Index(i)) => a.get_mut(*i),
        _ => None,
    }
}

/// The value at `path`.
pub(crate) fn get_at<'a>(v: &'a Value, path: &[Step]) -> Option<&'a Value> {
    path.iter().try_fold(v, child)
}

/// The value at `path`, mutably.
pub(crate) fn get_at_mut<'a>(v: &'a mut Value, path: &[Step]) -> Option<&'a mut Value> {
    let mut cur = v;
    for s in path {
        cur = child_mut(cur, s)?;
    }
    Some(cur)
}

/// Replaces the value at `path`.
pub(crate) fn set_at(v: &mut Value, path: &[Step], new: Value) -> G<()> {
    let slot = get_at_mut(v, path).ok_or_else(|| format!("no value at {path:?}"))?;
    *slot = new;
    Ok(())
}

/// Adds the member `key` to the object at `path`.
pub(crate) fn insert_member(v: &mut Value, path: &[Step], key: &str, value: Value) -> G<()> {
    let slot = get_at_mut(v, path).ok_or_else(|| format!("no value at {path:?}"))?;
    let o = slot
        .as_object_mut()
        .ok_or_else(|| format!("no object at {path:?}"))?;
    o.insert(key, value);
    Ok(())
}

/// Renames the member `from` of the object at `path` to `to`, keeping its value.
pub(crate) fn rename_member(v: &mut Value, path: &[Step], from: &str, to: &str) -> G<()> {
    let slot = get_at_mut(v, path).ok_or_else(|| format!("no value at {path:?}"))?;
    let o = slot
        .as_object_mut()
        .ok_or_else(|| format!("no object at {path:?}"))?;
    let value = o
        .remove(from)
        .ok_or_else(|| format!("no member {from:?} at {path:?}"))?;
    o.insert(to, value);
    Ok(())
}

fn walk(v: &Value, path: &mut Vec<Step>, f: &mut dyn FnMut(&[Step], &Value)) {
    f(path, v);
    match v {
        Value::Object(o) => {
            for (k, c) in o.iter() {
                path.push(Step::Key(k.to_owned()));
                walk(c, path, f);
                path.pop();
            }
        }
        Value::Array(a) => {
            for (i, c) in a.iter().enumerate() {
                path.push(Step::Index(i));
                walk(c, path, f);
                path.pop();
            }
        }
        _ => {}
    }
}

/// The paths of every object in `v`, the root included.
pub(crate) fn object_paths(v: &Value) -> Vec<Vec<Step>> {
    let mut out = Vec::new();
    walk(v, &mut Vec::new(), &mut |p, x| {
        if x.as_object().is_some() {
            out.push(p.to_vec());
        }
    });
    out
}

/// Every string value in `v` with its path.
pub(crate) fn string_leaves(v: &Value) -> Vec<(Vec<Step>, String)> {
    let mut out = Vec::new();
    walk(v, &mut Vec::new(), &mut |p, x| {
        if let Some(s) = x.as_str() {
            out.push((p.to_vec(), s.to_owned()));
        }
    });
    out
}

/// Every member name in `v`, with the path of its object.
pub(crate) fn member_names(v: &Value) -> Vec<(Vec<Step>, String)> {
    let mut out = Vec::new();
    walk(v, &mut Vec::new(), &mut |p, x| {
        if let Some(o) = x.as_object() {
            for k in o.keys() {
                out.push((p.to_vec(), k.to_owned()));
            }
        }
    });
    out
}

/// Whether `v` holds a JSON number anywhere.
pub(crate) fn has_number(v: &Value) -> bool {
    let mut found = false;
    walk(v, &mut Vec::new(), &mut |_, x| {
        if x.as_number().is_some() {
            found = true;
        }
    });
    found
}

/// The value at `path` exists.
pub(crate) fn exists(v: &Value, path: &[Step]) -> bool {
    get_at(v, path).is_some()
}

// ---------------------------------------------------------------------------
// Record variants
// ---------------------------------------------------------------------------

/// The fieldless tag of a [`Record`], with an exhaustive mapping, so a new
/// record variant fails to compile here until the tests cover it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum RecordTag {
    ProgrammeCreated,
    PolicyVersionRecorded,
    CallDrafted,
    CallEdited,
    CallApproved,
    CallPublished,
    BindingGranted,
    BindingEnded,
    BindingSuspended,
    BindingVoided,
    BindingReinstated,
    VaultEpochProcessed,
    ProposalCreated,
    PlanVersionRecorded,
    Submitted,
    Assigned,
    ConflictDeclared,
    ConflictDetected,
    AssignmentReleased,
    ContentRead,
    KnockOutRecorded,
    ScoreRecorded,
    ScoreVoided,
    RankingSummaryRecorded,
    Stage1Closed,
    QuestionAsked,
    NoQuestionsRecorded,
    AnswersRecorded,
    RevisionSubmitted,
    EffectiveScoreSet,
    CutOffRecorded,
    IrcReviewRecorded,
    DeferralRecorded,
    ReEntered,
    AmountDetermined,
    CapReserved,
    CapReleased,
    GrantAccepted,
    GrantApproved,
    ContractFactRecorded,
    GrantDecided,
    NegotiationDeclined,
    TerminationRecorded,
    Transitioned,
    VaultOutcome,
    OutboxEnqueued,
    PaymentRequested,
    LineAccepted,
    PaymentApproved,
    PaymentReleased,
    PaymentConfirmed,
    PaymentRequestWithdrawn,
    PaymentChangesRequested,
    DeliverableRecorded,
    AmendmentProposed,
    AmendmentRouted,
    AmendmentActivated,
}

impl RecordTag {
    /// Every tag, in declaration order of [`Record`].
    pub(crate) const ALL: [RecordTag; 57] = [
        RecordTag::ProgrammeCreated,
        RecordTag::PolicyVersionRecorded,
        RecordTag::CallDrafted,
        RecordTag::CallEdited,
        RecordTag::CallApproved,
        RecordTag::CallPublished,
        RecordTag::BindingGranted,
        RecordTag::BindingEnded,
        RecordTag::BindingSuspended,
        RecordTag::BindingVoided,
        RecordTag::BindingReinstated,
        RecordTag::VaultEpochProcessed,
        RecordTag::ProposalCreated,
        RecordTag::PlanVersionRecorded,
        RecordTag::Submitted,
        RecordTag::Assigned,
        RecordTag::ConflictDeclared,
        RecordTag::ConflictDetected,
        RecordTag::AssignmentReleased,
        RecordTag::ContentRead,
        RecordTag::KnockOutRecorded,
        RecordTag::ScoreRecorded,
        RecordTag::ScoreVoided,
        RecordTag::RankingSummaryRecorded,
        RecordTag::Stage1Closed,
        RecordTag::QuestionAsked,
        RecordTag::NoQuestionsRecorded,
        RecordTag::AnswersRecorded,
        RecordTag::RevisionSubmitted,
        RecordTag::EffectiveScoreSet,
        RecordTag::CutOffRecorded,
        RecordTag::IrcReviewRecorded,
        RecordTag::DeferralRecorded,
        RecordTag::ReEntered,
        RecordTag::AmountDetermined,
        RecordTag::CapReserved,
        RecordTag::CapReleased,
        RecordTag::GrantAccepted,
        RecordTag::GrantApproved,
        RecordTag::ContractFactRecorded,
        RecordTag::GrantDecided,
        RecordTag::NegotiationDeclined,
        RecordTag::TerminationRecorded,
        RecordTag::Transitioned,
        RecordTag::VaultOutcome,
        RecordTag::OutboxEnqueued,
        RecordTag::PaymentRequested,
        RecordTag::LineAccepted,
        RecordTag::PaymentApproved,
        RecordTag::PaymentReleased,
        RecordTag::PaymentConfirmed,
        RecordTag::PaymentRequestWithdrawn,
        RecordTag::PaymentChangesRequested,
        RecordTag::DeliverableRecorded,
        RecordTag::AmendmentProposed,
        RecordTag::AmendmentRouted,
        RecordTag::AmendmentActivated,
    ];

    /// The four payloads that only a witness builds. Tests cannot construct
    /// them, so their round trip is checked over the fuzz seed corpus.
    pub(crate) const WITNESS: [RecordTag; 4] = [
        RecordTag::Stage1Closed,
        RecordTag::EffectiveScoreSet,
        RecordTag::GrantDecided,
        RecordTag::PaymentReleased,
    ];

    /// Whether only a witness builds this payload.
    pub(crate) fn witness(self) -> bool {
        RecordTag::WITNESS.contains(&self)
    }

    /// Whether every generated value of this variant holds an amount or a
    /// percentage when drawn with `Draw::with_amounts`.
    pub(crate) fn holds_amounts(self) -> bool {
        matches!(
            self,
            RecordTag::PolicyVersionRecorded
                | RecordTag::CallDrafted
                | RecordTag::CallEdited
                | RecordTag::PlanVersionRecorded
                | RecordTag::CutOffRecorded
                | RecordTag::AmountDetermined
                | RecordTag::CapReserved
                | RecordTag::CapReleased
                | RecordTag::PaymentRequested
                | RecordTag::LineAccepted
        )
    }

    /// The tag of `r`.
    pub(crate) fn of(r: &Record) -> RecordTag {
        match r {
            Record::ProgrammeCreated { .. } => RecordTag::ProgrammeCreated,
            Record::PolicyVersionRecorded { .. } => RecordTag::PolicyVersionRecorded,
            Record::CallDrafted { .. } => RecordTag::CallDrafted,
            Record::CallEdited { .. } => RecordTag::CallEdited,
            Record::CallApproved { .. } => RecordTag::CallApproved,
            Record::CallPublished { .. } => RecordTag::CallPublished,
            Record::BindingGranted(_) => RecordTag::BindingGranted,
            Record::BindingEnded(_) => RecordTag::BindingEnded,
            Record::BindingSuspended(_) => RecordTag::BindingSuspended,
            Record::BindingVoided(_) => RecordTag::BindingVoided,
            Record::BindingReinstated(_) => RecordTag::BindingReinstated,
            Record::VaultEpochProcessed { .. } => RecordTag::VaultEpochProcessed,
            Record::ProposalCreated { .. } => RecordTag::ProposalCreated,
            Record::PlanVersionRecorded(_) => RecordTag::PlanVersionRecorded,
            Record::Submitted { .. } => RecordTag::Submitted,
            Record::Assigned(_) => RecordTag::Assigned,
            Record::ConflictDeclared(_) => RecordTag::ConflictDeclared,
            Record::ConflictDetected(_) => RecordTag::ConflictDetected,
            Record::AssignmentReleased(_) => RecordTag::AssignmentReleased,
            Record::ContentRead(_) => RecordTag::ContentRead,
            Record::KnockOutRecorded { .. } => RecordTag::KnockOutRecorded,
            Record::ScoreRecorded(_) => RecordTag::ScoreRecorded,
            Record::ScoreVoided(_) => RecordTag::ScoreVoided,
            Record::RankingSummaryRecorded { .. } => RecordTag::RankingSummaryRecorded,
            Record::Stage1Closed(_) => RecordTag::Stage1Closed,
            Record::QuestionAsked { .. } => RecordTag::QuestionAsked,
            Record::NoQuestionsRecorded { .. } => RecordTag::NoQuestionsRecorded,
            Record::AnswersRecorded { .. } => RecordTag::AnswersRecorded,
            Record::RevisionSubmitted { .. } => RecordTag::RevisionSubmitted,
            Record::EffectiveScoreSet(_) => RecordTag::EffectiveScoreSet,
            Record::CutOffRecorded(_) => RecordTag::CutOffRecorded,
            Record::IrcReviewRecorded { .. } => RecordTag::IrcReviewRecorded,
            Record::DeferralRecorded { .. } => RecordTag::DeferralRecorded,
            Record::ReEntered { .. } => RecordTag::ReEntered,
            Record::AmountDetermined { .. } => RecordTag::AmountDetermined,
            Record::CapReserved { .. } => RecordTag::CapReserved,
            Record::CapReleased { .. } => RecordTag::CapReleased,
            Record::GrantAccepted { .. } => RecordTag::GrantAccepted,
            Record::GrantApproved { .. } => RecordTag::GrantApproved,
            Record::ContractFactRecorded { .. } => RecordTag::ContractFactRecorded,
            Record::GrantDecided(_) => RecordTag::GrantDecided,
            Record::NegotiationDeclined { .. } => RecordTag::NegotiationDeclined,
            Record::TerminationRecorded { .. } => RecordTag::TerminationRecorded,
            Record::Transitioned(_) => RecordTag::Transitioned,
            Record::VaultOutcome { .. } => RecordTag::VaultOutcome,
            Record::OutboxEnqueued(_) => RecordTag::OutboxEnqueued,
            Record::PaymentRequested { .. } => RecordTag::PaymentRequested,
            Record::LineAccepted { .. } => RecordTag::LineAccepted,
            Record::PaymentApproved { .. } => RecordTag::PaymentApproved,
            Record::PaymentReleased(_) => RecordTag::PaymentReleased,
            Record::PaymentConfirmed { .. } => RecordTag::PaymentConfirmed,
            Record::PaymentRequestWithdrawn { .. } => RecordTag::PaymentRequestWithdrawn,
            Record::PaymentChangesRequested { .. } => RecordTag::PaymentChangesRequested,
            Record::DeliverableRecorded(_) => RecordTag::DeliverableRecorded,
            Record::AmendmentProposed { .. } => RecordTag::AmendmentProposed,
            Record::AmendmentRouted { .. } => RecordTag::AmendmentRouted,
            Record::AmendmentActivated { .. } => RecordTag::AmendmentActivated,
        }
    }

    /// Every tag that tests can generate.
    pub(crate) fn generated() -> Vec<RecordTag> {
        RecordTag::ALL
            .into_iter()
            .filter(|t| !t.witness())
            .collect()
    }
}

/// The command kinds whose generated values hold an amount when drawn with
/// `Draw::with_amounts`.
pub(crate) fn command_holds_amounts(k: CommandKind) -> bool {
    matches!(
        k,
        CommandKind::CreateProgramme
            | CommandKind::EditPolicy
            | CommandKind::DraftCall
            | CommandKind::EditCall
            | CommandKind::RecordPlanVersion
            | CommandKind::DetermineAmount
            | CommandKind::RequestPayment
            | CommandKind::AcceptLine
    )
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// The smallest marked id. Marked ids lie above `u64::MAX`, so no other
/// number in a value spells the same decimal.
const MARK_BASE: u128 = 1 << 64;

/// The smallest marked `Seq`. It is not a power of two and lies above 2^53.
const SEQ_MARK_BASE: u64 = 4_611_686_018_427_400_000;

/// How a generator draws, and what it saw.
#[derive(Debug, Default)]
pub(crate) struct Draw {
    /// Draw ids above `u64::MAX` and record each one.
    pub(crate) marked: bool,
    /// Make every collection that holds amounts non-empty.
    pub(crate) with_amounts: bool,
    /// The marked ids drawn.
    pub(crate) ids: Vec<u128>,
    /// The marked `Seq` values drawn.
    pub(crate) seqs: Vec<u64>,
}

impl Draw {
    /// Plain draws over the whole id domain.
    pub(crate) fn plain() -> Draw {
        Draw::default()
    }

    /// Marked draws, for the id tests.
    pub(crate) fn marked() -> Draw {
        Draw {
            marked: true,
            ..Draw::default()
        }
    }

    /// Draws whose amount collections are never empty, for the ADR-006 tests.
    pub(crate) fn amounts() -> Draw {
        Draw {
            with_amounts: true,
            ..Draw::default()
        }
    }

    fn min_len(&self) -> usize {
        usize::from(self.with_amounts)
    }
}

/// A raw id over the whole u128 domain, or a recorded marked id.
pub(crate) fn raw(g: &mut Gen, d: &mut Draw) -> u128 {
    if d.marked {
        let r = MARK_BASE | u128::from(g.u64());
        d.ids.push(r);
        r
    } else {
        let hi = u128::from(g.u64()).checked_shl(64).unwrap_or(0);
        hi | u128::from(g.u64())
    }
}

/// An id built by `f` from a raw draw.
pub(crate) fn id<T>(g: &mut Gen, d: &mut Draw, f: fn(u128) -> T) -> T {
    f(raw(g, d))
}

fn bytes16(g: &mut Gen) -> [u8; 16] {
    let mut a = [0u8; 16];
    for b in &mut a {
        *b = g.u8();
    }
    a
}

/// A content digest.
pub(crate) fn digest(g: &mut Gen) -> ContentDigest {
    let mut a = [0u8; 32];
    for b in &mut a {
        *b = g.u8();
    }
    ContentDigest::from_bytes(a)
}

/// A reference to free text held outside the ledger (ADR-007).
pub(crate) fn text(g: &mut Gen, d: &mut Draw) -> TextRef {
    TextRef::new(id(g, d, TextId::from_raw), digest(g))
}

/// A handle.
pub(crate) fn handle(g: &mut Gen) -> Handle {
    Handle::from_bytes(bytes16(g))
}

/// A timestamp within `MAX_AT` in magnitude.
pub(crate) fn ts(g: &mut Gen) -> Timestamp {
    Timestamp::from_micros(g.i64_in(-MAX_AT..=MAX_AT))
}

/// A vault epoch over the whole u64 domain.
pub(crate) fn epoch(g: &mut Gen) -> VaultEpoch {
    VaultEpoch::from_raw(g.u64())
}

/// A ledger sequence number from 1, recorded when marked.
pub(crate) fn seq(g: &mut Gen, d: &mut Draw) -> Seq {
    if d.marked {
        let s = g.u64_in(SEQ_MARK_BASE..=SEQ_MARK_BASE.saturating_add(u64::from(u32::MAX)));
        d.seqs.push(s);
        Seq::from_raw(s)
    } else {
        Seq::from_raw(g.u64_in(1..=u64::MAX))
    }
}

/// A call sequence number.
pub(crate) fn call_seq(g: &mut Gen) -> G<CallSeq> {
    let n = NonZeroU32::new(g.u32_in(1..=u32::MAX)).ok_or("call seq 0")?;
    Ok(CallSeq::new(n))
}

/// A string that starts with a letter, so it never matches the id or
/// amount grammar. The rest is any Unicode text.
pub(crate) fn word(g: &mut Gen) -> String {
    let mut s = String::from("x");
    s.push_str(&g.string(0..=12));
    s
}

/// A valid zone name.
pub(crate) fn zone(g: &mut Gen) -> G<ZoneName> {
    const CHARS: &[u8] = b"ABCZabcz019/_+-";
    let n = g.usize_in(1..=ZONE_NAME_MAX);
    let s: String = (0..n).map(|_| char::from(*g.pick(CHARS))).collect();
    ZoneName::new(&s).ok_or_else(|| format!("zone name {s:?} refused"))
}

/// A model name.
pub(crate) fn model(g: &mut Gen) -> ModelRef {
    ModelRef(word(g))
}

/// An SPDX identifier.
pub(crate) fn spdx(g: &mut Gen) -> SpdxId {
    const IDS: [&str; 6] = [
        "MIT",
        "Apache-2.0",
        "EUPL-1.2",
        "GPL-3.0-or-later",
        "BSD-3-Clause",
        "MPL-2.0",
    ];
    if g.bool() {
        SpdxId((*g.pick(&IDS)).to_owned())
    } else {
        SpdxId(format!("LicenseRef-{}", word(g)))
    }
}

/// A signed amount over the whole range of `Amount`, with zero and both
/// edges weighted.
pub(crate) fn signed(g: &mut Gen) -> G<Amount> {
    const MAX: i64 = Amount::MAX_ABS_MINOR;
    const MIN: i64 = -Amount::MAX_ABS_MINOR;
    let minor = match g.weighted(&[1, 1, 1, 5]) {
        0 => 0,
        1 => MIN,
        2 => MAX,
        _ => g.i64_in(MIN..=MAX),
    };
    Amount::from_minor(minor, Currency::Eur).map_err(|e| format!("amount: {e}"))
}

/// An amount of zero or more.
pub(crate) fn nonneg(g: &mut Gen) -> G<NonNegAmount> {
    let a = Amount::from_minor(g.i64_in(0..=Amount::MAX_ABS_MINOR), Currency::Eur)
        .map_err(|e| format!("amount: {e}"))?;
    NonNegAmount::new(a).map_err(|e| format!("non-negative amount: {e}"))
}

/// An amount above zero.
pub(crate) fn pos(g: &mut Gen) -> G<PosAmount> {
    let a = Amount::from_minor(g.i64_in(1..=Amount::MAX_ABS_MINOR), Currency::Eur)
        .map_err(|e| format!("amount: {e}"))?;
    PosAmount::new(a).map_err(|e| format!("positive amount: {e}"))
}

/// A percentage from 0.00 to 100.00.
pub(crate) fn percent(g: &mut Gen) -> G<Percent> {
    let bp = g.u16_in(0..=10_000);
    Percent::from_bp(bp).ok_or_else(|| format!("percent {bp} bp refused"))
}

fn nz8(g: &mut Gen) -> G<NonZeroU8> {
    NonZeroU8::new(g.u8_in(1..=u8::MAX)).ok_or_else(|| "zero".to_owned())
}

/// A canonical JSON value with no object inside, so injected members can
/// only land in schema objects.
pub(crate) fn opaque(g: &mut Gen) -> G<OpaqueValue> {
    let v = scalar(g)?;
    let v = if g.bool() {
        let items = g
            .vec(0..=3, scalar)
            .into_iter()
            .collect::<G<Vec<Value>>>()?;
        Value::Array(items.into())
    } else {
        v
    };
    OpaqueValue::from_value(&v).map_err(|e| format!("opaque value: {e}"))
}

fn scalar(g: &mut Gen) -> G<Value> {
    Ok(match g.u8_in(0..=3) {
        0 => Value::Null,
        1 => Value::Bool(g.bool()),
        2 => Value::Number(
            Number::from_lexeme(&g.i32().to_string()).map_err(|e| format!("lexeme: {e}"))?,
        ),
        _ => Value::String(word(g)),
    })
}

fn opaque_map(g: &mut Gen) -> G<BTreeMap<ParamId, OpaqueValue>> {
    let mut m = BTreeMap::new();
    for _ in 0..g.usize_in(0..=4) {
        let p = *g.pick(&ParamId::ALL);
        m.insert(p, opaque(g)?);
    }
    Ok(m)
}

/// P-01 criteria within the checked bounds, with unique ids.
pub(crate) fn criteria(g: &mut Gen, d: &mut Draw) -> G<Criteria> {
    let n = g.usize_in(1..=usize::from(Criteria::MAX_CRITERIA));
    let base = raw(g, d);
    let mut items = Vec::new();
    for i in 0..n {
        let r = base ^ u128::try_from(i).map_err(|_| "index")?;
        if d.marked && i > 0 {
            d.ids.push(r);
        }
        let weight = NonZeroU16::new(g.u16_in(1..=Criteria::MAX_WEIGHT)).ok_or("weight 0")?;
        items.push(Criterion {
            id: CriterionId::from_raw(r),
            weight,
        });
    }
    let scale = NonZeroU8::new(g.u8_in(1..=Criteria::MAX_SCALE)).ok_or("scale 0")?;
    Criteria::new(scale, items).map_err(|e| format!("criteria: {e}"))
}

/// A P-04 range, min at most max.
pub(crate) fn range(g: &mut Gen) -> G<AmountRange> {
    let a = nonneg(g)?;
    let b = nonneg(g)?;
    let (min, max) = match a.amount().cmp_same(b.amount()) {
        Ok(std::cmp::Ordering::Greater) => (b, a),
        _ => (a, b),
    };
    AmountRange::new(min, max).map_err(|e| format!("range: {e}"))
}

/// The frozen parameters of a policy version.
pub(crate) fn frozen(g: &mut Gen, d: &mut Draw) -> G<FrozenValues> {
    let p01 = criteria(g, d)?;
    let p02 = percent(g)?;
    let p03 = nz8(g)?;
    let p04 = range(g)?;
    let p07 = fstp_domain::time::Days::new(g.u16());
    let mut p09 = Vec::new();
    for _ in 0..g.usize_in(0..=3) {
        p09.push(KnockOutCriterion {
            id: id(g, d, KnockOutCriterionId::from_raw),
            text: text(g, d),
        });
    }
    Ok(FrozenValues {
        p01,
        p02,
        p03,
        p04,
        p07,
        p09: KnockOutCriteria(p09),
        p10: *g.pick(&[
            ReadAccess::AssignedReviewersOnly,
            ReadAccess::AllCommitteeMembers,
            ReadAccess::OperatorStaffOnly,
        ]),
        p11: *g.pick(&[ReviewerAnonymity::Anonymous, ReviewerAnonymity::Named]),
        p14: IrcExemptions(opaque(g)?),
        p15: nz8(g)?,
        p16: VotingRules(opaque(g)?),
        p17: TieBreakRule(opaque(g)?),
        p21: InferenceBinding {
            provider: opaque(g)?,
            primary: model(g),
            fallbacks: g.vec(0..=3, model),
        },
        p24: EffectiveScoreRule::HigherOfOriginalAndRevised,
        p26: LicenceSet(g.vec(0..=4, spdx).into_iter().collect()),
        p39: nz8(g)?,
        p53: FunderProfileRef(opaque(g)?),
        p77: *g.pick(&[McpBindingActions::DraftOnly, McpBindingActions::Allowed]),
        opaque: opaque_map(g)?,
    })
}

/// The live parameters of a policy version.
pub(crate) fn live(g: &mut Gen, d: &mut Draw) -> G<LiveValues> {
    let mut p13 = BTreeSet::new();
    for _ in 0..g.usize_in(0..=3) {
        p13.insert(id(g, d, ClassId::from_raw));
    }
    // Organisation ids are distinct by construction, so every drawn
    // proximity list id stays in the map.
    let mut p38 = BTreeMap::new();
    let base = raw(g, d);
    for i in 0..g.usize_in(0..=3) {
        let k = base ^ u128::try_from(i).map_err(|_| "index")?;
        if d.marked && i > 0 {
            d.ids.push(k);
        }
        let v = id(g, d, ProximityListId::from_raw);
        p38.insert(OrganisationId::from_raw(k), v);
    }
    if p38.is_empty() && d.marked {
        // The base id was drawn but is not in the value.
        d.ids.retain(|x| *x != base);
    }
    let p56 = if g.bool() { Some(nonneg(g)?) } else { None };
    let p58 = if g.bool() { Some(nonneg(g)?) } else { None };
    Ok(LiveValues {
        p05: nonneg(g)?,
        p12: CoolingOff(g.u8()),
        p13: ExclusionClasses(p13),
        p38: ProximityLists(p38),
        p56,
        p58,
        opaque: opaque_map(g)?,
    })
}

/// A policy version over the whole structural domain. The codec is
/// structural, so it keeps values that validation would refuse.
pub(crate) fn policy(g: &mut Gen, d: &mut Draw) -> G<PolicyVersion> {
    let pid = id(g, d, PolicyVersionId::from_raw);
    let programme = id(g, d, ProgrammeId::from_raw);
    let parent = if g.bool() {
        Some(id(g, d, PolicyVersionId::from_raw))
    } else {
        None
    };
    Ok(PolicyVersion {
        id: pid,
        programme,
        parent,
        currency: Currency::Eur,
        frozen: frozen(g, d)?,
        live: live(g, d)?,
    })
}

fn opt_text(g: &mut Gen, d: &mut Draw) -> Option<TextRef> {
    if g.bool() { Some(text(g, d)) } else { None }
}

fn opt_account(g: &mut Gen, d: &mut Draw) -> Option<AccountId> {
    if g.bool() {
        Some(id(g, d, AccountId::from_raw))
    } else {
        None
    }
}

fn role(g: &mut Gen) -> Role {
    *g.pick(&Role::ALL)
}

fn actor(g: &mut Gen, d: &mut Draw) -> Actor {
    if g.bool() {
        Actor::Account(id(g, d, AccountId::from_raw))
    } else {
        Actor::System(*g.pick(&[
            SystemCause::Timeline,
            SystemCause::Vault,
            SystemCause::ContractPort,
            SystemCause::PaymentPort,
        ]))
    }
}

fn plan_origin(g: &mut Gen) -> PlanOrigin {
    *g.pick(&[
        PlanOrigin::Submitted,
        PlanOrigin::Stage2Revision,
        PlanOrigin::Negotiated,
        PlanOrigin::Amendment,
    ])
}

fn milestone(g: &mut Gen, d: &mut Draw) -> G<Milestone> {
    let mid = id(g, d, MilestoneId::from_raw);
    let amount = pos(g)?;
    let start = ts(g);
    let due = ts(g);
    let activity = if g.bool() {
        Some(id(g, d, ActivityTypeId::from_raw))
    } else {
        None
    };
    let mut deliverables = Vec::new();
    for _ in 0..g.usize_in(0..=2) {
        deliverables.push(id(g, d, DeliverableId::from_raw));
    }
    Ok(Milestone {
        id: mid,
        amount,
        start,
        due,
        activity,
        deliverables,
    })
}

fn tasks(g: &mut Gen, d: &mut Draw) -> G<Vec<Task>> {
    let min = d.min_len();
    let mut out = Vec::new();
    for _ in 0..g.usize_in(min..=3) {
        let mut milestones = Vec::new();
        for _ in 0..g.usize_in(min..=3) {
            milestones.push(milestone(g, d)?);
        }
        out.push(Task { milestones });
    }
    Ok(out)
}

fn ethics(g: &mut Gen, d: &mut Draw) -> EthicsDeclaration {
    EthicsDeclaration {
        issues_declared: g.bool(),
        text: text(g, d),
    }
}

fn notice(g: &mut Gen) -> NoticeVersion {
    NoticeVersion(g.u32())
}

fn assignment_kind(g: &mut Gen, d: &mut Draw) -> AssignmentKind {
    match g.u8_in(0..=2) {
        0 => AssignmentKind::Reviewer,
        1 => AssignmentKind::Irc,
        _ => AssignmentKind::Amendment(id(g, d, AmendmentId::from_raw)),
    }
}

fn knock_outs(g: &mut Gen, d: &mut Draw) -> Vec<KnockOutResult> {
    let mut out = Vec::new();
    for _ in 0..g.usize_in(0..=4) {
        out.push(KnockOutResult {
            criterion: id(g, d, KnockOutCriterionId::from_raw),
            passed: g.bool(),
        });
    }
    out
}

fn score_key(g: &mut Gen, d: &mut Draw) -> ScoreKey {
    ScoreKey {
        assignment: id(g, d, AssignmentId::from_raw),
        stage: *g.pick(&[Stage::One, Stage::Two]),
        plan: id(g, d, PlanVersionId::from_raw),
    }
}

fn score_vector(g: &mut Gen) -> ScoreVector {
    ScoreVector(g.bytes(0..=16))
}

fn ballots(g: &mut Gen, d: &mut Draw) -> Vec<Ballot> {
    let mut out = Vec::new();
    for _ in 0..g.usize_in(0..=4) {
        out.push(Ballot {
            voter: id(g, d, AccountId::from_raw),
            vote: *g.pick(&[Vote::For, Vote::Against, Vote::Abstain]),
            delegated_by: opt_account(g, d),
        });
    }
    out
}

fn proposals(g: &mut Gen, d: &mut Draw) -> Vec<ProposalId> {
    let mut out = Vec::new();
    for _ in 0..g.usize_in(0..=4) {
        out.push(id(g, d, ProposalId::from_raw));
    }
    out
}

fn verdict(g: &mut Gen, d: &mut Draw) -> IrcVerdict {
    if g.bool() {
        IrcVerdict::Validate
    } else {
        IrcVerdict::Concern(text(g, d))
    }
}

fn deductions(g: &mut Gen, d: &mut Draw) -> G<Vec<IneligibleCost>> {
    let mut out = Vec::new();
    for _ in 0..g.usize_in(d.min_len()..=3) {
        out.push(IneligibleCost {
            amount: pos(g)?,
            reason: text(g, d),
        });
    }
    Ok(out)
}

fn lines(g: &mut Gen, d: &mut Draw) -> G<Vec<PaymentLine>> {
    let mut out = Vec::new();
    for _ in 0..g.usize_in(d.min_len()..=3) {
        out.push(PaymentLine {
            line: id(g, d, LineId::from_raw),
            milestone: id(g, d, MilestoneId::from_raw),
            amount: pos(g)?,
        });
    }
    Ok(out)
}

fn accounts(g: &mut Gen, d: &mut Draw) -> BTreeSet<AccountId> {
    let mut out = BTreeSet::new();
    for _ in 0..g.usize_in(0..=4) {
        out.insert(id(g, d, AccountId::from_raw));
    }
    out
}

fn rule_ref(g: &mut Gen) -> RuleRef {
    if g.u8_in(0..=3) == 0 {
        RuleRef::Param(*g.pick(&ParamId::ALL))
    } else {
        *g.pick(&RuleRef::ALL_FIXED)
    }
}

/// Every transition row.
pub(crate) const ROWS: [Row; 21] = [
    Row::DraftToSubmitted,
    Row::SubmittedToIneligible,
    Row::SubmittedToStage1,
    Row::Stage1ToNotSelected,
    Row::Stage1ToStage2,
    Row::Stage2ToRanked,
    Row::Stage2ToDeferred,
    Row::RankedToNotSelected,
    Row::RankedToIrcReview,
    Row::IrcReviewToNegotiation,
    Row::IrcReviewToDeferred,
    Row::IrcReviewToDeclined,
    Row::DeferredToStage2,
    Row::DeferredToIrcReview,
    Row::NegotiationToGranted,
    Row::NegotiationToDeclined,
    Row::Withdraw,
    Row::GrantedToInExecution,
    Row::GrantedToTerminated,
    Row::InExecutionToCompleted,
    Row::InExecutionToTerminated,
];

fn state_tag(g: &mut Gen) -> StateTag {
    *g.pick(&StateTag::ALL)
}

fn negotiation_failure(g: &mut Gen) -> NegotiationFailure {
    *g.pick(&[
        NegotiationFailure::IdentityNotVerified,
        NegotiationFailure::Sod09Refused,
        NegotiationFailure::ReceivingVoidedUnderI04,
        NegotiationFailure::ReceivingVoidedUnderI06,
        NegotiationFailure::NoAmountWithinRange,
        NegotiationFailure::NoAmountWithinCap,
        NegotiationFailure::RepeatRecordIncomplete,
        NegotiationFailure::GuardianConsentMissing,
    ])
}

fn reentry(g: &mut Gen) -> ReentryStage {
    *g.pick(&[ReentryStage::Stage2, ReentryStage::IrcReview])
}

fn route(g: &mut Gen) -> AmendmentRoute {
    *g.pick(&[AmendmentRoute::Exempt, AmendmentRoute::Irc])
}

fn rules(g: &mut Gen) -> RulesVersion {
    RulesVersion(g.u16())
}

fn outbox(g: &mut Gen, d: &mut Draw) -> OutboxEvent {
    match g.u8_in(0..=3) {
        0 => OutboxEvent::ProposalOutcome {
            proposal: id(g, d, ProposalId::from_raw),
            state: state_tag(g),
        },
        1 => OutboxEvent::IrcConcern {
            proposal: id(g, d, ProposalId::from_raw),
            concern: text(g, d),
        },
        2 => OutboxEvent::NotifiableConflict {
            proposal: id(g, d, ProposalId::from_raw),
        },
        _ => OutboxEvent::BindingEnded {
            binding: id(g, d, BindingId::from_raw),
        },
    }
}

/// A generated command of kind `k`.
pub(crate) fn command(g: &mut Gen, d: &mut Draw, k: CommandKind) -> G<Command> {
    Ok(match k {
        CommandKind::CreateProgramme => Command::CreateProgramme {
            policy: Box::new(policy(g, d)?),
        },
        CommandKind::EditPolicy => Command::EditPolicy {
            base: id(g, d, PolicyVersionId::from_raw),
            version: Box::new(policy(g, d)?),
        },
        CommandKind::DraftCall => Command::DraftCall {
            call: id(g, d, CallId::from_raw),
            programme: id(g, d, ProgrammeId::from_raw),
            opens: ts(g),
            deadline: ts(g),
            deadline_zone: zone(g)?,
            budget: nonneg(g)?,
            text: text(g, d),
        },
        CommandKind::EditCall => Command::EditCall {
            call: id(g, d, CallId::from_raw),
            opens: ts(g),
            deadline: ts(g),
            deadline_zone: zone(g)?,
            budget: nonneg(g)?,
            text: text(g, d),
        },
        CommandKind::ApproveCallPublication => Command::ApproveCallPublication {
            call: id(g, d, CallId::from_raw),
            decision: id(g, d, DecisionId::from_raw),
        },
        CommandKind::PublishCall => Command::PublishCall {
            call: id(g, d, CallId::from_raw),
            config: id(g, d, LlmConfigId::from_raw),
            config_model: model(g),
        },
        CommandKind::GrantRole => Command::GrantRole {
            binding: id(g, d, BindingId::from_raw),
            account: id(g, d, AccountId::from_raw),
            programme: id(g, d, ProgrammeId::from_raw),
            role: role(g),
            start: ts(g),
            second_admin: opt_account(g, d),
            confidentiality: opt_text(g, d),
            organisation: if g.bool() {
                Some(id(g, d, OrganisationId::from_raw))
            } else {
                None
            },
        },
        CommandKind::EndRole => Command::EndRole {
            binding: id(g, d, BindingId::from_raw),
            at: ts(g),
        },
        CommandKind::ReinstateBinding => Command::ReinstateBinding {
            binding: id(g, d, BindingId::from_raw),
            reason: text(g, d),
        },
        CommandKind::VaultChanged => Command::VaultChanged {
            epoch: epoch(g),
            changed: accounts(g, d),
        },
        CommandKind::CreateDraft => Command::CreateDraft {
            proposal: id(g, d, ProposalId::from_raw),
            call: id(g, d, CallId::from_raw),
            binding: id(g, d, BindingId::from_raw),
            minor: g.bool(),
        },
        CommandKind::AddTeamMember => Command::AddTeamMember {
            proposal: id(g, d, ProposalId::from_raw),
            account: id(g, d, AccountId::from_raw),
            binding: id(g, d, BindingId::from_raw),
        },
        CommandKind::AddGuardian => Command::AddGuardian {
            proposal: id(g, d, ProposalId::from_raw),
            account: id(g, d, AccountId::from_raw),
            binding: id(g, d, BindingId::from_raw),
        },
        CommandKind::RecordPlanVersion => Command::RecordPlanVersion {
            plan: id(g, d, PlanVersionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            origin: plan_origin(g),
            supersedes: if g.bool() {
                Some(id(g, d, PlanVersionId::from_raw))
            } else {
                None
            },
            tasks: tasks(g, d)?,
            content: digest(g),
        },
        CommandKind::Submit => Command::Submit {
            proposal: id(g, d, ProposalId::from_raw),
            plan: id(g, d, PlanVersionId::from_raw),
            ethics: ethics(g, d),
            notice: notice(g),
        },
        CommandKind::DeclareConflict => Command::DeclareConflict {
            subject: if g.bool() {
                DeclarationSubject::Assignment(id(g, d, AssignmentId::from_raw))
            } else {
                DeclarationSubject::Proposal(id(g, d, ProposalId::from_raw))
            },
            conflicted: g.bool(),
            notifiable: g.bool(),
        },
        CommandKind::Assign => Command::Assign {
            assignment: id(g, d, AssignmentId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            reviewer: id(g, d, AccountId::from_raw),
            kind: assignment_kind(g, d),
            handle: if g.bool() { Some(handle(g)) } else { None },
        },
        CommandKind::Unassign => Command::Unassign {
            assignment: id(g, d, AssignmentId::from_raw),
        },
        CommandKind::ReadContent => Command::ReadContent {
            proposal: id(g, d, ProposalId::from_raw),
        },
        CommandKind::RecordKnockOut => Command::RecordKnockOut {
            decision: id(g, d, DecisionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            outcomes: knock_outs(g, d),
            reason: opt_text(g, d),
        },
        CommandKind::AdmitToStage1 => Command::AdmitToStage1 {
            decision: id(g, d, DecisionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
        },
        CommandKind::RecordScore => Command::RecordScore {
            key: score_key(g, d),
            values: score_vector(g),
        },
        CommandKind::CorrectScore => Command::CorrectScore {
            key: score_key(g, d),
            values: score_vector(g),
            reason: text(g, d),
        },
        CommandKind::RecordRankingSummary => Command::RecordRankingSummary {
            proposal: id(g, d, ProposalId::from_raw),
            assignment: id(g, d, AssignmentId::from_raw),
            title: text(g, d),
            neutral_summary: text(g, d),
            rationale: text(g, d),
        },
        CommandKind::CloseStage1 => Command::CloseStage1 {
            proposal: id(g, d, ProposalId::from_raw),
        },
        CommandKind::AskQuestion => Command::AskQuestion {
            proposal: id(g, d, ProposalId::from_raw),
            assignment: id(g, d, AssignmentId::from_raw),
            text: text(g, d),
        },
        CommandKind::RecordNoQuestions => Command::RecordNoQuestions {
            proposal: id(g, d, ProposalId::from_raw),
            assignment: id(g, d, AssignmentId::from_raw),
        },
        CommandKind::AnswerQuestions => Command::AnswerQuestions {
            proposal: id(g, d, ProposalId::from_raw),
            text: text(g, d),
        },
        CommandKind::SubmitRevision => Command::SubmitRevision {
            proposal: id(g, d, ProposalId::from_raw),
            plan: id(g, d, PlanVersionId::from_raw),
        },
        CommandKind::RankAfterStage2 => Command::RankAfterStage2 {
            proposal: id(g, d, ProposalId::from_raw),
        },
        CommandKind::ExpireStage2 => Command::ExpireStage2 {
            proposal: id(g, d, ProposalId::from_raw),
        },
        CommandKind::RecordCutOff => Command::RecordCutOff {
            decision: id(g, d, DecisionId::from_raw),
            call: id(g, d, CallId::from_raw),
            order: proposals(g, d),
            nominated: g.u32(),
            rationale: text(g, d),
            tie_breaks: opt_text(g, d),
            ballots: ballots(g, d),
        },
        CommandKind::RecordIrcReview => Command::RecordIrcReview {
            assignment: id(g, d, AssignmentId::from_raw),
            verdict: verdict(g, d),
        },
        CommandKind::DeclineAfterConcern => Command::DeclineAfterConcern {
            proposal: id(g, d, ProposalId::from_raw),
        },
        CommandKind::ReEnter => Command::ReEnter {
            proposal: id(g, d, ProposalId::from_raw),
            call: id(g, d, CallId::from_raw),
        },
        CommandKind::DetermineAmount => Command::DetermineAmount {
            decision: id(g, d, DecisionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            agreed: id(g, d, PlanVersionId::from_raw),
            deductions: deductions(g, d)?,
        },
        CommandKind::AcceptGrant => Command::AcceptGrant {
            decision: id(g, d, DecisionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
        },
        CommandKind::ApproveGrant => Command::ApproveGrant {
            decision: id(g, d, DecisionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
        },
        CommandKind::ContractFact => Command::ContractFact {
            proposal: id(g, d, ProposalId::from_raw),
            contract: id(g, d, ContractId::from_raw),
            event: ContractEvent::Effective,
        },
        CommandKind::DeclineNegotiation => Command::DeclineNegotiation {
            proposal: id(g, d, ProposalId::from_raw),
        },
        CommandKind::Withdraw => Command::Withdraw {
            proposal: id(g, d, ProposalId::from_raw),
        },
        CommandKind::StartExecution => Command::StartExecution {
            proposal: id(g, d, ProposalId::from_raw),
        },
        CommandKind::Complete => Command::Complete {
            proposal: id(g, d, ProposalId::from_raw),
        },
        CommandKind::Terminate => Command::Terminate {
            decision: id(g, d, DecisionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            reason: text(g, d),
        },
        CommandKind::RequestPayment => Command::RequestPayment {
            request: id(g, d, RequestId::from_raw),
            grant: id(g, d, ProposalId::from_raw),
            lines: lines(g, d)?,
        },
        CommandKind::AcceptLine => Command::AcceptLine {
            request: id(g, d, RequestId::from_raw),
            line: id(g, d, LineId::from_raw),
            approved: nonneg(g)?,
            reason: opt_text(g, d),
        },
        CommandKind::ApprovePayment => Command::ApprovePayment {
            request: id(g, d, RequestId::from_raw),
        },
        CommandKind::ReleasePayment => Command::ReleasePayment {
            request: id(g, d, RequestId::from_raw),
        },
        CommandKind::ConfirmPaid => Command::ConfirmPaid {
            request: id(g, d, RequestId::from_raw),
        },
        CommandKind::WithdrawPaymentRequest => Command::WithdrawPaymentRequest {
            request: id(g, d, RequestId::from_raw),
        },
        CommandKind::RequestPaymentChanges => Command::RequestPaymentChanges {
            request: id(g, d, RequestId::from_raw),
            reason: text(g, d),
        },
        CommandKind::RecordDeliverable => Command::RecordDeliverable {
            deliverable: id(g, d, DeliverableId::from_raw),
            grant: id(g, d, ProposalId::from_raw),
            milestone: id(g, d, MilestoneId::from_raw),
            public_location: text(g, d),
            release: text(g, d),
            licence: spdx(g),
            snapshot: digest(g),
            accepted: g.bool(),
        },
        CommandKind::ProposeAmendment => Command::ProposeAmendment {
            amendment: id(g, d, AmendmentId::from_raw),
            grant: id(g, d, ProposalId::from_raw),
            plan: id(g, d, PlanVersionId::from_raw),
        },
        CommandKind::RouteAmendment => Command::RouteAmendment {
            amendment: id(g, d, AmendmentId::from_raw),
            route: route(g),
        },
        CommandKind::ActivateAmendment => Command::ActivateAmendment {
            amendment: id(g, d, AmendmentId::from_raw),
            contract: id(g, d, ContractId::from_raw),
        },
    })
}

/// A generated record of variant `t`. The four witness payloads have no
/// public constructor, so they are refused here.
pub(crate) fn record(g: &mut Gen, d: &mut Draw, t: RecordTag) -> G<Record> {
    Ok(match t {
        RecordTag::ProgrammeCreated => Record::ProgrammeCreated {
            programme: id(g, d, ProgrammeId::from_raw),
            currency: Currency::Eur,
            by: id(g, d, AccountId::from_raw),
        },
        RecordTag::PolicyVersionRecorded => Record::PolicyVersionRecorded {
            version: Box::new(policy(g, d)?),
            author: id(g, d, AccountId::from_raw),
        },
        RecordTag::CallDrafted => Record::CallDrafted {
            call: id(g, d, CallId::from_raw),
            programme: id(g, d, ProgrammeId::from_raw),
            opens: ts(g),
            deadline: ts(g),
            deadline_zone: zone(g)?,
            budget: nonneg(g)?,
            text: text(g, d),
            author: id(g, d, AccountId::from_raw),
        },
        RecordTag::CallEdited => Record::CallEdited {
            call: id(g, d, CallId::from_raw),
            opens: ts(g),
            deadline: ts(g),
            deadline_zone: zone(g)?,
            budget: nonneg(g)?,
            text: text(g, d),
            author: id(g, d, AccountId::from_raw),
        },
        RecordTag::CallApproved => Record::CallApproved {
            call: id(g, d, CallId::from_raw),
            decision: id(g, d, DecisionId::from_raw),
            approver: id(g, d, AccountId::from_raw),
        },
        RecordTag::CallPublished => Record::CallPublished {
            call: id(g, d, CallId::from_raw),
            policy: id(g, d, PolicyVersionId::from_raw),
            seq: call_seq(g)?,
            config: id(g, d, LlmConfigId::from_raw),
            by: id(g, d, AccountId::from_raw),
        },
        RecordTag::BindingGranted => Record::BindingGranted(BindingGranted {
            binding: id(g, d, BindingId::from_raw),
            account: id(g, d, AccountId::from_raw),
            programme: id(g, d, ProgrammeId::from_raw),
            role: role(g),
            scope: if g.bool() {
                BindingScope::Programme
            } else {
                BindingScope::Proposal {
                    proposal: id(g, d, ProposalId::from_raw),
                    call: id(g, d, CallId::from_raw),
                }
            },
            start: ts(g),
            granted_by: id(g, d, AccountId::from_raw),
            second_admin: opt_account(g, d),
            confidentiality: opt_text(g, d),
            organisation: if g.bool() {
                Some(id(g, d, OrganisationId::from_raw))
            } else {
                None
            },
            verified_epoch: if g.bool() { Some(epoch(g)) } else { None },
        }),
        RecordTag::BindingEnded => Record::BindingEnded(BindingEnded {
            binding: id(g, d, BindingId::from_raw),
            at: ts(g),
            barred_through: g.u32(),
            p12: CoolingOff(g.u8()),
        }),
        RecordTag::BindingSuspended => Record::BindingSuspended(BindingSuspended {
            binding: id(g, d, BindingId::from_raw),
            rule: rule_ref(g),
            epoch: epoch(g),
        }),
        RecordTag::BindingVoided => Record::BindingVoided(BindingVoided {
            binding: id(g, d, BindingId::from_raw),
            rule: rule_ref(g),
            epoch: epoch(g),
        }),
        RecordTag::BindingReinstated => Record::BindingReinstated(BindingReinstated {
            binding: id(g, d, BindingId::from_raw),
            by: id(g, d, AccountId::from_raw),
            reason: text(g, d),
        }),
        RecordTag::VaultEpochProcessed => Record::VaultEpochProcessed { epoch: epoch(g) },
        RecordTag::ProposalCreated => Record::ProposalCreated {
            proposal: id(g, d, ProposalId::from_raw),
            call: id(g, d, CallId::from_raw),
            lead: id(g, d, AccountId::from_raw),
            minor: g.bool(),
        },
        RecordTag::PlanVersionRecorded => Record::PlanVersionRecorded(PlanVersionRecorded {
            plan: id(g, d, PlanVersionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            origin: plan_origin(g),
            supersedes: if g.bool() {
                Some(id(g, d, PlanVersionId::from_raw))
            } else {
                None
            },
            tasks: tasks(g, d)?,
            content: digest(g),
        }),
        RecordTag::Submitted => Record::Submitted {
            proposal: id(g, d, ProposalId::from_raw),
            plan: id(g, d, PlanVersionId::from_raw),
            ethics: ethics(g, d),
            notice: notice(g),
        },
        RecordTag::Assigned => Record::Assigned(Assigned {
            assignment: id(g, d, AssignmentId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            call: id(g, d, CallId::from_raw),
            reviewer: id(g, d, AccountId::from_raw),
            kind: assignment_kind(g, d),
            handle: if g.bool() { Some(handle(g)) } else { None },
            by: id(g, d, AccountId::from_raw),
            epoch: epoch(g),
        }),
        RecordTag::ConflictDeclared => Record::ConflictDeclared(ConflictDeclared {
            subject: if g.bool() {
                Declared::Assignment(id(g, d, AssignmentId::from_raw))
            } else {
                Declared::Proposal {
                    proposal: id(g, d, ProposalId::from_raw),
                    account: id(g, d, AccountId::from_raw),
                }
            },
            conflicted: g.bool(),
            notifiable: g.bool(),
        }),
        RecordTag::ConflictDetected => Record::ConflictDetected(ConflictDetected {
            account: id(g, d, AccountId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            notifiable: g.bool(),
            epoch: epoch(g),
        }),
        RecordTag::AssignmentReleased => Record::AssignmentReleased(AssignmentReleased {
            assignment: id(g, d, AssignmentId::from_raw),
            cause: *g.pick(&[
                ReleaseCause::DeclaredConflict,
                ReleaseCause::DetectedConflict,
                ReleaseCause::Unassigned,
                ReleaseCause::BindingEnded,
                ReleaseCause::BindingSuspended,
                ReleaseCause::BindingVoided,
            ]),
        }),
        RecordTag::ContentRead => Record::ContentRead(ContentRead {
            account: id(g, d, AccountId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
        }),
        RecordTag::KnockOutRecorded => Record::KnockOutRecorded {
            decision: id(g, d, DecisionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            coordinator: id(g, d, AccountId::from_raw),
            outcomes: knock_outs(g, d),
            reason: opt_text(g, d),
            rules: rules(g),
        },
        RecordTag::ScoreRecorded => Record::ScoreRecorded(ScoreRecorded {
            key: score_key(g, d),
            values: score_vector(g),
            supersedes: if g.bool() { Some(seq(g, d)) } else { None },
            reason: opt_text(g, d),
        }),
        RecordTag::ScoreVoided => Record::ScoreVoided(ScoreVoided {
            key: score_key(g, d),
            cause: *g.pick(&[
                VoidCause::AssignmentReleased,
                VoidCause::Conflict,
                VoidCause::ComplaintRemedy,
            ]),
        }),
        RecordTag::RankingSummaryRecorded => Record::RankingSummaryRecorded {
            proposal: id(g, d, ProposalId::from_raw),
            assignment: id(g, d, AssignmentId::from_raw),
            title: text(g, d),
            neutral_summary: text(g, d),
            rationale: text(g, d),
        },
        RecordTag::QuestionAsked => Record::QuestionAsked {
            proposal: id(g, d, ProposalId::from_raw),
            assignment: id(g, d, AssignmentId::from_raw),
            text: text(g, d),
        },
        RecordTag::NoQuestionsRecorded => Record::NoQuestionsRecorded {
            proposal: id(g, d, ProposalId::from_raw),
            assignment: id(g, d, AssignmentId::from_raw),
        },
        RecordTag::AnswersRecorded => Record::AnswersRecorded {
            proposal: id(g, d, ProposalId::from_raw),
            text: text(g, d),
        },
        RecordTag::RevisionSubmitted => Record::RevisionSubmitted {
            proposal: id(g, d, ProposalId::from_raw),
            plan: id(g, d, PlanVersionId::from_raw),
        },
        RecordTag::CutOffRecorded => Record::CutOffRecorded(CutOffRecorded {
            decision: id(g, d, DecisionId::from_raw),
            call: id(g, d, CallId::from_raw),
            order: proposals(g, d),
            nominated: g.u32(),
            rationale: text(g, d),
            tie_breaks: opt_text(g, d),
            ballots: ballots(g, d),
            recused: accounts(g, d),
            remaining_budget: signed(g)?,
            recorder: id(g, d, AccountId::from_raw),
            rules: rules(g),
        }),
        RecordTag::IrcReviewRecorded => Record::IrcReviewRecorded {
            assignment: id(g, d, AssignmentId::from_raw),
            verdict: verdict(g, d),
        },
        RecordTag::DeferralRecorded => Record::DeferralRecorded {
            proposal: id(g, d, ProposalId::from_raw),
            from_call: id(g, d, CallId::from_raw),
            left: reentry(g),
        },
        RecordTag::ReEntered => Record::ReEntered {
            proposal: id(g, d, ProposalId::from_raw),
            from_call: id(g, d, CallId::from_raw),
            to_call: id(g, d, CallId::from_raw),
            stage: reentry(g),
        },
        RecordTag::AmountDetermined => Record::AmountDetermined {
            decision: id(g, d, DecisionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            plan_total: nonneg(g)?,
            deductions: deductions(g, d)?,
            granted: nonneg(g)?,
            agreed: id(g, d, PlanVersionId::from_raw),
            by: id(g, d, AccountId::from_raw),
            rules: rules(g),
        },
        RecordTag::CapReserved => Record::CapReserved {
            proposal: id(g, d, ProposalId::from_raw),
            amount: nonneg(g)?,
            epoch: epoch(g),
        },
        RecordTag::CapReleased => Record::CapReleased {
            proposal: id(g, d, ProposalId::from_raw),
            amount: nonneg(g)?,
        },
        RecordTag::GrantAccepted => Record::GrantAccepted {
            decision: id(g, d, DecisionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            by: id(g, d, AccountId::from_raw),
        },
        RecordTag::GrantApproved => Record::GrantApproved {
            decision: id(g, d, DecisionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            by: id(g, d, AccountId::from_raw),
        },
        RecordTag::ContractFactRecorded => Record::ContractFactRecorded {
            proposal: id(g, d, ProposalId::from_raw),
            contract: id(g, d, ContractId::from_raw),
            event: ContractEvent::Effective,
        },
        RecordTag::NegotiationDeclined => Record::NegotiationDeclined {
            proposal: id(g, d, ProposalId::from_raw),
            reason: negotiation_failure(g),
            rules: rules(g),
        },
        RecordTag::TerminationRecorded => Record::TerminationRecorded {
            decision: id(g, d, DecisionId::from_raw),
            proposal: id(g, d, ProposalId::from_raw),
            by: id(g, d, AccountId::from_raw),
            reason: text(g, d),
        },
        RecordTag::Transitioned => Record::Transitioned(Transitioned {
            proposal: id(g, d, ProposalId::from_raw),
            from: state_tag(g),
            to: state_tag(g),
            row: *g.pick(&ROWS),
            actor: actor(g, d),
            decision: if g.bool() {
                Some(id(g, d, DecisionId::from_raw))
            } else {
                None
            },
        }),
        RecordTag::VaultOutcome => Record::VaultOutcome {
            kind: *g.pick(&QueryKind::ALL),
            digest: digest(g),
            holds: g.bool(),
            epoch: epoch(g),
        },
        RecordTag::OutboxEnqueued => Record::OutboxEnqueued(outbox(g, d)),
        RecordTag::PaymentRequested => Record::PaymentRequested {
            request: id(g, d, RequestId::from_raw),
            grant: id(g, d, ProposalId::from_raw),
            lines: lines(g, d)?,
        },
        RecordTag::LineAccepted => Record::LineAccepted {
            request: id(g, d, RequestId::from_raw),
            line: id(g, d, LineId::from_raw),
            by: id(g, d, AccountId::from_raw),
            approved: nonneg(g)?,
            reason: opt_text(g, d),
        },
        RecordTag::PaymentApproved => Record::PaymentApproved {
            request: id(g, d, RequestId::from_raw),
            by: id(g, d, AccountId::from_raw),
        },
        RecordTag::PaymentConfirmed => Record::PaymentConfirmed {
            request: id(g, d, RequestId::from_raw),
            by: actor(g, d),
        },
        RecordTag::PaymentRequestWithdrawn => Record::PaymentRequestWithdrawn {
            request: id(g, d, RequestId::from_raw),
            by: id(g, d, AccountId::from_raw),
        },
        RecordTag::PaymentChangesRequested => Record::PaymentChangesRequested {
            request: id(g, d, RequestId::from_raw),
            by: id(g, d, AccountId::from_raw),
            reason: text(g, d),
        },
        RecordTag::DeliverableRecorded => Record::DeliverableRecorded(DeliverableRecorded {
            deliverable: id(g, d, DeliverableId::from_raw),
            grant: id(g, d, ProposalId::from_raw),
            milestone: id(g, d, MilestoneId::from_raw),
            public_location: text(g, d),
            release: text(g, d),
            licence: spdx(g),
            snapshot: digest(g),
            accepted: g.bool(),
        }),
        RecordTag::AmendmentProposed => Record::AmendmentProposed {
            amendment: id(g, d, AmendmentId::from_raw),
            grant: id(g, d, ProposalId::from_raw),
            plan: id(g, d, PlanVersionId::from_raw),
            by: id(g, d, AccountId::from_raw),
        },
        RecordTag::AmendmentRouted => Record::AmendmentRouted {
            amendment: id(g, d, AmendmentId::from_raw),
            route: route(g),
            by: id(g, d, AccountId::from_raw),
        },
        RecordTag::AmendmentActivated => Record::AmendmentActivated {
            amendment: id(g, d, AmendmentId::from_raw),
            plan: id(g, d, PlanVersionId::from_raw),
            route: route(g),
            contract: id(g, d, ContractId::from_raw),
        },
        RecordTag::Stage1Closed
        | RecordTag::EffectiveScoreSet
        | RecordTag::GrantDecided
        | RecordTag::PaymentReleased => {
            return Err(format!(
                "{t:?} is a witness payload with no public constructor; \
                 its round trip is checked over the fuzz seed corpus"
            ));
        }
    })
}

// ---------------------------------------------------------------------------
// Seed corpora
// ---------------------------------------------------------------------------

/// The seed corpus directory of a `fstp-domain` fuzz target.
pub(crate) fn seed_dir(target: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("seeds")
        .join(target)
}

/// Every seed of a corpus as (file name, bytes), in sorted name order.
pub(crate) fn seeds(target: &str) -> G<Vec<(String, Vec<u8>)>> {
    let dir = seed_dir(target);
    let entries =
        std::fs::read_dir(&dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
        let path = entry.path();
        if path.is_file() {
            let bytes =
                std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            out.push((entry.file_name().to_string_lossy().into_owned(), bytes));
        }
    }
    out.sort();
    Ok(out)
}

/// The seeds of `target` that decode, each checked for a canonical round
/// trip: the seed bytes are the RFC 8785 text of the encoding of the decoded
/// value, and that value survives a round trip.
pub(crate) fn decoded_seeds<T: PartialEq + Debug>(
    codec: &Codec<T>,
    target: &str,
) -> G<Vec<(String, T)>> {
    let mut out = Vec::new();
    for (name, bytes) in seeds(target)? {
        let Ok(v) = parse(&bytes) else {
            continue;
        };
        let Ok(t) = codec.decode(&v)? else {
            continue;
        };
        let text = codec
            .round_trip(&t)
            .map_err(|e| format!("seed {name}: {e}"))?;
        if text.as_bytes() != bytes.as_slice() {
            return Err(format!(
                "seed {name} decodes but is not in canonical form\n  seed:      {}\n  canonical: {text}",
                String::from_utf8_lossy(&bytes)
            ));
        }
        out.push((name, t));
    }
    Ok(out)
}

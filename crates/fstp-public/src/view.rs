//! The public view and its only constructor (I-41, I-42, I-43, P-54,
//! R-PB-03; M4 design section 3.10).
//!
//! [`public_view_with`] is the only filter. It reads the core state, the
//! grantee choice records and the public texts, and nothing else. The
//! open calls are the programme's published calls open at the view's
//! instant, each shown only when its title and every P-09 text are
//! public texts the view holds. A draft programme has no public view.
//!
//! # The filter, as the tests read it
//!
//! Interim readings, pending Daniel, each pinned by a test in
//! `fstp-api-testkit/tests/i41_i42_i43_p54_*`:
//!
//! - A proposal appears only once it reached GRANTED (I-41). GRANTED and
//!   IN_EXECUTION are the funded phase, under P-50. COMPLETED is the
//!   finished phase, under P-51. TERMINATED shows nowhere.
//! - A minor-flagged proposal never appears, at any level (I-42).
//! - A grant shows at the lower of the phase maximum and the grantee's
//!   choice for that phase. With no choice record it is hidden (I-43).
//!   A maximum that does not decode as a level reads as hidden.
//! - A level shows only the fields of `public-transparency.md`: project
//!   title, public summary, call and status; then the grantee name; then
//!   the granted amount. A text the level needs that [`PublicTexts`] does
//!   not hold hides the grant.
//! - An aggregate per call counts the grants the view shows, in either
//!   phase, and their granted amounts. It appears only when it counts at
//!   least P-54 grants (R-PB-05, Q27). A P-54 that does not decode shows
//!   no aggregate.
//! - An aggregate never reveals an amount the grantee chose to hide
//!   (I-43, R-PB-05: "so no single grant can be inferred"). Its total
//!   minus the amounts shown at [`Level::Full`] is the sum of the hidden
//!   amounts it counts. So it is withheld when it counts from 1 to
//!   `max(P-54, 2) - 1` grants whose amount the view hides. The `2`
//!   covers P-54 at 1, where one hidden amount would equal that
//!   difference.
//! - Every text comes from [`PublicTexts`], which holds only
//!   `TextClass::Public` texts: the call texts, the P-09 wording of a
//!   published call and the texts a grantee approved, which a choice
//!   record names. A proposal's own text never reaches the view (R-PB-03).

use std::collections::BTreeMap;

use fstp_domain::State;
use fstp_domain::id::{CallId, ProgrammeId, ProposalId, TextId};
use fstp_domain::programme::{CallView, ProgrammeStatus, programme_status};
use fstp_domain::roles::BindingScope;
use fstp_domain::rules::{ParamId, StateTag};
use fstp_domain::time::Timestamp;
use fstp_domain::view::{proposal_minor_flagged, proposal_state};
use fstp_money::Amount;

use crate::PublicError;

/// A public visibility level (`public-transparency.md`). The order is the
/// order of the levels table, so `min` gives the lower level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Nothing about the grant. The default for every grant.
    Hidden,
    /// Project title, public summary, call and status.
    Project,
    /// Adds the grantee name.
    ProjectAndGrantee,
    /// Adds the granted amount.
    Full,
}

impl Level {
    /// Every level, lowest first.
    pub const ALL: [Level; 4] = [
        Level::Hidden,
        Level::Project,
        Level::ProjectAndGrantee,
        Level::Full,
    ];

    /// The token a programme spec keeps for P-50 and P-51, such as
    /// `full`. Interim, pending Daniel: the spec names no token list.
    pub fn token(self) -> &'static str {
        match self {
            Level::Hidden => "hidden",
            Level::Project => "project",
            Level::ProjectAndGrantee => "project_and_grantee",
            Level::Full => "full",
        }
    }

    /// The level of `token`, or `None` for any other text.
    pub fn from_token(token: &str) -> Option<Level> {
        Level::ALL.into_iter().find(|l| l.token() == token)
    }
}

/// The phase of a public grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GrantStatus {
    /// GRANTED.
    Granted,
    /// IN_EXECUTION.
    InExecution,
    /// COMPLETED.
    Completed,
}

/// One grantee's visibility choice and the public texts they approved
/// (R-PB-02, R-PB-03).
///
/// The record arrives with M9. Until then only the testkit builds
/// synthetic ones, and every M4 cell passes [`GrantChoices::none`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrantChoice {
    /// The level chosen for the funded phase.
    pub funded: Level,
    /// The level chosen for the finished phase.
    pub finished: Level,
    /// The approved project title, a public text.
    pub title: TextId,
    /// The approved public summary, a public text.
    pub summary: TextId,
    /// The approved grantee name, a public text.
    pub grantee: TextId,
}

/// The grantee choice records of one programme, by proposal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct GrantChoices {
    records: BTreeMap<ProposalId, GrantChoice>,
}

impl GrantChoices {
    /// No choice record: every M4 cell (design section 3.10, Q11).
    pub fn none() -> GrantChoices {
        GrantChoices::default()
    }

    /// Records `choice` as the current choice for `proposal`, replacing
    /// any earlier one.
    pub fn insert(&mut self, proposal: ProposalId, choice: GrantChoice) {
        let _ = self.records.insert(proposal, choice);
    }

    /// Removes the choice of `proposal`, as a withdrawal does.
    pub fn remove(&mut self, proposal: ProposalId) {
        let _ = self.records.remove(&proposal);
    }

    /// The current choice of `proposal`.
    pub fn get(&self, proposal: ProposalId) -> Option<&GrantChoice> {
        self.records.get(&proposal)
    }

    /// Every record, in proposal order.
    pub fn iter(&self) -> impl Iterator<Item = (ProposalId, &GrantChoice)> {
        self.records.iter().map(|(p, c)| (*p, c))
    }
}

/// The public identity of a programme, from its draft spec: the public
/// slug, the name and the narrative.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProgrammeIdentity {
    /// The public slug, `identity.public_slug`.
    pub slug: String,
    /// The programme name, `identity.name`.
    pub name: String,
    /// The programme narrative, `identity.narrative`.
    pub narrative: String,
}

/// The rendered Guide for Applicants of one published call (R-GA-01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicGuide {
    /// The Guide version, from 1.
    pub version: u32,
    /// The Guide page as its publication stored it, followed by its
    /// corrigenda when it has any (I-53).
    pub document: String,
}

/// The texts a public view may show: only `TextClass::Public` texts
/// (R-PB-03), the programme identity and the published Guides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicTexts {
    identity: ProgrammeIdentity,
    texts: BTreeMap<TextId, String>,
    guides: BTreeMap<CallId, PublicGuide>,
}

impl PublicTexts {
    /// No text yet, for the programme `identity`.
    pub fn new(identity: ProgrammeIdentity) -> PublicTexts {
        PublicTexts {
            identity,
            texts: BTreeMap::new(),
            guides: BTreeMap::new(),
        }
    }

    /// The programme identity.
    pub fn identity(&self) -> &ProgrammeIdentity {
        &self.identity
    }

    /// Adds the public text `text` under `id`, replacing any earlier one.
    pub fn insert(&mut self, id: TextId, text: &str) {
        let _ = self.texts.insert(id, text.to_owned());
    }

    /// The public text `id`.
    pub fn text(&self, id: TextId) -> Option<&str> {
        self.texts.get(&id).map(String::as_str)
    }

    /// Adds the published Guide of `call`.
    pub fn insert_guide(&mut self, call: CallId, guide: PublicGuide) {
        let _ = self.guides.insert(call, guide);
    }

    /// The published Guide of `call`.
    pub fn guide(&self, call: CallId) -> Option<&PublicGuide> {
        self.guides.get(&call)
    }
}

/// The programme part of a public view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicProgramme {
    /// The public slug.
    pub slug: String,
    /// The programme name.
    pub name: String,
    /// The programme narrative.
    pub narrative: String,
    /// Whether the public feed is on (P-52).
    pub feed: bool,
}

/// One open call of a public view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicCall {
    /// The call's public identifier: its id in decimal.
    pub id: String,
    /// The call title: the call text.
    pub title: String,
    /// When it opens, an RFC 3339 instant in UTC.
    pub opens: String,
    /// The deadline, an RFC 3339 instant in UTC.
    pub deadline: String,
    /// The IANA zone of the deadline.
    pub deadline_zone: String,
    /// The call budget, an ADR-006 amount string.
    pub budget: String,
    /// The P-04 minimum, an ADR-006 amount string.
    pub grant_min: String,
    /// The P-04 maximum, an ADR-006 amount string.
    pub grant_max: String,
    /// The P-09 wording, in criterion order.
    pub eligibility: Vec<String>,
    /// The published Guide, when the cell supplied it.
    pub guide: Option<PublicGuide>,
}

/// One grant of a public view, at its effective level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicGrant {
    /// The call's public identifier.
    pub call: String,
    /// The effective level, never [`Level::Hidden`].
    pub level: Level,
    /// The phase.
    pub status: GrantStatus,
    /// The approved project title.
    pub title: String,
    /// The approved public summary.
    pub summary: String,
    /// The approved grantee name, from [`Level::ProjectAndGrantee`].
    pub grantee: Option<String>,
    /// The granted amount, an ADR-006 amount string, at [`Level::Full`].
    pub amount: Option<String>,
}

/// One public aggregate: the grants of one call that the view shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicAggregate {
    /// The call's public identifier.
    pub call: String,
    /// The number of grants, at least P-54.
    pub grants: u32,
    /// Their granted amounts in total, an ADR-006 amount string.
    pub total: String,
}

/// Everything a public page, the feed or a public tool may show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicView {
    /// The programme.
    pub programme: PublicProgramme,
    /// The calls open at the view's instant, in call id order.
    pub open_calls: Vec<PublicCall>,
    /// The funded grants, in proposal id order.
    pub funded: Vec<PublicGrant>,
    /// The finished grants, in proposal id order.
    pub finished: Vec<PublicGrant>,
    /// The aggregates, in call id order.
    pub aggregates: Vec<PublicAggregate>,
}

/// Builds the public view of one programme from the core state, with no
/// grantee choice record: every M4 cell (design section 3.10).
pub fn public_view(
    core: &State,
    programme: ProgrammeId,
    texts: &PublicTexts,
    now: Timestamp,
) -> Result<PublicView, PublicError> {
    public_view_with(core, programme, texts, &GrantChoices::none(), now)
}

/// Builds the public view of one programme from the core state and the
/// grantee choice records `choices`. The only filter (I-41, I-42, I-43,
/// P-54). It refuses [`PublicError::NotFound`] for a programme the state
/// does not hold as active.
pub fn public_view_with(
    core: &State,
    programme: ProgrammeId,
    texts: &PublicTexts,
    choices: &GrantChoices,
    now: Timestamp,
) -> Result<PublicView, PublicError> {
    if programme_status(core, programme) != Some(ProgrammeStatus::Active) {
        return Err(PublicError::NotFound);
    }
    let params = PublicParams::of(core, programme);
    let identity = texts.identity();
    let open_calls = core
        .calls()
        .iter()
        .filter(|(_, v)| v.programme() == programme && v.is_open_at(now))
        .filter_map(|(id, v)| public_call(id, v, texts))
        .collect();
    let mut funded = Vec::new();
    let mut finished = Vec::new();
    let mut counts: BTreeMap<CallId, Count> = BTreeMap::new();
    for (proposal, call) in proposals_of(core, programme) {
        let Some(shown) = public_grant(core, proposal, call, &params, choices, texts) else {
            continue;
        };
        let entry = counts.entry(call).or_insert(Count {
            grants: 0,
            hidden: 0,
            total: None,
        });
        entry.grants = entry.grants.saturating_add(1);
        if shown.grant.amount.is_none() {
            entry.hidden = entry.hidden.saturating_add(1);
        }
        entry.total = add(entry.total, shown.granted);
        if shown.grant.status == GrantStatus::Completed {
            finished.push(shown.grant);
        } else {
            funded.push(shown.grant);
        }
    }
    // R-PB-05, Q27: only over the grants the view shows, and only at P-54
    // or more. A total that does not add up shows no aggregate, nor one
    // that would reveal a hidden amount (module documentation).
    let aggregates = match params.p54 {
        Some(min) => counts
            .into_iter()
            .filter(|(_, c)| c.grants >= min && !reveals_hidden(c.hidden, min))
            .filter_map(|(call, c)| {
                c.total.map(|t| PublicAggregate {
                    call: call.raw().to_string(),
                    grants: c.grants,
                    total: t.to_string(),
                })
            })
            .collect(),
        None => Vec::new(),
    };
    Ok(PublicView {
        programme: PublicProgramme {
            slug: identity.slug.clone(),
            name: identity.name.clone(),
            narrative: identity.narrative.clone(),
            feed: params.p52,
        },
        open_calls,
        funded,
        finished,
        aggregates,
    })
}

/// The grants of one call that the view shows, for its aggregate.
struct Count {
    /// The grants shown.
    grants: u32,
    /// Those shown below [`Level::Full`], whose amount the view hides.
    hidden: u32,
    /// Their granted amounts in total, `None` when the sum overflows.
    total: Option<Amount>,
}

/// Whether an aggregate that counts `hidden` grants with a hidden amount
/// would let a reader infer one of them, under the P-54 minimum `min`:
/// from 1 to `max(min, 2) - 1` hidden amounts (module documentation).
fn reveals_hidden(hidden: u32, min: u32) -> bool {
    hidden >= 1 && hidden < min.max(2)
}

/// `a` plus `b`, or `None` when either is `None` or the sum overflows.
/// The first grant of a call starts the sum.
fn add(a: Option<Amount>, b: Amount) -> Option<Amount> {
    match a {
        None => Some(b),
        Some(a) => a.checked_add(b).ok(),
    }
}

/// The public parameters of a programme's head policy (P-50, P-51, P-52,
/// P-54). A value that does not decode reads as closed: hidden, off, or
/// no aggregate.
struct PublicParams {
    p50: Level,
    p51: Level,
    p52: bool,
    p54: Option<u32>,
}

impl PublicParams {
    fn of(core: &State, programme: ProgrammeId) -> PublicParams {
        let live = fstp_domain::policy::live_values(core, programme);
        let value = |p: ParamId| -> Option<fstp_json::Value> {
            let v = live?.opaque.get(&p)?;
            fstp_json::parse_str(v.as_str()).ok()
        };
        let level = |p: ParamId| {
            value(p)
                .and_then(|v| v.as_str().and_then(Level::from_token))
                .unwrap_or(Level::Hidden)
        };
        let p52 = matches!(value(ParamId::P52), Some(fstp_json::Value::Bool(true)));
        let p54 = match value(ParamId::P54) {
            Some(fstp_json::Value::Number(n)) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
            _ => None,
        };
        PublicParams {
            p50: level(ParamId::P50),
            p51: level(ParamId::P51),
            p52,
            p54,
        }
    }
}

/// Every proposal of `programme`, with the call it is in now: the call of
/// its latest Receiving binding, active or ended, in proposal id order.
fn proposals_of(core: &State, programme: ProgrammeId) -> BTreeMap<ProposalId, CallId> {
    let roster = core.roster();
    let mut latest: BTreeMap<ProposalId, (u32, Timestamp, CallId)> = BTreeMap::new();
    let all = roster
        .bindings()
        .map(|(_, b)| b)
        .chain(roster.ended().map(|(_, e)| &e.binding));
    for b in all {
        let BindingScope::Proposal { proposal, call } = b.scope else {
            continue;
        };
        let key = (b.opened, b.start, call);
        let slot = latest.entry(proposal).or_insert(key);
        if key > *slot {
            *slot = key;
        }
    }
    latest
        .into_iter()
        .filter(|(_, (_, _, call))| {
            fstp_domain::programme::call(core, *call).is_some_and(|v| v.programme() == programme)
        })
        .map(|(p, (_, _, call))| (p, call))
        .collect()
}

/// A grant the view shows, with its granted amount for the aggregates.
struct ShownGrant {
    grant: PublicGrant,
    granted: Amount,
}

/// The public grant of `proposal` in `call`, or `None` when the filter
/// hides it (module documentation).
fn public_grant(
    core: &State,
    proposal: ProposalId,
    call: CallId,
    params: &PublicParams,
    choices: &GrantChoices,
    texts: &PublicTexts,
) -> Option<ShownGrant> {
    // I-41: only from GRANTED on. TERMINATED and every earlier state show
    // nowhere.
    let (status, max) = match proposal_state(core, proposal)? {
        StateTag::Granted => (GrantStatus::Granted, params.p50),
        StateTag::InExecution => (GrantStatus::InExecution, params.p50),
        StateTag::Completed => (GrantStatus::Completed, params.p51),
        _ => return None,
    };
    // I-42: no minor-flagged proposal, at any level. The read fails
    // closed, so an unknown flag hides the grant.
    if proposal_minor_flagged(core, proposal) {
        return None;
    }
    // I-43: hidden with no choice, else the lower of maximum and choice.
    let choice = choices.get(proposal)?;
    let chosen = if status == GrantStatus::Completed {
        choice.finished
    } else {
        choice.funded
    };
    let level = max.min(chosen);
    if level == Level::Hidden {
        return None;
    }
    // R-PB-03: every text comes from the grantee-approved public texts.
    let title = texts.text(choice.title)?.to_owned();
    let summary = texts.text(choice.summary)?.to_owned();
    let grantee = if level >= Level::ProjectAndGrantee {
        Some(texts.text(choice.grantee)?.to_owned())
    } else {
        None
    };
    let granted = core.money().granted(proposal)?.amount();
    let amount = (level == Level::Full).then(|| granted.to_string());
    Some(ShownGrant {
        grant: PublicGrant {
            call: call.raw().to_string(),
            level,
            status,
            title,
            summary,
            grantee,
            amount,
        },
        granted,
    })
}

/// The public part of the open call `id`, or `None` when a text it needs
/// is not a public text the view holds, or a value has no public form.
fn public_call(id: CallId, view: &CallView, texts: &PublicTexts) -> Option<PublicCall> {
    let frozen = view.frozen()?.values();
    let title = texts.text(view.text().id())?.to_owned();
    let eligibility = frozen
        .p09
        .0
        .iter()
        .map(|k| texts.text(k.text.id()).map(str::to_owned))
        .collect::<Option<Vec<String>>>()?;
    Some(PublicCall {
        id: id.raw().to_string(),
        title,
        opens: rfc3339(view.opens())?,
        deadline: rfc3339(view.deadline())?,
        deadline_zone: view.deadline_zone().as_str().to_owned(),
        budget: view.budget().amount().to_string(),
        grant_min: frozen.p04.min().amount().to_string(),
        grant_max: frozen.p04.max().amount().to_string(),
        eligibility,
        guide: texts.guide(id).cloned(),
    })
}

/// `t` as an RFC 3339 instant in UTC, to the second, such as
/// `2026-10-29T11:00:00Z`. `None` outside the years 1970 to 9999.
pub(crate) fn rfc3339(t: Timestamp) -> Option<String> {
    const MICROS_PER_SECOND: i64 = 1_000_000;
    let micros = t.micros();
    if micros < 0 {
        return None;
    }
    let seconds = micros.checked_div(MICROS_PER_SECOND)?;
    let days = seconds.checked_div(86_400)?;
    let rem = seconds.checked_rem(86_400)?;
    let (y, m, d) = civil_from_days(days)?;
    if y > 9999 {
        return None;
    }
    let hh = rem.checked_div(3600)?;
    let mm = rem.checked_rem(3600)?.checked_div(60)?;
    let ss = rem.checked_rem(60)?;
    Some(format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z"))
}

/// The civil date of `days` since 1970-01-01, for `days` at least zero
/// (Howard Hinnant's `civil_from_days`, in integer arithmetic).
fn civil_from_days(days: i64) -> Option<(i64, i64, i64)> {
    let z = days.checked_add(719_468)?;
    let era = z.checked_div(146_097)?;
    let doe = z.checked_sub(era.checked_mul(146_097)?)?;
    let yoe = doe
        .checked_sub(doe.checked_div(1460)?)?
        .checked_add(doe.checked_div(36_524)?)?
        .checked_sub(doe.checked_div(146_096)?)?
        .checked_div(365)?;
    let y = yoe.checked_add(era.checked_mul(400)?)?;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe.checked_div(4)?)?
            .checked_sub(yoe.checked_div(100)?)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)?.checked_div(153)?;
    let d = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)?.checked_div(5)?)?
        .checked_add(1)?;
    let m = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let y = if m <= 2 { y.checked_add(1)? } else { y };
    Some((y, m, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R-PB-01: instants are written as RFC 3339 in UTC.
    #[test]
    fn r_pb_01_rfc3339_writes_utc_instants() {
        let cases = [
            (0_i64, "1970-01-01T00:00:00Z"),
            (1_793_271_600_000_000, "2026-10-29T11:00:00Z"),
            (951_782_400_000_000, "2000-02-29T00:00:00Z"),
            (253_402_300_799_000_000, "9999-12-31T23:59:59Z"),
        ];
        for (micros, want) in cases {
            assert_eq!(
                rfc3339(Timestamp::from_micros(micros)).as_deref(),
                Some(want)
            );
        }
        assert_eq!(rfc3339(Timestamp::from_micros(-1)), None);
        assert_eq!(
            rfc3339(Timestamp::from_micros(253_402_300_800_000_000)),
            None
        );
    }
}

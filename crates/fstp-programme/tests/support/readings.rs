//! The W1a test author's readings of the spec tables, made from the spec
//! text before `fstp-programme` was written.
//!
//! Interim, pending Daniel. Three groups of readings are interim:
//!
//! - [`DESIGN_PLACEMENT`] places every programme-level parameter in one
//!   creator step, as M4 design section 3.1 does (Q36 A).
//! - [`readings`] fixes the canonical JSON of every opaque SuperSAFE value.
//!   The spec states each value in prose and no design section fixes an
//!   encoding, so these texts are the contract the implementation follows.
//! - [`readings`] marks as synthetic every parameter whose SuperSAFE cell
//!   gives no concrete value. M4 design section 3.1 lists seven. This
//!   reading adds P-40, P-45 and P-49, whose cells give no value either.
//!   P-29 is partly synthetic: its cell gives the instrument, MoU, but no
//!   template version (`contracts.md`).
//!
//! Each reading carries the spec cell it was made from. A spec edit to that
//! cell fails `r_pg_01_supersafe_readings_match_the_spec_column`, so the
//! reading is revisited instead of drifting.

use std::collections::BTreeSet;

use fstp_domain::policy::{
    AgentContentAccess, EffectiveScoreRule, McpBindingActions, PolicyVersion, ReadAccess,
    ReviewerAnonymity,
};
use fstp_domain::roles::CoolingOff;
use fstp_domain::rules::ParamId;
use fstp_domain::time::Days;
use fstp_money::{Amount, AmountRange, Currency, NonNegAmount, Percent};

use ParamId::*;

/// The creator step of every programme-level parameter: the step the
/// creator table names it in, or the M4 design section 3.1 placement for
/// the parameters it names nowhere (Q36 A). Interim, pending Daniel.
pub(crate) const DESIGN_PLACEMENT: &[(u8, &[ParamId])] = &[
    (1, &[P53, P56, P57, P58, P41, P22, P46, P43]),
    (2, &[P25]),
    (3, &[P13, P17, P18, P19, P45]),
    (4, &[P55, P26]),
    (
        5,
        &[
            P01, P02, P03, P06, P07, P08, P09, P10, P11, P14, P15, P16, P21, P23, P24, P28, P39,
            P42, P75, P77,
        ],
    ),
    (6, &[P04, P05, P27, P34, P36, P59, P65, P66, P67]),
    (7, &[P29, P30, P44, P47, P48, P49]),
    (8, &[P60, P61, P62, P63, P64]),
    (9, &[P12]),
    (
        10,
        &[P31, P32, P33, P35, P37, P38, P40, P50, P51, P52, P54, P76],
    ),
];

/// The placement of `p` in [`DESIGN_PLACEMENT`], if any.
pub(crate) fn placement(p: ParamId) -> Option<u8> {
    DESIGN_PLACEMENT
        .iter()
        .find(|(_, ps)| ps.contains(&p))
        .map(|(step, _)| *step)
}

/// The programme-level parameters that no "Bounded by" cell of the creator
/// table names. Computed by hand from `programme-creator.md` and
/// `CATALOGUE`, and checked against both by
/// `r_pg_01_unlisted_in_creator_table_matches_spec`.
///
/// M4 design section 3.1 lists only P-06, P-12, P-19, P-22, P-39, P-42,
/// P-43 and P-46 to P-49. The spec leaves out more: this list is the full
/// set, so the design's list is a subset of it.
pub(crate) const UNLISTED_IN_CREATOR_TABLE: &[ParamId] = &[
    P06, P07, P08, P12, P14, P18, P19, P21, P22, P23, P27, P28, P34, P35, P36, P37, P38, P39, P40,
    P42, P43, P44, P45, P46, P47, P48, P49, P50, P51, P52, P54, P75, P76, P77,
];

/// How the SuperSAFE fixture must hold one parameter.
#[derive(Clone, Copy)]
pub(crate) enum Reading {
    /// A concrete value in a typed field of `PolicyVersion`, checked by the
    /// function.
    Typed(fn(&PolicyVersion) -> Result<(), String>),
    /// A concrete value in `frozen.opaque` or `live.opaque`, by the
    /// parameter's freeze flag, equal to this JSON text in canonical form.
    Opaque(&'static str),
    /// The cell gives no concrete value. The fixture holds a placeholder and
    /// lists the parameter in its provenance block with `"synthetic": true`.
    /// The text names the open point.
    Synthetic(&'static str),
    /// The cell gives part of the value. The opaque value equals the JSON
    /// text, which fills the rest with a placeholder, and the parameter is
    /// listed in the provenance block as for [`Reading::Synthetic`]. The
    /// second text names the open point.
    PartlySynthetic(&'static str, &'static str),
    /// Tenant-level or fixed in `CATALOGUE`. `compile` never sets it.
    NotProgramme,
}

/// One reading with the spec cell it was made from.
#[derive(Clone, Copy)]
pub(crate) struct SuperSafeReading {
    /// The parameter.
    pub(crate) id: ParamId,
    /// The "SuperSAFE default" cell of `policy-parameters.md`, verbatim.
    pub(crate) cell: &'static str,
    /// What the fixture must hold.
    pub(crate) reading: Reading,
}

/// `text` as a non-negative EUR amount (ADR-006).
pub(crate) fn eur(text: &str) -> Result<NonNegAmount, String> {
    let a = Amount::parse(text, Currency::Eur).map_err(|e| format!("{text}: {e:?}"))?;
    NonNegAmount::new(a).map_err(|e| format!("{text}: {e:?}"))
}

/// Whether two JSON texts denote the same canonical JSON (RFC 8785).
pub(crate) fn same_json(actual: &str, expected: &str) -> Result<(), String> {
    let canon = |t: &str| {
        fstp_json::parse_str(t)
            .map_err(|e| format!("{t:?} is not JSON: {e:?}"))
            .and_then(|v| fstp_json::to_canonical(&v).map_err(|e| format!("{t:?}: {e:?}")))
    };
    let (a, e) = (canon(actual)?, canon(expected)?);
    if a == e {
        Ok(())
    } else {
        Err(format!("holds {a}, the reading expects {e}"))
    }
}

fn expect<T: PartialEq + core::fmt::Debug>(
    what: &str,
    actual: T,
    expected: T,
) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{what} is {actual:?}, the reading expects {expected:?}"
        ))
    }
}

fn p01(v: &PolicyVersion) -> Result<(), String> {
    let c = &v.frozen.p01;
    expect("the P-01 scale maximum", c.scale_max().get(), 5)?;
    let weights: Vec<u16> = c.items().iter().map(|i| i.weight.get()).collect();
    expect("the P-01 weights in order", weights, vec![30, 40, 30])
}

fn p02(v: &PolicyVersion) -> Result<(), String> {
    let want = Percent::parse("75.00").map_err(|e| format!("75.00: {e:?}"))?;
    expect("P-02", v.frozen.p02, want)
}

fn p04(v: &PolicyVersion) -> Result<(), String> {
    let want = AmountRange::new(eur("5000.00")?, eur("100000.00")?)
        .map_err(|e| format!("P-04 range: {e:?}"))?;
    expect("P-04", v.frozen.p04, want)
}

fn p13(v: &PolicyVersion) -> Result<(), String> {
    // Two classes, split at the semicolon of the cell: consortium partners
    // with their affiliated entities and staff, and IRC members with their
    // employers, co-workers and relatives. Class ids are opaque (vault).
    expect("the number of P-13 classes", v.live.p13.0.len(), 2)
}

/// Every reading, one per parameter, in catalogue order.
pub(crate) fn readings() -> Vec<SuperSafeReading> {
    use Reading::{NotProgramme, Opaque, PartlySynthetic, Synthetic, Typed};
    let r =
        |id: ParamId, cell: &'static str, reading: Reading| SuperSafeReading { id, cell, reading };
    vec![
        r(
            P01,
            "Technical excellence 30, Relevance and impact 40, Value for money 30; scale 0 to 5",
            Typed(p01),
        ),
        r(P02, "75.00%", Typed(p02)),
        r(P03, "2", Typed(|v| expect("P-03", v.frozen.p03.get(), 2))),
        r(P04, "5k to 100k EUR", Typed(p04)),
        r(
            P05,
            "400k EUR per the Annexe, to confirm against the Data Sheet (L-10)",
            Typed(|v| expect("P-05", v.live.p05, eur("400000.00")?)),
        ),
        r(P06, "Quarterly", Opaque(r#""quarterly""#)),
        r(
            P07,
            "4 weeks",
            Typed(|v| expect("P-07", v.frozen.p07, Days::new(28))),
        ),
        r(
            P08,
            "5 working days after the decision",
            Opaque(r#"{"working_days":5}"#),
        ),
        r(
            P09,
            "Aligned with Open Internet Stack and SuperSAFE vision; R&D as primary objective; English",
            Typed(|v| expect("the number of P-09 criteria", v.frozen.p09.0.len(), 3)),
        ),
        r(
            P10,
            "Assigned reviewers only",
            Typed(|v| expect("P-10", v.frozen.p10, ReadAccess::AssignedReviewersOnly)),
        ),
        r(
            P11,
            "Anonymous",
            Typed(|v| expect("P-11", v.frozen.p11, ReviewerAnonymity::Anonymous)),
        ),
        r(
            P12,
            "1 call",
            Typed(|v| expect("P-12", v.live.p12, CoolingOff(1))),
        ),
        r(
            P13,
            "Consortium partners, their affiliated entities and staff; IRC members, employers, co-workers, relatives",
            Typed(p13),
        ),
        r(
            P14,
            "Team change; plan change without budget change; additional tasks in scope at equivalent rates with total under 100k EUR",
            Typed(|v| {
                same_json(
                    v.frozen.p14.0.as_str(),
                    r#"[{"kind":"team_change"},{"kind":"plan_change_without_budget_change"},{"kind":"additional_tasks_in_scope_at_equivalent_rates","total_below":"100000.00"}]"#,
                )
                .map_err(|e| format!("P-14 {e}"))
            }),
        ),
        r(P15, "2", Typed(|v| expect("P-15", v.frozen.p15.get(), 2))),
        r(
            P16,
            "Majority, vote delegation allowed, chair casting vote",
            Typed(|v| {
                same_json(
                    v.frozen.p16.0.as_str(),
                    r#"{"casting_vote":"chair","decision":"majority","delegation":true}"#,
                )
                .map_err(|e| format!("P-16 {e}"))
            }),
        ),
        r(
            P17,
            "EU and associated countries, with exception for exceptional quality and unique expertise",
            Typed(|v| {
                same_json(
                    v.frozen.p17.0.as_str(),
                    r#"{"exception":"exceptional_quality_and_unique_expertise","priority":"eu_and_associated_countries"}"#,
                )
                .map_err(|e| format!("P-17 {e}"))
            }),
        ),
        r(
            P18,
            "EUDI Wallet; document upload with manual check",
            Opaque(r#"["eudi_wallet","document_upload_manual_check"]"#),
        ),
        r(
            P19,
            "None: deleted on verification",
            Opaque(r#""delete_on_verification""#),
        ),
        r(
            P20,
            "Record-only. Execution is deferred by Daniel on 2026-11-04 (B-11)",
            NotProgramme,
        ),
        r(P21, "Tenant choice", Synthetic("tenant choice, NOTE 10")),
        r(
            P22,
            "Until the funder audit period ends (P-41)",
            Opaque(r#"{"until":"P-41"}"#),
        ),
        r(
            P23,
            "Enabled; 1 per day and 5 per call per proposal; account-level cap across drafts in the same call",
            Opaque(
                r#"{"account_cap_across_drafts_in_call":true,"enabled":true,"per_call_per_proposal":5,"per_day_per_proposal":1}"#,
            ),
        ),
        r(
            P24,
            "Higher of original and revised",
            Typed(|v| {
                expect(
                    "P-24",
                    v.frozen.p24,
                    EffectiveScoreRule::HigherOfOriginalAndRevised,
                )
            }),
        ),
        r(P25, "English", Opaque(r#""en""#)),
        r(
            P26,
            "Recognised free and open source licences",
            Synthetic("the exact SPDX list is not in the spec"),
        ),
        r(P27, "Yes", Opaque("true")),
        r(P28, "Off", Opaque("false")),
        r(
            P29,
            "MoU",
            PartlySynthetic(
                r#"{"instrument":"mou","template":{"id":"annexe-6-mou","version":1}}"#,
                "the version of the Annexe 6 MoU template is not in the spec",
            ),
        ),
        r(
            P30,
            "Wallet QES, then QTSP remote QES, then approved advanced",
            Opaque(r#"["wallet_qes","qtsp_remote_qes","approved_advanced"]"#),
        ),
        r(
            P31,
            "Minus 14 days, minus 3 days, due date",
            Opaque(r#"{"offsets_days":[-14,-3,0]}"#),
        ),
        r(
            P32,
            "Email, Matrix and WhatsApp (tenant-owned account); all four group types",
            Opaque(
                r#"{"channels":["email","matrix","whatsapp"],"group_types":["programme_announcements","committee_group","grantee_cohort","project_group"],"whatsapp_account":"tenant_owned"}"#,
            ),
        ),
        r(
            P33,
            "Plus 7 days to programme manager",
            Opaque(r#"{"after_days":7,"to":"programme_manager"}"#),
        ),
        r(
            P34,
            "Public location, release identifier, SPDX licence, report",
            Opaque(r#"["public_location","release_identifier","spdx_licence","report"]"#),
        ),
        r(P35, "Immediate", Opaque(r#""immediate""#)),
        r(P36, "7 days", Opaque(r#"{"days":7}"#)),
        r(P37, "Not stored", Opaque(r#""not_stored""#)),
        r(
            P38,
            "Declared by each partner at programme start",
            Typed(|v| {
                expect(
                    "the number of P-38 lists at build time",
                    v.live.p38.0.len(),
                    0,
                )
            }),
        ),
        r(P39, "2", Typed(|v| expect("P-39", v.frozen.p39.get(), 2))),
        r(
            P40,
            "Tenant-defined public holidays and weekend days",
            Synthetic("the tenant's calendar is not in the spec"),
        ),
        r(
            P41,
            "Horizon Europe Data Sheet standard time-limit; confirm in the signed GA (L-06)",
            Synthetic("L-06"),
        ),
        r(P42, "Yes", Opaque("true")),
        r(P43, "30 days", Opaque(r#"{"days":30}"#)),
        r(
            P44,
            "Per funder instrument; SuperSAFE: financial support to third parties as a grant",
            Opaque(r#""financial_support_to_third_parties_grant""#),
        ),
        r(
            P45,
            "Tenant registration or CrabNebula as intermediary; self-hosted cells use tenant registration only",
            Synthetic("the mode is a per-tenant choice, prefilled from onboarding"),
        ),
        r(P46, "30 days", Opaque(r#"{"days":30}"#)),
        r(
            P47,
            "Advanced electronic seal; qualified as option",
            Opaque(r#""advanced""#),
        ),
        r(P48, "Yes", Opaque("true")),
        r(P49, "Tenant choice", Synthetic("tenant choice")),
        r(P50, "Full", Opaque(r#""full""#)),
        r(P51, "Full", Opaque(r#""full""#)),
        r(P52, "On", Opaque("true")),
        r(
            P53,
            "Horizon Europe",
            Typed(|v| {
                same_json(
                    v.frozen.p53.0.as_str(),
                    r#"{"profile":"horizon-europe","version":1}"#,
                )
                .map_err(|e| format!("P-53 {e}"))
            }),
        ),
        r(P54, "3", Opaque("3")),
        r(
            P55,
            "From Annexe section 3, as a closed list (O-23)",
            Synthetic("O-23"),
        ),
        r(
            P56,
            "From the SuperSAFE estimated budget",
            Synthetic("the estimated budget is not in the spec"),
        ),
        r(
            P57,
            "From the SuperSAFE Data Sheet",
            Synthetic("the Data Sheet dates are not in the spec"),
        ),
        r(
            P58,
            "From the SuperSAFE Data Sheet (L-10)",
            Synthetic("L-10"),
        ),
        r(P59, "15 days", Opaque(r#"{"days":15}"#)),
        r(
            P60,
            "Mentoring by consortium experts; presenting results to the consortium; promotion and visibility; CRA compliance guidance",
            Opaque(
                r#"["mentoring_by_consortium_experts","presenting_results_to_consortium","promotion_and_visibility","cra_compliance_guidance"]"#,
            ),
        ),
        r(
            P61,
            "10 working days (proposed)",
            Opaque(r#"{"working_days":10}"#),
        ),
        r(
            P62,
            "15 working days (proposed)",
            Opaque(r#"{"working_days":15}"#),
        ),
        r(
            P63,
            "10 working days (proposed)",
            Opaque(r#"{"working_days":10}"#),
        ),
        r(
            P64,
            "20 working days (proposed)",
            Opaque(r#"{"working_days":20}"#),
        ),
        r(
            P65,
            "Options: public deliverables as for a full claim, or a progress report with deliverables at the final claim. SuperSAFE: public deliverables",
            Opaque(r#""public_deliverables""#),
        ),
        r(
            P66,
            "Enabled, with approval by an assigned reviewer",
            Opaque(r#"{"approval":"assigned_reviewer","enabled":true}"#),
        ),
        r(
            P67,
            "Options: return to the action's FSTP budget, or lapse and report as unspent. SuperSAFE: return to the FSTP budget",
            Opaque(r#""return_to_fstp_budget""#),
        ),
        r(
            P68,
            "Required in the footer of every interface and public page",
            NotProgramme,
        ),
        r(P69, "CC BY 4.0, publisher may choose another", NotProgramme),
        r(
            P70,
            "Passkeys always; EUDI Wallet, OPAQUE and magic links per tenant",
            NotProgramme,
        ),
        r(P71, "5 minutes (proposed)", NotProgramme),
        r(
            P72,
            "30 minutes idle, 12 hours absolute (proposed)",
            NotProgramme,
        ),
        r(P73, "Shared; dedicated on request", NotProgramme),
        r(
            P74,
            "Enabled for all roles, plus public research tools",
            NotProgramme,
        ),
        // D6 (M4 design 3.4) made P-75 a typed field of `FrozenValues`.
        r(
            P75,
            "Off",
            Typed(|v| expect("P-75", v.frozen.p75, AgentContentAccess::Off)),
        ),
        r(P76, "Off; programme opts in", Opaque("false")),
        r(
            P77,
            "Options: draft only, or allowed. SuperSAFE: draft only",
            Typed(|v| expect("P-77", v.frozen.p77, McpBindingActions::DraftOnly)),
        ),
        r(P78, "None", NotProgramme),
    ]
}

/// The parameters [`readings`] marks synthetic.
pub(crate) fn synthetic() -> BTreeSet<ParamId> {
    readings()
        .into_iter()
        .filter(|r| {
            matches!(
                r.reading,
                Reading::Synthetic(_) | Reading::PartlySynthetic(_, _)
            )
        })
        .map(|r| r.id)
        .collect()
}

/// The synthetic placeholders M4 design section 3.1 names. [`synthetic`]
/// holds each of them.
pub(crate) const DESIGN_SYNTHETIC: &[ParamId] = &[P21, P26, P41, P55, P56, P57, P58];

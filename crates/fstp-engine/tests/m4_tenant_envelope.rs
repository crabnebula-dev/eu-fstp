//! The tenant envelope of the engine (M4 design sections 3.5 and 4.2;
//! I-23, R-TN-01, SoD-07, Q31).
//!
//! Lane m4tenant, test author. The tests are written before the envelope
//! exists. They reach it only through the stored JSON form, so they
//! compile against the engine as it is. Until `Record`, `EnvelopeKind` and
//! the fold gain their tenant side, every decode of an `onboarding`
//! member is refused, and each test fails at that decode, naming I-23.
//!
//! # The contract these tests fix
//!
//! - A tenant record is stored under the envelope member `onboarding`.
//!   M3's cell envelope already stores its own tenant records under
//!   `tenant`, so the engine side takes a member no cell family uses (fix
//!   round 1; the member name is a reading, as the M2 ones are). Its
//!   inner value is the `fstp-tenant` codec form of the `TenantRecord`
//!   (design section 4.2: "`Record` and `EnvelopeKind` gain `Creator`,
//!   `Import` and `Tenant`").
//! - The tenant part of `EngineState` is a `TenantState`, whose genesis
//!   names the first tenant admin and the kind of cell (Q31 A: "M3
//!   provisioning the first admin"). The design gives no record for that
//!   genesis. Interim reading of this lane, pending the lead and Daniel:
//!   the cell appends one provisioning record under the same member, in
//!   the codec style of `fstp-tenant`,
//!   `{"cell": "saas" | "self_hosted", "first_admin": "<id>", "kind": "TenantProvisioned"}`.
//!   [`provisioned`] is the only place that spells it. A tenant record
//!   before it, or a second one, does not fold.
//! - The fold is structural, as for every other side. It refuses every
//!   tenant record that `TenantState::apply` refuses, so a ledger that
//!   breaks a tenant rule a record alone can show never replays.
//! - Tenant entries keep the ledger time-monotone across all parts.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::FoldError;
use fstp_domain::id::{AccountId, ContentDigest, LlmConfigId, ProgrammeId, TextId, TextRef};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_engine::{EngineState, Record, envelope_from_json, record_from_json_at, replay};
use fstp_json::{FromJson, Object, ToJson, Value, parse};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};
use fstp_tenant::{
    ApprovalId, BankInterface, BrandingPackage, DomainName, GrantRef, InferenceDefault,
    InvitationId, LoginMethod, McpSettings, OnboardingStep, PaymentMode, RpMode, SettingValue,
    SignatoryRole, StepFailure, StepOutcome, StepValues, TenantRecord, Token, TokenDigest,
    VerifyMethod, encode_record,
};

/// The first tenant admin, named by the provisioning record.
const A1: AccountId = AccountId::from_raw(11);
/// The second tenant admin, invited by A1.
const A2: AccountId = AccountId::from_raw(12);
/// The holder of both signatory roles (SoD-14, SoD-15, NOTE 5).
const SIGNATORY: AccountId = AccountId::from_raw(13);
/// An account outside the tenant admin set.
const OUTSIDER: AccountId = AccountId::from_raw(31);
/// The invitation of A2.
const INVITATION: InvitationId = InvitationId::from_raw(5);

// ---------------------------------------------------------------------------
// The stored form
// ---------------------------------------------------------------------------

/// The `fstp-tenant` codec form of `r`, as a JSON value.
fn inner(r: &TenantRecord) -> Value {
    let bytes = encode_record(r).expect("the tenant codec encodes every record");
    parse(&bytes).expect("the tenant codec writes JSON")
}

/// The interim provisioning record of this lane (crate documentation):
/// the genesis of the tenant part, with its first admin and kind of cell.
fn provisioned(first_admin: AccountId, cell: &str) -> Value {
    let mut o = Object::new();
    o.insert("cell", Value::from(cell));
    o.insert("first_admin", Value::from(first_admin.raw().to_string()));
    o.insert("kind", Value::from("TenantProvisioned"));
    Value::Object(o)
}

/// The stored envelope of a tenant inner value: the one member
/// `onboarding`. M3's cell envelope keeps `tenant` for its own tenant
/// records, so the engine side takes a member no cell family uses (fix
/// round 1 of lane m4tenant).
fn envelope(inner: Value) -> Value {
    let mut o = Object::new();
    o.insert("onboarding", inner);
    Value::Object(o)
}

/// The engine record of a tenant inner value, decoded from its stored
/// form under schema version 1. It fails the test, naming I-23, while the
/// engine has no tenant envelope.
fn record(inner: Value) -> Record {
    let stored = envelope(inner);
    record_from_json_at(1, &stored).unwrap_or_else(|e| {
        panic!("I-23: the engine does not decode a stored tenant envelope ({e:?}): {stored:?}")
    })
}

/// The engine record of `r`.
fn tenant(r: TenantRecord) -> Record {
    record(inner(&r))
}

// ---------------------------------------------------------------------------
// Ledgers
// ---------------------------------------------------------------------------

/// One ledger entry before it is numbered: its time and its records,
/// which share one command id.
struct Batch {
    at: i64,
    records: Vec<Record>,
}

fn batch(at: i64, records: Vec<Record>) -> Batch {
    Batch { at, records }
}

/// The command id of the `n`-th batch.
fn command(n: usize) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = 0x7e;
    id[8..].copy_from_slice(&(n as u64).to_be_bytes());
    id
}

/// Numbers `batches` from sequence 1, one entry per record and one
/// command id per batch.
fn ledger(batches: &[Batch]) -> Vec<Entry<Record>> {
    let mut store = MemStore::new();
    let mut head = Seq::ZERO;
    for (n, b) in batches.iter().enumerate() {
        head = store
            .append(head, b.at, command(n), b.records.clone())
            .unwrap_or_else(|e| panic!("the store refused batch {n}: {e:?}"));
    }
    let mut out = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut out).unwrap();
    out
}

/// Replays `batches` from genesis.
fn replay_batches(batches: &[Batch]) -> Result<EngineState, FoldError> {
    replay(&ledger(batches))
}

// ---------------------------------------------------------------------------
// Onboarding values that validate (`fstp_tenant::rules::values_check`)
// ---------------------------------------------------------------------------

fn token(s: &str) -> Token {
    Token::new(s).expect("a valid token")
}

fn domain(s: &str) -> DomainName {
    DomainName::new(s).expect("a valid domain name")
}

fn values(step: OnboardingStep) -> StepValues {
    match step {
        OnboardingStep::Organisation => StepValues::Organisation {
            data_protection_contact: TextRef::new(
                TextId::from_raw(1),
                ContentDigest::from_bytes([7; 32]),
            ),
            signatories: [A1].into_iter().collect(),
        },
        OnboardingStep::Agreements => StepValues::Agreements {
            saas_terms: 1,
            dpa: 1,
            sub_processors: 1,
        },
        OnboardingStep::Branding => StepValues::Branding {
            package: BrandingPackage::Default,
        },
        OnboardingStep::DomainsAndEmail => StepValues::DomainsAndEmail {
            sending_domain: domain("mail.e2e.invalid"),
        },
        OnboardingStep::Identity => StepValues::Identity {
            p18: [VerifyMethod::EudiWallet, VerifyMethod::DocumentUpload]
                .into_iter()
                .collect(),
            p45: RpMode::TenantRegistration,
        },
        OnboardingStep::Inference => StepValues::Inference(InferenceDefault {
            provider: token("placeholder"),
            primary: token("placeholder-model"),
            fallbacks: Vec::new(),
        }),
        OnboardingStep::Payments => StepValues::Payments {
            bank_interface: BankInterface::NotConnected,
        },
        OnboardingStep::Channels => StepValues::Channels {
            matrix_homeserver: None,
            whatsapp: false,
        },
        OnboardingStep::Administrators => StepValues::Administrators {
            admins: [A1, A2].into_iter().collect(),
        },
    }
}

/// The records of a save of `step` by `by` that validated it: the
/// `StepSaved` and its `StepValidated`, in one entry, as
/// `fstp_tenant::decide` returns them.
fn validated(step: OnboardingStep, by: AccountId) -> Vec<Record> {
    vec![
        tenant(TenantRecord::StepSaved {
            values: values(step),
            by,
            outcome: StepOutcome::Validated,
        }),
        tenant(TenantRecord::StepValidated { step, by }),
    ]
}

fn digest() -> TokenDigest {
    TokenDigest::from_bytes([0xd1; 32])
}

fn invited() -> Record {
    tenant(TenantRecord::AdminInvited {
        invitation: INVITATION,
        invitee: A2,
        token_digest: digest(),
        by: A1,
    })
}

fn added() -> Record {
    tenant(TenantRecord::AdminAdded {
        account: A2,
        invitation: INVITATION,
    })
}

fn p20_record_only() -> Record {
    tenant(TenantRecord::SettingChanged {
        value: SettingValue::P20(PaymentMode::RecordOnly),
        by: A1,
    })
}

/// A SaaS tenant through every onboarding step to completion with two
/// admins and a holder of each signatory role, one entry per command, one
/// second apart (design 2.2 J0).
fn onboarding() -> Vec<Batch> {
    let mut t = 1_000_000i64;
    let mut next = || {
        t = t.saturating_add(1_000_000);
        t
    };
    let mut out = vec![batch(next(), vec![record(provisioned(A1, "saas"))])];
    for step in [
        OnboardingStep::Organisation,
        OnboardingStep::Agreements,
        OnboardingStep::Branding,
        OnboardingStep::DomainsAndEmail,
        OnboardingStep::Identity,
        OnboardingStep::Inference,
    ] {
        out.push(batch(next(), validated(step, A1)));
    }
    out.push(batch(next(), vec![p20_record_only()]));
    out.push(batch(next(), validated(OnboardingStep::Payments, A1)));
    out.push(batch(next(), validated(OnboardingStep::Channels, A1)));
    out.push(batch(next(), vec![invited()]));
    out.push(batch(next(), vec![added()]));
    // SoD-14, SoD-15: the Administrators step validates only with a
    // holder of each signatory role.
    let at = next();
    out.push(batch(
        at,
        SignatoryRole::ALL
            .into_iter()
            .map(|role| {
                tenant(TenantRecord::SignatoryGranted {
                    role,
                    account: SIGNATORY,
                    by: A1,
                    at: Timestamp::from_micros(at),
                })
            })
            .collect(),
    ));
    out.push(batch(next(), validated(OnboardingStep::Administrators, A2)));
    out.push(batch(
        next(),
        vec![tenant(TenantRecord::OnboardingCompleted { by: A1 })],
    ));
    out
}

/// The first `n` batches of [`onboarding`].
fn onboarding_prefix(n: usize) -> Vec<Batch> {
    let mut all = onboarding();
    all.truncate(n);
    all
}

/// The time just after the last batch of `batches`.
fn after(batches: &[Batch]) -> i64 {
    batches
        .last()
        .map_or(1_000_000, |b| b.at.saturating_add(1_000_000))
}

/// The refusal of a ledger that breaks a tenant rule: a content refusal,
/// never a sequence or clock one.
fn content_refusal(r: Result<EngineState, FoldError>, what: &str) {
    match r {
        Err(FoldError::OutOfOrder | FoldError::TimeBackwards) => {
            panic!("{what}: refused for its numbering or clock, not its content")
        }
        Err(FoldError::NotImplemented) => panic!("{what}: the tenant fold is not implemented"),
        Err(_) => {}
        Ok(_) => panic!("{what}: the ledger replayed"),
    }
}

// ---------------------------------------------------------------------------
// One sample of every record variant
// ---------------------------------------------------------------------------

/// One stored inner value of each tenant record variant, the provisioning
/// record included.
fn every_variant() -> Vec<Value> {
    let grant = GrantRef {
        grantee: A1,
        programme: ProgrammeId::from_raw(1),
        role: Role::ProgrammeManager,
    };
    vec![
        provisioned(A1, "saas"),
        provisioned(A1, "self_hosted"),
        inner(&TenantRecord::StepSaved {
            values: values(OnboardingStep::Organisation),
            by: A1,
            outcome: StepOutcome::Validated,
        }),
        inner(&TenantRecord::StepSaved {
            values: values(OnboardingStep::Administrators),
            by: A1,
            outcome: StepOutcome::Failed(StepFailure::TooFewAdmins),
        }),
        inner(&TenantRecord::StepValidated {
            step: OnboardingStep::DomainsAndEmail,
            by: A1,
        }),
        inner(&TenantRecord::AdminInvited {
            invitation: INVITATION,
            invitee: A2,
            token_digest: digest(),
            by: A1,
        }),
        inner(&TenantRecord::AdminAdded {
            account: A2,
            invitation: INVITATION,
        }),
        inner(&TenantRecord::SelfGrantApproved {
            approval: ApprovalId::from_raw(3),
            grant,
            by: A2,
            at: Timestamp::from_micros(7_000_000),
        }),
        inner(&TenantRecord::SelfGrantApprovalUsed {
            approval: ApprovalId::from_raw(3),
            by: A1,
            at: Timestamp::from_micros(8_000_000),
        }),
        inner(&TenantRecord::SettingChanged {
            value: SettingValue::P70(
                [LoginMethod::Passkey, LoginMethod::EudiWallet]
                    .into_iter()
                    .collect(),
            ),
            by: A1,
        }),
        inner(&TenantRecord::SettingChanged {
            value: SettingValue::P74(McpSettings {
                enabled: true,
                roles: Some([Role::Applicant].into_iter().collect::<BTreeSet<_>>()),
                public_tools: false,
            }),
            by: A1,
        }),
        inner(&TenantRecord::InferenceConfigRecorded {
            config: LlmConfigId::from_raw(4),
            primary: token("placeholder-model"),
            fallbacks: vec![token("placeholder-fallback")],
            by: A1,
        }),
        inner(&TenantRecord::OnboardingCompleted { by: A1 }),
    ]
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/// I-23 (design section 4.2): every tenant record, stored under the
/// envelope member `tenant`, decodes on the tenant side and encodes back
/// to the same stored value. Through a store, its canonical text decodes
/// to the same entry.
#[test]
fn i23_tenant_records_round_trip_in_the_envelope() {
    for v in every_variant() {
        let stored = envelope(v.clone());
        let r = record(v);
        assert_eq!(
            r.to_json(),
            stored,
            "I-23: encoding changed the stored value"
        );
        assert_eq!(
            Record::from_json(&stored).as_ref(),
            Ok(&r),
            "I-23: the current decode and the schema 1 decode disagree"
        );
        let (kind, inner) = envelope_from_json(&stored).expect("the envelope splits");
        assert_eq!(kind.member(), "onboarding", "I-23: stored on another side");
        assert_eq!(
            Some(inner),
            stored.as_object().and_then(|o| o.get("onboarding"))
        );

        let mut store = MemStore::new();
        store
            .append(Seq::ZERO, 5, [1; 16], vec![r.clone()])
            .unwrap();
        let mut entries = Vec::new();
        store.read(Seq::ZERO, usize::MAX, &mut entries).unwrap();
        let text = entries[0].canonical_text().unwrap();
        let raw = Entry::<Value>::from_json(&parse(text.as_bytes()).unwrap()).unwrap();
        let back = raw
            .try_map_record(|schema, rec| record_from_json_at(schema, &rec))
            .unwrap();
        assert_eq!(
            back, entries[0],
            "I-23: the canonical text decodes to another entry"
        );
    }
}

/// I-23 (ADR-007): the tenant side decodes only what the tenant codec
/// accepts. A valid record decodes, and each malformed variant of it is
/// refused: an unknown or missing member, a JSON number for an id, an
/// unknown kind, a second envelope member and an unpublished schema.
#[test]
fn i23_tenant_envelope_refuses_what_the_tenant_codec_refuses() {
    let good = inner(&TenantRecord::StepValidated {
        step: OnboardingStep::Organisation,
        by: A1,
    });
    let _ = record(good.clone());
    let _ = record(provisioned(A1, "saas"));

    let edit = |f: &dyn Fn(&mut Object)| {
        let mut v = good.clone();
        f(v.as_object_mut().unwrap());
        envelope(v)
    };
    let mut bad = vec![
        (
            "unknown member",
            edit(&|o| {
                o.insert("extra", Value::from("x"));
            }),
        ),
        (
            "missing member",
            edit(&|o| {
                o.remove("by");
            }),
        ),
        (
            "number id",
            edit(&|o| {
                o.insert("by", parse(b"11").unwrap());
            }),
        ),
        (
            "unknown kind",
            edit(&|o| {
                o.insert("kind", Value::from("StepInvented"));
            }),
        ),
        (
            "unknown step",
            edit(&|o| {
                o.insert("step", Value::from("invented"));
            }),
        ),
    ];
    let mut two = Object::new();
    two.insert("onboarding", good.clone());
    two.insert("core", good.clone());
    bad.push(("two members", Value::Object(two)));
    let mut prov = provisioned(A1, "saas");
    prov.as_object_mut()
        .unwrap()
        .insert("cell", Value::from("invented"));
    bad.push(("unknown cell", envelope(prov)));
    let mut prov = provisioned(A1, "saas");
    prov.as_object_mut()
        .unwrap()
        .insert("first_admin", Value::from("011"));
    bad.push(("non-canonical first admin", envelope(prov)));
    for (what, v) in bad {
        assert!(
            record_from_json_at(1, &v).is_err(),
            "I-23: a tenant envelope with {what} decoded"
        );
    }
    for schema in [0, 2, u16::MAX] {
        assert!(
            record_from_json_at(schema, &envelope(good.clone())).is_err(),
            "I-23: schema {schema} decoded"
        );
    }
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

/// I-23, R-TN-01, SoD-07: a ledger that takes a SaaS tenant through every
/// onboarding step to completion with two admins replays, and so does
/// each of its prefixes at an entry boundary. Replay is deterministic,
/// and every tenant entry changes the folded state, so none is dropped.
#[test]
fn i23_tenant_onboarding_ledger_replays() {
    let all = onboarding();
    let mut previous: Option<EngineState> = None;
    for n in 1..=all.len() {
        let state = replay_batches(&onboarding_prefix(n))
            .unwrap_or_else(|e| panic!("I-23: the prefix of {n} entries does not replay: {e:?}"));
        assert_eq!(
            replay_batches(&onboarding_prefix(n)).as_ref(),
            Ok(&state),
            "I-23: replay is not deterministic"
        );
        if let Some(p) = previous {
            assert_ne!(p, state, "I-23: entry {n} left the state unchanged");
        }
        previous = Some(state);
    }
}

/// R-TN-01: each step validates before the next opens. A save of a step
/// whose earlier steps are not all validated does not fold, nor does a
/// `StepValidated` without a validating save. The same ledger with the
/// missing step in place replays.
#[test]
fn r_tn_01_fold_refuses_a_step_record_out_of_step_order() {
    // Provisioning and Organisation.
    let base = onboarding_prefix(2);
    let at = after(&base);
    let with = |records: Vec<Record>| {
        let mut b = onboarding_prefix(2);
        b.push(batch(at, records));
        b
    };
    assert!(
        replay_batches(&with(validated(OnboardingStep::Agreements, A1))).is_ok(),
        "R-TN-01: the next step in order does not fold"
    );
    content_refusal(
        replay_batches(&with(validated(OnboardingStep::Branding, A1))),
        "R-TN-01: Branding saved before Agreements validated",
    );
    content_refusal(
        replay_batches(&with(vec![tenant(TenantRecord::StepSaved {
            values: values(OnboardingStep::Identity),
            by: A1,
            outcome: StepOutcome::Failed(StepFailure::InvalidValues),
        })])),
        "R-TN-01: a failed save of a locked step",
    );
    content_refusal(
        replay_batches(&with(vec![tenant(TenantRecord::StepValidated {
            step: OnboardingStep::Agreements,
            by: A1,
        })])),
        "R-TN-01: a StepValidated with no validating save",
    );
    content_refusal(
        replay_batches(&with(vec![tenant(TenantRecord::StepSaved {
            values: StepValues::Organisation {
                data_protection_contact: TextRef::new(
                    TextId::from_raw(2),
                    ContentDigest::from_bytes([8; 32]),
                ),
                signatories: BTreeSet::new(),
            },
            by: A1,
            outcome: StepOutcome::Validated,
        })])),
        "R-TN-01: a save marked validated whose values fail the step",
    );
    // A self-hosted cell skips Agreements: Branding follows Organisation,
    // and a save of Agreements does not fold.
    let self_hosted = |records: Vec<Record>| {
        vec![
            batch(2_000_000, vec![record(provisioned(A1, "self_hosted"))]),
            batch(3_000_000, validated(OnboardingStep::Organisation, A1)),
            batch(4_000_000, records),
        ]
    };
    assert!(
        replay_batches(&self_hosted(validated(OnboardingStep::Branding, A1))).is_ok(),
        "R-TN-01: Branding after Organisation in a self-hosted cell does not fold"
    );
    content_refusal(
        replay_batches(&self_hosted(validated(OnboardingStep::Agreements, A1))),
        "R-TN-01: Agreements saved in a self-hosted cell",
    );
}

/// Q31 A: the admin set lives in the ledger. A tenant record by an
/// account outside it does not fold. An invitation adds no admin, an
/// `AdminAdded` needs an open invitation of the same invitee, and the
/// added admin's records fold after it.
#[test]
fn q31_fold_refuses_tenant_records_outside_the_ledger_admin_set() {
    let start = || vec![batch(2_000_000, vec![record(provisioned(A1, "saas"))])];
    let with = |records: Vec<Vec<Record>>| {
        let mut b = start();
        let mut at = 2_000_000i64;
        for r in records {
            at = at.saturating_add(1_000_000);
            b.push(batch(at, r));
        }
        b
    };
    let setting = |by: AccountId| {
        tenant(TenantRecord::SettingChanged {
            value: SettingValue::P69("MIT".to_owned()),
            by,
        })
    };
    assert!(replay_batches(&with(vec![vec![setting(A1)]])).is_ok());
    content_refusal(
        replay_batches(&with(vec![validated(
            OnboardingStep::Organisation,
            OUTSIDER,
        )])),
        "Q31: a step saved by an account outside the admin set",
    );
    content_refusal(
        replay_batches(&with(vec![vec![setting(OUTSIDER)]])),
        "Q31: a setting changed by an account outside the admin set",
    );
    content_refusal(
        replay_batches(&with(vec![vec![invited()], vec![setting(A2)]])),
        "Q31: a setting changed by an invitee who has not joined",
    );
    content_refusal(
        replay_batches(&with(vec![vec![added()]])),
        "Q31: an admin added with no invitation",
    );
    content_refusal(
        replay_batches(&with(vec![
            vec![invited()],
            vec![tenant(TenantRecord::AdminAdded {
                account: OUTSIDER,
                invitation: INVITATION,
            })],
        ])),
        "Q31: an admin added who is not the invitee",
    );
    content_refusal(
        replay_batches(&with(vec![vec![invited()], vec![added()], vec![added()]])),
        "Q31: one invitation taken twice",
    );
    assert!(
        replay_batches(&with(vec![
            vec![invited()],
            vec![added()],
            vec![setting(A2)]
        ]))
        .is_ok(),
        "Q31: the added admin's setting change does not fold"
    );
}

/// Q31 A: the tenant part starts from one provisioning record. A tenant
/// record before it does not fold, nor does a second provisioning.
#[test]
fn q31_fold_needs_exactly_one_provisioning_record() {
    content_refusal(
        replay_batches(&[batch(
            2_000_000,
            validated(OnboardingStep::Organisation, A1),
        )]),
        "Q31: a tenant record with no provisioning",
    );
    content_refusal(
        replay_batches(&[
            batch(2_000_000, vec![record(provisioned(A1, "saas"))]),
            batch(3_000_000, vec![record(provisioned(OUTSIDER, "saas"))]),
        ]),
        "Q31: a second provisioning record",
    );
}

/// SoD-07: at least two tenant admins. A validated Administrators step
/// with one admin does not fold, nor does a completion before the second
/// admin joined. Both fold once A2 is added.
#[test]
fn sod07_fold_refuses_two_admin_records_with_one_admin() {
    // Every step before Administrators, with the invitation but before A2
    // joins.
    let mut one = onboarding_prefix(11);
    let at = after(&one);
    one.push(batch(
        at,
        vec![tenant(TenantRecord::StepSaved {
            values: StepValues::Administrators {
                admins: [A1].into_iter().collect(),
            },
            by: A1,
            outcome: StepOutcome::Validated,
        })],
    ));
    content_refusal(
        replay_batches(&one),
        "SoD-07: Administrators validated with one admin",
    );
    let mut early = onboarding_prefix(11);
    early.push(batch(
        at,
        vec![tenant(TenantRecord::OnboardingCompleted { by: A1 })],
    ));
    content_refusal(
        replay_batches(&early),
        "SoD-07: onboarding completed with one admin",
    );
    assert!(replay_batches(&onboarding()).is_ok());
}

/// I-23 (design section 2.2): tenant entries keep the ledger
/// time-monotone across all parts. A tenant entry before the latest core
/// entry does not fold, nor a core entry before the latest tenant entry.
#[test]
fn i23_tenant_entries_keep_the_ledger_time_monotone() {
    let core = || {
        Record::Core(fstp_domain::Record::VaultEpochProcessed {
            epoch: fstp_domain::id::VaultEpoch::from_raw(1),
        })
    };
    assert!(
        replay_batches(&[
            batch(2_000_000, vec![record(provisioned(A1, "saas"))]),
            batch(3_000_000, vec![core()]),
            batch(3_000_000, validated(OnboardingStep::Organisation, A1)),
        ])
        .is_ok(),
        "I-23: entries at equal times do not fold"
    );
    assert_eq!(
        replay_batches(&[
            batch(2_000_000, vec![record(provisioned(A1, "saas"))]),
            batch(5_000_000, vec![core()]),
            batch(4_000_000, validated(OnboardingStep::Organisation, A1)),
        ]),
        Err(FoldError::TimeBackwards),
        "I-23: a tenant entry before the latest core entry"
    );
    assert_eq!(
        replay_batches(&[
            batch(2_000_000, vec![record(provisioned(A1, "saas"))]),
            batch(5_000_000, validated(OnboardingStep::Organisation, A1)),
            batch(4_000_000, vec![core()]),
        ]),
        Err(FoldError::TimeBackwards),
        "I-23: a core entry before the latest tenant entry"
    );
}

/// I-23: a ledger with no tenant record replays as before the tenant
/// side existed. Its stored text is unchanged byte for byte, holds no
/// `tenant` member, and decodes to the same entries.
#[test]
fn i23_ledgers_without_tenant_records_replay_unchanged() {
    let core = Record::Core(fstp_domain::Record::VaultEpochProcessed {
        epoch: fstp_domain::id::VaultEpoch::from_raw(9),
    });
    let mut store = MemStore::new();
    store
        .append(Seq::ZERO, 5, [1; 16], vec![core.clone()])
        .unwrap();
    let mut entries = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut entries).unwrap();
    let text = entries[0].canonical_text().unwrap();
    assert_eq!(
        text,
        "{\"at\":5,\"command\":\"01010101010101010101010101010101\",\"record\":{\"core\":{\"epoch\":\"9\",\"type\":\"VaultEpochProcessed\"}},\"schema\":1,\"seq\":\"1\"}",
        "I-23: the stored text of a core entry changed"
    );
    let raw = Entry::<Value>::from_json(&parse(text.as_bytes()).unwrap()).unwrap();
    let back = raw
        .try_map_record(|schema, rec| record_from_json_at(schema, &rec))
        .unwrap();
    assert_eq!(back, entries[0]);
    assert_eq!(
        replay(&[back]).unwrap(),
        replay(&entries).unwrap(),
        "I-23: the decoded ledger replays to another state"
    );
}

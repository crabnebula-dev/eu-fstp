//! Generators of cell records and cell commands of every member and
//! variant (M3 design sections 5.1 and 15).
//!
//! The M2 members reuse the generators of the M2 codec suites
//! (`crates/fstp-domain/tests/codec_support`), which cover every record
//! variant and every command kind. The test file that includes this
//! module includes `codec_support` at its crate root.
//!
//! Reading: fields that the stubs type as "canonical" bytes (`op`,
//! `policy`, `ticket`, `relationship`) are generated as RFC 8785 texts of
//! small JSON objects, so they are valid whether the codec embeds them as
//! JSON or carries them as opaque bytes.

#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_auth::{AuthCommand, AuthRecord};
use fstp_cell_core::ops::{OpsCommand, OpsRecord};
use fstp_cell_core::release::{ReleaseCommand, ReleaseRecord};
use fstp_cell_core::tenant::{TenantCommand, TenantRecord};
use fstp_cell_core::text::{TextCommand, TextRecord};
use fstp_cell_core::{CellCommand, CellRecord, KeyCommand, KeyRecord};
use fstp_domain::command::CommandKind;
use fstp_domain::id::AccountId;
use fstp_prop::Gen;

use crate::codec_support::{Draw, RecordTag, command, record};

/// The stored member names of the cell envelope (design section 5.1).
pub(crate) const MEMBERS: [&str; 8] = [
    "core", "finding", "auth", "tenant", "text", "key", "release", "ops",
];

/// The member a cell record is stored under.
pub(crate) fn member_of(r: &CellRecord) -> &'static str {
    match r {
        CellRecord::Engine(fstp_engine::Record::Core(_)) => "core",
        CellRecord::Engine(fstp_engine::Record::Finding(_)) => "finding",
        CellRecord::Auth(_) => "auth",
        CellRecord::Tenant(_) => "tenant",
        CellRecord::Text(_) => "text",
        CellRecord::Key(_) => "key",
        CellRecord::Release(_) => "release",
        CellRecord::Ops(_) => "ops",
    }
}

fn account(g: &mut Gen) -> AccountId {
    AccountId::from_raw(u128::from(g.u64()))
}

fn id16(g: &mut Gen) -> [u8; 16] {
    let mut out = [0u8; 16];
    for b in &mut out {
        *b = g.u8();
    }
    out
}

fn id32(g: &mut Gen) -> [u8; 32] {
    let mut out = [0u8; 32];
    for b in &mut out {
        *b = g.u8();
    }
    out
}

/// A canonical JSON object text: `{}` or `{"k":<n>}` with a small integer.
fn canonical_bytes(g: &mut Gen) -> Vec<u8> {
    if g.bool() {
        b"{}".to_vec()
    } else {
        format!("{{\"k\":{}}}", g.u32_in(0..=1_000_000)).into_bytes()
    }
}

/// An M2 core record of a variant drawn from every variant a test can
/// build. The four witness payloads have no public constructor, so M2
/// checks their round trip over its fuzz seed corpus
/// (`RecordTag::WITNESS`).
pub(crate) fn core_record(g: &mut Gen) -> Result<fstp_domain::Record, String> {
    let tags = RecordTag::generated();
    let tag = *g.pick(&tags);
    record(g, &mut Draw::plain(), tag)
}

/// An M2 finding record.
pub(crate) fn finding_record(g: &mut Gen) -> fstp_engine::FindingRecord {
    use fstp_domain::id::{CallId, LlmConfigId, ProposalId};
    let id = u128::from(g.u32());
    let call = CallId::from_raw(u128::from(g.u8_in(1..=3)));
    let proposal = ProposalId::from_raw(u128::from(g.u8_in(1..=3)));
    let config = LlmConfigId::from_raw(u128::from(g.u8_in(1..=3)));
    let f = fstp_domain_testkit::r#gen::findings::gen_finding(g, id, call, proposal, config, false);
    fstp_engine::FindingRecord::Recorded(f)
}

/// A cell record stored under `member`, of a variant drawn from all of
/// that member's variants.
pub(crate) fn record_in(g: &mut Gen, member: &str) -> Result<CellRecord, String> {
    Ok(match member {
        "core" => CellRecord::Engine(fstp_engine::Record::Core(core_record(g)?)),
        "finding" => CellRecord::Engine(fstp_engine::Record::Finding(finding_record(g))),
        "auth" => CellRecord::Auth(match g.u8_in(0..=2) {
            0 => AuthRecord::CredentialRegistered {
                account: account(g),
                credential: g.bytes(1..=64),
            },
            1 => AuthRecord::StepUpGranted {
                id: id16(g),
                action_digest: id32(g),
            },
            _ => AuthRecord::SessionEnded { session: id16(g) },
        }),
        "tenant" => CellRecord::Tenant(match g.u8_in(0..=4) {
            0 => TenantRecord::TenantAdminGranted {
                account: account(g),
            },
            1 => TenantRecord::TenantAdminEnded {
                account: account(g),
            },
            2 => TenantRecord::SelfGrantApproved {
                approver: account(g),
                grant_digest: id32(g),
                expires_at: g.i64_in(-fstp_ledger::MAX_AT..=fstp_ledger::MAX_AT),
            },
            3 => TenantRecord::SelfGrantApprovalUsed {
                grant_digest: id32(g),
            },
            _ => TenantRecord::LoginPolicySet {
                policy: canonical_bytes(g),
            },
        }),
        "text" => CellRecord::Text(if g.bool() {
            TextRecord::TextPut { id: id16(g) }
        } else {
            TextRecord::TextsErased {
                ids: g.vec(0..=4, id16),
            }
        }),
        "key" => CellRecord::Key(if g.bool() {
            KeyRecord::KeyOpRecorded {
                op: canonical_bytes(g),
            }
        } else {
            KeyRecord::EpochDestroyed {
                epoch: g.u64(),
                receipt: id32(g),
            }
        }),
        "release" => CellRecord::Release(if g.bool() {
            ReleaseRecord::TicketIssued {
                id: id16(g),
                kind: g.u16(),
                proposal: u128::from(g.u64()),
                holder: account(g),
            }
        } else {
            ReleaseRecord::IdentityReleaseIssued {
                id: id16(g),
                proposal: u128::from(g.u64()),
                by: account(g),
            }
        }),
        "ops" => CellRecord::Ops(if g.bool() {
            OpsRecord::BreakGlassApproved { grant: id16(g) }
        } else {
            OpsRecord::BreakGlassEnded { grant: id16(g) }
        }),
        other => return Err(format!("no member {other}")),
    })
}

/// A cell record of any member.
pub(crate) fn any_record(g: &mut Gen) -> Result<CellRecord, String> {
    let member = *g.pick(&MEMBERS);
    record_in(g, member)
}

/// The command members of the cell envelope. M2 finding commands are
/// left out: no generator covers them yet (lane W1 gap, reported).
pub(crate) const COMMAND_MEMBERS: [&str; 7] =
    ["core", "auth", "tenant", "text", "key", "release", "ops"];

/// An M2 core command of a kind drawn from every kind.
pub(crate) fn core_command(g: &mut Gen) -> Result<fstp_domain::Command, String> {
    let kind = *g.pick(&CommandKind::ALL);
    command(g, &mut Draw::plain(), kind)
}

/// A cell command of `member`, of a variant drawn from all of its variants.
pub(crate) fn command_in(g: &mut Gen, member: &str) -> Result<CellCommand, String> {
    Ok(match member {
        "core" => CellCommand::Engine(fstp_engine::Command::Core(core_command(g)?)),
        "auth" => CellCommand::Auth(match g.u8_in(0..=2) {
            0 => AuthCommand::RegisterCredential {
                account: account(g),
                credential: g.bytes(1..=64),
            },
            1 => AuthCommand::RevokeCredential {
                account: account(g),
                credential: g.bytes(1..=64),
            },
            _ => AuthCommand::GrantStepUp {
                session: id16(g),
                action_digest: id32(g),
            },
        }),
        "tenant" => CellCommand::Tenant(match g.u8_in(0..=3) {
            0 => TenantCommand::GrantTenantAdmin {
                account: account(g),
            },
            1 => TenantCommand::EndTenantAdmin {
                account: account(g),
            },
            2 => TenantCommand::ApproveSelfGrant {
                grant_digest: id32(g),
            },
            _ => TenantCommand::SetLoginPolicy {
                policy: canonical_bytes(g),
            },
        }),
        "text" => CellCommand::Text(if g.bool() {
            TextCommand::PutText { id: id16(g) }
        } else {
            TextCommand::EraseTexts {
                ids: g.vec(0..=4, id16),
                cause: g.u16(),
            }
        }),
        "key" => CellCommand::Key(if g.bool() {
            KeyCommand::RecordKeyOp {
                op: canonical_bytes(g),
            }
        } else {
            KeyCommand::RecordEpochDestroyed {
                epoch: g.u64(),
                receipt: id32(g),
            }
        }),
        "release" => CellCommand::Release(match g.u8_in(0..=2) {
            0 => ReleaseCommand::IssueReleaseTicket {
                proposal: u128::from(g.u64()),
            },
            1 => ReleaseCommand::IssueWriteTicket { kind: g.u16() },
            _ => ReleaseCommand::RecordRelationship {
                relationship: canonical_bytes(g),
            },
        }),
        "ops" => CellCommand::Ops(match g.u8_in(0..=3) {
            0 => OpsCommand::ApproveBreakGlass { request: id16(g) },
            1 => OpsCommand::EndBreakGlass { grant: id16(g) },
            2 => OpsCommand::ApplyOperatorTicket {
                ticket: canonical_bytes(g),
            },
            _ => OpsCommand::EndSessionsAtBindingEnd {
                account: account(g),
            },
        }),
        other => return Err(format!("no command member {other}")),
    })
}

/// A cell command of any member.
pub(crate) fn any_command(g: &mut Gen) -> Result<CellCommand, String> {
    let member = *g.pick(&COMMAND_MEMBERS);
    command_in(g, member)
}

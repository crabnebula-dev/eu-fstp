//! I-23, R-NF-02: every `Contract` envelope record round-trips through its
//! stored JSON form, and malformed input is refused without panicking.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use fstp_contract::{ChangeStatus, ContractRecord, Digest, Party, PartyRole, Route, Side};
use fstp_domain::id::{AccountId, ContractId, DecisionId, PlanVersionId, ProposalId};
use fstp_json::{FromJson, ToJson, parse};
use fstp_prop::{Gen, check, prop_assert_eq};

fn digest(g: &mut Gen) -> Digest {
    Digest::from_bytes(g.bytes(32..=32).try_into().unwrap())
}

/// Any u128, from two u64 halves.
fn wide(g: &mut Gen) -> u128 {
    (u128::from(g.u64()) << 64) | u128::from(g.u64())
}

fn record(g: &mut Gen) -> ContractRecord {
    let contract = ContractId::from_raw(wide(g));
    let version = g.u32();
    let party = (*g.pick(&["lead", "member-1", "signatory", "guardian"])).to_owned();
    match g.usize_in(0..=7) {
        0 => ContractRecord::Drafted {
            contract,
            proposal: ProposalId::from_raw(wide(g)),
            version,
            template: g.u32(),
            plan: PlanVersionId::from_raw(wide(g)),
            determination: DecisionId::from_raw(wide(g)),
            parties: vec![
                Party::new("lead", PartyRole::Lead, AccountId::from_raw(wide(g))),
                Party::new(
                    "guardian",
                    PartyRole::Guardian,
                    AccountId::from_raw(wide(g)),
                ),
                Party::new(
                    "signatory",
                    PartyRole::Signatory,
                    AccountId::from_raw(wide(g)),
                ),
            ],
            base: digest(g),
        },
        1 => ContractRecord::ClauseChange {
            contract,
            version,
            clause: g.u32(),
            diff: digest(g),
            proposer: *g.pick(&[Side::Grantee, Side::Operator]),
            status: *g.pick(&[
                ChangeStatus::Proposed,
                ChangeStatus::Accepted,
                ChangeStatus::Rejected,
            ]),
            base: g.option(digest),
        },
        2 => ContractRecord::Sent {
            contract,
            version,
            revision0: digest(g),
        },
        3 => ContractRecord::AdvancedApproved {
            contract,
            version,
            party,
            approver: AccountId::from_raw(wide(g)),
            reason: digest(g),
        },
        4 => ContractRecord::SignatureApplied {
            contract,
            version,
            party,
            route: *g.pick(&[Route::WalletQes, Route::QtspRemoteQes, Route::Advanced]),
            revision: g.u32(),
            revision_digest: digest(g),
            signer_certificate: digest(g),
            report: digest(g),
        },
        5 => ContractRecord::Effective {
            contract,
            version,
            final_digest: digest(g),
        },
        6 => ContractRecord::VersionSuperseded {
            contract,
            old: g.u32(),
            new: g.u32(),
        },
        _ => ContractRecord::Terminated {
            contract,
            version,
            reason: digest(g),
            sealed_draft: g.option(digest),
        },
    }
}

/// I-23: records round-trip through their compact JSON text.
#[test]
fn i23_contract_records_round_trip() {
    check("i23_contract_records_round_trip", |g| {
        let r = record(g);
        let text = r.to_json().to_compact();
        let back = ContractRecord::from_json(&parse(text.as_bytes()).unwrap())
            .map_err(|e| format!("{e}"))?;
        prop_assert_eq!(back, r);
        Ok(())
    });
}

/// R-NF-02: an unknown member, a bad digest and an upper-case digest are
/// refused, and the error names no input content.
#[test]
fn r_nf_02_malformed_contract_records_are_refused() {
    let good = ContractRecord::Sent {
        contract: ContractId::from_raw(5),
        version: 1,
        revision0: Digest::from_bytes([0xab; 32]),
    }
    .to_json()
    .to_compact();
    assert!(ContractRecord::from_json(&parse(good.as_bytes()).unwrap()).is_ok());
    for bad in [
        good.replace("\"version\"", "\"secretname\""),
        good.replace("abab", "ABAB"),
        good.replace("abab", "ab"),
        good.replace("\"5\"", "\"05\""),
        good.replace("contract_sent", "contract_sant"),
    ] {
        let e = ContractRecord::from_json(&parse(bad.as_bytes()).unwrap()).unwrap_err();
        assert!(!format!("{e}").contains("secretname"), "{e}");
    }
}

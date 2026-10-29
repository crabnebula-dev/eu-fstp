//! Guardian consent and the over-18 attestation in the vault core (I-18,
//! R-ID-04, design sections 6.4 and 6.6, `overview.md` NOTE 7,
//! state-machine NOTE 14).
//!
//! - `HasGuardianConsent` counts an effective consent whose guardian has
//!   an effective verification (`fstp_vault_core::eval::guardian_consent`,
//!   design section 14.4).
//! - `IsVerifiedAdultAtDeadline` answers yes only for an effective
//!   attestation of a verified account that shows it 18 or older at the
//!   deadline. It answers no in every other case.
//!
//! Reading (W1c): `HasGuardianConsent` names no account, so it is pending
//! while a consent write for its proposal is provisional. A provisional
//! guardian verification does not make it pending; it is answered over the
//! effective facts, where the guardian is not yet verified.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::VecDeque;

use common::{Fail, RQuery, Vault, fact, provisional_of, refusal};
use fstp_prop::{Gen, prop_assert_eq};
use fstp_vault_core::FactWrite;
use fstp_vault_proto::VaultRefusal;

const LEAD: u128 = 103;
const G: u128 = 105;
const H: u128 = 107;
const PERSON_LEAD: u128 = 1_003;
const PERSON_G: u128 = 1_005;
const PR: u128 = 1;
const OTHER: u128 = 2;
const DEADLINE: i64 = 4_000_000_000_000;

fn consent_q(proposal: u128) -> RQuery {
    RQuery::HasGuardianConsent { proposal }
}

fn adult_q(deadline: i64) -> RQuery {
    RQuery::IsVerifiedAdultAtDeadline {
        account: LEAD,
        deadline,
    }
}

/// I-18: a consent by a guardian with no verification does not count.
#[test]
fn i18_consent_of_an_unverified_guardian_does_not_count() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::consent(PR, G))?;
    assert!(!v.holds(consent_q(PR))?);
    v.commit(fact::verification(G, PERSON_G))?;
    assert!(v.holds(consent_q(PR))?);
    assert!(!v.holds(consent_q(OTHER))?, "a consent is for one proposal");
    Ok(())
}

/// I-18: a consent counts only once the guardian's verification is
/// effective. While the verification is provisional, the query is
/// answered over the effective facts, and the answer is no.
#[test]
fn i18_consent_waits_for_the_guardian_verification_to_be_effective() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::consent(PR, G))?;
    let events = v.write(fact::verification(G, PERSON_G))?;
    let epoch = provisional_of(&events).unwrap();
    assert!(!v.holds(consent_q(PR))?);
    v.ack(epoch, epoch)?;
    assert!(v.holds(consent_q(PR))?);
    Ok(())
}

/// I-18, NOTE 4: a provisional consent is pending, never counted, until
/// the cell acknowledges its reaction.
#[test]
fn i18_provisional_consent_is_pending_not_counted() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::verification(G, PERSON_G))?;
    let events = v.write(fact::consent(PR, G))?;
    let epoch = provisional_of(&events).unwrap();
    assert_eq!(
        refusal(v.ask(&[consent_q(PR)]))?,
        VaultRefusal::Pending { epoch }
    );
    assert!(!v.holds(consent_q(OTHER))?, "another proposal is answered");
    v.ack(epoch, epoch)?;
    assert!(v.holds(consent_q(PR))?);
    Ok(())
}

/// I-18: a withdrawn consent no longer counts, and a consent replaced by
/// one from an unverified account no longer counts either.
#[test]
fn i18_withdrawn_or_replaced_consent_no_longer_counts() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit_all([fact::verification(G, PERSON_G), fact::consent(PR, G)])?;
    assert!(v.holds(consent_q(PR))?);
    v.commit(fact::consent_withdrawn(PR))?;
    assert!(!v.holds(consent_q(PR))?);
    v.commit(fact::consent(PR, G))?;
    assert!(v.holds(consent_q(PR))?);
    v.commit(fact::consent(PR, H))?;
    assert!(!v.holds(consent_q(PR))?, "H is not verified");
    Ok(())
}

/// I-18, NOTE 4: the reaction to a provisional consent sees it.
#[test]
fn i18_reaction_sees_the_provisional_consent() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::verification(G, PERSON_G))?;
    let events = v.write(fact::consent(PR, G))?;
    let epoch = provisional_of(&events).unwrap();
    let a = v.react(epoch, &[consent_q(PR)])?;
    assert!(a[0].holds && a[0].epoch == epoch, "{a:?}");
    Ok(())
}

/// NOTE 7, R-ID-04: the attestation counts only for a verified account.
#[test]
fn i18_adult_attestation_needs_an_effective_verification() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::adult(LEAD, DEADLINE - 1))?;
    assert!(!v.holds(adult_q(DEADLINE))?);
    v.commit(fact::verification(LEAD, PERSON_LEAD))?;
    assert!(v.holds(adult_q(DEADLINE))?);
    Ok(())
}

/// NOTE 7: the attestation shows the lead 18 or older at the deadline
/// when its instant is at or before the deadline, to the microsecond.
#[test]
fn i18_adult_attestation_boundary_is_the_deadline() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit_all([
        fact::verification(LEAD, PERSON_LEAD),
        fact::adult(LEAD, DEADLINE),
    ])?;
    assert!(v.holds(adult_q(DEADLINE))?);
    assert!(v.holds(adult_q(DEADLINE + 1))?);
    assert!(!v.holds(adult_q(DEADLINE - 1))?);
    assert!(!v.holds(RQuery::IsVerifiedAdultAtDeadline {
        account: G,
        deadline: DEADLINE,
    })?);
    Ok(())
}

/// NOTE 7: a withdrawn attestation no longer counts.
#[test]
fn i18_withdrawn_attestation_no_longer_counts() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit_all([fact::verification(LEAD, PERSON_LEAD), fact::adult(LEAD, 0)])?;
    assert!(v.holds(adult_q(DEADLINE))?);
    v.commit(fact::attestation_withdrawn(LEAD))?;
    assert!(!v.holds(adult_q(DEADLINE))?);
    Ok(())
}

/// NOTE 7, NOTE 4: "The attestation becomes effective under the commit
/// protocol." A provisional attestation is pending, not counted.
#[test]
fn i18_provisional_attestation_is_pending() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::verification(LEAD, PERSON_LEAD))?;
    let events = v.write(fact::adult(LEAD, 0))?;
    let epoch = provisional_of(&events).unwrap();
    assert_eq!(
        refusal(v.ask(&[adult_q(DEADLINE)]))?,
        VaultRefusal::Pending { epoch }
    );
    v.ack(epoch, epoch)?;
    assert!(v.holds(adult_q(DEADLINE))?);
    Ok(())
}

// ---------------------------------------------------------------------------
// The consent rule against a model.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CWrite {
    VerifyG,
    Consent(u128),
    Withdraw,
}

impl CWrite {
    fn fact(self) -> FactWrite {
        match self {
            CWrite::VerifyG => fact::verification(G, PERSON_G),
            CWrite::Consent(guardian) => fact::consent(PR, guardian),
            CWrite::Withdraw => fact::consent_withdrawn(PR),
        }
    }

    fn is_consent_write(self) -> bool {
        !matches!(self, CWrite::VerifyG)
    }
}

#[derive(Debug, Default)]
struct CFacts {
    g_verified: bool,
    consent: Option<u128>,
}

impl CFacts {
    fn apply(&mut self, w: CWrite) {
        match w {
            CWrite::VerifyG => self.g_verified = true,
            CWrite::Consent(guardian) => self.consent = Some(guardian),
            CWrite::Withdraw => self.consent = None,
        }
    }

    fn counts(&self) -> bool {
        self.consent == Some(G) && self.g_verified
    }
}

/// I-18, design section 14.4 (vault-core property). The steps are random
/// guardian verifications, consents by G or by the unverified H,
/// withdrawals and acknowledgements. `HasGuardianConsent` says yes exactly
/// when an effective consent by G exists and G's verification is
/// effective. A provisional consent write is pending.
#[test]
fn i18_consent_counts_only_after_guardian_verification_is_effective() {
    fstp_prop::check(
        "i18_consent_counts_only_after_guardian_verification_is_effective",
        |g: &mut Gen| {
            let mut v = Vault::new();
            let stub = |f: Fail| format!("{f:?}");
            let mut effective = CFacts::default();
            let mut latest = CFacts::default();
            let mut provisional: Option<(u64, CWrite)> = None;
            let mut queue: VecDeque<CWrite> = VecDeque::new();
            let mut history = Vec::new();
            for _ in 0..g.usize_in(1..=16) {
                if g.bool() {
                    let w = match g.u8_in(0..=3) {
                        0 => CWrite::VerifyG,
                        1 => CWrite::Consent(G),
                        2 => CWrite::Consent(H),
                        _ if latest.consent.is_some() => CWrite::Withdraw,
                        _ => CWrite::Consent(G),
                    };
                    history.push(format!("write {w:?}"));
                    latest.apply(w);
                    let events = v.write(w.fact()).map_err(stub)?;
                    if provisional.is_none() {
                        let e = provisional_of(&events)
                            .ok_or_else(|| format!("no epoch for {w:?}: {events:?}"))?;
                        provisional = Some((e, w));
                    } else {
                        queue.push_back(w);
                    }
                } else if let Some((e, w)) = provisional {
                    history.push(format!("ack {e}"));
                    let events = v.ack(e, e).map_err(stub)?;
                    effective.apply(w);
                    provisional = match queue.pop_front() {
                        Some(next) => {
                            let ne = provisional_of(&events)
                                .ok_or_else(|| format!("no next epoch after {e}: {events:?}"))?;
                            Some((ne, next))
                        }
                        None => None,
                    };
                }
                let got = v.ask(&[consent_q(PR)]);
                match provisional {
                    Some((e, w)) if w.is_consent_write() => {
                        prop_assert_eq!(
                            refusal(got).map_err(stub)?,
                            VaultRefusal::Pending { epoch: e },
                            "after {history:?}"
                        );
                    }
                    _ => {
                        let a = got.map_err(stub)?;
                        prop_assert_eq!(a[0].holds, effective.counts(), "after {history:?}");
                    }
                }
            }
            Ok(())
        },
    );
}

/// NOTE 7, ADR-009 "Write kinds": a withdrawal with no attestation to end
/// is admitted by no ticket, as for a consent or an affiliation. Once an
/// attestation is held, only its own account's attestation ticket ends it.
#[test]
fn note7_attestation_withdrawal_with_nothing_to_end_is_admitted_by_no_ticket() -> Result<(), Fail> {
    let mut v = Vault::new();
    assert_eq!(v.binding(&fact::attestation_withdrawn(LEAD)), None);
    v.write(fact::adult(LEAD, DEADLINE))?;
    let b = v
        .binding(&fact::attestation_withdrawn(LEAD))
        .ok_or_else(|| Fail::Unexpected("no binding for a held attestation".to_owned()))?;
    assert_eq!(b.kind, fstp_vault_proto::WriteKind::AdultAttestation);
    assert_eq!(b.writer, fstp_vault_proto::WireAccount(LEAD));
    assert_eq!(v.binding(&fact::attestation_withdrawn(G)), None);
    Ok(())
}

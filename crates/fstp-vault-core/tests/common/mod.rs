//! Shared helpers of the `fstp-vault-core` test binaries.
//!
//! - [`fact`]: the fact writes of W1c's proposal in
//!   `fstp_celltest::reference::vault::wire`, with the same kind codes and
//!   canonical bodies.
//! - [`Vault`]: one adapter over the vault core API. Every test calls the
//!   core through it, so when the API changes only this file changes.
//!   Each call that the W0 stub lacks returns [`Fail::Stub`] with a seam
//!   message that names the missing API, so the tests that need it are
//!   red for that reason and for no other.
//! - Tickets of the vault origin, signed through `fstp_crypto::sig`.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "a shared test module: each test binary uses part of it"
)]

#[path = "../../../fstp-vault-proto/tests/common/wire.rs"]
pub mod wire;

use std::collections::BTreeSet;
use std::fmt;

use fstp_vault_core::{CoreError, FactWrite, ReleaseClaims, VaultEvent, VaultState};
use fstp_vault_proto::{VaultRefusal, WireAnswer, WireQuery};

pub use wire::RQuery;

/// The fact writes of the W1c proposal.
pub mod fact {
    use std::collections::BTreeSet;

    use fstp_vault_core::FactWrite;

    use super::wire::{id, id_set};

    /// `CountryStated`.
    pub const COUNTRY_STATED: u16 = 1;
    /// `AffiliationDeclared`, with no class.
    pub const AFFILIATION_DECLARED: u16 = 2;
    /// `AdultAttestation`.
    pub const ADULT_ATTESTATION: u16 = 3;
    /// `GuardianConsent`.
    pub const GUARDIAN_CONSENT: u16 = 4;
    /// `DocumentUpload`. W1c gives it no body yet.
    pub const DOCUMENT_UPLOAD: u16 = 5;
    /// `VerificationRecorded`.
    pub const VERIFICATION_RECORDED: u16 = 6;
    /// `ProximityListDeclared`.
    pub const PROXIMITY_LIST_DECLARED: u16 = 7;
    /// `ReviewerDeclaration`.
    pub const REVIEWER_DECLARATION: u16 = 8;
    /// `PartnerStaffDeclared`: an affiliation with a P-13 class.
    pub const PARTNER_STAFF_DECLARED: u16 = 9;
    /// `RecordRelationship` (I-54).
    pub const RELATIONSHIP: u16 = 10;
    /// A consent withdrawal.
    pub const CONSENT_WITHDRAWN: u16 = 11;
    /// An attestation withdrawal.
    pub const ATTESTATION_WITHDRAWN: u16 = 12;
    /// An ended affiliation.
    pub const AFFILIATION_ENDED: u16 = 13;

    fn fw(kind: u16, body: String) -> FactWrite {
        FactWrite {
            kind,
            body: body.into_bytes(),
        }
    }

    /// The synthetic verifier of [`verification`]: an id no test account
    /// takes, so no record is a self-verification.
    pub const SYNTHETIC_VERIFIER: u128 = u128::MAX;

    /// The R-ID-02 members of a synthetic verification record, in key
    /// order around the `account` and `identity` members.
    pub fn verification_body(account: u128, person: u128, verifier: u128) -> String {
        format!(
            "{{\"account\":{},\"at\":0,\"checks\":[\"document_authentic\",\"photo_match\"],\"document_type\":\"passport\",\"identity\":{},\"method\":\"manual\",\"verifier\":{}}}",
            id(account),
            id(person),
            id(verifier)
        )
    }

    /// A verification of `account` that shows the identity `person`, with
    /// a synthetic R-ID-02 record.
    ///
    /// Reading: the core takes the vault's identity id, which `fstp-vault`
    /// resolves from the match key before the write. W1c named it
    /// `person`. The body is now the R-ID-02 record (design section 6.7).
    pub fn verification(account: u128, person: u128) -> FactWrite {
        fw(
            VERIFICATION_RECORDED,
            verification_body(account, person, SYNTHETIC_VERIFIER),
        )
    }

    /// An over-18 attestation of `account`, adult from `adult_from`.
    pub fn adult(account: u128, adult_from: i64) -> FactWrite {
        fw(
            ADULT_ATTESTATION,
            format!(
                "{{\"account\":{},\"adult_from\":{adult_from}}}",
                id(account)
            ),
        )
    }

    /// The withdrawal of `account`'s attestation.
    pub fn attestation_withdrawn(account: u128) -> FactWrite {
        fw(
            ATTESTATION_WITHDRAWN,
            format!("{{\"account\":{}}}", id(account)),
        )
    }

    /// `guardian`'s consent for `proposal`.
    pub fn consent(proposal: u128, guardian: u128) -> FactWrite {
        fw(
            GUARDIAN_CONSENT,
            format!(
                "{{\"guardian\":{},\"proposal\":{}}}",
                id(guardian),
                id(proposal)
            ),
        )
    }

    /// The withdrawal of `proposal`'s consent.
    pub fn consent_withdrawn(proposal: u128) -> FactWrite {
        fw(
            CONSENT_WITHDRAWN,
            format!("{{\"proposal\":{}}}", id(proposal)),
        )
    }

    /// `account`'s affiliation with `org`, in the P-13 class `class` if
    /// any. A classed affiliation is a partner staff declaration.
    pub fn affiliation(account: u128, org: u128, class: Option<u128>) -> FactWrite {
        let class_text = class.map_or_else(|| "null".to_owned(), id);
        let kind = if class.is_some() {
            PARTNER_STAFF_DECLARED
        } else {
            AFFILIATION_DECLARED
        };
        fw(
            kind,
            format!(
                "{{\"account\":{},\"class\":{class_text},\"org\":{}}}",
                id(account),
                id(org)
            ),
        )
    }

    /// The end of `account`'s affiliation with `org`.
    pub fn affiliation_ended(account: u128, org: u128) -> FactWrite {
        fw(
            AFFILIATION_ENDED,
            format!("{{\"account\":{},\"org\":{}}}", id(account), id(org)),
        )
    }

    /// The P-38 list `list` with the organisations `orgs`.
    pub fn proximity_list(list: u128, orgs: &BTreeSet<u128>) -> FactWrite {
        fw(
            PROXIMITY_LIST_DECLARED,
            format!("{{\"list\":{},\"orgs\":{}}}", id(list), id_set(orgs)),
        )
    }

    /// `reviewer`'s declaration of an employer and relatives.
    pub fn reviewer(
        reviewer: u128,
        employer: Option<u128>,
        relatives: &BTreeSet<u128>,
    ) -> FactWrite {
        let employer_text = employer.map_or_else(|| "null".to_owned(), id);
        fw(
            REVIEWER_DECLARATION,
            format!(
                "{{\"employer\":{employer_text},\"relatives\":{},\"reviewer\":{}}}",
                id_set(relatives),
                id(reviewer)
            ),
        )
    }

    /// An I-54 relationship between `a` and `b`.
    pub fn relationship(a: u128, b: u128) -> FactWrite {
        fw(RELATIONSHIP, format!("{{\"a\":{},\"b\":{}}}", id(a), id(b)))
    }

    /// The P-17 country `country` stated by `account` in `programme`.
    pub fn country(account: u128, programme: u128, country: u16) -> FactWrite {
        fw(
            COUNTRY_STATED,
            format!(
                "{{\"account\":{},\"country\":{country},\"programme\":{}}}",
                id(account),
                id(programme)
            ),
        )
    }
}

/// Why an adapter call did not give the outcome a test wanted.
#[derive(Clone, PartialEq, Eq)]
pub enum Fail {
    /// The core refused.
    Refused(VaultRefusal),
    /// The W0 stub or a missing API. Red for the right reason.
    Stub(String),
    /// The core answered, but not as the test expected.
    Unexpected(String),
}

impl fmt::Debug for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fail::Refused(r) => write!(f, "refused: {r:?}"),
            Fail::Stub(s) => write!(f, "{s} (NotImplemented)"),
            Fail::Unexpected(s) => write!(f, "unexpected: {s}"),
        }
    }
}

fn core(e: CoreError) -> Fail {
    match e {
        CoreError::Refused(r) => Fail::Refused(r),
        CoreError::NotImplemented(op) => Fail::Stub(format!("{op} is NotImplemented")),
    }
}

/// The refusal of `r`. A stub outcome passes through as the error, and
/// an answer is [`Fail::Unexpected`].
pub fn refusal<T: fmt::Debug>(r: Result<T, Fail>) -> Result<VaultRefusal, Fail> {
    match r {
        Err(Fail::Refused(v)) => Ok(v),
        Err(other) => Err(other),
        Ok(v) => Err(Fail::Unexpected(format!(
            "answered {v:?}, a refusal was due"
        ))),
    }
}

/// The seam of a reaction ask: `fstp_vault_core::ask` takes no
/// `reaction_for` (W1c `REACTION_ASK_SEAM`, design section 6.3).
pub const REACTION_SEAM: &str = "fstp_vault_core::ask takes no reaction_for, so no reaction ask sees the provisional fact (design section 6.3, NOTE 4, lane W2d)";

/// The seam of the P-17 condition (W1c `P17_SEAM`).
pub const P17_SEAM: &str =
    "fstp_vault_core holds no P-17 condition per programme (NOTE 6, lane W2d)";

/// The seam of provisioning and negotiation facts (W1c `PROVISION_SEAM`).
pub const PROVISION_SEAM: &str = "fstp_vault_core has no API to pin the cell id and ticket keys, take NegotiationOpened and NegotiationClosed, or name the route of a release (design sections 6.2 and 6.5, lane W2d)";

/// The instant of every write in these tests.
pub const NOW: i64 = 1_000_000;

/// One cell's vault core, behind the adapter.
#[derive(Clone, Debug, Default)]
pub struct Vault {
    s: VaultState,
    /// The ledger sequence of the last negotiation fact pushed, so each
    /// push is newer than the one before.
    seq: u64,
}

impl Vault {
    /// An empty vault.
    pub fn new() -> Vault {
        Vault::default()
    }

    /// The effective epoch.
    pub fn effective(&self) -> u64 {
        self.s.effective()
    }

    /// Takes one fact write (NOTE 4 step 1).
    pub fn write(&mut self, w: FactWrite) -> Result<Vec<VaultEvent>, Fail> {
        fstp_vault_core::write(&mut self.s, w, NOW).map_err(core)
    }

    /// Records the cell's acknowledgement of `epoch` with its reaction at
    /// `seq` (NOTE 4 step 5).
    ///
    /// Gap: the stub `ack` takes no chain link. Design section 6.2 sends
    /// `Ack { epoch, ledger_seq, link }`, and the vault keeps the link in
    /// `vault.epoch.ack_link`. The link is dropped here until `ack` takes
    /// it.
    pub fn ack(&mut self, epoch: u64, seq: u64) -> Result<Vec<VaultEvent>, Fail> {
        fstp_vault_core::ack(&mut self.s, epoch, seq).map_err(core)
    }

    /// Asks raw wire queries outside a reaction.
    pub fn ask_raw(&self, qs: &[WireQuery]) -> Result<Vec<WireAnswer>, Fail> {
        fstp_vault_core::ask(&self.s, qs).map_err(core)
    }

    /// Asks queries outside a reaction.
    pub fn ask(&self, qs: &[RQuery]) -> Result<Vec<WireAnswer>, Fail> {
        let wq: Vec<WireQuery> = qs.iter().map(RQuery::wire).collect();
        self.ask_raw(&wq)
    }

    /// The bit of one query outside a reaction.
    pub fn holds(&self, q: RQuery) -> Result<bool, Fail> {
        let a = self.ask(std::slice::from_ref(&q))?;
        match a.as_slice() {
            [one] if one.accounts.is_none() => Ok(one.holds),
            other => Err(Fail::Unexpected(format!("{q:?} answered {other:?}"))),
        }
    }

    /// Asks queries in the reaction to the provisional `epoch`.
    pub fn react(&self, epoch: u64, qs: &[RQuery]) -> Result<Vec<WireAnswer>, Fail> {
        let wq: Vec<WireQuery> = qs.iter().map(RQuery::wire).collect();
        fstp_vault_core::ask_request(
            &self.s,
            &fstp_vault_core::Ask {
                reaction_for: Some(epoch),
                queries: &wq,
            },
        )
        .map_err(core)
    }

    /// Writes `w`, which must open a provisional epoch, and acknowledges
    /// that epoch with sequence `epoch`. Returns the epoch.
    pub fn commit(&mut self, w: FactWrite) -> Result<u64, Fail> {
        let events = self.write(w)?;
        let epoch = provisional_of(&events)
            .ok_or_else(|| Fail::Unexpected(format!("no provisional epoch in {events:?}")))?;
        let acked = self.ack(epoch, epoch)?;
        if !acked.contains(&VaultEvent::Effective { epoch }) {
            return Err(Fail::Unexpected(format!(
                "ack of {epoch} reported {acked:?}"
            )));
        }
        Ok(epoch)
    }

    /// Commits every write in order.
    pub fn commit_all(&mut self, ws: impl IntoIterator<Item = FactWrite>) -> Result<(), Fail> {
        for w in ws {
            self.commit(w)?;
        }
        Ok(())
    }

    /// Sets the P-17 countries of `programme` (NOTE 6, P-17).
    pub fn set_p17(&mut self, programme: u128, countries: &BTreeSet<u16>) -> Result<(), Fail> {
        fstp_vault_core::set_p17(
            &mut self.s,
            fstp_vault_proto::WireProgramme(programme),
            countries,
        )
        .map_err(core)
    }

    /// Pins the vault's cell id and the cell's current and next ticket
    /// public keys (design section 6.5, provisioning).
    pub fn provision(&mut self, cell: [u8; 16], pinned: &[[u8; 32]]) -> Result<(), Fail> {
        fstp_vault_core::provision(&mut self.s, cell, pinned).map_err(core)
    }

    /// Takes the negotiation fact the cell pushes when `proposal` enters
    /// NEGOTIATION (`NegotiationOpened`).
    pub fn negotiation_opened(
        &mut self,
        proposal: u128,
        accounts: &BTreeSet<u128>,
    ) -> Result<(), Fail> {
        let accounts: BTreeSet<fstp_vault_proto::WireAccount> = accounts
            .iter()
            .map(|a| fstp_vault_proto::WireAccount(*a))
            .collect();
        self.seq += 1;
        fstp_vault_core::negotiation_opened(
            &mut self.s,
            fstp_vault_proto::WireProposal(proposal),
            &accounts,
            self.seq,
        )
        .map_err(core)
        .map(|_| ())
    }

    /// Removes the negotiation fact of `proposal` (`NegotiationClosed`).
    pub fn negotiation_closed(&mut self, proposal: u128) -> Result<(), Fail> {
        self.seq += 1;
        fstp_vault_core::negotiation_closed(
            &mut self.s,
            fstp_vault_proto::WireProposal(proposal),
            self.seq,
        );
        Ok(())
    }

    /// Whether the release ticket `ticket`, presented on `POST /r` at
    /// `now`, may be honoured (I-17).
    pub fn release(&self, ticket: &[u8], now: i64) -> Result<(), Fail> {
        let claims = ReleaseClaims {
            ticket: ticket.to_vec(),
        };
        fstp_vault_core::release_allowed(&self.s, &claims, now).map_err(core)
    }

    /// The typed outcome of `fstp_vault_core::check_ticket` for `ticket`
    /// on the release route at `now`.
    pub fn check_release(
        &self,
        ticket: &[u8],
        now: i64,
    ) -> Result<fstp_vault_proto::TicketClaims, fstp_vault_core::TicketRefusal> {
        fstp_vault_core::check_ticket(&self.s, ticket, fstp_vault_core::Route::Release, now)
    }

    /// Asks queries outside a reaction, with at most `max_accounts` ids
    /// over all answers.
    pub fn ask_bounded(&self, qs: &[RQuery], max_accounts: usize) -> Result<Vec<WireAnswer>, Fail> {
        let wq: Vec<WireQuery> = qs.iter().map(RQuery::wire).collect();
        fstp_vault_core::ask_bounded(
            &self.s,
            &fstp_vault_core::Ask {
                reaction_for: None,
                queries: &wq,
            },
            max_accounts,
        )
        .map_err(core)
    }

    /// The binding a write ticket needs for the fact `w` over the newest
    /// facts, or none when no ticket admits it.
    pub fn binding(&self, w: &FactWrite) -> Option<fstp_vault_core::OriginBinding> {
        let f = fstp_vault_core::decode_fact(w.kind, &w.body).ok()?;
        fstp_vault_core::origin_binding(self.s.latest(), &f)
    }
}

/// The epoch of the first `Provisional` event, if any.
pub fn provisional_of(events: &[VaultEvent]) -> Option<u64> {
    events.iter().find_map(|e| match e {
        VaultEvent::Provisional { epoch } => Some(*epoch),
        VaultEvent::Effective { .. } => None,
    })
}

/// A set of ids.
pub fn set<const N: usize>(ids: [u128; N]) -> BTreeSet<u128> {
    ids.into_iter().collect()
}

/// A ticket signer: the Ed25519 key of seed `seed`.
pub struct Signer(fstp_crypto::sig::Ed25519SigningKey);

impl Signer {
    /// The key of `seed`.
    pub fn new(seed: u8) -> Signer {
        Signer(fstp_crypto::sig::Ed25519SigningKey::from_seed(&[seed; 32]).unwrap())
    }

    /// The public key.
    pub fn public(&self) -> [u8; 32] {
        self.0.public_key()
    }

    /// The signed ticket.
    pub fn sign(&self, t: &wire::RTicket) -> Vec<u8> {
        let sig = self.0.sign(&t.body()).unwrap();
        t.framed(&sig)
    }
}

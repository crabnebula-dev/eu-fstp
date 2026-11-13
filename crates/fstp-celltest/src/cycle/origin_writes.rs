//! The vault origin write steps `vault-origin:write:<canary>` and
//! `vault-origin:write:<write kind>:<text>` (I-17, NOTE 6, design sections
//! 6.5 and 14.4, lane m3/cycle-steps).
//!
//! A write goes as a browser sends it: a write ticket for the writer, then
//! `POST https://id.<cell host>/w` through the world's edge, with the
//! canonical frame of `fstp_vault::codec::encode_origin_write`. The vault
//! checks the ticket, takes the fact into the NOTE 4 protocol and answers
//! 204. The fact becomes effective after the cell's reaction to its
//! epoch, which the cell runs before its next command that asks the vault.
//!
//! Interim readings, pending Daniel:
//!
//! - The ticket is signed by the world with the cell's `Ticket` key
//!   (`crate::world::CellHandle::sign_ticket`). The cell's ticket routes
//!   answer 501 before the engine runs them (`super::VERIFY_IDENTITY_SEAM`),
//!   so no `TicketIssued` record logs the issue yet. It lives one minute.
//! - The writer is the applicant who signed up last and has not drafted,
//!   else the lead of the proposal the cycle acts on, else the lead of the
//!   newest proposal in the cell's ledger. The country's programme is the
//!   programme of that proposal, or of the newest one when the writer has
//!   none.
//! - A country is a code in the vault's write grammar
//!   (`fstp_vault_core::fact::Fact::CountryStated`). A decimal text from 1
//!   to 999 is that code. Any other text, such as a canary, gives a code
//!   from 1 to 999 drawn from its SHA-256 digest. The text itself has no
//!   member in the write, so the vault never holds it.
//! - The M3 vault origin takes no write of a name, an email address, a
//!   phone number or a document: `fact_kinds_of` gives document uploads
//!   and verifications no fact, and names arrive with the M4 verification
//!   methods. A canary of those kinds is therefore a value of the next
//!   applicant (`super::Person`), as `<kind>:<text>` is. That applicant
//!   signs up before the next other step: the email is its login address,
//!   and the other values form the attribute tuple of its seeded
//!   verification (design section 6.9).
//! - Another write kind refuses with [`ORIGIN_KIND_SEAM`].

use fstp_domain::id::{AccountId, ProgrammeId, ProposalId};
use fstp_vault_core::fact::Fact;
use fstp_vault_proto::{TicketClaims, TicketKind, WireAccount, WireProgramme, WriteKind};

use super::{Cycle, UNKNOWN_STEP_SEAM};
use crate::NotImplemented;
use crate::canary::{Canary, CanaryKind};
use crate::world::HttpRequest;

/// The prefix of a vault origin write step.
pub const PREFIX: &str = "vault-origin:write:";

/// The step names a write kind the cycle cannot write on the vault origin
/// yet.
pub const ORIGIN_KIND_SEAM: &str = "fstp_celltest::cycle vault-origin:write: the step writes only country_stated on the vault origin yet; a name, email, phone or document canary is a value of the next applicant, and the other ADR-009 write kinds need a writer rule per kind in the cell (fstp_cell_core decide_release refuses every write ticket kind but guardian_consent)";

/// The step found no writer: no applicant signed up and the cell holds
/// no proposal.
pub const NO_WRITER: &str = "fstp_celltest::cycle vault-origin:write: the step needs an applicant, from signup or a proposal in the cell, before it";

/// The vault origin refused the write. Not a seam: the reply is on
/// standard error.
pub const ORIGIN_REFUSED: &str = "fstp_celltest::cycle vault-origin:write: the vault origin refused the write (the reply is on standard error)";

/// The lifetime of a world-signed write ticket, in microseconds.
const TICKET_LIFE_US: i64 = 60_000_000;

/// The country code of `text` (module documentation).
pub fn country_code(text: &str) -> u16 {
    if let Ok(n) = text.parse::<u16>()
        && (1..=999).contains(&n)
        && !text.starts_with('0')
    {
        return n;
    }
    let d = fstp_crypto::sha256(text.as_bytes());
    let n = u16::from_be_bytes([d[0], d[1]]) % 999;
    n.saturating_add(1)
}

impl Cycle<'_> {
    /// Takes a vault origin write step whose canary is a value of the next
    /// applicant, and says whether it was one (module documentation). It
    /// runs before the cycle flushes a waiting signup, so the values of
    /// consecutive steps go to one applicant.
    pub(super) fn take_origin_value(&mut self, step: &str) -> bool {
        let Some(c) = step.strip_prefix(PREFIX).and_then(Canary::parse) else {
            return false;
        };
        if c.kind == CanaryKind::Country {
            return false;
        }
        let taken = self
            .values
            .take_step(&format!("{}:{}", c.kind.label(), c.text()));
        if taken {
            self.values.signup_due = true;
        }
        taken
    }

    /// A `vault-origin:write:...` step that is no value step.
    pub(super) fn vault_origin_write(&mut self, step: &str) -> Result<(), NotImplemented> {
        let rest = step
            .strip_prefix(PREFIX)
            .ok_or(NotImplemented::new(UNKNOWN_STEP_SEAM))?;
        if let Some(c) = Canary::parse(rest) {
            return match c.kind {
                CanaryKind::Country => self.country_write(step, rest),
                _ => Err(NotImplemented::new(ORIGIN_KIND_SEAM)),
            };
        }
        let (label, text) = rest
            .split_once(':')
            .ok_or(NotImplemented::new(UNKNOWN_STEP_SEAM))?;
        match WriteKind::ALL.iter().find(|w| w.label() == label) {
            Some(WriteKind::CountryStated) if !text.is_empty() => self.country_write(step, text),
            Some(_) => Err(NotImplemented::new(ORIGIN_KIND_SEAM)),
            None => Err(NotImplemented::new(UNKNOWN_STEP_SEAM)),
        }
    }

    /// The newest proposal in the cell's ledger and its lead.
    fn newest_proposal(
        &self,
        step: &str,
    ) -> Result<Option<(ProposalId, AccountId)>, NotImplemented> {
        let ledger = self
            .client
            .cell()
            .ledger()
            .map_err(|_| Self::refused(step, "the ledger read", None))?;
        Ok(ledger.iter().rev().find_map(|e| match &e.record {
            fstp_cell_core::CellRecord::Engine(fstp_engine::Record::Core(
                fstp_domain::Record::ProposalCreated { proposal, lead, .. },
            )) => Some((*proposal, *lead)),
            _ => None,
        }))
    }

    /// The writer of a vault origin write and the programme it writes for
    /// (module documentation).
    fn origin_writer(&self, step: &str) -> Result<(AccountId, ProgrammeId), NotImplemented> {
        let state = self.state()?;
        let core = &state.engine().core;
        let programme_of = |p: ProposalId| {
            let (call, _) = state.proposal(p)?;
            fstp_domain::programme::call(core, call).map(|c| c.programme())
        };
        let newest = self.newest_proposal(step)?;
        let (writer, proposal) = if let Some((who, _)) = &self.pending {
            (self.account(step, *who)?, newest.map(|(p, _)| p))
        } else if let Some(run) = &self.current {
            (self.account(step, run.lead)?, Some(run.proposal))
        } else if let Some((p, lead)) = newest {
            (lead, Some(p))
        } else {
            return Err(NotImplemented::new(NO_WRITER));
        };
        let programme = proposal
            .and_then(programme_of)
            .ok_or(NotImplemented::new(NO_WRITER))?;
        Ok((writer, programme))
    }

    /// A `country_stated` write of `text` by the writer.
    fn country_write(&mut self, step: &str, text: &str) -> Result<(), NotImplemented> {
        let (writer, programme) = self.origin_writer(step)?;
        let account = WireAccount(writer.raw());
        let programme = WireProgramme(programme.raw());
        let fact = Fact::CountryStated {
            account,
            programme,
            country: country_code(text),
        };
        let claims = TicketClaims {
            kind: TicketKind::Write(WriteKind::CountryStated),
            cell: self.client.cell().id(),
            account,
            proposal: None,
            scope: fstp_vault_proto::country_scope(programme),
            issued_at: self.now(),
            expires_at: self.now().saturating_add(TICKET_LIFE_US),
            nonce: fstp_crypto::random_array::<16>()
                .map_err(|_| Self::refused(step, "the ticket nonce", None))?,
        };
        self.post_write(step, &claims, &fact)
    }

    /// Posts the write of `fact` under a ticket of `claims` to the vault
    /// origin, as the vault origin's page does.
    fn post_write(
        &self,
        step: &str,
        claims: &TicketClaims,
        fact: &Fact,
    ) -> Result<(), NotImplemented> {
        let cell = self.client.cell();
        let ticket = cell
            .sign_ticket(claims)
            .map_err(|_| Self::refused(step, "the write ticket", None))?;
        let body = fact
            .body_value()
            .and_then(|v| fstp_vault_proto::json::to_canonical(&v))
            .map_err(|_| Self::refused(step, "the write body", None))?;
        let frame = fstp_vault::codec::encode_origin_write(&fstp_vault::codec::OriginWrite {
            ticket,
            body,
        })
        .map_err(|_| Self::refused(step, "the write frame", None))?;
        let host = cell.vault_host();
        let req = HttpRequest::new("POST", "/w")
            .header("host", host.as_str())
            .header("origin", format!("https://{host}"))
            .header("content-type", "application/json")
            .body(frame);
        let reply = cell
            .vault_origin_request(&req)
            .map_err(|_| Self::refused(step, "the vault origin request", None))?;
        if reply.ok() {
            return Ok(());
        }
        eprintln!(
            "fstp_celltest::cycle {step}: the vault origin answered {} {}",
            reply.status,
            String::from_utf8_lossy(&reply.body)
        );
        Err(NotImplemented::new(ORIGIN_REFUSED))
    }
}

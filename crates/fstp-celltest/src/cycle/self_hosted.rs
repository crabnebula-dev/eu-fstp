//! The self-hosted steps of `i38_egress` and `i39_licence` (I-38, I-39,
//! design sections 10 and 14.4, lane m3/licence-update).
//!
//! The release steps drive the cell's licence refresh and update check
//! against the world's CrabNebula stand-in (`crate::crabnebula`):
//!
//! - `restart`: the cell process stops and starts again
//!   (`crate::world::CellHandle::restart`).
//! - `licence-refresh` and `update-check`: the next call of that kind
//!   falls due and the step waits until the cell made it
//!   (`crate::world::CellHandle::release_call`). The stand-in answers in
//!   its current mode.
//! - `licence-refresh:<outcome>`: the same, with the stand-in in the mode
//!   `<outcome>` for that call only: `success`, or a fault label.
//! - `services-down:<fault>` and `services-up`: the stand-in answers in
//!   that mode from now on.
//!
//! The value step `seed:<kind>:<text>` gives `<kind>:<text>` to the next
//! applicant ([`super::Person`]). A value an earlier applicant of the cell
//! already took is not given again, so a later script that seeds the same
//! canaries reuses no login email. The canary already lives in the cell.
//!
//! The steps of the W1g cycle vocabulary map onto the cycle's own steps.
//! Interim readings, pending Daniel:
//!
//! - `submit` is `submit-proposal`, `stage1` is `score` and `stage2` is
//!   `rank` on a proposal in STAGE2 (each reviewer records no questions).
//! - `rank` on a proposal already RANKED is the cut-off round, and
//!   `irc-review` is the IRC validations, after the cut-off if it is still
//!   due. `negotiate` runs what is left of both, and nothing once the
//!   proposal is in NEGOTIATION.
//! - `request-payment`: the timeline starts execution, the lead requests
//!   half the milestone, and the payment port records the passed
//!   submission checks. `release-payment`: the payment port records the
//!   passed acceptance checks, the first reviewer accepts the line, a
//!   finance approver approves and a payment releaser releases, each with
//!   a step-up. The payment port is played in process by the world
//!   (`fstp_cell::process::RunningCell::payment_checks`), as the contract
//!   port is, since no checks runner runs in the cell before M5. The
//!   lead's bank details and their verification are seeded (design
//!   section 6.9), written at the world clock's start, so the P-36 hold
//!   has passed (I-33).
//! - `notify`: the lead asks for a copy of the submission record
//!   (R-SB-04), whose only record is an outbox event.
//! - `export`: the first admin reads the audit anchors, the export-class
//!   read the cell serves before the M9 export exists.
//! - `catalogue-to-granted` is the path from `create-programme` to
//!   `grant`, `payment-commands` is `request-payment` then
//!   `release-payment`, `enqueue-outbox` is `notify` and
//!   `export-entry-point` is `export`.

use fstp_domain::id::{AccountId, BindingId, LineId, RequestId};
use fstp_domain::payment::CheckPhase;
use fstp_domain::roles::Role;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::{money, review};
use fstp_vault_core::fact::{BankCheck, BankMethod, Fact};
use fstp_vault_proto::{WireAccount, WireProposal};

use super::{Cycle, STEP_REFUSED, synthetic_text};
use crate::NotImplemented;
use crate::canary::CanaryKind;
use crate::crabnebula::{Fault, Mode};
use crate::mc::auth_model::http::Cookie;
use crate::reference::auth::RefMethod;
use crate::vault_seed::SeedSource;
use crate::world::{CallKind, WorldError};

/// The prefix of a value step for the next applicant.
pub const SEED_PREFIX: &str = "seed:";

/// The finance approver of the payment steps, outside every model's
/// universe.
pub const FINANCE_APPROVER: AccountId = AccountId::from_raw(8_101);

/// The payment releaser of the payment steps, outside every model's
/// universe.
pub const PAYMENT_RELEASER: AccountId = AccountId::from_raw(8_102);

/// The amount each payment request asks: half the cycle's milestone of
/// 20 000.00 EUR.
const REQUESTED: i64 = 1_000_000;

/// How far `request-payment` moves the cell clock so the timeline ticks:
/// two of its one-second ticks (`fstp_cell::tasks::timeline::TICK`).
const TIMELINE_NUDGE_US: i64 = 2_000_000;

/// How long `request-payment` waits for the timeline's `StartExecution`.
const EXECUTION_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

/// The step named a fault or an outcome outside the stand-in's modes.
pub const UNKNOWN_MODE: &str = "fstp_celltest::cycle services-down and licence-refresh: the step names no mode of the CrabNebula stand-in (success, refused, timed-out, failed-tls, garbage, slow-body, expired-token, bad-signature, clock-skew)";

/// The synthetic IBAN of the seeded bank details, as the vault
/// reference uses it.
const SYNTHETIC_IBAN: &str = "DE89370400440532013000";

/// Whether `step` is a step of this module.
pub fn is_step(step: &str) -> bool {
    matches!(
        step,
        "restart"
            | "licence-refresh"
            | "update-check"
            | "services-up"
            | "submit"
            | "stage1"
            | "stage2"
            | "irc-review"
            | "request-payment"
            | "release-payment"
            | "notify"
            | "export"
            | "catalogue-to-granted"
            | "payment-commands"
            | "enqueue-outbox"
            | "export-entry-point"
    ) || step.starts_with("licence-refresh:")
        || step.starts_with("services-down:")
}

/// A world error as the refusal of `step`.
fn world_refusal(step: &str, e: WorldError) -> NotImplemented {
    match e {
        WorldError::NotImplemented(n) => n,
        other => {
            eprintln!("fstp_celltest::cycle {step}: {other}");
            NotImplemented::new(STEP_REFUSED)
        }
    }
}

impl Cycle<'_> {
    /// Records `seed:<kind>:<text>` as a value of the next applicant, and
    /// says whether `step` was one (module documentation).
    pub(super) fn take_seed(&mut self, step: &str) -> bool {
        let Some(rest) = step.strip_prefix(SEED_PREFIX) else {
            return false;
        };
        let Some((label, text)) = rest.split_once(':') else {
            return false;
        };
        let Some(kind) = CanaryKind::ALL.into_iter().find(|k| k.label() == label) else {
            return false;
        };
        if text.is_empty() {
            return false;
        }
        if self.values.seeded.insert((kind, text.to_owned())) {
            self.values.take_step(rest)
        } else {
            true
        }
    }

    /// Runs one step of this module ([`is_step`]).
    pub(super) fn self_hosted_step(&mut self, step: &str) -> Result<(), NotImplemented> {
        let cell = self.client.cell();
        match step {
            "restart" => cell.restart().map_err(|e| world_refusal(step, e)),
            "licence-refresh" => cell
                .release_call(CallKind::Licence, None)
                .map(|_| ())
                .map_err(|e| world_refusal(step, e)),
            "update-check" => cell
                .release_call(CallKind::Update, None)
                .map(|_| ())
                .map_err(|e| world_refusal(step, e)),
            "services-up" => cell
                .set_crabnebula_mode(Mode::Up)
                .map_err(|e| world_refusal(step, e)),
            s if s.starts_with("licence-refresh:") => {
                let mode = s
                    .strip_prefix("licence-refresh:")
                    .and_then(Mode::parse)
                    .ok_or(NotImplemented::new(UNKNOWN_MODE))?;
                cell.release_call(CallKind::Licence, Some(mode))
                    .map(|_| ())
                    .map_err(|e| world_refusal(step, e))
            }
            s if s.starts_with("services-down:") => {
                let fault = s
                    .strip_prefix("services-down:")
                    .and_then(Fault::parse)
                    .ok_or(NotImplemented::new(UNKNOWN_MODE))?;
                cell.set_crabnebula_mode(Mode::Down(fault))
                    .map_err(|e| world_refusal(step, e))
            }
            "submit" => self.submit_proposal(),
            "stage1" => self.score(),
            "stage2" => self.rank(),
            "irc-review" => self.irc_review_step(),
            "request-payment" => self.request_payment(),
            "release-payment" => self.release_payment(),
            "notify" | "enqueue-outbox" => self.notify(),
            "export" | "export-entry-point" => self.export(),
            "catalogue-to-granted" => {
                for s in [
                    "create-programme",
                    "publish-call",
                    "submit",
                    "stage1",
                    "stage2",
                    "rank",
                    "irc-review",
                    "negotiate",
                    "grant",
                ] {
                    self.step(s)?;
                }
                Ok(())
            }
            "payment-commands" => {
                self.request_payment()?;
                self.release_payment()
            }
            _ => Err(NotImplemented::new(super::UNKNOWN_STEP_SEAM)),
        }
    }

    /// The state of the current proposal.
    fn current_state(&self) -> Result<Option<StateTag>, NotImplemented> {
        let proposal = self.run_of()?.proposal;
        let s = self.state()?;
        Ok(fstp_domain::view::proposal_state(
            &s.engine().core,
            proposal,
        ))
    }

    /// `rank`: on a proposal in STAGE2, each reviewer records no
    /// questions. On a proposal already RANKED, the cut-off round (module
    /// documentation).
    pub(super) fn rank_step(&mut self) -> Result<(), NotImplemented> {
        match self.current_state()? {
            Some(StateTag::Ranked) => self.cut_off(),
            _ => self.rank(),
        }
    }

    /// `irc-review`: the cut-off if it is still due, then the IRC
    /// validations. Nothing once the proposal is in NEGOTIATION.
    fn irc_review_step(&mut self) -> Result<(), NotImplemented> {
        match self.current_state()? {
            Some(StateTag::Ranked) => {
                self.cut_off()?;
                self.irc_validate()
            }
            Some(StateTag::Negotiation) => Ok(()),
            _ => self.irc_validate(),
        }
    }

    /// `negotiate`: what is left of the cut-off and the IRC validations.
    /// Nothing once the proposal is in NEGOTIATION.
    pub(super) fn negotiate_step(&mut self) -> Result<(), NotImplemented> {
        match self.current_state()? {
            Some(StateTag::IrcReview) => self.irc_validate(),
            Some(StateTag::Negotiation) => Ok(()),
            _ => self.negotiate(),
        }
    }

    /// A session of `who`, who holds `role` on P1: enrolled, verified and
    /// granted by the first admin with a step-up on first use, logged in
    /// with its passkey after.
    fn staff_session(
        &mut self,
        step: &str,
        who: AccountId,
        role: Role,
    ) -> Result<Cookie, NotImplemented> {
        if self.client.cell_account(who).is_some() {
            return self
                .client
                .login(who, RefMethod::Passkey)?
                .ok_or_else(|| Self::refused(step, "a passkey login", None));
        }
        let admin = self
            .admin
            .clone()
            .ok_or(NotImplemented::new(super::NOT_LOGGED_IN))?;
        let cookie = self.enrol_and_login(step, who)?;
        self.verify(step, who)?;
        let account = self.account(step, who)?;
        let binding = BindingId::from_raw(self.fresh());
        self.command(
            step,
            "a payment role's GrantRole",
            &admin,
            super::grant(binding, account, role, self.now()),
            true,
        )?;
        Ok(cookie)
    }

    /// The payment request of the current proposal: the latest one this
    /// cycle made, with its line.
    fn payment_of(&self) -> Result<(RequestId, LineId), NotImplemented> {
        let proposal = self.run_of()?.proposal;
        // The ids are drawn so the request names its proposal: request
        // and line ids are the proposal id with a fixed offset.
        let request = RequestId::from_raw(proposal.raw().saturating_add(500_000));
        let line = LineId::from_raw(proposal.raw().saturating_add(600_000));
        Ok((request, line))
    }

    /// `request-payment` (module documentation).
    fn request_payment(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "request-payment";
        let (lead, cookie, proposal, milestone) = {
            let run = self.run_of()?;
            (run.lead, run.cookie.clone(), run.proposal, run.milestone)
        };
        // The timeline starts execution at the earliest milestone start,
        // which lies before the grant (state machine NOTE 11).
        let started = std::time::Instant::now();
        loop {
            match self.current_state()? {
                Some(StateTag::InExecution) => break,
                Some(StateTag::Granted) if started.elapsed() < EXECUTION_WAIT => {
                    self.client.cell().clock().advance(TIMELINE_NUDGE_US);
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                other => {
                    eprintln!("fstp_celltest::cycle {STEP}: the proposal is in {other:?}");
                    return Err(Self::refused(STEP, "the start of execution", None));
                }
            }
        }
        let (request, line) = self.payment_of()?;
        let ask = money::request_payment(lead, request, proposal, &[(line, milestone, REQUESTED)])
            .map_err(|_| Self::refused(STEP, "the payment request", None))?;
        self.by(STEP, "RequestPayment", &cookie, ask.cmd)?;
        self.checks(STEP, request, line, CheckPhase::Submission)
    }

    /// The payment port's passed `phase` checks of `request`, in process.
    fn checks(
        &self,
        step: &str,
        request: RequestId,
        line: LineId,
        phase: CheckPhase,
    ) -> Result<(), NotImplemented> {
        let fstp_domain::Command::RecordChecks {
            results, snapshot, ..
        } = money::record_checks(request, phase, &[line], false).cmd
        else {
            return Err(Self::refused(step, "the checks", None));
        };
        self.client
            .cell()
            .payment_checks(request, phase, results, snapshot)
            .map_err(|e| world_refusal(step, e))
    }

    /// `release-payment` (module documentation).
    fn release_payment(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "release-payment";
        let (lead, proposal) = {
            let run = self.run_of()?;
            (run.lead, run.proposal)
        };
        let (request, line) = self.payment_of()?;
        self.checks(STEP, request, line, CheckPhase::Acceptance)?;
        let reviewer = self.judge(review::R1)?;
        let accept = money::accept_line(review::R1, request, line, REQUESTED, false)
            .map_err(|_| Self::refused(STEP, "the line decision", None))?;
        self.by(STEP, "AcceptLine", &reviewer, accept.cmd)?;
        let approver = self.staff_session(STEP, FINANCE_APPROVER, Role::FinanceApprover)?;
        self.command(
            STEP,
            "ApprovePayment",
            &approver,
            super::core(money::approve_payment(FINANCE_APPROVER, request).cmd),
            true,
        )?;
        let releaser = self.staff_session(STEP, PAYMENT_RELEASER, Role::PaymentReleaser)?;
        self.seed_bank(STEP, lead, proposal)?;
        self.command(
            STEP,
            "ReleasePayment",
            &releaser,
            super::core(money::release_payment(PAYMENT_RELEASER, request).cmd),
            true,
        )
    }

    /// Seeds the lead's bank details of `proposal` and their verification
    /// by the finance approver (design section 6.9, I-33).
    fn seed_bank(
        &self,
        step: &str,
        lead: AccountId,
        proposal: fstp_domain::id::ProposalId,
    ) -> Result<(), NotImplemented> {
        let writer = self.account(step, lead)?;
        let verifier = self.account(step, FINANCE_APPROVER)?;
        let grant = WireProposal(proposal.raw());
        let at = crate::world::WORLD_CLOCK_START;
        for fact in [
            Fact::BankDetails {
                grant,
                account: WireAccount(writer.raw()),
                at,
                holder: "Synthetic Holder".to_owned(),
                iban: SYNTHETIC_IBAN.to_owned(),
            },
            Fact::BankVerified {
                grant,
                version: 1,
                verifier: WireAccount(verifier.raw()),
                at,
                method: BankMethod::BankStatement,
                checks: BankCheck::ALL.into_iter().collect(),
            },
        ] {
            self.client
                .cell()
                .seed_vault_fact(SeedSource::SyntheticVerification, fact)
                .map_err(|e| {
                    eprintln!("fstp_celltest::cycle {step}: the seeded bank fact: {e}");
                    NotImplemented::new(STEP_REFUSED)
                })?;
        }
        Ok(())
    }

    /// `notify` (module documentation).
    fn notify(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "notify";
        let (cookie, proposal) = {
            let run = self.run_of()?;
            (run.cookie.clone(), run.proposal)
        };
        self.by(
            STEP,
            "RequestCopy",
            &cookie,
            fstp_domain::Command::RequestCopy {
                proposal,
                address: synthetic_text(0x0e),
            },
        )
    }

    /// `export` (module documentation).
    fn export(&mut self) -> Result<(), NotImplemented> {
        const STEP: &str = "export";
        if self.admin.is_none() {
            self.login()?;
        }
        let admin = self
            .admin
            .clone()
            .ok_or(NotImplemented::new(super::NOT_LOGGED_IN))?;
        let r = self
            .client
            .call("GET", "/api/v1/audit/anchors", Some(&admin), b"")?;
        if r.ok() {
            Ok(())
        } else {
            Err(Self::refused(STEP, "GET /api/v1/audit/anchors", Some(&r)))
        }
    }
}

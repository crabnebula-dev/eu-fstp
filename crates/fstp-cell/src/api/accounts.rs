//! The accounts port of the production cell: the invitation of a person
//! to a programme role, display handles and login emails (J2, ADR-026
//! record of lane L5, I-25, I-26, I-86).
//!
//! `creator.invite` appends the creator invitation and then hands its link
//! token and address here. The port, in order:
//!
//! 1. refuses at once when the cell has no relay, so nothing is recorded
//!    for a mail that cannot leave;
//! 2. for an address that holds no login email account, issues the M3
//!    enrolment invitation of the same token (`IssueRoleInvitation`, the
//!    system task `Provisioning`) for a new random account, and notes the
//!    address for that enrolment, as the command route notes it;
//! 3. schedules the `ROLE_INVITATION` timeline event and fires it, each
//!    under the system task `Timeline`. The fire entry records the
//!    template version and the one message, whose composed body the store
//!    seals into its `ops.outbox` row in the same append (I-25);
//! 4. delivers that one message through the relay with the dispatcher's
//!    attempt protocol (`crate::api::mail`, I-26).
//!
//! Each step runs under a command id bound to the creator invitation, and
//! each checks the ledger first, so a retry commits nothing twice. The
//! token reaches the composed body only. The ledger holds its digest, and
//! the event names the programme and the creator invitation.

use std::sync::Arc;

use fstp_api_core::port::{Accounts, DisplayHandle, InvitationLink, InviteKind, PortError};
use fstp_cell_core::gate::{self, Action};
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::timeline::{EventStatus, TimelineCommand};
use fstp_cell_core::{CellCommand, SystemTask};
use fstp_domain::id::{AccountId, ProgrammeId};
use fstp_domain::time::Timestamp;
use fstp_mail::{
    Bindings, InvitationToken, LinkTarget, MailConfig, Mailbox, Message, Origin, Slot, Value,
};
use fstp_rt::Runtime;

use super::Inner;
use super::mail::SharedRelay;
use crate::engine::VaultClient;
use crate::routes::Backend;

/// The label of the command id of an enrolment invitation.
const ENROL_LABEL: &[u8] = b"fstp-role-invitation-enrol-v1";

/// The label of the command id of an admin enrolment invitation (ADR-026
/// record of lane L18).
const ADMIN_ENROL_LABEL: &[u8] = b"fstp-admin-invitation-enrol-v1";

/// The accounts port.
pub(crate) struct CellAccounts<R: Runtime, V>(pub(super) Arc<Inner<R, V>>);

/// The system command id of the enrolment invitation of the creator
/// invitation `invitation` in the cell `cell`, keyed by the cell id as the
/// timeline's ids are (I-20).
fn enrol_command_id(cell: [u8; 16], invitation: u128) -> [u8; 16] {
    labelled_command_id(ENROL_LABEL, cell, invitation)
}

/// The system command id under `label` of the invitation `invitation` in
/// the cell `cell`, keyed by the cell id (I-20).
fn labelled_command_id(label: &[u8], cell: [u8; 16], invitation: u128) -> [u8; 16] {
    let mut h = fstp_crypto::HmacSha256::new(&cell);
    h.update(label);
    h.update(&invitation.to_be_bytes());
    let d = h.finish();
    let mut suffix = [0u8; 8];
    for (o, b) in suffix.iter_mut().zip(d.iter()) {
        *o = *b;
    }
    fstp_cell_core::system_command_id(suffix)
}

impl<R: Runtime, V: VaultClient> CellAccounts<R, V> {
    /// The tenant's look for a message about `programme`, if any (ADR-030 section
    /// 5): the brand colour and the logos an email shows, their bytes
    /// read from the blob store. A logo that does not read is left out,
    /// so the message still goes with the tenant's name as text.
    async fn mail_brand(&self, programme: Option<ProgrammeId>) -> Option<fstp_mail::MailBrand> {
        use fstp_api_core::port::{BlobRef, BlobStore as _};
        let (colour, plan) = {
            let st = self.0.engine.state();
            fstp_api_core::brand::mail_plan(st.engine().tenant.state()?, programme)?
        };
        let blobs = super::content::CellBlobs(Arc::clone(&self.0));
        let mut logos = Vec::new();
        for (l, alt) in plan {
            if let Ok(png) = blobs.get_brand(BlobRef(l.digest.bytes())).await {
                logos.push(fstp_mail::MailLogo { png, alt });
            }
        }
        Some(fstp_mail::MailBrand { colour, logos })
    }

    /// The funding card of a message about `programme` (ADR-034, I-69):
    /// the platform's Funded by the European Union logo and the card's
    /// lines, or `None` for a message about no programme.
    fn mail_funding(&self, programme: Option<ProgrammeId>) -> Option<fstp_mail::MailFunding> {
        let card = {
            let st = self.0.engine.state();
            fstp_api_core::port::funding_card(st.engine(), programme?)?
        };
        Some(fstp_mail::MailFunding {
            png: fstp_api_core::brand::funding::FUNDED_BY_EU_PNG.to_vec(),
            alt: fstp_api_core::brand::funding::FUNDED_BY_EU_ALT.to_owned(),
            lines: card.text_lines(),
        })
    }

    /// Admits `command` for the system task `task` under `id` and runs it,
    /// with the outbox bodies of a firing. A duplicate of a committed id is
    /// success.
    async fn system(
        &self,
        command: CellCommand,
        task: SystemTask,
        id: [u8; 16],
        bodies: Vec<fstp_cell_core::timeline::MessageBody>,
        now: Timestamp,
    ) -> Result<(), PortError> {
        let state = self.0.engine.state();
        let mut admitted = gate::admit_system(&state, Action::Command(command), task, id, now)
            .map_err(|_| PortError::Refused)?;
        if !bodies.is_empty() {
            admitted = admitted.with_outbox(bodies);
        }
        self.0
            .engine
            .execute(admitted)
            .await
            .map(|_| ())
            .map_err(|_| PortError::Unavailable)
    }

    /// Step 2: the M3 enrolment invitation of a new account for the link
    /// token, unless the ledger holds one for this creator invitation.
    async fn enrolment(
        &self,
        programme: ProgrammeId,
        invitation: u128,
        token: &[u8; 32],
        email: &str,
        now: Timestamp,
    ) -> Result<(), PortError> {
        if self
            .0
            .engine
            .state()
            .auth()
            .invitation(invitation.to_be_bytes())
            .is_some()
        {
            return Ok(());
        }
        let digest = fstp_auth::ceremony::token_digest(&fstp_auth::codec::Token(*token));
        let raw = fstp_crypto::random_array::<16>().map_err(|_| PortError::Unavailable)?;
        let account = AccountId::from_raw(u128::from_be_bytes(raw));
        // The enrolment binds the address as the login email (design
        // section 4.2), as for an invitation of the command route.
        self.0
            .backend
            .note_invitation_email(digest, email.to_owned())
            .await
            .map_err(|_| PortError::Unavailable)?;
        let command = CellCommand::Tenant(TenantCommand::IssueRoleInvitation {
            programme,
            role_invitation: invitation,
            account,
            token_digest: digest,
        });
        let id = enrol_command_id(self.0.cell, invitation);
        self.system(command, SystemTask::Provisioning, id, Vec::new(), now)
            .await
    }

    /// The account whose login email is `email`, if any.
    async fn login_account(&self, email: &str) -> Result<Option<AccountId>, PortError> {
        self.0
            .erasure
            .login_account(crate::tasks::erasure::normalise_email(email))
            .await
            .map_err(|_| PortError::Unavailable)
    }

    /// Step 2 of an admin invitation (SoD-07, ADR-026 record of lane L18):
    /// the M3 enrolment invitation of the invitee the API core drew, for
    /// the link token, unless the ledger holds it already. The enrolment
    /// binds the address as the login email and takes the tenant admin
    /// invitation.
    async fn admin_enrolment(
        &self,
        invitation: u128,
        invitee: AccountId,
        token: &[u8; 32],
        email: &str,
        now: Timestamp,
    ) -> Result<(), PortError> {
        if self
            .0
            .engine
            .state()
            .auth()
            .invitation(invitation.to_be_bytes())
            .is_some()
        {
            return Ok(());
        }
        let digest = fstp_auth::ceremony::token_digest(&fstp_auth::codec::Token(*token));
        self.0
            .backend
            .note_invitation_email(digest, email.to_owned())
            .await
            .map_err(|_| PortError::Unavailable)?;
        let command = CellCommand::Tenant(TenantCommand::IssueAdminInvitation {
            admin_invitation: invitation,
            account: invitee,
            token_digest: digest,
        });
        let id = labelled_command_id(ADMIN_ENROL_LABEL, self.0.cell, invitation);
        self.system(command, SystemTask::Provisioning, id, Vec::new(), now)
            .await
    }

    /// Step 3: the invitation event `derived`, scheduled and fired with the
    /// composed message, whose one link is `link`. The message carries the
    /// tenant's look and, for a programme role, the programme's logo.
    /// Returns the row and body to deliver, or `None` when the event fired
    /// before.
    async fn fire(
        &self,
        relay: &SharedRelay,
        derived: fstp_timeline::Derived,
        link: LinkTarget,
        to: &Mailbox,
        programme: Option<ProgrammeId>,
        now: Timestamp,
    ) -> Result<Option<([u8; 16], Vec<u8>)>, PortError> {
        let event = derived.id();
        if self.0.engine.state().timeline().event(&event).is_none() {
            let plan = TimelineCommand::Plan {
                records: vec![derived.scheduled()],
            };
            let id = fstp_timeline::command_id(self.0.cell, &plan);
            self.system(
                CellCommand::Timeline(plan),
                SystemTask::Timeline,
                id,
                Vec::new(),
                now,
            )
            .await?;
        }
        let state = self.0.engine.state();
        match state.timeline().event(&event).map(|e| e.status) {
            Some(EventStatus::Scheduled) => {}
            Some(EventStatus::Fired) => return Ok(None),
            _ => return Err(PortError::Unavailable),
        }
        let address =
            fstp_crypto::sha256(crate::tasks::erasure::normalise_email(to.as_str()).as_bytes());
        let message = match link {
            LinkTarget::AdminInvitation(_) => {
                fstp_timeline::admin_invitation_message(&event, address)
            }
            _ => fstp_timeline::role_invitation_message(&event, address),
        }
        .ok_or(PortError::Unavailable)?;
        let cfg = MailConfig {
            origin: Origin::new(&format!("https://{}", self.0.host))
                .map_err(|_| PortError::Unavailable)?,
            from: Mailbox::new(relay.sender()).map_err(|_| PortError::Unavailable)?,
            from_name: None,
            dkim: Vec::new(),
            // ADR-030: the tenant's and the programme's logos and colour.
            brand: self.mail_brand(programme).await,
            // ADR-034: the funding card of the message's programme.
            funding: self.mail_funding(programme),
        };
        let bindings = Bindings::new().with(Slot::Link, Value::Link(link));
        let body = fstp_mail::compose(
            &cfg,
            &Message {
                template: message.template,
                bindings: &bindings,
                to,
                idem: message.idem,
                event,
                date: now,
                pdf: None,
            },
        )
        .map_err(|_| PortError::Unavailable)?;
        let firing =
            fstp_timeline::role_invitation_firing(&state, &event, &message, body.clone(), now)
                .ok_or(PortError::Unavailable)?;
        let id = fstp_timeline::command_id(self.0.cell, &firing.command);
        self.system(
            CellCommand::Timeline(firing.command),
            SystemTask::Timeline,
            id,
            firing.bodies,
            now,
        )
        .await?;
        Ok(Some((message.outbox, body)))
    }
}

impl<R: Runtime, V: VaultClient> Accounts for CellAccounts<R, V> {
    /// The invitation of a person to a programme role (module
    /// documentation). The link is the landing, `/app/invitation#<token>`.
    async fn invite(&self, kind: InviteKind) -> Result<InvitationLink, PortError> {
        // Step 1: no relay, no invitation.
        let relay = self.0.relay.clone().ok_or(PortError::Unavailable)?;
        let now = self.0.now();
        let (to, derived, link, path, programme) = match kind {
            InviteKind::ProgrammeRole {
                programme,
                invitation,
                email,
                token,
                ..
            } => {
                let to = Mailbox::new(&email).map_err(|_| PortError::Refused)?;
                let invitation = invitation.raw();
                let known = self.login_account(&email).await?;
                if known.is_none() {
                    self.enrolment(programme, invitation, token.bytes(), &email, now)
                        .await?;
                }
                let derived = fstp_timeline::role_invitation_event(programme, invitation, now);
                let link = LinkTarget::RoleInvitation(InvitationToken(*token.bytes()));
                let path = format!("/app/invitation#{}", token.hex());
                (to, derived, link, path, Some(programme))
            }
            // SoD-07, ADR-026 record of lane L18: the second tenant admin.
            InviteKind::TenantAdmin {
                invitation,
                invitee,
                email,
                token,
            } => {
                let to = Mailbox::new(&email).map_err(|_| PortError::Refused)?;
                if self.login_account(&email).await?.is_some() {
                    return Err(PortError::Refused);
                }
                let invitation = invitation.raw();
                self.admin_enrolment(invitation, invitee, token.bytes(), &email, now)
                    .await?;
                let derived = fstp_timeline::admin_invitation_event(invitation, now);
                let link = LinkTarget::AdminInvitation(InvitationToken(*token.bytes()));
                let path = format!("/auth/invite#{}", token.hex());
                (to, derived, link, path, None)
            }
        };
        let fired = self
            .fire(&relay, derived, link, &to, programme, now)
            .await?;
        // Step 4. Without the digest key the row waits for the dispatcher.
        if let Some((outbox, body)) = fired
            && let Ok(Some(key)) = self.0.erasure.delivery_digest_key().await
        {
            let engine = self.0.engine.clone();
            let _ = super::mail::deliver_once(&self.0.app, &relay, key, outbox, &body, move || {
                engine.now()
            })
            .await;
        }
        Ok(InvitationLink(path))
    }

    /// A pseudonymous handle from the account id. Never an email.
    async fn display_handle(&self, a: AccountId) -> Result<DisplayHandle, PortError> {
        let h = fstp_crypto::sha256(&a.raw().to_be_bytes());
        let tail: String = h.iter().take(3).map(|b| format!("{b:02x}")).collect();
        Ok(DisplayHandle(format!("member-{tail}")))
    }

    /// The cell's login email index (SA-11, I-86).
    async fn login_email(&self, a: AccountId) -> Result<Option<String>, PortError> {
        self.0
            .erasure
            .login_email(a)
            .await
            .map_err(|_| PortError::Unavailable)
    }
}

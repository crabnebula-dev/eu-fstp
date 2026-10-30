//! The tenant side of the e2e cell (M4 design sections 2.2 J0 and 3.5,
//! lane m4tenant): the provisioning of a reset cell and the M3 half of a
//! tenant admin invitation.
//!
//! - **Provisioning.** A reset cell's ledger starts with the provisioning
//!   record of the tenant part: a SaaS cell whose first tenant admin is
//!   [`crate::control::FIRST_ADMIN`], with the agreement versions the
//!   control plane recorded as accepted ([`AGREEMENTS`], Q22).
//! - **Invitation.** `tenant.invite_admin` runs through the API core with
//!   its step-up (I-78), and appends the invitation with the invitee's
//!   account and the digest of a token the core drew. No port hands that
//!   token and the email to M3 yet (`port::InviteKind` is a W0
//!   placeholder). So, standing in for M3, the cell binds the email to
//!   the invitee's account and mails a one-time enrolment link of its own
//!   (`admin_invitation`).
//! - **Acceptance.** When the invitee enrols a passkey through that link,
//!   the cell issues `AcceptAdminInvitation` as the invitee, as M3's
//!   enrolment ceremony would (design J0). The token the API core drew
//!   never left it, so the cell presents the digest the ledger holds. Its
//!   own enrolment link, used once, is what stands for the token here.
//!   This is test-only emulation (layering rule A9).

use fstp_domain::command::{Actor, Ctx, Via};
use fstp_domain::id::{AccountId, CommandId};
use fstp_engine::{Command, Provisioning, Record, TenantEntry, TenantRequest};
use fstp_http::{Request, Response, StatusCode};
use fstp_ledger::{MemStore, RecordStore};
use fstp_tenant::{AgreementVersions, CellKind, InvitationId, TenantCommand};

use crate::wire;
use crate::{Inner, lock};

/// The API route of `tenant.invite_admin`.
pub(crate) const INVITE_ROUTE: &str = "/api/v1/admin/admins";

/// The agreement versions the synthetic control plane recorded as
/// accepted by the tenant of a reset cell (Q22). The agreement texts are
/// `TODO(legal)` until Daniel supplies them.
pub(crate) const AGREEMENTS: AgreementVersions = AgreementVersions {
    saas_terms: 1,
    dpa: 1,
    sub_processors: 1,
};

/// Appends the provisioning record of a SaaS cell whose first tenant
/// admin is `first_admin`, at `at`, as the first entry of `store`.
pub(crate) fn provision(
    store: &mut MemStore<Record>,
    first_admin: AccountId,
    at: i64,
) -> Result<(), String> {
    let record = Record::Tenant(TenantEntry::Provisioned(Provisioning {
        first_admin,
        cell: CellKind::Saas,
        agreements: Some(AGREEMENTS),
    }));
    let mut command = *b"fstp:e2e:tenant\0";
    command[15] = 1;
    store
        .append(store.head(), at, command, vec![record])
        .map(|_| ())
        .map_err(|e| format!("the provisioning record: {e:?}"))
}

/// The invitation and the invitee of the latest `InviteAdmin` the engine
/// port appended after its first `before` executions.
fn appended_invitation(inner: &Inner, before: usize) -> Option<(InvitationId, AccountId)> {
    inner
        .ports
        .engine
        .appended()
        .into_iter()
        .skip(before)
        .rev()
        .find_map(|e| match e.cmd {
            Command::Tenant(TenantRequest {
                command:
                    TenantCommand::InviteAdmin {
                        invitation,
                        invitee,
                        ..
                    },
                ..
            }) => Some((invitation, invitee)),
            _ => None,
        })
}

/// `POST /api/v1/admin/admins`: the call goes to the API core unchanged.
/// When it appended an invitation, the cell plays M3's part: it binds the
/// email to the invitee and mails the enrolment link (module
/// documentation). A call that did not append mails nothing, so a
/// cancelled step-up sends no invitation.
pub(crate) async fn invite_admin(inner: &Inner, req: Request) -> Response {
    let email = wire::body(&req).and_then(|o| wire::str_member(&o, "email").map(str::to_owned));
    let before = inner.ports.engine.appended().len();
    let reply = inner.web.serve(req).await;
    if reply.status != StatusCode::OK {
        return reply;
    }
    let (Some(email), Some((invitation, invitee))) = (email, appended_invitation(inner, before))
    else {
        return reply;
    };
    let mut auth = lock(&inner.auth);
    if auth.account(&email).is_some_and(|a| a != invitee) {
        // The address already names another account. M3 would invite that
        // account, which the drawn invitee is not, so nothing is mailed.
        return reply;
    }
    auth.person(&email, invitee);
    match auth.invite(invitee) {
        Ok(link) => {
            auth.admin_invitation(invitee, invitation);
            auth.mail(&email, "admin_invitation", link);
        }
        Err(_) => return wire::refuse(StatusCode::SERVICE_UNAVAILABLE, "random"),
    }
    reply
}

/// The invitee `account`, who just enrolled a passkey through an admin
/// invitation link, takes the invitation (`AcceptAdminInvitation`, web
/// only, I-85). An account with no open admin invitation is left as it
/// is.
pub(crate) fn accept(inner: &Inner, account: AccountId) -> Result<(), String> {
    let Some(invitation) = lock(&inner.auth).taken_admin_invitation(account) else {
        return Ok(());
    };
    let state = inner.ports.engine.state();
    let token_digest = state
        .tenant
        .state()
        .and_then(|t| t.invitation(invitation))
        .filter(|i| i.invitee == account && !i.taken)
        .map(|i| i.token_digest)
        .ok_or_else(|| "the admin invitation is not open".to_owned())?;
    let mut id = wire::random::<16>()?;
    // Command ids of the driver's own namespace are refused, so the cell
    // never draws one.
    if let Some(first) = id.first_mut() {
        *first = b'e';
    }
    let ctx = Ctx {
        now: inner.ports.clock.read(),
        actor: Actor::Account(account),
        command: CommandId::from_bytes(id),
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    };
    let cmd = Command::Tenant(TenantRequest::new(TenantCommand::AcceptAdminInvitation {
        invitation,
        token_digest,
    }));
    inner
        .ports
        .engine
        .environment(cmd, ctx)
        .map(|_| ())
        .map_err(|e| format!("the admin invitation: {e}"))
}

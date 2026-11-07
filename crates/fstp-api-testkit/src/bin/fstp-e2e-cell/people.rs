//! M3's half of a programme role invitation in the e2e cell (M4 design
//! section 2.2 J2, lane inv).
//!
//! `creator.invite` runs through the API core, which draws the link token,
//! appends the invitation under the token's digest and hands the token and
//! the email to M3 through the accounts port. The fake accounts port keeps
//! each one. Standing in for M3, the cell then:
//!
//! - binds the email to an account: the account the address already
//!   names, or a new one the vault knows under a fresh synthetic identity,
//!   unverified, as a fresh self-registration is;
//! - makes the link token that account's one-time enrolment token, so the
//!   landing enrols a passkey at `/auth/invitations/{token}/register`;
//! - mails kind `invitation` with `<origin>/app/invitation#<token>`.
//!
//! The invitation is mailed after the call that appended it, so a refused
//! call mails nothing. This mirrors `crate::onboarding::invite_admin` and
//! is test-only emulation (layering rule A9).

use fstp_api_core::port::InviteKind;
use fstp_http::{Request, Response};

use crate::{Inner, lock};

/// Serves `req` through the API core, then mails every programme role
/// invitation the accounts port received meanwhile (module documentation).
pub(crate) async fn serve(inner: &Inner, req: Request) -> Response {
    let reply = inner.web.serve(req).await;
    mail_new(inner);
    reply
}

/// Mails the invitations the accounts port received and the cell has not
/// mailed yet.
pub(crate) fn mail_new(inner: &Inner) {
    let mut fresh = Vec::new();
    {
        let mut auth = lock(&inner.auth);
        for kind in auth.take_unmailed(inner.ports.accounts.invitations()) {
            let InviteKind::ProgrammeRole { email, token, .. } = kind;
            let token = token.hex();
            let (account, new) = auth.invite_programme_role(&email, &token);
            if new && let Some(tag) = auth.fresh_identity() {
                fresh.push((account, tag));
            }
            let link = auth.invitation_link(&token);
            auth.mail(&email, "invitation", link);
        }
    }
    for (account, tag) in fresh {
        inner.ports.vault.change(|t| t.set_identity(account, tag));
    }
}

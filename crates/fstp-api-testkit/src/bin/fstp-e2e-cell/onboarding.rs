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

/// The demo tenant's legal details (ADR-037 section 5): CrabNebula Ltd's
/// values, supplied by Daniel on 2026-11-22 for the demo cell. Shared code
/// holds no value.
pub(crate) const DEMO_LEGAL_DETAILS: &[(&str, &str)] = &[
    ("legal_name", "CrabNebula Ltd"),
    ("address", "27 Triq it-Tramuntana, Birgu BRG1160, Malta"),
    (
        "registered_address",
        "27 Triq it-Tramuntana, Birgu BRG1160, Malta",
    ),
    ("privacy_contact", "privacy@crabnebula.dev"),
    ("dpo_name", "Daniel Thompson-Yvetot"),
    ("dpo_contact", "privacy@crabnebula.dev"),
    (
        "supervisory_authority",
        "Information and Data Protection Commissioner (IDPC), Malta",
    ),
    ("company_number", "C 103590"),
    ("vat_number", "MT29710913"),
    ("transparency_register", "3419964101239-38"),
    ("governing_law", "Maltese law"),
];

/// Appends the provisioning record of a SaaS cell whose first tenant
/// admin is `first_admin`, then the invitation of `second_admin` and its
/// acceptance, as `tenant.invite_admin` and M3's enrolment append them
/// (Q31 A). The scenes found their organisation on this ledger through
/// real onboarding and activation (ADR-021).
pub(crate) fn provision_two_admins(
    store: &mut MemStore<Record>,
    first_admin: AccountId,
    second_admin: AccountId,
    at: i64,
) -> Result<(), String> {
    provision(store, first_admin, at)?;
    let invitation = InvitationId::from_raw(0x1a2);
    let records = [
        fstp_tenant::TenantRecord::AdminInvited {
            invitation,
            invitee: second_admin,
            token_digest: fstp_tenant::TokenDigest::from_bytes([0xd2; 32]),
            by: first_admin,
        },
        fstp_tenant::TenantRecord::AdminAdded {
            account: second_admin,
            invitation,
        },
        // ADR-034: the demo tenant's funding card defaults, the pilot's
        // coordinator and its role address, as Daniel asked on 2026-11-22.
        // An organisation and a role address, never a person.
        fstp_tenant::TenantRecord::FundingDefaultsSet {
            defaults: fstp_brand::funding::FundingDefaults::new(
                "CrabNebula Ltd",
                "privacy@crabnebula.dev",
            )
            .ok_or("the funding card defaults")?,
            by: first_admin,
        },
        // ADR-037: the demo tenant's legal details, CrabNebula Ltd's
        // values as Daniel supplied them on 2026-11-22. No accessibility
        // contact was supplied, so the pages show it as not set.
        fstp_tenant::TenantRecord::LegalDetailsSet {
            details: fstp_brand::legal::LegalDetails::from_pairs(DEMO_LEGAL_DETAILS)
                .ok_or("the legal details")?,
            by: first_admin,
        },
    ];
    for (n, r) in (2u8..).zip(records) {
        let mut command = *b"fstp:e2e:tenant\0";
        command[15] = n;
        store
            .append(
                store.head(),
                at,
                command,
                vec![Record::Tenant(TenantEntry::Record(r))],
            )
            .map_err(|e| format!("the second admin's tenant record: {e:?}"))?;
    }
    Ok(())
}

/// The invitation and the invitee of the latest `InviteAdmin` the engine
/// port appended after its first `before` executions.
pub(crate) fn appended_invitation(
    inner: &Inner,
    before: usize,
) -> Option<(InvitationId, AccountId)> {
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
    take(inner, account, invitation)
}

/// `account` takes the open admin invitation `invitation` with the token
/// digest the ledger holds (`AcceptAdminInvitation`, web only, I-85), as
/// M3's enrolment ceremony would.
pub(crate) fn take(
    inner: &Inner,
    account: AccountId,
    invitation: InvitationId,
) -> Result<(), String> {
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

#[cfg(test)]
mod legal_tests {
    use super::DEMO_LEGAL_DETAILS;
    use fstp_api_core::legal::{LegalText, page_html};
    use fstp_brand::legal::LegalDetails;

    /// ADR-037 section 5: the demo values are valid legal details and
    /// fill the imprint; the accessibility contact, which Daniel did not
    /// supply, shows as not set.
    #[test]
    fn adr037_demo_legal_details_fill_the_imprint() {
        let d = LegalDetails::from_pairs(DEMO_LEGAL_DETAILS);
        assert!(d.is_some(), "the demo values are plain text");
        let html = page_html(LegalText::Imprint, d.as_ref(), None).unwrap_or_default();
        for v in [
            "CrabNebula Ltd",
            "C 103590",
            "MT29710913",
            "3419964101239-38",
        ] {
            assert!(html.contains(v), "{v}");
        }
        let html = page_html(LegalText::Accessibility, d.as_ref(), None).unwrap_or_default();
        assert!(html.contains("[not set: tenant.accessibility_contact]"));
    }
}

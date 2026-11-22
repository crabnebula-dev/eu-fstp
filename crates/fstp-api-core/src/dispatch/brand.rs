//! Logos and themes in the dispatch (ADR-030; I-68, R-WL-03).
//!
//! - `tenant.branding.logos`: the tenant admin's read of every slot.
//! - `me.set_theme`: the caller's own `ThemeSet` record.
//! - [`theme`]: the theme of the session's account, for the shell.
//! - [`asset`]: the bytes of a current logo, for the `/brand` route.
//! - [`letterhead`]: the logos a PDF of a programme shows.

use fstp_brand::ThemeMode;
use fstp_brand::image::{LogoFormat, PdfColours, logo_path_digest, pdf_image};
use fstp_domain::command::Via;
use fstp_domain::id::{AccountId, ProgrammeId};
use fstp_engine::{Command, EngineState, TenantRequest};
use fstp_tenant::{LogoOwner, LogoRef, TenantCommand, Theme};

use super::{Call, Seams, dry_run, exec_failed};
use crate::brand::{LogoAsset, LogosView};
use crate::port::{AsyncEngine, BlobRef, BlobStore, Clock, ExecMeta, OpName};
use crate::{ApiError, Credential, ErrorCode, OpResult, ReadModel, RequestHead};

/// `tenant.branding.logos` (ADR-030): every programme of the tenant with
/// its own logos, and the tenant's. `authorize_read` admitted the caller
/// as a tenant admin.
pub(super) fn logos<P: Seams>(call: &Call<'_, P>) -> ReadModel {
    let programmes = super::creator_ops::programmes(&call.state)
        .into_iter()
        .map(|p| (p, crate::creator::programme_name(p)));
    ReadModel::Logos(LogosView::of(call.state.tenant.state(), programmes))
}

/// `me.set_theme` (ADR-030 section 1): the caller's own choice, a
/// `ThemeSet` record of the tenant ledger. Web only: no tool reaches it.
pub(super) async fn set_theme<P: Seams>(
    call: &Call<'_, P>,
    account: AccountId,
    theme: Theme,
) -> Result<OpResult, ApiError> {
    if call.caller.via() != Via::Web {
        return Err(ApiError::refused(ErrorCode::NotExposed, "I-85"));
    }
    if call.state.tenant.state().is_none() {
        return Err(ApiError::refused(ErrorCode::NotFound, "Input"));
    }
    let cmd = Command::Tenant(TenantRequest::new(TenantCommand::SetTheme { theme }));
    let command_id = fstp_domain::id::CommandId::from_bytes(call.draw()?.to_be_bytes());
    let ctx = call.ctx(account, &cmd, Via::Web, command_id);
    dry_run(call, account, &cmd, ctx).await?;
    let meta = ExecMeta {
        via: Via::Web,
        session: call.caller.session,
        agent: call.caller.agent,
        op: OpName(call.spec.name),
        request: call.digest,
        step_up: None,
        pending: None,
        second_tenant_admin: None,
    };
    let seq = call
        .ports
        .engine()
        .execute(cmd, ctx, meta)
        .await
        .map_err(exec_failed)?;
    Ok(OpResult::Done {
        body: ReadModel::Accepted,
        seq: Some(seq),
    })
}

/// The theme of the account `cred`'s session holds, or System for no
/// session (ADR-030 section 1). Nothing is recorded.
pub(crate) async fn theme<P: Seams>(ports: &P, cred: &Credential, head: &RequestHead) -> Theme {
    let state = ports.engine().snapshot();
    let now = ports.clock().now();
    let Ok(caller) = super::resolve(ports, cred, head, false, &state, now).await else {
        return Theme::System;
    };
    match (caller.p.account(), state.tenant.state()) {
        (Some(a), Some(ts)) => ts.theme(a),
        _ => Theme::System,
    }
}

/// The bytes of the logo `path` names, when a current slot names its
/// digest with the same format (ADR-030 section 3). Any other path,
/// a stale logo included, gives `None`.
pub(crate) async fn asset<P: Seams>(ports: &P, path: &str) -> Option<LogoAsset> {
    let (digest, format) = logo_path_digest(path)?;
    let state = ports.engine().snapshot();
    let logo = crate::brand::current(state.tenant.state()?, &digest)?;
    if logo.format != format {
        return None;
    }
    let bytes = ports.blobs().get_brand(BlobRef(digest)).await.ok()?;
    (fstp_crypto::sha256(&bytes) == digest).then_some(LogoAsset { format, bytes })
}

/// The bytes of a logo of `owner` in light mode, when a PDF can show it.
async fn pdf_logo<P: Seams>(
    ports: &P,
    state: &EngineState,
    owner: LogoOwner,
) -> Option<fstp_pdf::Image> {
    let ts = state.tenant.state()?;
    let l: LogoRef = crate::brand::logo_of(ts, owner, ThemeMode::Light)?;
    if !l.pdf || l.format != LogoFormat::Png {
        return None;
    }
    let bytes = ports
        .blobs()
        .get_brand(BlobRef(l.digest.bytes()))
        .await
        .ok()?;
    pdf_of(&bytes)
}

/// The `fstp-pdf` image of a checked PNG, by IDAT pass-through.
pub(crate) fn pdf_of(png: &[u8]) -> Option<fstp_pdf::Image> {
    let img = pdf_image(png)?;
    Some(fstp_pdf::Image {
        width: img.width,
        height: img.height,
        colours: match img.colours {
            PdfColours::Gray => fstp_pdf::ImageColours::Gray,
            PdfColours::Rgb => fstp_pdf::ImageColours::Rgb,
            PdfColours::Indexed(p) => fstp_pdf::ImageColours::Indexed(p),
        },
        bits: img.bits,
        mask: img.mask,
        data: img.data,
    })
}

/// The letterhead of a PDF of programme `programme` (ADR-030 section 6):
/// the tenant's logo, then the programme's, each when a PDF can show it,
/// and the platform's EU emblem slot.
pub(crate) async fn letterhead<P: Seams>(
    ports: &P,
    state: &EngineState,
    programme: Option<ProgrammeId>,
) -> fstp_pdf::Letterhead {
    let mut logos = Vec::new();
    if let Some(i) = pdf_logo(ports, state, LogoOwner::Tenant).await {
        logos.push(i);
    }
    if let Some(p) = programme
        && let Some(i) = pdf_logo(ports, state, LogoOwner::Programme(p)).await
    {
        logos.push(i);
    }
    fstp_pdf::Letterhead {
        logos,
        emblem: fstp_brand::emblem::EU_EMBLEM_PNG.and_then(pdf_of),
    }
}

/// Whether `account` holds an active Programme manager binding in
/// `programme`, as the engine answers the domain's question (ADR-030,
/// lead reading of 2026-11-22).
pub(crate) fn manages(state: &EngineState, account: AccountId, programme: ProgrammeId) -> bool {
    state.core.roster().bindings().any(|(_, b)| {
        b.account == account
            && b.programme == programme
            && b.role == fstp_domain::roles::Role::ProgrammeManager
            && b.held()
    })
}

/// `programme.logos` (ADR-030, lead reading of 2026-11-22): the tenant's
/// logos, shown read-only, and the one programme's slots. The read rule
/// admitted the caller as a programme manager of `programme`.
pub(super) fn programme_logos<P: Seams>(call: &Call<'_, P>, programme: ProgrammeId) -> ReadModel {
    ReadModel::Logos(LogosView::of(
        call.state.tenant.state(),
        [(programme, crate::creator::programme_name(programme))],
    ))
}

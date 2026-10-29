//! Shared helpers of the `fstp-release-svc` request decoder tests.
//!
//! Every valid request comes from `fstp_release::egress::encode`, the only
//! code that builds requests to CrabNebula hosts (I-38). So the services
//! accept exactly what a cell sends, with the production hosts, and
//! nothing else. Off-grammar requests are edits of those bytes.

#![allow(dead_code)]

use fstp_prop::Gen;
use fstp_release::ReleaseError;
use fstp_release::egress::{self, Channel, CnCall, LicenceRefresh, ProductVersion, UpdateCheck};
use fstp_release::licence::LicenceId;
use fstp_release_svc::{RefreshRequest, ServiceError, UpdateQuery};

/// The closed code of the stable channel in `UpdateQuery`.
///
/// Gap: `UpdateQuery::channel` is a bare `u8`, not
/// `fstp_release::egress::Channel`. The tests use code 1, the W1g
/// metadata code of the stable channel. Lane W2j may type the field
/// instead, and then maps it in [`update_call`].
pub(crate) const STABLE_CODE: u8 = 1;

/// Whether `e` is the W0 stub refusal of `fstp-release-svc`.
pub(crate) fn is_stub(e: &ServiceError) -> bool {
    matches!(e, ServiceError::NotImplemented(_))
}

fn release_stub(e: &ReleaseError) -> String {
    match e {
        ReleaseError::NotImplemented(op) => format!("{op} is NotImplemented"),
        #[allow(unreachable_patterns, reason = "lane W2j adds typed refusals")]
        _ => format!("encode refused: {e:?}"),
    }
}

/// `fstp_release::egress::encode`, with a stub refusal named.
pub(crate) fn encode(call: &CnCall) -> Result<Vec<u8>, String> {
    egress::encode(call).map_err(|e| release_stub(&e))
}

/// `decode_refresh_request`: the request, `None` for a typed refusal.
pub(crate) fn decode_refresh(bytes: &[u8]) -> Result<Option<RefreshRequest>, String> {
    match fstp_release_svc::decode_refresh_request(bytes) {
        Ok(r) => Ok(Some(r)),
        Err(e) if is_stub(&e) => Err(format!("{e}")),
        Err(_) => Ok(None),
    }
}

/// `decode_update_query`: the query, `None` for a typed refusal.
pub(crate) fn decode_update(bytes: &[u8]) -> Result<Option<UpdateQuery>, String> {
    match fstp_release_svc::decode_update_query(bytes) {
        Ok(q) => Ok(Some(q)),
        Err(e) if is_stub(&e) => Err(format!("{e}")),
        Err(_) => Ok(None),
    }
}

/// Any product version.
pub(crate) fn gen_version(g: &mut Gen) -> ProductVersion {
    ProductVersion(g.u16(), g.u16(), g.u16())
}

/// Any licence refresh.
pub(crate) fn gen_refresh(g: &mut Gen) -> LicenceRefresh {
    let mut id = [0u8; 16];
    for b in &mut id {
        *b = g.u8();
    }
    LicenceRefresh {
        licence: LicenceId(id),
        version: gen_version(g),
    }
}

/// Any update check.
pub(crate) fn gen_update(g: &mut Gen) -> UpdateCheck {
    UpdateCheck {
        version: gen_version(g),
        channel: Channel::Stable,
    }
}

/// The call a decoded refresh request stands for.
pub(crate) fn refresh_call(r: &RefreshRequest) -> CnCall {
    CnCall::Licence(LicenceRefresh {
        licence: LicenceId(r.licence),
        version: ProductVersion(r.version.0, r.version.1, r.version.2),
    })
}

/// The call a decoded update query stands for.
///
/// # Errors
///
/// Names a channel code outside the closed set.
pub(crate) fn update_call(q: &UpdateQuery) -> Result<CnCall, String> {
    let channel = match q.channel {
        STABLE_CODE => Channel::Stable,
        other => {
            return Err(format!(
                "I-38: channel code {other} is outside the closed set"
            ));
        }
    };
    Ok(CnCall::Update(UpdateCheck {
        version: ProductVersion(q.version.0, q.version.1, q.version.2),
        channel,
    }))
}

/// `bytes` with `line` inserted after the `Host` header.
pub(crate) fn with_header(bytes: &[u8], line: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let mut parts = text.splitn(3, "\r\n");
    let first = parts.next().unwrap_or_default();
    let host = parts.next().unwrap_or_default();
    let rest = parts.next().unwrap_or_default();
    format!("{first}\r\n{host}\r\n{line}\r\n{rest}").into_bytes()
}

/// `bytes` with the first `from` replaced by `to`.
pub(crate) fn replace_once(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    String::from_utf8_lossy(bytes)
        .replacen(from, to, 1)
        .into_bytes()
}

/// One random single-byte edit of `bytes`: a change, an insertion or a
/// deletion.
pub(crate) fn mutate(g: &mut Gen, bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let len = out.len();
    match g.u8_in(0..=2) {
        0 if len > 0 => {
            let i = g.usize_in(0..=len - 1);
            if let Some(b) = out.get_mut(i) {
                *b ^= g.u8_in(1..=255);
            }
        }
        1 => {
            let i = g.usize_in(0..=len);
            out.insert(i, g.u8());
        }
        _ if len > 0 => {
            out.remove(g.usize_in(0..=len - 1));
        }
        _ => out.push(g.u8()),
    }
    out
}

//! Issue 6 L10 (H-21), ADR-008 "Sign counts": a signed sign-count
//! regression at a login or a step-up records `CredentialSuspect`, as the
//! cell's own system task, and the login or step-up is refused as before.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_auth::AuthRecord;
use fstp_cell::routes::Backend as _;
use fstp_cell::routes::memory::{LOCAL_ADMIN, LocalCell};
use fstp_cell_core::tenant::{TenantCommand, TenantLoginPolicy};
use fstp_cell_core::{CellCommand, CellRecord};
use fstp_http::{Method, Request, RequestTarget, Response};

const CELL: [u8; 16] = [0xC3; 16];
const HOST: &str = "tenant-c.fstp.test";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn request(path: &str, cookie: Option<&[u8]>, body: &[u8]) -> Request {
    let mut req = Request::new(Method::POST, RequestTarget::origin(path).unwrap())
        .try_with_header("host", HOST)
        .unwrap()
        .try_with_header("origin", format!("https://{HOST}"))
        .unwrap()
        .try_with_header("content-type", "application/json")
        .unwrap();
    if let Some(c) = cookie {
        req = req.try_with_header("cookie", c.to_vec()).unwrap();
    }
    req.body = body.to_vec();
    req
}

fn challenge_id_of(resp: &Response) -> [u8; 16] {
    let text = std::str::from_utf8(&resp.body).unwrap();
    let (_, rest) = text.split_once("\"challenge_id\":\"").unwrap();
    let (h, _) = rest.split_once('"').unwrap();
    fstp_cell::http::body::hex_array::<16>(h).unwrap()
}

/// The id of the seeded admin's credential, from the ledger.
fn admin_credential(c: &LocalCell) -> Vec<u8> {
    c.backend()
        .records()
        .into_iter()
        .find_map(|r| match r {
            CellRecord::Auth(AuthRecord::CredentialRegistered {
                account,
                credential,
                ..
            }) if account == LOCAL_ADMIN => Some(credential),
            _ => None,
        })
        .unwrap()
}

fn suspect_marks(c: &LocalCell, credential: &[u8]) -> usize {
    c.backend()
        .records()
        .iter()
        .filter(|r| {
            matches!(r, CellRecord::Auth(AuthRecord::CredentialSuspect { account, credential: k })
                if *account == LOCAL_ADMIN && k == credential)
        })
        .count()
}

/// The fold's view of the credential, from the backend's state.
fn is_suspect(c: &LocalCell, credential: &[u8]) -> bool {
    let mut fut = std::pin::pin!(c.backend().state());
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(Ok(s)) => s
            .auth()
            .credential(credential)
            .is_some_and(|k| k.suspect && !k.revoked),
        _ => panic!("the memory backend answers at once"),
    }
}

/// Issue 6 L10, H-21, ADR-008 "Sign counts": a login whose assertion is
/// signed but whose count did not grow is refused (401) and records
/// `CredentialSuspect`. The fold marks the credential. A second regression
/// adds no record.
#[test]
fn issue6_l10_h21_sign_count_regression_records_credential_suspect() {
    let c = LocalCell::start(CELL, HOST).unwrap();
    let _ = c.admin_session().unwrap();
    let cred = admin_credential(&c);
    assert_eq!(suspect_marks(&c, &cred), 0);
    drop(c.backend().set_sign_count(cred.clone(), 1000));
    let r = c.serve(c.admin_login_request().unwrap());
    assert_eq!(r.status.as_u16(), 401, "refused exactly as before");
    assert_eq!(suspect_marks(&c, &cred), 1);
    assert!(is_suspect(&c, &cred));
    // Repeat regressions grow the ledger by nothing.
    for _ in 0..3 {
        let r = c.serve(c.admin_login_request().unwrap());
        assert_eq!(r.status.as_u16(), 401);
    }
    assert_eq!(suspect_marks(&c, &cred), 1);
}

/// Issue 6 L10, H-21: the same at a step-up. The step-up is refused (403)
/// and the credential is marked suspect.
#[test]
fn issue6_l10_h21_stepup_sign_count_regression_records_credential_suspect() {
    let c = LocalCell::start(CELL, HOST).unwrap();
    let owner = c.admin_session().unwrap();
    let cred = admin_credential(&c);
    let high = CellCommand::Tenant(TenantCommand::SetLoginPolicy {
        policy: TenantLoginPolicy {
            p70_magic_links: Some(false),
            ..TenantLoginPolicy::default()
        }
        .encode(),
    });
    let command = String::from_utf8(fstp_cell_core::encode_cell_command(&high)).unwrap();
    let body = format!(
        "{{\"command\":{command},\"command_id\":\"{}\"}}",
        hex(&[8; 16])
    );
    let options = c.serve(request(
        "/auth/stepup/options",
        Some(&owner),
        body.as_bytes(),
    ));
    assert_eq!(options.status.as_u16(), 200);
    let id = challenge_id_of(&options);
    drop(c.backend().set_sign_count(cred.clone(), 1000));
    let r = c.serve(c.admin_stepup_request(&owner, id).unwrap());
    assert_eq!(r.status.as_u16(), 403, "refused exactly as before");
    assert_eq!(suspect_marks(&c, &cred), 1);
    assert!(is_suspect(&c, &cred));
}

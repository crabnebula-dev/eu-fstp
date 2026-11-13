//! Reviewer reproducers for lane w3ar (routes and HTTP layer). Each test
//! fails against the lane's current code and passes once the defect it
//! names is fixed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "review reproducers assert on known-good fixtures"
)]

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fstp_auth::{EnabledMethods, Method as LoginMethod};
use fstp_cell::http::{Front, FrontConfig, MemoryLog, set_session_cookie};
use fstp_cell::routes::memory::MemoryBackend;
use fstp_cell::routes::{
    AnchorRow, Backend, BackendFault, ChallengeRow, ErasureRow, SessionRow, TokenKind, TokenRow,
};
use fstp_cell_core::driver::{Done, ExecError};
use fstp_cell_core::gate::Admitted;
use fstp_cell_core::tenant::TenantRecord;
use fstp_cell_core::{CellRecord, CellState};
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_http::{Method, Request, RequestTarget};
use fstp_ledger::Seq;

const CELL: [u8; 16] = [0x5e; 16];
const HOST: &str = "tenant-r.fstp.test";
const ADMIN: AccountId = AccountId::from_raw(0xad77);

/// A backend that runs every operation on a `MemoryBackend`, except that
/// `execute` only counts the call and reports a commit. A commit stands
/// for the append the production engine makes.
struct Spy {
    inner: MemoryBackend,
    executed: AtomicUsize,
}

impl Backend for Spy {
    fn now(&self) -> Timestamp {
        self.inner.now()
    }
    fn state(&self) -> impl Future<Output = Result<Arc<CellState>, BackendFault>> + Send {
        self.inner.state()
    }
    fn execute(
        &self,
        admitted: Admitted,
    ) -> impl Future<Output = Result<Result<Done, ExecError>, BackendFault>> + Send {
        let _ = admitted;
        self.executed.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(Ok(Done {
            head: Seq::from_raw(2),
            receipt: None,
            duplicate: None,
        })))
    }
    fn session(
        &self,
        token: [u8; 32],
    ) -> impl Future<Output = Result<Option<SessionRow>, BackendFault>> + Send {
        self.inner.session(token)
    }
    fn sessions_of(
        &self,
        account: AccountId,
    ) -> impl Future<Output = Result<Vec<SessionRow>, BackendFault>> + Send {
        self.inner.sessions_of(account)
    }
    fn all_sessions(&self) -> impl Future<Output = Result<Vec<SessionRow>, BackendFault>> + Send {
        self.inner.all_sessions()
    }
    fn open_session(
        &self,
        token: [u8; 32],
        row: SessionRow,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        self.inner.open_session(token, row)
    }
    fn touch_session(
        &self,
        id: [u8; 16],
        at: Timestamp,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        self.inner.touch_session(id, at)
    }
    fn put_challenge(
        &self,
        row: ChallengeRow,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        self.inner.put_challenge(row)
    }
    fn take_challenge(
        &self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<ChallengeRow>, BackendFault>> + Send {
        self.inner.take_challenge(id)
    }
    fn sign_count(
        &self,
        credential: Vec<u8>,
    ) -> impl Future<Output = Result<u32, BackendFault>> + Send {
        self.inner.sign_count(credential)
    }
    fn set_sign_count(
        &self,
        credential: Vec<u8>,
        count: u32,
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        self.inner.set_sign_count(credential, count)
    }
    fn login_account(
        &self,
        email: String,
    ) -> impl Future<Output = Result<Option<AccountId>, BackendFault>> + Send {
        self.inner.login_account(email)
    }
    fn put_token(&self, row: TokenRow) -> impl Future<Output = Result<(), BackendFault>> + Send {
        self.inner.put_token(row)
    }
    fn take_token(
        &self,
        digest: [u8; 32],
        kind: TokenKind,
    ) -> impl Future<Output = Result<Option<TokenRow>, BackendFault>> + Send {
        self.inner.take_token(digest, kind)
    }
    fn send_magic_link(
        &self,
        account: AccountId,
        token: [u8; 32],
    ) -> impl Future<Output = Result<(), BackendFault>> + Send {
        self.inner.send_magic_link(account, token)
    }
    fn stepup_asserted_at(
        &self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<Timestamp>, BackendFault>> + Send {
        self.inner.stepup_asserted_at(id)
    }
    fn anchors(&self) -> impl Future<Output = Result<Vec<AnchorRow>, BackendFault>> + Send {
        self.inner.anchors()
    }
    fn erasures(&self) -> impl Future<Output = Result<Vec<ErasureRow>, BackendFault>> + Send {
        self.inner.erasures()
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// I-17, R-AU-01, ADR-009, design section 6.5: a vault ticket route that
/// answers 501 (the ticket cannot be signed yet) must not have committed
/// the issue record first. Today `routes::api::issue` runs the command
/// through `Backend::execute` and only then answers 501. In production
/// that appends `IdentityReleaseIssued` or `TicketIssued`, so the audit
/// trail shows an identity release that no ticket can ever carry out, and
/// every retry with a fresh command id appends another.
#[test]
fn review_i17_vault_ticket_501_commits_no_issue_record() {
    let spy = Arc::new(Spy {
        inner: MemoryBackend::new(),
        executed: AtomicUsize::new(0),
    });
    let now = spy.inner.now();
    spy.inner
        .seed(
            Timestamp::from_micros(now.micros() - 1_000_000),
            vec![CellRecord::Tenant(TenantRecord::TenantAdminGranted {
                account: ADMIN,
            })],
        )
        .unwrap();
    let token = [0x7b; 32];
    fstp_rt::future::block_on(spy.inner.open_session(
        fstp_crypto::sha256(&token),
        SessionRow {
            id: [0x11; 16],
            account: ADMIN,
            method: LoginMethod::Passkey,
            started: now,
            last_used: now,
            credential: None,
        },
    ))
    .unwrap();
    let front = Front::new(
        FrontConfig {
            cell: CELL,
            host: HOST.to_owned(),
            enabled: EnabledMethods {
                methods: vec![LoginMethod::Passkey],
            },
        },
        Arc::clone(&spy),
        Arc::new(MemoryLog::default()),
    )
    .unwrap();
    let set = set_session_cookie(CELL, &token);
    let cookie = set
        .as_bytes()
        .split(|b| *b == b';')
        .next()
        .unwrap()
        .to_vec();
    let body = format!(
        "{{\"command_id\":\"{}\",\"kind\":\"release\",\"proposal\":\"1\"}}",
        hex(&[0x42; 16])
    );
    let mut req = Request::new(
        Method::POST,
        RequestTarget::origin("/api/v1/vault-tickets").unwrap(),
    )
    .try_with_header("host", HOST)
    .and_then(|r| r.try_with_header("origin", format!("https://{HOST}")))
    .and_then(|r| r.try_with_header("content-type", "application/json"))
    .and_then(|r| r.try_with_header("cookie", cookie))
    .unwrap();
    req.body = body.into_bytes();
    let resp = fstp_rt::future::block_on(front.serve(req));
    let executed = spy.executed.load(Ordering::SeqCst);
    assert!(
        !(resp.status.as_u16() == 501 && executed > 0),
        "the route answered 501 after it ran the issue command {executed} time(s): \
         an issue record commits for a ticket that is never returned"
    );
}

/// TH-26, I-18, design section 15: the `command_request_decode` target
/// checks size limits and the `minor` refusal only on bodies the decoder
/// accepts. The fuzz project ships no seed corpus
/// (`fuzz/seeds/command_request_decode`, the convention of
/// `tools/fuzz-all.sh`), and libFuzzer does not reach an accepted body in
/// the CI smoke time, so both checks never run. A seed that the decoder
/// accepts makes them run from the first input.
#[test]
fn review_th_26_command_request_fuzz_target_has_an_accepted_seed() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("seeds")
        .join("command_request_decode");
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!(
            "no seed corpus at {}: {e}; the minor and size checks never run",
            dir.display()
        )
    });
    let accepted = entries
        .filter_map(Result::ok)
        .filter_map(|e| std::fs::read(e.path()).ok())
        .any(|bytes| fstp_cell::http::decode_command_body(&bytes).is_ok());
    assert!(
        accepted,
        "no seed in {} decodes, so the target's I-18 and size checks never run",
        dir.display()
    );
}

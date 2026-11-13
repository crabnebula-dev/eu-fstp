//! ADR-011 "Two-operator approval", R-SW-02: `fstp-pgagent` checks the two
//! approvals of a destructive job again itself, against the staff
//! passkeys pinned in its own configuration. Lane m3/erase-cell-2,
//! written before the agent's check.
//!
//! The approvals come from the operator login of `fstp-control`, signed
//! by software passkeys in this file. The agent recomputes the job digest
//! from its own cluster and the job, so an approval binds the job kind,
//! the cluster and every argument. It admits a job only on two fresh,
//! unspent approvals of two distinct pinned staff members, each with
//! user verification. A refusal spends nothing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_control::ControlError;
use fstp_control::agent::approved_frame;
use fstp_control::approval::{
    AGENT_APPROVAL_WINDOW_SECS, AGENT_CLOCK_SKEW_SECS, AgentApprovals, ApprovalBook,
    ApprovalEvidence, DestructiveJob, PinnedApprovers, approval_challenge, job_digest,
};
use fstp_control::operator::{OperatorLogin, OperatorSession, Purpose, StaffCredential};
use fstp_control::pg::{CellDatabase, cell_role_plan};
use fstp_control::pgagent::{
    APPROVED_VERSION, ApprovedFrame, DbIdent, MAX_APPROVED_LEN, PgagentJob, RoleIdent, Target,
    decode_approved_job, encode_approved_job, encode_pgagent_job,
};
use fstp_control::placement::ClusterId;
use fstp_cp_proto::{CellId, RoleName, StaffRef};
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};
use fstp_webauthn::{AssertionResponse, CoseKey};

const HOST: &str = "control.example.test";
const T0: i64 = 1_800_000_000;
const CLUSTER: ClusterId = ClusterId([0x31; 16]);

/// A software passkey of one staff member.
struct Passkey {
    staff: StaffRef,
    id: Vec<u8>,
    key: Ed25519SigningKey,
    count: u32,
}

impl Passkey {
    fn new(staff: u8, id: u8) -> Passkey {
        Passkey {
            staff: StaffRef([staff; 16]),
            id: vec![id; 16],
            key: Ed25519SigningKey::generate().unwrap(),
            count: 0,
        }
    }

    fn pinned(&self) -> StaffCredential {
        StaffCredential {
            staff: self.staff,
            credential_id: self.id.clone(),
            key: CoseKey::Ed25519 {
                x: self.key.public_key(),
            },
        }
    }

    /// An assertion over `challenge` for `host`, with the UV flag when
    /// `uv` is set.
    fn assert_for(&mut self, challenge: &[u8; 32], host: &str, uv: bool) -> AssertionResponse {
        self.count += 1;
        let mut auth = fstp_crypto::sha256(host.as_bytes()).to_vec();
        auth.push(if uv { 0x05 } else { 0x01 });
        auth.extend_from_slice(&self.count.to_be_bytes());
        let b64 = fstp_pgwire::base64::encode(challenge)
            .replace('+', "-")
            .replace('/', "_")
            .replace('=', "");
        let client = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{b64}\",\"origin\":\"https://{host}\"}}"
        )
        .into_bytes();
        let mut message = auth.clone();
        message.extend_from_slice(&fstp_crypto::sha256(&client));
        AssertionResponse {
            credential_id: self.id.clone(),
            client_data_json: client,
            authenticator_data: auth,
            signature: self.key.sign(&message).unwrap().to_vec(),
        }
    }

    fn assert(&mut self, challenge: &[u8; 32]) -> AssertionResponse {
        self.assert_for(challenge, HOST, true)
    }

    /// The evidence of an approval of `job` on `cluster`, drawn at
    /// `issued_at`.
    fn evidence(
        &mut self,
        cluster: ClusterId,
        job: &PgagentJob,
        issued_at: i64,
        nonce: u8,
    ) -> ApprovalEvidence {
        let digest = job_digest(&DestructiveJob::pgagent(cluster, job.clone()).unwrap());
        let nonce = [nonce; 32];
        let c = approval_challenge(digest, issued_at, &nonce);
        ApprovalEvidence {
            issued_at,
            nonce,
            assertion: self.assert(&c),
        }
    }
}

fn db(cell: u8) -> DbIdent {
    DbIdent::new(CellDatabase::App, CellId([cell; 16]))
}

fn drop_db(cell: u8) -> PgagentJob {
    PgagentJob::DropCellDatabase(db(cell))
}

fn agent(pinned: &[&Passkey]) -> AgentApprovals {
    AgentApprovals::new(&PinnedApprovers {
        cluster: CLUSTER,
        operator_host: HOST.to_owned(),
        staff: pinned.iter().map(|p| p.pinned()).collect(),
    })
    .unwrap()
}

fn log_in(login: &mut OperatorLogin, p: &mut Passkey, now: i64) -> OperatorSession {
    let c = login.begin(Purpose::Login, now).unwrap();
    login.finish_login(c, &p.assert(&c), now).unwrap().0
}

fn approve(
    login: &mut OperatorLogin,
    s: OperatorSession,
    p: &mut Passkey,
    job: &DestructiveJob,
    now: i64,
) {
    let c = login.begin_approval(s, job, now).unwrap();
    let a = p.assert(&c);
    login.finish_approval(s, c, &a, now).unwrap();
}

/// ADR-011, R-SW-02: approvals made through the operator login of
/// `fstp-control` travel with the approved agent job, survive the frame
/// codec, and the agent admits the job on them. Sent again, the same
/// frame is refused, since each challenge counts once.
#[test]
fn adr011_pgagent_admits_a_job_on_the_operator_logins_approvals() {
    let mut a = Passkey::new(1, 0xa1);
    let mut b = Passkey::new(2, 0xb2);
    let mut login = OperatorLogin::new(HOST, &[a.pinned(), b.pinned()]).unwrap();
    let sa = log_in(&mut login, &mut a, T0);
    let sb = log_in(&mut login, &mut b, T0);
    let job = DestructiveJob::pgagent(CLUSTER, drop_db(7)).unwrap();
    approve(&mut login, sa, &mut a, &job, T0 + 1);
    approve(&mut login, sb, &mut b, &job, T0 + 2);
    let approved = login.authorise_destructive(sa, &job, T0 + 3).unwrap();
    let evidence = approved.evidence().expect("both approvals carry evidence");
    assert_eq!(evidence[0].issued_at, T0 + 1);
    assert_eq!(evidence[1].issued_at, T0 + 2);
    let frame = approved_frame(&approved).unwrap();
    let bytes = encode_approved_job(&frame).unwrap();
    assert_eq!(bytes[0], APPROVED_VERSION);
    let decoded = decode_approved_job(&bytes).unwrap();
    assert_eq!(decoded, frame);
    let mut check = agent(&[&a, &b]);
    let verified = check
        .verify(&decoded.job, &decoded.approvals, T0 + 4)
        .unwrap();
    assert_eq!(verified.job(), &drop_db(7));
    assert_eq!(
        check.verify(&decoded.job, &decoded.approvals, T0 + 5),
        Err(ControlError::ApprovalRequired),
        "a spent approval counted again"
    );
}

/// ADR-011: an erasure approval, or an approved job whose approvals came
/// without a passkey ceremony, has no frame for the agent.
#[test]
fn adr011_pgagent_frame_needs_an_agent_job_with_evidence() {
    let erase = DestructiveJob::EraseCell {
        cell: CellId([1; 16]),
    };
    let agent_job = DestructiveJob::pgagent(CLUSTER, drop_db(1)).unwrap();
    for job in [erase, agent_job] {
        let mut book = ApprovalBook::default();
        book.approve(StaffRef([1; 16]), &job, T0).unwrap();
        book.approve(StaffRef([2; 16]), &job, T0).unwrap();
        let approved = book.take(StaffRef([1; 16]), &job, T0).unwrap();
        assert_eq!(approved.evidence(), None);
        assert_eq!(
            approved_frame(&approved),
            Err(ControlError::ApprovalRequired)
        );
    }
}

/// The ways an approval pair can fail the agent's check.
#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    OtherCluster,
    OtherJob,
    NonceChanged,
    TimeChanged,
    Stale,
    Future,
    SameEvidenceTwice,
    SameStaffTwoPasskeys,
    Unpinned,
    NoUserVerification,
    OtherHost,
    SignatureFlipped,
}

const FAULTS: [Fault; 13] = [
    Fault::None,
    Fault::OtherCluster,
    Fault::OtherJob,
    Fault::NonceChanged,
    Fault::TimeChanged,
    Fault::Stale,
    Fault::Future,
    Fault::SameEvidenceTwice,
    Fault::SameStaffTwoPasskeys,
    Fault::Unpinned,
    Fault::NoUserVerification,
    Fault::OtherHost,
    Fault::SignatureFlipped,
];

fn destructive_job(g: &mut Gen) -> PgagentJob {
    let d = DbIdent::new(
        if g.bool() {
            CellDatabase::App
        } else {
            CellDatabase::Vault
        },
        CellId([g.u8_in(0..=255); 16]),
    );
    match g.usize_in(0..=2) {
        0 => PgagentJob::DropCellDatabase(d),
        1 => PgagentJob::DropRoles(d),
        _ => PgagentJob::SetNoLogin(RoleIdent::new(d, RoleName::Migrator).unwrap()),
    }
}

/// ADR-011 "fstp-pgagent checks both approvals again itself": over random
/// destructive jobs, times and one fault each, the agent admits the job
/// exactly when there is no fault. The faults cover the digest's cluster
/// and job, the challenge's nonce and time, the lifetime window, one
/// approval twice, one person with two passkeys, an unpinned passkey, an
/// assertion without user verification, another relying party and a
/// broken signature.
#[test]
fn adr011_pgagent_admits_exactly_two_valid_distinct_approvals() {
    check(
        "adr011_pgagent_admits_exactly_two_valid_distinct_approvals",
        |g| {
            let mut a = Passkey::new(1, 0xa1);
            let mut b = Passkey::new(2, 0xb2);
            let mut a2 = Passkey::new(1, 0xa3);
            let mut stranger = Passkey::new(9, 0xee);
            let job = destructive_job(g);
            let fault = FAULTS[g.usize_in(0..=FAULTS.len() - 1)];
            g.note("fault", &fault);
            let age = g.i64_in(0..=AGENT_APPROVAL_WINDOW_SECS);
            let issued = T0;
            let now = T0 + age;
            let mut ev_a = a.evidence(CLUSTER, &job, issued, 1);
            let mut ev_b = b.evidence(CLUSTER, &job, issued, 2);
            let mut at = now;
            match fault {
                Fault::None => {}
                Fault::OtherCluster => ev_b = b.evidence(ClusterId([0x32; 16]), &job, issued, 2),
                Fault::OtherJob => {
                    let other = match &job {
                        PgagentJob::DropRoles(d) => PgagentJob::DropCellDatabase(*d),
                        _ => PgagentJob::DropRoles(db(0x77)),
                    };
                    ev_a = a.evidence(CLUSTER, &other, issued, 1);
                }
                Fault::NonceChanged => ev_b.nonce[0] ^= 1,
                Fault::TimeChanged => ev_a.issued_at += 1,
                Fault::Stale => at = issued + AGENT_APPROVAL_WINDOW_SECS + 1 + age,
                Fault::Future => at = issued - AGENT_CLOCK_SKEW_SECS - 1 - age,
                Fault::SameEvidenceTwice => ev_b = ev_a.clone(),
                Fault::SameStaffTwoPasskeys => ev_b = a2.evidence(CLUSTER, &job, issued, 2),
                Fault::Unpinned => ev_b = stranger.evidence(CLUSTER, &job, issued, 2),
                Fault::NoUserVerification => {
                    let digest =
                        job_digest(&DestructiveJob::pgagent(CLUSTER, job.clone()).unwrap());
                    let c = approval_challenge(digest, issued, &ev_b.nonce);
                    ev_b.assertion = b.assert_for(&c, HOST, false);
                }
                Fault::OtherHost => {
                    let digest =
                        job_digest(&DestructiveJob::pgagent(CLUSTER, job.clone()).unwrap());
                    let c = approval_challenge(digest, issued, &ev_a.nonce);
                    ev_a.assertion = a.assert_for(&c, "other.example.test", true);
                }
                Fault::SignatureFlipped => ev_a.assertion.signature[3] ^= 1,
            }
            let mut check = agent(&[&a, &b, &a2]);
            let got = check.verify(&job, &[ev_a.clone(), ev_b.clone()], at);
            match fault {
                Fault::None => {
                    prop_assert_eq!(got.map(|v| v.job().clone()), Ok(job.clone()));
                }
                _ => {
                    prop_assert_eq!(got.map(|_| ()), Err(ControlError::ApprovalRequired));
                    // A refusal spends nothing: the valid pair still runs.
                    let fa = a.evidence(CLUSTER, &job, issued, 1);
                    let fb = b.evidence(CLUSTER, &job, issued, 2);
                    prop_assert!(check.verify(&job, &[fa, fb], now).is_ok());
                }
            }
            Ok(())
        },
    );
}

/// ADR-011 job table: the agent's check refuses a job that is not
/// destructive, which runs on one operator's request instead.
#[test]
fn adr011_pgagent_check_refuses_a_non_destructive_job() {
    let mut a = Passkey::new(1, 0xa1);
    let mut b = Passkey::new(2, 0xb2);
    let job = PgagentJob::CreateCellDatabase(db(3));
    let ev = |p: &mut Passkey, n| {
        let digest = fstp_crypto::sha256(b"not a destructive job");
        let nonce = [n; 32];
        let c = approval_challenge(fstp_control::approval::JobDigest(digest), T0, &nonce);
        ApprovalEvidence {
            issued_at: T0,
            nonce,
            assertion: p.assert(&c),
        }
    };
    let pair = [ev(&mut a, 1), ev(&mut b, 2)];
    assert!(matches!(
        agent(&[&a, &b]).verify(&job, &pair, T0),
        Err(ControlError::Job(_))
    ));
}

/// ADR-011: pinned approvers need a relying party host, at least one
/// passkey, and distinct credential ids.
#[test]
fn adr011_pgagent_pinned_approvers_are_checked() {
    let a = Passkey::new(1, 0xa1);
    let pinned = |host: &str, staff: Vec<StaffCredential>| PinnedApprovers {
        cluster: CLUSTER,
        operator_host: host.to_owned(),
        staff,
    };
    assert!(AgentApprovals::new(&pinned(HOST, vec![a.pinned()])).is_ok());
    assert!(AgentApprovals::new(&pinned(HOST, vec![])).is_err());
    assert!(AgentApprovals::new(&pinned(HOST, vec![a.pinned(), a.pinned()])).is_err());
    assert!(AgentApprovals::new(&pinned("not a host", vec![a.pinned()])).is_err());
}

/// TH-26, ADR-011: an approved frame round-trips, and every other frame
/// is refused: a plain job frame, a non-destructive job, a truncated or
/// longer frame, a field above its limit, and a frame above the limit.
#[test]
fn th26_approved_frame_codec_has_one_spelling() {
    let mut a = Passkey::new(1, 0xa1);
    let mut b = Passkey::new(2, 0xb2);
    let job = drop_db(5);
    let frame = ApprovedFrame {
        job: job.clone(),
        approvals: [
            a.evidence(CLUSTER, &job, T0, 1),
            b.evidence(CLUSTER, &job, T0, 2),
        ],
    };
    let bytes = encode_approved_job(&frame).unwrap();
    assert_eq!(decode_approved_job(&bytes), Ok(frame.clone()));
    for cut in 0..bytes.len() {
        assert!(decode_approved_job(&bytes[..cut]).is_err(), "cut {cut}");
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(decode_approved_job(&longer).is_err());
    assert!(decode_approved_job(&encode_pgagent_job(&job).unwrap()).is_err());
    let mut plain = frame.clone();
    plain.job = PgagentJob::CreateCellDatabase(db(5));
    assert!(encode_approved_job(&plain).is_err());
    // The same bytes with a non-destructive job frame inside.
    let inner = encode_pgagent_job(&plain.job).unwrap();
    let mut forged = vec![APPROVED_VERSION];
    forged.extend_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
    forged.extend_from_slice(&inner);
    let job_len = 2 + encode_pgagent_job(&job).unwrap().len();
    forged.extend_from_slice(&bytes[1 + job_len..]);
    assert!(decode_approved_job(&forged).is_err());
    let mut big = frame.clone();
    big.approvals[0].assertion.client_data_json = vec![b'x'; 4096];
    assert!(encode_approved_job(&big).is_err());
    let mut empty = frame;
    empty.approvals[1].assertion.credential_id.clear();
    assert!(encode_approved_job(&empty).is_err());
    assert!(decode_approved_job(&vec![APPROVED_VERSION; MAX_APPROVED_LEN + 1]).is_err());
}

/// R-SW-02, ADR-011 "DDL identifier grammar": a verified drop renders one
/// `DROP DATABASE IF EXISTS ... WITH (FORCE)` of the cell's quoted name
/// in the maintenance database. A verified role drop refuses while the
/// database exists and drops exactly the plan's roles of that database.
/// `SetNoLogin` sets NOLOGIN, then ends the role's sessions.
#[test]
fn r_sw_02_verified_destructive_jobs_render_the_drop_statements() {
    let mut a = Passkey::new(1, 0xa1);
    let mut b = Passkey::new(2, 0xb2);
    let mut check = agent(&[&a, &b]);
    let mut verified = |job: PgagentJob, n: u8| {
        let pair = [
            a.evidence(CLUSTER, &job, T0, n),
            b.evidence(CLUSTER, &job, T0, n.wrapping_add(100)),
        ];
        check.verify(&job, &pair, T0).unwrap()
    };
    let cell = CellId([0x5c; 16]);
    let d = DbIdent::new(CellDatabase::Vault, cell);
    let s = fstp_control::pgagent::destructive_statements(&verified(
        PgagentJob::DropCellDatabase(d),
        1,
    ))
    .unwrap();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].target, Target::Maintenance);
    assert_eq!(
        s[0].sql,
        format!(
            "DROP DATABASE IF EXISTS \"v_{}\" WITH (FORCE)",
            "5c".repeat(16)
        )
    );

    let s = fstp_control::pgagent::destructive_statements(&verified(PgagentJob::DropRoles(d), 2))
        .unwrap();
    assert_eq!(s.len(), 1);
    assert!(s[0].sql.contains(&format!("datname = '{}'", d.name())));
    assert!(s[0].sql.contains("RAISE EXCEPTION"));
    let plan = cell_role_plan(cell).unwrap();
    let mut want = 0;
    for r in plan
        .roles
        .iter()
        .filter(|r| r.database == CellDatabase::Vault)
    {
        let role = RoleIdent::new(d, r.role).unwrap();
        assert!(
            s[0].sql.contains(&format!("DROP ROLE {};", role.render())),
            "{}",
            role.name()
        );
        want += 1;
    }
    assert_eq!(s[0].sql.matches("DROP ROLE").count(), want);
    assert!(
        !s[0].sql.contains("\"c_") && !s[0].sql.contains("'c_"),
        "an application name in a vault drop"
    );

    let r = RoleIdent::new(d, RoleName::Vault).unwrap();
    let s = fstp_control::pgagent::destructive_statements(&verified(PgagentJob::SetNoLogin(r), 3))
        .unwrap();
    assert_eq!(s.len(), 2);
    assert!(
        s[0].sql
            .contains(&format!("ALTER ROLE {} NOLOGIN", r.render()))
    );
    assert!(s[1].sql.contains("pg_terminate_backend"));
    assert!(s[1].sql.contains(&format!("usename = '{}'", r.name())));
}

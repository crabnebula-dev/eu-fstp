//! R-SW-02, ADR-011 "Two-operator approval", ADR-004 "Decided by Daniel,
//! 2026-11-15 (late)": one batch approval per operator per erasure. Each
//! of the two operators approves once, with a passkey, over a signed list
//! of all the erasure's job digests. The two-operator rule is unchanged,
//! and `fstp-pgagent` checks again that each job digest is in an approved
//! batch. Lane m3/erase-prod, written before the batch code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_control::ControlError;
use fstp_control::agent::approved_frame;
use fstp_control::approval::{
    AgentApprovals, ApprovalBatch, ApprovalEvent, ApprovedJob, DestructiveJob, JobDigest,
    MAX_BATCH, PinnedApprovers, batch_challenge, job_digest,
};
use fstp_control::erase::{erasure_batch, erasure_jobs};
use fstp_control::operator::{OperatorLogin, OperatorSession, Purpose, StaffCredential};
use fstp_control::pg::CellDatabase;
use fstp_control::pgagent::{
    APPROVED_VERSION, DbIdent, PgagentJob, decode_approved_job, encode_approved_job,
};
use fstp_control::placement::{Cluster, ClusterId, ClusterKind, Placement};
use fstp_cp_proto::{CellId, StaffRef};
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_webauthn::{AssertionResponse, CoseKey};

const HOST: &str = "control.example.test";
const T0: i64 = 1_800_000_000;
const APP: ClusterId = ClusterId([0xa0; 16]);
const VAULT: ClusterId = ClusterId([0xb0; 16]);
const CELL: CellId = CellId([0x5c; 16]);

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

    fn assert(&mut self, challenge: &[u8; 32]) -> AssertionResponse {
        self.count += 1;
        let mut auth = fstp_crypto::sha256(HOST.as_bytes()).to_vec();
        auth.push(0x05);
        auth.extend_from_slice(&self.count.to_be_bytes());
        let b64 = fstp_pgwire::base64::encode(challenge)
            .replace('+', "-")
            .replace('/', "_")
            .replace('=', "");
        let client = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{b64}\",\"origin\":\"https://{HOST}\"}}"
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
}

fn placement() -> Placement {
    Placement::new(
        &Cluster {
            id: APP,
            kind: ClusterKind::Application,
        },
        &Cluster {
            id: VAULT,
            kind: ClusterKind::Vault,
        },
    )
    .unwrap()
}

struct Operators {
    login: OperatorLogin,
    a: (Passkey, OperatorSession),
    b: (Passkey, OperatorSession),
}

impl Operators {
    fn new() -> Operators {
        let mut a = Passkey::new(1, 0xa1);
        let mut b = Passkey::new(2, 0xb2);
        let mut login = OperatorLogin::new(HOST, &[a.pinned(), b.pinned()]).unwrap();
        let mut session = |p: &mut Passkey| {
            let c = login.begin(Purpose::Login, T0).unwrap();
            login.finish_login(c, &p.assert(&c), T0).unwrap().0
        };
        let sa = session(&mut a);
        let sb = session(&mut b);
        Operators {
            login,
            a: (a, sa),
            b: (b, sb),
        }
    }

    /// Each operator approves the batch of `jobs` once.
    fn approve_batch(&mut self, jobs: &[DestructiveJob]) {
        for (p, s) in [&mut self.a, &mut self.b] {
            let c = self.login.begin_batch_approval(*s, jobs, T0 + 1).unwrap();
            let assertion = p.assert(&c);
            self.login
                .finish_approval(*s, c, &assertion, T0 + 1)
                .unwrap();
        }
    }

    fn agent(&self, cluster: ClusterId) -> AgentApprovals {
        AgentApprovals::new(&PinnedApprovers {
            cluster,
            operator_host: HOST.to_owned(),
            staff: vec![self.a.0.pinned(), self.b.0.pinned()],
        })
        .unwrap()
    }
}

/// R-SW-02, ADR-004 (2026-11-15 late): each operator approves the
/// erasure once, over the batch of its five job digests. Every job of the
/// batch is then admitted once, each with both operators' approvals,
/// and the log holds one batch approval per operator. A job outside the
/// batch, and a job of the batch asked for again, are refused.
#[test]
fn r_sw_02_one_batch_approval_per_operator_admits_every_erasure_job_once() {
    let mut ops = Operators::new();
    let jobs = erasure_jobs(CELL, &placement()).unwrap();
    assert_eq!(jobs.len(), 5);
    ops.approve_batch(&jobs);
    let batch = erasure_batch(CELL, &placement()).unwrap();
    let approved: Vec<ApprovedJob> = jobs
        .iter()
        .map(|j| ops.login.authorise_destructive(ops.a.1, j, T0 + 2).unwrap())
        .collect();
    for a in &approved {
        assert_eq!(a.approvers(), [ops.a.0.staff, ops.b.0.staff]);
        let ev = a.evidence().expect("both approvals carry evidence");
        for e in ev {
            assert_eq!(e.batch.as_ref(), Some(&batch));
        }
    }
    let batches = ops
        .login
        .approval_log()
        .iter()
        .filter(|e| matches!(e, ApprovalEvent::ApprovedBatch { jobs: 5, .. }))
        .count();
    assert_eq!(batches, 2, "not one batch approval per operator");
    assert_eq!(
        ops.login.authorise_destructive(ops.a.1, &jobs[1], T0 + 3),
        Err(ControlError::ApprovalRequired),
        "a job of the batch ran twice"
    );
    let outside = DestructiveJob::EraseCell {
        cell: CellId([0x5d; 16]),
    };
    assert_eq!(
        ops.login.authorise_destructive(ops.a.1, &outside, T0 + 3),
        Err(ControlError::ApprovalRequired),
        "a job outside the batch ran"
    );
}

/// ADR-011, unchanged by ADR-004 (2026-11-15 late): one operator's batch
/// approval alone admits no job, and a second batch approval of the same
/// operator does not stand in for the other.
#[test]
fn r_sw_02_batch_approval_keeps_the_two_operator_rule() {
    let mut ops = Operators::new();
    let jobs = erasure_jobs(CELL, &placement()).unwrap();
    for _ in 0..2 {
        let c = ops
            .login
            .begin_batch_approval(ops.a.1, &jobs, T0 + 1)
            .unwrap();
        let assertion = ops.a.0.assert(&c);
        ops.login
            .finish_approval(ops.a.1, c, &assertion, T0 + 1)
            .unwrap();
    }
    for j in &jobs {
        assert_eq!(
            ops.login.authorise_destructive(ops.a.1, j, T0 + 2),
            Err(ControlError::ApprovalRequired)
        );
    }
}

/// R-SW-02, ADR-011, ADR-004 (2026-11-15 late): the agent admits both
/// drops of one cluster on the same two batch approvals, each once, after
/// the frame codec. It refuses a frame whose batch does not list the job,
/// a batch whose list was changed after the assertion, and a job sent
/// again.
#[test]
fn r_sw_02_pgagent_checks_each_job_digest_is_in_the_approved_batch() {
    let mut ops = Operators::new();
    let jobs = erasure_jobs(CELL, &placement()).unwrap();
    ops.approve_batch(&jobs);
    let approved: Vec<ApprovedJob> = jobs
        .iter()
        .map(|j| ops.login.authorise_destructive(ops.a.1, j, T0 + 2).unwrap())
        .collect();
    let mut app = ops.agent(APP);
    for a in &approved[1..3] {
        let bytes = encode_approved_job(&approved_frame(a).unwrap()).unwrap();
        assert_eq!(bytes[0], APPROVED_VERSION);
        let frame = decode_approved_job(&bytes).unwrap();
        assert!(frame.approvals.iter().all(|e| e.batch.is_some()));
        assert!(app.verify(&frame.job, &frame.approvals, T0 + 3).is_ok());
        assert_eq!(
            app.verify(&frame.job, &frame.approvals, T0 + 3).map(|_| ()),
            Err(ControlError::ApprovalRequired),
            "a job ran twice on one batch approval"
        );
    }
    // The vault drop on the application agent: its digest names the vault
    // cluster, so the batch lists no such job here.
    let vault_frame = approved_frame(&approved[3]).unwrap();
    assert_eq!(
        app.verify(&vault_frame.job, &vault_frame.approvals, T0 + 3)
            .map(|_| ()),
        Err(ControlError::ApprovalRequired)
    );
    // A job the batch does not list, on the right agent.
    let other = PgagentJob::DropCellDatabase(DbIdent::new(CellDatabase::App, CellId([9; 16])));
    assert_eq!(
        app.verify(&other, &vault_frame.approvals, T0 + 3)
            .map(|_| ()),
        Err(ControlError::ApprovalRequired)
    );
    // A list changed after the assertions: one digest swapped.
    let mut vault = ops.agent(VAULT);
    let mut changed = vault_frame.clone();
    for e in &mut changed.approvals {
        let mut digests = e.batch.as_ref().unwrap().digests().to_vec();
        digests[0] = JobDigest([0xee; 32]);
        e.batch = Some(ApprovalBatch::new(digests).unwrap());
    }
    assert_eq!(
        vault
            .verify(&changed.job, &changed.approvals, T0 + 3)
            .map(|_| ()),
        Err(ControlError::ApprovalRequired)
    );
    // The untouched frame still runs: a refusal spends nothing.
    assert!(
        vault
            .verify(&vault_frame.job, &vault_frame.approvals, T0 + 3)
            .is_ok()
    );
}

/// TH-26, ADR-004 (2026-11-15 late): a batch holds 1 to `MAX_BATCH`
/// distinct digests, its digest has one spelling per list, and the frame
/// codec refuses a batch count above the limit or a digest listed twice.
#[test]
fn th26_approval_batch_bounds_and_frame_codec() {
    let d = |n: u8| JobDigest([n; 32]);
    assert!(ApprovalBatch::new(Vec::new()).is_err());
    assert!(ApprovalBatch::new(vec![d(1), d(1)]).is_err());
    assert!(ApprovalBatch::new((0..=MAX_BATCH as u8).map(d).collect()).is_err());
    let full = ApprovalBatch::new((0..MAX_BATCH as u8).map(d).collect()).unwrap();
    let ab = ApprovalBatch::new(vec![d(1), d(2)]).unwrap();
    let ba = ApprovalBatch::new(vec![d(2), d(1)]).unwrap();
    assert_ne!(ab.digest(), ba.digest());
    assert!(ab.same_jobs(&ba));
    assert_ne!(
        batch_challenge(&ab, T0, &[0; 32]),
        batch_challenge(&ab, T0 + 1, &[0; 32])
    );

    let mut ops = Operators::new();
    let job = DestructiveJob::pgagent(
        APP,
        PgagentJob::DropRoles(DbIdent::new(CellDatabase::App, CELL)),
    )
    .unwrap();
    ops.approve_batch(std::slice::from_ref(&job));
    let a = ops
        .login
        .authorise_destructive(ops.a.1, &job, T0 + 2)
        .unwrap();
    let mut frame = approved_frame(&a).unwrap();
    let bytes = encode_approved_job(&frame).unwrap();
    assert_eq!(decode_approved_job(&bytes), Ok(frame.clone()));
    for cut in 0..bytes.len() {
        assert!(decode_approved_job(&bytes[..cut]).is_err(), "cut {cut}");
    }
    let mut v2 = bytes.clone();
    v2[0] = 2;
    assert!(
        decode_approved_job(&v2).is_err(),
        "a version 2 frame decoded"
    );
    frame.approvals[0].batch = Some(full);
    let wide = encode_approved_job(&frame).unwrap();
    assert!(decode_approved_job(&wide).is_ok());
    // The first approval's batch count octet follows the version octet,
    // the job field, the time and the nonce.
    let job_len = 2 + usize::from(u16::from_be_bytes([wide[1], wide[2]]));
    let count_at = 1 + job_len + 8 + 32;
    assert_eq!(usize::from(wide[count_at]), MAX_BATCH);
    let mut over = wide.clone();
    over[count_at] = u8::try_from(MAX_BATCH + 1).unwrap();
    over.splice(count_at + 1..count_at + 1, [0u8; 32]);
    assert!(decode_approved_job(&over).is_err());
    let mut twice = wide;
    let first = twice[count_at + 1..count_at + 33].to_vec();
    twice.splice(count_at + 33..count_at + 65, first);
    assert!(decode_approved_job(&twice).is_err());
    let _ = job_digest(&job);
}

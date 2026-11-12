//! The first-admin invitation, its enrolment and the verified step-up
//! admission (design sections 8.3, 8.4 and 9.2 step 10, G10, Q35, I-78).
//! Lane int5.
//!
//! The registrations and assertions here are real WebAuthn bytes over an
//! Ed25519 key from `fstp_crypto::sig`, written by the small builders
//! below. The crate's integration tests cannot reach the inputs a gate
//! admission sets, so these tests live beside the code.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_auth::ceremony::{InvitationProof, Registration, split_token_digest, token_digest};
use fstp_auth::codec::Token;
use fstp_auth::recovery::Deployment;
use fstp_auth::stepup::StepUpRequest;
use fstp_auth::{AuthRecord, Method, SessionView};
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_domain::id::AccountId;
use fstp_domain::oracle::Answers;
use fstp_domain::time::Timestamp;
use fstp_ledger::{MemStore, RecordStore, Seq};
use fstp_webauthn::{AssertionResponse, RegistrationResponse, RelyingParty};

use crate::gate::{self, Action, Deny, Principal, RouteDeny};
use crate::tenant::{TenantCommand, TenantRecord};
use crate::{CellCommand, CellRecord, CellState, SystemTask};

const HOST: &str = "tenant-c.fstp.test";
const CELL: [u8; 16] = [0xCE; 16];
const NOW: Timestamp = Timestamp::from_micros(1_800_000_000_000_000);
const ADMIN: AccountId = AccountId::from_raw(0xA0A0);
const FIRST: [u8; 32] = [0x01; 32];
const SECOND: [u8; 32] = [0x02; 32];
const INVITATION: [u8; 16] = [0x1A; 16];

fn rp() -> RelyingParty {
    RelyingParty::new(HOST).unwrap()
}

fn base64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for chunk in b.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, x)| n | (u32::from(*x) << (16 - 8 * i)));
        for k in 0..=chunk.len() {
            s.push(char::from(
                A[usize::try_from((n >> (18 - 6 * k)) & 63).unwrap()],
            ));
        }
    }
    s
}

fn cbor_head(out: &mut Vec<u8>, major: u8, n: usize) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | u8::try_from(n).unwrap()),
        24..=255 => out.extend([m | 24, u8::try_from(n).unwrap()]),
        _ => {
            out.push(m | 25);
            out.extend(u16::try_from(n).unwrap().to_be_bytes());
        }
    }
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_head(out, 2, b.len());
    out.extend_from_slice(b);
}

fn cbor_text(out: &mut Vec<u8>, t: &str) {
    cbor_head(out, 3, t.len());
    out.extend_from_slice(t.as_bytes());
}

/// A software passkey: an Ed25519 key and a credential id.
struct Passkey {
    key: Ed25519SigningKey,
    id: Vec<u8>,
    counter: u32,
}

impl Passkey {
    fn new() -> Passkey {
        Passkey {
            key: Ed25519SigningKey::generate().unwrap(),
            id: fstp_crypto::random_array::<16>().unwrap().to_vec(),
            counter: 0,
        }
    }

    /// A `none` registration over `challenge` on the cell origin, with UP
    /// and, when `uv` holds, UV.
    fn registration(&self, challenge: [u8; 32], uv: bool) -> RegistrationResponse {
        let client = format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://{HOST}\",\"crossOrigin\":false}}",
            base64url(&challenge)
        )
        .into_bytes();
        // COSE_Key: {1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: x}.
        let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21];
        cbor_bytes(&mut cose, &self.key.public_key());
        let mut auth = fstp_crypto::sha256(HOST.as_bytes()).to_vec();
        auth.push(if uv { 0x01 | 0x04 | 0x40 } else { 0x01 | 0x40 });
        auth.extend(0u32.to_be_bytes());
        auth.extend([0u8; 16]);
        auth.extend(u16::try_from(self.id.len()).unwrap().to_be_bytes());
        auth.extend(&self.id);
        auth.extend(cose);
        let mut att = Vec::new();
        cbor_head(&mut att, 5, 3);
        cbor_text(&mut att, "fmt");
        cbor_text(&mut att, "none");
        cbor_text(&mut att, "attStmt");
        cbor_head(&mut att, 5, 0);
        cbor_text(&mut att, "authData");
        cbor_bytes(&mut att, &auth);
        RegistrationResponse {
            client_data_json: client,
            attestation_object: att,
        }
    }

    /// An assertion over `challenge` with UP and UV and the next counter.
    fn assertion(&mut self, challenge: [u8; 32]) -> AssertionResponse {
        self.counter += 1;
        let client = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://{HOST}\",\"crossOrigin\":false}}",
            base64url(&challenge)
        )
        .into_bytes();
        let mut auth = fstp_crypto::sha256(HOST.as_bytes()).to_vec();
        auth.push(0x01 | 0x04);
        auth.extend(self.counter.to_be_bytes());
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

/// Folds `batches`, each `(at, command id, records)`, from genesis,
/// through a `MemStore` that numbers the entries.
fn state_of(batches: &[(Timestamp, [u8; 16], Vec<CellRecord>)]) -> CellState {
    let mut store: MemStore<CellRecord> = MemStore::new();
    for (at, command, records) in batches {
        store
            .append(store.head(), at.micros(), *command, records.clone())
            .unwrap();
    }
    let mut entries = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut entries).unwrap();
    crate::replay(&entries).unwrap()
}

/// The provisioning batch of the split first-admin invitation of `ADMIN`.
fn issued_split() -> (Timestamp, [u8; 16], Vec<CellRecord>) {
    (
        NOW,
        crate::system_command_id(*b"inv-0001"),
        vec![CellRecord::Auth(AuthRecord::InvitationIssued {
            invitation: INVITATION,
            account: ADMIN,
            token_digest: split_token_digest(&Token(FIRST), &Token(SECOND)),
            first_admin: true,
            split: true,
        })],
    )
}

fn halves() -> InvitationProof {
    InvitationProof::Halves(Token(FIRST), Token(SECOND))
}

/// Admits and decides the enrolment of `key` through `proof` at `at`.
fn enrol(
    s: &CellState,
    proof: &InvitationProof,
    key: &Passkey,
    uv: bool,
    at: Timestamp,
) -> Result<Vec<CellRecord>, String> {
    let challenge = [0x5C; 32];
    let response = key.registration(challenge, uv);
    let rp = rp();
    let reg = Registration {
        response: &response,
        rp: &rp,
        challenge,
    };
    let admitted = gate::admit_invitation_enrolment(s, proof, &reg, [0x77; 16], at)
        .map_err(|e| format!("{e:?}"))?;
    let Principal::Ceremony(account) = admitted.principal() else {
        return Err("not a ceremony principal".to_owned());
    };
    let Action::Command(c) = admitted.action() else {
        return Err("not a command".to_owned());
    };
    crate::decide_with_inputs(
        s,
        c,
        &crate::CellCtx {
            actor: account,
            at: at.micros(),
        },
        [0x77; 16],
        admitted.inputs(),
        &Answers::new(),
    )
    .map_err(|e| format!("{e:?}"))
}

/// G10, Q35, design sections 8.3 and 9.2 step 10: the split first-admin
/// invitation enrols its passkey only with both halves, first half first.
/// The batch consumes the invitation, registers the verified key with UV,
/// records `FirstAdminEnrolled` and grants the tenant admin role.
#[test]
fn g10_split_invitation_enrols_the_first_admin_with_both_halves() {
    let s = state_of(&[issued_split()]);
    let key = Passkey::new();
    let batch = enrol(&s, &halves(), &key, true, NOW).unwrap();
    assert_eq!(batch.len(), 4, "{batch:?}");
    assert_eq!(
        batch[0],
        CellRecord::Auth(AuthRecord::InvitationConsumed {
            invitation: INVITATION
        })
    );
    assert!(matches!(
        &batch[1],
        CellRecord::Auth(AuthRecord::CredentialRegistered { account, credential, user_verified: true, .. })
            if *account == ADMIN && *credential == key.id
    ));
    assert_eq!(
        batch[2],
        CellRecord::Auth(AuthRecord::FirstAdminEnrolled { account: ADMIN })
    );
    assert_eq!(
        batch[3],
        CellRecord::Tenant(TenantRecord::TenantAdminGranted { account: ADMIN })
    );
    let after = state_of(&[issued_split(), (NOW, [0x77; 16], batch)]);
    assert!(after.tenant().is_admin(ADMIN));
    assert!(after.auth().first_admin_enrolled(ADMIN));
    assert!(after.auth().has_credential(ADMIN, &key.id));
    assert!(
        after
            .auth()
            .invitation(INVITATION)
            .is_some_and(|i| i.consumed)
    );
}

/// G10, Q35: one half alone, the halves swapped, a wrong half and the
/// split token given as one token are all refused, and nothing is
/// admitted.
#[test]
fn g10_split_invitation_refuses_any_other_proof() {
    let s = state_of(&[issued_split()]);
    let key = Passkey::new();
    for proof in [
        InvitationProof::Halves(Token(SECOND), Token(FIRST)),
        InvitationProof::Halves(Token(FIRST), Token([0x03; 32])),
        InvitationProof::Token(Token(FIRST)),
        InvitationProof::Token(Token(SECOND)),
    ] {
        assert!(
            enrol(&s, &proof, &key, true, NOW).is_err(),
            "{proof:?} enrolled"
        );
    }
}

/// G10, ADR-008: a used invitation, one older than 72 hours and a first
/// admin's registration without UV are refused.
#[test]
fn g10_invitation_enrolment_refuses_used_expired_and_no_uv() {
    let s = state_of(&[issued_split()]);
    let key = Passkey::new();
    let batch = enrol(&s, &halves(), &key, true, NOW).unwrap();
    let used = state_of(&[issued_split(), (NOW, [0x77; 16], batch)]);
    assert!(enrol(&used, &halves(), &Passkey::new(), true, NOW).is_err());
    let late = Timestamp::from_micros(NOW.micros() + fstp_auth::ceremony::INVITATION_US + 1);
    assert!(enrol(&s, &halves(), &Passkey::new(), true, late).is_err());
    assert!(enrol(&s, &halves(), &Passkey::new(), false, NOW).is_err());
}

/// Design section 8.3, I-77: no session admits an enrolment or a
/// provisioning invitation, so `CellEngine::execute` reaches them only
/// through their own admissions.
#[test]
fn i77_enrolment_and_provisioning_never_come_through_a_session() {
    let s = state_of(&[issued_split()]);
    let session = SessionView {
        id: [0x5E; 16],
        account: ADMIN,
        method: Method::Passkey,
        started: NOW,
        last_used: NOW,
    };
    let policy = gate::LoginPolicy {
        stepup_freshness_us: crate::tenant::P71_DEFAULT_US,
    };
    for c in [
        CellCommand::Tenant(TenantCommand::EnrolByInvitation {
            invitation: INVITATION,
            credential: vec![1, 2],
        }),
        CellCommand::Tenant(TenantCommand::IssueFirstAdminInvitation {
            invitation: [0x2B; 16],
            account: AccountId::from_raw(9),
            token_digest: [0; 32],
        }),
    ] {
        assert_eq!(
            gate::admit_command(
                &s,
                &session,
                Action::Command(c),
                [1; 16],
                None,
                NOW,
                &policy
            )
            .err(),
            Some(Deny::NotPermitted)
        );
    }
}

/// Admits and decides `IssueFirstAdminInvitation` on `s` in `mode`.
fn provision(
    s: &CellState,
    invitation: [u8; 16],
    account: AccountId,
    digest: [u8; 32],
    mode: Deployment,
    at: Timestamp,
) -> Result<Vec<CellRecord>, String> {
    let id = crate::system_command_id(*b"inv-test");
    let admitted = gate::admit_first_admin_invitation(s, invitation, account, digest, mode, id, at)
        .map_err(|e| format!("{e:?}"))?;
    let Action::Command(c) = admitted.action() else {
        return Err("not a command".to_owned());
    };
    crate::decide_system_with_inputs(
        s,
        c,
        &crate::SystemCtx {
            task: SystemTask::Provisioning,
            at: at.micros(),
        },
        id,
        admitted.inputs(),
        &Answers::new(),
    )
    .map_err(|e| format!("{e:?}"))
}

/// ADR-008 "Ceremonies and the first passkey", Q35, design section 9.2
/// step 10: provisioning records one first-admin invitation, split on a
/// SaaS cell and whole on a self-hosted one. While it is open, and once
/// the first admin enrolled, no second one is issued. An expired one does
/// not block a new one.
#[test]
fn adr008_provisioning_issues_one_first_admin_invitation() {
    let digest = split_token_digest(&Token(FIRST), &Token(SECOND));
    let saas = provision(
        &CellState::genesis(),
        INVITATION,
        ADMIN,
        digest,
        Deployment::Saas,
        NOW,
    )
    .unwrap();
    assert_eq!(saas, issued_split().2);
    let whole = provision(
        &CellState::genesis(),
        INVITATION,
        ADMIN,
        token_digest(&Token(FIRST)),
        Deployment::SelfHosted,
        NOW,
    )
    .unwrap();
    assert!(matches!(
        &whole[..],
        [CellRecord::Auth(AuthRecord::InvitationIssued {
            first_admin: true,
            split: false,
            ..
        })]
    ));
    let open = state_of(&[issued_split()]);
    let other = AccountId::from_raw(0xB0B0);
    assert!(provision(&open, [0x2B; 16], other, [7; 32], Deployment::Saas, NOW).is_err());
    let late = Timestamp::from_micros(NOW.micros() + fstp_auth::ceremony::INVITATION_US + 1);
    assert!(provision(&open, [0x2B; 16], other, [7; 32], Deployment::Saas, late).is_ok());
    let batch = enrol(&open, &halves(), &Passkey::new(), true, NOW).unwrap();
    let enrolled = state_of(&[issued_split(), (NOW, [0x77; 16], batch)]);
    assert!(
        provision(
            &enrolled,
            [0x2B; 16],
            other,
            [7; 32],
            Deployment::Saas,
            late
        )
        .is_err()
    );
    // An account a record names already is no invitee (ADR-008).
    assert!(
        provision(
            &enrolled,
            [0x2C; 16],
            ADMIN,
            [8; 32],
            Deployment::Saas,
            late
        )
        .is_err()
    );
}

/// ADR-008 "Ceremonies and the first passkey", design section 9.2 step
/// 10: an invitation that no enrolment used does not make its account
/// known (`invitee_new` of `fstp_auth::ceremony::issue_invitation`). Once
/// the first-admin invitation of `ADMIN` expired unused, provisioning may
/// invite `ADMIN` again. Once an enrolment used it, `ADMIN` is known.
#[test]
fn adr008_unused_invitation_does_not_make_its_account_known() {
    let open = state_of(&[issued_split()]);
    let late = Timestamp::from_micros(NOW.micros() + fstp_auth::ceremony::INVITATION_US + 1);
    let again = provision(&open, [0x2B; 16], ADMIN, [7; 32], Deployment::Saas, late);
    assert!(
        matches!(
            again.as_deref(),
            Ok([CellRecord::Auth(AuthRecord::InvitationIssued { account, first_admin: true, .. })])
                if *account == ADMIN
        ),
        "{again:?}"
    );
    let batch = enrol(&open, &halves(), &Passkey::new(), true, NOW).unwrap();
    let enrolled = state_of(&[issued_split(), (NOW, [0x77; 16], batch)]);
    assert!(enrolled.auth().names_account(ADMIN));
}

/// I-78, design section 8.4: a verified step-up assertion admits
/// `GrantStepUp` under the challenge id as its command id, and the batch
/// records `StepUpGranted` under that id. An assertion over another
/// challenge, of another account's key, or in a magic-link session is
/// refused.
#[test]
fn i78_verified_stepup_is_admitted_under_its_challenge_id() {
    let s0 = state_of(&[issued_split()]);
    let mut key = Passkey::new();
    let batch = enrol(&s0, &halves(), &key, true, NOW).unwrap();
    let s = state_of(&[issued_split(), (NOW, [0x77; 16], batch)]);
    let session = SessionView {
        id: [0x5E; 16],
        account: ADMIN,
        method: Method::Passkey,
        started: NOW,
        last_used: NOW,
    };
    let req = StepUpRequest {
        id: [0xC1; 16],
        cell: CELL,
        action_digest: [0x46; 32],
        nonce: [0x0E; 32],
        rp: rp(),
    };
    let challenge = fstp_auth::stepup::challenge(CELL, session.id, req.action_digest, req.nonce);
    let assertion = key.assertion(challenge);
    let (admitted, granted) =
        gate::admit_verified_stepup(&s, &session, &req, &assertion, 0, NOW).unwrap();
    assert_eq!(admitted.command_id(), Some(req.id));
    assert_eq!(granted.stepup.id, req.id);
    let Action::Command(c) = admitted.action() else {
        panic!("not a command");
    };
    let records = crate::decide_with_id(
        &s,
        c,
        &crate::CellCtx {
            actor: ADMIN,
            at: NOW.micros(),
        },
        req.id,
        &Answers::new(),
    )
    .unwrap();
    assert_eq!(
        records,
        vec![CellRecord::Auth(AuthRecord::StepUpGranted {
            id: req.id,
            action_digest: req.action_digest,
            session: session.id,
        })]
    );
    // Another challenge.
    let other = key.assertion([0x99; 32]);
    assert!(matches!(
        gate::admit_verified_stepup(&s, &session, &req, &other, 0, NOW),
        Err(RouteDeny::StepUp(_))
    ));
    // A key the ledger never registered.
    let mut stranger = Passkey::new();
    let foreign = stranger.assertion(challenge);
    assert_eq!(
        gate::admit_verified_stepup(&s, &session, &req, &foreign, 0, NOW).err(),
        Some(RouteDeny::UnknownCredential)
    );
    // A magic-link session never steps up.
    let magic = SessionView {
        method: Method::MagicLink,
        ..session
    };
    let again = key.assertion(challenge);
    assert!(gate::admit_verified_stepup(&s, &magic, &req, &again, 0, NOW).is_err());
}

/// The first admin enrolled, so `ADMIN` is a tenant admin.
fn with_admin() -> Vec<(Timestamp, [u8; 16], Vec<CellRecord>)> {
    let open = state_of(&[issued_split()]);
    let batch = enrol(&open, &halves(), &Passkey::new(), true, NOW).unwrap();
    vec![issued_split(), (NOW, [0x77; 16], batch)]
}

/// Decides `IssueInvitation` by `actor`, with the step-up instant `stepup`.
fn issue(
    s: &CellState,
    actor: AccountId,
    invitation: [u8; 16],
    account: AccountId,
    token: [u8; 32],
    stepup: Option<Timestamp>,
) -> Result<Vec<CellRecord>, String> {
    let c = CellCommand::Tenant(TenantCommand::IssueInvitation {
        invitation,
        account,
        token_digest: token_digest(&Token(token)),
    });
    crate::decide::decide_with(
        s,
        &c,
        crate::decide::Who::Account(actor),
        NOW.micros(),
        Some([0x88; 16]),
        stepup,
        &crate::inputs::RouteInputs::none(),
        &Answers::new(),
    )
    .map_err(|e| format!("{e:?}"))
}

/// `authentication.md` "First passkey", design section 8.3 ceremony 1,
/// I-78: a tenant admin's invitation needs a step-up. The gate classes
/// `IssueInvitation` as `ManagementRoleChange`, so a session without a
/// step-up is refused, and the decider refuses a batch without one too.
#[test]
fn i78_tenant_admin_invitation_needs_a_step_up() {
    let s = state_of(&with_admin());
    let invitee = AccountId::from_raw(0xB1B1);
    let c = CellCommand::Tenant(TenantCommand::IssueInvitation {
        invitation: [0x2D; 16],
        account: invitee,
        token_digest: [9; 32],
    });
    assert_eq!(
        gate::HighRiskAction::of(&Action::Command(c.clone())),
        Ok(Some(gate::HighRiskAction::ManagementRoleChange))
    );
    let session = SessionView {
        id: [0x5E; 16],
        account: ADMIN,
        method: Method::Passkey,
        started: NOW,
        last_used: NOW,
    };
    let policy = gate::LoginPolicy {
        stepup_freshness_us: crate::tenant::P71_DEFAULT_US,
    };
    assert_eq!(
        gate::admit_command(
            &s,
            &session,
            Action::Command(c),
            [1; 16],
            None,
            NOW,
            &policy
        )
        .err(),
        Some(Deny::StepUpRequired(
            gate::HighRiskAction::ManagementRoleChange
        ))
    );
    assert!(issue(&s, ADMIN, [0x2D; 16], invitee, [5; 32], None).is_err());
}

/// Design section 8.3 ceremony 1, ADR-008: a tenant admin with a step-up
/// issues a whole, non-first-admin invitation for a new account. Its
/// invitee enrols with the one token and a UV passkey. A non-admin, a
/// reused invitation id and an account a record names are refused.
#[test]
fn adr008_tenant_admin_invitation_enrols_a_new_account() {
    let base = with_admin();
    let s = state_of(&base);
    let invitee = AccountId::from_raw(0xB1B1);
    let token = [0x44; 32];
    let batch = issue(&s, ADMIN, [0x2D; 16], invitee, token, Some(NOW)).unwrap();
    assert_eq!(
        batch,
        vec![CellRecord::Auth(AuthRecord::InvitationIssued {
            invitation: [0x2D; 16],
            account: invitee,
            token_digest: token_digest(&Token(token)),
            first_admin: false,
            split: false,
        })]
    );
    assert!(
        issue(
            &s,
            invitee,
            [0x2E; 16],
            AccountId::from_raw(3),
            token,
            Some(NOW)
        )
        .is_err()
    );
    assert!(issue(&s, ADMIN, [0x2F; 16], ADMIN, token, Some(NOW)).is_err());
    let mut log = base.clone();
    log.push((NOW, [0x88; 16], batch));
    let issued = state_of(&log);
    assert!(
        issue(
            &issued,
            ADMIN,
            [0x2D; 16],
            AccountId::from_raw(4),
            token,
            Some(NOW)
        )
        .is_err(),
        "a reused invitation id"
    );
    let key = Passkey::new();
    let enrolled = enrol(
        &issued,
        &InvitationProof::Token(Token(token)),
        &key,
        true,
        NOW,
    )
    .unwrap();
    assert!(enrolled.iter().any(|r| matches!(
        r,
        CellRecord::Auth(AuthRecord::CredentialRegistered { account, .. }) if *account == invitee
    )));
    assert!(
        !enrolled
            .iter()
            .any(|r| matches!(r, CellRecord::Auth(AuthRecord::FirstAdminEnrolled { .. })))
    );
}

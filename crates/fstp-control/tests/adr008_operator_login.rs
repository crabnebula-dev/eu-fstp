//! ADR-008 "Control plane", ADR-011 "Two-operator approval", I-77, I-78,
//! SoD-08: the operator login of `fstp-control`.
//!
//! Staff log in with pinned passkeys only, with user verification, for
//! the control-plane host as relying party. A software authenticator in
//! this file signs with Ed25519 keys from `fstp-crypto`. The tests pass
//! the time in seconds, so lifetimes are checked without waiting.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_control::ControlError;
use fstp_control::api::{CpApiRequest, OrgRef};
use fstp_control::operator::{
    CHALLENGE_LIFETIME_SECS, OperatorLogin, OperatorRefusal, Purpose, SESSION_LIFETIME_SECS,
    STEP_UP_WINDOW_SECS, StaffCredential,
};
use fstp_control::placement::ClusterId;
use fstp_control::provision::CellMode;
use fstp_cp_proto::{CellId, StaffRef};
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_webauthn::{AssertionResponse, CoseKey};

const HOST: &str = "control.example.test";
const T0: i64 = 1_800_000_000;

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

    /// An assertion over `challenge` for `rp_host` at `origin`, with the
    /// UV flag when `uv` is set.
    fn assert_for(
        &mut self,
        challenge: &[u8; 32],
        rp_host: &str,
        origin: &str,
        uv: bool,
    ) -> AssertionResponse {
        self.count += 1;
        let mut auth = fstp_crypto::sha256(rp_host.as_bytes()).to_vec();
        auth.push(if uv { 0x05 } else { 0x01 });
        auth.extend_from_slice(&self.count.to_be_bytes());
        let b64 = fstp_pgwire::base64::encode(challenge)
            .replace('+', "-")
            .replace('/', "_")
            .replace('=', "");
        let client = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{b64}\",\"origin\":\"{origin}\"}}"
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
        self.assert_for(challenge, HOST, &format!("https://{HOST}"), true)
    }
}

/// Builds an assertion from the pinned passkey, the stranger and a challenge.
type MakeAssertion = dyn Fn(&mut Passkey, &mut Passkey, &[u8; 32]) -> AssertionResponse;

fn provision() -> CpApiRequest {
    CpApiRequest::ProvisionCell {
        org: OrgRef([3; 16]),
        mode: CellMode::Shared,
    }
}

fn audit() -> CpApiRequest {
    CpApiRequest::PrivilegeAudit {
        cluster: ClusterId([4; 16]),
    }
}

fn refusal(r: Result<impl std::fmt::Debug, ControlError>) -> OperatorRefusal {
    match r {
        Err(ControlError::Operator(o)) => o,
        other => panic!("not an operator refusal: {other:?}"),
    }
}

/// ADR-008, I-77: a pinned passkey with user verification opens a
/// session, which may ask for a read-only audit.
#[test]
fn adr008_operator_login_with_a_pinned_passkey_opens_a_session() {
    let mut a = Passkey::new(1, 0xa1);
    let mut login = OperatorLogin::new(HOST, &[a.pinned()]).unwrap();
    let c = login.begin(Purpose::Login, T0).unwrap();
    let (session, staff) = login.finish_login(c, &a.assert(&c), T0 + 1).unwrap();
    assert_eq!(staff, a.staff);
    assert_eq!(login.authorise(session, &audit(), T0 + 2).unwrap(), a.staff);
}

/// I-77, ADR-008 "User verification": an assertion without UV, for
/// another relying party, from another origin or from a credential that
/// is not pinned opens no session.
#[test]
fn i77_operator_login_refuses_anything_but_a_verified_pinned_passkey() {
    let mut a = Passkey::new(1, 0xa1);
    let mut stranger = Passkey::new(9, 0xf9);
    let mut login = OperatorLogin::new(HOST, &[a.pinned()]).unwrap();
    let cases: Vec<(&str, Box<MakeAssertion>)> = vec![
        (
            "no UV",
            Box::new(|a, _, c| a.assert_for(c, HOST, &format!("https://{HOST}"), false)),
        ),
        (
            "other RP",
            Box::new(|a, _, c| {
                a.assert_for(c, "evil.example.test", &format!("https://{HOST}"), true)
            }),
        ),
        (
            "other origin",
            Box::new(|a, _, c| a.assert_for(c, HOST, "https://evil.example.test", true)),
        ),
        ("stranger", Box::new(|_, s, c| s.assert(c))),
    ];
    for (what, make) in cases {
        let c = login.begin(Purpose::Login, T0).unwrap();
        let assertion = make(&mut a, &mut stranger, &c);
        let r = login.finish_login(c, &assertion, T0 + 1);
        assert!(
            matches!(
                refusal(r),
                OperatorRefusal::Assertion | OperatorRefusal::Credential
            ),
            "{what}"
        );
    }
}

/// ADR-008 "Challenges": a challenge is single use, bound to its purpose
/// and refused once older than its lifetime.
#[test]
fn adr008_operator_challenges_are_single_use_bound_and_short_lived() {
    let mut a = Passkey::new(1, 0xa1);
    let mut login = OperatorLogin::new(HOST, &[a.pinned()]).unwrap();
    let c = login.begin(Purpose::Login, T0).unwrap();
    let assertion = a.assert(&c);
    login.finish_login(c, &assertion, T0 + 1).unwrap();
    assert_eq!(
        refusal(login.finish_login(c, &a.assert(&c), T0 + 2)),
        OperatorRefusal::Challenge
    );
    let step = login.begin(Purpose::StepUp, T0).unwrap();
    assert_eq!(
        refusal(login.finish_login(step, &a.assert(&step), T0 + 1)),
        OperatorRefusal::Challenge
    );
    let late = login.begin(Purpose::Login, T0).unwrap();
    let r = login.finish_login(late, &a.assert(&late), T0 + CHALLENGE_LIFETIME_SECS + 1);
    assert!(matches!(
        refusal(r),
        OperatorRefusal::Challenge | OperatorRefusal::ChallengeExpired
    ));
}

/// I-78, ADR-011 "Non-destructive jobs run on one operator's request with
/// a passkey and a step-up": `provision-cell` needs a fresh step-up of the
/// same staff member, and each step-up admits one request.
#[test]
fn i78_provision_cell_needs_a_fresh_step_up_of_the_same_staff_member() {
    let mut a = Passkey::new(1, 0xa1);
    let mut b = Passkey::new(2, 0xb2);
    let mut login = OperatorLogin::new(HOST, &[a.pinned(), b.pinned()]).unwrap();
    let c = login.begin(Purpose::Login, T0).unwrap();
    let (session, _) = login.finish_login(c, &a.assert(&c), T0).unwrap();
    assert_eq!(
        refusal(login.authorise(session, &provision(), T0 + 1)),
        OperatorRefusal::StepUpRequired
    );

    let s = login.begin(Purpose::StepUp, T0 + 2).unwrap();
    assert_eq!(
        refusal(login.finish_step_up(session, s, &b.assert(&s), T0 + 3)),
        OperatorRefusal::OtherStaff
    );

    let s = login.begin(Purpose::StepUp, T0 + 4).unwrap();
    login
        .finish_step_up(session, s, &a.assert(&s), T0 + 5)
        .unwrap();
    assert_eq!(
        login.authorise(session, &provision(), T0 + 6).unwrap(),
        a.staff
    );
    assert_eq!(
        refusal(login.authorise(session, &provision(), T0 + 7)),
        OperatorRefusal::StepUpRequired
    );

    let s = login.begin(Purpose::StepUp, T0 + 8).unwrap();
    login
        .finish_step_up(session, s, &a.assert(&s), T0 + 9)
        .unwrap();
    assert_eq!(
        refusal(login.authorise(session, &provision(), T0 + 9 + STEP_UP_WINDOW_SECS + 1)),
        OperatorRefusal::StepUpRequired
    );
}

/// ADR-011 "Two-operator approval": `erase-cell` is refused whatever the
/// session holds, until the two-operator check exists.
#[test]
fn adr011_erase_cell_stays_refused_until_the_two_operator_check_exists() {
    let mut a = Passkey::new(1, 0xa1);
    let mut login = OperatorLogin::new(HOST, &[a.pinned()]).unwrap();
    let c = login.begin(Purpose::Login, T0).unwrap();
    let (session, _) = login.finish_login(c, &a.assert(&c), T0).unwrap();
    let s = login.begin(Purpose::StepUp, T0).unwrap();
    login.finish_step_up(session, s, &a.assert(&s), T0).unwrap();
    let erase = CpApiRequest::EraseCell {
        cell: CellId([5; 16]),
    };
    assert_eq!(
        login.authorise(session, &erase, T0 + 1),
        Err(ControlError::ApprovalRequired)
    );
}

/// ADR-008: an operator session ends after its lifetime, and a session
/// token that was never issued admits nothing.
#[test]
fn adr008_operator_session_expires() {
    let mut a = Passkey::new(1, 0xa1);
    let mut login = OperatorLogin::new(HOST, &[a.pinned()]).unwrap();
    let c = login.begin(Purpose::Login, T0).unwrap();
    let (session, _) = login.finish_login(c, &a.assert(&c), T0).unwrap();
    assert!(
        login
            .authorise(session, &audit(), T0 + SESSION_LIFETIME_SECS)
            .is_ok()
    );
    assert_eq!(
        refusal(login.authorise(session, &audit(), T0 + SESSION_LIFETIME_SECS + 1)),
        OperatorRefusal::SessionExpired
    );
    let forged = fstp_control::operator::OperatorSession([7; 32]);
    assert_eq!(
        refusal(login.authorise(forged, &audit(), T0)),
        OperatorRefusal::Session
    );
}

/// ADR-008 "Relying party id": the control-plane host must be a full host
/// name, not a registrable parent domain.
#[test]
fn adr008_operator_relying_party_is_the_exact_host() {
    assert_eq!(
        refusal(OperatorLogin::new("example.test", &[])),
        OperatorRefusal::Host
    );
    assert!(OperatorLogin::new(HOST, &[]).is_ok());
}

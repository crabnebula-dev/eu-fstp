//! The vertical slice over HTTP (design sections 8, 14.3 and 19, step
//! W3b). Each test starts a one-cell SaaS world in shared mode and drives
//! the cell's own routes with a software passkey, as a browser on the
//! cell origin would. Nothing here writes a store or a ledger directly.
//!
//! Lane W3b wrote these tests before the production code. They are red
//! because `World::start` refuses a world with cells. Once it starts real
//! cells, each test is red at the first route or harness read that still
//! refuses, and its message names that step.
//!
//! Readings of lane W3b, for lane W3a and the lead:
//!
//! - The invitation path parameter `{token}` of the first admin's split
//!   invitation is the lowercase hexadecimal of both halves, first half
//!   first (128 digits). Design section 8.3 fixes two halves but no
//!   spelling.
//! - The invitation register body is the canonical JSON object
//!   `{attestation_object, challenge_id, client_data_json}`, each in
//!   lowercase hexadecimal, as the assertion bodies of `fstp-cell` are.
//!   Its options reply carries `challenge_id` and `public_key.challenge`
//!   in base64url, as the login options reply does.
//! - The step-up id that an action request names is the challenge id of
//!   its step-up (design sections 4.2 and 8.4,
//!   `fstp_auth::stepup::verify_step_up`).
//! - The cycle steps are the names other lanes already use
//!   (`t_iso_i19`, `r_nf_m3`, `i20_tenants`, `i82_role_plan`). Their
//!   meaning is stated at [`FULL_CYCLE`].
//!
//! Each check of the ledger reads it through `CellHandle::ledger`. Each
//! check of the chain reads `audit.chain` and `audit.anchor` as the
//! superuser, and the witness's own `witness.anchor`, so the slice does
//! not trust the cell's view of its own anchors.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_audit::anchor::{decode_receipt, receipt_signature_verifies};
use fstp_audit::{CellId, ChainId};
use fstp_auth::AuthRecord;
use fstp_cell_core::CellRecord;
use fstp_celltest::soft_authn::{
    self, Alg, AttestedCredential, Ceremony, SoftAuthenticator, flags,
};
use fstp_celltest::world::{
    CellHandle, ClusterKind, CycleScript, DbMode, HttpReply, HttpRequest, VaultLayout, World,
    WorldSpec,
};
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_domain::Record;
use fstp_domain::id::{AccountId, ProposalId};
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::roster::{P1, SodSetup};
use fstp_ledger::Entry;

// ---------------------------------------------------------------------------
// World.

fn one_cell_world() -> World {
    World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("the one-cell SaaS world did not start: {e}"))
}

fn cell0(world: &World) -> &CellHandle {
    world
        .cell(0)
        .unwrap_or_else(|| panic!("the one-cell world holds no cell 0"))
}

// ---------------------------------------------------------------------------
// Encodings.

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hexadecimal {s:?}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| panic!("bad hex {s:?}")))
        .collect()
}

fn unhex_array<const N: usize>(s: &str) -> [u8; N] {
    unhex(s)
        .try_into()
        .unwrap_or_else(|_| panic!("{s:?} is not {N} bytes"))
}

/// Unpadded base64url (RFC 4648 section 5), as a WebAuthn options reply
/// writes its challenge.
fn unbase64url(s: &str) -> Vec<u8> {
    let value = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("{s:?} is not unpadded base64url"),
        }
    };
    let mut out = Vec::new();
    for chunk in s.as_bytes().chunks(4) {
        assert!(chunk.len() >= 2, "{s:?} has a dangling base64url digit");
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= value(*c) << (18 - 6 * i);
        }
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    out
}

fn text(r: &HttpReply) -> String {
    format!("{} {}", r.status, String::from_utf8_lossy(&r.body))
}

/// The string member `key` of a JSON reply. The cell writes canonical
/// JSON whose strings here hold only hexadecimal or base64url, so the
/// first `"key":"` names it. A nested member is found the same way.
fn json_str(body: &[u8], key: &str) -> Option<String> {
    let t = std::str::from_utf8(body).ok()?;
    let (_, rest) = t.split_once(&format!("\"{key}\":\""))?;
    let (v, _) = rest.split_once('"')?;
    Some(v.to_owned())
}

/// The decimal member `key`, a JSON string or a JSON number.
fn json_u64(body: &[u8], key: &str) -> Option<u64> {
    if let Some(s) = json_str(body, key) {
        return s.parse().ok();
    }
    let t = std::str::from_utf8(body).ok()?;
    let (_, rest) = t.split_once(&format!("\"{key}\":"))?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

// ---------------------------------------------------------------------------
// HTTP, as the cell's own pages send it.

fn request(cell: &CellHandle, method: &str, path: &str, cookie: Option<&[u8]>) -> HttpRequest {
    let mut r = HttpRequest::new(method, path).header("host", cell.host());
    if matches!(method, "POST" | "DELETE") {
        r = r.header("origin", format!("https://{}", cell.host()));
    }
    if let Some(c) = cookie {
        r = r.header("cookie", c.to_vec());
    }
    r
}

fn post(cell: &CellHandle, path: &str, cookie: Option<&[u8]>, body: &[u8]) -> HttpReply {
    let r = request(cell, "POST", path, cookie)
        .header("content-type", "application/json")
        .body(body.to_vec());
    cell.request(&r)
        .unwrap_or_else(|e| panic!("POST {path} did not reach the cell: {e}"))
}

fn get(cell: &CellHandle, path: &str, cookie: Option<&[u8]>) -> HttpReply {
    cell.request(&request(cell, "GET", path, cookie))
        .unwrap_or_else(|e| panic!("GET {path} did not reach the cell: {e}"))
}

// ---------------------------------------------------------------------------
// A software passkey: the SoftAuthenticator's byte builders and an Ed25519
// key, so every registration and assertion is real WebAuthn.

struct Passkey {
    auth: SoftAuthenticator,
    key: Ed25519SigningKey,
    id: Vec<u8>,
}

/// One assertion, as the assertion bodies of `fstp-cell` carry it.
struct Assertion {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
}

impl Passkey {
    fn new(rp_id: &str) -> Passkey {
        Passkey {
            auth: SoftAuthenticator::for_rp(rp_id),
            key: Ed25519SigningKey::generate().unwrap(),
            id: fstp_crypto::random_array::<16>().unwrap().to_vec(),
        }
    }

    /// A `none` attestation of this credential over `challenge`, with UP
    /// and UV: `(attestation_object, client_data_json)`.
    fn registration(&mut self, challenge: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let client_data = self
            .auth
            .client_data(Ceremony::Create, challenge, &[])
            .unwrap();
        let attested = AttestedCredential {
            aaguid: [0; 16],
            id: self.id.clone(),
            cose_key: soft_authn::cose_key(Alg::Ed25519, &self.key.public_key(), None),
        };
        let auth_data = soft_authn::authenticator_data(
            self.auth.rp_id(),
            flags::UP | flags::UV,
            0,
            Some(&attested),
        );
        (soft_authn::none_attestation_object(&auth_data), client_data)
    }

    /// An assertion over `challenge` with UP, UV and the next counter.
    fn assertion(&mut self, challenge: [u8; 32]) -> Assertion {
        let client_data_json = self
            .auth
            .client_data(Ceremony::Get, challenge, &[])
            .unwrap();
        let authenticator_data = self.auth.assertion_data(&[]).unwrap();
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&fstp_crypto::sha256(&client_data_json));
        let signature = self.key.sign(&message).unwrap().to_vec();
        Assertion {
            authenticator_data,
            client_data_json,
            signature,
        }
    }

    /// The canonical assertion body naming the challenge row `challenge_id`.
    fn assertion_body(&mut self, challenge_id: &str, challenge: [u8; 32]) -> Vec<u8> {
        let a = self.assertion(challenge);
        format!(
            "{{\"authenticator_data\":\"{}\",\"challenge_id\":\"{challenge_id}\",\
             \"client_data_json\":\"{}\",\"credential_id\":\"{}\",\"signature\":\"{}\"}}",
            hex(&a.authenticator_data),
            hex(&a.client_data_json),
            hex(&self.id),
            hex(&a.signature),
        )
        .into_bytes()
    }
}

/// The `challenge_id` and the 32-byte `public_key.challenge` of an options
/// reply.
fn options_challenge(reply: &HttpReply, what: &str) -> (String, [u8; 32]) {
    assert_eq!(reply.status, 200, "{what} options: {}", text(reply));
    let id = json_str(&reply.body, "challenge_id")
        .unwrap_or_else(|| panic!("{what} options name no challenge_id: {}", text(reply)));
    let challenge = json_str(&reply.body, "challenge")
        .unwrap_or_else(|| panic!("{what} options carry no challenge: {}", text(reply)));
    let bytes: [u8; 32] = unbase64url(&challenge)
        .try_into()
        .unwrap_or_else(|_| panic!("the {what} challenge is not 32 bytes"));
    (id, bytes)
}

// ---------------------------------------------------------------------------
// The slice steps.

/// Enrols `passkey` as the first tenant admin through the split
/// invitation (design section 8.3, Q35). The relying party the options
/// name is the exact cell host (I-20).
fn enrol_first_admin(cell: &CellHandle, passkey: &mut Passkey) {
    let inv = cell
        .first_admin_invitation()
        .unwrap_or_else(|e| panic!("the world holds no first admin invitation: {e}"));
    let token = format!("{}{}", hex(&inv.first), hex(&inv.second));
    let base = format!("/auth/invitations/{token}/register");
    let options = post(cell, &format!("{base}/options"), None, b"{}");
    let (challenge_id, challenge) = options_challenge(&options, "invitation register");
    let rp_id = std::str::from_utf8(&options.body)
        .ok()
        .and_then(|t| t.split_once("\"rp\":{"))
        .and_then(|(_, rp)| json_str(rp.as_bytes(), "id"));
    assert_eq!(
        rp_id.as_deref(),
        Some(cell.host()),
        "I-20: the registration options name another relying party: {}",
        text(&options)
    );
    let (attestation, client_data) = passkey.registration(challenge);
    let body = format!(
        "{{\"attestation_object\":\"{}\",\"challenge_id\":\"{challenge_id}\",\"client_data_json\":\"{}\"}}",
        hex(&attestation),
        hex(&client_data)
    );
    let reply = post(cell, &base, None, body.as_bytes());
    assert!(
        reply.ok(),
        "the first admin's enrolment was refused: {}",
        text(&reply)
    );
}

/// A passkey session.
struct Session {
    /// The `Cookie` field value.
    cookie: Vec<u8>,
    /// The session id.
    id: [u8; 16],
}

/// A passkey login through `POST /auth/passkey/login/options` and
/// `POST /auth/passkey/login` (I-77).
fn login(cell: &CellHandle, passkey: &mut Passkey) -> Session {
    let options = post(cell, "/auth/passkey/login/options", None, b"{}");
    let (challenge_id, challenge) = options_challenge(&options, "login");
    let body = passkey.assertion_body(&challenge_id, challenge);
    let reply = post(cell, "/auth/passkey/login", None, &body);
    assert_eq!(reply.status, 200, "the passkey login: {}", text(&reply));
    let set = reply
        .header("set-cookie")
        .unwrap_or_else(|| panic!("the login set no cookie: {}", text(&reply)));
    let pair = set
        .split(|b| *b == b';')
        .next()
        .unwrap_or_default()
        .to_vec();
    assert!(
        pair.starts_with(format!("{}=", fstp_cell::http::COOKIE_NAME).as_bytes()),
        "B11: the session cookie is not {}",
        fstp_cell::http::COOKIE_NAME
    );
    let id = json_str(&reply.body, "session")
        .unwrap_or_else(|| panic!("the login reply names no session: {}", text(&reply)));
    Session {
        cookie: pair,
        id: unhex_array(&id),
    }
}

/// The canonical command body `{command, command_id, stepup?}`.
fn command_body(
    command: &fstp_cell_core::CellCommand,
    command_id: [u8; 16],
    stepup: Option<[u8; 16]>,
) -> Vec<u8> {
    let c = String::from_utf8(fstp_cell_core::encode_cell_command(command)).unwrap();
    let mut body = format!("{{\"command\":{c},\"command_id\":\"{}\"", hex(&command_id));
    if let Some(s) = stepup {
        body.push_str(&format!(",\"stepup\":\"{}\"", hex(&s)));
    }
    body.push('}');
    body.into_bytes()
}

/// A step-up for `command` under `command_id` in `session`: options, then
/// a passkey assertion with UV (design section 8.4). Returns the step-up
/// id the action request names, which is the challenge id.
fn step_up(
    cell: &CellHandle,
    passkey: &mut Passkey,
    session: &Session,
    command: &fstp_cell_core::CellCommand,
    command_id: [u8; 16],
) -> [u8; 16] {
    let options = post(
        cell,
        "/auth/stepup/options",
        Some(&session.cookie),
        &command_body(command, command_id, None),
    );
    let (challenge_id, challenge) = options_challenge(&options, "step-up");
    let body = passkey.assertion_body(&challenge_id, challenge);
    let reply = post(cell, "/auth/stepup", Some(&session.cookie), &body);
    assert!(reply.ok(), "the step-up was refused: {}", text(&reply));
    unhex_array(&challenge_id)
}

/// `CreateProgramme` of P1 with a synthetic first policy version.
fn create_programme() -> fstp_cell_core::CellCommand {
    let policy = SodSetup::one(1, &[]).version(P1).unwrap();
    fstp_cell_core::CellCommand::Engine(fstp_engine::Command::Core(
        fstp_domain::Command::CreateProgramme {
            policy: Box::new(policy),
        },
    ))
}

/// The first tenant admin, from `FirstAdminEnrolled` in the ledger.
fn first_admin(ledger: &[Entry<CellRecord>]) -> AccountId {
    ledger
        .iter()
        .find_map(|e| match &e.record {
            CellRecord::Auth(AuthRecord::FirstAdminEnrolled { account }) => Some(*account),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the ledger records no FirstAdminEnrolled"))
}

fn core(e: &Entry<CellRecord>) -> Option<&Record> {
    match &e.record {
        CellRecord::Engine(fstp_engine::Record::Core(r)) => Some(r),
        _ => None,
    }
}

fn read_ledger(cell: &CellHandle) -> Vec<Entry<CellRecord>> {
    cell.ledger()
        .unwrap_or_else(|e| panic!("the cell ledger cannot be read: {e}"))
}

// ---------------------------------------------------------------------------
// The chain, read from the databases.

fn app_sql(world: &World, cell: &CellHandle, sql: &str) -> String {
    world
        .cluster(ClusterKind::Application)
        .unwrap_or_else(|| panic!("the world runs no application cluster"))
        .server()
        .psql(&cell.app_database(), sql)
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

fn witness_sql(world: &World, sql: &str) -> String {
    world
        .cluster(ClusterKind::Witness)
        .unwrap_or_else(|| panic!("the world runs no witness cluster"))
        .server()
        .psql("witness", sql)
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

fn fields(line: &str, n: usize, what: &str) -> Vec<String> {
    let f: Vec<String> = line.split('|').map(str::to_owned).collect();
    assert_eq!(f.len(), n, "{what}: {line:?}");
    f
}

/// One anchor of the App chain.
#[derive(Debug, PartialEq, Eq)]
struct Anchored {
    n: u64,
    link: String,
    witness_seq: u64,
}

/// I-24, design sections 5.3 and 7.2: ledger entry `seq` has one kind 1
/// row in `audit.chain`. The first anchor at or after that row commits
/// its link, and its receipt names this cell, the App chain, the anchor's
/// row and link and its witness sequence. The receipt verifies under the
/// pinned witness keys. The witness's own `witness.anchor` holds the
/// same head with the same witness fields.
fn anchored(world: &World, cell: &CellHandle, seq: u64, keys: &[Vec<u8>]) -> Anchored {
    let row = app_sql(
        world,
        cell,
        &format!("SELECT n FROM audit.chain WHERE kind = 1 AND ledger_seq = {seq}"),
    );
    let lines: Vec<&str> = row.lines().collect();
    assert_eq!(lines.len(), 1, "ledger entry {seq} has chain rows {row:?}");
    let n: u64 = lines[0].parse().unwrap();
    let anchor = app_sql(
        world,
        cell,
        &format!(
            "SELECT n, encode(link, 'hex'), witness_seq, encode(receipt, 'hex') \
             FROM audit.anchor WHERE n >= {n} ORDER BY n LIMIT 1"
        ),
    );
    assert!(
        !anchor.is_empty(),
        "I-24: chain row {n} of entry {seq} has no anchor"
    );
    let a = fields(&anchor, 4, "audit.anchor");
    let got = Anchored {
        n: a[0].parse().unwrap(),
        link: a[1].clone(),
        witness_seq: a[2].parse().unwrap(),
    };
    let head_link = app_sql(
        world,
        cell,
        &format!(
            "SELECT encode(link, 'hex') FROM audit.chain WHERE n = {}",
            got.n
        ),
    );
    assert_eq!(
        head_link, got.link,
        "I-24: anchor {} names a link the chain does not hold",
        got.n
    );
    let receipt = decode_receipt(&unhex(&a[3]))
        .unwrap_or_else(|e| panic!("the receipt of anchor {} does not decode: {e:?}", got.n));
    assert_eq!(
        receipt.cell,
        CellId(cell.id()),
        "the receipt names another cell"
    );
    assert_eq!(
        receipt.chain,
        ChainId::App,
        "the receipt names another chain"
    );
    assert_eq!(receipt.fields.n, got.n, "the receipt names another row");
    assert_eq!(
        hex(&receipt.fields.link.0),
        got.link,
        "the receipt names another link"
    );
    assert_eq!(
        receipt.fields.witness_seq, got.witness_seq,
        "the receipt names another witness sequence"
    );
    assert!(
        receipt_signature_verifies(&receipt, keys),
        "I-24, I-90: the receipt of anchor {} does not verify under the pinned witness keys",
        got.n
    );
    let held = witness_sql(
        world,
        &format!(
            "SELECT encode(link, 'hex'), witness_seq, encode(witness_link, 'hex'), received_at \
             FROM witness.anchor WHERE cell_id = '\\x{}'::bytea AND chain = {} AND n = {}",
            hex(&cell.id()),
            ChainId::App.byte(),
            got.n
        ),
    );
    assert!(
        !held.is_empty(),
        "I-24: the witness holds no prepare for anchor {}",
        got.n
    );
    let w = fields(&held, 4, "witness.anchor");
    assert_eq!(
        (
            w[0].clone(),
            w[1].parse::<u64>().unwrap(),
            w[2].clone(),
            w[3].parse::<i64>().unwrap()
        ),
        (
            got.link.clone(),
            receipt.fields.witness_seq,
            hex(&receipt.fields.witness_link.0),
            receipt.fields.received_at
        ),
        "I-24: the witness's record of anchor {} differs from the cell's receipt",
        got.n
    );
    got
}

// ---------------------------------------------------------------------------
// S1.

/// R-PC-01, R-LG-01, R-LG-03, I-77, I-78, I-24, design section 19 (step
/// W3b): the first tenant admin enrols a passkey through the split
/// invitation and logs in with it over the cell's routes. A
/// `CreateProgramme` with a fresh step-up commits. Its `ProgrammeCreated`
/// is in the ledger, in the batch that consumes that step-up. The step-up
/// was logged earlier with the command's action digest. The entry is a
/// row of the anchored App chain, whose receipt the witness signed and
/// holds. The tenant admin sees that anchor over HTTP.
#[test]
fn slice_s1_passkey_login_create_programme_lands_in_ledger_and_chain() {
    let world = one_cell_world();
    let cell = cell0(&world);
    let mut admin = Passkey::new(cell.host());
    enrol_first_admin(cell, &mut admin);
    let session = login(cell, &mut admin);

    // I-77: the management account's session is a passkey session.
    let sessions = get(cell, "/auth/sessions", Some(&session.cookie));
    assert_eq!(
        sessions.status,
        200,
        "GET /auth/sessions: {}",
        text(&sessions)
    );
    let listed = String::from_utf8_lossy(&sessions.body).into_owned();
    assert!(
        listed.contains(&format!("\"id\":\"{}\"", hex(&session.id)))
            && listed.contains("\"method\":\"passkey\"")
            && !listed.contains("magic_link"),
        "I-77: the admin's sessions are not passkey sessions: {listed}"
    );

    let command = create_programme();
    let command_id = fstp_crypto::random_array::<16>().unwrap();
    let stepup = step_up(cell, &mut admin, &session, &command, command_id);
    let reply = post(
        cell,
        "/api/v1/commands",
        Some(&session.cookie),
        &command_body(&command, command_id, Some(stepup)),
    );
    assert_eq!(
        reply.status,
        200,
        "CreateProgramme with a fresh step-up: {}",
        text(&reply)
    );
    let head = json_u64(&reply.body, "head")
        .unwrap_or_else(|| panic!("the command reply names no head: {}", text(&reply)));
    assert!(
        String::from_utf8_lossy(&reply.body).contains("\"duplicate\":false"),
        "a first CreateProgramme answered as a duplicate: {}",
        text(&reply)
    );

    let ledger = read_ledger(cell);
    let admin_account = first_admin(&ledger);
    let batch: Vec<&Entry<CellRecord>> =
        ledger.iter().filter(|e| e.command == command_id).collect();
    let created = batch
        .iter()
        .find(|e| {
            matches!(core(e), Some(Record::ProgrammeCreated { programme, by, .. })
                if *programme == P1 && *by == admin_account)
        })
        .unwrap_or_else(|| {
            panic!("R-PC-01: no ProgrammeCreated of P1 by the first admin in the batch {batch:?}")
        });
    assert_eq!(
        batch.last().map(|e| e.seq.raw()),
        Some(head),
        "the reply's head is not the batch's last entry"
    );
    assert!(
        batch.iter().any(|e| matches!(
            &e.record,
            CellRecord::Auth(AuthRecord::StepUpConsumed { id }) if *id == stepup
        )),
        "I-78: the CreateProgramme batch does not consume its step-up: {batch:?}"
    );
    let digest = fstp_cell_core::action_digest(&command, command_id);
    assert!(
        ledger.iter().any(|e| e.seq < created.seq
            && matches!(
                &e.record,
                CellRecord::Auth(AuthRecord::StepUpGranted { id, action_digest, session: s })
                    if *id == stepup && *action_digest == digest && *s == session.id
            )),
        "I-78: no earlier StepUpGranted logs the step-up with the command's action digest"
    );

    let keys = world
        .witness_keys()
        .unwrap_or_else(|e| panic!("the world pins no witness keys: {e}"));
    let anchor = anchored(&world, cell, created.seq.raw(), &keys);

    let anchors = get(cell, "/api/v1/audit/anchors", Some(&session.cookie));
    assert_eq!(
        anchors.status,
        200,
        "GET /api/v1/audit/anchors: {}",
        text(&anchors)
    );
    let listed = String::from_utf8_lossy(&anchors.body).into_owned();
    assert!(
        listed.contains(&format!("\"link\":\"{}\"", anchor.link)),
        "the tenant admin's anchor list lacks anchor {anchor:?}: {listed}"
    );
}

/// I-78, design sections 5.4 and 8.4: over the same routes, a
/// `CreateProgramme` that names no step-up is refused with 403 and
/// records nothing. The ledger is the same before and after.
#[test]
fn slice_s1_i78_create_programme_without_step_up_records_nothing() {
    let world = one_cell_world();
    let cell = cell0(&world);
    let mut admin = Passkey::new(cell.host());
    enrol_first_admin(cell, &mut admin);
    let session = login(cell, &mut admin);
    let before = read_ledger(cell);
    let command = create_programme();
    let command_id = fstp_crypto::random_array::<16>().unwrap();
    let reply = post(
        cell,
        "/api/v1/commands",
        Some(&session.cookie),
        &command_body(&command, command_id, None),
    );
    assert_eq!(
        reply.status,
        403,
        "I-78: CreateProgramme without a step-up: {}",
        text(&reply)
    );
    assert_eq!(
        read_ledger(cell),
        before,
        "I-78: a refused CreateProgramme changed the ledger"
    );
}

/// I-78, design section 8.4 ("One step-up authorises one command"): a
/// step-up consumed by one `CreateProgramme` does not admit the same
/// command again under a new command id. The second request is refused
/// with 403 and records nothing.
#[test]
fn slice_s1_i78_consumed_step_up_admits_no_second_command() {
    let world = one_cell_world();
    let cell = cell0(&world);
    let mut admin = Passkey::new(cell.host());
    enrol_first_admin(cell, &mut admin);
    let session = login(cell, &mut admin);
    let command = create_programme();
    let first_id = fstp_crypto::random_array::<16>().unwrap();
    let stepup = step_up(cell, &mut admin, &session, &command, first_id);
    let first = post(
        cell,
        "/api/v1/commands",
        Some(&session.cookie),
        &command_body(&command, first_id, Some(stepup)),
    );
    assert_eq!(
        first.status,
        200,
        "the first CreateProgramme: {}",
        text(&first)
    );
    let before = read_ledger(cell);
    let second_id = fstp_crypto::random_array::<16>().unwrap();
    let second = post(
        cell,
        "/api/v1/commands",
        Some(&session.cookie),
        &command_body(&command, second_id, Some(stepup)),
    );
    assert_eq!(
        (second.status, read_ledger(cell) == before),
        (403, true),
        "I-78: a consumed step-up admitted a second command: {}",
        text(&second)
    );
}

// ---------------------------------------------------------------------------
// The call cycle over HTTP.

/// The full call cycle of design section 14.4, as far as M3 builds it
/// (Q33). Lane W3b's step vocabulary, which `World::run_cycle` drives
/// through the cell's routes only:
///
/// - `login`: the first tenant admin enrols through the split invitation
///   and logs in with a passkey.
/// - `create-programme`: `CreateProgramme` with a step-up, then the
///   programme manager and call drafter grants, each with a step-up.
/// - `publish-call`: `DraftCall`, `ApproveCallPublication`, then
///   `PublishCall` with a step-up.
/// - `signup`: an applicant self-registers with an email proof and a
///   passkey (design section 8.3, ceremony 2).
/// - `verify-identity`: the applicant's over-18 attestation reaches the
///   vault through the vault origin (Q13 A, ADR-008).
/// - `submit-proposal`: `CreateDraft`, the plan and `Submit` by the
///   applicant.
/// - `score`, `rank`, `negotiate` and `grant`: the M2 evaluation path to
///   GRANTED, by staff and reviewers that the tenant admin invited.
pub const FULL_CYCLE: [&str; 10] = [
    "login",
    "create-programme",
    "publish-call",
    "signup",
    "verify-identity",
    "submit-proposal",
    "score",
    "rank",
    "negotiate",
    "grant",
];

/// Runs the first `steps` of [`FULL_CYCLE`] on cell 0 and returns its
/// decrypted ledger.
fn run(world: &World, steps: usize) -> Vec<Entry<CellRecord>> {
    let script = CycleScript {
        steps: FULL_CYCLE[..steps]
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    };
    world
        .run_cycle(0, &script)
        .result
        .unwrap_or_else(|e| panic!("the cycle {:?} did not run: {e}", script.steps));
    read_ledger(cell0(world))
}

/// The one proposal the cycle created.
fn the_proposal(ledger: &[Entry<CellRecord>]) -> (ProposalId, bool) {
    let created: Vec<(ProposalId, bool)> = ledger
        .iter()
        .filter_map(|e| match core(e) {
            Some(Record::ProposalCreated {
                proposal, minor, ..
            }) => Some((*proposal, *minor)),
            _ => None,
        })
        .collect();
    assert_eq!(created.len(), 1, "the cycle created proposals {created:?}");
    created[0]
}

/// R-PC-03, I-12, design section 14.4: after `login`, `create-programme`
/// and `publish-call` over HTTP, the ledger holds the programme, the
/// call's publication approval and then its publication, in that order.
#[test]
fn slice_cycle_r_pc_03_call_is_published_after_its_approval() {
    let world = one_cell_world();
    let ledger = run(&world, 3);
    let seq_of = |f: &dyn Fn(&Record) -> bool| {
        ledger
            .iter()
            .find(|e| core(e).is_some_and(f))
            .map(|e| e.seq.raw())
    };
    let created = seq_of(&|r| matches!(r, Record::ProgrammeCreated { .. }));
    let approved = seq_of(&|r| matches!(r, Record::CallApproved { .. }));
    let published = seq_of(&|r| matches!(r, Record::CallPublished { .. }));
    assert!(
        matches!((created, approved, published), (Some(c), Some(a), Some(p)) if c < a && a < p),
        "R-PC-03: programme {created:?}, approval {approved:?}, publication {published:?}"
    );
}

/// I-18, R-ID-04 (interim Q13), design section 14.4: a proposal drafted
/// and submitted over HTTP by a self-registered applicant is
/// minor-flagged, since no request sets the flag. Its `Submitted` record
/// is in the ledger.
#[test]
fn slice_cycle_i18_proposal_submitted_over_http_is_minor_flagged() {
    let world = one_cell_world();
    let ledger = run(&world, 6);
    let (proposal, minor) = the_proposal(&ledger);
    assert!(minor, "I-18: a draft from a request is not minor-flagged");
    assert!(
        ledger.iter().any(|e| matches!(
            core(e),
            Some(Record::Submitted { proposal: p, .. }) if *p == proposal
        )),
        "the proposal was not submitted"
    );
}

/// Design sections 14.4 and 19 (step W3b), state-machine NOTE 14: the full
/// cycle over HTTP takes the proposal through SUBMITTED, STAGE1, STAGE2,
/// RANKED, IRC_REVIEW and NEGOTIATION to GRANTED, in that order.
#[test]
fn slice_cycle_full_call_cycle_reaches_granted() {
    let world = one_cell_world();
    let ledger = run(&world, FULL_CYCLE.len());
    let (proposal, _) = the_proposal(&ledger);
    let reached: Vec<StateTag> = ledger
        .iter()
        .filter_map(|e| match core(e) {
            Some(Record::Transitioned(t)) if t.proposal == proposal => Some(t.to),
            _ => None,
        })
        .collect();
    let want = [
        StateTag::Submitted,
        StateTag::Stage1,
        StateTag::Stage2,
        StateTag::Ranked,
        StateTag::IrcReview,
        StateTag::Negotiation,
        StateTag::Granted,
    ];
    let mut rest = reached.iter();
    let ordered = want.iter().all(|w| rest.any(|r| r == w));
    assert!(
        ordered && reached.last() == Some(&StateTag::Granted),
        "the proposal's states over HTTP: {reached:?}"
    );
}

/// Whether `batch` is the batch of a high-risk command, one of the seven
/// kinds of `fstp_domain::CommandKind::high_risk` (I-78, m3-base
/// re-derivation 1), told by the records only those commands write:
///
/// - `CreateProgramme`: `ProgrammeCreated`;
/// - `GrantRole`: `BindingGranted` at programme scope, since a Receiving
///   binding at proposal scope comes from a proposal command;
/// - `EndRole` with a later instant: `BindingEndScheduled` without a
///   `BindingGranted`, which a grant with an end also writes;
/// - `ReinstateBinding`: `BindingReinstated`;
/// - `ApprovePayment`: `PaymentApproved`;
/// - `ReleasePayment`: `PaymentReleased`;
/// - `PublishCall`: `CallPublished`.
///
/// An `EndRole` at once writes `BindingEnded`, as the system command
/// `EndScheduledRole` and the terminal ends do, so that record alone
/// does not tell. The scripted cycle ends no role.
fn high_risk_batch(batch: &[&Entry<CellRecord>]) -> bool {
    let records: Vec<&Record> = batch.iter().filter_map(|e| core(e)).collect();
    let granted = records
        .iter()
        .any(|r| matches!(r, Record::BindingGranted(_)));
    records.iter().any(|r| match r {
        Record::ProgrammeCreated { .. }
        | Record::CallPublished { .. }
        | Record::BindingReinstated(_)
        | Record::PaymentApproved { .. }
        | Record::PaymentReleased(_) => true,
        Record::BindingGranted(g) => g.scope == fstp_domain::roles::BindingScope::Programme,
        Record::BindingEndScheduled { .. } => !granted,
        _ => false,
    })
}

/// I-78, design section 5.1 ("Step-up consumption"): over the full cycle,
/// every batch of a high-risk command ([`high_risk_batch`]) consumes
/// exactly one step-up. That step-up was granted at an earlier entry,
/// and no step-up is consumed twice in the ledger. The cycle as scripted
/// runs at least four: `CreateProgramme`, the programme manager and call
/// drafter grants, and `PublishCall`.
#[test]
fn slice_cycle_i78_every_programme_and_publication_consumes_one_step_up() {
    let world = one_cell_world();
    let ledger = run(&world, FULL_CYCLE.len());
    let mut consumed: Vec<[u8; 16]> = Vec::new();
    let mut failures = Vec::new();
    let mut high_risk = 0usize;
    let commands: std::collections::BTreeSet<[u8; 16]> = ledger.iter().map(|e| e.command).collect();
    for command in commands {
        let batch: Vec<&Entry<CellRecord>> =
            ledger.iter().filter(|e| e.command == command).collect();
        let ids: Vec<[u8; 16]> = batch
            .iter()
            .filter_map(|e| match &e.record {
                CellRecord::Auth(AuthRecord::StepUpConsumed { id }) => Some(*id),
                _ => None,
            })
            .collect();
        consumed.extend(&ids);
        if !high_risk_batch(&batch) {
            continue;
        }
        high_risk += 1;
        let first = batch.first().map_or(0, |e| e.seq.raw());
        let granted_before = |id: &[u8; 16]| {
            ledger.iter().any(|e| {
                e.seq.raw() < first
                    && matches!(
                        &e.record,
                        CellRecord::Auth(AuthRecord::StepUpGranted { id: g, .. }) if g == id
                    )
            })
        };
        if ids.len() != 1 || !granted_before(&ids[0]) {
            failures.push(format!("{}: consumed {ids:?}", hex(&command)));
        }
    }
    let mut unique = consumed.clone();
    unique.sort_unstable();
    unique.dedup();
    assert!(
        high_risk >= 4 && failures.is_empty() && unique.len() == consumed.len(),
        "I-78: {high_risk} high-risk batches, failures {failures:?}, consumed {} with {} distinct",
        consumed.len(),
        unique.len()
    );
}

/// I-24, design sections 5.3 and 7.2: over the full cycle, every ledger
/// entry is a row of the App chain and is covered by an anchor whose
/// receipt the witness signed and holds. No committed entry is
/// unwitnessed.
#[test]
fn slice_cycle_i24_every_entry_is_chained_and_receipted() {
    let world = one_cell_world();
    let ledger = run(&world, FULL_CYCLE.len());
    let cell = cell0(&world);
    let stored = app_sql(&world, cell, "SELECT seq FROM ledger.entry ORDER BY seq");
    let seqs: Vec<u64> = stored.lines().map(|l| l.parse().unwrap()).collect();
    assert_eq!(
        seqs,
        ledger.iter().map(|e| e.seq.raw()).collect::<Vec<_>>(),
        "the stored entries differ from the decrypted ledger"
    );
    let keys = world
        .witness_keys()
        .unwrap_or_else(|e| panic!("the world pins no witness keys: {e}"));
    for seq in seqs {
        let _ = anchored(&world, cell, seq, &keys);
    }
}

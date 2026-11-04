//! Shared helpers of the `fstp-signup` tests (lane W2f, test author).
//!
//! The helpers encode forms the way a browser submits
//! `application/x-www-form-urlencoded` bodies, generate synthetic field
//! values and build the control plane commands of journey J0. Every value
//! is synthetic. No helper reads production internals.

#![allow(dead_code)]

use fstp_prop::Gen;
use fstp_signup::{
    AgreementFields, AgreementVersions, CpCommand, CpRecord, MAX_FIELD_BYTES, ReviewOutcome,
    SignupError, SignupFields, SignupState, StaffId, TenantId, decide,
};

/// The field names of the sign-up form, in the order the page renders them.
pub(crate) const SIGNUP_FIELDS: [&str; 4] = [
    "form",
    "legal_name",
    "billing_address",
    "contracting_signatory",
];

/// The field names of the agreement form, in the order the page renders them.
pub(crate) const AGREEMENT_FIELDS: [&str; 6] = [
    "form",
    "tenant",
    "saas_terms",
    "dpa",
    "sub_processors",
    "accepted_by",
];

/// The text fields of each form, which the length and character rules cover.
pub(crate) const SIGNUP_TEXT_FIELDS: [&str; 3] =
    ["legal_name", "billing_address", "contracting_signatory"];
pub(crate) const AGREEMENT_TEXT_FIELDS: [&str; 1] = ["accepted_by"];
pub(crate) const AGREEMENT_NUMBER_FIELDS: [&str; 3] = ["saas_terms", "dpa", "sub_processors"];

/// A fixed synthetic time for commands, in Unix seconds.
pub(crate) const AT: i64 = 1_793_404_800;

pub(crate) const T1: TenantId = TenantId::from_raw(0x5e1f_0000_0000_0000_0000_0000_0000_0001);
pub(crate) const T2: TenantId = TenantId::from_raw(0x5e1f_0000_0000_0000_0000_0000_0000_0002);
pub(crate) const S1: StaffId = StaffId::from_raw(0x57af_0001);
pub(crate) const S2: StaffId = StaffId::from_raw(0x57af_0002);
pub(crate) const S3: StaffId = StaffId::from_raw(0x57af_0003);

/// The agreement versions the control plane offers in most tests.
pub(crate) const V1: AgreementVersions = AgreementVersions {
    saas_terms: 1,
    dpa: 1,
    sub_processors: 1,
};

/// A later offer in which only the data processing agreement changed.
pub(crate) const V2: AgreementVersions = AgreementVersions {
    saas_terms: 1,
    dpa: 2,
    sub_processors: 1,
};

/// Percent-encodes `value` as a browser does for a form body: ASCII
/// letters, digits and `*-._` stay, a space becomes `+`, and every other
/// byte becomes `%XX` with upper-case hex digits.
pub(crate) fn encode_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(char::from(b));
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Joins already-encoded pairs into a body.
pub(crate) fn body_encoded(pairs: &[(String, String)]) -> Vec<u8> {
    pairs
        .iter()
        .map(|(n, v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes()
}

/// Encodes the values of raw pairs and joins them into a body. Names are
/// written as they are.
pub(crate) fn body(pairs: &[(String, String)]) -> Vec<u8> {
    let encoded: Vec<(String, String)> = pairs
        .iter()
        .map(|(n, v)| (n.clone(), encode_value(v)))
        .collect();
    body_encoded(&encoded)
}

/// The tenant id as the agreement form carries it: 32 lower-case hex digits.
pub(crate) fn tenant_hex(t: TenantId) -> String {
    format!("{:032x}", t.raw())
}

/// The raw pairs of a sign-up form, in rendering order.
pub(crate) fn signup_pairs(f: &SignupFields) -> Vec<(String, String)> {
    vec![
        ("form".to_owned(), "signup".to_owned()),
        ("legal_name".to_owned(), f.legal_name.clone()),
        ("billing_address".to_owned(), f.billing_address.clone()),
        (
            "contracting_signatory".to_owned(),
            f.contracting_signatory.clone(),
        ),
    ]
}

/// The raw pairs of an agreement form, in rendering order.
pub(crate) fn agreement_pairs(f: &AgreementFields) -> Vec<(String, String)> {
    vec![
        ("form".to_owned(), "agreements".to_owned()),
        ("tenant".to_owned(), tenant_hex(f.tenant)),
        ("saas_terms".to_owned(), f.versions.saas_terms.to_string()),
        ("dpa".to_owned(), f.versions.dpa.to_string()),
        (
            "sub_processors".to_owned(),
            f.versions.sub_processors.to_string(),
        ),
        ("accepted_by".to_owned(), f.accepted_by.clone()),
    ]
}

/// True for the characters a valid text value never holds: Unicode `Cc`
/// controls, every Unicode 16.0 `Cf` format character, and U+2028 and
/// U+2029 (TH-46, TH-26).
fn excluded(c: char) -> bool {
    c.is_control()
        || matches!(
            u32::from(c),
            0x00ad
                | 0x0600..=0x0605
                | 0x061c
                | 0x06dd
                | 0x070f
                | 0x0890..=0x0891
                | 0x08e2
                | 0x180e
                | 0x200b..=0x200f
                | 0x2028..=0x2029
                | 0x202a..=0x202e
                | 0x2060..=0x2064
                | 0x2066..=0x206f
                | 0xfeff
                | 0xfff9..=0xfffb
                | 0x110bd
                | 0x110cd
                | 0x13430..=0x1343f
                | 0x1bca0..=0x1bca3
                | 0x1d173..=0x1d17a
                | 0xe0001
                | 0xe0020..=0xe007f
        )
}

/// Truncates `s` to at most `max` bytes on a character boundary.
fn truncate_bytes(mut s: String, max: usize) -> String {
    while s.len() > max {
        s.pop();
    }
    s
}

/// A valid text value: 1 to 40 characters, no control character, no
/// leading or trailing whitespace, at most [`MAX_FIELD_BYTES`] bytes.
/// When `line_breaks` holds, CR LF pairs may appear inside the value.
pub(crate) fn gen_text(g: &mut Gen, line_breaks: bool) -> String {
    let chars = g.vec(1..=40, |g| {
        let c = g.char();
        if excluded(c) { 'x' } else { c }
    });
    let mut s = String::new();
    let last = chars.len().saturating_sub(1);
    for (i, c) in chars.into_iter().enumerate() {
        let edge = i == 0 || i == last;
        let c = if edge && c.is_whitespace() { 'x' } else { c };
        s.push(c);
        if line_breaks && i != last && g.u8_in(0..=7) == 0 {
            s.push_str("\r\n");
        }
    }
    let s = truncate_bytes(s, MAX_FIELD_BYTES);
    // Truncation may leave whitespace or half a line break at the end.
    let trimmed = s.trim_end_matches(|c: char| c.is_whitespace()).to_owned();
    if trimmed.is_empty() {
        "x".to_owned()
    } else {
        trimmed
    }
}

/// A synthetic tenant id.
pub(crate) fn gen_tenant(g: &mut Gen) -> TenantId {
    let hi = u128::from(g.u64());
    let lo = u128::from(g.u64());
    TenantId::from_raw((hi << 64) | lo)
}

/// A version number as the agreement form carries it: 1 to `u32::MAX`.
pub(crate) fn gen_version(g: &mut Gen) -> u32 {
    g.u32_in(1..=u32::MAX)
}

pub(crate) fn gen_versions(g: &mut Gen) -> AgreementVersions {
    AgreementVersions {
        saas_terms: gen_version(g),
        dpa: gen_version(g),
        sub_processors: gen_version(g),
    }
}

pub(crate) fn gen_signup_fields(g: &mut Gen) -> SignupFields {
    SignupFields {
        legal_name: gen_text(g, false),
        billing_address: gen_text(g, true),
        contracting_signatory: gen_text(g, false),
    }
}

pub(crate) fn gen_agreement_fields(g: &mut Gen) -> AgreementFields {
    AgreementFields {
        tenant: gen_tenant(g),
        versions: gen_versions(g),
        accepted_by: gen_text(g, false),
    }
}

/// Synthetic sign-up values of the e2e test tenant.
pub(crate) fn synthetic_signup() -> SignupFields {
    SignupFields {
        legal_name: "Synthetic Test Organisation SRL".to_owned(),
        billing_address: "1 Synthetic Street\r\n0000 Testville".to_owned(),
        contracting_signatory: "Synthetic Signatory".to_owned(),
    }
}

pub(crate) fn synthetic_agreements(
    tenant: TenantId,
    versions: AgreementVersions,
) -> AgreementFields {
    AgreementFields {
        tenant,
        versions,
        accepted_by: "Synthetic Signatory".to_owned(),
    }
}

pub(crate) fn signup_cmd(tenant: TenantId) -> CpCommand {
    CpCommand::Signup {
        tenant,
        form: synthetic_signup(),
        at: AT,
    }
}

/// Operator staff member `S1` offers `versions`.
pub(crate) fn offer_cmd(versions: AgreementVersions) -> CpCommand {
    CpCommand::OfferAgreements {
        versions,
        staff: S1,
        at: AT,
    }
}

/// `tenant` accepts `versions`, which the ledger's current offer must
/// equal.
pub(crate) fn accept_cmd(tenant: TenantId, versions: AgreementVersions) -> CpCommand {
    CpCommand::AcceptAgreements {
        form: synthetic_agreements(tenant, versions),
        at: AT,
    }
}

pub(crate) fn provisioned_cmd(tenant: TenantId) -> CpCommand {
    CpCommand::RecordProvisioned { tenant, at: AT }
}

/// A state whose only record is the offer of `versions`.
pub(crate) fn offered(versions: AgreementVersions) -> SignupState {
    let mut s = SignupState::new();
    must(&mut s, &offer_cmd(versions));
    s
}

pub(crate) fn review_cmd(tenant: TenantId, staff: StaffId, outcome: ReviewOutcome) -> CpCommand {
    CpCommand::ReviewTenant {
        tenant,
        staff,
        outcome,
        at: AT,
    }
}

/// Decides `cmd` and folds its records into `state`. Returns the records,
/// or the refusal with `state` unchanged.
pub(crate) fn run(state: &mut SignupState, cmd: &CpCommand) -> Result<Vec<CpRecord>, SignupError> {
    let records = decide(state, cmd)?;
    for r in &records {
        state.apply(r)?;
    }
    Ok(records)
}

/// Runs `cmd` and fails the test with its refusal.
pub(crate) fn must(state: &mut SignupState, cmd: &CpCommand) -> Vec<CpRecord> {
    match run(state, cmd) {
        Ok(records) => records,
        Err(e) => panic!("{cmd:?} was refused: {e:?}"),
    }
}

/// A state in which `versions` are offered and `tenant` signed up and
/// accepted them.
pub(crate) fn signed_and_accepted(tenant: TenantId, versions: AgreementVersions) -> SignupState {
    let mut s = offered(versions);
    must(&mut s, &signup_cmd(tenant));
    must(&mut s, &accept_cmd(tenant, versions));
    s
}

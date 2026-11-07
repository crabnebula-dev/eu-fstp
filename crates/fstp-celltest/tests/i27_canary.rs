//! T5 of M6 design section 7: I-27 canaries through the dispatcher.
//!
//! A synthetic world seeds proposal titles and text, team names,
//! identities, IRC concern text and a copy address as `fstp-celltest`
//! canaries. Every template is composed for that world, stored as the
//! outbox body, and sent by the `fstp-dispatch` worker to the loopback
//! SMTP sink. The scan reads:
//!
//! - what the server received: the envelope and the DATA bytes;
//! - each decoded MIME part (quoted-printable and base64);
//! - each stored outbox body.
//!
//! A hit fails the test. The copy address is the recipient of its own
//! message, so it may appear in that message's envelope and `To` header,
//! and nowhere else. The placeholder enum itself is enumerated by
//! `fstp-mail` (`i_27_placeholder_enum_is_enumerated`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use fstp_api_testkit::smtp_sink::{SinkConfig, SmtpSink};
use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::scan::{StoreSet, scan};
use fstp_dispatch::store::MemDelivery;
use fstp_dispatch::{LoadError, Outcome, Prepared, SmtpTransport, Source, Worker, prepare};
use fstp_domain::StateTag;
use fstp_domain::id::{CallId, ContractId, MilestoneId, ProposalId, RequestId};
use fstp_domain::time::Timestamp;
use fstp_mail::{
    Bindings, LinkTarget, MailConfig, Mailbox, Message, Moment, Origin, TEMPLATES, Value, ValueKind,
};
use fstp_money::{Amount, Currency};
use fstp_pgstore::Phase;
use fstp_rt::tokio::TokioRuntime;

const SENDER: &str = "noreply@tenant-a.example";
const AT: i64 = 1_794_050_000_000_000;

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

/// The synthetic world: what each id stands for, as canaries.
struct World {
    /// Every canary of the world.
    canaries: Vec<Canary>,
    /// The copy address of R-SB-04.
    copy_address: Canary,
    proposal: ProposalId,
    call: CallId,
}

fn world() -> World {
    let mut canaries = Vec::new();
    for kind in [
        // Proposal title and text, IRC concern text.
        CanaryKind::ProposalText,
        CanaryKind::ProposalText,
        CanaryKind::ProposalText,
        // Team names and the lead's identity.
        CanaryKind::Name,
        CanaryKind::Name,
        CanaryKind::Email,
        CanaryKind::Phone,
        CanaryKind::Country,
        CanaryKind::Document,
        CanaryKind::AccountId,
    ] {
        canaries.push(Canary::generate(1, kind).unwrap());
    }
    let copy_address = Canary::generate(1, CanaryKind::Email).unwrap();
    canaries.push(copy_address.clone());
    World {
        canaries,
        copy_address,
        proposal: ProposalId::from_raw(0x1111_2222_3333_4444_5555_6666_7777_8888),
        call: CallId::from_raw(0x0a0b_0c0d_0e0f_1011_1213_1415_1617_1819),
    }
}

fn value(w: &World, kind: ValueKind) -> Value {
    match kind {
        ValueKind::Proposal => Value::Proposal(w.proposal),
        ValueKind::Call => Value::Call(w.call),
        ValueKind::Contract => Value::Contract(ContractId::from_raw(41)),
        ValueKind::Milestone => Value::Milestone(MilestoneId::from_raw(42)),
        ValueKind::Request => Value::Request(RequestId::from_raw(43)),
        ValueKind::State => Value::State(StateTag::ALL[0]),
        ValueKind::Moment => Value::Moment(Moment::new(Timestamp::from_micros(AT), 60).unwrap()),
        ValueKind::Amount => Value::Amount(Amount::from_minor(1_250_000, Currency::Eur).unwrap()),
        ValueKind::Link => Value::Link(LinkTarget::Proposal(w.proposal)),
        ValueKind::Count => Value::Count(3),
    }
}

fn config() -> MailConfig {
    MailConfig {
        origin: Origin::new("https://demo-cell.example").unwrap(),
        from: Mailbox::new(SENDER).unwrap(),
        from_name: None,
        dkim: Vec::new(),
    }
}

/// One stored message: its outbox id, recipient and composed bytes.
struct Stored {
    outbox: [u8; 16],
    to: String,
    raw: Vec<u8>,
}

/// Composes every template for the world, as the timeline stores them.
fn compose_all(w: &World) -> Vec<Stored> {
    let cfg = config();
    let pdf = b"%PDF-1.7 synthetic sealed notice".to_vec();
    TEMPLATES
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let mut b = Bindings::new();
            for slot in t.slots() {
                b = b.with(slot, value(w, slot.kind()));
            }
            let to = if t.id() == fstp_mail::TemplateId::SubmissionCopy {
                w.copy_address.email_address()
            } else {
                format!("lead.{i}@synthetic.example")
            };
            let mailbox = Mailbox::new(&to).unwrap();
            let n = u8::try_from(i).unwrap();
            let raw = fstp_mail::compose(
                &cfg,
                &Message {
                    template: t,
                    bindings: &b,
                    to: &mailbox,
                    idem: [n; 32],
                    event: [n.wrapping_add(100); 32],
                    date: Timestamp::from_micros(AT),
                    pdf: t.allows_pdf().then_some(pdf.as_slice()),
                },
            )
            .unwrap_or_else(|e| panic!("{:?}: {e}", t.id()));
            Stored {
                outbox: [n.wrapping_add(1); 16],
                to,
                raw,
            }
        })
        .collect()
}

/// S2 over the stored bodies, through `fstp_dispatch::prepare`.
struct StoredSource(BTreeMap<[u8; 16], Vec<u8>>);

impl Source for StoredSource {
    async fn load(&mut self, outbox: [u8; 16]) -> Result<Prepared, LoadError> {
        let raw = self.0.get(&outbox).ok_or(LoadError::Unusable)?;
        prepare(raw, SENDER).map_err(|_| LoadError::Unusable)
    }
}

/// The canaries a store about the message to `to` must not hold: all of
/// them, except the recipient's own address where `allow_recipient` says
/// so.
fn forbidden(w: &World, to: &str, allow_recipient: bool) -> Vec<Canary> {
    w.canaries
        .iter()
        .filter(|c| !(allow_recipient && c.email_address() == to))
        .cloned()
        .collect()
}

fn assert_clean(stores: &StoreSet, canaries: &[Canary], what: &str) {
    let report = scan(stores, canaries).unwrap();
    assert!(report.is_clean(), "I-27: {what}: {:?}", report.hits);
}

/// The stores of a decoded message: each leaf part and its subject.
fn decoded_parts(raw: &[u8]) -> StoreSet {
    let parsed = fstp_mail::parse(raw).unwrap_or_else(|e| panic!("parse: {e}"));
    let mut parts = StoreSet::default();
    for (i, p) in parsed.parts.iter().enumerate() {
        parts.push(format!("part {i} {}", p.content_type), p.decoded.clone());
    }
    let subject = parsed.header("Subject").unwrap_or_default();
    let subject = fstp_mail::encode::decode_unstructured(subject).unwrap();
    parts.push("subject", subject.into_bytes());
    parts
}

/// I-27, M6 design section 7 (T5): no canary of the world reaches what
/// the server received, a decoded MIME part or a stored outbox body, for
/// every template sent by the dispatcher.
#[test]
fn i27_dispatched_mail_holds_no_canary() {
    let w = world();
    let stored = compose_all(&w);
    assert_eq!(stored.len(), TEMPLATES.len());
    let sink = rt()
        .block_on(SmtpSink::start(rt(), SinkConfig::default()))
        .unwrap();
    let mut tx = SmtpTransport::new(
        rt().clone(),
        sink.client().unwrap(),
        "127.0.0.1",
        sink.addr().port(),
    );
    let ids: Vec<[u8; 16]> = stored.iter().map(|s| s.outbox).collect();
    let mut log = MemDelivery::new(ids.iter().copied());
    let mut source = StoredSource(stored.iter().map(|s| (s.outbox, s.raw.clone())).collect());
    let mut worker = Worker::new([9; 16]);
    for _ in 0..(5 * ids.len() + 5) {
        let _: Outcome = rt().block_on(worker.step(&mut log, &mut source, &mut tx, &ids, AT));
    }
    for s in &stored {
        assert_eq!(
            log.head(&s.outbox).map(|h| h.phase),
            Some(Phase::Sent),
            "every template was delivered"
        );
    }
    let received = sink.messages();
    assert_eq!(received.len(), stored.len());
    for s in &stored {
        let got = received
            .iter()
            .find(|m| m.data == s.raw)
            .unwrap_or_else(|| panic!("{} was not received byte for byte", s.to));
        assert_eq!(got.to, vec![s.to.clone()]);
        // Everything except the recipient's own address.
        let mut transcript = StoreSet::default();
        transcript.push(
            "envelope and data",
            [
                format!(
                    "MAIL FROM:<{}>\r\nRCPT TO:<{}>\r\nDATA\r\n",
                    got.from, got.to[0]
                )
                .into_bytes(),
                got.data.clone(),
            ]
            .concat(),
        );
        transcript.push("outbox body", s.raw.clone());
        assert_clean(&transcript, &forbidden(&w, &s.to, true), "transcript");
        // The decoded parts: not even the recipient's address.
        assert_clean(
            &decoded_parts(&got.data),
            &forbidden(&w, &s.to, false),
            "parts",
        );
    }
}

/// I-27 teeth (T5): a canary hidden behind a quoted-printable soft break
/// and in a base64 part is found in the decoded parts.
#[test]
fn i27_canary_scan_teeth_finds_encoded_content() {
    let w = world();
    let text = w.canaries[0].text();
    let (a, b) = text.split_at(10);
    let b64 = fstp_mail::encode::base64_encode_wrapped(w.canaries[3].text().as_bytes());
    let raw = format!(
        "From: <{SENDER}>\r\nTo: <lead@synthetic.example>\r\nSubject: s\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\n\
         Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n\
         {a}=\r\n{b}\r\n--b\r\nContent-Type: application/pdf; name=\"notice.pdf\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{b64}--b--\r\n"
    );
    let report = scan(&decoded_parts(raw.as_bytes()), &w.canaries).unwrap();
    let hits: Vec<&String> = report.hits.iter().map(|(_, c)| c).collect();
    assert!(hits.contains(&&w.canaries[0].text()), "{hits:?}");
    assert!(hits.contains(&&w.canaries[3].text()), "{hits:?}");
}

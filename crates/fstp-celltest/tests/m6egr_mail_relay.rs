//! M6 lane L6-EGR (ADR-018, proposed): the tenant's mail relay setting
//! through the one dispatch, and the cell's mail submission egress
//! against the test SMTP sink.
//!
//! - The setting is a tenant admin's high-risk operation: it asks for a
//!   step-up and appends nothing before it (I-78, R-LG-03). A CrabNebula
//!   host is refused under I-38 before any step-up.
//! - `fstp_cell::egress::MailEgress` opens port 465 only, verifies the
//!   relay against the public roots plus the pinned CA, and hands the
//!   stream to `fstp_smtp`. Here its transport reaches the loopback sink,
//!   whose certificate the `fstp-tls` test CA issued for `localhost`.
//!
//! Every value is synthetic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::port::LoginMethod;
use fstp_api_core::{ApiError, Op, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::fixture::{self, World};
use fstp_api_testkit::smtp_sink::{SinkConfig, SmtpSink};
use fstp_cell::config::Mode;
use fstp_cell::egress::{MailEgress, MailFault, MailHost, MailTransport};
use fstp_domain::id::AccountId;
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_engine::{Record, record_from_json_at};
use fstp_json::{Object, Value};
use fstp_ledger::{MemStore, RecordStore};
use fstp_rt::Runtime;
use fstp_rt::tokio::TokioRuntime;
use fstp_smtp::client::{Credentials, Envelope, SUBMISSION_PORT, SmtpError};
use fstp_tls::TlsErrorKind;

const A1: AccountId = AccountId::from_raw(0x0a01);

/// The `fstp-tls` test CA, which issued the sink's certificate.
const TEST_CA: &[u8] = include_bytes!("../../fstp-tls/testdata/ca.pem");

/// A SaaS cell whose only tenant admin is A1.
fn cell() -> FakeCell {
    let mut truth = GroundTruth::new();
    truth.set_identity(A1, IdentityTag::new(0xa1));
    truth.verify(A1);
    let mut o = Object::new();
    o.insert("cell", Value::from("saas"));
    o.insert("first_admin", Value::from(A1.raw().to_string()));
    o.insert("kind", Value::from("TenantProvisioned"));
    let mut env = Object::new();
    env.insert("onboarding", Value::Object(o));
    let rec: Record = record_from_json_at(1, &Value::Object(env)).unwrap();
    let mut store = MemStore::new();
    let head = store.head();
    store
        .append(head, 1_000_000, [0x7e; 16], vec![rec])
        .unwrap();
    let world = World {
        store,
        truth,
        start: fixture::START,
        admins: [A1].into_iter().collect(),
    };
    FakeCell::from_world(&world).unwrap()
}

fn set(host: &str, ca_pem: &str) -> Result<Op, ApiError> {
    let mut o = Object::new();
    o.insert("ca_pem", Value::from(ca_pem));
    o.insert("credential", Value::from("mail-relay"));
    o.insert("host", Value::from(host));
    let body = fstp_json::to_canonical(&Value::Object(o)).unwrap();
    decode_route(Method::Put, "/admin/settings/mail-relay", body.as_bytes())
}

/// I-78, R-LG-03, ADR-018: setting the mail relay asks for a step-up bound
/// to its digest and appends nothing before it. With the proof it records
/// the relay, and the pinned CA is stored as a text, never in the record.
#[test]
fn i78_set_mail_relay_needs_a_step_up() {
    let c = cell();
    let l = c.login(A1, LoginMethod::Passkey);
    let pem = std::str::from_utf8(TEST_CA).unwrap();
    let ch = match c.web(&l, set("smtp.relay.example", pem)) {
        Ok(OpResult::StepUpRequired(ch)) => ch,
        other => panic!("I-78: set without a proof: {other:?}"),
    };
    assert!(c.ports.engine.appended().is_empty());
    c.ports.step_up.approve(l.session, ch.action).unwrap();
    match c.web(&l, set("smtp.relay.example", pem)) {
        Ok(OpResult::Done { .. }) => {}
        other => panic!("set with its proof: {other:?}"),
    }
    assert_eq!(c.ports.engine.appended().len(), 1);
    let s = c.ports.engine.state();
    let relay = s.tenant.state().and_then(|t| t.mail_relay().cloned());
    let relay = relay.expect("the relay is recorded");
    assert_eq!(relay.host.as_str(), "smtp.relay.example");
    assert_eq!(relay.credential.as_str(), "mail-relay");
    let ca = relay.ca.expect("the pinned CA is referenced");
    let stored = c.ports.texts.public_texts();
    assert_eq!(stored.get(&ca.id()).map(String::as_str), Some(pem), "CA");
}

/// I-38, ADR-018: a CrabNebula host is refused under I-38 before any
/// step-up, and nothing is recorded.
#[test]
fn i38_set_mail_relay_refuses_a_crabnebula_host_before_step_up() {
    let c = cell();
    let l = c.login(A1, LoginMethod::Passkey);
    match c.web(&l, set("smtp.fstp.crabnebula.dev", "")) {
        Err(ApiError::Refused { rule, .. }) => assert_eq!(rule, "I-38"),
        other => panic!("I-38: {other:?}"),
    }
    assert!(c.ports.step_up.begun().is_empty(), "a step-up was begun");
    assert!(c.ports.engine.appended().is_empty());
}

/// A transport that opens every relay at the sink's loopback address and
/// records the host and port it was asked for.
struct SinkTransport {
    rt: TokioRuntime,
    addr: SocketAddr,
    opened: Mutex<Vec<(String, u16)>>,
}

impl MailTransport for SinkTransport {
    type Conn = <TokioRuntime as Runtime>::Tcp;

    fn open(
        &self,
        host: &MailHost,
        port: u16,
    ) -> impl Future<Output = Result<Self::Conn, MailFault>> + Send {
        self.opened
            .lock()
            .unwrap()
            .push((host.as_str().to_owned(), port));
        let rt = self.rt.clone();
        let addr = self.addr;
        async move {
            rt.connect_tcp(addr)
                .await
                .map_err(|_| MailFault::Unreachable)
        }
    }
}

const BODY: &[u8] = b"From: noreply@cell.fstp.test\r\n\
To: applicant-1@example.test\r\n\
Subject: Synthetic notice\r\n\
\r\n\
Proposal P-000123 is SUBMITTED.\r\n";

fn envelope() -> Envelope {
    Envelope {
        from: "noreply@cell.fstp.test".to_owned(),
        to: "applicant-1@example.test".to_owned(),
    }
}

/// Runs `f` with a sink on loopback and an egress to it, which pins
/// `ca_pem` when given.
fn with_egress<F, Fut>(ca_pem: Option<&'static [u8]>, f: F)
where
    F: FnOnce(TokioRuntime, SmtpSink, MailEgress<TokioRuntime, SinkTransport>) -> Fut,
    Fut: Future<Output = ()>,
{
    let rt = TokioRuntime::new_current_thread().unwrap();
    let rt2 = rt.clone();
    rt.block_on(async move {
        let cfg = SinkConfig::default();
        let sink = SmtpSink::start(&rt2, cfg.clone()).await.unwrap();
        let transport = SinkTransport {
            rt: rt2.clone(),
            addr: sink.addr(),
            opened: Mutex::new(Vec::new()),
        };
        let egress = MailEgress::new(
            Mode::Saas,
            rt2.clone(),
            transport,
            "localhost",
            ca_pem,
            "cell.fstp.test",
            Credentials::new(&cfg.username, &cfg.password),
        )
        .unwrap();
        f(rt2, sink, egress).await;
    });
}

/// ADR-018, R-NT-03: a message sent through the egress, with the sink's CA
/// pinned on top of the public roots, reaches the sink byte-exact. The
/// transport was asked for the relay host on port 465 only.
#[test]
fn adr018_send_through_mail_egress_reaches_the_test_sink() {
    with_egress(Some(TEST_CA), |rt, sink, egress| async move {
        let staged = egress.stage(&envelope(), BODY).await.unwrap();
        assert!(sink.messages().is_empty(), "I-26: nothing before the dot");
        let reply = staged.commit().await.unwrap();
        assert_eq!(reply.code(), 250);
        rt.sleep(Duration::from_millis(50)).await;
        let got = sink.messages();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, BODY);
        assert_eq!(got[0].to, ["applicant-1@example.test"]);
        let opened = egress.transport().opened.lock().unwrap().clone();
        assert_eq!(opened, [("localhost".to_owned(), SUBMISSION_PORT)]);
    });
}

/// ADR-018, R-NF-09: without the pinned CA the sink's certificate chains
/// to no trusted root, so the handshake fails before any SMTP byte and
/// the sink keeps nothing.
#[test]
fn r_nf_09_mail_egress_refuses_an_unknown_ca() {
    with_egress(None, |rt, sink, egress| async move {
        let r = egress.stage(&envelope(), BODY).await;
        assert_eq!(
            r.err(),
            Some(MailFault::Smtp(SmtpError::Tls(
                TlsErrorKind::UntrustedCertificate
            )))
        );
        rt.sleep(Duration::from_millis(50)).await;
        assert!(sink.messages().is_empty());
    });
}

/// I-38, ADR-018: the egress refuses a CrabNebula relay and an invalid
/// pinned CA before it opens anything.
#[test]
fn i38_mail_egress_refuses_crabnebula_relays_and_bad_pins() {
    let rt = TokioRuntime::new_current_thread().unwrap();
    let mk = |host: &str, pem: Option<&[u8]>| {
        MailEgress::new(
            Mode::SelfHosted,
            rt.clone(),
            SinkTransport {
                rt: rt.clone(),
                addr: "127.0.0.1:9".parse().unwrap(),
                opened: Mutex::new(Vec::new()),
            },
            host,
            pem,
            "cell.fstp.test",
            Credentials::new("u", "p"),
        )
        .err()
    };
    assert_eq!(
        mk("licences.fstp.crabnebula.dev", None),
        Some(MailFault::Refused(
            fstp_cell::egress::EgressRefusal::CrabNebulaHost
        ))
    );
    assert_eq!(
        mk(
            "smtp.relay.example",
            Some(b"-----BEGIN CERTIFICATE-----\nx\n")
        ),
        Some(MailFault::Config)
    );
    assert_eq!(mk("smtp.relay.example", None), None);
}

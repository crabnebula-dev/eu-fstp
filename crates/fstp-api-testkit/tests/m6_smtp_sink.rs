//! M6 lane L6-SMTP: the fstp-smtp client against the in-process test SMTP
//! sink, over loopback TCP with implicit TLS from the fstp-tls test CA.
//!
//! I-25: a message arrives byte-exact, so the body digest the dispatcher
//! records is the digest of what the server holds. I-26, R-NT-03: nothing
//! is accepted before the final dot, and the refuse and drop faults surface
//! as typed errors that tell a definite failure from an unknown outcome.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::time::Duration;

use fstp_api_testkit::smtp_sink::{Fault, SinkConfig, SmtpSink};
use fstp_rt::Runtime;
use fstp_rt::tokio::TokioRuntime;
use fstp_smtp::client::{Credentials, Envelope, Phase, SmtpError};

const BODY: &[u8] = b"From: noreply@cell.fstp.test\r\n\
To: applicant-1@example.test\r\n\
Subject: Synthetic notice\r\n\
\r\n\
.a line that starts with a dot\r\n\
..and one with two\r\n\
Proposal P-000123 is SUBMITTED.\r\n";

fn envelope() -> Envelope {
    Envelope {
        from: "noreply@cell.fstp.test".to_owned(),
        to: "applicant-1@example.test".to_owned(),
    }
}

fn with_sink<F, Fut>(f: F)
where
    F: FnOnce(TokioRuntime, SmtpSink) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let rt = TokioRuntime::new_current_thread().unwrap();
    let rt2 = rt.clone();
    rt.block_on(async move {
        let sink = SmtpSink::start(&rt2, SinkConfig::default()).await.unwrap();
        f(rt2, sink).await;
    });
}

/// Lets the sink task catch up with what the client wrote.
async fn settle(rt: &TokioRuntime) {
    rt.sleep(Duration::from_millis(50)).await;
}

/// I-25: a message sent to the sink arrives byte-exact, dot-stuffing and
/// all, with its envelope.
#[test]
fn i25_message_sent_to_sink_arrives_byte_exact() {
    with_sink(|rt, sink| async move {
        let client = sink.client().unwrap();
        let tcp = rt.connect_tcp(sink.addr()).await.unwrap();
        let staged = client.stage(&rt, tcp, &envelope(), BODY).await.unwrap();
        let reply = staged.commit().await.unwrap();
        assert_eq!(reply.code(), 250);
        settle(&rt).await;
        let got = sink.messages();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, BODY);
        assert_eq!(got[0].from, "noreply@cell.fstp.test");
        assert_eq!(got[0].to, ["applicant-1@example.test"]);
        // An 8-bit body goes out with BODY=8BITMIME, also byte-exact.
        let eight = "Subject: x\r\n\r\nGr\u{fc}\u{df}e\r\n".as_bytes();
        let tcp = rt.connect_tcp(sink.addr()).await.unwrap();
        let staged = client.stage(&rt, tcp, &envelope(), eight).await.unwrap();
        staged.commit().await.unwrap();
        settle(&rt).await;
        assert_eq!(sink.messages()[1].data, eight);
    });
}

/// I-26, R-NT-03: a staged message holds everything but the final dot, so
/// the sink has accepted nothing until the commit. An abandoned stage
/// never arrives.
#[test]
fn i26_staged_message_is_not_accepted_before_commit() {
    with_sink(|rt, sink| async move {
        let client = sink.client().unwrap();
        let tcp = rt.connect_tcp(sink.addr()).await.unwrap();
        let staged = client.stage(&rt, tcp, &envelope(), BODY).await.unwrap();
        settle(&rt).await;
        assert!(sink.messages().is_empty(), "accepted before the final dot");
        staged.abandon().await;
        settle(&rt).await;
        assert!(sink.messages().is_empty(), "an abandoned stage arrived");
        let tcp = rt.connect_tcp(sink.addr()).await.unwrap();
        let staged = client.stage(&rt, tcp, &envelope(), BODY).await.unwrap();
        settle(&rt).await;
        assert!(sink.messages().is_empty());
        staged.commit().await.unwrap();
        settle(&rt).await;
        assert_eq!(sink.messages().len(), 1);
    });
}

/// I-26: the refuse fault answers the end of DATA with 451. The client
/// reports a definite transient failure, and the sink holds nothing.
#[test]
fn i26_refuse_fault_surfaces_as_transient_error() {
    with_sink(|rt, sink| async move {
        let client = sink.client().unwrap();
        sink.set_fault(Some(Fault::Refuse(451)));
        let tcp = rt.connect_tcp(sink.addr()).await.unwrap();
        let staged = client.stage(&rt, tcp, &envelope(), BODY).await.unwrap();
        let err = staged.commit().await.unwrap_err();
        match &err {
            SmtpError::Transient { phase, reply } => {
                assert_eq!(*phase, Phase::EndOfData);
                assert_eq!(reply.code(), 451);
            }
            other => panic!("expected a transient failure, got {other:?}"),
        }
        assert!(!err.in_doubt());
        settle(&rt).await;
        assert!(sink.messages().is_empty());
        // The fault is one-shot: the retry is accepted.
        let tcp = rt.connect_tcp(sink.addr()).await.unwrap();
        let staged = client.stage(&rt, tcp, &envelope(), BODY).await.unwrap();
        staged.commit().await.unwrap();
        settle(&rt).await;
        assert_eq!(sink.messages().len(), 1);
        // A 5xx refusal is permanent.
        sink.set_fault(Some(Fault::Refuse(550)));
        let tcp = rt.connect_tcp(sink.addr()).await.unwrap();
        let staged = client.stage(&rt, tcp, &envelope(), BODY).await.unwrap();
        let err = staged.commit().await.unwrap_err();
        assert!(
            matches!(
                err,
                SmtpError::Permanent {
                    phase: Phase::EndOfData,
                    ..
                }
            ),
            "{err:?}"
        );
    });
}

/// I-26: the drop fault closes the connection after the final dot without
/// a reply. The outcome is unknown, so the client reports it in doubt and
/// the dispatcher never sends it again on its own. The lose-reply fault
/// shows why: the sink accepted that message.
#[test]
fn i26_drop_fault_surfaces_as_in_doubt() {
    with_sink(|rt, sink| async move {
        let client = sink.client().unwrap();
        for (fault, kept) in [(Fault::Drop, 0), (Fault::LoseReply, 1)] {
            sink.set_fault(Some(fault));
            let tcp = rt.connect_tcp(sink.addr()).await.unwrap();
            let staged = client.stage(&rt, tcp, &envelope(), BODY).await.unwrap();
            let err = staged.commit().await.unwrap_err();
            assert!(
                matches!(
                    err,
                    SmtpError::Closed {
                        phase: Phase::EndOfData
                    }
                ),
                "{fault:?}: {err:?}"
            );
            assert!(err.in_doubt(), "{fault:?}");
            settle(&rt).await;
            assert_eq!(sink.messages().len(), kept, "{fault:?}");
        }
    });
}

/// I-26: failures before the final dot are definite. Wrong credentials
/// fail at AUTH with 535 and are never in doubt.
#[test]
fn i26_auth_refusal_is_permanent_and_not_in_doubt() {
    with_sink(|rt, sink| async move {
        let client = sink
            .client()
            .unwrap()
            .with_credentials(Credentials::new("demo", "wrong"));
        let tcp = rt.connect_tcp(sink.addr()).await.unwrap();
        let Err(err) = client.stage(&rt, tcp, &envelope(), BODY).await else {
            panic!("staged with wrong credentials");
        };
        match &err {
            SmtpError::Permanent { phase, reply } => {
                assert_eq!(*phase, Phase::Auth);
                assert_eq!(reply.code(), 535);
            }
            other => panic!("expected 535 at AUTH, got {other:?}"),
        }
        assert!(!err.in_doubt());
        assert!(!format!("{client:?}").contains("wrong"), "credentials leak");
    });
}

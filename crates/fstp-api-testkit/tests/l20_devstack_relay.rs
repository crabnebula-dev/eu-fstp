//! ADR-026 record of lane L20: the devstack's relay process. It accepts
//! mail over implicit TLS with the sink's synthetic credential, writes each
//! message to its mail directory byte for byte, and its fake resolver
//! answers a TXT question of each kind. Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fstp_rt::Runtime as _;
use fstp_rt::tokio::TokioRuntime;
use fstp_smtp::client::{Credentials, Envelope, SmtpClient};
use fstp_tls::ClientConfig;

const CA_PEM: &[u8] = include_bytes!("../../fstp-tls/testdata/ca.pem");

/// A TXT question for `name` over TCP, and the text of the first answer.
fn ask_txt(addr: SocketAddr, name: &str) -> String {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        q.push(u8::try_from(label.len()).unwrap());
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 16, 0, 1]);
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut out = u16::try_from(q.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(&q);
    s.write_all(&out).unwrap();
    let mut len = [0u8; 2];
    s.read_exact(&mut len).unwrap();
    let mut a = vec![0u8; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut a).unwrap();
    assert_eq!(&a[..2], &[0x12, 0x34], "the id is echoed");
    assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1, "one answer");
    // The question is copied, then the answer: a 2-byte pointer, type,
    // class, TTL and length (10 bytes), then the TXT string.
    let rdata = q.len() + 12;
    let n = usize::from(a[rdata]);
    String::from_utf8(a[rdata + 1..rdata + 1 + n].to_vec()).unwrap()
}

/// ADR-026 record of lane L20, rule A9: the relay process of the
/// devstack accepts mail, keeps it as files, and answers TXT questions.
#[test]
fn l20_devstack_relay_accepts_mail_and_answers_txt() {
    let tag = fstp_crypto::random_array::<6>().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "fstp-l20-relay-{}",
        tag.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    let mut child = Command::new(env!("CARGO_BIN_EXE_fstp-devstack-relay"))
        .arg(dir.join("mail"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut got = std::collections::BTreeMap::new();
    for line in lines.by_ref() {
        let line = line.unwrap();
        if line == "ready" {
            break;
        }
        let (k, v) = line.split_once(' ').unwrap();
        got.insert(k.to_owned(), v.to_owned());
    }
    let relay: SocketAddr = got["relay"].parse().unwrap();
    let resolver: SocketAddr = got["resolver"].parse().unwrap();
    assert!(relay.ip().is_loopback() && resolver.ip().is_loopback());

    assert_eq!(
        ask_txt(resolver, "_dmarc.mail.example.test"),
        "v=DMARC1; p=reject"
    );
    assert!(ask_txt(resolver, "dev._domainkey.mail.example.test").starts_with("v=DKIM1;"));
    assert_eq!(ask_txt(resolver, "mail.example.test"), "v=spf1 -all");

    let body: &[u8] = b"Subject: Synthetic invitation\r\n\r\nOpen https://a.fstp.localhost/auth/invite#synthetic\r\n";
    let rt = TokioRuntime::new_current_thread().unwrap();
    let client = SmtpClient::new(
        ClientConfig::new(CA_PEM).unwrap(),
        "localhost",
        "cell.fstp.test",
        Credentials::new(&got["user"], &got["password"]),
    );
    let reply = rt.block_on(async {
        let tcp = rt.connect_tcp(relay).await.unwrap();
        let envelope = Envelope {
            from: "noreply@cell.fstp.test".to_owned(),
            to: "admin-2@example.test".to_owned(),
        };
        client
            .stage(&rt, tcp, &envelope, body)
            .await
            .unwrap()
            .commit()
            .await
            .unwrap()
    });
    assert_eq!(reply.code(), 250);
    let file = dir.join("mail").join("0001.eml");
    let start = Instant::now();
    while !file.exists() && start.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        std::fs::read(&file).unwrap(),
        body,
        "the message, byte for byte"
    );

    drop(child.stdin.take());
    let status = child.wait().unwrap();
    assert!(status.success(), "the relay ends when its input closes");
    let _ = std::fs::remove_dir_all(&dir);
}

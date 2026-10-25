//! Client behaviour against scripted servers over the in-memory duplex.
//!
//! A real PostgreSQL server never sends a wrong SCRAM signature, asks for
//! MD5 over this configuration, or injects plaintext after `S`. These tests
//! play such servers to check that the client refuses them. Tests named
//! `r_nf_09_*` verify R-NF-09; `th26_*` tests cover hostile input (TH-26).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::num::NonZeroU32;

use fstp_pgwire::proto::backend::{
    Authentication, BackendMessage, DataRow, ErrorFields, FieldDescription, TransactionStatus,
};
use fstp_pgwire::{
    AuthMethod, Client, ClientTls, Config, ErrorKind, Password, RequireAuth, Session, base64,
};
use fstp_rt::duplex::{DuplexStream, duplex};
use fstp_rt::future::join;
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Connection, IoExt, Runtime};
use fstp_tls::{ServerConfig, TlsStream};

const CA: &[u8] = include_bytes!("../../fstp-tls/testdata/ca.pem");
const SERVER: &[u8] = include_bytes!("../../fstp-tls/testdata/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../../fstp-tls/testdata/server-key.pem");
const CLIENT: &[u8] = include_bytes!("../../fstp-tls/testdata/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("../../fstp-tls/testdata/client-key.pem");
const PASSWORD: &str = "mock-password";

fn rt() -> &'static TokioRuntime {
    static RT: std::sync::OnceLock<TokioRuntime> = std::sync::OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

fn config() -> Config {
    Config::new(
        "localhost",
        5432,
        "alice",
        Password::new(PASSWORD).unwrap(),
        "db",
        ClientTls::new(CA, CLIENT, CLIENT_KEY).unwrap(),
    )
    .unwrap()
    .connect_timeout(None)
}

fn server_der() -> Vec<u8> {
    let text = std::str::from_utf8(SERVER).unwrap();
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    base64::decode(body.as_bytes()).unwrap()
}

/// The server side of a connection.
struct Peer<S> {
    io: S,
}

impl<S: Connection> Peer<S> {
    async fn read_startup(&mut self) -> Vec<u8> {
        let mut len = [0u8; 4];
        self.io.read_exact(&mut len).await.unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize - 4];
        self.io.read_exact(&mut body).await.unwrap();
        body
    }

    async fn read_msg(&mut self) -> (u8, Vec<u8>) {
        let mut head = [0u8; 5];
        self.io.read_exact(&mut head).await.unwrap();
        let len = u32::from_be_bytes(head[1..5].try_into().unwrap()) as usize;
        let mut body = vec![0u8; len - 4];
        self.io.read_exact(&mut body).await.unwrap();
        (head[0], body)
    }

    async fn send(&mut self, msgs: &[BackendMessage]) {
        let mut out = Vec::new();
        for m in msgs {
            m.encode(&mut out).unwrap();
        }
        self.io.write_all(&out).await.unwrap();
        self.io.flush().await.unwrap();
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        self.io.write_all(bytes).await.unwrap();
        self.io.flush().await.unwrap();
    }

    /// Sends the messages that end a successful startup.
    async fn ready(&mut self) {
        self.send(&[
            BackendMessage::Authentication(Authentication::Ok),
            BackendMessage::ParameterStatus {
                name: "client_encoding".into(),
                value: "UTF8".into(),
            },
            BackendMessage::BackendKeyData {
                process_id: 42,
                secret_key: 7,
            },
            BackendMessage::ReadyForQuery(TransactionStatus::Idle),
        ])
        .await;
    }
}

/// Accepts the SSLRequest and the TLS handshake as the test server.
async fn accept_tls(io: DuplexStream) -> Peer<TlsStream<DuplexStream>> {
    let mut io = io;
    let mut req = [0u8; 8];
    io.read_exact(&mut req).await.unwrap();
    assert_eq!(req, [0, 0, 0, 8, 4, 210, 22, 47]);
    io.write_all(b"S").await.unwrap();
    io.flush().await.unwrap();
    let cfg = ServerConfig::new(SERVER, SERVER_KEY).unwrap();
    Peer {
        io: fstp_tls::accept(&cfg, io).await.unwrap(),
    }
}

/// How the scripted SCRAM server misbehaves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scram {
    Honest,
    WrongSignature,
    ErrorInFinal,
    SkipFinal,
}

/// Plays the server side of SCRAM-SHA-256(-PLUS). Checks the client's GS2
/// header, channel binding data and proof like PostgreSQL does.
async fn scram_server<S: Connection>(
    peer: &mut Peer<S>,
    mechanisms: &[&str],
    expected_gs2: &str,
    behaviour: Scram,
) {
    peer.send(&[BackendMessage::Authentication(Authentication::Sasl {
        mechanisms: mechanisms.iter().map(|m| (*m).to_owned()).collect(),
    })])
    .await;
    let (tag, body) = peer.read_msg().await;
    assert_eq!(tag, b'p');
    let nul = body.iter().position(|b| *b == 0).unwrap();
    let mechanism = std::str::from_utf8(&body[..nul]).unwrap().to_owned();
    let data = &body[nul + 5..];
    let first = std::str::from_utf8(data).unwrap();
    assert!(first.starts_with(expected_gs2), "{first}");
    let bare = &first[expected_gs2.len()..];
    let cnonce = bare.strip_prefix("n=,r=").unwrap();
    let nonce = format!("{cnonce}srvnonce");
    let salt = b"pepper-salt";
    let server_first = format!("r={nonce},s={},i=4096", base64::encode(salt));
    peer.send(&[BackendMessage::Authentication(
        Authentication::SaslContinue {
            data: server_first.clone().into_bytes(),
        },
    )])
    .await;

    let (tag, body) = peer.read_msg().await;
    assert_eq!(tag, b'p');
    let fin = std::str::from_utf8(&body).unwrap();
    let (without_proof, proof) = fin.rsplit_once(",p=").unwrap();
    let mut cbind = expected_gs2.as_bytes().to_vec();
    if mechanism == "SCRAM-SHA-256-PLUS" {
        cbind.extend_from_slice(&fstp_crypto::sha256(&server_der()));
    }
    assert_eq!(
        without_proof,
        format!("c={},r={nonce}", base64::encode(&cbind)),
        "channel binding data"
    );
    let auth_message = format!("{bare},{server_first},{without_proof}");
    let mut salted = [0u8; 32];
    fstp_crypto::pbkdf2_hmac_sha256(
        PASSWORD.as_bytes(),
        salt,
        NonZeroU32::new(4096).unwrap(),
        &mut salted,
    );
    let client_key = fstp_crypto::hmac_sha256(&salted, b"Client Key");
    let stored_key = fstp_crypto::sha256(&client_key);
    let signature = fstp_crypto::hmac_sha256(&stored_key, auth_message.as_bytes());
    let proof = base64::decode(proof.as_bytes()).unwrap();
    let recovered: Vec<u8> = proof.iter().zip(signature).map(|(p, s)| p ^ s).collect();
    assert_eq!(fstp_crypto::sha256(&recovered), stored_key, "client proof");
    let server_key = fstp_crypto::hmac_sha256(&salted, b"Server Key");
    let mut server_sig = fstp_crypto::hmac_sha256(&server_key, auth_message.as_bytes());
    match behaviour {
        Scram::Honest => {}
        Scram::WrongSignature => server_sig[0] ^= 1,
        Scram::ErrorInFinal => {
            peer.send(&[BackendMessage::Authentication(Authentication::SaslFinal {
                data: b"e=other-error".to_vec(),
            })])
            .await;
            return;
        }
        Scram::SkipFinal => {
            peer.send(&[BackendMessage::Authentication(Authentication::Ok)])
                .await;
            return;
        }
    }
    peer.send(&[BackendMessage::Authentication(Authentication::SaslFinal {
        data: format!("v={}", base64::encode(&server_sig)).into_bytes(),
    })])
    .await;
}

fn run_tls<F, Fut>(cfg: Config, server: F) -> Result<Client<TokioRuntime>, fstp_pgwire::Error>
where
    F: FnOnce(Peer<TlsStream<DuplexStream>>) -> Fut,
    Fut: std::future::Future<Output = Peer<TlsStream<DuplexStream>>>,
{
    let (c, s) = duplex(1 << 16);
    rt().block_on(async {
        let (client, _peer) = join(Client::connect_over(rt(), c, &cfg), async move {
            let mut peer = accept_tls(s).await;
            peer.read_startup().await;
            server(peer).await
        })
        .await;
        client
    })
}

#[test]
fn r_nf_09_scram_plus_binds_to_the_server_certificate() {
    let client = run_tls(config(), |mut p| async move {
        scram_server(
            &mut p,
            &["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"],
            "p=tls-server-end-point,,",
            Scram::Honest,
        )
        .await;
        p.ready().await;
        p
    })
    .unwrap();
    assert_eq!(client.auth_method(), Some(AuthMethod::ScramSha256Plus));
    assert_eq!(client.cancel_token().process_id(), Some(42));
}

#[test]
fn r_nf_09_client_signals_channel_binding_support_when_not_offered() {
    let client = run_tls(config(), |mut p| async move {
        scram_server(&mut p, &["SCRAM-SHA-256"], "y,,", Scram::Honest).await;
        p.ready().await;
        p
    })
    .unwrap();
    assert_eq!(client.auth_method(), Some(AuthMethod::ScramSha256));
}

#[test]
fn r_nf_09_wrong_server_signature_is_rejected() {
    let err = run_tls(config(), |mut p| async move {
        scram_server(
            &mut p,
            &["SCRAM-SHA-256-PLUS"],
            "p=tls-server-end-point,,",
            Scram::WrongSignature,
        )
        .await;
        p.ready().await;
        p
    })
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Auth, "{err}");
}

#[test]
fn r_nf_09_scram_error_in_final_message_is_rejected() {
    let err = run_tls(config(), |mut p| async move {
        scram_server(&mut p, &["SCRAM-SHA-256"], "y,,", Scram::ErrorInFinal).await;
        p
    })
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Auth, "{err}");
}

#[test]
fn r_nf_09_authentication_ok_without_server_proof_is_rejected() {
    let err = run_tls(config(), |mut p| async move {
        scram_server(&mut p, &["SCRAM-SHA-256"], "y,,", Scram::SkipFinal).await;
        p
    })
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Auth, "{err}");
}

#[test]
fn r_nf_09_plain_scram_refused_when_channel_binding_is_required() {
    let cfg = config().require_auth(RequireAuth::SCRAM_PLUS_ONLY);
    let err = run_tls(cfg, |mut p| async move {
        p.send(&[BackendMessage::Authentication(Authentication::Sasl {
            mechanisms: vec!["SCRAM-SHA-256".into()],
        })])
        .await;
        p
    })
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Auth, "{err}");
}

fn single_auth_request(
    auth: Authentication,
    cfg: Config,
) -> Result<Client<TokioRuntime>, fstp_pgwire::Error> {
    run_tls(cfg, |mut p| async move {
        p.send(&[BackendMessage::Authentication(auth)]).await;
        p
    })
}

#[test]
fn md5_is_always_rejected() {
    let all = RequireAuth::SCRAM
        .with(AuthMethod::Password)
        .with(AuthMethod::None);
    let err = single_auth_request(
        Authentication::Md5Password { salt: *b"salt" },
        config().require_auth(all),
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Auth, "{err}");
    for auth in [
        Authentication::KerberosV5,
        Authentication::Gss,
        Authentication::Sspi,
        Authentication::ScmCredential,
    ] {
        let err = single_auth_request(auth, config().require_auth(all)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Auth, "{err}");
    }
}

#[test]
fn cleartext_password_is_rejected_by_default() {
    let err = single_auth_request(Authentication::CleartextPassword, config()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Auth, "{err}");
}

#[test]
fn cleartext_password_is_sent_inside_tls_only_when_allowed() {
    let cfg = config().require_auth(RequireAuth::only(&[AuthMethod::Password]));
    let client = run_tls(cfg, |mut p| async move {
        p.send(&[BackendMessage::Authentication(
            Authentication::CleartextPassword,
        )])
        .await;
        let (tag, body) = p.read_msg().await;
        assert_eq!(tag, b'p');
        assert_eq!(body, format!("{PASSWORD}\0").into_bytes());
        p.ready().await;
        p
    })
    .unwrap();
    assert_eq!(client.auth_method(), Some(AuthMethod::Password));
}

#[test]
fn unauthenticated_login_is_rejected_by_default() {
    let err = single_auth_request(Authentication::Ok, config()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Auth, "{err}");
    let cfg = config().require_auth(RequireAuth::SCRAM.with(AuthMethod::None));
    let client = run_tls(cfg, |mut p| async move {
        p.ready().await;
        p
    })
    .unwrap();
    assert_eq!(client.auth_method(), Some(AuthMethod::None));
}

/// Runs the client against raw server bytes sent right after the
/// SSLRequest, without TLS.
fn ssl_reply(reply: &'static [u8]) -> fstp_pgwire::Error {
    let (c, mut s) = duplex(1 << 16);
    rt().block_on(async {
        let (client, ()) = join(Client::connect_over(rt(), c, &config()), async move {
            let mut req = [0u8; 8];
            s.read_exact(&mut req).await.unwrap();
            s.write_all(reply).await.unwrap();
            s.flush().await.unwrap();
            if reply.is_empty() {
                drop(s);
            } else {
                // Keep the connection open until the client gives up.
                let mut sink = Vec::new();
                let _ = s.read_to_end(&mut sink, 1 << 20).await;
            }
        })
        .await;
        client.unwrap_err()
    })
}

#[test]
fn r_nf_09_ssl_refusal_is_tls_required() {
    assert_eq!(ssl_reply(b"N").kind(), ErrorKind::TlsRequired);
}

#[test]
fn th26_plaintext_injected_after_s_is_refused() {
    let err = ssl_reply(b"S\x16\x03\x03\x00\x02ab");
    assert_eq!(err.kind(), ErrorKind::Protocol, "{err}");
}

#[test]
fn th26_error_reply_to_ssl_request_is_not_parsed() {
    let err = ssl_reply(b"EFATAL: canary");
    assert_eq!(err.kind(), ErrorKind::Protocol);
    assert!(!err.to_string().contains("canary"));
    assert_eq!(ssl_reply(b"X").kind(), ErrorKind::Protocol);
    assert_eq!(ssl_reply(b"").kind(), ErrorKind::Closed);
}

// ----- Session-level sequencing over a plaintext duplex -----

/// Starts a session against a scripted plaintext server that accepts any
/// login, then runs `client` and `server` concurrently.
fn session_test<C, CF, S, SF>(client: C, server: S)
where
    C: FnOnce(Session) -> CF,
    CF: std::future::Future<Output = ()>,
    S: FnOnce(Peer<DuplexStream>) -> SF,
    SF: std::future::Future<Output = ()>,
{
    let (c, s) = duplex(1 << 20);
    let cfg = config().require_auth(RequireAuth::SCRAM.with(AuthMethod::None));
    rt().block_on(async {
        join(
            async {
                let session = Session::startup(Box::new(c), &cfg, None).await.unwrap();
                client(session).await;
            },
            async move {
                let mut peer = Peer { io: s };
                peer.read_startup().await;
                peer.ready().await;
                server(peer).await;
            },
        )
        .await;
    });
}

fn int4_column(name: &str) -> FieldDescription {
    FieldDescription {
        name: name.into(),
        table_oid: 0,
        column_id: 0,
        type_oid: 23,
        type_size: 4,
        type_modifier: -1,
        format: 0,
    }
}

/// Answers Parse/Describe/Sync for a one-column int4 statement.
async fn answer_prepare(peer: &mut Peer<DuplexStream>) {
    for &expected in b"PDS" {
        assert_eq!(peer.read_msg().await.0, expected);
    }
    peer.send(&[
        BackendMessage::ParseComplete,
        BackendMessage::ParameterDescription(vec![]),
        BackendMessage::RowDescription(vec![int4_column("x")]),
        BackendMessage::ReadyForQuery(TransactionStatus::Idle),
    ])
    .await;
    for &expected in b"BES" {
        assert_eq!(peer.read_msg().await.0, expected);
    }
}

fn error_fields(code: &str, severity: &str) -> ErrorFields {
    ErrorFields(vec![
        (b'S', severity.as_bytes().to_vec()),
        (b'V', severity.as_bytes().to_vec()),
        (b'C', code.as_bytes().to_vec()),
        (b'M', b"scripted error".to_vec()),
    ])
}

#[test]
fn th26_row_with_wrong_column_count_breaks_the_session() {
    session_test(
        |mut s| async move {
            let err = s.query("SELECT 1", &[]).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Protocol, "{err}");
            assert!(s.is_broken());
        },
        |mut p| async move {
            answer_prepare(&mut p).await;
            let row = DataRow::from_values(&[Some(&[0, 0, 0, 1]), None]).unwrap();
            p.send(&[BackendMessage::BindComplete, BackendMessage::DataRow(row)])
                .await;
        },
    );
}

#[test]
fn th26_ready_before_command_complete_breaks_the_session() {
    session_test(
        |mut s| async move {
            let err = s.query("SELECT 1", &[]).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Protocol, "{err}");
        },
        |mut p| async move {
            answer_prepare(&mut p).await;
            p.send(&[
                BackendMessage::BindComplete,
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ])
            .await;
        },
    );
}

#[test]
fn error_after_some_rows_is_reported_and_the_session_survives() {
    session_test(
        |mut s| async move {
            let err = s.query("SELECT 1", &[]).await.unwrap_err();
            assert_eq!(err.code(), Some("22012"));
            assert!(!s.is_broken());
            // The statement is cached, so the next query sends only Bind.
            let rows = s.query("SELECT 1", &[]).await.unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].get::<i32>(0).unwrap(), 9);
        },
        |mut p| async move {
            answer_prepare(&mut p).await;
            let row = DataRow::from_values(&[Some(&[0, 0, 0, 1])]).unwrap();
            p.send(&[
                BackendMessage::BindComplete,
                BackendMessage::DataRow(row),
                BackendMessage::NoticeResponse(error_fields("01000", "WARNING")),
                BackendMessage::ErrorResponse(error_fields("22012", "ERROR")),
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ])
            .await;
            for &expected in b"BES" {
                assert_eq!(p.read_msg().await.0, expected);
            }
            let row = DataRow::from_values(&[Some(&[0, 0, 0, 9])]).unwrap();
            p.send(&[
                BackendMessage::BindComplete,
                BackendMessage::ParameterStatus {
                    name: "TimeZone".into(),
                    value: "UTC".into(),
                },
                BackendMessage::DataRow(row),
                BackendMessage::CommandComplete("SELECT 1".into()),
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ])
            .await;
        },
    );
}

#[test]
fn th26_changed_client_encoding_breaks_the_session() {
    session_test(
        |mut s| async move {
            let err = s.query("SELECT 1", &[]).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Protocol, "{err}");
            assert!(s.is_broken());
        },
        |mut p| async move {
            for _ in 0..3 {
                p.read_msg().await;
            }
            p.send(&[BackendMessage::ParameterStatus {
                name: "client_encoding".into(),
                value: "LATIN1".into(),
            }])
            .await;
        },
    );
}

#[test]
fn fatal_error_breaks_the_session() {
    session_test(
        |mut s| async move {
            let err = s.query("SELECT 1", &[]).await.unwrap_err();
            assert_eq!(err.code(), Some("57P01"));
            assert!(s.is_broken());
            assert_eq!(
                s.query("SELECT 1", &[]).await.unwrap_err().kind(),
                ErrorKind::Closed
            );
        },
        |mut p| async move {
            for _ in 0..3 {
                p.read_msg().await;
            }
            p.send(&[BackendMessage::ErrorResponse(error_fields(
                "57P01", "FATAL",
            ))])
            .await;
        },
    );
}

#[test]
fn th26_unknown_message_type_breaks_the_session() {
    session_test(
        |mut s| async move {
            let err = s.query("SELECT 1", &[]).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Protocol, "{err}");
            assert!(s.is_broken());
        },
        |mut p| async move {
            for _ in 0..3 {
                p.read_msg().await;
            }
            p.send_raw(b"Q\x00\x00\x00\x04").await;
        },
    );
}

#[test]
fn th26_function_call_response_breaks_the_session() {
    session_test(
        |mut s| async move {
            let err = s.query("SELECT 1", &[]).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Protocol, "{err}");
            assert!(s.is_broken());
        },
        |mut p| async move {
            for _ in 0..3 {
                p.read_msg().await;
            }
            p.send(&[BackendMessage::Unsupported {
                tag: b'V',
                body: vec![0, 0, 0, 0],
            }])
            .await;
        },
    );
}

#[test]
fn th26_duplicate_backend_key_is_rejected() {
    let (c, s) = duplex(1 << 16);
    let cfg = config().require_auth(RequireAuth::SCRAM.with(AuthMethod::None));
    rt().block_on(async {
        let (result, ()) = join(Session::startup(Box::new(c), &cfg, None), async move {
            let mut p = Peer { io: s };
            p.read_startup().await;
            p.send(&[
                BackendMessage::Authentication(Authentication::Ok),
                BackendMessage::BackendKeyData {
                    process_id: 1,
                    secret_key: 1,
                },
                BackendMessage::BackendKeyData {
                    process_id: 2,
                    secret_key: 2,
                },
            ])
            .await;
        })
        .await;
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Protocol);
    });
}

#[test]
fn th26_cleartext_password_never_goes_over_a_plaintext_transport() {
    let (c, s) = duplex(1 << 16);
    let cfg = config().require_auth(RequireAuth::only(&[AuthMethod::Password]));
    rt().block_on(async {
        let (result, ()) = join(Session::startup(Box::new(c), &cfg, None), async move {
            let mut p = Peer { io: s };
            p.read_startup().await;
            p.send(&[BackendMessage::Authentication(
                Authentication::CleartextPassword,
            )])
            .await;
        })
        .await;
        assert_eq!(result.unwrap_err().kind(), ErrorKind::Auth);
    });
}

#[test]
fn th26_startup_messages_are_size_limited() {
    let (c, s) = duplex(1 << 20);
    let cfg = config();
    rt().block_on(async {
        let (result, ()) = join(Session::startup(Box::new(c), &cfg, None), async move {
            let mut p = Peer { io: s };
            p.read_startup().await;
            // An authentication message larger than the startup limit.
            let mut msg = vec![b'R'];
            msg.extend_from_slice(&(100_004u32).to_be_bytes());
            msg.extend_from_slice(&[0u8; 64]);
            p.send_raw(&msg).await;
        })
        .await;
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Protocol, "{err}");
    });
}

// ----- Regressions from the M1 review -----

/// The SQL text of a Parse message body.
fn parse_sql(body: &[u8]) -> String {
    let name_end = body.iter().position(|b| *b == 0).unwrap();
    let rest = &body[name_end + 1..];
    let sql_end = rest.iter().position(|b| *b == 0).unwrap();
    String::from_utf8(rest[..sql_end].to_vec()).unwrap()
}

/// Reads the Parse, Bind, Execute and Sync of a transaction control
/// statement and returns its SQL text.
async fn read_control<S: Connection>(peer: &mut Peer<S>) -> String {
    let (tag, body) = peer.read_msg().await;
    assert_eq!(tag, b'P');
    for &expected in b"BES" {
        assert_eq!(peer.read_msg().await.0, expected);
    }
    parse_sql(&body)
}

async fn answer_control<S: Connection>(peer: &mut Peer<S>, tag: &str, status: TransactionStatus) {
    peer.send(&[
        BackendMessage::ParseComplete,
        BackendMessage::BindComplete,
        BackendMessage::CommandComplete(tag.into()),
        BackendMessage::ReadyForQuery(status),
    ])
    .await;
}

/// A client config whose cancel requests go to a closed port, with a short
/// statement timeout.
fn timeout_config() -> Config {
    Config::new(
        "localhost",
        1,
        "alice",
        Password::new(PASSWORD).unwrap(),
        "db",
        ClientTls::new(CA, CLIENT, CLIENT_KEY).unwrap(),
    )
    .unwrap()
    .connect_timeout(None)
    .require_auth(RequireAuth::SCRAM.with(AuthMethod::None))
    .statement_timeout(Some(std::time::Duration::from_millis(200)))
    .cancel_grace(std::time::Duration::from_secs(3))
}

/// Runs `client` against a scripted TLS server that accepts any login and
/// then runs `server`.
fn tls_session_test<C, CF, S, SF>(cfg: Config, client: C, server: S)
where
    C: FnOnce(Client<TokioRuntime>) -> CF,
    CF: std::future::Future<Output = ()>,
    S: FnOnce(Peer<TlsStream<DuplexStream>>) -> SF,
    SF: std::future::Future<Output = ()>,
{
    let (c, s) = duplex(1 << 20);
    rt().block_on(async {
        join(
            async {
                let client_conn = Client::connect_over(rt(), c, &cfg).await.unwrap();
                client(client_conn).await;
            },
            async move {
                let mut peer = accept_tls(s).await;
                peer.read_startup().await;
                peer.ready().await;
                server(peer).await;
            },
        )
        .await;
    });
}

/// The server reports an error after CommandComplete, as PostgreSQL does
/// when the implicit transaction fails at commit. The client reports the
/// SQLSTATE, discards the row count and keeps the session.
#[test]
fn review_pg_err_after_commandcomplete_mock() {
    session_test(
        |mut s| async move {
            let err = s.execute("SELECT 1", &[]).await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Db, "{err}");
            assert_eq!(err.code(), Some("23503"));
            assert!(!s.is_broken());
            let mut stream = s.query_stream("SELECT 1", &[]).await.unwrap();
            assert!(stream.next().await.unwrap().is_some());
            let err = stream.next().await.unwrap_err();
            assert_eq!(err.code(), Some("40001"));
            assert_eq!(stream.rows_affected(), None);
            drop(stream);
            assert!(!s.is_broken());
            // A fatal error at the same point still breaks the session.
            let err = s.execute("SELECT 1", &[]).await.unwrap_err();
            assert_eq!(err.code(), Some("57P01"));
            assert!(s.is_broken());
        },
        |mut p| async move {
            answer_prepare(&mut p).await;
            let row = DataRow::from_values(&[Some(&[0, 0, 0, 1])]).unwrap();
            p.send(&[
                BackendMessage::BindComplete,
                BackendMessage::DataRow(row.clone()),
                BackendMessage::CommandComplete("SELECT 1".into()),
                BackendMessage::ErrorResponse(error_fields("23503", "ERROR")),
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ])
            .await;
            for &expected in b"BES" {
                assert_eq!(p.read_msg().await.0, expected);
            }
            p.send(&[
                BackendMessage::BindComplete,
                BackendMessage::DataRow(row.clone()),
                BackendMessage::CommandComplete("SELECT 1".into()),
                BackendMessage::ErrorResponse(error_fields("40001", "ERROR")),
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ])
            .await;
            for &expected in b"BES" {
                assert_eq!(p.read_msg().await.0, expected);
            }
            p.send(&[
                BackendMessage::BindComplete,
                BackendMessage::DataRow(row),
                BackendMessage::CommandComplete("SELECT 1".into()),
                BackendMessage::ErrorResponse(error_fields("57P01", "FATAL")),
            ])
            .await;
        },
    );
}

/// A BEGIN that exceeds the statement timeout but then succeeds leaves a
/// transaction open. No `Transaction` owns it, so the client rolls it back
/// before the next statement.
#[test]
fn review_pg_begin_timeout_unowned_tx() {
    tls_session_test(
        timeout_config(),
        |mut client| async move {
            let err = client.transaction().await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Timeout, "{err}");
            assert!(!client.is_broken());
            let tx = client.transaction().await.unwrap();
            tx.rollback().await.unwrap();
            assert_eq!(client.transaction_status(), TransactionStatus::Idle);
            assert!(!client.is_broken());
        },
        |mut p| async move {
            assert_eq!(read_control(&mut p).await, "BEGIN");
            // The server is slow, but BEGIN succeeds.
            rt().sleep(std::time::Duration::from_millis(600)).await;
            answer_control(&mut p, "BEGIN", TransactionStatus::InTransaction).await;
            assert_eq!(read_control(&mut p).await, "ROLLBACK");
            answer_control(&mut p, "ROLLBACK", TransactionStatus::Idle).await;
            assert_eq!(read_control(&mut p).await, "BEGIN");
            answer_control(&mut p, "BEGIN", TransactionStatus::InTransaction).await;
            assert_eq!(read_control(&mut p).await, "ROLLBACK");
            answer_control(&mut p, "ROLLBACK", TransactionStatus::Idle).await;
        },
    );
}

/// A prepare dropped by the statement timeout after its Parse was sent
/// created a named statement on the server. The client closes it later.
#[test]
fn review_pg_pending_close_lost_after_dropped_prepare() {
    tls_session_test(
        timeout_config(),
        |mut client| async move {
            let err = client.prepare("SELECT 1").await.unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Timeout, "{err}");
            assert!(!client.is_broken());
            assert_eq!(client.cached_statements(), 0);
            let rows = client.query("SELECT 1", &[]).await.unwrap();
            assert_eq!(rows[0].get::<i32>(0).unwrap(), 1);
        },
        |mut p| async move {
            let (tag, body) = p.read_msg().await;
            assert_eq!(tag, b'P');
            assert!(body.starts_with(b"fstp_1\0"));
            for &expected in b"DS" {
                assert_eq!(p.read_msg().await.0, expected);
            }
            rt().sleep(std::time::Duration::from_millis(600)).await;
            p.send(&[
                BackendMessage::ParseComplete,
                BackendMessage::ParameterDescription(vec![]),
                BackendMessage::RowDescription(vec![int4_column("x")]),
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ])
            .await;
            // The next request first closes the orphaned statement.
            let (tag, body) = p.read_msg().await;
            assert_eq!(tag, b'C');
            assert_eq!(body, b"Sfstp_1\0");
            let (tag, body) = p.read_msg().await;
            assert_eq!(tag, b'P');
            assert!(body.starts_with(b"fstp_2\0"));
            for &expected in b"DS" {
                assert_eq!(p.read_msg().await.0, expected);
            }
            p.send(&[
                BackendMessage::CloseComplete,
                BackendMessage::ParseComplete,
                BackendMessage::ParameterDescription(vec![]),
                BackendMessage::RowDescription(vec![int4_column("x")]),
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ])
            .await;
            for &expected in b"BES" {
                assert_eq!(p.read_msg().await.0, expected);
            }
            let row = DataRow::from_values(&[Some(&[0, 0, 0, 1])]).unwrap();
            p.send(&[
                BackendMessage::BindComplete,
                BackendMessage::DataRow(row),
                BackendMessage::CommandComplete("SELECT 1".into()),
                BackendMessage::ReadyForQuery(TransactionStatus::Idle),
            ])
            .await;
        },
    );
}

/// A server that asks for fewer SCRAM iterations than the configured floor
/// (4096 by default, RFC 7677) is refused before the client sends a proof.
#[test]
fn review_pg_scram_no_min_iterations_session() {
    let err = run_tls(config(), |mut p| async move {
        p.send(&[BackendMessage::Authentication(Authentication::Sasl {
            mechanisms: vec!["SCRAM-SHA-256".into()],
        })])
        .await;
        let (tag, body) = p.read_msg().await;
        assert_eq!(tag, b'p');
        let text = String::from_utf8_lossy(&body).into_owned();
        let cnonce = text.rsplit("r=").next().unwrap().to_owned();
        let server_first = format!("r={cnonce}srv,s={},i=1", base64::encode(b"salt"));
        p.send(&[BackendMessage::Authentication(
            Authentication::SaslContinue {
                data: server_first.into_bytes(),
            },
        )])
        .await;
        p
    })
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Auth, "{err}");
    let source = std::error::Error::source(&err)
        .and_then(|s| s.downcast_ref::<fstp_pgwire::scram::ScramError>())
        .cloned();
    assert_eq!(
        source,
        Some(fstp_pgwire::scram::ScramError::TooFewIterations {
            requested: 1,
            minimum: 4096
        })
    );
}

/// Review finding pg-begin-timeout-unowned-tx, other code path. The caller
/// drops `transaction()` itself, here through its own deadline, after
/// BEGIN was sent and before its answer arrived. No statement timeout is
/// set. The BEGIN still opened a transaction that no `Transaction` owns,
/// so the client rolls it back before the next statement.
#[test]
fn review_pg_begin_dropped_by_caller_unowned_tx() {
    let cfg = timeout_config().statement_timeout(None);
    tls_session_test(
        cfg,
        |mut client| async move {
            let res = fstp_rt::timeout(
                rt(),
                std::time::Duration::from_millis(200),
                client.transaction(),
            )
            .await
            .map(drop);
            assert!(res.is_err(), "the caller's deadline passed first");
            assert!(!client.is_broken());
            let tx = client.transaction().await.unwrap();
            tx.rollback().await.unwrap();
            assert_eq!(client.transaction_status(), TransactionStatus::Idle);
            assert!(!client.is_broken());
        },
        |mut p| async move {
            assert_eq!(read_control(&mut p).await, "BEGIN");
            // The server is slow, but BEGIN succeeds.
            rt().sleep(std::time::Duration::from_millis(600)).await;
            answer_control(&mut p, "BEGIN", TransactionStatus::InTransaction).await;
            assert_eq!(read_control(&mut p).await, "ROLLBACK");
            answer_control(&mut p, "ROLLBACK", TransactionStatus::Idle).await;
            assert_eq!(read_control(&mut p).await, "BEGIN");
            answer_control(&mut p, "BEGIN", TransactionStatus::InTransaction).await;
            assert_eq!(read_control(&mut p).await, "ROLLBACK");
            answer_control(&mut p, "ROLLBACK", TransactionStatus::Idle).await;
        },
    );
}

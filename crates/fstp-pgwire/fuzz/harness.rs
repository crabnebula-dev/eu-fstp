//! Shared bodies of the fstp-pgwire fuzz targets (TH-26, H-05).
//!
//! The fuzz targets in `fuzz_targets/` call these functions, and
//! `tests/hostile.rs` runs them over the committed seeds and their
//! mutations on every `cargo test`. Each function panics when a property
//! fails, and checks more than "no panic":
//!
//! - [`backend_decode`]: whole-input framing agrees with chunked streaming
//!   decoding, every message re-encodes to its exact bytes, and decoded
//!   messages respect the limits.
//! - [`scram_server_messages`]: the client accepts a server-first-message
//!   exactly when an independent reference parser does, its proof matches a
//!   reference computation, and only the reference server signature
//!   verifies.
//! - [`value_decode`]: every accepted binary value re-encodes to the same
//!   bytes, or for `numeric`, `json` and `jsonb` to the same value.
//! - [`hostile_server`]: the whole client state machine, fed arbitrary
//!   server bytes over the fstp-rt duplex or a scripted transport,
//!   terminates within a poll budget and stays broken once broken. It never
//!   authenticates without the server proving the password. In every mode
//!   the bytes the client writes are checked too. A cleartext password
//!   never leaves the client without TLS and a server certificate, and
//!   before TLS only the SSLRequest is sent.

#![allow(dead_code)]

use std::io;
use std::num::NonZeroU32;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};

use fstp_json::Value;
use fstp_pgwire::proto::backend::{BackendDecoder, BackendMessage, DecodeLimits, decode_frame};
use fstp_pgwire::scram::{ChannelBinding, ScramClient};
use fstp_pgwire::x509::{EndPointHash, end_point_hash, tls_server_end_point};
use fstp_pgwire::{
    AuthMethod, ClientTls, Config, Date, ErrorKind, FromSql, Limits, Numeric, Password,
    RequireAuth, Session, Timestamptz, ToSql, Type, Uuid, base64,
};
use fstp_rt::duplex::{DuplexStream, duplex};
use fstp_rt::future::{join, poll_bounded};
use fstp_rt::scripted::ScriptedStream;
use fstp_rt::{AsyncRead, AsyncWrite, Connection};

pub const CA: &[u8] = include_bytes!("../../fstp-tls/testdata/ca.pem");
pub const SERVER: &[u8] = include_bytes!("../../fstp-tls/testdata/server.pem");
pub const SERVER_KEY: &[u8] = include_bytes!("../../fstp-tls/testdata/server-key.pem");
pub const CLIENT: &[u8] = include_bytes!("../../fstp-tls/testdata/client.pem");
pub const CLIENT_KEY: &[u8] = include_bytes!("../../fstp-tls/testdata/client-key.pem");

fn ctrl(data: &[u8], i: usize) -> u8 {
    data.get(i).copied().unwrap_or(0)
}

// ----- pg_backend_decode -----

/// Decodes `stream` frame by frame with `decode_frame` and `parse`,
/// returning each message with its raw bytes and the first error.
fn decode_whole(
    stream: &[u8],
    limits: &DecodeLimits,
) -> (Vec<(BackendMessage, Vec<u8>)>, Option<String>) {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let rest = &stream[pos..];
        match decode_frame(rest, limits.max_message_len) {
            Ok(None) => return (out, None),
            Ok(Some((tag, body_len))) => {
                let end = 5 + body_len;
                match BackendMessage::parse(tag, &rest[5..end], limits) {
                    Ok(m) => out.push((m, rest[..end].to_vec())),
                    Err(e) => return (out, Some(e.to_string())),
                }
                pos += end;
            }
            Err(e) => return (out, Some(e.to_string())),
        }
    }
}

/// Decodes `stream` with the streaming decoder, pushing chunks whose sizes
/// follow `seed`.
fn decode_chunked(
    stream: &[u8],
    limits: DecodeLimits,
    seed: u8,
) -> (Vec<BackendMessage>, Option<String>) {
    let mut d = BackendDecoder::new(limits);
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut step = u32::from(seed);
    loop {
        loop {
            match d.next_message() {
                Ok(Some(m)) => out.push(m),
                Ok(None) => break,
                Err(e) => return (out, Some(e.to_string())),
            }
        }
        if pos >= stream.len() {
            return (out, None);
        }
        step = step.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        let size = 1 + (step >> 16) as usize % 97;
        let end = (pos + size).min(stream.len());
        d.push(&stream[pos..end]);
        pos = end;
    }
}

pub fn backend_decode(data: &[u8]) {
    let c0 = ctrl(data, 0);
    let c1 = ctrl(data, 1);
    let stream = data.get(2..).unwrap_or_default();
    let limits = DecodeLimits {
        max_message_len: [0usize, 16, 64, 300, 4096, 1 << 20][usize::from(c0 % 6)],
        max_columns: [0usize, 1, 3, 1664][usize::from((c0 >> 4) % 4)],
        max_parameters: [0usize, 1, 3, 65_535][usize::from(c1 >> 6)],
    };
    let (whole, whole_err) = decode_whole(stream, &limits);
    let (chunked, chunked_err) = decode_chunked(stream, limits, c1);
    let whole_msgs: Vec<&BackendMessage> = whole.iter().map(|(m, _)| m).collect();
    let chunked_msgs: Vec<&BackendMessage> = chunked.iter().collect();
    assert_eq!(
        whole_msgs, chunked_msgs,
        "chunking changed the decoded messages"
    );
    assert_eq!(whole_err, chunked_err, "chunking changed the error");
    for (msg, raw) in &whole {
        let mut again = Vec::new();
        msg.encode(&mut again)
            .expect("a decoded message must re-encode");
        assert_eq!(&again, raw, "re-encoding changed the bytes of {msg:?}");
        assert!(
            raw.len() - 5 <= limits.max_message_len,
            "message over the size limit"
        );
        match msg {
            BackendMessage::DataRow(r) => assert!(r.len() <= limits.max_columns),
            BackendMessage::RowDescription(f) => assert!(f.len() <= limits.max_columns),
            BackendMessage::ParameterDescription(t) => assert!(t.len() <= limits.max_parameters),
            _ => {}
        }
    }
}

// ----- pg_scram_server_messages -----

const NONCE: &str = "fuzzclientnonce";
/// A low floor keeps PBKDF2 cheap while both sides of it stay reachable.
const MIN_ITERATIONS: u32 = 8;
const MAX_ITERATIONS: u32 = 64;

fn min_iterations() -> NonZeroU32 {
    NonZeroU32::new(MIN_ITERATIONS).unwrap()
}

/// An independent strict base64 decoder for the reference parser.
fn ref_base64(s: &[u8]) -> Option<Vec<u8>> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let pad = s.iter().rev().take_while(|b| **b == b'=').count();
    if pad > 2 {
        return None;
    }
    let body = &s[..s.len() - pad];
    let mut bits: u64 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for b in body {
        let v = A.iter().position(|a| a == b)? as u64;
        bits = (bits << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    // Leftover bits must be zero and match the padding.
    if bits != 0 {
        return None;
    }
    let expected_pad = match body.len() % 4 {
        0 => 0,
        2 => 2,
        3 => 1,
        _ => return None,
    };
    if expected_pad != pad {
        return None;
    }
    Some(out)
}

/// An independent parser for server-first-message, with the client's
/// nonce and iteration limit applied.
fn ref_server_first(msg: &[u8]) -> Option<(String, Vec<u8>, u32)> {
    if msg.is_empty() || msg.len() > 4096 {
        return None;
    }
    let parts: Vec<&[u8]> = msg.split(|b| *b == b',').collect();
    for p in &parts {
        if p.len() < 2 || !p[0].is_ascii_alphabetic() || p[1] != b'=' {
            return None;
        }
        if !p[2..].iter().all(|b| (0x20..=0x7e).contains(b)) {
            return None;
        }
    }
    if parts.len() < 3 || parts[0][0] != b'r' || parts[1][0] != b's' || parts[2][0] != b'i' {
        return None;
    }
    let nonce = &parts[0][2..];
    if nonce.is_empty() || !nonce.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return None;
    }
    let nonce = String::from_utf8(nonce.to_vec()).ok()?;
    let salt = ref_base64(&parts[1][2..])?;
    if salt.is_empty() {
        return None;
    }
    let it = &parts[2][2..];
    if it.is_empty() || it.len() > 10 || it[0] == b'0' || !it.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let iterations: u32 = std::str::from_utf8(it).ok()?.parse().ok()?;
    if !nonce.starts_with(NONCE)
        || nonce.len() <= NONCE.len()
        || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations)
    {
        return None;
    }
    Some((nonce, salt, iterations))
}

/// Splits `data` into a 2-byte-length-prefixed part and the rest.
fn take_part(data: &[u8]) -> (&[u8], &[u8]) {
    let len = usize::from(u16::from_be_bytes([ctrl(data, 0), ctrl(data, 1)]));
    let rest = data.get(2..).unwrap_or_default();
    let len = len.min(rest.len());
    rest.split_at(len)
}

pub fn scram_server_messages(data: &[u8]) {
    let mode = ctrl(data, 0);
    let (server_first, rest) = take_part(data.get(1..).unwrap_or_default());
    let (server_final, extra) = take_part(rest);

    let binding = match mode % 3 {
        0 => ChannelBinding::NotSupported,
        1 => ChannelBinding::NotOffered,
        _ => ChannelBinding::TlsServerEndPoint(fstp_crypto::sha256(extra).to_vec()),
    };
    let password = Password::new("pencil").unwrap();
    let mut client = ScramClient::with_nonce(
        &password,
        binding.clone(),
        NONCE,
        min_iterations(),
        MAX_ITERATIONS,
    )
    .unwrap();
    let first = client.client_first();
    let gs2: &[u8] = match &binding {
        ChannelBinding::NotSupported => b"n,,",
        ChannelBinding::NotOffered => b"y,,",
        ChannelBinding::TlsServerEndPoint(_) => b"p=tls-server-end-point,,",
    };
    assert_eq!(first, [gs2, format!("n=,r={NONCE}").as_bytes()].concat());

    let reference = ref_server_first(server_first);
    let result = client.handle_server_first(server_first);
    assert_eq!(
        result.is_ok(),
        reference.is_some(),
        "client and reference disagree on server-first {:?}: {result:?}",
        String::from_utf8_lossy(server_first)
    );
    let (Ok(client_final), Some((nonce, salt, iterations))) = (result, reference) else {
        assert!(client.handle_server_final(server_final).is_err());
        assert!(!client.is_done());
        check_codecs(extra);
        return;
    };

    // Reference computation of the proof and the server signature.
    let mut cbind = gs2.to_vec();
    if let ChannelBinding::TlsServerEndPoint(d) = &binding {
        cbind.extend_from_slice(d);
    }
    let without_proof = format!("c={},r={nonce}", base64::encode(&cbind));
    let auth_message = [
        format!("n=,r={NONCE},").as_bytes(),
        server_first,
        b",",
        without_proof.as_bytes(),
    ]
    .concat();
    let mut salted = [0u8; 32];
    fstp_crypto::pbkdf2_hmac_sha256(
        b"pencil",
        &salt,
        NonZeroU32::new(iterations).unwrap(),
        &mut salted,
    );
    let client_key = fstp_crypto::hmac_sha256(&salted, b"Client Key");
    let stored = fstp_crypto::sha256(&client_key);
    let sig = fstp_crypto::hmac_sha256(&stored, &auth_message);
    let proof: Vec<u8> = client_key.iter().zip(sig).map(|(k, s)| k ^ s).collect();
    let expected_final = format!("{without_proof},p={}", base64::encode(&proof));
    assert_eq!(
        client_final,
        expected_final.as_bytes(),
        "client-final differs from the reference"
    );
    let server_sig = fstp_crypto::hmac_sha256(
        &fstp_crypto::hmac_sha256(&salted, b"Server Key"),
        &auth_message,
    );
    let good = format!("v={}", base64::encode(&server_sig));

    let accepted = client.handle_server_final(server_final).is_ok();
    if accepted {
        assert!(
            server_final.starts_with(good.as_bytes())
                && (server_final.len() == good.len()
                    || server_final.get(good.len()) == Some(&b',')),
            "a server-final without the reference signature was accepted"
        );
        assert!(client.is_done());
    }
    // A fresh client accepts the reference signature.
    let mut honest =
        ScramClient::with_nonce(&password, binding, NONCE, min_iterations(), MAX_ITERATIONS)
            .unwrap();
    honest.handle_server_first(server_first).unwrap();
    honest.handle_server_final(good.as_bytes()).unwrap();
    assert!(honest.is_done());
    check_codecs(extra);
}

/// Base64 canonical round trip and the certificate walker on any bytes.
fn check_codecs(extra: &[u8]) {
    if let Ok(decoded) = base64::decode(extra) {
        assert_eq!(
            base64::encode(&decoded).as_bytes(),
            extra,
            "non-canonical base64 accepted"
        );
        assert_eq!(
            ref_base64(extra),
            Some(decoded),
            "base64 disagrees with the reference"
        );
    } else {
        assert_eq!(
            ref_base64(extra),
            None,
            "base64 rejected what the reference accepts"
        );
    }
    match end_point_hash(extra) {
        Ok(EndPointHash::Sha256) => {
            assert_eq!(
                tls_server_end_point(extra).unwrap(),
                fstp_crypto::sha256(extra)
            );
        }
        Ok(EndPointHash::Unsupported(_)) | Err(_) => assert!(tls_server_end_point(extra).is_err()),
    }
}

// ----- pg_value_decode -----

fn encode<T: ToSql>(v: &T, ty: Type) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    v.to_sql(ty, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// For types whose binary form is canonical: decode then encode gives the
/// input back.
fn exact<T: FromSql + ToSql + std::fmt::Debug>(ty: Type, raw: &[u8]) {
    assert!(<T as FromSql>::accepts(ty));
    if let Ok(v) = T::from_sql(ty, raw) {
        assert!(v.accepts(ty));
        assert_eq!(
            encode(&v, ty).as_deref(),
            Ok(raw),
            "{ty} value {v:?} did not re-encode exactly"
        );
    }
    assert!(T::from_sql_nullable(ty, None).is_err());
    assert!(matches!(Option::<T>::from_sql_nullable(ty, None), Ok(None)));
}

pub fn value_decode(raw: &[u8]) {
    exact::<bool>(Type::BOOL, raw);
    exact::<i16>(Type::INT2, raw);
    exact::<i32>(Type::INT4, raw);
    exact::<i64>(Type::INT8, raw);
    exact::<f64>(Type::FLOAT8, raw);
    exact::<Vec<u8>>(Type::BYTEA, raw);
    exact::<Uuid>(Type::UUID, raw);
    exact::<Timestamptz>(Type::TIMESTAMPTZ, raw);
    exact::<Date>(Type::DATE, raw);
    for ty in [Type::TEXT, Type::VARCHAR, Type::BPCHAR, Type::NAME] {
        if let Ok(s) = String::from_sql(ty, raw) {
            if raw.contains(&0) {
                assert!(encode(&s, ty).is_err(), "text with NUL must not encode");
            } else {
                assert_eq!(encode(&s, ty).as_deref(), Ok(raw));
            }
        } else {
            assert!(std::str::from_utf8(raw).is_err());
        }
    }
    if let Ok(n) = Numeric::from_sql(Type::NUMERIC, raw) {
        assert_eq!(
            Numeric::parse(n.as_str()).as_ref(),
            Ok(&n),
            "numeric text is not canonical"
        );
        let bytes = encode(&n, Type::NUMERIC).expect("a decoded numeric must encode");
        assert_eq!(Numeric::from_sql(Type::NUMERIC, &bytes).as_ref(), Ok(&n));
        assert_eq!(
            encode(
                &Numeric::from_sql(Type::NUMERIC, &bytes).unwrap(),
                Type::NUMERIC
            ),
            Ok(bytes)
        );
    }
    for ty in [Type::JSONB, Type::JSON] {
        if let Ok(v) = Value::from_sql(ty, raw) {
            let bytes = encode(&v, ty).expect("a decoded json value must encode");
            assert_eq!(Value::from_sql(ty, &bytes).as_ref(), Ok(&v));
        }
    }
    // Types are never reinterpreted.
    assert!(!<i32 as FromSql>::accepts(Type::INT8));
    assert!(!<i64 as FromSql>::accepts(Type::INT4));
    assert!(!<String as FromSql>::accepts(Type::BYTEA));
}

// ----- pg_hostile_server -----

/// The password of every hostile-server configuration.
pub const PASSWORD: &str = "pencil";

/// Most client bytes a [`Tap`] keeps.
const MAX_TAPPED: usize = 1 << 20;

/// A transport wrapper that records every byte the client writes.
struct Tap<S> {
    inner: S,
    log: Arc<Mutex<Vec<u8>>>,
}

/// Wraps `inner` and returns the shared record of its writes.
fn tap<S>(inner: S) -> (Tap<S>, Arc<Mutex<Vec<u8>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    (
        Tap {
            inner,
            log: log.clone(),
        },
        log,
    )
}

fn tapped(log: &Arc<Mutex<Vec<u8>>>) -> Vec<u8> {
    log.lock().map(|l| l.clone()).unwrap_or_default()
}

impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r
            && let Ok(mut log) = this.log.lock()
        {
            let keep = (*n)
                .min(buf.len())
                .min(MAX_TAPPED.saturating_sub(log.len()));
            log.extend_from_slice(&buf[..keep]);
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Parses a client's plaintext protocol stream and returns how many
/// PasswordMessages carry the cleartext password.
///
/// The stream starts with the startup packet. Every later frame must have a
/// message type this client sends; the simple Query message is never one of
/// them. Only the last frame may be cut short, by a failed write.
pub fn cleartext_passwords(out: &[u8]) -> usize {
    let Some(head) = out.get(..8) else {
        return 0;
    };
    let len = u32::from_be_bytes(head[..4].try_into().unwrap()) as usize;
    let version = i32::from_be_bytes(head[4..8].try_into().unwrap());
    assert_eq!(
        version,
        fstp_pgwire::proto::PROTOCOL_VERSION,
        "the client stream does not start with a startup packet"
    );
    assert!(len >= 8, "startup packet of {len} bytes");
    let wanted = [PASSWORD.as_bytes(), b"\0"].concat();
    let mut count = 0;
    let mut pos = len;
    while let Some(head) = out.get(pos..pos + 5) {
        let tag = head[0];
        assert!(
            b"pPBEDSCXH".contains(&tag),
            "client sent message type {tag:#04x}"
        );
        let len = u32::from_be_bytes(head[1..5].try_into().unwrap()) as usize;
        assert!(len >= 4, "client frame with length {len}");
        let end = pos + 1 + len;
        let Some(body) = out.get(pos + 5..end) else {
            break;
        };
        if tag == b'p' && body == wanted.as_slice() {
            count += 1;
        }
        pos = end;
    }
    count
}

/// The properties of a client's plaintext protocol stream. A cleartext
/// password is sent at most once, and only when the session runs over TLS
/// with a server certificate and `require_auth` allows it.
fn check_client_stream(out: &[u8], tls_cert: bool, cfg: &Config) {
    let sent = cleartext_passwords(out);
    if !tls_cert {
        assert_eq!(sent, 0, "cleartext password sent without a TLS certificate");
    }
    if !cfg.allowed_auth().allows(AuthMethod::Password) {
        assert_eq!(sent, 0, "cleartext password sent against require_auth");
    }
    assert!(sent <= 1, "cleartext password sent {sent} times");
}

/// The properties of a client's raw transport output when it negotiates
/// TLS. The SSLRequest comes first, and everything after it is whole TLS
/// records, except for a last record cut short by a failed write. Nothing,
/// least of all a password, travels outside TLS.
pub fn check_tls_wire(out: &[u8]) {
    let ssl = fstp_pgwire::proto::frontend::ssl_request();
    if out.len() < ssl.len() {
        assert!(ssl.starts_with(out), "client did not start with SSLRequest");
        return;
    }
    assert_eq!(out[..8], ssl, "client did not start with SSLRequest");
    let mut pos = ssl.len();
    while let Some(head) = out.get(pos..pos + 5) {
        assert!(
            matches!(head[0], 20..=23),
            "byte {:#04x} outside a TLS record after the SSLRequest",
            head[0]
        );
        assert!(
            head[1] == 3 && matches!(head[2], 1..=3),
            "TLS record with version {:#04x}{:02x}",
            head[1],
            head[2]
        );
        let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        assert!(len <= (1 << 14) + 256, "TLS record of {len} bytes");
        pos += 5 + len;
    }
}

/// The server side over the duplex: writes the script in chunks of
/// `chunk` bytes while reading and discarding whatever the client sends.
async fn scripted_server<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    script: &[u8],
    chunk: usize,
) {
    let mut pos = 0usize;
    let mut closed = false;
    let mut sink = [0u8; 4096];
    std::future::poll_fn(|cx| {
        loop {
            let mut progress = false;
            match std::pin::Pin::new(&mut io).poll_read(cx, &mut sink) {
                std::task::Poll::Ready(Ok(0)) | std::task::Poll::Ready(Err(_)) => {
                    return std::task::Poll::Ready(());
                }
                std::task::Poll::Ready(Ok(_)) => progress = true,
                std::task::Poll::Pending => {}
            }
            if pos < script.len() {
                let end = (pos + chunk).min(script.len());
                match std::pin::Pin::new(&mut io).poll_write(cx, &script[pos..end]) {
                    std::task::Poll::Ready(Ok(n)) if n > 0 => {
                        pos += n;
                        progress = true;
                    }
                    std::task::Poll::Ready(_) => return std::task::Poll::Ready(()),
                    std::task::Poll::Pending => {}
                }
            } else if !closed {
                let _ = std::pin::Pin::new(&mut io).poll_shutdown(cx);
                closed = true;
                progress = true;
            }
            if !progress {
                return std::task::Poll::Pending;
            }
        }
    })
    .await;
}

/// The client's TLS settings, built once. [`Session::startup`] does not
/// use them; the TLS modes run [`fstp_pgwire::tls_handshake`] themselves.
fn client_tls() -> ClientTls {
    static TLS: OnceLock<ClientTls> = OnceLock::new();
    TLS.get_or_init(|| ClientTls::new(CA, CLIENT, CLIENT_KEY).unwrap())
        .clone()
}

fn hostile_config(require: RequireAuth) -> Config {
    Config::new(
        "localhost",
        5432,
        "fuzz",
        Password::new(PASSWORD).unwrap(),
        "db",
        client_tls(),
    )
    .unwrap()
    .require_auth(require)
    .statement_cache_capacity(2)
    .limits(Limits {
        max_message_len: 8192,
        max_startup_message_len: 2048,
        max_result_bytes: 4096,
        max_columns: 8,
        max_parameters: 8,
        min_scram_iterations: NonZeroU32::new(8).unwrap(),
        max_scram_iterations: 16,
        max_server_parameters: 8,
    })
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

/// Runs one operation and checks that a broken session stays broken.
macro_rules! op {
    ($s:expr, $fut:expr) => {{
        let was_broken = $s.is_broken();
        let r = $fut.await;
        if was_broken {
            let e = r
                .as_ref()
                .err()
                .expect("a broken session must refuse every operation");
            assert_eq!(e.kind(), ErrorKind::Closed);
        }
        assert!(!was_broken || $s.is_broken(), "a broken session recovered");
        r
    }};
}

/// Exercises the client after startup.
async fn drive(mut s: Session) -> usize {
    let mut ok = 0usize;
    if let Ok(rows) = op!(s, s.query("SELECT $1::int4", &[&7i32])) {
        ok += 1;
        for row in rows {
            let _ = row.get::<i32>(0usize);
            let _ = row.get::<Option<i64>>(0usize);
            let _ = row.get::<String>(0usize);
            let _ = row.get::<Numeric>(0usize);
            let _ = row.get::<Value>(0usize);
            let _ = row.get::<Timestamptz>(0usize);
            let _ = row.get::<Date>(0usize);
            let _ = row.get::<Uuid>(0usize);
            let _ = row.get::<Vec<u8>>(0usize);
            let _ = row.get::<bool>(0usize);
            let _ = row.get::<f64>(0usize);
            let _ = row.get::<i16>("x");
        }
    }
    ok += usize::from(op!(s, s.execute("UPDATE t SET x = $1", &[&"text"])).is_ok());
    {
        let was_broken = s.is_broken();
        match s.query_stream("SELECT g FROM s", &[]).await {
            Ok(mut stream) => {
                let mut rows = 0;
                for _ in 0..3 {
                    match stream.next().await {
                        Ok(Some(_)) => rows += 1,
                        _ => break,
                    }
                }
                ok += usize::from(rows == 3);
            }
            Err(e) => {
                if was_broken {
                    assert_eq!(e.kind(), ErrorKind::Closed);
                }
            }
        }
    }
    ok += usize::from(op!(s, s.prepare("SELECT 2")).is_ok());
    // The transcript seeds answer this one with an error.
    ok += usize::from(op!(s, s.query("SELECT 1", &[])).is_err());
    let _ = op!(s, s.query("SELECT 3", &[]));
    let _ = s.close().await;
    ok
}

async fn startup_and_drive<S: Connection>(
    io: S,
    cfg: &Config,
    cert: Option<&[u8]>,
    must_fail: bool,
) -> Option<usize> {
    match Session::startup(Box::new(io), cfg, cert).await {
        Ok(s) => {
            assert!(
                !must_fail,
                "authenticated against a server that cannot know the password"
            );
            let method = s.auth_method().expect("startup without an auth method");
            assert!(
                cfg.allowed_auth().allows(method),
                "used a method require_auth excludes"
            );
            Some(drive(s).await)
        }
        Err(e) => {
            let _ = e.kind();
            None
        }
    }
}

/// Runs the plaintext duplex mode and returns how many of the driven
/// operations behaved as the transcript seeds script them, or `None` when
/// startup failed. Used to self-test the harness and the seeds.
pub fn transcript_ops(script: &[u8], chunk: usize) -> Option<usize> {
    plaintext_run(script, chunk, false).0
}

/// Runs `script` over the plaintext duplex with every method allowed.
/// `fake_cert` makes the session believe it runs over TLS with the test
/// server certificate. Returns the driven operations, as for
/// [`transcript_ops`], and every byte the client wrote.
pub fn plaintext_run(script: &[u8], chunk: usize, fake_cert: bool) -> (Option<usize>, Vec<u8>) {
    let everything = RequireAuth::SCRAM
        .with(AuthMethod::Password)
        .with(AuthMethod::None);
    let cfg = hostile_config(everything);
    let der = if fake_cert { server_der() } else { Vec::new() };
    let cert = fake_cert.then_some(der.as_slice());
    let (c, s) = duplex(1 << 20);
    let (c, log) = tap(c);
    let budget = 200_000 + script.len() * 64;
    let done = poll_bounded(
        join(
            startup_and_drive(c, &cfg, cert, false),
            scripted_server(s, script, chunk),
        ),
        budget,
    );
    let out = tapped(&log);
    check_client_stream(&out, fake_cert, &cfg);
    let Some((ops, ())) = done else {
        panic!("client did not terminate within {budget} polls");
    };
    (ops, out)
}

pub fn hostile_server(data: &[u8]) {
    let mode = ctrl(data, 0);
    let chunk = usize::from(ctrl(data, 1) % 64) + 1;
    let script = data.get(2..).unwrap_or_default();
    let everything = RequireAuth::SCRAM
        .with(AuthMethod::Password)
        .with(AuthMethod::None);
    let budget = 200_000 + data.len() * 64;
    let done = match mode % 8 {
        // A genuine TLS session on the duplex, fuzzed bytes inside it.
        7 => {
            let _ = hostile_server_tls(data);
            Some(())
        }
        // Plaintext duplex, every method allowed, no TLS certificate.
        0 | 6 => {
            let _ = plaintext_run(script, chunk, false);
            Some(())
        }
        // As 0, but the session believes it runs over TLS with the test
        // server certificate, which enables SCRAM-SHA-256-PLUS paths.
        1 => {
            let _ = plaintext_run(script, chunk, true);
            Some(())
        }
        // The default policy: SCRAM only. A server that cannot compute the
        // SCRAM signature for a random nonce must never get through.
        2 => {
            let cfg = hostile_config(RequireAuth::default());
            let (c, s) = duplex(1 << 20);
            let (c, log) = tap(c);
            let done = poll_bounded(
                join(
                    startup_and_drive(c, &cfg, None, true),
                    scripted_server(s, script, chunk),
                ),
                budget,
            )
            .map(drop);
            check_client_stream(&tapped(&log), false, &cfg);
            done
        }
        // A scripted transport with fuzzed chunking and pending points.
        3 | 4 => {
            let cfg = hostile_config(everything);
            let io = ScriptedStream::from_fuzz_input(data.get(1..).unwrap_or_default());
            let (io, log) = tap(io);
            let done = poll_bounded(startup_and_drive(io, &cfg, None, false), budget).map(drop);
            check_client_stream(&tapped(&log), false, &cfg);
            done
        }
        // TLS negotiation against hostile bytes: the SSLRequest reply and
        // the handshake can never succeed without the server key.
        _ => {
            let io = ScriptedStream::from_fuzz_input(data.get(1..).unwrap_or_default());
            let (io, log) = tap(io);
            let tls = fstp_tls::ClientConfig::new(CA).unwrap();
            let done = poll_bounded(
                async {
                    let r = fstp_pgwire::tls_handshake(io, &tls, "localhost").await;
                    assert!(r.is_err(), "TLS succeeded against a hostile server");
                },
                budget,
            );
            check_tls_wire(&tapped(&log));
            done
        }
    };
    assert!(
        done.is_some(),
        "client did not terminate within {budget} polls"
    );
}

/// A hostile server over real TLS on the duplex: the fuzzed bytes arrive
/// inside a genuine TLS session with the test certificate. Slower, so the
/// fuzz target runs it for a fraction of inputs.
pub fn hostile_server_tls(data: &[u8]) -> Option<usize> {
    let chunk = usize::from(ctrl(data, 1) % 64) + 1;
    let script = data.get(2..).unwrap_or_default().to_vec();
    let cfg = hostile_config(
        RequireAuth::SCRAM
            .with(AuthMethod::Password)
            .with(AuthMethod::None),
    );
    let (c, s): (DuplexStream, DuplexStream) = duplex(1 << 20);
    let (c, wire_log) = tap(c);
    let inner_log = Arc::new(Mutex::new(Vec::new()));
    let server_cfg = fstp_tls::ServerConfig::new(SERVER, SERVER_KEY).unwrap();
    let client_tls = fstp_tls::ClientConfig::new(CA).unwrap();
    let budget = 2_000_000 + data.len() * 64;
    let client = async {
        let tls = fstp_pgwire::tls_handshake(c, &client_tls, "localhost")
            .await
            .ok()?;
        let der = tls.peer_end_entity_der().map(<[u8]>::to_vec);
        assert!(der.is_some(), "TLS session without a server certificate");
        let tls = Tap {
            inner: tls,
            log: inner_log.clone(),
        };
        startup_and_drive(tls, &cfg, der.as_deref(), false).await
    };
    let server = async {
        use fstp_rt::IoExt;
        let mut s = s;
        let mut req = [0u8; 8];
        if s.read_exact(&mut req).await.is_err() || s.write_all(b"S").await.is_err() {
            return;
        }
        let _ = s.flush().await;
        if let Ok(tls) = fstp_tls::accept(&server_cfg, s).await {
            scripted_server(tls, &script, chunk).await;
        }
    };
    let done = poll_bounded(join(client, server), budget);
    check_tls_wire(&tapped(&wire_log));
    check_client_stream(&tapped(&inner_log), true, &cfg);
    let Some((ops, ())) = done else {
        panic!("TLS client did not terminate within {budget} polls");
    };
    ops
}

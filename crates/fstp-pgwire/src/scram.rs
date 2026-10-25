//! Sans-IO SCRAM-SHA-256 and SCRAM-SHA-256-PLUS client (RFC 5802, RFC 7677).
//!
//! The exchange is:
//!
//! 1. [`ScramClient::client_first`]: the GS2 header and the
//!    client-first-message-bare with a fresh nonce.
//! 2. [`ScramClient::handle_server_first`]: parses the server-first-message,
//!    derives the keys with PBKDF2 and returns the client-final-message
//!    with the proof.
//! 3. [`ScramClient::handle_server_final`]: checks the server signature in
//!    constant time. A client must not treat authentication as complete
//!    before this succeeds, because the signature is what proves that the
//!    server knows the password verifier.
//!
//! Hashes, HMAC, PBKDF2, randomness and the comparison come from
//! fstp-crypto. The user name in the client-first-message is empty, as
//! PostgreSQL ignores it and takes the name from the startup packet.

use std::fmt;
use std::num::NonZeroU32;

use crate::base64;
use crate::config::Password;

/// The SCRAM-SHA-256 mechanism name.
pub const SCRAM_SHA_256: &str = "SCRAM-SHA-256";

/// The SCRAM-SHA-256-PLUS mechanism name.
pub const SCRAM_SHA_256_PLUS: &str = "SCRAM-SHA-256-PLUS";

/// Number of random bytes in a client nonce. The base64 form has 24
/// characters.
pub const NONCE_BYTES: usize = 18;

/// Largest server-first-message or server-final-message accepted.
pub const MAX_SERVER_MESSAGE_LEN: usize = 4096;

/// How the client handles channel binding (the GS2 header).
#[derive(Clone, PartialEq, Eq)]
pub enum ChannelBinding {
    /// `n`: the client does not support channel binding. Used without TLS.
    NotSupported,
    /// `y`: the client supports channel binding but the server did not offer
    /// it. Used over TLS when the server offers only SCRAM-SHA-256, so that
    /// a server that does support it detects a downgrade.
    NotOffered,
    /// `p=tls-server-end-point`: binds the exchange to the TLS session with
    /// this channel binding data (a hash of the server certificate).
    TlsServerEndPoint(Vec<u8>),
}

impl fmt::Debug for ChannelBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChannelBinding::NotSupported => f.write_str("NotSupported"),
            ChannelBinding::NotOffered => f.write_str("NotOffered"),
            ChannelBinding::TlsServerEndPoint(d) => {
                write!(f, "TlsServerEndPoint({} bytes)", d.len())
            }
        }
    }
}

impl ChannelBinding {
    fn gs2_header(&self) -> &'static str {
        match self {
            ChannelBinding::NotSupported => "n,,",
            ChannelBinding::NotOffered => "y,,",
            ChannelBinding::TlsServerEndPoint(_) => "p=tls-server-end-point,,",
        }
    }
}

/// Why a SCRAM exchange failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScramError {
    /// A server message is not valid SCRAM syntax.
    Malformed(&'static str),
    /// The server's nonce does not extend the client's nonce.
    NonceMismatch,
    /// The salt is empty or not canonical base64.
    InvalidSalt,
    /// The iteration count is not a positive decimal integer.
    InvalidIterations,
    /// The iteration count is below the configured floor. RFC 7677
    /// recommends at least 4096; fewer make an offline guess cheap.
    TooFewIterations {
        /// The count the server asked for.
        requested: u32,
        /// The configured floor.
        minimum: u32,
    },
    /// The iteration count exceeds the configured limit.
    TooManyIterations {
        /// The count the server asked for.
        requested: u32,
        /// The configured limit.
        limit: u32,
    },
    /// The server sent `e=`, with this error value. Only printable ASCII is
    /// kept, and at most 64 characters.
    ServerError(String),
    /// The server signature does not verify. The server does not know the
    /// password verifier, or the exchange was tampered with.
    BadServerSignature,
    /// A message arrived in the wrong state, or the exchange already failed.
    UnexpectedMessage,
    /// The system random number generator failed.
    Randomness,
    /// The client nonce given for testing is not valid.
    InvalidNonce,
}

impl fmt::Display for ScramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScramError::Malformed(what) => write!(f, "malformed SCRAM message: {what}"),
            ScramError::NonceMismatch => {
                f.write_str("server nonce does not extend the client nonce")
            }
            ScramError::InvalidSalt => f.write_str("invalid SCRAM salt"),
            ScramError::InvalidIterations => f.write_str("invalid SCRAM iteration count"),
            ScramError::TooFewIterations { requested, minimum } => write!(
                f,
                "server asked for {requested} SCRAM iterations, fewer than the minimum of {minimum}"
            ),
            ScramError::TooManyIterations { requested, limit } => write!(
                f,
                "server asked for {requested} SCRAM iterations, more than the limit of {limit}"
            ),
            ScramError::ServerError(e) => write!(f, "server reported SCRAM error {e:?}"),
            ScramError::BadServerSignature => f.write_str("SCRAM server signature is invalid"),
            ScramError::UnexpectedMessage => f.write_str("unexpected SCRAM message"),
            ScramError::Randomness => f.write_str("system randomness unavailable"),
            ScramError::InvalidNonce => f.write_str("invalid client nonce"),
        }
    }
}

impl std::error::Error for ScramError {}

enum State {
    /// client-first sent, waiting for server-first.
    First,
    /// client-final sent, waiting for server-final.
    Final { server_signature: [u8; 32] },
    /// Server signature verified.
    Done,
    /// Any error ends the exchange.
    Failed,
}

/// A SCRAM-SHA-256(-PLUS) client exchange. See the [module docs](self).
pub struct ScramClient {
    password: Vec<u8>,
    channel_binding: ChannelBinding,
    nonce: String,
    client_first_bare: String,
    min_iterations: NonZeroU32,
    max_iterations: u32,
    state: State,
}

impl fmt::Debug for ScramClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScramClient")
            .field("channel_binding", &self.channel_binding)
            .field("min_iterations", &self.min_iterations)
            .field("max_iterations", &self.max_iterations)
            .finish_non_exhaustive()
    }
}

/// RFC 5802 `printable`: 0x21 to 0x7E except ','.
fn is_printable(b: u8) -> bool {
    (0x21..=0x7e).contains(&b) && b != b','
}

impl ScramClient {
    /// Starts an exchange with a fresh random nonce from fstp-crypto.
    ///
    /// The server's iteration count must lie between `min_iterations` and
    /// `max_iterations`, inclusive.
    ///
    /// # Errors
    ///
    /// Returns [`ScramError::Randomness`] when the system generator fails.
    pub fn new(
        password: &Password,
        channel_binding: ChannelBinding,
        min_iterations: NonZeroU32,
        max_iterations: u32,
    ) -> Result<ScramClient, ScramError> {
        let raw: [u8; NONCE_BYTES] =
            fstp_crypto::random_array().map_err(|_| ScramError::Randomness)?;
        Self::with_nonce(
            password,
            channel_binding,
            &base64::encode(&raw),
            min_iterations,
            max_iterations,
        )
    }

    /// Starts an exchange with a given nonce. For known-answer tests and
    /// fuzzing only: a predictable nonce enables replay attacks.
    ///
    /// # Errors
    ///
    /// Returns [`ScramError::InvalidNonce`] unless the nonce is 1 to 256
    /// printable characters without ','.
    pub fn with_nonce(
        password: &Password,
        channel_binding: ChannelBinding,
        nonce: &str,
        min_iterations: NonZeroU32,
        max_iterations: u32,
    ) -> Result<ScramClient, ScramError> {
        Self::with_user(
            password.as_bytes(),
            channel_binding,
            nonce,
            "",
            min_iterations,
            max_iterations,
        )
    }

    fn with_user(
        password: &[u8],
        channel_binding: ChannelBinding,
        nonce: &str,
        user: &str,
        min_iterations: NonZeroU32,
        max_iterations: u32,
    ) -> Result<ScramClient, ScramError> {
        if nonce.is_empty() || nonce.len() > 256 || !nonce.bytes().all(is_printable) {
            return Err(ScramError::InvalidNonce);
        }
        Ok(ScramClient {
            password: password.to_vec(),
            channel_binding,
            nonce: nonce.to_owned(),
            client_first_bare: format!("n={user},r={nonce}"),
            min_iterations,
            max_iterations,
            state: State::First,
        })
    }

    /// The mechanism name for the SASLInitialResponse.
    #[must_use]
    pub fn mechanism(&self) -> &'static str {
        match self.channel_binding {
            ChannelBinding::TlsServerEndPoint(_) => SCRAM_SHA_256_PLUS,
            _ => SCRAM_SHA_256,
        }
    }

    /// The client-first-message: GS2 header plus client-first-message-bare.
    #[must_use]
    pub fn client_first(&self) -> Vec<u8> {
        let mut out = self.channel_binding.gs2_header().as_bytes().to_vec();
        out.extend_from_slice(self.client_first_bare.as_bytes());
        out
    }

    /// True once the server signature has been verified.
    #[must_use]
    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Processes the server-first-message and returns the
    /// client-final-message.
    ///
    /// # Errors
    ///
    /// Returns a [`ScramError`] for malformed input, a nonce that does not
    /// extend the client nonce, a bad salt, an iteration count outside the
    /// configured range, or a call in the wrong state. The exchange cannot
    /// continue after an error.
    pub fn handle_server_first(&mut self, msg: &[u8]) -> Result<Vec<u8>, ScramError> {
        if !matches!(self.state, State::First) {
            self.state = State::Failed;
            return Err(ScramError::UnexpectedMessage);
        }
        self.state = State::Failed;
        let parsed = parse_server_first(msg)?;
        if !parsed.nonce.starts_with(self.nonce.as_str()) || parsed.nonce.len() <= self.nonce.len()
        {
            return Err(ScramError::NonceMismatch);
        }
        if parsed.iterations < self.min_iterations.get() {
            return Err(ScramError::TooFewIterations {
                requested: parsed.iterations,
                minimum: self.min_iterations.get(),
            });
        }
        if parsed.iterations > self.max_iterations {
            return Err(ScramError::TooManyIterations {
                requested: parsed.iterations,
                limit: self.max_iterations,
            });
        }
        let iterations = NonZeroU32::new(parsed.iterations).ok_or(ScramError::InvalidIterations)?;

        let mut cbind_input = self.channel_binding.gs2_header().as_bytes().to_vec();
        if let ChannelBinding::TlsServerEndPoint(data) = &self.channel_binding {
            cbind_input.extend_from_slice(data);
        }
        let without_proof = format!("c={},r={}", base64::encode(&cbind_input), parsed.nonce);
        let server_first =
            std::str::from_utf8(msg).map_err(|_| ScramError::Malformed("not UTF-8"))?;
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, without_proof
        );

        let mut salted = [0u8; 32];
        fstp_crypto::pbkdf2_hmac_sha256(&self.password, &parsed.salt, iterations, &mut salted);
        let client_key = fstp_crypto::hmac_sha256(&salted, b"Client Key");
        let stored_key = fstp_crypto::sha256(&client_key);
        let client_signature = fstp_crypto::hmac_sha256(&stored_key, auth_message.as_bytes());
        let mut proof = [0u8; 32];
        for ((p, k), s) in proof.iter_mut().zip(client_key).zip(client_signature) {
            *p = k ^ s;
        }
        let server_key = fstp_crypto::hmac_sha256(&salted, b"Server Key");
        let server_signature = fstp_crypto::hmac_sha256(&server_key, auth_message.as_bytes());

        self.state = State::Final { server_signature };
        Ok(format!("{without_proof},p={}", base64::encode(&proof)).into_bytes())
    }

    /// Processes the server-final-message and verifies the server signature
    /// in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`ScramError::BadServerSignature`] when the signature does not
    /// verify, [`ScramError::ServerError`] for an `e=` message, and other
    /// errors for malformed input or a call in the wrong state.
    pub fn handle_server_final(&mut self, msg: &[u8]) -> Result<(), ScramError> {
        let State::Final { server_signature } = self.state else {
            self.state = State::Failed;
            return Err(ScramError::UnexpectedMessage);
        };
        self.state = State::Failed;
        let verifier = parse_server_final(msg)?;
        if !fstp_crypto::constant_time_eq(&verifier, &server_signature) {
            return Err(ScramError::BadServerSignature);
        }
        self.state = State::Done;
        Ok(())
    }
}

struct ServerFirst<'a> {
    nonce: &'a str,
    salt: Vec<u8>,
    iterations: u32,
}

/// Splits `msg` into `x=value` attributes, checking the value syntax.
fn attributes(msg: &[u8]) -> Result<Vec<(u8, &[u8])>, ScramError> {
    if msg.is_empty() {
        return Err(ScramError::Malformed("empty message"));
    }
    if msg.len() > MAX_SERVER_MESSAGE_LEN {
        return Err(ScramError::Malformed("message too long"));
    }
    let mut out = Vec::new();
    for part in msg.split(|b| *b == b',') {
        let [name, b'=', value @ ..] = part else {
            return Err(ScramError::Malformed(
                "attribute is not of the form x=value",
            ));
        };
        if !name.is_ascii_alphabetic() {
            return Err(ScramError::Malformed("attribute name is not a letter"));
        }
        if !value.iter().all(|b| (0x20..=0x7e).contains(b)) {
            return Err(ScramError::Malformed(
                "attribute value is not printable ASCII",
            ));
        }
        out.push((*name, value));
    }
    Ok(out)
}

fn parse_server_first(msg: &[u8]) -> Result<ServerFirst<'_>, ScramError> {
    let attrs = attributes(msg)?;
    let mut it = attrs.into_iter();
    let nonce = match it.next() {
        Some((b'r', v)) => v,
        Some((b'm', _)) => {
            return Err(ScramError::Malformed(
                "mandatory extension is not supported",
            ));
        }
        _ => return Err(ScramError::Malformed("server-first does not start with r=")),
    };
    if nonce.is_empty() || !nonce.iter().all(|b| is_printable(*b)) {
        return Err(ScramError::Malformed("nonce contains invalid characters"));
    }
    let nonce = std::str::from_utf8(nonce).map_err(|_| ScramError::Malformed("nonce"))?;
    let salt = match it.next() {
        Some((b's', v)) => v,
        _ => return Err(ScramError::Malformed("server-first has no s= after r=")),
    };
    let salt = base64::decode(salt).map_err(|_| ScramError::InvalidSalt)?;
    if salt.is_empty() {
        return Err(ScramError::InvalidSalt);
    }
    let iterations = match it.next() {
        Some((b'i', v)) => v,
        _ => return Err(ScramError::Malformed("server-first has no i= after s=")),
    };
    // Positive decimal without sign or leading zeros.
    if iterations.is_empty()
        || iterations.len() > 10
        || iterations.first() == Some(&b'0')
        || !iterations.iter().all(u8::is_ascii_digit)
    {
        return Err(ScramError::InvalidIterations);
    }
    let iterations = std::str::from_utf8(iterations)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or(ScramError::InvalidIterations)?;
    // Optional extensions follow; RFC 5802 lets the client ignore them.
    Ok(ServerFirst {
        nonce,
        salt,
        iterations,
    })
}

fn parse_server_final(msg: &[u8]) -> Result<Vec<u8>, ScramError> {
    let attrs = attributes(msg)?;
    match attrs.first() {
        Some((b'v', v)) => {
            let sig =
                base64::decode(v).map_err(|_| ScramError::Malformed("verifier is not base64"))?;
            if sig.len() != 32 {
                return Err(ScramError::Malformed("verifier is not 32 bytes"));
            }
            Ok(sig)
        }
        Some((b'e', v)) => {
            let text: String = v.iter().take(64).map(|b| char::from(*b)).collect();
            Err(ScramError::ServerError(text))
        }
        _ => Err(ScramError::Malformed("server-final is neither v= nor e=")),
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// RFC 7677 section 3 test vector.
    #[test]
    fn rfc7677_known_answer() {
        let mut c = ScramClient::with_user(
            b"pencil",
            ChannelBinding::NotSupported,
            "rOprNGfwEbeRWgbNEkqO",
            "user",
            NonZeroU32::new(4096).unwrap(),
            4096,
        )
        .unwrap();
        assert_eq!(c.client_first(), b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        let final_msg = c
            .handle_server_first(
                b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
            )
            .unwrap();
        assert_eq!(
            String::from_utf8(final_msg).unwrap(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
             p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        c.handle_server_final(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .unwrap();
        assert!(c.is_done());
    }

    /// A client with a low iteration floor, so tests run quickly.
    fn client(cb: ChannelBinding) -> ScramClient {
        ScramClient::with_nonce(&Password::new("pw").unwrap(), cb, "abc", MIN_16, 10_000).unwrap()
    }

    const MIN_16: NonZeroU32 = match NonZeroU32::new(16) {
        Some(n) => n,
        None => NonZeroU32::MIN,
    };

    /// RFC 7677: a server that asks for fewer iterations than the floor is
    /// refused before any key is derived. The default floor is 4096.
    #[test]
    fn review_pg_scram_no_min_iterations() {
        let p = Password::new("pw").unwrap();
        let floor = crate::config::DEFAULT_MIN_SCRAM_ITERATIONS;
        for (count, ok) in [(1u32, false), (4095, false), (4096, true)] {
            let mut c =
                ScramClient::with_nonce(&p, ChannelBinding::NotSupported, "abc", floor, 1_000_000)
                    .unwrap();
            let msg = format!("r=abcd,s=c2FsdA==,i={count}");
            let r = c.handle_server_first(msg.as_bytes());
            if ok {
                assert!(r.is_ok(), "{count}: {r:?}");
            } else {
                assert_eq!(
                    r,
                    Err(ScramError::TooFewIterations {
                        requested: count,
                        minimum: 4096
                    })
                );
                assert!(!c.is_done());
            }
        }
        // The floor is configurable, down to 1.
        let mut c =
            ScramClient::with_nonce(&p, ChannelBinding::NotSupported, "abc", NonZeroU32::MIN, 8)
                .unwrap();
        assert!(c.handle_server_first(b"r=abcd,s=c2FsdA==,i=1").is_ok());
    }

    #[test]
    fn wrong_server_signature_is_rejected() {
        let mut c = client(ChannelBinding::NotSupported);
        c.handle_server_first(b"r=abcdef,s=c2FsdA==,i=16").unwrap();
        let bad = format!("v={}", base64::encode(&[0u8; 32]));
        assert_eq!(
            c.handle_server_final(bad.as_bytes()),
            Err(ScramError::BadServerSignature)
        );
        assert!(!c.is_done());
        // No second chance.
        assert_eq!(
            c.handle_server_final(bad.as_bytes()),
            Err(ScramError::UnexpectedMessage)
        );
    }

    #[test]
    fn th26_server_first_is_validated() {
        let cases: &[(&[u8], ScramError)] = &[
            (b"r=xyz,s=c2FsdA==,i=16", ScramError::NonceMismatch),
            (b"r=abc,s=c2FsdA==,i=16", ScramError::NonceMismatch),
            (b"r=abcd,s=,i=16", ScramError::InvalidSalt),
            (b"r=abcd,s=c2Fsd,i=16", ScramError::InvalidSalt),
            (b"r=abcd,s=c2FsdA==,i=0", ScramError::InvalidIterations),
            (
                b"r=abcd,s=c2FsdA==,i=15",
                ScramError::TooFewIterations {
                    requested: 15,
                    minimum: 16,
                },
            ),
            (b"r=abcd,s=c2FsdA==,i=016", ScramError::InvalidIterations),
            (b"r=abcd,s=c2FsdA==,i=+16", ScramError::InvalidIterations),
            (
                b"r=abcd,s=c2FsdA==,i=99999999999",
                ScramError::InvalidIterations,
            ),
            (
                b"r=abcd,s=c2FsdA==,i=10001",
                ScramError::TooManyIterations {
                    requested: 10001,
                    limit: 10_000,
                },
            ),
        ];
        for (msg, want) in cases {
            let mut c = client(ChannelBinding::NotSupported);
            assert_eq!(
                c.handle_server_first(msg).as_ref().err(),
                Some(want),
                "{msg:?}"
            );
        }
        for msg in [
            &b""[..],
            b"m=ext,r=abcd,s=c2FsdA==,i=16",
            b"s=c2FsdA==,r=abcd,i=16",
            b"r=abcd,i=16,s=c2FsdA==",
            b"r=abcd,s=c2FsdA==",
            b"r=ab\x01cd,s=c2FsdA==,i=16",
            b"r=abcd,s=c2FsdA==,i=16,",
            b"rr=abcd",
        ] {
            let mut c = client(ChannelBinding::NotSupported);
            assert!(
                matches!(c.handle_server_first(msg), Err(ScramError::Malformed(_))),
                "{msg:?}"
            );
        }
        // Extensions after i= are ignored, as RFC 5802 allows.
        let mut c = client(ChannelBinding::NotSupported);
        assert!(
            c.handle_server_first(b"r=abcd,s=c2FsdA==,i=16,x=ext")
                .is_ok()
        );
    }

    #[test]
    fn server_error_is_reported_and_sanitised() {
        let mut c = client(ChannelBinding::NotSupported);
        c.handle_server_first(b"r=abcd,s=c2FsdA==,i=16").unwrap();
        assert_eq!(
            c.handle_server_final(b"e=invalid-proof"),
            Err(ScramError::ServerError("invalid-proof".into()))
        );
    }

    #[test]
    fn channel_binding_goes_into_the_final_message() {
        let mut c = client(ChannelBinding::TlsServerEndPoint(vec![0xaa; 32]));
        assert_eq!(c.mechanism(), SCRAM_SHA_256_PLUS);
        assert!(
            c.client_first()
                .starts_with(b"p=tls-server-end-point,,n=,r=abc")
        );
        let f = c.handle_server_first(b"r=abcd,s=c2FsdA==,i=16").unwrap();
        let mut cb = b"p=tls-server-end-point,,".to_vec();
        cb.extend_from_slice(&[0xaa; 32]);
        let expected = format!("c={},r=abcd,p=", base64::encode(&cb));
        assert!(f.starts_with(expected.as_bytes()));

        let c = client(ChannelBinding::NotOffered);
        assert_eq!(c.mechanism(), SCRAM_SHA_256);
        assert!(c.client_first().starts_with(b"y,,n=,r=abc"));
    }

    #[test]
    fn calls_out_of_order_fail() {
        let mut c = client(ChannelBinding::NotSupported);
        assert_eq!(
            c.handle_server_final(b"v=x"),
            Err(ScramError::UnexpectedMessage)
        );
        let mut c = client(ChannelBinding::NotSupported);
        c.handle_server_first(b"r=abcd,s=c2FsdA==,i=16").unwrap();
        assert_eq!(
            c.handle_server_first(b"r=abcd,s=c2FsdA==,i=16"),
            Err(ScramError::UnexpectedMessage)
        );
    }

    #[test]
    fn nonces_are_random_and_valid() {
        let p = Password::new("pw").unwrap();
        let a = ScramClient::new(&p, ChannelBinding::NotSupported, MIN_16, 10).unwrap();
        let b = ScramClient::new(&p, ChannelBinding::NotSupported, MIN_16, 10).unwrap();
        assert_ne!(a.client_first(), b.client_first());
        assert_eq!(a.nonce.len(), 24);
        let none = ChannelBinding::NotSupported;
        assert!(ScramClient::with_nonce(&p, none.clone(), "a,b", MIN_16, 1).is_err());
        assert!(ScramClient::with_nonce(&p, none, "", MIN_16, 1).is_err());
    }
}

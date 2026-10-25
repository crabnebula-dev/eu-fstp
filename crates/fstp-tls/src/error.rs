//! Typed TLS errors.

use std::fmt;
use std::io;

use rustls::{CertificateError, Error as RustlsError};

/// Broad classes of TLS failure.
///
/// The classes are stable even when the underlying rustls error changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsErrorKind {
    /// Configuration input such as PEM data, keys, names or ALPN values was
    /// invalid.
    Config,
    /// The peer's certificate chain does not lead to a trusted root.
    UntrustedCertificate,
    /// The server's certificate is not valid for the requested name.
    NameMismatch,
    /// The peer's certificate is expired or not yet valid.
    CertificateExpired,
    /// The peer presented no certificate although one is required.
    CertificateRequired,
    /// Another certificate problem, such as bad encoding, a wrong key usage
    /// or a bad signature.
    BadCertificate,
    /// The peer sent a fatal alert, for example because it rejected our
    /// certificate.
    PeerAlert,
    /// No common protocol version, cipher suite, key exchange group or
    /// signature scheme.
    NoCommonParameters,
    /// The peer violated the TLS protocol or sent undecryptable data.
    Protocol,
    /// The peer closed the connection during the handshake.
    HandshakeEof,
    /// Any other failure.
    Other,
}

/// A TLS failure with a stable [`TlsErrorKind`].
///
/// Functions that return [`io::Error`] wrap a `TlsError` inside it. Use
/// [`TlsError::from_io`] to get it back.
#[derive(Debug, Clone)]
pub struct TlsError {
    kind: TlsErrorKind,
    message: String,
    source: Option<RustlsError>,
}

impl TlsError {
    pub(crate) fn config(message: impl Into<String>) -> Self {
        Self {
            kind: TlsErrorKind::Config,
            message: message.into(),
            source: None,
        }
    }

    pub(crate) fn config_from(context: &str, e: RustlsError) -> Self {
        Self {
            kind: TlsErrorKind::Config,
            message: format!("{context}: {e}"),
            source: Some(e),
        }
    }

    pub(crate) fn handshake_eof() -> Self {
        Self {
            kind: TlsErrorKind::HandshakeEof,
            message: String::from("connection closed during the TLS handshake"),
            source: None,
        }
    }

    /// rustls refused to buffer more of the peer's input, for example a
    /// handshake message over its 64 KiB limit. rustls reports this as a
    /// plain `io::Error` with a fixed message that quotes no peer data.
    pub(crate) fn record_layer(e: &io::Error) -> Self {
        Self {
            kind: TlsErrorKind::Protocol,
            message: format!("peer input rejected by the record layer: {e}"),
            source: None,
        }
    }

    pub(crate) fn from_rustls(e: RustlsError) -> Self {
        let kind = match &e {
            RustlsError::InvalidCertificate(c) => match c {
                CertificateError::UnknownIssuer => TlsErrorKind::UntrustedCertificate,
                CertificateError::NotValidForName
                | CertificateError::NotValidForNameContext { .. } => TlsErrorKind::NameMismatch,
                CertificateError::Expired
                | CertificateError::ExpiredContext { .. }
                | CertificateError::NotValidYet
                | CertificateError::NotValidYetContext { .. } => TlsErrorKind::CertificateExpired,
                _ => TlsErrorKind::BadCertificate,
            },
            RustlsError::NoCertificatesPresented => TlsErrorKind::CertificateRequired,
            RustlsError::AlertReceived(_) => TlsErrorKind::PeerAlert,
            RustlsError::PeerIncompatible(_) => TlsErrorKind::NoCommonParameters,
            RustlsError::InappropriateMessage { .. }
            | RustlsError::InappropriateHandshakeMessage { .. }
            | RustlsError::InvalidMessage(_)
            | RustlsError::DecryptError
            | RustlsError::PeerMisbehaved(_)
            | RustlsError::PeerSentOversizedRecord
            | RustlsError::InvalidEncryptedClientHello(_) => TlsErrorKind::Protocol,
            _ => TlsErrorKind::Other,
        };
        Self {
            kind,
            message: e.to_string(),
            source: Some(e),
        }
    }

    /// The class of this failure.
    #[must_use]
    pub fn kind(&self) -> TlsErrorKind {
        self.kind
    }

    /// The underlying rustls error, when there is one.
    #[must_use]
    pub fn rustls_error(&self) -> Option<&RustlsError> {
        self.source.as_ref()
    }

    /// Extracts the `TlsError` that this crate placed inside an
    /// [`io::Error`], if any.
    #[must_use]
    pub fn from_io(e: &io::Error) -> Option<&TlsError> {
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<TlsError>())
    }

    /// Wraps this error in an [`io::Error`].
    ///
    /// The IO kind is `UnexpectedEof` for [`TlsErrorKind::HandshakeEof`],
    /// `InvalidInput` for [`TlsErrorKind::Config`], and `InvalidData`
    /// otherwise.
    #[must_use]
    pub fn into_io(self) -> io::Error {
        let kind = match self.kind {
            TlsErrorKind::HandshakeEof => io::ErrorKind::UnexpectedEof,
            TlsErrorKind::Config => io::ErrorKind::InvalidInput,
            _ => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, self)
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS error: {}", self.message)
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

impl From<TlsError> for io::Error {
    fn from(e: TlsError) -> Self {
        e.into_io()
    }
}

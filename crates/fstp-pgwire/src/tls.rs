//! TLS negotiation: SSLRequest, then an fstp-tls handshake with full
//! certificate verification.

use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;

use fstp_rt::{Connection, IoExt};
use fstp_tls::TlsStream;

use crate::error::{Error, ErrorKind};
use crate::proto::frontend;

/// Sends an SSLRequest over `io` and, when the server accepts, performs the
/// TLS handshake with `tls` for `server_name`.
///
/// The certificate must chain to a root in `tls` and be valid for
/// `server_name` (verify-full). When `tls` carries a client certificate, it
/// is presented for mutual TLS (R-NF-09).
///
/// Bytes that arrive after the server's `S` and before the handshake are
/// unencrypted data that an attacker could have injected, so the
/// connection is refused. The text of an `E` reply is never read, because
/// it is unauthenticated.
///
/// # Errors
///
/// - [`ErrorKind::TlsRequired`] when the server answers `N`.
/// - [`ErrorKind::Protocol`] for any other reply or for injected bytes.
/// - [`ErrorKind::Tls`] when the handshake or verification fails.
/// - [`ErrorKind::Io`] or [`ErrorKind::Closed`] for transport failures.
pub async fn tls_handshake<S: Connection>(
    mut io: S,
    tls: &fstp_tls::ClientConfig,
    server_name: &str,
) -> Result<TlsStream<S>, Error> {
    io.write_all(&frontend::ssl_request())
        .await
        .map_err(|e| Error::io("cannot send the SSLRequest", e))?;
    io.flush()
        .await
        .map_err(|e| Error::io("cannot send the SSLRequest", e))?;
    let mut reply = [0u8; 64];
    let n = io
        .read(&mut reply)
        .await
        .map_err(|e| Error::io("cannot read the SSLRequest reply", e))?;
    match reply.get(..n).unwrap_or_default() {
        [] => {
            return Err(Error::closed(
                "server closed the connection before answering the SSLRequest",
            ));
        }
        [b'S'] => {}
        [b'S', ..] => {
            return Err(Error::protocol(
                "server sent unencrypted data after accepting TLS; refusing the connection",
            ));
        }
        [b'N', ..] => {
            return Err(Error::new(
                ErrorKind::TlsRequired,
                "server does not accept TLS, and this client never connects without it",
            ));
        }
        [b'E', ..] => {
            return Err(Error::protocol(
                "server answered the SSLRequest with an error; its unencrypted text is ignored",
            ));
        }
        _ => {
            return Err(Error::protocol(
                "server answered the SSLRequest with an unknown reply",
            ));
        }
    }
    // Anything already waiting now was sent in the clear after `S`.
    let mut probe = [0u8; 1];
    let waiting = poll_fn(|cx| match Pin::new(&mut io).poll_read(cx, &mut probe) {
        Poll::Ready(r) => Poll::Ready(Some(r)),
        Poll::Pending => Poll::Ready(None),
    })
    .await;
    match waiting {
        None => {}
        Some(Ok(0)) => {
            return Err(Error::closed(
                "server closed the connection before the TLS handshake",
            ));
        }
        Some(Ok(_)) => {
            return Err(Error::protocol(
                "server sent unencrypted data after accepting TLS; refusing the connection",
            ));
        }
        Some(Err(e)) => return Err(Error::io("cannot read before the TLS handshake", e)),
    }
    fstp_tls::connect(tls, server_name, io)
        .await
        .map_err(|e| Error::io("TLS handshake failed", e))
}

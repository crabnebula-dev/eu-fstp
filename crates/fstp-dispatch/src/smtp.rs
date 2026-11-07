//! The [`Transport`] over the in-house SMTP client (M6 design sections
//! 5.1 and 5.2).
//!
//! [`SmtpTransport`] opens one TCP connection per attempt to the
//! submission host, and `fstp-smtp` runs implicit TLS over it. Production
//! uses port 465 only. The egress check of the host belongs to the cell
//! (`Destination::MailSubmission`, lane L6-EGR).

use fstp_rt::Runtime;
use fstp_smtp::client::{Envelope as SmtpEnvelope, SmtpClient, SmtpError, Staged};

use crate::prepare::Envelope;
use crate::worker::{EndOfData, Refused, Transport};

/// The SMTP client and the host it submits to.
#[derive(Clone, Debug)]
pub struct SmtpTransport<R> {
    rt: R,
    client: SmtpClient,
    host: String,
    port: u16,
}

impl<R: Runtime> SmtpTransport<R> {
    /// Submits through `client` to `host` on `port`.
    pub fn new(rt: R, client: SmtpClient, host: &str, port: u16) -> SmtpTransport<R> {
        SmtpTransport {
            rt,
            client,
            host: host.to_owned(),
            port,
        }
    }
}

/// The refusal of a session that failed before the final dot.
fn refused(e: &SmtpError) -> Refused {
    match e {
        SmtpError::Transient { reply, .. } => Refused::Transient(Some(reply.code())),
        SmtpError::Permanent { reply, .. } => Refused::Permanent(Some(reply.code())),
        SmtpError::Unsupported(_) | SmtpError::Envelope | SmtpError::Body(_) => {
            Refused::Permanent(None)
        }
        SmtpError::Tls(_)
        | SmtpError::Io { .. }
        | SmtpError::Timeout { .. }
        | SmtpError::Closed { .. }
        | SmtpError::Malformed { .. }
        | SmtpError::Unsolicited { .. }
        | SmtpError::Unexpected { .. } => Refused::Transient(None),
    }
}

impl<R: Runtime> Transport for SmtpTransport<R> {
    type Staged = Staged<R, R::Tcp>;

    async fn stage(&mut self, envelope: &Envelope, body: &[u8]) -> Result<Self::Staged, Refused> {
        let addrs = self
            .rt
            .resolve(&self.host, self.port)
            .await
            .map_err(|_| Refused::Transient(None))?;
        let addr = addrs.first().ok_or(Refused::Transient(None))?;
        let conn = self
            .rt
            .connect_tcp(*addr)
            .await
            .map_err(|_| Refused::Transient(None))?;
        let env = SmtpEnvelope {
            from: envelope.from.clone(),
            to: envelope.to.clone(),
        };
        self.client
            .stage(&self.rt, conn, &env, body)
            .await
            .map_err(|e| refused(&e))
    }

    async fn end_of_data(&mut self, staged: Self::Staged) -> EndOfData {
        match staged.commit().await {
            Ok(reply) => EndOfData::Reply(reply.code()),
            Err(SmtpError::Transient { reply, .. } | SmtpError::Permanent { reply, .. }) => {
                EndOfData::Reply(reply.code())
            }
            Err(_) => EndOfData::Unknown,
        }
    }

    async fn abandon(&mut self, staged: Self::Staged) {
        staged.abandon().await;
    }
}

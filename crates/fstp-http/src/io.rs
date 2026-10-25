//! Transport helpers shared by the server and client drivers.

use std::future::Future;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fstp_rt::{AsyncRead, AsyncWrite};
use fstp_tls::TlsStream;

/// A plain or TLS transport.
pub(crate) enum MaybeTls<S> {
    Plain(S),
    Tls(Box<TlsStream<S>>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeTls<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTls::Tls(s) => Pin::new(&mut **s).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaybeTls<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTls::Tls(s) => Pin::new(&mut **s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTls::Tls(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTls::Tls(s) => Pin::new(&mut **s).poll_shutdown(cx),
        }
    }
}

/// Polls a future and turns a panic into `Err(())`.
pub(crate) struct CatchUnwind<F> {
    fut: Pin<Box<F>>,
}

impl<F: Future> CatchUnwind<F> {
    pub(crate) fn new(fut: F) -> Self {
        Self { fut: Box::pin(fut) }
    }
}

impl<F: Future> Future for CatchUnwind<F> {
    type Output = Result<F::Output, ()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let fut = self.fut.as_mut();
        match catch_unwind(AssertUnwindSafe(move || fut.poll(cx))) {
            Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(Err(())),
        }
    }
}

/// The instant `d` from now, capped far in the future on overflow.
pub(crate) fn deadline_after(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d)
        .or_else(|| now.checked_add(Duration::from_secs(10 * 365 * 24 * 3600)))
        .unwrap_or(now)
}

/// Time left until `deadline`, zero once it passed.
pub(crate) fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Formats `t` as an IMF-fixdate (RFC 9110 section 5.6.7), such as
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
pub(crate) fn http_date(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        // Year 9999 keeps the format at four digits.
        .min(253_402_300_799);
    let days = secs.wrapping_div(86_400);
    let rem = secs.wrapping_rem(86_400);
    let (h, m, s) = (
        rem.wrapping_div(3600),
        rem.wrapping_rem(3600).wrapping_div(60),
        rem.wrapping_rem(60),
    );
    let weekday = usize::try_from(days.wrapping_add(4).wrapping_rem(7)).unwrap_or(0);
    let (y, mo, d) = civil_from_days(days);
    let month = MONTHS
        .get(usize::try_from(mo.wrapping_sub(1)).unwrap_or(0))
        .copied()
        .unwrap_or("Jan");
    let wd = WEEKDAYS.get(weekday).copied().unwrap_or("Sun");
    format!("{wd}, {d:02} {month} {y:04} {h:02}:{m:02}:{s:02} GMT")
}

/// Converts days since 1970-01-01 to a proleptic Gregorian date. This is
/// the well-known era-based algorithm, restricted to non-negative input.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days.wrapping_add(719_468);
    let era = z.wrapping_div(146_097);
    let doe = z.wrapping_rem(146_097);
    let yoe = doe
        .wrapping_sub(doe.wrapping_div(1460))
        .wrapping_add(doe.wrapping_div(36_524))
        .wrapping_sub(doe.wrapping_div(146_096))
        .wrapping_div(365);
    let y = yoe.wrapping_add(era.wrapping_mul(400));
    let doy = doe.wrapping_sub(
        yoe.wrapping_mul(365)
            .wrapping_add(yoe.wrapping_div(4))
            .wrapping_sub(yoe.wrapping_div(100)),
    );
    let mp = doy.wrapping_mul(5).wrapping_add(2).wrapping_div(153);
    let d = doy
        .wrapping_sub(mp.wrapping_mul(153).wrapping_add(2).wrapping_div(5))
        .wrapping_add(1);
    let m = if mp < 10 {
        mp.wrapping_add(3)
    } else {
        mp.wrapping_sub(9)
    };
    let y = if m <= 2 { y.wrapping_add(1) } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imf_fixdate() {
        let t = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(http_date(t), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        let t = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(http_date(t), "Tue, 29 Feb 2000 00:00:00 GMT");
        let t = UNIX_EPOCH + Duration::from_secs(1_792_800_000);
        assert_eq!(http_date(t), "Sat, 24 Oct 2026 00:00:00 GMT");
        let t = UNIX_EPOCH + Duration::from_secs(300_000_000_000);
        assert_eq!(http_date(t), "Fri, 31 Dec 9999 23:59:59 GMT");
    }
}

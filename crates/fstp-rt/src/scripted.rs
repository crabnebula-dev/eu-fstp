//! A transport that replays fixed peer bytes, for fuzzing protocol endpoints.
//!
//! A [`ScriptedStream`] plays a hostile or recorded peer:
//!
//! - Reads return the script's bytes in chunks no larger than the read chunk
//!   limit, then end of stream.
//! - Writes are accepted in chunks no larger than the write chunk limit. The
//!   first bytes are kept for inspection, up to a cap.
//! - A pending pattern makes some operations return `Pending` once before
//!   they make progress. The stream wakes the task itself first, so any
//!   executor, including a no-op waker loop, keeps going.
//!
//! [`ScriptedStream::from_fuzz_input`] derives all of this from a fuzzer's
//! byte string, so one input explores both content and IO timing.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::io::{AsyncRead, AsyncWrite};

/// Largest number of written bytes a [`ScriptedStream`] keeps.
pub const MAX_RECORDED_WRITES: usize = 1 << 20;

/// Number of control bytes [`ScriptedStream::from_fuzz_input`] consumes.
pub const FUZZ_CONTROL_LEN: usize = 3;

/// An in-memory peer that replays a script. See the [module docs](self).
pub struct ScriptedStream {
    input: Vec<u8>,
    pos: usize,
    read_chunk: usize,
    write_chunk: usize,
    pending_pattern: u8,
    op: u32,
    last_was_pending: bool,
    written: Vec<u8>,
    written_total: u64,
    shut_down: bool,
}

impl fmt::Debug for ScriptedStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptedStream")
            .field("remaining", &self.remaining())
            .field("written_total", &self.written_total)
            .field("shut_down", &self.shut_down)
            .finish_non_exhaustive()
    }
}

impl ScriptedStream {
    /// A stream that delivers `input` with no chunking limits and never
    /// returns `Pending`.
    #[must_use]
    pub fn new(input: Vec<u8>) -> Self {
        Self {
            input,
            pos: 0,
            read_chunk: usize::MAX,
            write_chunk: usize::MAX,
            pending_pattern: 0,
            op: 0,
            last_was_pending: false,
            written: Vec::new(),
            written_total: 0,
            shut_down: false,
        }
    }

    /// Derives the stream from fuzzer input.
    ///
    /// The first [`FUZZ_CONTROL_LEN`] bytes select the read chunk limit, the
    /// pending pattern and the write chunk limit. The rest is the script.
    /// Missing control bytes count as zero.
    #[must_use]
    pub fn from_fuzz_input(data: &[u8]) -> Self {
        let ctrl = |i: usize| data.get(i).copied().unwrap_or(0);
        let script = data.get(FUZZ_CONTROL_LEN..).unwrap_or_default().to_vec();
        Self::new(script)
            .with_read_chunk(chunk_from_control(ctrl(0)))
            .with_pending_pattern(ctrl(1))
            .with_write_chunk(chunk_from_control(ctrl(2)))
    }

    /// Limits every read to at most `n` bytes. Zero is raised to one.
    #[must_use]
    pub fn with_read_chunk(mut self, n: usize) -> Self {
        self.read_chunk = n.max(1);
        self
    }

    /// Limits every write to at most `n` bytes. Zero is raised to one.
    #[must_use]
    pub fn with_write_chunk(mut self, n: usize) -> Self {
        self.write_chunk = n.max(1);
        self
    }

    /// Bit `i % 8` of `pattern` makes the `i`-th IO operation return
    /// `Pending` first. An operation never returns `Pending` twice in a row.
    #[must_use]
    pub fn with_pending_pattern(mut self, pattern: u8) -> Self {
        self.pending_pattern = pattern;
        self
    }

    /// Script bytes not yet read.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    /// The first written bytes, up to [`MAX_RECORDED_WRITES`].
    #[must_use]
    pub fn written(&self) -> &[u8] {
        &self.written
    }

    /// Total number of bytes accepted by writes.
    #[must_use]
    pub fn written_total(&self) -> u64 {
        self.written_total
    }

    /// True once `poll_shutdown` was called.
    #[must_use]
    pub fn is_shut_down(&self) -> bool {
        self.shut_down
    }

    /// Decides whether the current operation returns `Pending` first.
    fn maybe_pending(&mut self, cx: &mut Context<'_>) -> bool {
        let bit = self.op % 8;
        self.op = self.op.wrapping_add(1);
        if self.last_was_pending {
            self.last_was_pending = false;
            return false;
        }
        if (self.pending_pattern >> bit) & 1 == 1 {
            self.last_was_pending = true;
            cx.waker().wake_by_ref();
            return true;
        }
        false
    }
}

/// Maps a control byte to a chunk limit: 1 to 64 bytes for most values, and
/// no limit for the top quarter of the range.
fn chunk_from_control(b: u8) -> usize {
    if b >= 192 {
        usize::MAX
    } else {
        usize::from(b % 64).saturating_add(1)
    }
}

impl AsyncRead for ScriptedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.maybe_pending(cx) {
            return Poll::Pending;
        }
        let rest = this.input.get(this.pos..).unwrap_or_default();
        let n = rest.len().min(buf.len()).min(this.read_chunk);
        for (dst, src) in buf.iter_mut().zip(rest.iter().take(n)) {
            *dst = *src;
        }
        this.pos = this.pos.saturating_add(n);
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for ScriptedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.shut_down {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after shutdown",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.maybe_pending(cx) {
            return Poll::Pending;
        }
        let n = buf.len().min(this.write_chunk);
        let room = MAX_RECORDED_WRITES.saturating_sub(this.written.len());
        this.written.extend(buf.iter().take(n.min(room)));
        this.written_total = this
            .written_total
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().shut_down = true;
        Poll::Ready(Ok(()))
    }
}

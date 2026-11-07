//! Span maps from a transformed text back to its source (R-LA-02).
//!
//! A map is a sequence of segments in output order. A copied segment maps
//! byte for byte. A replaced segment maps its whole output range to its
//! whole source range, so a quote that covers a placeholder maps back to
//! the full value it stands for. A removed segment has no output bytes.

/// One segment of a [`SpanMap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seg {
    out_start: usize,
    out_len: usize,
    src_start: usize,
    src_len: usize,
    copied: bool,
}

/// Maps byte offsets of an output text to byte offsets of its source.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpanMap {
    segs: Vec<Seg>,
    out_len: usize,
    src_len: usize,
}

impl SpanMap {
    /// An empty map, to be built with the `push_*` methods in order.
    pub(crate) fn new() -> SpanMap {
        SpanMap::default()
    }

    fn push(&mut self, out_len: usize, src_len: usize, copied: bool) {
        if out_len == 0 && src_len == 0 {
            return;
        }
        self.segs.push(Seg {
            out_start: self.out_len,
            out_len,
            src_start: self.src_len,
            src_len,
            copied,
        });
        self.out_len = self.out_len.saturating_add(out_len);
        self.src_len = self.src_len.saturating_add(src_len);
    }

    /// `len` source bytes copied unchanged.
    pub(crate) fn push_copy(&mut self, len: usize) {
        self.push(len, len, true);
    }

    /// `src_len` source bytes replaced by `out_len` output bytes.
    pub(crate) fn push_replace(&mut self, src_len: usize, out_len: usize) {
        self.push(out_len, src_len, false);
    }

    /// The source offset where an output span starting at `a` starts.
    fn start(&self, a: usize) -> Option<usize> {
        if a == self.out_len {
            return Some(self.src_len);
        }
        let s = self.segs.iter().find(|s| {
            s.out_len > 0 && s.out_start <= a && a < s.out_start.saturating_add(s.out_len)
        })?;
        if s.copied {
            s.src_start.checked_add(a.checked_sub(s.out_start)?)
        } else {
            Some(s.src_start)
        }
    }

    /// The source offset where an output span ending at `b` ends.
    fn end(&self, b: usize) -> Option<usize> {
        if b == 0 {
            return self.start(0);
        }
        let s = self.segs.iter().find(|s| {
            s.out_len > 0 && s.out_start < b && b <= s.out_start.saturating_add(s.out_len)
        })?;
        if s.copied {
            s.src_start.checked_add(b.checked_sub(s.out_start)?)
        } else {
            s.src_start.checked_add(s.src_len)
        }
    }

    /// The source span of the output span `a..b`, or `None` when the span
    /// is out of range or reversed. An empty span maps to a point.
    pub fn span(&self, a: usize, b: usize) -> Option<(usize, usize)> {
        if a > b || b > self.out_len {
            return None;
        }
        let start = self.start(a)?;
        if a == b {
            return Some((start, start));
        }
        let end = self.end(b)?;
        (start <= end).then_some((start, end))
    }
}

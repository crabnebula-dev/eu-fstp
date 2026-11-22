//! The tenant admin's erasure page (P-41, ADR-007; Daniel, 2026-11-15
//! late, `docs/handoff/m3-exit-audit.md` section 9; lane m5/retention).
//!
//! - `admin.erasures` lists the erasure log of the text store and the
//!   grants whose funder retention ended (`fstp_domain::retention`), with
//!   the confirmation instants the journal folded. Ids, causes and
//!   instants only (I-27). The log names no authoriser: an account is
//!   never named on a page (R-CF-03).
//! - `admin.request_erasure` takes `{cause, grant}`. A tenant admin
//!   requests any of the four causes (ADR-007, decided 2026-11-15). It is
//!   high-risk by Daniel's decision, so it needs a step-up and is web
//!   only. The text store erases every text the grant owns.
//!
//! Interim readings of lane m5/retention, pending Daniel:
//!
//! - The request names a grant, and only a grant whose retention ended.
//!   ADR-007 defers the erasure of records under the funder retention
//!   obligation until P-41 ends, so a grant still under retention is
//!   refused under P-41 whatever the cause. Erasures that name no grant,
//!   such as a cell erasure or one person's account, are not on this
//!   page. TODO(legal): which records the retention obligation covers
//!   (ADR-007 "Retention and erasure").
//! - The page lists the grants whose retention ended, not those still
//!   under retention.

use fstp_domain::retention::RetentionEnd;
use fstp_domain::time::Timestamp;
use fstp_json::{Array, Object, ToJson, Value};

use crate::port::ErasureRow;

/// `admin.erasures`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasuresView {
    /// The erasure log, oldest first.
    pub erasures: Vec<ErasureRow>,
    /// The grants whose retention ended, by grant.
    pub retention_ended: Vec<RetentionEnd>,
}

fn dec(n: u128) -> Value {
    Value::String(n.to_string())
}

fn instant(t: Timestamp) -> Value {
    Value::String(t.micros().to_string())
}

impl ToJson for ErasuresView {
    fn to_json(&self) -> Value {
        let mut erasures = Array::new();
        for r in &self.erasures {
            let mut o = Object::new();
            let _ = o.insert("text", dec(r.text.0));
            let _ = o.insert("cause", Value::from(r.cause.wire()));
            let _ = o.insert("grant", r.grant.map_or(Value::Null, |g| dec(g.raw())));
            let _ = o.insert("requested_at", instant(r.requested_at));
            let _ = o.insert("completed_at", r.completed_at.map_or(Value::Null, instant));
            // Lane L33: what the text held, and the root epoch whose
            // destruction completed the erasure.
            let _ = o.insert("kind", Value::from(r.kind.wire()));
            let _ = o.insert(
                "destroyed_epoch",
                r.destroyed_epoch
                    .map_or(Value::Null, |e| dec(u128::from(e))),
            );
            erasures.push(Value::Object(o));
        }
        let mut ended = Array::new();
        for e in &self.retention_ended {
            let mut o = Object::new();
            let _ = o.insert("grant", dec(e.grant.raw()));
            let _ = o.insert("programme", dec(e.programme.raw()));
            let _ = o.insert("start", instant(e.start));
            let _ = o.insert("end", instant(e.end));
            ended.push(Value::Object(o));
        }
        let mut o = Object::new();
        let _ = o.insert("erasures", Value::Array(erasures));
        let _ = o.insert("retention_ended", Value::Array(ended));
        Value::Object(o)
    }
}

/// The grants whose retention ended at `now`: the end is at or before it.
pub(crate) fn ended(ends: Vec<RetentionEnd>, now: Timestamp) -> Vec<RetentionEnd> {
    ends.into_iter().filter(|e| e.end <= now).collect()
}

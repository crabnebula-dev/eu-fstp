//! The read steps `judging:read-every-route` and `drafting:read-every-route`
//! (I-17, design section 14.4, lane m3/cycle-steps).
//!
//! Each live holder of a Judging or Drafting binding on the cell, whose
//! passkey the cycle's client holds, logs in with that passkey and reads
//! every read route of the cell in its fresh session: each `GET` row of
//! `fstp_cell::routes::table` and `fstp_cell::routes::page_table` that is
//! not loopback-only and names no path parameter. The client records each
//! reply with the session's account (`crate::responses`), so a test scans
//! what these sessions were shown.
//!
//! Interim reading, pending Daniel: the page asset rows
//! (`/assets/auth/{file}`) are public compiled files with no session data,
//! so the step reads no file of them. A holder whose passkey login the
//! cell refuses is skipped, since a login refusal is the I-77 machine's
//! to judge. At least one holder must read, or the step refuses with
//! [`NO_HOLDER`].

use std::collections::BTreeSet;

use fstp_cell::routes::Access;
use fstp_domain::id::AccountId;
use fstp_domain::roles::Group;
use fstp_domain::time::Timestamp;

use super::Cycle;
use crate::NotImplemented;
use crate::reference::auth::RefMethod;

/// The cell has no live holder of the group whose passkey the cycle's
/// client holds, so no session of the group read anything.
pub const NO_HOLDER: &str = "fstp_celltest::cycle judging:read-every-route and drafting:read-every-route: the cell has no live holder of the group whose passkey the cycle's client holds, so no session of the group read a route";

/// The session route every holder must read with a 2xx answer, so a step
/// whose sessions are refused never passes as a read.
const SESSIONS: &str = "/auth/sessions";

/// The read routes of the cell (module documentation).
pub fn read_paths() -> Vec<&'static str> {
    fstp_cell::routes::table()
        .iter()
        .chain(fstp_cell::routes::page_table())
        .filter_map(|r| {
            let (method, path, _) = r.parts();
            (method == "GET" && r.access() != Access::Loopback && !path.contains('{'))
                .then_some(path)
        })
        .collect()
}

impl Cycle<'_> {
    /// `judging:read-every-route` or `drafting:read-every-route`.
    pub(super) fn read_every_route(
        &mut self,
        step: &str,
        group: Group,
    ) -> Result<(), NotImplemented> {
        let s = self.state()?;
        let now = Timestamp::from_micros(self.now());
        let holders: BTreeSet<AccountId> = s
            .engine()
            .core
            .roster()
            .bindings()
            .filter(|(_, b)| b.group() == group && b.active_at(now))
            .map(|(_, b)| b.account)
            .collect();
        let paths = read_paths();
        let mut read = 0usize;
        for cell in &holders {
            let Some(model) = self.client.model_of(*cell) else {
                continue;
            };
            let Some(cookie) = self.client.login(model, RefMethod::Passkey)? else {
                continue;
            };
            for path in &paths {
                let r = self.client.call("GET", path, Some(&cookie), b"")?;
                if *path == SESSIONS && !r.ok() {
                    return Err(Self::refused(step, "GET /auth/sessions", Some(&r)));
                }
            }
            read = read.saturating_add(1);
        }
        if read == 0 {
            eprintln!(
                "fstp_celltest::cycle {step}: {} live holders of {group:?}, none read",
                holders.len()
            );
            return Err(NotImplemented::new(NO_HOLDER));
        }
        Ok(())
    }
}

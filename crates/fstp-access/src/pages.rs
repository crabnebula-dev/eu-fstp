//! The `/app/` page table (SA-09, `docs/design/spec-amendments.md`).
//!
//! Daniel, 2026-11-15: "I should never be able to see a route that my
//! user (or a non-logged in user) does not have permissions to see." So
//! the server decides before it serves any `/app/` page, and it decides
//! with the rule the API uses for the read the page cannot render
//! without. This table is that one list of pages:
//!
//! - each row names a page route pattern, as the client router of
//!   `web/src/shell/main.ts` holds it;
//! - [`PageNeed`] names what the page needs: nothing, a signed-in
//!   account, or one or more reads of [`crate::OPS`], whose path
//!   parameters the page's own parameters fill;
//! - a parameter with a closed set of values (a creator step, a setup
//!   stage) lists them, and every other parameter is an id;
//! - [`Listed`] names a page id that its read does not take, such as the
//!   assignment of `/app/assignments/{assignment}`, whose read
//!   `me.assignments` lists the viewer's own. The page is then served
//!   only when that id is one the read lists for the viewer.
//!
//! `gen-ts` writes the table into `web/src/gen/api.ts` as `PAGES`, and a
//! web test checks that the client router's routes are exactly these
//! patterns (`web/test/pages.test.ts`), so a new page cannot skip the
//! gate. `fstp-api-core` judges a row (`ApiCore::page`), and `fstp-web`
//! answers the outcome before it serves the shell.
//!
//! Interim readings, pending Daniel:
//!
//! - A page that reads nothing it cannot render without is gated on the
//!   read nearest to what it does: the branding and terminology screens
//!   on `tenant.settings` (tenant admins), the two creator start pages on
//!   `creator.list_templates` (the creator start lists), and the payment
//!   request form on `payment.status` (the grant's readers).
//! - `/app/` home, `/app/me` and the invitation landing need no read.
//!   The home page and the profile need a signed-in account, before
//!   activation too (ADR-021). The invitation landing reads the token in
//!   its fragment, which no server sees, so it is open to anyone and
//!   its read is judged when the page loads.
//! - The consent page of an agent connection works the same way: its
//!   handle is in the fragment (lane L2).

use crate::registry::{Method, OPS, OpKind, route_params};

/// What a page needs before the server serves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageNeed {
    /// Anyone, with or without a session.
    Anyone,
    /// A signed-in account, whatever its roles, before activation too
    /// (ADR-021: the home page and the account pages).
    Account,
    /// The first of these reads that admits the viewer, by operation
    /// name. Each read's path parameters are filled from the page's.
    Reads(&'static [&'static str]),
}

/// A page id its read does not take, which must be one the read lists
/// for the viewer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listed {
    /// The viewer's own reviewer assignment, as `me.assignments` lists it.
    ReviewerAssignment,
    /// The viewer's own IRC assignment, as `me.irc_cases` lists it.
    IrcAssignment,
    /// A payment request of the page's grant, as `payment.status` lists it.
    PaymentRequest,
    /// The viewer's own pending action, as `pending.list` lists it.
    PendingAction,
}

/// One `/app/` page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageRow {
    /// The route pattern, such as `/app/proposals/{proposal}`.
    pub pattern: &'static str,
    /// What the page needs.
    pub need: PageNeed,
    /// The parameters with a closed set of values. Every other parameter
    /// is an id: a canonical decimal `u128`.
    pub values: &'static [(&'static str, &'static [&'static str])],
    /// A page id the read does not take, and how the read lists it.
    pub listed: Option<(&'static str, Listed)>,
}

impl PageRow {
    const fn read(pattern: &'static str, reads: &'static [&'static str]) -> PageRow {
        PageRow {
            pattern,
            need: PageNeed::Reads(reads),
            values: &[],
            listed: None,
        }
    }

    const fn need(pattern: &'static str, need: PageNeed) -> PageRow {
        PageRow {
            pattern,
            need,
            values: &[],
            listed: None,
        }
    }

    const fn values(mut self, values: &'static [(&'static str, &'static [&'static str])]) -> Self {
        self.values = values;
        self
    }

    const fn listed(mut self, param: &'static str, how: Listed) -> Self {
        self.listed = Some((param, how));
        self
    }

    /// The closed values of parameter `name`, or `None` for an id.
    pub fn values_of(&self, name: &str) -> Option<&'static [&'static str]> {
        self.values
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| *v)
    }

    /// The reads the page needs: none for [`PageNeed::Anyone`] and
    /// [`PageNeed::Account`].
    pub fn reads(&self) -> &'static [&'static str] {
        match self.need {
            PageNeed::Reads(r) => r,
            PageNeed::Anyone | PageNeed::Account => &[],
        }
    }
}

/// The creator steps of `web/src/creator/model.ts` `CREATOR_STEPS`.
pub const CREATOR_STEPS: &[&str] = &[
    "funder",
    "identity",
    "eligibility",
    "funding",
    "evaluation",
    "money",
    "contract",
    "support",
    "people",
    "comms",
    "review",
];

/// The setup stages of a draft (`web/src/setup/model.ts` `isDraftStage`).
pub const SETUP_STAGES: &[&str] = &[
    "programme",
    "applicants",
    "evaluation",
    "team",
    "communications",
    "review",
];

/// The onboarding steps (`fstp_tenant::OnboardingStep::name`,
/// `web/src/onboarding/model.ts` `ONBOARDING_STEPS`).
pub const ONBOARDING_STEPS: &[&str] = &[
    "organisation",
    "agreements",
    "branding",
    "domains_and_email",
    "identity",
    "inference",
    "payments",
    "channels",
    "administrators",
];

/// The tenant settings with a page (`web/src/onboarding/model.ts`
/// `SETTINGS`).
pub const SETTINGS: &[&str] = &["p20", "p69", "p70", "p71", "p72", "p74"];

const PROPOSAL_VIEW: &[&str] = &["proposal.view"];
const DRAFT: &[&str] = &["creator.get_draft"];
const CREATOR_START: &[&str] = &["creator.list_templates"];
const TENANT_ADMIN: &[&str] = &["tenant.settings"];
const GRANT_READ: &[&str] = &["payment.status"];
const ASSIGNMENTS: &[&str] = &["me.assignments"];

/// Every `/app/` page, in the order the server matches them. No path
/// matches two rows (a test pins it).
pub const PAGES: &[PageRow] = &[
    // The home page, the profile and the account pages (ADR-021).
    PageRow::need("/app/", PageNeed::Account),
    PageRow::need("/app/me", PageNeed::Account),
    PageRow::read("/app/me/identity", &["me.get_verification"]),
    PageRow::read("/app/mailbox", &["me.mailbox"]),
    PageRow::read("/app/pending/{pending}", &["pending.list"])
        .listed("pending", Listed::PendingAction),
    PageRow::read("/app/notices", &["me.notices"]),
    // The invitation landing: its token is in the fragment.
    PageRow::need("/app/invitation", PageNeed::Anyone),
    // Lane L2 (ADR-013 amendment of 2026-11-20): the consent page of an
    // agent connection. Its handle is in the fragment, so no server sees
    // it, and the page asks the visitor to sign in itself.
    PageRow::need("/app/connect", PageNeed::Anyone),
    // Onboarding and the tenant admin's screens.
    PageRow::read("/app/admin/approvals", &["admin.approvals"]),
    PageRow::read("/app/admin/onboarding/summary", &["tenant.get_activation"]),
    PageRow::read("/app/admin/onboarding/{step}", &["tenant.get_step"])
        .values(&[("step", ONBOARDING_STEPS)]),
    PageRow::read("/app/admin/settings/{param}", TENANT_ADMIN).values(&[("param", SETTINGS)]),
    PageRow::read("/app/admin/branding", TENANT_ADMIN),
    PageRow::read("/app/admin/terminology", TENANT_ADMIN),
    // P-41, ADR-007 (lane m5/retention): the erasure page reads the log.
    PageRow::read("/app/admin/erasures", &["admin.erasures"]),
    // ADR-028 record of lane L20: the System page, tenant admins only.
    PageRow::read("/app/admin/system", &["tenant.system"]),
    // Daniel, 2026-11-15 (late): tenant copies of funder profiles.
    PageRow::read("/app/admin/funder-profiles", &["tenant.funder_profiles"]),
    // SA-11 (Daniel, 2026-11-15, night): the member page, tenant admins only.
    PageRow::read("/app/admin/members", &["admin.members"]),
    // The creator, the Planning Studio, the wizard and the people page.
    PageRow::read("/app/creator/new", CREATOR_START),
    PageRow::read("/app/setup/new", CREATOR_START),
    PageRow::read("/app/programmes/{programme}/creator/start", DRAFT),
    PageRow::read(
        "/app/programmes/{programme}/creator/imports",
        &["import.list"],
    ),
    PageRow::read("/app/programmes/{programme}/creator/{step}", DRAFT)
        .values(&[("step", CREATOR_STEPS)]),
    PageRow::read("/app/programmes/{programme}/studio", DRAFT),
    PageRow::read("/app/programmes/{programme}/studio/approval", DRAFT),
    PageRow::read(
        "/app/programmes/{programme}/studio/guide",
        &["creator.get_report"],
    ),
    PageRow::read("/app/programmes/{programme}/studio/knock-outs", DRAFT),
    PageRow::read("/app/programmes/{programme}/setup/progress", DRAFT),
    PageRow::read("/app/programmes/{programme}/setup/{stage}", DRAFT)
        .values(&[("stage", SETUP_STAGES)]),
    PageRow::read("/app/programmes/{programme}/people", DRAFT),
    // SA-11: the team page, for the manager and the tenant admins.
    PageRow::read("/app/programmes/{programme}/team", &["team.list"]),
    // ADR-030 (lead reading of 2026-11-22): the programme's logo, for its
    // programme managers.
    PageRow::read("/app/programmes/{programme}/logo", &["programme.logos"]),
    PageRow::read(
        "/app/programmes/{programme}/audit",
        &["audit.entries", "audit.unmasks"],
    ),
    PageRow::read("/app/programmes/{programme}/reports", &["report.list"]),
    // Daniel, 2026-11-15 (late): every programme staff role reads the
    // programme's funder profile, read-only.
    PageRow::read(
        "/app/programmes/{programme}/funder-profile",
        &["programme.funder_profile.view"],
    ),
    // The calls and the applicant pages.
    PageRow::read("/app/calls", &["calls.list_open"]),
    PageRow::read("/app/calls/{call}", &["calls.get"]),
    PageRow::read("/app/calls/{call}/guide", &["calls.guide"]),
    PageRow::read("/app/proposals", &["proposal.list_own"]),
    PageRow::read("/app/proposals/{proposal}", PROPOSAL_VIEW),
    PageRow::read(
        "/app/proposals/{proposal}/workspace",
        &["proposal.get_workspace"],
    ),
    PageRow::read(
        "/app/proposals/{proposal}/precheck",
        &["proposal.precheck_runs"],
    ),
    PageRow::read("/app/proposals/{proposal}/plan", PROPOSAL_VIEW),
    PageRow::read("/app/proposals/{proposal}/team", PROPOSAL_VIEW),
    PageRow::read("/app/proposals/{proposal}/eligibility", PROPOSAL_VIEW),
    PageRow::read("/app/proposals/{proposal}/submit", PROPOSAL_VIEW),
    PageRow::read("/app/proposals/{proposal}/stage2", PROPOSAL_VIEW),
    PageRow::read("/app/proposals/{proposal}/negotiation", PROPOSAL_VIEW),
    PageRow::read("/app/proposals/{proposal}/guardian", PROPOSAL_VIEW),
    // The voyager pages (lane j3).
    PageRow::read("/app/proposals/{proposal}/progress", &["proposal.journey"]),
    PageRow::read("/app/proposals/{proposal}/activity", &["proposal.diary"]),
    // The Judging pages: the coordinator, reviewers, committee and IRC.
    PageRow::read("/app/calls/{call}/intake", &["intake.queue"]),
    PageRow::read("/app/calls/{call}/board", &["call.board"]),
    PageRow::read(
        "/app/calls/{call}/notifiable-conflicts",
        &["review.notifiable_conflicts"],
    ),
    PageRow::read(
        "/app/proposals/{proposal}/declaration",
        &["review.declaration_view"],
    ),
    PageRow::read(
        "/app/proposals/{proposal}/knock-out",
        &["review.read_content"],
    ),
    PageRow::read(
        "/app/proposals/{proposal}/assignments",
        &["review.assignments"],
    ),
    PageRow::read("/app/proposals/{proposal}/parties", &["identity.parties"]),
    PageRow::read("/app/me/assignments", ASSIGNMENTS),
    PageRow::read("/app/assignments/{assignment}", ASSIGNMENTS)
        .listed("assignment", Listed::ReviewerAssignment),
    PageRow::read("/app/assignments/{assignment}/summary", ASSIGNMENTS)
        .listed("assignment", Listed::ReviewerAssignment),
    PageRow::read(
        "/app/assignments/{assignment}/stage2",
        &["review.stage2_thread"],
    ),
    PageRow::read("/app/calls/{call}/ranking", &["committee.ranking"]),
    PageRow::read("/app/cut-off-rounds/{round}", &["committee.round"]),
    PageRow::read("/app/me/irc-cases", &["me.irc_cases"]),
    PageRow::read("/app/irc-assignments/{irc_assignment}", &["me.irc_cases"])
        .listed("irc_assignment", Listed::IrcAssignment),
    // The post-grant pages (M5).
    PageRow::read("/app/grants", &["grant.list_mine"]),
    PageRow::read(
        "/app/grants/{proposal}",
        &["grant.overview", "grant.determination_view"],
    ),
    PageRow::read(
        "/app/grants/{proposal}/visibility",
        &["grant.publicity.view"],
    ),
    PageRow::read("/app/grants/{proposal}/contract", &["contract.view"]),
    PageRow::read("/app/grants/{proposal}/payments", GRANT_READ),
    PageRow::read("/app/grants/{proposal}/payments/new", GRANT_READ),
    PageRow::read(
        "/app/grants/{proposal}/payments/{request}",
        &["payment.status", "payment.line_review_view"],
    )
    .listed("request", Listed::PaymentRequest),
    PageRow::read(
        "/app/grants/{proposal}/payments/{request}/resubmit",
        GRANT_READ,
    )
    .listed("request", Listed::PaymentRequest),
    PageRow::read("/app/operations", &["payment.queue"]),
];

/// Whether `s` is a canonical decimal `u128`: digits only, no leading
/// zero, and in range.
pub fn canonical_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.iter().all(u8::is_ascii_digit)
        && (b.len() == 1 || b.first() != Some(&b'0'))
        && s.parse::<u128>().is_ok()
}

/// The row of `path` and its parameters, by name, or `None` for a path
/// no page has. `path` is the request path with no query.
pub fn page_of(path: &str) -> Option<(&'static PageRow, Vec<(&'static str, String)>)> {
    PAGES
        .iter()
        .find_map(|row| match_row(row, path).map(|p| (row, p)))
}

/// Matches `path` against one row.
fn match_row(row: &'static PageRow, path: &str) -> Option<Vec<(&'static str, String)>> {
    let pat = row.pattern.split('/');
    let mut got = path.split('/');
    let mut params = Vec::new();
    for p in pat {
        let g = got.next()?;
        match p.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some(name) => {
                let ok = match row.values_of(name) {
                    Some(vals) => vals.contains(&g),
                    None => canonical_id(g),
                };
                if !ok {
                    return None;
                }
                params.push((name, g.to_owned()));
            }
            None if p == g => {}
            None => return None,
        }
    }
    if got.next().is_some() {
        return None;
    }
    Some(params)
}

/// The read operation `name` of a page row: a read with a `GET` route.
pub fn page_read(name: &str) -> Option<&'static crate::OpSpec> {
    OPS.iter().find(|o| {
        o.name == name
            && matches!(o.kind, OpKind::Read(_))
            && matches!(o.route, Some((Method::Get, _)))
    })
}

/// The path parameters of `read`'s route that its page fills.
pub fn read_params(read: &crate::OpSpec) -> impl Iterator<Item = &'static str> {
    read.route
        .map(|(_, p)| p)
        .into_iter()
        .flat_map(route_params)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// SA-09 rule 5: every read a page row names is a read of the
    /// registry with a `GET` route, and the page fills each of its path
    /// parameters with an id of its own.
    #[test]
    fn sa09_every_page_read_is_a_registry_read_its_page_fills() {
        for row in PAGES {
            let page: Vec<&str> = route_params(row.pattern).collect();
            if let PageNeed::Reads(reads) = row.need {
                assert!(!reads.is_empty(), "{}", row.pattern);
            }
            for name in row.reads() {
                let Some(spec) = page_read(name) else {
                    panic!("{}: {name} is no GET read", row.pattern);
                };
                for p in read_params(spec) {
                    assert!(page.contains(&p), "{}: {name} needs {{{p}}}", row.pattern);
                }
            }
            for (name, _) in row.values {
                assert!(page.contains(name), "{}: {name}", row.pattern);
            }
            if let Some((name, _)) = row.listed {
                assert!(page.contains(&name), "{}: {name}", row.pattern);
                assert!(row.values_of(name).is_none(), "{}", row.pattern);
            }
        }
    }

    /// SA-09: the patterns are distinct, each under `/app/`, and no path
    /// matches two rows: wherever two rows of one length differ, one
    /// segment tells them apart.
    #[test]
    fn sa09_no_path_matches_two_page_rows() {
        for (i, a) in PAGES.iter().enumerate() {
            assert!(a.pattern.starts_with("/app/"), "{}", a.pattern);
            for b in PAGES.iter().skip(i.saturating_add(1)) {
                assert_ne!(a.pattern, b.pattern);
                let sa: Vec<&str> = a.pattern.split('/').collect();
                let sb: Vec<&str> = b.pattern.split('/').collect();
                if sa.len() != sb.len() {
                    continue;
                }
                let apart = sa.iter().zip(&sb).any(|(x, y)| disjoint(a, x, b, y));
                assert!(apart, "{} and {} overlap", a.pattern, b.pattern);
            }
        }
    }

    /// The values one segment of a row admits: `None` for any id.
    fn admitted(row: &PageRow, seg: &str) -> Option<Vec<String>> {
        match seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            Some(name) => row
                .values_of(name)
                .map(|v| v.iter().map(|s| (*s).to_owned()).collect()),
            None => Some(vec![seg.to_owned()]),
        }
    }

    fn disjoint(a: &PageRow, x: &str, b: &PageRow, y: &str) -> bool {
        match (admitted(a, x), admitted(b, y)) {
            (None, None) => false,
            (Some(v), None) | (None, Some(v)) => v.iter().all(|s| !canonical_id(s)),
            (Some(v), Some(w)) => v.iter().all(|s| !w.contains(s)),
        }
    }

    /// SA-09: a path matches its row with its parameters, and an unknown
    /// value, a non-canonical id or an extra segment matches none.
    #[test]
    fn sa09_page_paths_match_their_rows() {
        let (row, params) = page_of("/app/proposals/12/workspace").unwrap();
        assert_eq!(row.pattern, "/app/proposals/{proposal}/workspace");
        assert_eq!(params, vec![("proposal", "12".to_owned())]);
        let (row, _) = page_of("/app/programmes/3/creator/start").unwrap();
        assert_eq!(row.pattern, "/app/programmes/{programme}/creator/start");
        let (row, _) = page_of("/app/programmes/3/creator/money").unwrap();
        assert_eq!(row.pattern, "/app/programmes/{programme}/creator/{step}");
        assert_eq!(page_of("/app/").map(|r| r.0.need), Some(PageNeed::Account));
        for none in [
            "/app",
            "/app/nothing",
            "/app/proposals/012",
            "/app/proposals/x",
            "/app/proposals/1/",
            "/app/programmes/3/creator/other",
            "/app/admin/settings/p99",
            "/app/grants/1/payments/new/x",
        ] {
            assert!(page_of(none).is_none(), "{none}");
        }
    }
}

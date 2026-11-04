//! The demo page of one cell, on its loopback control base only (layering
//! rule A9). It is a plain HTML page with no script, for a person running
//! the demo by hand:
//!
//! - `GET /demo`: the scene, every unused one-time sign-in link with the
//!   person it is for and one line on what that person can do in the
//!   scene, and every message the cell has sent, so a sign-up proof can
//!   be opened without an email server.
//! - `GET /demo/review?stage=<stage>` and `GET /demo/applicant?at=<at>`: a
//!   fresh cell seeded as `POST /test/scenario/*` seeds it.
//! - `GET /demo/reset`: the cell at first start, with its first tenant
//!   admin's link.
//! - `GET /demo/advance?minutes=<n>`: moves the cell clock forward.
//!
//! The scene and clock links change the cell on a GET, so a person can
//! follow them from this page. A request from this page carries
//! `Sec-Fetch-Site: same-origin`, which only the control base itself can
//! send. A cell origin is another site, so no cell page reaches these
//! routes: `Sec-Fetch-Site: cross-site` and any `Origin` are refused, as
//! on the other control routes.

use fstp_http::{Method, Request, Response, StatusCode};

use std::collections::BTreeSet;

use fstp_domain::StateTag;
use fstp_domain::assignment::{AssignmentKind, AssignmentStatus};
use fstp_domain::id::{AccountId, ProgrammeId, ProposalId};
use fstp_domain::roles::{BindingScope, Role};

use crate::{Inner, Site, control, lock, scenario, wire};

/// The review stages of [`scenario::ReviewAt`], in the order a call runs.
const REVIEW_STAGES: [&str; 7] = [
    "submitted",
    "stage1",
    "stage1_scored",
    "stage2",
    "ranked",
    "ranked_tie",
    "irc_review",
];

/// The applicant states of [`scenario::At`].
const APPLICANT_AT: [&str; 7] = [
    "OPEN_CALL",
    "STAGE2",
    "IRC_REVIEW_MINOR",
    "NEGOTIATION",
    "NOT_SELECTED",
    "DEFERRED_AFTER_CONCERN",
    "INELIGIBLE",
];

/// Whether `req` may use the demo routes: a loopback `Host` of the control
/// base, no `Origin`, and a `Sec-Fetch-Site` of `none` (typed or
/// bookmarked) or `same-origin` (a link on this page), or none at all.
fn allowed(site: &Site, req: &Request) -> bool {
    if req.method != Method::GET || req.headers.get("origin").is_some() {
        return false;
    }
    if let Some(v) = req.headers.get("sec-fetch-site")
        && !matches!(v.as_bytes(), b"none" | b"same-origin")
    {
        return false;
    }
    control::loopback_host(&site.info, req)
}

/// Answers one demo request.
pub(crate) async fn handle(site: &Site, req: Request) -> Response {
    if !allowed(site, &req) {
        return wire::refuse(StatusCode::FORBIDDEN, "control");
    }
    let path = req.target.path().to_owned();
    let done = match path.as_str() {
        "/demo" | "/demo/" => return page(site),
        "/demo/reset" => control::fresh(&site.info).map(|f| site.replace(f.inner)),
        "/demo/review" => match wire::query_param(&req, "stage") {
            Some(s) if REVIEW_STAGES.contains(&s.as_str()) => scenario::demo_review(site, &s).await,
            _ => return wire::bad("stage"),
        },
        "/demo/applicant" => match wire::query_param(&req, "at") {
            Some(a) if APPLICANT_AT.contains(&a.as_str()) => {
                scenario::demo_applicant(site, &a).await
            }
            _ => return wire::bad("at"),
        },
        "/demo/advance" => {
            match wire::query_param(&req, "minutes").and_then(|m| m.parse::<i64>().ok()) {
                Some(m) if (1..=10_080).contains(&m) => {
                    site.inner()
                        .ports
                        .clock
                        .advance(m.saturating_mul(60_000_000));
                    Ok(())
                }
                _ => return wire::bad("minutes"),
            }
        }
        _ => return wire::not_found(),
    };
    match done {
        Ok(()) => {
            let mut r = Response::new(StatusCode::SEE_OTHER);
            let _ = r.headers.try_insert("location", "/demo");
            r
        }
        Err(e) => wire::refuse(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

/// `s` escaped for HTML text and double-quoted attribute values.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// `n` and the noun `one` or `many` after it, such as `2 review
/// assignments`.
fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The unreleased assignments of one kind that a person holds: those
/// whose page still opens, those of them awaiting the declaration, and
/// the finished ones.
#[derive(Default)]
struct Tally {
    open: usize,
    waiting: usize,
    finished: usize,
}

impl Tally {
    /// The words for the tally, such as `2 review assignments to work
    /// on, 2 to declare first`. `then` follows the count waiting.
    fn say(&self, one: &str, many: &str, then: &str) -> String {
        if self.open == 0 {
            return if self.finished == 0 {
                format!("no {one} in this scene")
            } else {
                format!("no {one} open in this scene ({} finished)", self.finished)
            };
        }
        let mut s = format!(
            "{} to work on, {} {then}",
            count(self.open, one, many),
            self.waiting
        );
        if self.finished > 0 {
            s.push_str(&format!(", and {} finished", self.finished));
        }
        s
    }
}

/// One short line on what the person with `account` can do in the
/// scene the cell holds now, read from its state: the tenant admin set,
/// the person's bindings and their assignments.
///
/// Interim, pending Daniel (design section 15.0, 2026-10-31): Daniel
/// reported that the demo gives a person nothing to do after the
/// passkey. Each line says where the home page leads that person.
pub(crate) fn what_they_can_do(inner: &Inner, account: AccountId) -> String {
    let state = inner.ports.engine.state();
    let core = &state.core;
    let now = inner.ports.clock.read();
    let mut parts: Vec<String> = Vec::new();
    if inner.ports.tenant.holds_admin(account) {
        parts.push(
            "Tenant admin: the onboarding steps, a new programme draft and the approval inbox."
                .to_owned(),
        );
    }
    let roster = core.roster();
    let mut staff: BTreeSet<Role> = BTreeSet::new();
    let mut managed: BTreeSet<ProgrammeId> = BTreeSet::new();
    let mut receiving: BTreeSet<(ProposalId, Role)> = BTreeSet::new();
    let mine = roster
        .bindings()
        .map(|(_, b)| (*b, b.active_at(now)))
        .chain(roster.ended().map(|(_, e)| (e.binding, false)));
    for (b, active) in mine.filter(|(b, _)| b.account == account) {
        match b.scope {
            BindingScope::Programme if active => {
                staff.insert(b.role);
                if b.role == Role::ProgrammeManager {
                    managed.insert(b.programme);
                }
            }
            BindingScope::Proposal { proposal, .. } => {
                receiving.insert((proposal, b.role));
            }
            BindingScope::Programme => {}
        }
    }
    // Each assignment the person holds, unreleased, by whether its page
    // still opens: a reviewer's while its proposal is in a review stage
    // (or, before the declaration, in the states the declaration view
    // opens in), an IRC member's while its proposal is in IRC_REVIEW.
    // A finished assignment is counted apart, so the line never promises
    // work whose page refuses (review findings U2 and U3).
    let tally = |irc: bool| {
        let mut t = Tally::default();
        for (_, a) in core.review().assignments() {
            if a.reviewer != account
                || !a.unreleased()
                || matches!(a.kind, AssignmentKind::Irc) != irc
            {
                continue;
            }
            let tag = fstp_domain::view::proposal_state(core, a.proposal);
            let waiting = matches!(a.status, AssignmentStatus::AwaitingDeclaration);
            let open = match tag {
                Some(StateTag::IrcReview) => irc,
                Some(StateTag::Stage1 | StateTag::Stage2) => !irc,
                Some(StateTag::Submitted | StateTag::Negotiation) => !irc && waiting,
                _ => false,
            };
            if !open {
                t.finished = t.finished.saturating_add(1);
            } else if waiting {
                t.open = t.open.saturating_add(1);
                t.waiting = t.waiting.saturating_add(1);
            } else {
                t.open = t.open.saturating_add(1);
            }
        }
        t
    };
    for role in staff {
        parts.push(match role {
            Role::ProgrammeManager => {
                if managed.iter().any(|p| state.creator.draft(*p).is_some()) {
                    "Programme manager: the programme set-up and people pages of the programme, and its call boards."
                        .to_owned()
                } else {
                    // A programme without a creator draft would refuse
                    // both pages that read one (review finding U1).
                    "Programme manager: the board of each published call of the programme.".to_owned()
                }
            }
            Role::CallDrafter => "Call drafter: the call boards of the programme.".to_owned(),
            Role::FstpCoordinator => {
                "FSTP coordinator: the intake queue and the board of each published call.".to_owned()
            }
            Role::CommitteeMember => format!(
                "Committee member: {}, and the ranking of each published call.",
                tally(false).say("review assignment", "review assignments", "to declare first")
            ),
            // No read of this crate gives the open cut-off rounds, which
            // only the API core's journal folds, so the line promises
            // none. The home page links one when it is open (review
            // finding U4).
            Role::CommitteeChair => {
                "Committee chair: the ranking of each published call.".to_owned()
            }
            Role::IrcMember => format!(
                "IRC member: {}.",
                tally(true).say("IRC case", "IRC cases", "to declare first, then validate or raise a concern")
            ),
            other => format!(
                "{}: this release has no page for this role yet.",
                fstp_access::role_wire_name(other)
            ),
        });
    }
    for (proposal, role) in receiving {
        let tag =
            fstp_domain::view::proposal_state(core, proposal).map_or("UNKNOWN", |t| t.spec_name());
        let p = proposal.raw();
        parts.push(match role {
            Role::Applicant => {
                format!("Lead applicant of proposal {p}, now {tag}: open it from the home page.")
            }
            Role::Guardian => {
                format!("Guardian of proposal {p}, now {tag}: give consent on its guardian page.")
            }
            _ => format!("Team member of proposal {p}, now {tag}."),
        });
    }
    if parts.is_empty() {
        parts.push("No role in this scene: the home page offers the open calls.".to_owned());
    }
    parts.join(" ")
}

/// The demo page.
fn page(site: &Site) -> Response {
    let inner = site.inner();
    let auth = lock(&inner.auth);
    let mut people = String::new();
    for (account, url) in auth.open_invites() {
        let email = auth.email_of(account).unwrap_or("");
        let who = scenario::persona_label(account).unwrap_or(email);
        people.push_str(&format!(
            "<li><a href=\"{u}\" target=\"_blank\" rel=\"noopener\">{w}</a> <small>{e}</small><br>\
<span>{n}</span></li>\n",
            u = esc(&url),
            w = esc(who),
            e = esc(email),
            n = esc(&what_they_can_do(&inner, account)),
        ));
    }
    if people.is_empty() {
        people.push_str("<li>Every sign-in link of this scene is used. Signed-in people sign in again at <a href=\"");
        people.push_str(&esc(&format!("{}/auth/login", site.info.origin)));
        people.push_str("\" target=\"_blank\" rel=\"noopener\">/auth/login</a>.</li>\n");
    }
    let mut mail = String::new();
    for m in auth.all_messages().iter().rev() {
        mail.push_str(&format!(
            "<li>{k} to {t}: <a href=\"{l}\" target=\"_blank\" rel=\"noopener\">open</a></li>\n",
            k = esc(m.kind),
            t = esc(&m.to),
            l = esc(&m.link),
        ));
    }
    if mail.is_empty() {
        mail.push_str("<li>No message yet. A sign-up on the cell puts its proof link here.</li>\n");
    }
    drop(auth);
    let now = inner.ports.clock.read().micros();
    let review: String = REVIEW_STAGES
        .iter()
        .map(|s| format!("<a href=\"/demo/review?stage={s}\">{s}</a> "))
        .collect();
    let applicant: String = APPLICANT_AT
        .iter()
        .map(|a| format!("<a href=\"/demo/applicant?at={a}\">{a}</a> "))
        .collect();
    let origin = esc(&site.info.origin);
    let body = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta http-equiv=\"refresh\" content=\"10\">\
<title>FSTP demo, cell {name}</title></head><body>\n\
<h1>FSTP demo, cell {name}</h1>\n\
<p>Test cell with synthetic data only. Cell: <a href=\"{origin}/auth/login\" target=\"_blank\" rel=\"noopener\">{origin}</a>. \
Cell clock: {now} µs. This page reloads every 10 seconds.</p>\n\
<p>Open each link in its own incognito window and choose \"Create a passkey\". The person is signed in and lands on the home page, which links to their work. A link works once. Under each person, one line says what they can do in this scene.</p>\n\
<h2>People of this scene</h2>\n<ul>\n{people}</ul>\n\
<h2>Messages the cell sent</h2>\n<p>Newest first. To sign up, open {origin}/auth/signup, send a synthetic address such as demo@e2e.invalid, then open its link here.</p>\n<ul>\n{mail}</ul>\n\
<h2>Scenes</h2>\n<p>Each scene replaces the whole cell state and makes new links.</p>\n\
<p>Review: {review}</p>\n<p>Applicant: {applicant}</p>\n\
<p><a href=\"/demo/reset\">Reset</a> (an empty cell and its first tenant admin)</p>\n\
<p>Clock: <a href=\"/demo/advance?minutes=60\">+60 minutes</a> <a href=\"/demo/advance?minutes=1440\">+1 day</a></p>\n\
</body></html>\n",
        name = esc(site.info.name),
    );
    let mut r = Response::with_body(
        StatusCode::OK,
        "text/html; charset=utf-8",
        body.into_bytes(),
    );
    let _ = r.headers.try_insert("cache-control", "no-store");
    let _ = r.headers.try_insert(
        "content-security-policy",
        "default-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    let _ = r.headers.try_insert("x-content-type-options", "nosniff");
    let _ = r.headers.try_insert("referrer-policy", "no-referrer");
    r
}

#[cfg(test)]
mod tests {
    use super::esc;

    /// The page escapes every value it shows.
    #[test]
    fn demo_page_escapes_html() {
        assert_eq!(
            esc("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}

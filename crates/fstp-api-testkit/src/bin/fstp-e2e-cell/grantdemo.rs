//! The demo surfaces of the post-grant lifecycle (M5 design section 7,
//! lane L-DEMO): the fake vault pages, the fake forge and the clock
//! links. Test only: this module lives in `fstp-e2e-cell` (rule A9).
//!
//! - **Fake vault.** The fake vault answers a bank detail or hardship
//!   ticket with `{vault origin}/r#ticket`, the read page the grant pages
//!   accept. It shows the one action of the person's latest ticket: the lead
//!   enters synthetic bank details, the finance approver verifies them,
//!   the releaser views the payee. The action writes the synthetic vault
//!   as the real vault origin would (I-33, I-86). No bank value is shown
//!   or stored anywhere: the vault holds facts only.
//! - **Fake forge.** `/demo/forge/synthetic-sensor-kit` on the control
//!   base is a public synthetic repository with a licence file. It is the
//!   location the demo payment request names.
//! - **Clock links.** `to=milestone_start`, `p36`, `due_minus_14`, `due`
//!   and `due_plus_7` move the cell clock to the instant their name says.

use fstp_api_core::port::VerificationPurpose;
use fstp_domain::time::Timestamp;
use fstp_http::{Method, Request, Response, StatusCode};

use crate::{Inner, wire};

/// Day, in microseconds.
const DAY: i64 = 86_400 * 1_000_000;
/// The call deadline of the seeds, 2026-10-29T11:00:00Z.
const DEADLINE: i64 = 1_793_271_600 * 1_000_000;
/// The first milestone start and the due date of proposal x.
const MILESTONE_START: i64 = DEADLINE + 40 * DAY;
const MILESTONE_DUE: i64 = DEADLINE + 300 * DAY;
/// The demo's reading of the P-36 hold: a month.
const P36_HOLD_DAYS: i64 = 30;

/// The clock links of the demo page: query value and link text.
pub(crate) const CLOCK_LINKS: [(&str, &str); 5] = [
    ("milestone_start", "Advance to the first milestone start"),
    ("p36", "Advance the P-36 bank hold (30 days)"),
    ("due_minus_14", "Advance to milestone due minus 14 days"),
    ("due", "Advance to the milestone due date"),
    ("due_plus_7", "Advance to milestone due plus 7 days"),
];

/// Moves the clock of `inner` as `to` says. A target in the past leaves
/// the clock where it is.
pub(crate) fn clock_to(inner: &Inner, to: &str) -> Result<(), String> {
    let now = inner.ports.clock.read().micros();
    let target = match to {
        "milestone_start" => MILESTONE_START + 3_600_000_000,
        "p36" => now.saturating_add(P36_HOLD_DAYS * DAY),
        "due_minus_14" => MILESTONE_DUE - 14 * DAY,
        "due" => MILESTONE_DUE,
        "due_plus_7" => MILESTONE_DUE + 7 * DAY,
        _ => return Err("to".to_owned()),
    };
    if target > now {
        inner.ports.clock.set(Timestamp::from_micros(target));
    }
    Ok(())
}

fn page(title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title}</title></head>\n<body><main><h1>{title}</h1>\n{body}\n</main></body></html>\n"
    );
    let mut r = Response::with_body(
        StatusCode::OK,
        "text/html; charset=utf-8",
        html.into_bytes(),
    );
    let _ = r.headers.try_insert("cache-control", "no-store");
    let _ = r.headers.try_insert(
        "content-security-policy",
        "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    let _ = r.headers.try_insert("x-content-type-options", "nosniff");
    r
}

/// The words and the button of a purpose, or `None` when the fake vault
/// has no page for it.
fn action_of(p: &VerificationPurpose) -> Option<(&'static str, &'static str)> {
    Some(match p {
        VerificationPurpose::BankDetails(_) => {
            ("Enter the bank details", "Submit synthetic bank details")
        }
        VerificationPurpose::BankVerification(_) => {
            ("Verify the bank details", "Verify the bank details")
        }
        VerificationPurpose::BankDispute(_) => ("Dispute the bank details", "Open a dispute"),
        VerificationPurpose::BankView(_) => {
            ("Payee of the released payment", "Mark the payee as viewed")
        }
        VerificationPurpose::HardshipEvidence(_) => (
            "Submit the hardship evidence",
            "Submit synthetic hardship evidence",
        ),
        VerificationPurpose::HardshipVerification(_) => (
            "Verify the hardship evidence",
            "Verify the hardship evidence",
        ),
        _ => return None,
    })
}

/// The script of the vault's read page: it reads the ticket's action from
/// the vault, shows its button and posts the action. No bank value passes.
const R_JS: &str = "(async () => {\n  const t = await (await fetch('/r/ticket')).json();\n  document.querySelector('h1').textContent = t.title;\n  const b = document.querySelector('#vault-action');\n  b.textContent = t.button;\n  b.hidden = false;\n  b.addEventListener('click', async () => {\n    const r = await fetch('/r/act', { method: 'POST' });\n    if (r.ok) {\n      b.hidden = true;\n      const d = document.querySelector('#vault-done');\n      d.hidden = false;\n    }\n  });\n})();\n";

fn vault_response(kind: &str, body: Vec<u8>, script: bool) -> Response {
    let mut r = Response::with_body(StatusCode::OK, kind, body);
    let _ = r.headers.try_insert("cache-control", "no-store");
    let csp = if script {
        "default-src 'none'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    } else {
        "default-src 'none'; frame-ancestors 'none'"
    };
    let _ = r.headers.try_insert("content-security-policy", csp);
    let _ = r.headers.try_insert("x-content-type-options", "nosniff");
    let _ = r.headers.try_insert("referrer-policy", "no-referrer");
    r
}

/// The vault origin's read page `/r` (M5 design section 7): the synthetic
/// vault shows the action of its latest bank ticket. The finance
/// approver verifies bank details here, the lead enters them, the
/// releaser views the payee. The vault holds facts only (I-33, I-86).
/// `None` for any other path.
pub(crate) fn vault_read(inner: &Inner, req: &Request) -> Option<Response> {
    let path = req.target.path();
    let ticket = || {
        inner
            .ports
            .vault
            .verifications()
            .into_iter()
            .rev()
            .find(|(p, _)| action_of(p).is_some())
    };
    match (&req.method, path) {
        (&Method::GET, "/r") => Some(vault_response(
            "text/html; charset=utf-8",
            b"<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Identity vault</title></head>\n<body><main><h1>Identity vault</h1>\n<p>Synthetic test vault of the e2e cell. The vault holds the bank details. The platform never sees them (I-86).</p>\n<button type=\"button\" id=\"vault-action\" hidden>Continue</button>\n<p id=\"vault-done\" hidden>Done. The vault recorded the fact. No bank value leaves the vault.</p>\n<script src=\"/r.js\"></script></main></body></html>\n".to_vec(),
            true,
        )),
        (&Method::GET, "/r.js") => Some(vault_response(
            "text/javascript; charset=utf-8",
            R_JS.as_bytes().to_vec(),
            true,
        )),
        (&Method::GET, "/r/ticket") => {
            let (title, button) = ticket()
                .and_then(|(p, _)| action_of(&p))
                .unwrap_or(("No ticket", "Continue"));
            Some(wire::json(
                StatusCode::OK,
                &wire::obj(vec![("title", title.into()), ("button", button.into())]),
            ))
        }
        (&Method::POST, "/r/act") => {
            let Some((purpose, _)) = ticket() else {
                return Some(wire::not_found());
            };
            let now = inner.ports.clock.read();
            inner.ports.vault.change(|t| match purpose {
                VerificationPurpose::BankDetails(g) => t.write_bank(g, now),
                VerificationPurpose::BankVerification(g) => t.verify_bank(g),
                VerificationPurpose::BankDispute(g) => t.dispute_bank(g, true),
                // R-PR-04: the reference is the one the seed filed.
                VerificationPurpose::HardshipVerification(g) => {
                    t.verify_hardship(g, crate::scenario::postgrant::hardship_evidence(g));
                }
                _ => {}
            });
            Some(wire::json(StatusCode::OK, &wire::obj(vec![])))
        }
        _ => None,
    }
}

/// `/demo/forge/synthetic-sensor-kit` on the control base: a public
/// synthetic repository with a licence file.
pub(crate) fn forge(req: &Request) -> Option<Response> {
    let p = req.target.path();
    if p == "/demo/forge/synthetic-sensor-kit" || p == "/demo/forge/synthetic-sensor-kit/" {
        return Some(page(
            "synthetic-sensor-kit",
            "<p>Public synthetic repository. Release v1.0.0. <a href=\"/demo/forge/synthetic-sensor-kit/LICENSE\">LICENSE</a></p>",
        ));
    }
    if p == "/demo/forge/synthetic-sensor-kit/LICENSE" {
        let mut r = Response::with_body(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            b"SPDX-License-Identifier: MIT\nSynthetic licence file of the demo forge.\n".to_vec(),
        );
        let _ = r.headers.try_insert("cache-control", "no-store");
        return Some(r);
    }
    None
}

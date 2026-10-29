//! The relying party, `fstp_webauthn::RelyingParty::new` (I-20, B11,
//! ADR-008 "Relying party id", design section 8.1).
//!
//! The RP id of a cell is the exact cell host, and the origin is
//! `https://<cell host>`. `new` refuses a registrable parent domain, since
//! a parent-domain RP id would let one passkey serve several tenant hosts.
//!
//! Readings used here, for the lane report:
//!
//! - Without a public suffix list, the strict reading of "registrable
//!   parent domain" refuses any host of one or two labels, such as `eu` or
//!   `fstp.eu`. A cell host always sits below a registrable domain.
//! - A host has one spelling: lower-case LDH labels, no trailing dot, no
//!   scheme, port, path, IP literal or wildcard, and A-labels for IDNs.
//!   The origin is compared as an exact string, so a second spelling of
//!   the same host would be a second relying party.
//! - `localhost`, which the SoftAuthenticator defaults to, is not decided
//!   here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::assert_refused;
use common::authn::{HOST, OTHER_CELL};
use fstp_prop::{check, prop_assert_eq};
use fstp_webauthn::RelyingParty;

/// I-20, B11, ADR-008 "Relying party id" (the name the design section
/// 14.4 and 20 checklists use): the RP id is the exact cell host and the
/// origin is its HTTPS origin. The registrable parent domains above the
/// cell host are refused, so no RP id spans two cells.
#[test]
fn i20_rp_id_is_the_exact_cell_host() {
    let rp = RelyingParty::new(HOST).expect("a cell host");
    assert_eq!(rp.parts(), (HOST, "https://c0ffee.cells.fstp.example"));
    for parent in ["fstp.example", "example"] {
        assert!(
            HOST.ends_with(&format!(".{parent}")),
            "fixture: {parent} is a parent of {HOST}"
        );
        assert_refused(parent, &RelyingParty::new(parent));
    }
}

/// I-20: two cells have two relying parties, and neither is a parent of
/// the other.
#[test]
fn i20_relying_parties_of_two_cells_differ() {
    let a = RelyingParty::new(HOST).expect("cell A");
    let b = RelyingParty::new(OTHER_CELL).expect("cell B");
    assert_ne!(a, b);
    assert_ne!(a.parts().0, b.parts().0);
}

/// I-20, ADR-008: a registrable domain or a bare public suffix is
/// refused as an RP id, so no passkey can span the cells below it.
#[test]
fn i20_relying_party_refuses_a_registrable_parent_domain() {
    for host in [
        "eu",
        "com",
        "example",
        "fstp.eu",
        "fstp.example",
        "example.com",
    ] {
        assert_refused(host, &RelyingParty::new(host));
    }
}

/// I-20, ADR-008: anything that is not a bare host name in its one
/// spelling is refused.
#[test]
fn i20_relying_party_refuses_a_host_in_another_spelling() {
    let cases = [
        String::new(),
        format!("https://{HOST}"),
        format!("{HOST}:443"),
        format!("{HOST}/"),
        format!("{HOST}."),
        format!(" {HOST}"),
        format!("{HOST}\n"),
        HOST.to_uppercase(),
        "C0ffee.cells.fstp.example".to_owned(),
        "c0ffee..fstp.example".to_owned(),
        "-c0ffee.cells.fstp.example".to_owned(),
        "c0ffee-.cells.fstp.example".to_owned(),
        "c0_ffee.cells.fstp.example".to_owned(),
        "*.cells.fstp.example".to_owned(),
        "192.0.2.1".to_owned(),
        "[2001:db8::1]".to_owned(),
        "caf\u{e9}.cells.fstp.example".to_owned(),
        format!("{}.cells.fstp.example", "a".repeat(64)),
        format!("user@{HOST}"),
    ];
    for host in cases {
        assert_refused(&format!("{host:?}"), &RelyingParty::new(&host));
    }
}

/// I-20: an IDN host in its A-label form is a host like any other.
#[test]
fn i20_relying_party_accepts_an_a_label_host() {
    let host = "xn--caf-dma.cells.fstp.example";
    let rp = RelyingParty::new(host).expect("an A-label host");
    assert_eq!(rp.parts(), (host, "https://xn--caf-dma.cells.fstp.example"));
}

/// I-20: every generated host of three to five lower-case LDH labels is
/// accepted, with the origin `https://<host>`.
#[test]
fn i20_relying_party_accepts_generated_cell_hosts() {
    check("i20_relying_party_accepts_generated_cell_hosts", |g| {
        let labels = g.usize_in(3..=5);
        let host: Vec<String> = (0..labels)
            .map(|_| {
                let len = g.usize_in(1..=12);
                let mut s: String = (0..len)
                    .map(|_| char::from(*g.pick(b"abcdefghijklmnopqrstuvwxyz0123456789-")))
                    .collect();
                // A label neither starts nor ends with a hyphen.
                s.replace_range(0..1, "a");
                if s.ends_with('-') {
                    s.pop();
                    s.push('z');
                }
                s
            })
            .collect();
        let host = host.join(".");
        g.note("host", &host);
        match RelyingParty::new(&host) {
            Ok(rp) => {
                let origin = format!("https://{host}");
                prop_assert_eq!(rp.parts(), (host.as_str(), origin.as_str()));
                Ok(())
            }
            Err(e) => Err(format!("refused {host:?}: {e:?}")),
        }
    });
}

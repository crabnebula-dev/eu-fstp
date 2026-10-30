//! TH-26, H-05, design section 15, ADR-011, R-NF-01: the control plane's API
//! decoder and the self-hosted install configuration decoder.
//!
//! Every in-house parser answers every input with a value or a typed
//! refusal. These tests also pin what an accepted install configuration
//! may hold: its host is a lowercase LDH host name, and so is `id.<host>`.
//! The install configures edge routes for both (design section 9.5 step
//! 7), so a host whose vault origin name is not a host name cannot be
//! routed.
//!
//! Gap, recorded for lane W2h: `CpApiRequest` holds only a `u16` operation
//! and `InstallConfig` only a host. The design names neither format, so
//! these tests cannot build a valid input and check only totality,
//! refusals and the host rule.
//!
//! Lane W2h test author. Red until lane W2h writes both decoders: each is
//! a W0 stub that refuses with `ControlError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{is_ldh_host, is_stub, refused};
use fstp_control::api::decode_cp_api;
use fstp_control::install::decode_install_config;
use fstp_prop::{Gen, prop_assert};

/// Inputs for a decoder: arbitrary bytes and printable text.
fn input(g: &mut Gen) -> Vec<u8> {
    if g.bool() {
        g.bytes(0..=512)
    } else {
        g.ascii_string(0..=256).into_bytes()
    }
}

/// TH-26, design section 15 (`cp_api_decode`): the API decoder answers
/// every input with a request or a refusal, never a stub error.
#[test]
fn th_26_cp_api_decoder_answers_every_input() {
    fstp_prop::check(
        "th_26_cp_api_decoder_answers_every_input",
        |g: &mut Gen| match decode_cp_api(&input(g)) {
            Err(e) if is_stub(&e) => Err(format!("{e}")),
            _ => Ok(()),
        },
    );
}

/// TH-26: empty input and free text are no API request.
#[test]
fn th_26_cp_api_decoder_refuses_empty_and_free_text() {
    let cases: [&[u8]; 4] = [b"", b"\0", b"provision-cell", b"{\"org\":\"Acme GmbH\"}"];
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|b| refused(&String::from_utf8_lossy(b), decode_cp_api(b)).err())
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// TH-26, R-NF-01, design sections 9.5 and 15 (`install_config_decode`):
/// the install configuration decoder answers every input, and an accepted
/// configuration names a host that is a lowercase LDH name, with `id.`
/// before it one too.
#[test]
fn th_26_install_config_decoder_answers_every_input_with_a_routable_host() {
    fstp_prop::check(
        "th_26_install_config_decoder_answers_every_input_with_a_routable_host",
        |g: &mut Gen| match decode_install_config(&input(g)) {
            Err(e) if is_stub(&e) => Err(format!("{e}")),
            Err(_) => Ok(()),
            Ok(cfg) => {
                prop_assert!(is_ldh_host(&cfg.host), "host {:?}", cfg.host);
                prop_assert!(
                    is_ldh_host(&format!("id.{}", cfg.host)),
                    "vault origin of {:?}",
                    cfg.host
                );
                Ok(())
            }
        },
    );
}

/// TH-26: empty input and free text are no install configuration.
#[test]
fn th_26_install_config_decoder_refuses_empty_and_free_text() {
    let cases: [&[u8]; 4] = [b"", b"\0", b"host=Example.ORG", b"password=changeme"];
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|b| refused(&String::from_utf8_lossy(b), decode_install_config(b)).err())
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The host rule itself: the reference accepts LDH names and refuses the
/// forms an install configuration must never route.
#[test]
fn th_26_ldh_host_reference_refuses_unroutable_names() {
    for good in ["example.org", "fstp-1.example.org", "a.b", "x1.example"] {
        assert!(is_ldh_host(good), "{good}");
    }
    let long = format!("{}.org", vec!["a".repeat(63); 4].join("."));
    for bad in [
        "",
        "Example.org",
        "example.org.",
        ".example.org",
        "-a.example.org",
        "a-.example.org",
        "a..b",
        "a_b.example",
        "10.0.0.1",
        "exa mple.org",
        long.as_str(),
    ] {
        assert!(!is_ldh_host(bad), "{bad:?}");
    }
}

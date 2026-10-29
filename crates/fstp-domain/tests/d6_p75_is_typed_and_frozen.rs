//! I-12 and TH-62: P-75 is a typed frozen value of every policy version (M4 design section 3.4, D6).
//!
//! D6 gives P-75 ("whether reviewers' agents may read full proposal content
//! through MCP", `SPEC/02-domain/policy-parameters.md`) a typed field of
//! `FrozenValues`, so one checked guard reads it. It leaves the opaque map,
//! and the codec decodes it strictly. The guard itself is checked in the
//! testkit (`d11_every_read_has_a_rule_in_every_state.rs`).
//!
//! The policy texts start from the `policy_version_p75` seed of the
//! `policy_decode` fuzz corpus.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod codec_support;

use codec_support::{codec_for, seed_dir};
use fstp_domain::policy::{AgentContentAccess, ParamId, PolicyVersion, is_frozen_opaque};
use fstp_json::parse;

/// The text of the `policy_version_p75` seed.
fn seed_text() -> String {
    let path = seed_dir("policy_decode").join("policy_version_p75");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// D6, I-12: P-75 is typed, so it is not an opaque frozen parameter.
#[test]
fn d6_p75_is_not_opaque() {
    assert!(!is_frozen_opaque(ParamId::P75));
    assert!(
        is_frozen_opaque(ParamId::P08),
        "untyped frozen parameters stay opaque"
    );
}

/// D6, I-12: the policy codec decodes the typed P-75 values "Off" and "On",
/// and refuses another spelling and a missing member.
#[test]
fn d6_p75_codec_is_strict() {
    let codec = codec_for!(PolicyVersion);
    let text = seed_text();
    let decode = |t: &str| -> Option<PolicyVersion> {
        let v = parse(t.as_bytes()).unwrap_or_else(|e| panic!("json: {e:?}"));
        codec.decode(&v).unwrap_or_else(|e| panic!("{e}")).ok()
    };
    let off = decode(&text).unwrap_or_else(|| panic!("the P-75 seed does not decode"));
    assert_eq!(off.frozen.p75, AgentContentAccess::Off);
    let on = decode(&text.replace("\"p75\":\"Off\"", "\"p75\":\"On\""))
        .unwrap_or_else(|| panic!("P-75 \"On\" does not decode"));
    assert_eq!(on.frozen.p75, AgentContentAccess::On);
    assert!(
        decode(&text.replace("\"p75\":\"Off\"", "\"p75\":\"Allowed\"")).is_none(),
        "another spelling of P-75 decodes"
    );
    assert!(
        decode(&text.replace("\"p75\":\"Off\",", "")).is_none(),
        "a policy without P-75 decodes"
    );
}

//! The explicit rustls crypto provider (ADR-001).

use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::{self, cipher_suite, kx_group};

/// Names of the key exchange groups offered, in order of preference.
///
/// X25519MLKEM768 comes first. aws-lc-rs provides it until the moduletto
/// group replaces its ML-KEM half in M9 (ADR-001). Classical X25519 stays
/// enabled for peers without hybrid support. secp256r1 is kept for
/// PostgreSQL 16, whose default `ssl_ecdh_curve` offers only that group.
pub const KEY_EXCHANGE_GROUPS: &[&str] = &["X25519MLKEM768", "X25519", "secp256r1", "secp384r1"];

/// Names of the TLS 1.3 cipher suites offered, in order of preference.
pub const CIPHER_SUITES: &[&str] = &[
    "TLS13_AES_256_GCM_SHA384",
    "TLS13_AES_128_GCM_SHA256",
    "TLS13_CHACHA20_POLY1305_SHA256",
];

/// Builds the provider every configuration in this crate uses.
///
/// It starts from the rustls aws-lc-rs provider and lists cipher suites and
/// key exchange groups explicitly, so that a change in rustls defaults cannot
/// change what the platform offers. Only TLS 1.3 suites are listed, and the
/// rustls `tls12` feature is off.
pub(crate) fn crypto_provider() -> Arc<CryptoProvider> {
    let base = aws_lc_rs::default_provider();
    Arc::new(CryptoProvider {
        cipher_suites: vec![
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ],
        kx_groups: vec![
            kx_group::X25519MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
            kx_group::SECP384R1,
        ],
        ..base
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::group_name;

    #[test]
    fn provider_lists_match_the_documented_names() {
        let p = crypto_provider();
        let groups: Vec<&str> = p.kx_groups.iter().map(|g| group_name(g.name())).collect();
        assert_eq!(groups, KEY_EXCHANGE_GROUPS);
        let suites: Vec<&str> = p
            .cipher_suites
            .iter()
            .map(|s| s.suite().as_str().unwrap_or("unknown"))
            .collect();
        assert_eq!(suites, CIPHER_SUITES);
        assert!(
            p.cipher_suites
                .iter()
                .all(|s| s.version() == &rustls::version::TLS13),
            "TLS 1.3 only"
        );
    }
}

//! The tenant seeds of the `api_request_decode` fuzz target reach the
//! tenant decoders (TH-26, design section 9, lane m4tenant). Each seed
//! decodes through `decode_request` to the operation it names, so the
//! fuzzer starts inside each tenant body form.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use fstp_api_core::decode::decode_request;

/// TH-26: every tenant seed decodes to its tenant operation.
#[test]
fn th26_tenant_fuzz_seeds_decode_to_their_operations() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/api_request_decode");
    let want = [
        ("tenant_save_step_organisation", "tenant.save_step"),
        ("tenant_save_step_identity", "tenant.save_step"),
        ("tenant_set_mcp", "tenant.set_mcp"),
        (
            "tenant_set_session_lifetimes",
            "tenant.set_session_lifetimes",
        ),
        ("tenant_invite_admin", "tenant.invite_admin"),
        ("tenant_get_step", "tenant.get_step"),
        ("tenant_complete", "tenant.complete"),
        ("tenant_list_signatories", "tenant.list_signatories"),
        ("tenant_grant_signatory", "tenant.grant_signatory"),
        ("tenant_end_signatory", "tenant.end_signatory"),
        ("tenant_get_activation", "tenant.get_activation"),
        ("tenant_request_activation", "tenant.request_activation"),
        ("tenant_approve_activation", "tenant.approve_activation"),
    ];
    for (file, op) in want {
        let bytes = std::fs::read(dir.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let decoded = decode_request(&bytes).unwrap_or_else(|e| panic!("{file}: {e:?}"));
        assert_eq!(decoded.name(), op, "{file}");
    }
}

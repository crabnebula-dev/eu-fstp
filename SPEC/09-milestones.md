# Milestones

| ID | Content | Exit criteria |
| --- | --- | --- |
| M0 | Spec freeze for v1 | ADR-001 to ADR-005 accepted in structure |
| M1 | Foundations in Rust: HTTP, JSON, PostgreSQL wire protocol, migrations, property harness, model checker | Each component fuzzed; harnesses self-tested |
| M2 | Domain core: state machine, policy engine, SoD, scoring | I-01 to I-15, I-23 and I-34 to I-36 green at domain level (NOTE 1) |
| M3 | Cell runtime, control plane, authentication, key custody, identity vault, audit log, update and licence services | I-16 to I-20, I-24, I-38, I-39 and I-77 to I-83 green; isolation tests green; hosting provider named in ADR-005 |
| M4 | Tenant onboarding, programme creator, applicant, reviewer, committee and IRC interfaces, MCP server and public research tools | SuperSAFE programme built in the creator; end-to-end call cycle to NEGOTIATION; authorisation matrix green; I-65 to I-67, I-84 to I-87 green |
| M5 | Contracts, payment requests, payment adapters, MCP client integrations | I-30 to I-33, I-88, I-89 green; call cycle through to PAID |
| M6 | Timeline engine, dispatcher, email | I-25 to I-27 green under crash injection |
| M7 | Assessor, pre-check, evaluation harness, synthetic corpus | LLM evaluation thresholds met; I-10 and I-11 green through the assessment pipeline; I-21 green |
| M8 | Messaging adapters: Matrix and WhatsApp | I-28, I-29 green |
| M9 | moduletto ML-DSA-65 integration with ACVP and differential tests, composite signatures, desktop client, white-labelling and custom domains, export and import, profile bundles, public transparency pages, funder profiles with the Horizon Europe profile, self-hosted packaging, SBOM | I-22, I-41 to I-44, I-68 to I-71, I-90, I-91 green; self-hosted cell passes full suite |
| M10 | Hardening on a Mythos-tier model | Exit criteria in `08-hardening/hardening-plan.md` |
| M11 | Pilot: SuperSAFE as first tenant, a second programme to validate configurability | First live call completed with no invariant violations |
| M12 | Calibration with consented real proposals | Metrics reported per corpus; I-37 green |

NOTE 1: M2 scope, decided 2026-10-25.

- I-10 and I-11 are claimed for the domain core with a fake assessor. M7 claims them again through the assessment pipeline.
- I-13 to I-15 are claimed against a synthetic identity vault. The identity vault itself is built in M3.
- I-23 is claimed by prevention, a verifier and replay. The tamper-evident audit log (I-24) is M3.
- I-34 to I-36 join the M2 exit because no other milestone claimed them.

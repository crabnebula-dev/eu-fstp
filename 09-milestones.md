# Milestones

| ID | Content | Exit criteria |
| --- | --- | --- |
| M0 | Spec freeze for v1 | ADR-001 to ADR-005 accepted in structure |
| M1 | Foundations in Rust: HTTP, JSON, PostgreSQL wire protocol, migrations, property harness, model checker | Each component fuzzed; harnesses self-tested |
| M2 | Domain core: state machine, policy engine, SoD, scoring | I-01 to I-15 and I-23 green |
| M3 | Cell runtime, control plane, authentication, key custody, identity vault, audit log, update and licence services | I-16 to I-20, I-24, I-38, I-39 and I-77 to I-83 green; isolation tests green; hosting provider named in ADR-005 |
| M4 | Tenant onboarding, programme creator, applicant, reviewer, committee and IRC interfaces, MCP server and public research tools | SuperSAFE programme built in the creator; end-to-end call cycle to NEGOTIATION; authorisation matrix green; I-65 to I-67, I-84 to I-87 green |
| M5 | Contracts, payment requests, payment adapters, MCP client integrations | I-30 to I-33, I-88, I-89 green; call cycle through to PAID |
| M6 | Timeline engine, dispatcher, email | I-25 to I-27 green under crash injection |
| M7 | Assessor, pre-check, evaluation harness, synthetic corpus | LLM evaluation thresholds met; I-10, I-11, I-21 green |
| M8 | Messaging adapters: Matrix and WhatsApp | I-28, I-29 green |
| M9 | moduletto ML-DSA-65 integration with ACVP and differential tests, composite signatures, desktop client, white-labelling and custom domains, export and import, profile bundles, public transparency pages, funder profiles with the Horizon Europe profile, self-hosted packaging, SBOM | I-22, I-41 to I-44, I-68 to I-71, I-90, I-91 green; self-hosted cell passes full suite |
| M10 | Hardening on a Mythos-tier model | Exit criteria in `08-hardening/hardening-plan.md` |
| M11 | Pilot: SuperSAFE as first tenant, a second programme to validate configurability | First live call completed with no invariant violations |
| M12 | Calibration with consented real proposals | Metrics reported per corpus; I-37 green |

# Milestones

| ID | Content | Exit criteria |
| --- | --- | --- |
| M0 | Spec freeze for v1 | ADR-001 to ADR-005 accepted in structure |
| M1 | Foundations in Rust: HTTP, JSON, PostgreSQL wire protocol, migrations, property harness, model checker | Each component fuzzed; harnesses self-tested |
| M2 | Domain core: state machine, policy engine, SoD, scoring | I-01 to I-15, I-23 and I-34 to I-36 green at domain level (NOTE 1) |
| M3 | Cell runtime, control plane, authentication, key custody, identity vault, audit log, update and licence services | I-16 to I-20, I-24, I-38, I-39 and I-77 to I-83 green; isolation tests green; hosting provider named in ADR-005 (NOTE 2) |
| M4 | Tenant onboarding, programme creator, applicant, reviewer, committee and IRC interfaces, MCP server and public research tools | SuperSAFE programme built in the creator; end-to-end call cycle to NEGOTIATION; authorisation matrix green; I-65 to I-67, I-84 to I-87 green |
| M5 | Contracts, payment requests, payment adapters, MCP client integrations | I-30 to I-33, I-88, I-89 green; call cycle through to PAID |
| M6 | Timeline engine, dispatcher, email | I-25 to I-27 green under crash injection |
| M7 | Assessor, pre-check, evaluation harness, synthetic corpus | LLM evaluation thresholds met; I-10 and I-11 green through the assessment pipeline; I-21 green |
| M8 | Messaging adapter: Matrix (WhatsApp deferred by Daniel on 2026-11-04 (B-03)) | I-28, I-29 green |
| M9 | moduletto ML-DSA-65 integration with ACVP and differential tests, composite signatures, white-labelling and custom domains, export and import, profile bundles, public transparency pages, funder profiles with the Horizon Europe profile, self-hosted packaging, SBOM | I-22, I-41 to I-44, I-68 to I-71, I-90, I-91 green; self-hosted cell passes full suite |
| M10 | Hardening on a Mythos-tier model | Exit criteria in `08-hardening/hardening-plan.md` |
| M11 | Pilot: SuperSAFE as first tenant, a second programme to validate configurability | First live call completed with no invariant violations |
| M12 | Calibration with consented real proposals | Metrics reported per corpus; I-37 green |

NOTE 1: M2 scope, decided 2026-10-25.

- I-10 and I-11 are claimed for the domain core with a fake assessor. M7 claims them again through the assessment pipeline.
- I-13 to I-15 are claimed against a synthetic identity vault. The identity vault itself is built in M3.
- I-23 is claimed by prevention, a verifier and replay. The tamper-evident audit log (I-24) is M3.
- I-34 to I-36 join the M2 exit because no other milestone claimed them.

NOTE 2: M3 scope, decided 2026-10-28. These items are claimed in part. Where a later milestone is named, it reruns the same tests.

- I-39 is claimed with the call cycle as far as M3 builds it. The test-plan row also needs payment and export, so M5 reruns it with payment and M9 with export.
- I-16 is claimed statically and structurally. Payment adapters arrive in M5, which reruns the I-16 tests over them.
- I-18 is claimed over the vault core, and over the real vault with facts seeded by test-only tooling. The claim through production verifications follows once a verification method records real facts (R-ID-04, `02-domain/roles-and-sod.md` Manual identity checks). The platform operator verifies each tenant's first tenant admin, who then records the checks of others (decided 2026-10-28, `02-domain/roles-and-sod.md`). Under the release-window interim of ADR-008, which still awaits Daniel, no production proposal passes IRC_REVIEW to NEGOTIATION in M3.
- I-24 is claimed with composite anchors, whose ML-DSA-65 half comes from moduletto. moduletto has no ML-DSA-65 yet. It is added on a moduletto pull request that Claude writes and Daniel reviews and merges (decided 2026-10-28, ADR-001 A2). Until it lands, composite signing refuses with a typed error, so no production anchor is signed and production writes are refused. Nothing falls back to Ed25519 alone or to aws-lc-rs ML-DSA in production. The I-24 tests meanwhile use the aws-lc-rs ML-DSA test oracle, and the exit report states which implementation they ran against. Witness receipts, staff assertions and operator tickets depend on the same pull request.
- I-82 is claimed under the reading of Q4 A (decided 2026-10-28). It covers every role that can log in from another host, applied to the self-operated clusters. The managed control-plane cluster holds no cell data. The cluster superuser and the replication role log in only over loopback on the database host (ADR-005). The I-82 text in `02-domain/invariants.md` is unchanged.
- I-81 is claimed for file custody under the scope "the key volume is excluded from host backups and snapshots" (ADR-004, decided 2026-10-28).
- R-KY-01 is claimed for the EU-operated KMS option only. The CrabNebula-operated HSM is not built in M3.
- R-HS-01 is claimed only after the L-15 hosting due diligence (`10-open-questions.md`). This item awaits Daniel's confirmation: the summary he answered listed only I-39, I-16, I-18 and R-KY-01.

The M3 exit report also states each scoped claim that rests on an interim reading or an open verify item, with its basis. These include R-NF-09 for internal links only (ADR-009, interim) and I-80 for OKMS-held root epochs (ADR-004 verify item K7).

NOTE: On 2026-11-04 Daniel deferred the desktop client (B-04) and WhatsApp (B-03) for now. M8 builds the Matrix adapter only, and M9 builds no desktop client. Both keep their design and reserved identifiers in `11-backlog.md`.

# M4 design: onboarding, programme creator, role interfaces, MCP server and public tools (final)

Milestone M4 in `SPEC/09-milestones.md`: "Tenant onboarding, programme creator, applicant, reviewer, committee and IRC interfaces, MCP server and public research tools". Exit criteria:

- the SuperSAFE programme is built in the creator;
- an end-to-end call cycle runs to NEGOTIATION;
- the authorisation matrix is green;
- I-65 to I-67 and I-84 to I-87 are green.

Status: final design for Daniel's review, revision 2. Revision 2 closes the completeness critique (section 0.5). No repository file was changed while writing it. Every repository change named here is staged by the implementing agent with a proposed commit message. Daniel creates, signs and pushes each commit.

ADR-013 and ADR-014 are new ADRs this design proposes (section 10). They do not exist yet.

Labels such as `Q4`, `W3`, `D2`, `L-DOM`, `J4`, `TW-3` and `M-ACTIVATE` exist only in this document. They are not spec identifiers. In particular, lane labels such as `L-DOM` are not the `L-` legal checks of `SPEC/10-open-questions.md`. Every `I-`, `R-`, `P-`, `SoD-`, `TH-`, `T-`, `H-`, `O-`, `L-` and `ADR-` identifier is quoted from the repository. Crate, type, table, route and test names are design proposals.

Sources re-read for this final version:

- `.claude/CLAUDE.md`, `SPEC/README.md`, `SPEC/00-scope.md`, `SPEC/09-milestones.md`, `SPEC/10-open-questions.md`, `SPEC/11-backlog.md`.
- `SPEC/02-domain/`: `invariants.md`, `programme-creator.md`, `guide-for-applicants.md`, `public-transparency.md`, `roles-and-sod.md`, `policy-parameters.md`, `state-machine.md`, `contracts.md`.
- `SPEC/01-requirements/functional.md` and `non-functional.md`, in full.
- `SPEC/03-architecture/`: `overview.md`, `authentication.md`, `mcp-server.md`, `mcp-client.md`, `white-labelling.md`, `desktop-client.md`.
- `SPEC/04-llm-assessment/assessment.md`, `SPEC/06-threat-model/threat-model.md`, `SPEC/07-test-plan/test-plan.md`, `SPEC/08-hardening/hardening-plan.md`, `SPEC/schemas/README.md`, `SPEC/profiles/horizon-europe/guide-for-applicants.md`.
- `docs/adr/ADR-001` to `ADR-007`, `docs/handoff/HANDOFF.md`, `docs/handoff/m2-design.md` (all sections, with sections 4 and 5 for the M3 seams) and `docs/handoff/m2-exit-audit.md`.
- Code on branch `m2-domain-core` at `44b2b0e`: `fstp-domain/src/{command,rules,engine,visibility,oracle,refusal,decision,programme}.rs`, `policy/mod.rs`, `roles/mod.rs`; `fstp-engine/src/{lib,driver}.rs`; the testkit's use of `CreateProgramme`; `fstp-rt/src/runtime.rs`; the `fstp-http` router, handler and server; `fstp-crypto`; `fstp-json` canonical encoding and `json_struct!`; `fstp-money` JSON codecs; `tools/deps-check/src/layering.rs`.
- OVHcloud public documentation, fetched on 2026-10-28 (section 7 lists each source).
- Re-read for revision 2: `SPEC/05-compliance/ai-act.md` and `dsa.md`; `SPEC/schemas/README.md`; `fstp-domain/src/{record,visibility,grant}.rs` and `rules.rs` `CATALOGUE`; `fstp-findings/src/record.rs`; `fstp-engine/Cargo.toml`; `fstp-domain-testkit/src/scenario.rs` and every file that issues `CreateProgramme`; `docs/adr/ADR-001` Uses table and `ADR-004` key levels.

---

## 0. Approach

### 0.1 Base and grafts

The base is the programme-first proposal (proposal 3). It had the highest totals from both judges (40 and 41). It treats a programme as a typed document with a deterministic compile step. A draft is a real M2 programme, so authorship, the R-PC-03 drafter set and I-23 history come from M2 unchanged. Import proposals live in a store that the creator and the domain cannot name, which is the I-10 pattern applied to I-65.

Grafted from the journeys-first proposal (proposal 1):

- Journeys J0 to J9 with a synthetic cast that covers the edges (section 2). Each step names a screen, an operation, the domain command and a route, so requirement coverage can be audited row by row.
- An engine-level single path for activation. The engine refuses a core activation command that arrives from outside, and its fold refuses a `ProgrammeActivated` record without an `ActivationApproved` creator record in the same entry. No test-mode flag exists.
- Ballots cast by each committee member (change D5). M2's `RecordCutOff` takes every `Ballot` from one recorder.
- `McpSafe` required by MCP response construction, with compile-fail twins for each sensitive type.
- A byte-identical page property: equal `PublicView` values give equal page bytes.
- `script-src 'none'` and no `Set-Cookie` on public pages.
- A magic-link session holding a management role, and a stale step-up, as matrix profiles.
- Pending import proposals count as a validation failure.
- A fuzz target for the TypeScript source scanner.
- A synthetic legal-wording profile that only the end-to-end cell loads.

Grafted from the authorisation-first proposal (proposal 2):

- One pure, total function, `channel_policy`, is the only place where the web and MCP channels differ. I-84 parity becomes "MCP outcome equals `channel_policy` applied to the web outcome", which is the test in `SPEC/07-test-plan/test-plan.md` for I-84.
- Before an MCP call becomes a pending action, the engine dry-runs it with web semantics. An agent can prepare only what its user could do.
- Step-up proofs are bound to an RFC 8785 action digest and consumed on use. A confirmation replays the stored canonical arguments, never arguments resent by the browser.
- A bypass twin that calls the engine with `Via::Mcp` directly, so the domain's own I-85 refusal is tested alone.
- The M-PREP and M-PUBLIC models, the render-trace test for I-87, the application database dump test for I-86 and a stratified PostgreSQL sample of the matrix.
- `VaultBound<T>` for facts that only the vault may receive.
- Proposed web and OAuth threats TW-1 to TW-9 for the threat model.
- The ingress question for OVHcloud: TLS pass-through at the load balancer (R-NF-09).

### 0.2 Fixes applied to the proposals

These are the flaws the judges found, with the fix. Section 12.4 lists the factual corrections with sources.

1. **I-84 structure.** In proposal 3 the MCP crate could name engine commands through its dependencies. Here the adapters `fstp-web` and `fstp-mcp` have a fixed allowlist of direct dependencies, which excludes every domain and engine crate. A Rust crate can name only its direct dependencies. A scan of the public API of `fstp-api-core` refuses any re-export of engine or domain command types (layering rule A2).
2. **Single-recorder ballots.** M2's `RecordCutOff` lets one member's session state every other member's vote (`decision.rs`, `Ballot`). Change D5 adds `OpenCutOffRound`, `CastBallot` and `DelegateVote`. `RecordCutOff` then counts only ballots that each voter cast (Q4).
3. **Witness cycle for I-66 and I-67.** Proposal 3 built a domain record from a creator witness, which is a dependency cycle. Here `ActivationApproved` is a creator record built only from `&ActivationClearance` inside `fstp-creator`. The domain's `ProgrammeActivated` carries no witness. The engine supplies the single path: it refuses the core command from outside, composes it only from an approved creator decision, and its fold refuses an unpaired record (section 3.4, D2).
4. **Roles and scopes.** `Role::ALL` has 14 roles, not 15. M4 issues only scopes it has operations for. Scopes for M5 and later are reserved names, never issued.
5. **No extraction binary in M4.** M4 imports UTF-8 `text/plain` and `text/markdown` only. Both are validated and normalised in process by a fuzzed decoder. Sandboxed extraction of PDF and other formats arrives with M7, where `SPEC/03-architecture/overview.md` places "PDF and document text extraction, sandboxed, fuzzed".
6. **SSE.** The MCP transport answers with `application/json` only. Tests scan response bodies; no SSE frame exists.
7. **Domain change scope.** The domain changes are listed once (section 3.4), each with its tests and tripwire re-measurement. M2 tripwires are measured again and reported, never relaxed.
8. **Import resolution strength.** An unresolved import proposal is a validation failure, not a warning.
9. **Pre-declaration summary.** Proposal 3 recommended title only, which departs from `roles-and-sod.md` ("title and a neutral summary"). This design shows both. The applicant writes the neutral summary in a length-limited field (Q9).
10. **Fuzzing the source scanner.** `tools/deps-check/src/web_scan.rs` gets the `ts_token_scan` target.
11. **Horizon Europe overlap.** M9 owns "funder profiles with the Horizon Europe profile". M4 ships only what SuperSAFE needs: the Guide template, parameter bounds and the flow-down obligation list as identifiers. The overlap is raised as Q18.
12. **Matrix cost.** The matrix size and CI time are estimated and sharded (section 8.3).
13. **Public rate-limit key.** Keying on an IP prefix while R-NF-02 is open on IP addresses is raised as Q19.
14. **Step-up before refusal.** Proposal 2 could ask for a step-up before refusing an unauthorised high-risk call. Here a dry run decides first, so an unauthorised caller gets the refusal and no step-up prompt.
15. **Per-grant step-up.** Proposal 1 batched role grants into activation under one step-up. Here the activation batch holds no grants. Each `GrantRole` is its own high-risk operation with its own step-up.
16. **Gate admission claims.** Proposal 2 treated `admits_actor_kind` as the domain's actor rule. It checks only the actor kind (`engine.rs`: "Rules that need state admit every account here"). This design never relies on it. Commands are decided by `decide` and dry-run `decide` only.
17. **Activation path coverage.** Proposal 2's coverage test forced every `CommandKind` onto a route or a system-only list. Here a third list, `COMPOSED_ONLY`, holds `ActivateProgramme`, and a test checks that no route or tool reaches it.
18. **OVHcloud facts.** Each product statement in section 7 names the page it comes from and the date it was read. Unconfirmed facts are marked as such.

### 0.3 Where each exit item is held

| Exit item | Structure | Single checked constructor or guard | Tests (section 8) |
| --- | --- | --- | --- |
| SuperSAFE built in the creator | `ProgrammeSpec` fixture checked against the SuperSAFE column of `policy-parameters.md`; built step by step through the API and the browser | `fstp_programme::compile`, deterministic | Fixture test, API walk, Playwright build |
| Call cycle to NEGOTIATION | Journeys J0 to J8 through `dispatch` and through the browser | The M2 engine | Rust journey test, Playwright cycle |
| Authorisation matrix | One registry of operations; reads through `READ_RULES`; commands through `decide` | `fstp_api_core::dispatch` | Matrix in three channels, two-way, teeth |
| I-65 | `fstp-domain`, `fstp-programme` and `fstp-creator` have no dependency path to `fstp-import` | `bridge::resolve_import` in `fstp-engine`: active programme manager binding, unresolved proposal, matching `shown` digest | Layering gate, twin machine, M-IMPORT, teeth, Playwright |
| I-66 | `ActivationApproved` built only from `&ActivationClearance`, which holds a `CleanReport` bound to the draft revision; engine fold pairing | `fstp_creator::clean`, with probes run in the approval request | Seeded-failure property, R-PG-01 AC test, M-ACTIVATE, fold test, compile-fail twins, teeth |
| I-67 | Builder set folded from records; the approver is checked twice, in the creator and in the core guard | `clear_activation` and the `ActivateProgramme` core guard, with `IsVerified` for the approver and every builder, then `SameIdentityAsAny` (Q2) | Machine, M-ACTIVATE, mutant-creator test, unverified-builder test, teeth, Playwright |
| I-84 | Adapters cannot name engine, domain, access or port types (rules A1, A2, A2b); one opaque `ApiCore` with one `dispatch`; one `channel_policy`; one tool table, inside `OPS` | `ApiCore::dispatch`, `Principal` constructors in `fstp-access`, and `channel_policy` | Matrix parity, M-PARITY, audit parity, layering gate, teeth |
| I-85 | `channel_policy` returns `Prepare` for every high-risk operation that has a tool; prepare-only tools exist for the high-risk operations of the capability table (Q32); the domain refuses `high_risk()` with `Via::Mcp` (existing `RuleRef::I85`) | `PendingAction::confirm`: web only, same account, digest match, fresh step-up | M-PREP, matrix slice, bypass twin, teeth, Playwright |
| I-86 | `fstp-mcp` and `fstp-api-core` have no path to the M3 vault client; MCP output needs `McpSafe` | `McpResponse::new<T: McpSafe>` | Layering gate, compile-fail twins, canary crawl, teeth |
| I-87 | Pages, feed and public tools take only `&PublicView` | `fstp_public::public_view`, the only constructor and the only filter | Equality property, render trace, canary leaf coverage, M-PUBLIC, two-cell test, teeth |

### 0.4 What M4 builds and what it leaves

| In M4 | Left to |
| --- | --- |
| JSON API and in-house TypeScript application for every role up to NEGOTIATION, plus the two decline rows (O-49) | Amount determination, grant acceptance, contracts and payments: M5 |
| Server-rendered public pages for programmes, open calls and the Guide; the public feed; public MCP tools | Proposed, pending your answer: Guide PDF (R-GA-02) to M5 (Q28). Grantee opt-in records (R-PB-02): M9. Corrigendum notification dispatch (I-53): M6, with corrigendum generation per Q37 |
| Programme creator: blank, clone, shipped template, tenant-private template, text import with a deterministic proposer | Inference-backed proposer and PDF extraction: M7. Proposed, pending your answer: cross-tenant template library (I-73) to M9 (Q17) |
| Tenant onboarding in the control plane (`fstp-signup`, with operator review of the tenant's identity) and the cell | Custom domains (I-71) and white-label packages (I-68 to I-70 as claims): M9 |
| MCP server over Streamable HTTP with OAuth 2.1 and PKCE; public research tools; prepare-only tools for high-risk actions (Q32) | MCP client (I-88, I-89) and P-78 settings: M5. Proposed, pending your answer: platform-wide directory (P-76) to M9 (Q17) |
| A minimal deadline sweep that issues `ExpireStage2` and `ReEnter` from the cell clock (R-EV-07, D13) | The timeline engine replaces the sweep: M6 |
| Authorisation matrix over every M4 operation in three channels | Operations from M5 on join the same registry and matrix |
| Default platform theme with mandatory footer elements and platform attribution (P-68) | Tenant branding: M9 |
| In-app notice list read from outbox records | Email, Matrix and WhatsApp dispatch: M6 and M8 |

### 0.5 Changes after the completeness critique

The numbers are the critique's. Section 12.5 records each point rejected in part, with the reason.

1. **Layering.** `fstp-public` now depends on `fstp-domain` and takes the core `State`, so A4 holds. `fstp-access` depends on `fstp-engine` for `EngineState` (section 1.1, rule A4).
2. **I-84 structure.** `OPS` is the only tool table. `McpSafe` and the read models live in `fstp-api-core`. `Principal` has private fields and checked constructors, and it carries the caller's roles. Adapters get an opaque `ApiCore` and cannot name ports (rule A2b).
3. **I-85.** Prepare-only tools exist for the high-risk operations in the capability table (Q32). The I-85 tests exercise them.
4. **Live SoD check.** `preview_grant` evaluates the SoD guards without the Draft gate. A property shows it equals `GrantRole` on an activated copy (D3).
5. **D6.** The applicant team is exempt from the P-75 guard.
6. **High-risk settings.** Tenant admin invitations and every tenant setting change are high-risk. P-73 and P-78 cannot be set in M4.
7. **Sybil check.** `IsVerified` must hold for the approver and every builder. Tenant admins verify their identity at onboarding.
8. **Dry-run vault answers** are recorded as a query digest and the answer bit (NOTE 5), and rate-limited.
9. **Minor flag.** Q23 becomes blocking, with options.
10. **New vault queries.** Q35 is a blocking question.
11. **Parameter coverage.** Every programme-level `CATALOGUE` entry has one field. P-18, P-21 and P-45 are programme fields, prefilled from tenant defaults.
12. **M2 gaps.** D9 fills per-criterion weighted scores. D10 totals the effective plan. D11 states a read rule for every state.
13. **Work plan.** The activation helper changes owner in sequence. The D8 file list is complete. `Scenario::programme()` was a wrong name.
14. **Lane ownership.** W0 runs alone first. Every shared file has an owner, and the missing dependencies are added.
15. **Control plane.** New crate `fstp-signup` and lane W2f, with a fuzzed form decoder.
16. **Registry.** `OpKind` gains `Finding` and `Import`.
17. **moduletto.** Workspace drafts are sealed through an M3 `Sealer` port that wraps keys with hybrid X25519 plus ML-KEM-768. I-74 and I-75 apply to the cell.
18. **P-05 and P-13.** Guide resolvers read the publication snapshot. Live tightening after publication is Q37, blocking.
19. **Q12** is built: publication recomputes the report.
20. **Threats.** TH-04, TH-18, TH-27, TH-46, TH-49 and TH-57 are mapped (section 5.1).
21. **Requirements.** Each listed requirement is mapped to an operation or a seam (section 14).
22. **Coverage claims** for R-TN-01, R-PG-02 and R-SB-03 are now partial.
23. **I-77 and I-78 seams.** M3 requirements 10 and 11 cover weak sessions at grant and strong-method enrolment. J1 now verifies M1 before the grant.
24. **`PublishCall` configuration.** The tenant's inference record supplies `LlmConfigId` and the model (section 3.5).
25. **Pre-check in the Guide.** Q38, blocking.
26. **Decisions that belong to you.** Q17, Q28 and Q31 become blocking. Export of workspace drafts is Q40. Onboarding data gets a proposed export file.
27. **TypeScript parsers.** Q33, blocking, with an in-house fuzz harness as the interim. New Rust targets cover Guide Markdown and HTML well-formedness.
28. **Contrast.** An integer method with bounded lookup tables (section 3.2).
29. **Matrix cost.** A revised estimate with every dimension. Q34, blocking.
30. **OVHcloud.** Object storage and load balancer rows are now checked. The Aiven question is raised for L-15.
31. **Desktop client.** A seam for M9 (section 6.3).
32. **Compliance seams.** AI Act and DSA seams, terms stating P-75 and P-77, `TODO(legal)` markers, and funder visibility elements.
33. **Synthetic wording** lives in `fstp-api-testkit`. A9b keeps it out of production.
34. **R-AU-01.** Applicant reads append `ContentRead` too.
35. **MCP `Origin` and `serverInfo`.** A missing `Origin` is allowed and a foreign one refused. The server name is a checked domain label.

---

## 1. Crates, binaries and layering

### 1.1 New in-house crates

No third-party Rust crate is added. The npm and Node.js questions are in section 10.

| Crate | Kind | Responsibility | In-house dependencies | Fuzz project |
| --- | --- | --- | --- | --- |
| `fstp-programme` | lib, pure | `ProgrammeSpec`, `FieldId`, the `FIELDS` table, `compile` and `decompile`, shipped templates, the SuperSAFE fixture, R-PG-04 `impact` | `fstp-domain`, `fstp-money`, `fstp-json` | `spec_decode`, `spec_compile`, `field_value_decode` |
| `fstp-creator` | lib, pure | Draft records and commands, provenance, invitations, probes, acknowledgements, `ValidationReport`, `CleanReport`, `ActivationClearance`, `ActivationApproved` | `fstp-programme`, `fstp-guide`, `fstp-domain`, `fstp-ledger`, `fstp-money`, `fstp-json` | `creator_command_decode`, `creator_record_decode`, `validate_total` |
| `fstp-import` | lib, pure | `ImportDocument` metadata, `ImportProposal`, `UntrustedValue`, the `Proposer` trait, `ImportStore`, import records, the text normaliser | `fstp-programme` (for `FieldId` and field schemas only), `fstp-ledger`, `fstp-json`, `fstp-findings` (for `UntrustedText` only) | `import_text_decode`, `proposal_decode`, `import_record_decode` |
| `fstp-html` | lib, pure | Escaping HTML writer with no raw-insertion API; message catalogues for server-rendered text (R-NF-04); `Label` and `ApprovedText` kinds (I-72 seam); a test sink that records every dynamic text node; the well-formedness checker used by tests and fuzz targets | `fstp-json` | `message_format_parse`, `accept_language_parse`, `html_wellformed_check` |
| `fstp-guide` | lib, pure | Guide template parser for `{{...}}` placeholders and the Markdown subset the template uses, binding to the draft or frozen policy, section completeness, legal-wording status, HTML rendering, content digest; `ShippedProfiles`, the only production profile source | `fstp-domain`, `fstp-programme`, `fstp-html` | `guide_template_parse`, `guide_markdown_parse`, `guide_render` |
| `fstp-public` | lib, pure | `PublicView`, `public_view`, the page renderer, the feed and public tool encoder | `fstp-domain` (the core `State` only), `fstp-programme`, `fstp-guide`, `fstp-html`, `fstp-json`. No path to `fstp-engine` or `fstp-findings` (rule A4) | `public_query_parse` |
| `fstp-tenant` | lib, pure | Onboarding steps, tenant-level settings (P-20, P-69 to P-72, P-74) as ledger records, tenant defaults that prefill the programme fields for P-18, P-21 and P-45, the tenant admin set (Q31), and the inference configuration record (section 3.5). P-73 and P-78 are not settable in M4. Merges into M3 tenant configuration if M3 defines one (section 6.1) | `fstp-domain`, `fstp-ledger`, `fstp-json` | `tenant_command_decode`, `tenant_record_decode` |
| `fstp-access` | lib, pure | `Principal` with private fields and checked constructors, `OpKind`, `OpSpec`, the `OPS` registry with every `ToolDef` (the only tool table), `ReadKind`, `READ_RULES`, `Scope`, `Classification`, `channel_policy`, `authorize_read`, `SYSTEM_ONLY`, `COMPOSED_ONLY`, `LATER` | `fstp-domain`, `fstp-engine` (for `EngineState`), `fstp-creator`, `fstp-import` (kinds only), `fstp-tenant` | none: no parser |
| `fstp-api-core` | lib | `ApiCore`, an opaque handle with `dispatch`; request decoders per operation; identity-free read models and the `McpSafe` marker they implement; `PendingAction`; step-up binding; rate limits; the `ids` module that re-exports id types only; the `meta` module that re-exports `ToolDef`, `Scope` and `Classification` and offers `tools()` over `OPS` | `fstp-access`, `fstp-engine`, `fstp-creator`, `fstp-import`, `fstp-public`, `fstp-guide`, `fstp-tenant`, `fstp-json`, `fstp-money`, `fstp-crypto`, `fstp-rt` | `api_request_decode`, `query_params_decode`, `cursor_decode`, `pending_request_decode` |
| `fstp-oauth` | lib, sans-IO | OAuth 2.1 authorisation server: RFC 8414 and RFC 9728 metadata, RFC 7591 registration, authorise with PKCE S256, token and refresh rotation, RFC 7009 revocation, RFC 8707 resource binding, strict URL parser, form decoder | `fstp-json`, `fstp-crypto` | `url_parse`, `form_urlencoded_decode`, `authorize_query_decode`, `token_request_decode`, `client_metadata_decode`, `bearer_header_parse`, `base64url_decode` |
| `fstp-mcp` | lib, sans-IO core | JSON-RPC 2.0, MCP lifecycle, Streamable HTTP rules, Origin check, serving the tool table from `fstp_api_core::meta::tools()`, response classification | `fstp-api-core`, `fstp-oauth`, `fstp-http`, `fstp-json` | `jsonrpc_decode`, `mcp_message_decode`, `tool_args_decode`, `mcp_headers_decode`, `mcp_http_post` |
| `fstp-signup` | lib, sans-IO | Control plane onboarding: the server-rendered sign-up and agreement forms, their strict form decoder, control plane records for sign-up, agreement acceptance and the operator review of the tenant's identity (TH-46), and the client side of the `Provisioner` port | `fstp-html`, `fstp-json`, `fstp-crypto`, `fstp-ledger` | `signup_form_decode`, `cp_record_decode` |
| `fstp-web` | lib | Routes over `fstp_http::Router` for `/api/v1`, `/app`, `/p`, `/mcp`, `/mcp/public`, `/oauth` and `/.well-known`; CSRF and Origin rules; security headers; body limits | `fstp-api-core`, `fstp-mcp`, `fstp-oauth`, `fstp-web-assets`, `fstp-http`, `fstp-json`, `fstp-rt` | `origin_header_parse`, `web_op_request` |
| `fstp-web-assets` | lib | Loads the compiled frontend from a directory, verifies it against a SHA-256 manifest at start, serves it with fixed headers | `fstp-http`, `fstp-crypto`, `fstp-json` | `asset_manifest_decode`, `static_path_resolve` |
| `fstp-api-testkit` | test only, `publish = false` | Fake M3 ports, the matrix generator and its independent reference, the three-channel harness over `fstp_rt::duplex`, the canary vault, the M4 models, the scenario bridge to `fstp-domain-testkit`, the `fstp-e2e-cell` test binary, and the synthetic legal-wording profile in `fstp-api-testkit/profiles/synthetic-wording/` | all of the above, `fstp-domain-testkit`, `fstp-prop`, `fstp-mc` | none: no parser |

Tools, which never ship:

| Tool | Purpose | Fuzz project |
| --- | --- | --- |
| `tools/gen-ts` | Writes `web/src/gen/api.ts` (types, operation table, route segments, structural validators) from `OPS`. CI runs `--check`, as `gen-sqlstate.sh --check` does | none: it only writes |
| `web/fuzz/` | In-house TypeScript fuzz harness for the TypeScript parsers, the interim answer to Q33 (section 9) | It is the fuzz harness |
| `tools/deps-check/src/web_scan.rs` | Token scanner over `web/src/**/*.ts`. It fails on `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, string timers, `on*` attribute strings and imports from outside `web/src` | `ts_token_scan` in `tools/deps-check/fuzz` |
| `tools/deps-check/src/npm.rs` | Checks `web/package-lock.json` against `deps/npm-allowlist.txt`: exact versions, integrity hashes, no install scripts | `npm_lock_parse` in `tools/deps-check/fuzz` |

The TypeScript application lives in `web/` (section 3.9).

### 1.2 Binaries and runtimes

| Binary | Owner | Runtime | M4 additions |
| --- | --- | --- | --- |
| `fstp-cell` | M3 | tokio through `fstp-rt` (ADR-002 record) | Mounts `fstp_web::router` on the tenant listener. `crates/fstp-cell/src/routes/m4.rs` holds only that mount and the port adapters |
| `fstp-control` | M3 | tokio through `fstp-rt` | Mounts the `fstp-signup` routes: tenant sign-up, agreement acceptance, operator review and cell provisioning for onboarding |
| `fstp-e2e-cell` | M4, test only, in `fstp-api-testkit` | tokio through `fstp-rt` | The `fstp-cell` library with a controllable clock, the synthetic vault, recording-fake probes and the synthetic legal-wording profile |

Each binary uses exactly one runtime, behind `fstp_rt::Runtime`. No M4 crate names tokio. M4 needs no new tokio feature, because it opens no UDP socket. The `fstp_rt::Runtime` trait offers TCP only, and M4 keeps it that way.

### 1.3 Layering rules

The existing `tools/deps-check/src/layering.rs` gains these rules, each with its own tests. Each is checked from `cargo metadata`, as the M2 rules are.

- **A1. Adapters have a fixed set of direct dependencies (I-84).** `fstp-mcp` may depend directly on `fstp-api-core`, `fstp-oauth`, `fstp-http` and `fstp-json` only. `fstp-web` may add `fstp-mcp`, `fstp-web-assets` and `fstp-rt`. Neither may depend directly on `fstp-engine`, `fstp-domain`, `fstp-findings`, `fstp-creator`, `fstp-import`, `fstp-programme`, `fstp-public`, `fstp-access` or any M3 crate. A Rust crate can name only its direct dependencies, so neither adapter can build an engine command.
- **A2. The API core exposes no command type and no port (I-84).** A source scan of `crates/fstp-api-core/src/**` fails on any `pub use` of `fstp_engine`, `fstp_domain::command`, `fstp_domain::Actor`, `fstp_creator` command types or `fstp_access::Principal`. It also fails on any public item outside `port.rs` whose signature names `CellPorts`, `AsyncEngine` or a port trait. Id types reach adapters only through `fstp_api_core::ids`. Tool metadata reaches them only through `fstp_api_core::meta`, which may re-export `ToolDef`, `Scope` and `Classification` and nothing else. `dispatch` takes `fstp_api_core::Op`, its own enum. Adapters receive `&ApiCore`, an opaque struct with no accessor for its ports.
- **A2b. Adapters never name ports (I-84).** A source scan of `crates/fstp-web/src/**` and `crates/fstp-mcp/src/**` fails on `port::`, `CellPorts`, `AsyncEngine`, `Principal` and `ExecMeta`. Only `fstp-cell` builds an `ApiCore` from its ports. So no adapter can reach `AsyncEngine::execute` around `dispatch`.
- **A3. The I-65 boundary.** `fstp-domain`, `fstp-programme` and `fstp-creator` have no dependency path to `fstp-import`. `fstp-import` has no path to `fstp-creator` or `fstp-engine`. Only `fstp-engine` (the bridge), `fstp-access` (operation kinds only) and `fstp-api-core` name both.
- **A4. The I-10 boundary kept.** `fstp-programme`, `fstp-creator`, `fstp-guide` and `fstp-public` have no path to `fstp-findings`. So `fstp-public` depends on `fstp-domain`, never on `fstp-engine`, which depends on `fstp-findings`. `fstp-import` uses only `fstp_findings::text::UntrustedText`, and `fstp-findings` cannot reach `fstp-import`. `fstp-access` and `fstp-api-core` reach `fstp-findings` through `fstp-engine`, which the `GetFindings` read needs. The existing rule that `fstp-domain` cannot reach `fstp-findings` is unchanged.
- **A5. The I-86 boundary.** `fstp-mcp`, `fstp-public`, `fstp-access` and `fstp-api-core` have no path to the M3 vault client crate. The vault reaches them only through the boolean oracle of `fstp-engine` and the write-only `VaultIntake` port, whose argument type `VaultBound<T>` has no accessor outside the M3 vault client.
- **A6. The I-87 boundary.** A source scan checks that `fstp-public/src/html.rs`, `fstp-public/src/tools.rs` and `fstp-public/src/feed.rs` name no state type except `PublicView` and its parts.
- **A7. No system actors from adapters.** `fstp-api-core`, `fstp-mcp` and `fstp-oauth` never name `fstp_domain::command::SystemCause` or build `Actor::System`. A source scan enforces this, because `Actor` is a public enum.
- **A8. The EUPL boundary.** No M4 crate depends on the export and import executable.
- **A9. Test code never ships.** No crate takes `fstp-api-testkit` as a normal dependency. `fstp-cell` and `fstp-control` are checked by name.
- **A9b. Production loads shipped profiles only.** `fstp-guide` has no public constructor for a profile from outside data. Its `ProfileSource` trait is implemented in production only by `ShippedProfiles`, which compiles in `crates/fstp-guide/profiles/**`. A source scan checks that `fstp-cell` and `fstp-control` name no other `ProfileSource`. A test checks that no file under `crates/fstp-guide/profiles/` contains the synthetic marker "SYNTHETIC TEST WORDING". A release check scans the `fstp-cell` binary for the same marker. The synthetic profile lives in `fstp-api-testkit` and reaches only `fstp-e2e-cell`.
- **A10. Pure crates stay pure.** `fstp-programme`, `fstp-creator`, `fstp-import`, `fstp-guide`, `fstp-public`, `fstp-tenant`, `fstp-access`, `fstp-signup` and `fstp-html` depend on no I/O crate: `fstp-rt`, `fstp-http`, `fstp-tls`, `fstp-pgwire`, `fstp-pgtest` or `fstp-migrate`. Each carries the M2 lint header: `#![deny(clippy::float_arithmetic, clippy::float_cmp, clippy::cast_precision_loss, clippy::arithmetic_side_effects)]`. The testkit source scan for floats extends to them. State explored by `fstp-mc` uses `BTreeMap` and `BTreeSet`.

### 1.4 Repository changes to stage in W0

- `Cargo.toml`: the new `members` and `[workspace.dependencies]` path entries.
- `deps/fuzz-required.txt`: `fstp-programme`, `fstp-creator`, `fstp-import`, `fstp-html`, `fstp-guide`, `fstp-public`, `fstp-tenant`, `fstp-signup`, `fstp-api-core`, `fstp-oauth`, `fstp-mcp`, `fstp-web`, `fstp-web-assets`.
- `crates/<each>/fuzz/`: one cargo-fuzz project with at least one target from the first commit.
- Every shared module file with all its `mod` lines and stub files that refuse with `NotImplemented`: `fstp-domain-testkit/src/{mc,reference}/mod.rs`, `fstp-api-testkit/src/lib.rs`, and `mod bridge; mod compose; mod sweep;` in `fstp-engine/src/lib.rs`. After W0, no lane edits these lines.
- `.github/workflows/ci.yml`: jobs for Node.js, `npm ci --ignore-scripts`, tsc, the TypeScript tests and fuzz harness, the pinned Playwright browsers, and a separate matrix job with its own timeout (section 8.3).
- `web/playwright.config.ts` and an initial generated `web/src/gen/api.ts` from the stub `OPS`.
- `tools/deps-check/src/{layering,web_scan,npm}.rs` and their registration and tests; new targets in `tools/deps-check/fuzz`.
- `docs/adr/ADR-013-mcp-and-oauth-profile.md` and `docs/adr/ADR-014-frontend-architecture.md`, as drafts for Daniel's acceptance before the code they govern.
- `docs/adr/ADR-003-build-and-test-tools.md`: record rows for tsc, Playwright and the browser builds, and the Node.js host once Q7 is answered.
- `web/package.json`, `web/package-lock.json`, `web/tsconfig.json`.

---

## 2. Journeys through one SuperSAFE call

### 2.1 Cast

All people are synthetic test accounts. Three organisations, O1 to O3, stand in for consortium partners.

| Label | Role | Notes |
| --- | --- | --- |
| A1, A2 | Tenant admin | SoD-07 needs at least two. Both verify their identity through the vault at onboarding (Q2). A1 opens the draft, so A1 is a builder. A2 approves activation |
| M1 | Programme manager on the draft | Invited, accepts the confidentiality terms and verifies identity (SoD-09) before the grant. Builds SuperSAFE in the creator |
| M2 | Programme manager, granted after activation | Approves call publication. Not a drafter (R-PC-03) |
| D1 | Call drafter | Writes the call text |
| C1 | FSTP coordinator | Declaration, knock-out, assignment, stage 1 close |
| R1 to R4 | Committee members of O1, O2, O3 and O1 | Assigned reviewers come from at least P-39 organisations |
| H1 | Committee chair | Casting vote on a tie |
| I1, I2 | IRC member | At least P-15 per nominated proposal |
| X | Applicant who reaches NEGOTIATION | |
| Y | Applicant who becomes NOT_SELECTED at stage 1 | Scores at exactly 75.00% under a test policy with a 0 to 4 scale (R-EV-03 AC) |
| Z | Applicant who becomes INELIGIBLE at the knock-out | |
| V, G | Minor applicant and guardian | V reaches NEGOTIATION only with a verified consent record (I-18) |
| W | Applicant who becomes NOT_SELECTED below the cut-off | |

The SuperSAFE run itself uses the 0 to 5 scale of P-01. The Y edge runs in a second programme built from the same template with the scale changed, so the fixture stays equal to the spec column.

### 2.2 Journeys

"Op" is the operation in the registry (section 3.6). "Domain" is the command or read behind it. All API routes start with `/api/v1`.

**J0. Tenant onboarding (A1, A2)**

| Step | Screen | Op | Domain or service | Route |
| --- | --- | --- | --- | --- |
| Sign up the organisation and accept agreements | Control plane sign-up, server-rendered | `cp.signup`, `cp.accept_agreements` | `fstp-signup` records | `POST https://{control}/signup` |
| CrabNebula operator staff review the tenant's identity before provisioning (TH-46); self-hosted cells skip this | Control plane operator console | `cp.review_tenant` | `fstp-signup` `TenantReviewed { outcome, by }` | `POST https://{control}/operator/tenants/{t}/review` |
| Cell provisioned; A1 enrols a passkey from a one-time link | M3 enrolment | none | M3 | M3 routes |
| A1 verifies identity through the vault (Q2) | M3 vault flow | `me.begin_verification` | `VaultIntake::begin_verification(AdminIdentity)` | `POST /me/verification` |
| Walk the onboarding steps | `/app/admin/onboarding/{step}` | `tenant.get_step`, `tenant.save_step` | `TenantCommand::SaveStep` | `GET`, `PUT /admin/onboarding/{step}` |
| Invite A2 with step-up; A2 enrols and verifies identity | Administrators step | `tenant.invite_admin` (high-risk: granting tenant admin) | `TenantCommand::InviteAdmin`, M3 enrolment | `POST /admin/admins` |
| Change a tenant setting with step-up | Settings | `tenant.set_login_methods`, `tenant.set_step_up_freshness`, `tenant.set_session_lifetimes`, `tenant.set_mcp`, `tenant.set_payment_mode`, `tenant.set_template_licence` (each high-risk) | `TenantCommand::SetSetting` per parameter | `PUT /admin/settings/{param}` |
| Finish onboarding | Summary | `tenant.complete` | Every step validated, two verified admins | `POST /admin/onboarding/complete` |

**J1. Programme creator (A1 opens, M1 builds, A2 approves)**

| Step | Screen | Op | Domain or creator | Route |
| --- | --- | --- | --- | --- |
| Open a draft with step-up | Creator start | `creator.open_draft` (high-risk) | `CreatorCommand::OpenDraft` with core `CreateProgramme` (Draft status) | `POST /programmes` |
| Invite M1 as programme manager on the draft | People | `creator.invite` | `Invite`; `preview_grant` (D3) | `POST /programmes/{p}/invitations` |
| M1 enrols, accepts the confidentiality terms and verifies identity for SoD-09 | Invitation landing, M3 vault flow | `people.accept_invitation`, `people.begin_verification` | As in J2 | `POST /invitations/{i}/accept`, `POST /invitations/{i}/verification` |
| A1 grants M1 the programme manager role on the draft, with step-up | People | `roles.grant` (high-risk) | `GrantRole` (Draft admits programme manager only; SoD-09 needs `IsVerified`) | `POST /programmes/{p}/roles` |
| Choose a starting point: SuperSAFE template, clone, blank, or import | Starting point | `creator.apply_start`, `import.upload` | `SaveFields` with template provenance, then `EditPolicy` by M1; or `RegisterDocument` | `POST /programmes/{p}/draft/start`, `POST /programmes/{p}/imports` |
| Resolve each proposed value with its evidence span | Import review | `import.resolve` | `BridgeCommand::ResolveImport` (I-65) | `POST /programmes/{p}/imports/proposals/{q}/resolution` |
| Steps 1 to 10, validated per step | Step pages | `creator.save_fields` | `SaveFields`, `EditPolicy` by M1 | `PUT /programmes/{p}/draft/fields` |
| People: invite D1, M2, C1, R1 to R4, H1, I1, I2, with live SoD checks | People | `creator.invite` | `Invite`; `preview_grant` per invitation, which runs the SoD guards without the Draft gate (D3); vault answers recorded (NOTE 5) | `POST /programmes/{p}/invitations` |
| Run the report; acknowledge warnings | Review | `creator.get_report`, `creator.acknowledge` | `ValidationReport`, `WarningAcknowledged` | `GET /programmes/{p}/draft/report`, `POST /programmes/{p}/draft/acknowledgements` |
| Preview the Guide, public page and contract placeholder | Review | `creator.preview` | `fstp-guide`, `fstp-public` on the draft | `GET /programmes/{p}/draft/previews/{guide,public,contract}` |
| Request activation | Review | `creator.request_activation` | `ActivationRequested` | `POST /programmes/{p}/activation-request` |
| A2 approves with step-up | Approval inbox | `creator.approve_activation` (high-risk) | Probes, report, clearance, `ActivationApproved` plus `ProgrammeActivated` in one entry | `POST /programmes/{p}/activation` |

**J2. People get their roles (invitees, then A1)**

| Step | Screen | Op | Domain | Route |
| --- | --- | --- | --- | --- |
| Invitee opens the link, enrols with a passkey, accepts the confidentiality terms | Invitation landing | `people.accept_invitation` | Terms are an `ApprovedText` with `TODO(legal)` wording until Daniel supplies it. For Judging roles they state the programme's P-75 and P-77 choices through bound placeholders (`mcp-server.md`). The accepted terms version is recorded | `POST /invitations/{i}/accept` |
| Invitee verifies identity for SoD-09 | M3 vault flow | `people.begin_verification` | `VaultIntake::begin_verification` | `POST /invitations/{i}/verification` |
| A1 grants each role with its own step-up, recording the committee organisation. M3 ends any OPAQUE or magic-link session of the account at the grant (I-77, section 6.1 item 10) | People admin | `roles.grant` (high-risk) | `GrantRole`, which the engine composes only when a `TermsAccepted` record exists for the account and role; SoD-09 needs `IsVerified` | `POST /programmes/{p}/roles` |
| A tenant admin grants a role to their own account; a second admin approves with step-up (SoD-07) | Approval inbox | `admin.approve_self_grant` (high-risk) | `TenantCommand::ApproveSelfGrant`, which yields the `ApprovalId` the grant consumes | `POST /admin/approvals/{a}` |

**J3. Call drafting and publication (D1, M2)**

| Step | Screen | Op | Domain | Route |
| --- | --- | --- | --- | --- |
| Draft call text, opening, deadline with time zone, budget | Call editor | `call.draft`, `call.edit` | `DraftCall`, `EditCall` | `POST /programmes/{p}/calls`, `PUT /calls/{c}` |
| M2 approves; M1 cannot if M1 is a drafter of the call | Approval | `call.approve` | `ApproveCallPublication` (R-PC-03) | `POST /calls/{c}/approval` |
| M2 publishes with step-up; the report is recomputed and must be clean; the Guide is generated in the same entry | Publish | `call.publish` (high-risk) | `PublishCall` with `config` and `config_model` from the tenant's inference record, never from the client (section 3.5); plus `GuidePublished { digest }` | `POST /calls/{c}/publication` |
| An agent prepares the publication; M2 confirms in the platform with step-up (I-85) | Pending actions | `call.publish` through the prepare-only tool `fstp_prepare_call_publication` (Q32) | Stored as a `PendingAction`; executed only by `pending.confirm` | `POST /mcp`, then `POST /pending-actions/{id}/confirmation` |

**J4. Applicants (X, Y, Z, V with G, W)**

| Step | Screen | Op | Domain or service | Route |
| --- | --- | --- | --- | --- |
| Read the public call page and Guide, with no script and no cookie | Public pages | `public.call`, `public.guide` | `PublicView` | `GET /p/{slug}/calls/{c}`, `GET /p/{slug}/calls/{c}/guide` |
| Create an account by magic link or passkey | M3 | none | M3 | M3 routes |
| Start a proposal; give the minor information that Q23 decides | New proposal | `proposal.create` | `CreateDraft { minor }`, `VaultIntake::declare_minor` (Q23, blocking) | `POST /calls/{c}/proposals` |
| Read the own proposal; each read appends `ContentRead` (R-AU-01) | Proposal | `proposal.view` | `ReadContent` by the team | `GET /proposals/{x}` |
| Write the form; autosave to the private workspace (I-21) | Workspace | `proposal.save_workspace` | `workspace.drafts`, team only | `PUT /proposals/{x}/workspace` |
| Save a plan version | Plan editor | `proposal.record_plan` | `RecordPlanVersion` | `PUT /proposals/{x}/plan` |
| Add team members, or a guardian for V | Team | `proposal.add_member`, `proposal.add_guardian` | `AddTeamMember`, `AddGuardian` | `POST /proposals/{x}/team`, `POST /proposals/{x}/guardian` |
| State country and declared affiliations, to the vault only | Eligibility | `proposal.state_country`, `proposal.declare_affiliations` | `VaultIntake` with `VaultBound<T>`; never through MCP | `PUT /proposals/{x}/vault/{country,affiliations}` |
| Read the data protection notice; ethics self-declaration; submit | Submit | `proposal.submit` | `Submit` with notice version (R-NG-06) and ethics (R-SB-05) | `POST /proposals/{x}/submission` |
| Request a copy by email | Proposal | `proposal.request_copy` | Outbox record, sent in M6 (R-SB-04) | `POST /proposals/{x}/copy` |
| Read notices: outcomes such as NOT_SELECTED (R-EV-04, P-08) and IRC concerns (R-IR-02) | Notices | `me.notices` | Outbox records `ProposalOutcome` and `IrcConcern` for the account; email dispatch within P-08 arrives with M6 | `GET /me/notices` |
| Stage 2: read questions under handles, answer, revise | Stage 2 | `stage2.view`, `stage2.answer`, `stage2.revise` | `AnswerQuestions`, `RecordPlanVersion`, `SubmitRevision` | `GET /proposals/{x}/stage2`, `POST /proposals/{x}/stage2/{answers,revision}` |
| Withdraw before GRANTED | Proposal | `proposal.withdraw` | `Withdraw` | `POST /proposals/{x}/withdrawal` |
| G gives consent through the vault | Guardian page | `guardian.begin_consent` | `VaultIntake::begin_verification(GuardianConsent)` | `POST /proposals/{x}/guardian/consent` |
| Land in NEGOTIATION: the data protection notice at negotiation (R-NG-06), next steps | Negotiation | `negotiation.view`, `negotiation.acknowledge_notice` | Read only in M4, plus a `NoticeShown { version }` audit entry and an acknowledgement record | `GET /proposals/{x}/negotiation`, `POST /proposals/{x}/negotiation/notice` |

**J5. FSTP coordinator (C1)**

| Step | Screen | Op | Domain | Route |
| --- | --- | --- | --- | --- |
| Intake queue for the closed call | Intake | `intake.queue` | Read | `GET /calls/{c}/intake` |
| See title and neutral summary, then declare | Declaration | `review.declaration_view`, `review.declare_proposal` | `DeclareConflict` | `GET /proposals/{x}/declaration-view`, `POST /proposals/{x}/coordinator-declaration` |
| Read for the knock-out | Content | `review.read_content` | `ReadContent`, then a read clearance | `GET /proposals/{x}/content` |
| Record the knock-out | Knock-out | `review.knock_out` | `RecordKnockOut` | `POST /proposals/{x}/knock-out` |
| Assign reviewers; P-39 and proximity results show as pass or fail only | Assignment | `review.assign`, `review.unassign` | `Assign`, `Unassign` | `POST /proposals/{x}/assignments`, `DELETE /assignments/{a}` |
| Admit to stage 1; record the stage 1 close | Board | `review.admit`, `review.close_stage1` | `AdmitToStage1`, `CloseStage1` | `POST /proposals/{x}/{admission,stage1-close}` |
| Read notifiable-conflict drafts and copy them for the granting authority (R-CF-04) | Conflicts | `review.notifiable_conflicts` | Outbox records `NotifiableConflict`; the coordinator sends outside the platform in M4 | `GET /calls/{c}/notifiable-conflicts` |

**J6. Assigned reviewers (R1 to R4)**

| Step | Screen | Op | Domain | Route |
| --- | --- | --- | --- | --- |
| My assignments | Assignments | `me.assignments` | Read | `GET /me/assignments` |
| Declare before reading | Declaration | `review.declare_assignment` | `DeclareConflict` | `POST /assignments/{a}/declaration` |
| Read and score every criterion; correct a score | Score sheet | `review.read_content`, `review.score`, `review.correct_score` | `ReadContent`, `RecordScore`, `CorrectScore` | `GET /proposals/{x}/content`, `POST /assignments/{a}/scores`, `PUT /assignments/{a}/scores/{s}` |
| Write the ranking summary and rationale | Summary | `review.ranking_summary` | `RecordRankingSummary` | `POST /assignments/{a}/ranking-summary` |
| Stage 2: ask questions or record "no questions" | Stage 2 | `stage2.ask`, `stage2.no_questions` | `AskQuestion`, `RecordNoQuestions` | `POST /assignments/{a}/{questions,no-questions}` |
| Rescore the revision and rank | Score sheet | `review.score`, `review.rank` | `RecordScore`, `RankAfterStage2` | `POST /assignments/{a}/ranking` |
| Mark a finding as agreed or disputed; no findings exist before M7 | Findings | `review.mark_finding` | `FindingCommand::Mark` | `POST /findings/{f}/mark` |

**J7. Committee (R1 to R4, H1)**

| Step | Screen | Op | Domain | Route |
| --- | --- | --- | --- | --- |
| Ranking view with remaining budget and no findings | Ranking | `committee.ranking` | `ranking_view`; rows with a conflict fact for the viewer show "recused" only (Q16) | `GET /calls/{c}/ranking` |
| Open a cut-off round with order, position, rationale and tie-break | Cut-off | `committee.open_round` | `OpenCutOffRound` (D5) | `POST /calls/{c}/cut-off-rounds` |
| Each member casts or delegates a ballot; recused members cannot | Ballot | `committee.cast`, `committee.delegate` | `CastBallot`, `DelegateVote` (D5) | `POST /cut-off-rounds/{r}/{ballot,delegation}` |
| Record the cut-off; outcomes are computed | Cut-off | `committee.record_cutoff` | `RecordCutOff { round }` | `POST /cut-off-rounds/{r}/record` |

**J8. IRC (I1, I2) and the programme manager**

| Step | Screen | Op | Domain | Route |
| --- | --- | --- | --- | --- |
| IRC cases | Cases | `me.irc_cases` | Read | `GET /me/irc-cases` |
| Declare; read the nominated proposal and its outcome, never the deliberation | Case | `irc.declare`, `irc.case` | `DeclareConflict`, `ReadContent`; the view has no ballot, score or rationale field (R-IR-03) | `POST /irc-assignments/{a}/declaration`, `GET /irc-assignments/{a}/case` |
| Validate or raise a concern | Verdict | `irc.review` | `RecordIrcReview` | `POST /irc-assignments/{a}/review` |
| Record the decline rows (O-49) | Proposal admin | `decision.decline_after_concern`, `decision.decline_negotiation` | `DeclineAfterConcern`, `DeclineNegotiation` | `POST /proposals/{x}/{decline-after-concern,decline-negotiation}` |

The last validation moves X to NEGOTIATION. V moves only with a verified consent record (I-18).

**J9. Agents and public research**

| Step | Screen | Op | Route |
| --- | --- | --- | --- |
| Connect an agent: OAuth consent with step-up (linking a device) | Consent | `agents.consent` (high-risk) | `GET /oauth/authorize` to `/app/agents/consent`, then `POST /api/v1/oauth/consent` |
| List and revoke agents, with scopes and recent activity (R-MC-03, `mcp-server.md`) | My agents | `agents.list`, `agents.activity`, `agents.revoke` | `GET /me/agents`, `GET /me/agents/{client}/activity`, `POST /me/agents/{client}/revocation` |
| See and end sessions and linked devices (R-LG-04) | Sessions | `me.sessions`, `me.end_session` | `GET /me/sessions`, `POST /me/sessions/{s}/end` |
| Add a phishing-resistant method before a first high-risk action (`authentication.md`) | Security | `me.add_passkey` (high-risk: adding a passkey) | M3 enrolment routes |
| Confirm or discard pending actions | Pending actions | `pending.list`, `pending.confirm`, `pending.discard` | `GET /me/pending-actions`, `POST /pending-actions/{id}/{confirmation,discard}` |
| Agent calls tools | none | Tools from the registry | `POST /mcp` |
| Public research without an account | none | Public tools over `PublicView` | `POST /mcp/public` |

**J10. Tenant admin approvals backed by M3 (A1, A2; Q41)**

| Step | Screen | Op | Route |
| --- | --- | --- | --- |
| Approve the recovery of another account outside the Receiving group, with step-up (I-79, TH-57) | Approval inbox | `admin.approve_recovery` (high-risk, web only) | `POST /admin/recoveries/{r}/approval` |
| Approve or refuse a break-glass request, with step-up (SoD-08, TH-18) | Approval inbox | `admin.approve_break_glass` (high-risk, web only) | `POST /admin/break-glass/{b}/approval` |

Both screens call M3 ports (`Recovery`, `BreakGlass`, section 6.1). M3 owns the flows and their invariants. M4 owns the screens and the registry rows.

---

## 3. Components and their interfaces

### 3.1 The programme as data (`fstp-programme`)

```rust
/// One programme as the creator captures it. People are never part of it (I-73).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProgrammeSpec {
    pub schema: SpecSchema,            // "fstp.programme/1"
    pub currency: Currency,
    pub funder: FunderStep,            // step 1: P-53, P-56, P-57, P-58, P-41; retention P-22, P-46; P-43 (Q36)
    pub identity: IdentityStep,        // step 2: name, narrative, scope, P-25, public slug
    pub eligibility: EligibilityStep,  // step 3: persons, P-13, P-17, minors; verification P-18, P-19, P-45 (Q36)
    pub funding: WhatWeFundStep,       // step 4: P-55, P-26
    pub evaluation: EvaluationStep,    // step 5: P-01 to P-03, P-06, P-07 to P-11, P-14 to P-16, P-21, P-23, P-24, P-28, P-39, P-42, P-75, P-77
    pub money: MoneyStep,              // step 6: P-04, P-05, P-27, P-34, P-36, P-59, P-65 to P-67, amount criteria
    pub contract: ContractStep,        // step 7: P-29, P-30, P-44, P-47 to P-49, flow-down obligations (I-49)
    pub support: SupportStep,          // step 8: P-60, P-61 to P-64
    pub people: PeoplePolicyStep,      // step 9: P-12 only; people themselves are never part of the spec
    pub comms: CommsStep,              // step 10: P-31 to P-33, P-35, P-37, P-38, P-40, P-50 to P-52, P-54, P-76, templates, FAQ
}

/// A field value or an explicit gap. A gap compiles to the profile's placeholder
/// and is always a validation failure (`FieldUnset`).
pub enum Field<T> { Set(T), Unset }

/// Narrative text: inline in templates, the fixture and exports; a TextRef in ledger bodies (ADR-007).
pub enum Narrative { Inline(String), Stored(TextRef) }

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldId { /* one variant per field of the steps above */ }

pub struct FieldSpec {
    pub id: FieldId,
    pub step: Step,                     // 1 to 10, matching programme-creator.md
    pub params: &'static [ParamId],     // the P- values it sets; empty for pure narrative
    pub kind: FieldKind,                // Policy | Artefact
    pub importable: bool,               // whether import may propose it
    pub bound_by: &'static [RuleRef],   // for example I-50 for the cap
}
pub const FIELDS: &[FieldSpec];

pub fn compile(spec: &ProgrammeSpec, profile: &FunderProfile, ids: CompileIds) -> Result<Compiled, CompileError>;
pub struct Compiled { pub policy: PolicyVersion, pub artefacts: ProgrammeArtefacts, pub unset: BTreeSet<FieldId> }
pub fn decompile(policy: &PolicyVersion, artefacts: &ProgrammeArtefacts, unset: &BTreeSet<FieldId>) -> ProgrammeSpec;

/// R-PG-04: which calls a change affects.
pub fn impact(state: &State, programme: ProgrammeId, changed: &BTreeSet<FieldId>) -> Vec<CallImpact>;
pub enum ImpactEffect {
    NextCallOnly,                            // frozen, call published (I-12)
    AppliesToDraftCall,                      // call not yet published
    TightensPublished { corrigendum: CorrigendumNeed }, // P-05 or P-13 under NOTE 7; always needs a corrigendum (Q37)
    Refused(RuleRef),                        // for example P-05 below a committed sum
}
```

Rules:

- **Programme level only.** `compile` sets every `CATALOGUE` entry with programme level, and nothing else. Tenant-level parameters (P-20, P-69 to P-74, P-78) come from `fstp-tenant`. P-68 is fixed.
- **Tenant defaults are not parameters.** `CATALOGUE` makes P-18, P-21 and P-45 programme level (`rules.rs`). `programme-creator.md` captures them in the onboarding Identity and Inference steps. Both hold when onboarding records tenant defaults only. A new draft takes them as prefilled values with `Provenance::Default { tenant }`. The programme field is the only parameter, and the programme manager confirms it in the creator.
- **Steps the creator table does not name.** P-06, P-12, P-19, P-22, P-39, P-42, P-43 and P-46 to P-49 are programme level but appear in no "Bounded by" cell. Each has one field in the step shown above. The placement is a reading (Q36). `r_pg_01_creator_table_maps_to_fields` treats them through an explicit `UNLISTED_IN_CREATOR_TABLE` constant, which the test also checks against the spec.
- **Coverage, read from the spec.** `r_pg_01_creator_table_maps_to_fields` reads the "Bounded by" column of `SPEC/02-domain/programme-creator.md` at test time. Every parameter named there is in some `FieldSpec::params`, and the reverse holds for programme-level parameters. `r_pg_01_every_programme_parameter_has_one_field` checks against `CATALOGUE`.
- **Round trip.** `compile` then `decompile` is the identity on specs that `compile` accepts. A property test over generated specs checks this.
- **Determinism.** `compile` is a pure function of the spec, the profile and shell-supplied ids, so a clone or template start reproduces exactly.
- **SuperSAFE fixture.** `crates/fstp-programme/fixtures/supersafe.programme.json` is canonical RFC 8785 text. `r_pg_01_supersafe_fixture_matches_policy_defaults` reads the SuperSAFE column of `policy-parameters.md` at test time and checks every concrete entry. Examples:
  - P-01 weights 30, 40 and 30 on a 0 to 5 scale; P-02 75.00; P-03 2;
  - P-04 5000.00 to 100000.00; P-05 400000.00; P-07 28 days; P-08 5 working days;
  - P-10, P-11, P-16, P-24, P-32 and P-77 (draft only) as their options;
  - P-12 1 call; P-15 2; P-25 English; P-39 2; P-54 3; P-59 15 days;
  - P-50 and P-51 Full; P-52 on; P-75 off.
- **Synthetic placeholders.** Values the spec does not give carry `"synthetic": true` in the fixture's provenance block, never inside the policy. These are P-21, P-26's exact licence list, P-41 (L-06), P-55's closed list (O-23), P-56, P-57 and P-58 (L-10). The test lists them, so the gap stays visible.

### 3.2 The creator (`fstp-creator`)

A draft is an M2 programme in `Draft` status plus creator records. The creator stays the editing interface after activation.

```rust
pub enum StartingPoint {
    Blank { profile: FunderProfileRef },
    Clone { source: ProgrammeId },                    // same tenant only (I-19)
    Template { template: TemplateId, version: u32 },  // shipped or tenant-private
    Import { document: ImportDocumentId },            // values arrive as proposals
}
pub enum Provenance {
    Manual, Default { profile: FunderProfileRef }, Template { template: TemplateId, version: u32 },
    Clone { source: ProgrammeId, version: PolicyVersionId },
    Import { proposal: ImportProposalId, resolution: ImportResolution },   // Confirmed | Edited
}

pub enum CreatorCommand {
    OpenDraft { programme: ProgrammeId, version: PolicyVersionId, profile: FunderProfileRef },
    ApplyStart { programme: ProgrammeId, base: DraftRevision, start: StartingPoint },
    SaveFields { programme: ProgrammeId, base: DraftRevision, fields: Vec<FieldEdit> },
    AcceptNarrative { programme: ProgrammeId, base: DraftRevision, field: FieldId }, // template text is never applied silently
    Invite { programme: ProgrammeId, invitation: InvitationId, role: Role, invitee: Invitee, organisation: Option<OrganisationId> },
    WithdrawInvitation { programme: ProgrammeId, invitation: InvitationId },
    AcknowledgeWarning { programme: ProgrammeId, revision: DraftRevision, warning: WarningKey },
    RequestActivation { programme: ProgrammeId, revision: DraftRevision },
    ApproveActivation { programme: ProgrammeId, revision: DraftRevision, decision: DecisionId },
    SaveAsTenantTemplate { programme: ProgrammeId, template: TemplateId },   // tenant-private only (Q17)
}

pub enum CreatorRecord {
    DraftOpened { programme: ProgrammeId, profile: FunderProfileRef, by: AccountId },
    StartApplied { programme: ProgrammeId, revision: DraftRevision, start: StartingPoint, by: AccountId },
    FieldsSaved { programme: ProgrammeId, revision: DraftRevision, fields: Vec<(FieldId, ValueDigest, Provenance)>, by: AccountId },
    NarrativeAccepted { programme: ProgrammeId, revision: DraftRevision, field: FieldId, by: AccountId },
    InvitationRecorded { .. }, InvitationWithdrawn { .. },
    ProbeRecorded { programme: ProgrammeId, probe: ProbeKind, outcome: ProbeOutcome, at: Timestamp },
    WarningAcknowledged { programme: ProgrammeId, revision: DraftRevision, warning: WarningKey, by: AccountId },
    ActivationRequested { programme: ProgrammeId, revision: DraftRevision, report: ReportDigest, by: AccountId },
    ActivationApproved(ActivationApproved),   // private fields; `ActivationApproved::new(&ActivationClearance)` only
    TemplateSaved { template: TemplateId, spec: ContentDigest, by: AccountId },
}

/// Monotone per draft. Every creator record and every core record on the programme bumps it.
pub struct DraftRevision { seq: u32, digest: ContentDigest }

pub fn decide_creator(core: &State, creator: &CreatorState, cmd: &CreatorCommand, ctx: &Ctx, ext: &CreatorInputs)
    -> Result<CreatorDecision, CreatorRefusal>;
pub struct CreatorDecision {
    pub records: Vec<CreatorRecord>,
    /// Core commands the engine decides in the same entry, with the same actor and context.
    pub core: Vec<fstp_domain::Command>,
}
/// What the engine passes in, so the creator never sees the import store or the vault.
pub struct CreatorInputs { pub unresolved_imports: u32, pub probes: ProbeSet, pub sod: SodPreview, pub vault: VaultChecks }
```

How a save becomes policy:

- `OpenDraft` is issued by a tenant admin. It carries core `CreateProgramme` with the profile-default policy. The programme starts in `Draft` status (D1). `CreateProgramme` stays high-risk (Q10).
- A `SaveFields` or `ApplyStart` that touches any `FieldKind::Policy` field compiles the draft spec with the edits. It emits one core `EditPolicy { base: head, version }`. The engine runs it through `fstp_domain::decide` with the programme manager as actor. `validate` (I-50 and the M2 checks), authorship and I-23 apply unchanged.
- So the programme manager who sets P-01 or P-09 becomes its last author. Activation never rewrites policy, so builder authorship survives it (R-PC-03).
- Artefact-only fields produce creator records alone.
- The creator and core records of one save are one ledger entry, or nothing.
- `base` must equal the current `DraftRevision`. A concurrent edit fails with `StaleRevision`, and the client reloads.

Validation:

```rust
pub enum Severity { Failure, Warning }
pub struct CheckResult { pub check: CheckId, pub severity: Severity, pub subject: CheckSubject, pub detail: CheckDetail }
pub struct ValidationReport { revision: DraftRevision, results: Vec<CheckResult> }   // read-only accessors
pub fn validate(core: &State, creator: &CreatorState, programme: ProgrammeId, profile: &FunderProfile,
                inputs: &CreatorInputs) -> ValidationReport;

/// I-66 witness. No Failure, and every Warning acknowledged at `revision`.
pub struct CleanReport { revision: DraftRevision, digest: ReportDigest }
pub fn clean(report: &ValidationReport, acks: &AckSet) -> Result<CleanReport, Uncleared>;

/// I-67 witness. The approver is outside the builder set and shares no verified identity with it.
pub struct ActivationClearance { report: CleanReport, approver: AccountId, builders: BTreeSet<AccountId> }
pub fn clear_activation(core: &State, creator: &CreatorState, programme: ProgrammeId, report: CleanReport,
                        ctx: &Ctx, inputs: &CreatorInputs) -> Result<ActivationClearance, CreatorRefusal>;
```

The check catalogue is a constant table, `CHECKS: &[CheckSpec]`. Each row names its source:

| Check | Source | Severity | M4 implementation |
| --- | --- | --- | --- |
| `PolicyInvalid` | `fstp_domain::policy::validate` refusal | Failure | Reuses M2 |
| `CapAboveCeiling` | I-50, R-PG-01 AC; the detail names the P-05 and P-58 values as ADR-006 strings | Failure | Pure |
| `P04MaxAboveP05`, `P39AboveP03` | M2 `ValidationWarning` | Warning | Reuses M2 |
| `FieldUnset` | A field with no value | Failure | Pure over `Compiled::unset` |
| `ActionDatesInconsistent` | P-57 start after end | Failure | Pure |
| `CallPackageIncomplete` | I-48: maximum per recipient, criteria for the exact amount, closed activity list, persons supported, award criteria and procedure | Failure | Pure over the spec |
| `GuideSectionMissing` | I-52: every required section of `guide-for-applicants.md` | Failure | `fstp_guide::preview` |
| `GuideBindingUnresolved` | I-51: every parameter-bound placeholder resolves from the draft policy | Failure | `fstp_guide::preview` |
| `LegalWordingPending` | `guide-for-applicants.md` Rules: statements on grant agreement obligations use approved wording | Failure (Q6) | Pure over the profile's wording status |
| `FlowDownMissing` | I-49: the obligations listed in `contracts.md` under the Horizon Europe profile, as identifiers | Failure | Pure over `FlowDownSet` |
| `InviteeRefused` | SoD-01 to SoD-13 across invited people | Failure | `fstp_domain::roles::preview_grant` per invitation with an account: the `GrantRole` SoD guards without the Draft gate (D3). Vault answers are recorded and rate-limited (Q13) |
| `InviteeWithoutAccount` | An invitation not yet accepted cannot be checked yet; the grant checks again (enforcement point 1) | Warning | Pure |
| `TooFewTenantAdmins` | SoD-07, the onboarding "at least two tenant admins" | Failure | `fstp-tenant` projection |
| `BuilderUnverified` | I-67 strict reading: the Sybil check needs every builder verified (Q2) | Failure | Existing `IsVerified` query per builder, recorded |
| `RosterShort` | Fewer invited committee members than P-03 or P-39 organisations, fewer IRC members than P-15, no chair or no coordinator; the spec states no rule | Warning | Pure |
| `ExclusionClassUnknown` | P-13 class ids the vault does not know, so I-04 could not be checked | Failure | New vault query, pending Q35 (blocking) |
| `ProximityListMissing` | P-38: a partner organisation without a declared list | Warning | New vault query, pending Q35 (blocking) |
| `PrecheckUnavailable` | P-23 enabled while no pre-check provider exists (Q38) | Warning (Q38 C, 2026-11-06: the Guide notes the pre-check is not yet available) | Pure over the `Precheck` port's presence; absent until M7 |
| `AiActReassessment` | `ai-act.md` reassessment trigger: P-77 "allowed" while score tools exist | Warning | Pure; the acknowledgement records that the AI Act position was reviewed (`TODO(legal)`) |
| `ChannelUnreachable` | Every enabled channel of P-32 | Failure | `Prober`; an absent prober reports Failure (Q5) |
| `SendingDomainUnverified` | SPF, DKIM and DMARC of the sending domain | Failure | `Prober`, same rule (Q5) |
| `InferenceUnreachable` | P-21; R-NF-10 says loss of inference never blocks human evaluation | Warning | `Prober` |
| `MandatoryElementMissing` | I-69 | Failure | Pure over the default theme in M4 |
| `ContrastFailure` | I-70: every text colour pair, light and dark | Failure | Pure integer computation over the default tokens (rule below) |
| `ImportUnresolved` | A proposal neither confirmed, edited nor dismissed | Failure (Q30) | `CreatorInputs::unresolved_imports`, a count from the engine |

Rules:

- **Fresh probes.** `ApproveActivation` makes the shell run every probe in the same request. The engine records `ProbeRecorded` in the same entry. The report is recomputed over those results, never over the stored request-time report.
- **Bound to a revision.** Any record on the draft after the report makes the clearance fail with `StaleRevision`. Acknowledgements bind to `(revision, WarningKey)`, so an edit voids them.
- **Builders (Q1).** The builder set is every account that issued `CreateProgramme`, `OpenDraft`, `ApplyStart`, any `EditPolicy`, any creator record on the programme, any import resolution, or a `GrantRole` on the draft. Acknowledging a warning or granting a draft binding therefore makes an account a builder.
- **Approver (Q1, interim).** A tenant admin outside the builder set. The approval is high-risk, so M3 enforces a fresh step-up (I-78). The vault must answer `IsVerified` as true for the approver and for every builder. Only then does `SameIdentityAsAny(approver, builders)` mean something, and it must answer false (Q2). An unverified second account of a builder is therefore refused, not passed.
- **Contrast without floats (I-70, rule A10).** WCAG luminance needs the sRGB transfer function, which has a power of 2.4. `fstp-creator` uses two `const` tables of 256 entries: a lower and an upper bound of each channel's linear value, as integers scaled by 10^12. Luminance is the integer weighted sum with the WCAG weights scaled by 10^4. The check takes the lighter colour's lower bound and the darker colour's upper bound. It then compares `(L1 + 0.05) * 2 >= 9 * (L2 + 0.05)` by integer cross-multiplication, so it passes only if the exact value passes. A test in `fstp-api-testkit`, outside the float lint, recomputes both tables with `f64`. It checks that each bound encloses the `f64` value with a margin of at least 10^-9, far above the `f64` error.

### 3.3 Document import (`fstp-import`)

```rust
pub struct ImportDocument { pub id: ImportDocumentId, pub programme: ProgrammeId, pub blob: BlobRef,
                            pub media: ImportMedia /* TextPlain | TextMarkdown */, pub digest: ContentDigest,
                            pub uploaded_by: AccountId }
/// Normalised document text. Never Display, never Deref<Target = str>.
pub struct ExtractedText(UntrustedText);
/// A proposed value. Never Display, never Deref.
pub struct UntrustedValue(fstp_json::Value);
pub struct ImportProposal { pub id: ImportProposalId, pub document: ImportDocumentId, pub field: FieldId,
                            pub value: UntrustedValue, pub evidence: Vec<Span>, pub config: ImportConfigId,
                            pub conflicts_with_profile: Vec<RuleRef> }   // flagged, never adjusted
pub trait Proposer {
    /// The document travels only as data. Instructions come only from the pinned import prompt (M7).
    fn propose(&self, doc: &ExtractedText, schema: &[FieldSpec], config: &ImportConfig) -> Result<Vec<RawProposal>, ProposerError>;
}
pub fn normalise(bytes: &[u8], media: ImportMedia, limits: ImportLimits) -> Result<ExtractedText, ImportError>;
pub enum ImportCommand { RegisterDocument(ImportDocument), RecordProposals { document: ImportDocumentId, proposals: Vec<ImportProposal> } }
pub enum ImportRecord { DocumentRegistered(..), ProposalsRecorded(..),
                        ProposalResolved { proposal: ImportProposalId, resolution: ImportResolution, by: AccountId } }
```

The engine bridge is the only place both sides meet:

```rust
// fstp-engine/src/bridge.rs
pub enum BridgeCommand {
    /// The client sends the value it displayed and its digest. Confirm and Edit carry a value; Dismiss carries none.
    ResolveImport { programme: ProgrammeId, proposal: ImportProposalId, shown: ValueDigest,
                    resolution: ClientResolution, base: DraftRevision },
}
```

`resolve_import` checks that:

- the actor holds an active programme manager binding on the draft at `now`;
- the proposal exists, belongs to this programme and is unresolved;
- `shown` equals the digest of the stored proposal value;
- the field is importable;
- for `Confirm` the value equals the proposal, and for `Edit` it differs;
- a flagged profile conflict carries an explicit `conflict_acknowledged: true`.

It then emits `ImportRecord::ProposalResolved` and the creator's `SaveFields` with `Provenance::Import { proposal, resolution }` in one entry. `Dismiss` emits only the import record.

Rules:

- **One value per resolution.** There is no bulk accept in M4 (Q30).
- **Profile conflicts are flagged, never adjusted.** P-05 against P-58 (L-10) is the fixture example.
- **Untrusted document.** The document is untrusted data under `04-llm-assessment/assessment.md`. It travels only in the data channel. It is never concatenated into instructions.
- **M4 formats.** UTF-8 `text/plain` and `text/markdown` only, up to a size limit (Q24). Markdown is not rendered or parsed into structure. It is normalised as text, and evidence spans are byte offsets into the normalised text.
- **M4 proposers.** `FakeProposer` is deterministic and fixture-driven. `HavocProposer` returns arbitrary values for tests. `NoProposer` shows the document beside a manual form. The inference-backed proposer arrives in M7. I-65 does not depend on proposer quality.
- **AI disclosure.** The import screen shows the AI disclosure when a proposer that uses inference is configured, as R-LA-08 does for assessment. In M4 no such proposer exists.

### 3.4 Changes to the M2 domain core and engine (lane L-DOM)

Each change has tests first. Every M2 suite stays green. Every M2 tripwire is measured again and any count change is reported, never absorbed.

| ID | Change | Why | Files |
| --- | --- | --- | --- |
| D1 | `ProgrammeStatus { Draft, Active }` in the programme projection. `CreateProgramme` creates a `Draft` programme. It keeps `ActorRule::TenantAdmin` and stays `high_risk()` | The activation step that I-66 and I-67 need | `fstp-domain/src/programme.rs`, `command.rs` |
| D2 | `Command::ActivateProgramme { programme, decision, report: ReportDigest, revision, creator_builders: BTreeSet<AccountId> }` and `Record::ProgrammeActivated` with private fields. `ActorRule::TenantAdmin` (interim, Q1). `high_risk()` and `binding_action()`. The core guard refuses when the actor is in `programme_builders(state, p) ∪ creator_builders`, or when `SameIdentityAsAny(actor, builders)` holds (Q2) | Defence in depth for I-67 | `command.rs`, `rules.rs`, `programme.rs`, new `policy/activation.rs` |
| D2e | Engine: `DomainDecider` refuses `Command::Core(ActivateProgramme)` that arrives through `execute` with `RuleRef::I66`. Only `Command::Creator(ApproveActivation)` composes it, from the creator decision. The engine fold refuses an entry holding `ProgrammeActivated` without a `Creator(ActivationApproved)` for the same programme, revision and report digest. The same pattern holds for publication: the engine composes `PublishCall` only with a recomputed clean report and a `GuidePublished` record in the same entry, and the fold refuses a `CallPublished` without its `GuidePublished` (I-52 at Guide generation, Q12 built) | One path to an active programme, for I-66 and I-67; one path to a published call, for I-51 and I-52 | `fstp-engine/src/{lib,driver,compose}.rs` |
| D3 | Refusals on `Draft` programmes: `DraftCall`, `EditCall`, `ApproveCallPublication`, `PublishCall` and `CreateDraft`. `GrantRole` on a draft admits only `ProgrammeManager`. The `GrantRole` guard splits into a status gate and the SoD guards. `pub fn preview_grant(state, grant, ctx, answers) -> Result<(), Refusal>` runs the SoD guards only, so the creator can check invitees on a draft | Nothing runs on an unactivated programme, and the live SoD check still works | `programme.rs`, `roles/commands.rs`, `proposal/draft.rs` |
| D4 | Under P-10 "operator staff only", the FSTP coordinator reads in STAGE1 and STAGE2 after a proposal-level declaration of no conflict (O-43, decided 2026-10-25). `visibility.rs` still refuses this read | The spec is decided and the code lags | `visibility.rs`, testkit `reference/review.rs` |
| D5 | `OpenCutOffRound { round, call, order, nominated, rationale, tie_breaks }`, `CastBallot { round, vote }` and `DelegateVote { round, to }`, each by a committee member who is not recused. `RecordCutOff { round }` counts only cast ballots under P-16 (NOTE 8). The `ballots` field leaves the command | No member can state another member's vote (R-EV-09, Q4) | `command.rs`, `decision.rs`, `rules.rs`, `record.rs`, codec |
| D6 | P-75 becomes typed in `FrozenValues`. `ReadContent` with `Via::Mcp` is refused unless P-75 is on, except for a reader whose basis is `ReadBasis::Team`. P-75 governs reviewers' agents only (`mcp-server.md`, Confidentiality), so the applicant team reads its own proposal through MCP as through the web | One checked guard for P-75 (TH-62), with I-84 parity for applicants | `policy/mod.rs`, `visibility.rs` |
| D7 | `RuleRef` gains `I65`, `I66` and `I67`. `CommandKind::ALL` grows from 57 to 61. `RulesVersion` is bumped, so earlier decisions keep their recorded version | Refusals name the rule | `refusal.rs`, `command.rs`, `rules.rs`, `engine.rs` (lane routing and gate entries for the new kinds) |
| D8 | Testkit and test setup: every place that issues `CreateProgramme` then activates the programme. Assertions do not change. Each adapted file's diff touches only setup lines, which review checks | M2 suites keep running | See the file list and sequencing below |
| D9 | `ranking_view` fills `criterion_scores` with each criterion's weighted score: the mean over assigned reviewers of weight times score, as an exact `Ratio` (R-EV-08, `roles-and-sod.md` Committee ranking view). It uses the effective score set after stage 2 (I-09) | The view the spec names; M2 returns an empty list | `visibility.rs`, testkit `reference/review.rs` |
| D10 | `requested` totals the effective plan (I-09): the last plan of a submitted stage 2 revision, else the submitted plan. The doc comment that says revisions cannot be recorded is corrected | `SubmitRevision` exists in M2, so the comment is stale and the total can be wrong | `visibility.rs`, `proposal/intake.rs` |
| D11 | Every read has a rule for every one of the 16 states. `can_read_content` lists each state. RANKED, DEFERRED and the terminal states admit only the applicant team, and RANKED admits no committee or coordinator content read (Q39). The M2 audit's 1,436 unjudged RANKED reads become judged refusals | The matrix reference needs a rule in every state | `visibility.rs`, testkit `reference/review.rs` |
| D12 | The call projection gains a typed effective-limits record per published call for P-05 and P-13: the publication snapshot plus every later tightening (NOTE 7, O-52). Built only if Q37 is answered C | The Guide plus its corrigenda must equal the effective limits (I-51) | `programme.rs`, `policy/mod.rs` |
| D13 | `fstp-engine/src/sweep.rs`: a pure function from engine state and `now` to the due system commands, `ExpireStage2` at the P-07 deadline and `ReEnter` when a next call opens. The cell runs it on its clock as `Actor::System`. M6's timeline engine replaces it | R-EV-07 holds in M4 cells, where nothing else issues these kinds | `fstp-engine/src/sweep.rs` |

The live SoD check in creator step 9 reuses the pure core. `preview_grant` calls the vault queries and the SoD guards and appends no domain record. Each vault answer is recorded in the audit log as a query digest and the answer bit (`overview.md` NOTE 5), and previews are rate-limited per account and per draft (H-07). A refusal becomes `InviteeRefused` with the rule reference only, never an account (R-CF-03). `d3_preview_grant_equals_grant_on_activated_copy` is a property over generated states. For each invitation, `preview_grant` on the draft equals the `GrantRole` decision on a copy of the state where the programme is `Active`.

**D8 file list.** Every Rust file that issues `CreateProgramme` today:

- `fstp-domain-testkit/src/gen/{money,policy,review,roster}.rs`, `src/mc/{findings_model,life_model}.rs`, `src/reference/policy.rs`;
- `fstp-domain-testkit/tests/i12_mcp_binding_reads_the_frozen_p77.rs` and `tests/i12_policy_validation.rs`;
- `fstp-domain/tests/{interface_stubs,codec_round_trip,review_api_sufficiency,review_spec_fidelity}.rs` and `tests/codec_support/mod.rs`;
- `fstp-engine/fuzz/fuzz_targets/decide_sequence.rs`.

The testkit has no `Scenario::programme()`. Setup code builds programmes through `Scenario::execute`. The new helper is `fstp-domain-testkit/src/activation.rs`, with `activate(scenario, programme, approver)`.

**D8 sequencing.** No suite goes red between lanes.

1. W1b lands D1, D2 and D3 together with the setup changes in one commit. Until D2e lands, `activate` issues core `ActivateProgramme` by a second admin through `Scenario::execute`. The engine still accepts that path.
2. W2e lands D2e. In the same commit, W2e takes ownership of `activation.rs` and switches `activate` to `fstp_engine::Command::Creator(ApproveActivation)` over a minimal synthetic spec. `fstp-creator` exists by then (W2a). Domain-level tests keep calling `fstp_domain::decide` with core `ActivateProgramme`, which D2e does not touch.
3. `fstp-creator` takes no dev-dependency on `fstp-domain-testkit`, so no cycle arises.

### 3.5 Tenant onboarding (`fstp-tenant`)

```rust
pub enum OnboardingStep { Organisation, Agreements, Branding, DomainsAndEmail, Identity, Inference, Payments, Channels, Administrators }
pub enum StepStatus { Open, Saved, Validated, Unavailable { milestone: &'static str } }
pub enum TenantCommand { SaveStep { step: OnboardingStep, values: StepValues, base: TenantRevision },
                         InviteAdmin { invitation: InvitationId },                 // high-risk: grants tenant admin
                         ApproveSelfGrant { approval: ApprovalId, grant: GrantRef }, // SoD-07, high-risk
                         SetSetting { param: TenantParam, value: SettingValue },    // high-risk, one op per parameter
                         RecordInferenceConfig { config: LlmConfigId, primary: ModelRef, fallbacks: Vec<ModelRef> } }
/// Settable in M4: P-20, P-69, P-70, P-71, P-72, P-74. P-73 and P-78 have no variant.
pub enum TenantParam { P20, P69, P70, P71, P72, P74 }
pub enum TenantRecord { StepSaved { .. }, StepValidated { .. }, AdminInvited { .. }, AdminAdded { .. },
                        SelfGrantApproved { .. }, SettingChanged { param, value, by }, InferenceConfigRecorded { .. } }
```

- **Order.** Each step validates before the next opens. The tenant can save and return at any time.
- **Control plane and cell (Q22).** Organisation and Agreements start in the control plane, because the SaaS contract is between CrabNebula and the tenant. The control plane keeps the legal entity, billing address, contracting signatory and agreement acceptance. The cell keeps the data protection contact and contract signatories. The agreement texts carry `TODO(legal)` until Daniel supplies them.
- **Operator review (TH-46).** Before a SaaS cell is provisioned, CrabNebula operator staff review the tenant's identity in the control plane. `fstp-signup` records the outcome and the reviewer. Provisioning refuses without an accepted review. This happens in the control plane, so operator staff still hold no roles in the cell (SoD-08).
- **Administrators.** The first admin enrols through a one-time link from the control plane. Self-hosted cells print an enrolment token at first start, with no default credentials (R-NF-05). The second admin is invited from the cell. Inviting an admin grants tenant admin, so it is high-risk with step-up (`authentication.md`). Each admin logs in with a phishing-resistant method (I-77) and verifies identity through the vault, so the I-67 Sybil check can apply (Q2). The admin set is recorded in the cell ledger (Q31, blocking).
- **Tenant defaults.** The Identity step records default values for P-18 and P-45, and the Inference step records a default for P-21. They prefill new drafts and are never parameters themselves (section 3.1).
- **Inference configuration.** The Inference step also records an `InferenceConfigRecorded` entry: an `LlmConfigId`, its primary model and its ordered fallbacks. `call.publish` takes `config` and `config_model` from this record, never from the client. The engine composition refuses unless `config_model` equals the frozen P-21 primary, as M2's `PublishCall` already checks. The record is only data until the M7 assessor uses it.
- **Later machinery.** Branding offers the default package only (M9). Domains and email record the sending domain, and its check runs through the `Prober` (M6). Channels record configuration (M6, M8). Payments captures P-20 (M5). Each shows its state, and production validation fails closed where no prober exists (Q5).
- **Settings.** Every change is a ledger record and an audit entry. Every setting change is high-risk with step-up. `authentication.md` names login method changes (P-70). The others are high-risk by the strict reading, listed in `STRICT_EXTRA_HIGH_RISK` (section 3.6). P-71 may only shorten. P-73 (database mode) changes through the control plane under ADR-005, not in the cell. P-78 changes arrive with the MCP client in M5, as a high-risk action (`mcp-client.md`).

### 3.6 Access, channels and the registry (`fstp-access`)

```rust
/// Fields are private. Only the constructors below build a Principal, and only fstp-api-core calls them.
pub struct Principal { account: Option<AccountId>, tenant_admin: bool, method: Option<LoginMethod>,
                       phishing_resistant: bool, session: Option<SessionId>, via: Via,
                       agent: Option<AgentClientId>, scopes: ScopeSet, roles: RoleSet }
impl Principal {
    pub fn anonymous() -> Principal;
    /// From an M3 session; tenant_admin from the tenant admin set; roles from active bindings at `now`.
    pub fn web(s: &SessionPrincipal, admins: &AdminSet, state: &EngineState, now: Timestamp) -> Principal;
    /// From a validated token; strength inherited from the consenting session; scopes from the grant.
    pub fn mcp(t: &TokenGrant, admins: &AdminSet, state: &EngineState, now: Timestamp) -> Principal;
    // read-only accessors for every field
}
/// The kinds of role an account holds now, plus `Applicant` for an account acting with no binding yet.
pub struct RoleSet(BTreeSet<RoleOrApplicant>);

pub enum OpKind { Command(CommandKind), Creator(CreatorKind), Bridge(BridgeKind), Tenant(TenantKind),
                  Finding(FindingKind) /* Mark */, Import(ImportKind) /* RegisterDocument */,
                  Read(ReadKind), Agent(AgentKind), Pending(PendingKind), Public(PublicKind),
                  M3Port(PortKind) /* sessions, recovery and break-glass approvals, enrolment */ }

pub struct OpSpec {
    pub kind: OpKind,
    pub route: Option<(Method, &'static str)>,   // every human op has one web route
    pub tool: Option<ToolDef>,                   // the only tool table: fixed name, description and input schema
    pub high_risk: bool,                         // equals CommandKind::high_risk() for Command ops
    pub binding: bool,                           // equals CommandKind::binding_action() for Command ops
    pub session: SessionNeed,                    // Any | PhishingResistant (I-77)
    pub scope: Option<Scope>,
    pub acting: &'static [RoleOrApplicant],      // the roles through which the op can be performed (P-74)
    pub classification: Classification,          // Public | Confidential | Personal
}
pub struct ToolDef { pub name: &'static str, pub description: &'static str, pub input: &'static Schema,
                     pub scope: Scope, pub prepare_only: bool }
pub const OPS: &[OpSpec];
/// High-risk by the strict reading, beyond the authentication.md table: tenant settings other than P-70.
pub const STRICT_EXTRA_HIGH_RISK: &[OpKind];

/// Kinds that never arrive from a person: VaultChanged, ExpireStage2, ReEnter, ContractFact,
/// StartExecution, Complete, RecordDeliverable, ActivateAmendment. In M4 cells, the D13 sweep issues
/// ExpireStage2 and ReEnter; M3 issues VaultChanged; the rest arrive with M5.
pub const SYSTEM_ONLY: &[CommandKind];
/// Finding and import kinds that never arrive from a person: FindingCommand::Record and Regenerate
/// (the assessor, M7), ImportCommand::RecordProposals (the proposer, run by the shell).
pub const SYSTEM_ONLY_OTHER: &[OpKind];
/// Kinds only the engine composes from a creator decision: ActivateProgramme.
pub const COMPOSED_ONLY: &[CommandKind];
/// Kinds whose operations arrive in a later milestone, each with its milestone (M5 for grant and payment kinds).
pub const LATER: &[(CommandKind, Milestone)];

pub enum ChannelVerdict { Execute, Prepare, Deny(ChannelDenial) }
/// The only channel-specific function. Total and pure.
pub fn channel_policy(op: &OpSpec, p: &Principal, governing_p77: McpBindingActions, tenant: &McpSettings) -> ChannelVerdict;
```

`channel_policy`:

- `Via::Web`: `Execute`.
- `Via::Mcp`: `Deny(NotExposed)` without a tool, `Deny(Scope)` without the scope, and `Deny(P74)` when the tenant disabled MCP. `Deny(P74)` also applies when any role in `p.roles() ∩ op.acting` is outside the roles P-74 allows. This is the strict reading: an op that could act under a disallowed role is refused (Q42). Otherwise `Prepare` when `op.high_risk`, or when `op.binding` and the governing P-77 is "draft only". Otherwise `Execute`.
- A tool with `prepare_only: true` exists only for high-risk ops. `channel_policy` can never return `Execute` for it.

It reads nothing but its arguments: the op, the principal's channel, scopes and roles, the governing P-77 and the tenant's MCP settings. The matrix compares the MCP outcome with `channel_policy` applied to the web outcome.

Registry rules, tested in `fstp-access`:

- `ops_cover_every_command_kind_once`: each kind in `CommandKind::ALL` is in exactly one of a routed op, `SYSTEM_ONLY`, `COMPOSED_ONLY` or `LATER`. In M4 that is 37 routed, 8 system-only, 1 composed and 15 later kinds, for 61.
- `ops_cover_every_finding_and_import_kind_once`: `FindingCommand::Mark` and `ImportCommand::RegisterDocument` are routed; `Record`, `Regenerate` and `RecordProposals` are in `SYSTEM_ONLY_OTHER`. The test matches on each enum without a wildcard, so a new variant fails to compile until it is placed.
- `i66_no_route_or_tool_reaches_activate_programme`.
- `ops_high_risk_and_binding_follow_the_domain`: for each command op, `high_risk` and `binding` equal the domain's functions.
- `r_lg_03_high_risk_table_matches_authentication_md`: reads the high-risk table at test time and checks a hand-written row map in both directions. The map covers `tenant.invite_admin` (granting tenant admin), `tenant.set_login_methods` (login methods), `me.add_passkey` and `agents.consent` (linking a device), `admin.approve_break_glass`, `roles.grant`, `creator.approve_activation`, `creator.open_draft` and `call.publish`. Ops in `STRICT_EXTRA_HIGH_RISK` are high-risk too and are listed with their reason.
- `i85_every_high_risk_tool_is_prepare_only`: every tool whose op is high-risk has `prepare_only: true`, and the reverse.
- `i84_principal_has_no_public_fields`: a compile-fail twin builds a `Principal` with a struct literal.
- `i84_every_tool_has_a_web_route`: no tool exists without a web route ("No tool exists that the user's roles could not perform in the interface").
- `ops_tools_match_mcp_capability_table`: reads the capability table of `mcp-server.md` and checks a hand-written row map in both directions.

Reads, each a strict default:

```rust
pub enum ReadKind {
    ListOpenCalls, GetPublicCall, GetGuide,
    ListOwnProposals, GetOwnProposal, GetOwnWorkspace, GetOwnStage2Thread, GetOwnNotices, GetNegotiationLanding,
    ListMyAssignments, GetDeclarationView, GetContent, GetScoreSheet, GetStage2Thread, GetFindings,
    GetRankingView, GetCutOffRound, ListMyIrcCases, GetIrcCase, GetIntakeQueue, GetCallBoard,
    GetDraft, GetReport, GetPreview, GetImpact, ListImportProposals, ListInvitations,
    ListBindings, GetAuditLog, GetVaultOutcomes, ListMyAgents, ListMyAgentActivity, ListMyPendingActions,
    ListMySessions, ListNotifiableConflicts, ListApprovals, GetTenantSettings, GetOnboarding,
}
pub enum ReadRule { Public, Team, Lead, AssignedReviewer, Assignee, ContentReader, Holder(Role), CommitteeNotRecused,
                    IrcAssignee, DraftManager, Auditor, TenantAdmin, Own, AnyOf(&'static [ReadRule]) }
pub const READ_RULES: &[(ReadKind, ReadRule, &'static [StateTag])];
pub fn authorize_read(op: &ReadOp, p: &Principal, state: &EngineState, now: Timestamp) -> Result<ReadClearance, Denied>;
```

- **Every state has a rule.** `READ_RULES` lists, for each read, the states where it is open. The reference and `t_authz_matrix_covers_every_rule` check every read in all 16 states, so no state is unjudged (D11).
- **`GetContent`** always runs the domain `ReadContent` command first. So it is logged (R-AU-01), needs a `ReviewerAct` (I-03) and follows P-10 (R-AC-01). The text store releases content only against the resulting clearance.
- **Applicant reads are logged too (R-AU-01).** `GetOwnProposal`, `GetOwnStage2Thread` and the MCP applicant tools that return proposal content run `ReadContent` by the team, so each appends `ContentRead`. `GetOwnWorkspace` reads drafts, not proposal content, and appends a `WorkspaceRead` audit entry.
- **`GetDeclarationView`** shows the title and the applicant-written neutral summary before the declaration (Q9). It holds no other field.
- **`GetRankingView`** is for committee members. A row for a proposal where the viewer has a conflict fact shows "recused" without title or summary (Q16). It carries weighted scores per criterion (D9) and the requested total of the effective plan (D10). It has no findings field, as in M2.
- **`ListMyAgentActivity`** shows the caller's own audit entries made through one agent client, with operation, outcome and time.
- **`ListMySessions`** reads the M3 session port for the caller only (R-LG-04).
- **`GetIrcCase`** holds the nominated proposal reference and its outcome. It has no field for scores, ballots, rationale or tie-breaks (R-IR-03).
- **`GetOwnWorkspace`** admits the team only (I-21). Through MCP, it admits only the caller's own proposal.
- **`GetStage2Thread`** shows reviewers under P-11 handles. Applicants see question times at day granularity (TH-08, Q26).
- **`GetVaultOutcomes`** is for the Auditor only (`overview.md` NOTE 5) and is never an MCP tool (I-86).
- **`GetFindings`** is for assigned reviewers within P-10 and P-28. Through MCP with P-75 off, it returns kind, criterion, severity, confidence and evidence pointer ids, without `statement` (Q14).
- **No Judging read model carries an identity field (I-17).** Applicants appear as "Proposal" plus an id. Account display names and emails never enter a Judging read model.

### 3.7 API and dispatch (`fstp-api-core`)

```rust
pub enum Op { /* one variant per OpSpec, with its decoded request */ }
/// What an adapter extracted from the request. The adapter attests nothing.
pub enum Credential { None, SessionCookie(SessionToken), Bearer(AccessToken) }
/// Opaque: built only by fstp-cell from its ports; no accessor exposes them (rules A2, A2b).
pub struct ApiCore { /* private: Box<dyn CellPorts> */ }
impl ApiCore {
    pub async fn dispatch(&self, cred: Credential, head: &RequestHead, op: Op) -> Result<OpResult, ApiError>;
}
pub enum OpResult { Done { body: ReadModel, seq: Option<Seq> }, Pending(PendingReceipt),
                    StepUpRequired(StepUpChallenge), StrongMethodRequired }
/// Implemented by hand for identity-free read models only. Lives here, beside the read models.
pub trait McpSafe: ToJson {}

/// SHA-256 of the RFC 8785 text of { op, canonical request, target, tenant, account }.
pub struct ActionDigest([u8; 32]);

pub struct PendingAction { pub id: PendingId, pub account: AccountId, pub agent: AgentClientId, pub op: OpKind,
                           pub request: TextRef /* canonical request JSON */, pub digest: ActionDigest,
                           pub created: Timestamp, pub expires: Timestamp, pub status: PendingStatus }
impl PendingAction {
    /// Needs Via::Web, the same account, an open and unexpired action, `shown == digest`, and, for
    /// high-risk kinds, a proof for this digest within P-71. Executes the stored request with Via::Web.
    pub async fn confirm<P: CellPorts>(&self, ports: &P, p: &Principal, shown: ActionDigest) -> Result<OpResult, ApiError>;
}
```

`dispatch` runs these steps in order:

0. **Principal.** `ApiCore` resolves the credential through the M3 `Sessions` port or the `fstp-oauth` token store. It then builds the `Principal` with `Principal::web` or `Principal::mcp` from the attested admin set and the current snapshot. A missing or invalid credential gives `Principal::anonymous()`.
1. **Decode** the request with the operation's strict decoder, under limits. `json_struct!` types reject unknown members. Amounts decode through `fstp_money::amount_from_json`, so JSON numbers are refused (ADR-006). Free text goes to the M3 `TextStore` and travels on as a `TextRef`.
2. **Session strength.** `SessionNeed::PhishingResistant` refuses magic-link and OPAQUE sessions (I-77). MCP tokens inherit the strength of the session that consented to them.
3. **Channel.** `channel_policy`. `Deny` returns the refusal.
4. **Rate limits** per session, account, token and client.
5. **Dry run.** Commands go through `AsyncEngine::dry_run` with web semantics. A refusal returns now, before any step-up prompt or pending action. Every vault answer the dry run obtains is recorded in the audit log as a query digest and the answer bit, as `overview.md` NOTE 5 requires for each vault answer. If recording fails, the dry run refuses (fail closed). Dry runs that ask the vault have their own rate limit per account (H-07).
6. **Prepare.** For `ChannelVerdict::Prepare`, store a `PendingAction` with the canonical request and digest. Return `{status: "awaiting_confirmation", confirm_path, expires}`.
7. **Step-up.** For high-risk ops through the web, `StepUp::take(session, digest, now)` must return a proof younger than P-71 for this digest. The proof is consumed. Otherwise return `StepUpRequired` with a challenge bound to the digest. An account with no phishing-resistant method gets `StrongMethodRequired`, and the client sends the user to add a passkey first (`authentication.md`).
8. **Execute.** Commands go to `AsyncEngine::execute` with `ExecMeta`. The domain re-runs every guard. It also refuses `Via::Mcp` with high-risk commands (`RuleRef::I85`) and draft-only binding commands (P-77), as a second line. Reads go to `authorize_read`, then the read model.
9. **Audit.** One entry per call, accepted or refused, with the user, the channel, the agent client for MCP, the operation, the outcome rule and the request digest. It commits in the same transaction as any ledger append (section 6.1).
10. **Classify** the result for MCP.

`ApiError` maps a domain `Refusal` to a stable code and the rule text only, such as `{"code":"refused","rule":"I-03"}`. It never names an account (`overview.md` NOTE 5, R-CF-03). `Ctx.tenant_admin` and `Ctx.second_tenant_admin` come only from the attested tenant admin set and a recorded `SelfGrantApproved` entry. Who owns that set is Q31, which blocks, because I-67 and SoD-07 rest on it.

### 3.8 MCP server and OAuth (`fstp-mcp`, `fstp-oauth`)

Transport and protocol:

- Streamable HTTP at `https://{tenant domain}/mcp` and `/mcp/public`. `POST` takes one JSON-RPC message and answers `application/json`. `GET` answers 405, so no server-initiated stream exists. `DELETE` ends the MCP session.
- The `Origin` header is checked against DNS rebinding. Native MCP clients send no `Origin`, so a request without one is accepted on the bearer token alone. `/mcp/public` holds no credential and serves only public data, so it also accepts a missing `Origin`. A present `Origin` must equal one of the tenant's own origins, or the request gets 403. A duplicated or unparsable `Origin` is refused. `Mcp-Session-Id` is 128 random bits from `fstp_crypto::random_bytes`, stored hashed.
- Methods: `initialize`, `notifications/initialized`, `ping`, `tools/list` and `tools/call`. No resources, prompts, sampling or elicitation in M4.
- The MCP revision is pinned in ADR-013 (Q8). I propose the 2025-06-18 revision as the floor. I believe it removed JSON-RPC batching, requires the `MCP-Protocol-Version` header after initialisation, and requires RFC 9728 metadata and RFC 8707 resource indicators. I believe a later revision changed client registration guidance, including client ID metadata documents. ADR-013 must check the published text before it is accepted.
- `serverInfo.name` is white-labelled (`mcp-server.md`) but carries no free text, so tenant text cannot reach agents as instructions (TH-63). It is the first label of the tenant's verified domain, matched against `^[a-z0-9][a-z0-9-]{0,30}$`. No `instructions` field is sent. `serverInfo.title` is not sent (Q43).
- Tool names, descriptions and input schemas are `const` data in the `OPS` registry of `fstp-access`, the only tool table. `fstp-mcp` serves `fstp_api_core::meta::tools()` and defines no tool of its own (TH-63).

```rust
// fstp-mcp
pub struct McpResponse { classification: Classification, data: Value, untrusted: Vec<JsonPointer> }
impl McpResponse { pub fn new<T: fstp_api_core::McpSafe>(c: Classification, v: &T) -> McpResponse; }
```

- **Results.** The read model goes in `structuredContent.data`, with `classification` and `untrusted`, the JSON pointers to user-supplied text. User text sits only inside `data`. The `content` text block is a fixed sentence naming the classification. It never holds user text (TH-60).
- **Tools in M4,** limited to the capability table of `mcp-server.md` (Q8):

  | Role row | Tools |
  | --- | --- |
  | Applicant | `fstp_list_open_calls`, `fstp_get_guide`, `fstp_list_my_proposals`, `fstp_get_my_proposal`, `fstp_save_workspace`, `fstp_record_plan_version`, `fstp_submit_proposal` (binding), `fstp_get_stage2_questions`, `fstp_answer_stage2` (binding), `fstp_submit_revision` (binding), `fstp_list_notices` |
  | Reviewer and committee | `fstp_list_assignments`, `fstp_get_score_sheet`, `fstp_record_score` (binding), `fstp_correct_score` (binding), `fstp_record_ranking_summary` (binding), `fstp_get_ranking_view`, `fstp_get_findings`, `fstp_get_proposal_content` (refused by D6 unless P-75 is on) |
  | Programme staff | `fstp_creator_get_draft`, `fstp_creator_get_report`, `fstp_creator_save_fields`, `fstp_draft_call`, `fstp_edit_call`, `fstp_get_call_board`, `fstp_prepare_call_publication` (prepare-only, high-risk, Q32) |
  | Auditor | `fstp_audit_list_entries` |
  | Anyone, without an account | `fstp_public_list_open_calls`, `fstp_public_get_call`, `fstp_public_get_guide`, `fstp_public_get_deadlines`, `fstp_public_get_eligibility`, `fstp_public_list_funded`, `fstp_public_list_finished`, `fstp_public_get_programme` |

  The pre-check (P-23) arrives with M7. Grantee and finance rows arrive with M5. Timeline, reminder and reporting tools arrive with M6 and M9.

  I-85 says an agent can prepare high-risk actions. The capability table gives programme staff "call drafting", and publishing a call is the one M4 high-risk action that row reaches. So `fstp_prepare_call_publication` is a prepare-only tool. It always yields a pending action, which only the user can confirm in the platform with a step-up. Every other high-risk op has no tool and gets `Deny(NotExposed)`. Prepare-only tools for tenant admin operations would need a new capability row, which Q32 asks about.
- **Applicant reads through MCP** append `ContentRead`, as through the web (R-AU-01). `fstp_get_my_proposal` runs `ReadContent` by the team, which D6 admits whatever P-75 says.
- **Agent attribution.** Every audit entry for an MCP call records the agent client next to the user.

OAuth 2.1:

- Protected resource metadata (RFC 9728) at `/.well-known/oauth-protected-resource`. Authorisation server metadata (RFC 8414) at `/.well-known/oauth-authorization-server`. A missing token gets 401 with `WWW-Authenticate: Bearer resource_metadata="..."`.
- `/oauth/authorize`: authorisation code with PKCE `S256` only. The `resource` parameter must equal this cell's MCP URL. Redirect URIs match exactly, except the port of loopback URIs for native clients (RFC 8252). The URL parser accepts a strict subset and rejects userinfo, fragments and non-ASCII hosts.
- The consent page lists every scope in fixed plain-language text. It shows the client name as untrusted text with an "unverified" label, and the redirect host. Approving links a device, so it needs a step-up (I-78). A magic-link session therefore cannot connect an agent.
- `/oauth/token`: authorisation code and refresh grants. Codes are single use and live 60 seconds. Access tokens live 10 minutes. Refresh tokens rotate, reuse revokes the family, and the family never outlives the P-72 absolute lifetime (Q25).
- `/oauth/register`: dynamic registration (RFC 7591), rate-limited. A client has no rights until a consent. Client metadata documents fetched from URLs are off, because the cell would fetch arbitrary URLs (Q8).
- `/oauth/revoke` (RFC 7009) and `POST /api/v1/me/agents/{client}/revocation` take effect at once (R-MC-03).
- Tokens are 256-bit values from `fstp_crypto::random_bytes`, stored as SHA-256 hashes and compared with `constant_time_eq`. They are bound to account, client, scopes, audience and cell. Roles are re-evaluated on every call, so no token outlives a role.
- Scopes issued in M4: `calls:read`, `proposals:read`, `proposals:draft`, `proposals:binding`, `stage2:draft`, `review:read`, `review:draft`, `ranking:read`, `findings:read`, `creator:draft`, `calls:draft`, `audit:read`. Each has consent text. A scope never adds a right that the roles lack.

### 3.9 Frontend (`web/`)

- **Layout.** `web/src/core/` holds `dom.ts`, `router.ts`, `store.ts`, `api.ts`, `i18n.ts`, `a11y.ts`, `money.ts`, `forms.ts` and `stepup.ts`. Feature folders are `web/src/{onboarding,creator,people,calls,applicant,coordinator,reviewer,committee,irc,admin,auditor,agents}/`. Generated code is in `web/src/gen/api.ts`. Tests are in `web/test/` and `web/e2e/`.
- **Compiler.** tsc with `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes` and `noImplicitOverride`. Target and module ES2022. Output is native ES modules in `web/dist/`, with no bundler and no runtime dependency.
- **DOM.** `dom.ts` offers `h(tag, attrs, children)` with tag and attribute allowlists. Text goes in through `textContent` only. URLs go through `safeUrl`, which allows same-origin paths and `https:`. The page sets `require-trusted-types-for 'script'` with one policy that refuses every HTML string. The source scan blocks the banned sinks.
- **Parsers in TypeScript, kept few and fuzzed.** These TypeScript modules parse input: `money.ts` (ADR-006 strings), `dom.ts` `safeUrl` (URLs), `router.ts` (paths against generated segments), the generated structural validators in `gen/api.ts` (server JSON after `JSON.parse`), and `i18n.ts` (message placeholders). Each has a target in the in-house harness `web/fuzz/` (section 9, Q33). Where a Rust parser exists for the same grammar, a differential test runs both on the same corpus: `money.ts` against `fstp-money`, and `safeUrl` against the `fstp-oauth` URL parser's subset.
- **Money.** `money.ts` handles ADR-006 strings only. The browser never computes money. Totals and P-04 checks come from the server.
- **Step-up.** On `step_up_required`, `stepup.ts` runs the M3 WebAuthn ceremony for the challenge's digest and retries once. On `strong_method_required`, it sends the user to add a passkey first, which is itself a high-risk action under M3's enrolment rules.
- **Desktop client seam (M9).** The Tauri client in `desktop-client.md` cannot use the `__Host-` cookie, the `Origin` rule or this CSP. It will sign in as an OAuth 2.1 native public client through `fstp-oauth`, with PKCE and a loopback redirect. "Signing in the desktop client" is a high-risk step-up (`authentication.md`). It then calls `/api/v1` with a bearer token as `Via::Web`, since it shows the same interface. That token has its own audience, so an MCP token can never act as a desktop token (RFC 8707 binding). Bearer requests need no CSRF defence. ADR-014 records this seam. M4 builds none of it.
- **Shell and assets.** `/app/` serves a shell with one `<script type="module">` and no inline script. Assets are at `/app/assets/{sha256}.js`, immutable, verified by `fstp-web-assets` at start.
- **Headers on `/app`.** `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types fstp-dom`. Also `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin` and HSTS.
- **CSRF.** M3's `__Host-` session cookie with `Secure`, `HttpOnly`, `SameSite=Strict` and `Path=/`. State-changing requests need `Origin` equal to the tenant origin and an `X-FSTP-Request: 1` header.
- **Accessibility (R-NF-03).** Landmarks, labelled controls, error summaries linked to fields, visible focus, live regions, keyboard reachability, no colour-only state, reduced motion.
- **Localisation (R-NF-04).** Catalogues per locale. Interface strings are `Label`. Approved wording is `ApprovedText` and never overridable (I-72 seam).
- **Footer.** Every page shows the privacy notice, the accessibility statement and the platform attribution (P-68, R-WL-04, I-69 seam). It also shows the AI disclosure where findings appear, the Data Act information for tenant admins, and the funder visibility elements that the funder profile requires. The shell takes a `MandatoryElements` value with no optional fields. The privacy notice, accessibility statement, Data Act information and funder visibility texts carry `TODO(legal)` until Daniel supplies approved wording. The Horizon Europe visibility elements are not quoted here from memory.

### 3.10 Public pages and the Guide (`fstp-public`, `fstp-guide`)

```rust
pub struct PublicView { pub programme: PublicProgramme, pub open_calls: Vec<PublicCall>,
                        pub funded: Vec<PublicGrant>, pub finished: Vec<PublicGrant>,
                        pub aggregates: Vec<PublicAggregate>, pub as_of: Seq }
/// The only constructor and the only filter (I-41, I-42, I-43, P-54). It takes the core state only,
/// so fstp-public has no path to findings (rule A4). The caller passes `&snapshot.core`.
pub fn public_view(core: &fstp_domain::State, programme: ProgrammeId, texts: &PublicTexts, now: Timestamp) -> PublicView;
pub fn render_html(view: &PublicView, page: PublicPage, chrome: &Chrome) -> HtmlDocument;
pub fn feed(view: &PublicView) -> fstp_json::Value;                        // P-52
pub fn select(view: &PublicView, q: PublicQuery) -> fstp_json::Value;      // the public tools
```

- **The filter.** Only proposals that reached GRANTED appear (I-41). No minor appears (I-42). A grant shows at the lower of P-50 or P-51 and the grantee's current choice, and is hidden with no choice (I-43). Aggregates appear only over at least P-54 grants (R-PB-05). Summaries come only from grantee-approved texts, never proposal text (R-PB-03). `PublicTexts` holds only `TextClass::Public` texts.
- **No choices in M4.** The grantee choice record arrives with M9. So every grant is hidden, and `funded` and `finished` are empty in M4 cells. The filter is still built and tested over generated states that include GRANTED and later, with synthetic choice records in the testkit. I-41 to I-43 are supporting properties in M4 and are claimed in M9 (Q11).
- **Freshness.** Pages are rendered per request from the current engine snapshot. No cache exists, so a narrowing is visible on the next request (R-PB-02 AC).
- **Routes.** `/p/{slug}/`, `/p/{slug}/calls/{call}`, `/p/{slug}/calls/{call}/guide`, `/p/{slug}/funded`, `/p/{slug}/finished` and `/p/{slug}/feed.json` when P-52 is on. The CSP is `default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. No `/p` response sets a cookie, and the session cookie is ignored there (R-PB-04, TH-37).
- **Guide template.** `fstp-guide` parses `crates/fstp-guide/profiles/horizon-europe/guide.v1.md`. A test checks that it equals `SPEC/profiles/horizon-europe/guide-for-applicants.md` byte for byte. Placeholders such as `{{P-04.min}}` or `{{call.deadline}}` each have one resolver over the draft or frozen policy, the call record or programme artefacts. Parameter-bound text is not editable (I-51). The template is Markdown. `fstp-guide` parses only the subset the template uses (headings, paragraphs, lists, tables, emphasis and links), refuses anything else, and has its own fuzz target.
- **P-05 and P-13 in the Guide.** These two are live, not frozen (NOTE 7). Their resolvers read the call's publication snapshot (`policy.snapshot()`), never the live value, because "the Guide for Applicants shows that snapshot". A test edits the live P-05 after publication and checks that the Guide bytes do not change. A tightening after publication needs a numbered corrigendum (I-53). Q37 decides how M4 handles it.
- **Pre-check statement.** The template's "How to apply" section describes the pre-check when P-23 is enabled. No pre-check exists before M7, so `PrecheckUnavailable` fails validation in any cell without a `Precheck` port (Q38). The e2e cell provides a fake port whose every run returns a fixed "synthetic" result, so its Guide statement is true there.
- **Timeline table.** The template's `{{timeline.table}}` comes from the call record and frozen windows in M4. M6's timeline engine becomes its source later.
- **Legal wording.** The template marks two sections with `TODO(legal)`. Their status is pending, so `LegalWordingPending` fails validation (Q6). The end-to-end cell loads a profile variant whose wording reads "SYNTHETIC TEST WORDING. NOT LEGAL TEXT." That variant lives in `fstp-api-testkit/profiles/synthetic-wording/`, never in `fstp-guide`. It reaches `fstp-guide` only through a testkit implementation of `ProfileSource`. Rules A9 and A9b keep it out of production, and the shipped tree and the release binary are scanned for its marker.
- **Publication.** `PublishCall` and `GuidePublished { call, version: 1, digest }` are one entry (R-GA-01). The engine recomputes the validation report at publication and refuses unless it is clean, so I-52 holds when the Guide is generated (D2e). The digest is SHA-256 through `fstp-crypto` over the canonical document. The fold refuses a second `GuidePublished` for a call. A corrigendum is its own record kind (Q37). HTML only in M4, pending Q28 on the PDF.

---

## 4. Data model and storage

### 4.1 Where data lives

| Place | M4 contents | Never |
| --- | --- | --- |
| Cell application database, ledger (M3) | Envelope records: core, finding, creator, import, tenant | Identity attributes, bank details, free text, tokens |
| Cell application database, `mcp` and `api` schemas | OAuth clients, grants, code and token hashes, MCP sessions, pending actions | Token values, vault data |
| Cell application database, `workspace` schema | Private drafts, sealed per proposal through the M3 `Sealer` port: an AES-256-GCM data key per proposal, wrapped by a level 2 key with hybrid X25519 plus ML-KEM-768 (ADR-001 Uses, ADR-004 level 3) | Readable by anyone but the team (I-21) |
| Cell object store (M3) | Uploaded import documents and narrative texts, each under its own data key (ADR-004 level 3), Guide snapshots | Plaintext keys |
| Identity vault, separate cluster (I-83) | Stated country (R-NG-01), affiliations, the minor information Q23 decides, exclusion class definitions, proximity lists, verification and consent facts, tenant admin verifications | Proposal content, policy |
| Control plane | Tenant record, legal entity, agreement acceptances, enrolment links, cell routing | Tenant content, cell accounts |
| Memory only | Rate-limit counters and keys | Persisted or logged anywhere |

### 4.2 Ledger envelope

`fstp_engine::Command` gains `Creator`, `Bridge`, `Import` and `Tenant` variants. `Record` and `EnvelopeKind` gain `Creator`, `Import` and `Tenant`. Each follows ADR-007: canonical RFC 8785 body, a schema version per entry, free text behind `TextRef`, insert-only storage, structural replay and `verify_append_only` over the whole envelope.

```rust
pub struct EngineState { pub core: fstp_domain::State, pub findings: FindingStore,
                         pub creator: CreatorState, pub import: ImportStore, pub tenant: TenantState }
```

- The core `decide` never sees the other parts (I-10).
- The creator decide sees `core` read-only and gets import facts only as `CreatorInputs`.
- The import decide sees neither core nor creator.
- The bridge and the activation composition live in `fstp-engine` (`bridge.rs`, `compose.rs`).

### 4.3 Tables and migrations

Cell application database, in the M3 migration set at numbers M3 reserves:

```sql
-- 01xx_workspace.sql
CREATE SCHEMA workspace;
CREATE TABLE workspace.drafts (
  proposal   bytea NOT NULL CHECK (octet_length(proposal) = 16),
  section    text  NOT NULL CHECK (section ~ '^[a-z0-9_]{1,64}$'),
  revision   bigint NOT NULL CHECK (revision > 0),
  key_ref    bytea NOT NULL,                                   -- wrapped data key, ADR-004 level 3
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) <= 1048576),
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (proposal, section));

-- 01xx_mcp.sql
CREATE SCHEMA mcp;
CREATE TABLE mcp.clients (client_id bytea PRIMARY KEY, metadata text NOT NULL,   -- RFC 8785 text
  registered_at timestamptz NOT NULL, status text NOT NULL CHECK (status IN ('pending','active','revoked')));
CREATE TABLE mcp.grants (grant_id bytea PRIMARY KEY, account bytea NOT NULL, client_id bytea NOT NULL REFERENCES mcp.clients,
  scopes text[] NOT NULL, created_at timestamptz NOT NULL, step_up bytea NOT NULL, revoked_at timestamptz);
CREATE TABLE mcp.codes (code_hash bytea PRIMARY KEY CHECK (octet_length(code_hash) = 32),
  grant_id bytea NOT NULL REFERENCES mcp.grants, pkce_challenge bytea NOT NULL CHECK (octet_length(pkce_challenge) = 32),
  redirect_uri text NOT NULL, resource text NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz);
CREATE TABLE mcp.tokens (token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  grant_id bytea NOT NULL REFERENCES mcp.grants, kind text NOT NULL CHECK (kind IN ('access','refresh')),
  family bytea NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz, revoked_at timestamptz);
CREATE INDEX mcp_tokens_family ON mcp.tokens (family);
CREATE TABLE mcp.sessions (session_hash bytea PRIMARY KEY, client_id bytea NOT NULL, account bytea,
  protocol_version text NOT NULL, created_at timestamptz NOT NULL, last_seen timestamptz NOT NULL);

-- 01xx_pending.sql
CREATE SCHEMA api;
CREATE TABLE api.pending_actions (id bytea PRIMARY KEY, account bytea NOT NULL, client_id bytea NOT NULL,
  op_kind text NOT NULL, request_ref bytea NOT NULL, digest bytea NOT NULL CHECK (octet_length(digest) = 32),
  created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('open','confirmed','expired','discarded')), confirmed_seq bigint);
```

- **Roles.** The cell application role gets SELECT, INSERT, UPDATE and DELETE on `workspace`, `mcp` and `api` only. Updates are revocations, rotations and status changes. A retention job deletes expired rows. The ledger role keeps INSERT and SELECT only (ADR-007).
- **Exactly once.** A confirmation updates `api.pending_actions` with `WHERE status = 'open'` in the same transaction as the ledger append. Zero updated rows aborts the transaction.
- **Projections.** Creator, import, tenant, access and public projections are in-memory folds. They are checkpointed through M3's checkpoint mechanism and need no new tables.

Control plane (M3 runner):

```sql
CREATE TABLE cp.tenants (tenant_id bytea PRIMARY KEY, legal_name text NOT NULL, billing_address text NOT NULL,
  contracting_signatory text NOT NULL, status text NOT NULL, cell_id bytea, created_at timestamptz NOT NULL);
CREATE TABLE cp.agreement_acceptances (tenant_id bytea NOT NULL REFERENCES cp.tenants, agreement text NOT NULL,
  version text NOT NULL, accepted_at timestamptz NOT NULL, accepted_by text NOT NULL,
  PRIMARY KEY (tenant_id, agreement, version));
CREATE TABLE cp.enrolment_links (tenant_id bytea NOT NULL, link_hash bytea PRIMARY KEY,
  expires_at timestamptz NOT NULL, used_at timestamptz);
```

CrabNebula is controller for this account data (`05-compliance/gdpr.md`). The cell learns the legal entity name and agreement versions only.

### 4.4 Export mapping (M9 seam)

New records map to files that `SPEC/schemas/README.md` already names: creator and import records to `programme-drafts/`, OAuth grants and revocations to `agent-clients.ndjson`, Guide versions and corrigenda to `guides/`, and the default branding choice to `branding/`.

The schema names no home for onboarding records, tenant settings, the tenant admin set or the inference configuration record. `branding/` holds the white-label package, so it is the wrong home. I stage a spec proposal for a new `tenant.ndjson` file with these records. `llm-configs.ndjson` already exists for the inference configuration.

Token hashes and pending action requests are not exported. Like integration credentials, they are secrets or transient state, not tenant data.

Workspace drafts are an open conflict. R-TD-01 and I-22 call for every exportable record, so an export plus import should restore them. I-21 says drafts are not readable by operator roles, and a tenant export is read by tenant admins. This design builds neither choice and asks Q40.

The mapping is for the M9 tool and goes through the file interface only, with no EUPL code linked (R-TD-03).

---

## 5. Security design

### 5.1 Threats M4 must close

| Threat | M4 response | Test |
| --- | --- | --- |
| TH-03 second account on both sides | SoD-09 at every grant; `SameIdentityAsAny` at activation (Q2) | `i67_sybil_builder_and_approver_refused` (T-SOD-SYBIL) |
| TH-04 undeclared conflicts or collusion | Declaration screens before every content read (J5, J6, J8); the declaration view holds title and neutral summary only; vault conflict check at every `ReadContent`; IRC review | `r_cf_02_declaration_precedes_every_content_read`, matrix rows for conflicted reviewers (T-SOD-CONFLICT) |
| TH-05 tenant admin self-escalation | SoD-07 for self-grants, with `admin.approve_self_grant` by a second admin; no content read rule for tenant admins in `READ_RULES`; every content read is a `ReadContent` record | Matrix rows tenant admin × every content op (T-AUTHZ-MATRIX), `sod07_self_grant_needs_second_admin_approval` |
| TH-06 cross-tenant leakage | Per-cell processes and databases; rate-limit keys and caches per cell | `i87_two_cells_never_cross` (T-ISO) |
| TH-07 identity through metadata | No attachments in M4 (Q24); Judging read models have no identity field | Canary scan over web read models for Judging roles (T-PRIV-CANARY) |
| TH-08 reviewer de-anonymisation | Handles per proposal; day-granular question times for applicants (Q26) | `r_an_01_stage2_thread_shows_only_handles`, `th08_question_times_are_day_granular` (T-PRIV-ANON) |
| TH-15 supply chain | Node.js, tsc and Playwright at build and test time only, pinned, lockfile gate, `--ignore-scripts` | CI gate |
| TH-16 malicious uploads | Media allowlist, size limit, strict UTF-8, fuzzed normaliser, no extraction in M4 | `import_text_decode` (T-FUZZ-UPLOAD) |
| TH-17 policy change after publication | M2 I-12 unchanged; the R-PG-04 impact view; edits stay `EditPolicy` records; Guide resolvers read the P-05 and P-13 snapshot | M2 I-12 suite, `r_pg_04_impact_matches_reference`, `i51_live_p05_edit_leaves_guide_bytes_unchanged` (T-POLICY) |
| TH-18 operator insider access | Break-glass approval screen for tenant admins, high-risk and web only; M3 owns the flow (J10, Q41) | Matrix rows for `admin.approve_break_glass` (T-BREAKGLASS seed) |
| TH-27 partner reviewers favouring their constituencies | The assignment screen runs SoD-10 and SoD-11 at `Assign` and shows pass or fail only; the vault proximity query is the only source | `th27_assignment_refused_on_proximity_and_org_count` (T-SOD-ASSIGN) |
| TH-26 parser defects | A fuzz target per parser from its first commit (section 9) | T-FUZZ-* targets |
| TH-35 public disclosure of applicants | `public_view` filter, tested in every state | `i87_*`, `i41_i42_*` (T-PUB-LEAK) |
| TH-37 visitor tracking | No scripts, cookies or third-party assets on `/p` | `r_pb_04_public_routes_set_no_cookie_and_load_no_script` (T-PUB-PRIVACY) |
| TH-45 branding injection | Default theme only; no tenant style, markup or script path; strict CSP and Trusted Types | `i68_no_tenant_markup_route` (T-WL-INJECT seed) |
| TH-46 tenant impersonating another organisation | Operator review of the SaaS tenant's identity before provisioning (J0); no custom domains in M4 | `th46_provisioning_refused_without_operator_review` (T-WL-DOMAIN seed) |
| TH-49 template carrying phishing links | Shipped and tenant templates apply no narrative silently (`AcceptNarrative`). Every link in template text shows as plain text with its full URL and host, never as an active link, until the manager accepts the field. Message templates follow the same rule. No cross-tenant templates in M4 (Q17) | `th49_template_links_shown_as_text_until_accepted` (T-PG-TEMPLATE seed) |
| TH-47 injection through an imported document | Data channel only; `UntrustedValue`; strict per-field decoding; per-value human confirmation (I-65) | `i65_injected_annex_changes_no_value_without_confirmation` (T-PG-IMPORT) |
| TH-55, TH-56 phishing and session hijack | M3 phishing-resistant login; step-up bound to the action digest and consumed on use; weak sessions end when an account receives a management role | Matrix login and step-up dimensions (T-AU-ROLES, T-AU-STEPUP), `i77_grant_ends_weak_sessions` |
| TH-57 recovery abused to take over a management account | Recovery approval screen for a tenant admin other than the holder, high-risk and web only; M3 owns the I-79 flow (J10, Q41) | Matrix rows for `admin.approve_recovery` (T-AU-RECOVERY seed) |
| TH-60 injection through MCP content | Delimited `data` fields, `untrusted` pointers, classification, no user text in `content`, P-75 off by default | `th60_untrusted_text_only_under_data` (T-MC-INJECT) |
| TH-61 stolen MCP token | 10-minute hashed tokens, audience binding, rotation with reuse detection, step-up to connect, revocation, roles checked per call | M-OAUTH, `th61_refresh_reuse_revokes_family` (T-MC-TOKEN) |
| TH-62 proposals to users' AI providers | D6 guard; the Guide shows `{{P-75.description}}` and `{{P-77.description}}` | `p75_off_refuses_content_through_mcp` |
| TH-63 tool poisoning | `const` tool definitions; `tools/list` bytes identical across tenants with hostile names | `th63_tool_list_is_byte_identical_across_tenants` (T-MC-POISON) |
| TH-66 public tools leaking | One `PublicView` | `i87_*` (T-MC-PUBLIC) |

### 5.2 Web and OAuth threats the threat model does not list yet

I propose these for `SPEC/06-threat-model/threat-model.md` with TH ids (Q26). The labels are local to this document.

| Label | Threat | Mitigation |
| --- | --- | --- |
| TW-1 | Cross-site request forgery on operations | `SameSite=Strict`, Origin check, custom header |
| TW-2 | Script injection through proposal or narrative text in the frontend | `textContent` only, source scan, Trusted Types, XSS canaries in Playwright |
| TW-3 | Clickjacking of consent and confirmation pages | `frame-ancestors 'none'` |
| TW-4 | OAuth redirect manipulation and open redirects | Exact match, strict URL parser, fuzzing |
| TW-5 | Authorisation code interception | PKCE S256 only, single-use 60-second codes |
| TW-6 | Token replay at another resource | Audience binding (RFC 8707), checked per call |
| TW-7 | DNS rebinding against `/mcp` | Origin validation |
| TW-8 | Consent phishing through a client name | Untrusted name, "unverified" label, redirect host shown, step-up |
| TW-9 | A pending action used to trick a user into confirming | Full canonical rendering, the agent named, untrusted text marked, digest-bound step-up, short expiry, no batch confirmation |

### 5.3 What a compromised component can still do

- A bug in `fstp-web` or `fstp-mcp` cannot build an engine command or reach a port (rules A1, A2 and A2b). It can send a wrong `Op` or credential to `ApiCore::dispatch`, which then authorises that op as itself.
- A bug in a read model can leak inside the classes that read is allowed. The canary scans are the test for that.
- A bug in `channel_policy` that executes instead of preparing still meets the domain's `RuleRef::I85` and P-77 refusals.

### 5.4 Credentials, logs and untrusted content

- No M4 crate calls moduletto directly, but M4 depends on it. Workspace drafts, import documents and narrative texts are sealed under ADR-004 level 3 data keys. ADR-001 wraps those keys with hybrid X25519 plus ML-KEM-768, and ML-KEM-768 comes from moduletto. So M4 uses the M3 `Sealer` and `TextStore` ports, and the hybrid rule (I-75) applies inside M3's implementation. Any cell release with M4 features carries the I-74 release gate for the exact moduletto version. Hashing, randomness and comparisons come from `fstp-crypto` (ADR-001 Tier A through aws-lc-rs). M4 adds no signature.
- Request logs hold the operation, outcome class, duration and refusal rule. They never hold arguments, bodies, tokens or IP addresses (R-NF-02). Every log line in the matrix run is captured and scanned for canaries.
- `UntrustedText` and `UntrustedValue` have no `Display`, `Deref<Target = str>` or `AsRef<str>`. No M4 code sends any text to a model.

---

## 6. Seams to earlier and later milestones

### 6.1 What M4 needs from M3

M4 is built against these traits in `fstp-api-core::port` and `fstp-engine`. `fstp-api-testkit` holds fakes for each, so M4 lanes start before M3 lands. If the M3 design names them differently, only `crates/fstp-cell/src/routes/m4.rs` changes. A contract test runs each fake and each M3 implementation through the same suite.

```rust
// Sessions and principals (authentication.md)
pub trait Sessions: Send + Sync { fn principal(&self, head: &RequestHead, now: Timestamp) -> impl Future<Output = Result<SessionPrincipal, AuthError>> + Send; }
pub struct SessionPrincipal { pub account: AccountId, pub session: SessionId, pub method: LoginMethod,
                              pub phishing_resistant: bool, pub tenant_admin: bool }

// Step-up (I-78), bound to one action digest and consumed on use
pub trait StepUp: Send + Sync {
    fn begin(&self, s: SessionId, action: ActionDigest) -> impl Future<Output = Result<StepUpChallenge, StepUpError>> + Send;
    fn finish(&self, s: SessionId, response: &[u8]) -> impl Future<Output = Result<StepUpRef, StepUpError>> + Send;
    /// A proof for exactly this digest and session, younger than P-71 at `now`. Consumed.
    fn take(&self, s: SessionId, action: ActionDigest, now: Timestamp) -> impl Future<Output = Result<StepUpProof, StepUpRequired>> + Send;
}

// Accounts: invitations, enrolment, pseudonymous display handles only
pub trait Accounts: Send + Sync {
    fn invite(&self, kind: InviteKind) -> impl Future<Output = Result<InvitationLink, AccountError>> + Send;
    fn display_handle(&self, a: AccountId) -> impl Future<Output = Result<DisplayHandle, AccountError>> + Send;   // never an email
}

// Vault: the M2 oracle answers, async, plus write-only intake and two proposed one-bit queries (Q35, blocking).
// Every answer, including those of dry runs and previews, is recorded through VaultAudit (overview.md NOTE 5).
pub struct VaultBound<T>(T);   // no Debug, Display, ToJson or Clone; consumed only by the M3 vault client
pub trait Vault: AsyncIdentityOracle {
    fn state_country(&self, a: AccountId, p: ProposalId, c: VaultBound<CountryCode>) -> impl Future<Output = Result<Receipt, OracleDown>> + Send;
    fn declare_affiliations(&self, a: AccountId, p: ProposalId, d: VaultBound<Affiliations>) -> impl Future<Output = Result<Receipt, OracleDown>> + Send;
    fn declare_minor(&self, a: AccountId, p: ProposalId, under_18_at_deadline: VaultBound<bool>) -> impl Future<Output = Result<Receipt, OracleDown>> + Send;
    fn begin_verification(&self, purpose: VerificationPurpose, a: AccountId) -> impl Future<Output = Result<VerificationRedirect, OracleDown>> + Send;
    fn classes_defined(&self, programme: ProgrammeId, classes: &ExclusionClasses) -> impl Future<Output = Result<Answer, OracleDown>> + Send;
    fn proximity_lists_declared(&self, programme: ProgrammeId, orgs: &BTreeSet<OrganisationId>) -> impl Future<Output = Result<Answer, OracleDown>> + Send;
}

// Async driver over the M2 pure functions, with a dry run
pub struct ExecMeta { pub via: Via, pub session: Option<SessionId>, pub agent: Option<AgentClientId>,
                      pub op: OpName, pub request: ActionDigest, pub step_up: Option<StepUpRef>,
                      pub pending: Option<PendingId>, pub second_tenant_admin: Option<AccountId> }
pub trait AsyncEngine: Send + Sync {
    /// Queries, vault answers, decide, then one transaction: ledger batch, audit entry, pending status.
    fn execute(&self, cmd: fstp_engine::Command, ctx: Ctx, meta: ExecMeta) -> impl Future<Output = Result<Seq, ExecError>> + Send;
    /// The same with no append and no audit entry for a commit.
    fn dry_run(&self, cmd: &fstp_engine::Command, ctx: Ctx) -> impl Future<Output = Result<(), Refusal>> + Send;
    fn snapshot(&self) -> Arc<EngineState>;
}

// Audit (I-24): one entry per call, in the same transaction as any append; refusals too
pub trait AuditSink: Send + Sync { fn record(&self, tx: &mut Tx, e: AuditEntry) -> Result<(), AuditError>; }
pub struct AuditEntry { pub actor: Option<AccountId>, pub via: Via, pub agent: Option<AgentClientId>, pub op: OpName,
                        pub outcome: Outcome, pub request: ActionDigest, pub step_up: Option<StepUpRef> }

// Free text and blobs, each under its own data key (ADR-004, ADR-007)
pub trait TextStore: Send + Sync {
    fn put(&self, class: TextClass, owner: TextOwner, bytes: &[u8]) -> impl Future<Output = Result<TextRef, StoreError>> + Send;
    fn get(&self, r: TextRef, clearance: &ReadClearance) -> impl Future<Output = Result<Vec<u8>, StoreError>> + Send;
    fn get_public(&self, r: PublicTextRef) -> impl Future<Output = Result<Vec<u8>, StoreError>> + Send;
}
pub trait BlobStore: Send + Sync { /* put and get, content-addressed, size-limited, per-object keys */ }

// Sealing under ADR-004 level 3 keys, hybrid-wrapped in M3 (ADR-001; I-74, I-75 apply to M3's implementation)
pub trait Sealer: Send + Sync {
    fn seal(&self, owner: SealOwner, plaintext: &[u8]) -> impl Future<Output = Result<Sealed, SealError>> + Send;
    fn open(&self, owner: SealOwner, sealed: &Sealed, clearance: &ReadClearance) -> impl Future<Output = Result<Vec<u8>, SealError>> + Send;
}

// Recording of vault answers that commit no command (dry runs, previews), as a query digest and the answer bit
pub trait VaultAudit: Send + Sync { fn record(&self, q: QueryDigest, answer: bool, epoch: VaultEpoch) -> impl Future<Output = Result<(), AuditError>> + Send; }

// Sessions and devices (R-LG-04), and the M3 approval flows behind J10 (Q41)
pub trait SessionsAdmin: Send + Sync {
    fn list(&self, a: AccountId) -> impl Future<Output = Result<Vec<SessionInfo>, AuthError>> + Send;
    fn end(&self, a: AccountId, s: SessionId) -> impl Future<Output = Result<(), AuthError>> + Send;
}
pub trait Recovery: Send + Sync { fn approve(&self, approver: AccountId, r: RecoveryId, proof: StepUpProof) -> impl Future<Output = Result<(), AuthError>> + Send; }
pub trait BreakGlass: Send + Sync { fn decide(&self, approver: AccountId, b: BreakGlassId, approve: bool, proof: StepUpProof) -> impl Future<Output = Result<(), AuthError>> + Send; }

// Pre-check provider (M7). Absent in M4 production cells, so PrecheckUnavailable fails (Q38).
pub trait Precheck: Send + Sync { /* defined by M7 */ }

// Tenant configuration (Ctx.tenant_admin, second-admin approvals, P-70 to P-74)
pub trait TenantConfig: Send + Sync {
    fn settings(&self) -> Arc<TenantSettings>;
    fn is_tenant_admin(&self, a: AccountId) -> bool;
    fn approval(&self, id: ApprovalId) -> impl Future<Output = Result<SecondAdminApproval, ConfigError>> + Send;
}
pub trait Outbox: Send + Sync { fn notices(&self, a: AccountId, page: Page) -> NoticePage; }
pub trait Prober: Send + Sync { fn probe(&self, p: ProbeKind) -> impl Future<Output = ProbeOutcome> + Send; }
pub trait Clock: Send + Sync { fn now(&self) -> Timestamp; }
pub trait Ids: Send + Sync { fn fresh<T: FromRaw>(&self) -> T; }   // fstp_crypto::random_array

// Control plane
pub trait Provisioner: Send + Sync {
    fn provision_cell(&self, t: TenantId) -> impl Future<Output = Result<CellRef, ProvisionError>> + Send;
    fn enrolment_link(&self, t: TenantId) -> impl Future<Output = Result<EnrolmentLink, ProvisionError>> + Send;
}
```

Requirements on the M3 design:

1. **One transaction** for the ledger batch, its audit entry and the pending-action status change. Without it, "at most one confirmation" needs another protocol.
2. **Digest-bound step-up,** consumed on use. `authentication.md` logs every step-up "with the action it authorised".
3. **Attested `Ctx`.** `tenant_admin`, `second_tenant_admin` and `binds_tenant_admin` come from the attested tenant admin set. Who owns that set is Q31, which blocks.
4. **Ending a binding ends sessions** that relied on it (`authentication.md`). MCP calls re-evaluate roles per call, so tokens need no hook.
5. **Vault intake** that never touches application tables, logs or metrics (R-NF-02, R-NG-01).
6. **Two new vault queries,** `classes_defined` and `proximity_lists_declared`, each one bit. The query set was decided on 2026-10-25, so they need your decision first (Q35, blocking). Until then they exist only in the synthetic vault, and production validation fails closed on the two checks that use them.
7. **The multi-cell harness** from M3's isolation tests, reused for `i87_two_cells_never_cross`.
8. **Migration numbers** reserved for M4 in the cell set.
9. **A synthetic vault service** with real query semantics for Playwright runs.
10. **Weak sessions end at a management grant (I-77).** When an account receives any Drafting, Judging, Operations or tenant admin role, M3 ends its OPAQUE and magic-link sessions in the same transaction. Its next login must be phishing-resistant.
11. **Strong method before the first high-risk action.** M3 enrolment lets an account without a phishing-resistant method add a passkey, under M3's rules for adding a passkey (`authentication.md`).
12. **`VaultAudit`.** Each vault answer that commits no command is recorded as a query digest and the answer bit (`overview.md` NOTE 5). The Auditor reads positive matches only (R-CF-03).
13. **Tenant admin verification.** A vault verification purpose `AdminIdentity`, so the I-67 Sybil check covers tenant admins (Q2).
14. **`Sealer`** for workspace drafts, with hybrid-wrapped data keys (ADR-001, ADR-004).
15. **`SessionsAdmin`, `Recovery` and `BreakGlass`** ports for the screens in J9 and J10 (Q41).

### 6.2 What M4 changes in M2

Section 3.4 lists D1 to D13. Each changes closed code, so W1b (and W2e for D2e and D13) runs every M2 suite before and after, and re-measures every tripwire of `m2-exit-audit.md`. The audit listed I-12 as open on Q-W6-3. `i12_frozen_edits_leave_call_outcomes_unchanged` now exists on `m2-domain-core`, but the audit table still says open. M4 starts the D-changes only once the M2 exit is green in CI with that test. M4 reuses `ACTOR_RULES` as the seed of the matrix reference only through its own independent reading of the spec. The reference never reads `ACTOR_RULES`.

### 6.3 Seams to later milestones

| Milestone | Seam M4 leaves |
| --- | --- |
| M5 | `LATER` lists the grant and payment kinds; their ops join `OPS` and the matrix. `fstp-api-identity` arrives as a web-only crate for identity release from NEGOTIATION on (`overview.md`), under rule A5. The PDF writer adds the Guide PDF if Q28 is answered so. MCP client crates sit outside the A1 adapter set. P-78 settings join `fstp-tenant` as a high-risk op (`mcp-client.md`) |
| M6 | The outbox records M4 enqueues (copy requests, notices, outcomes, IRC concerns) are dispatched, P-08 timing included (R-EV-04). The timeline engine replaces the D13 sweep. `{{timeline.table}}` switches source. Corrigendum notification for I-53 |
| M7 | `Proposer` gets the inference-backed implementation and sandboxed extraction for PDF. The `Precheck` port and pre-check tools join the applicant row, which clears `PrecheckUnavailable`. Findings fill `GetFindings` and the mark screen. The assessor uses the inference configuration record |
| M8 | Channel probers for Matrix and WhatsApp |
| M9 | Grantee choice records feed `public_view`; I-41 to I-43 are claimed. White-label packages replace the default theme under I-68 to I-70. Template publication (I-73) and the P-76 directory, if Q17 is answered so. The desktop client signs in through `fstp-oauth` as a native client (section 3.9). Export follows the Q40 answer and the proposed `tenant.ndjson` |

Compliance seams M4 leaves:

- **AI Act.** `ai-act.md` lists a reassessment trigger when a programme lets agents record scores (P-77) and reviewers delegate scoring to an AI system. M4 exposes `fstp_record_score` as a binding tool. So `AiActReassessment` is a warning that needs acknowledgement whenever P-77 is "allowed". The acknowledgement is a record for the AI Act file, not a legal conclusion (`TODO(legal)`).
- **DSA.** `dsa.md` ties online platform status to the cross-tenant directory (P-76), the public MCP tools and the template library. M4 ships per-cell public MCP tools. L-16 is open, so Q44 asks whether that changes the position.
- **Reviewer terms.** Terms for Judging roles state the programme's P-75 and P-77 choices through bound placeholders (`mcp-server.md`). Their wording carries `TODO(legal)`.
- **Notices and statements.** The privacy notice, accessibility statement, Data Act tenant information, data protection notices at submission and negotiation (R-NG-06), and funder visibility elements carry `TODO(legal)` markers until Daniel supplies approved wording.

---

## 7. Hosting on OVHcloud (decided 2026-10-28)

Daniel named OVHcloud as the hosting provider on 2026-10-28. ADR-005 records it in M3, together with the L-15 due diligence. M4 itself is provider-agnostic. The notes below are what the decision implies for ADR-005 and ADR-004, with each source and its reading date. "Unsure" marks what I could not confirm.

### 7.1 Implications for ADR-005

| Need | OVHcloud service | What the source says (read 2026-10-28) | Unsure |
| --- | --- | --- | --- |
| PostgreSQL 16, one database per cell | Public Cloud Databases for PostgreSQL | The capabilities page lists PostgreSQL 15, 16, 17 and 18. An indexed copy of the same page also listed 14 | Lifecycle dates for 16 |
| ADR-005 D2: `clientcert=verify-full` on every `hostssl` line, CN equal to the role, SCRAM-SHA-256-PLUS | Same | The TLS guide covers only the client verifying the server. The capabilities page says connections use TLS and access is limited by CIDR allowlists. It does not mention client certificates, SCRAM or `pg_hba` | Whether D2 is possible at all on the managed service. If not, D2 forces self-managed PostgreSQL |
| I-82 in shared mode | Same | The default `avnadmin` user "has extended rights (role and database creation, replication); it is not a superuser" | Whether `avnadmin` or the provider can read across databases of different cells |
| L-15 sub-processor chain | Same | `avnadmin` is the default administrator name of Aiven's managed databases. OVHcloud press releases from 2021 and 2022 announce a partnership with Aiven for its Database-as-a-Service offer. Neither says whether Aiven operates the service or reaches tenant data | Whether Aiven is a sub-processor of the managed PostgreSQL service. If so, L-15 must name it in every tenant DPA. Not confirmed |
| I-83: vault never on an application cluster | Separate managed services, or separate self-managed clusters | Public and private networking (vRack) are available for all offers | Isolation between services in one project |
| ADR-005 D3: hybrid database link | Same | Not stated | The OpenSSL version and TLS group settings of the managed build |
| EU regions only | All | The capabilities page lists regions including Beauharnois, Singapore, London and Mumbai, which are outside the EU | Sub-processor list per product (L-15) |
| Backups at an EU-owned provider | Object Storage, S3-compatible | The endpoints page lists European regions, among them Gravelines, Roubaix, Strasbourg, Paris, Milan, Frankfurt and Warsaw, beside London, Beauharnois, Toronto, Singapore, Sydney and Mumbai. The Object Lock guide offers Governance and Compliance retention modes and legal hold. Object Lock must be enabled when the bucket is created, and needs versioning. The compliance page marks retention and legal hold as supported in regions but not in Local Zones | Whether every EU region supports Object Lock, which the pages do not list per region. ADR-005 prefers a second EU provider for backups anyway. An S3 client is in-house M3 work with an XML parser that needs a fuzz target |
| Ingress without breaking R-NF-09 | Public Cloud Load Balancer | The concepts page lists listener protocols HTTP, HTTPS, TCP, UDP and SCTP. Its matrix lets a TCP listener forward to a TCP pool. The product page describes the HTTPS listener as passthrough, with TLS handled by the members, and `TERMINATED_HTTPS` as the terminating listener. The concepts page itself does not define passthrough | A TCP listener with a TCP pool appears to keep TLS end to end, so the cell keeps mutual authentication and the X25519MLKEM768 group. This needs a test against a real balancer before ADR-005 relies on it. Whether PROXY protocol is needed to keep client addresses for rate limits (Q19) |

Recommendation for ADR-005, which does not block M4: plan for self-managed PostgreSQL 16 on OVHcloud instances or bare metal in a vRack. Use one cluster for application databases and separate clusters for vault databases. Build it against OpenSSL 3.5 or later, so D3 can be met. Ask OVHcloud in writing whether the managed service supports client certificates per role and SCRAM-SHA-256-PLUS. Move to the managed service only if both are confirmed, the admin role cannot read across cell databases, and the Aiven question is settled for L-15. For ingress, use a TCP listener with a TCP pool so TLS ends in the cell. For backups, create buckets with Object Lock in an EU region whose support is confirmed in writing.

### 7.2 Implications for ADR-004

| Need | OVHcloud service | What the source says (read 2026-10-28) | Unsure |
| --- | --- | --- | --- |
| EU-operated KMS for root keys | OVHcloud KMS | Access "through open standards (KMIP and REST API)". Standard keys are "ISO 27001 and FIPS 140-3 Level 1 certified". Lifecycle events go to OVHcloud Log Data Platform | Whether a root key can be created as non-exportable. ADR-004 requires "created inside it and never exported" |
| HSM-backed keys | KMS on HSM | "Backed by Thales Luna HSM validated to FIPS 140-3 Level 3, EAL4+", with "progressive deployment in all regions" | Availability in the regions a cell uses |
| Key export | KMS BYOK | "Import and export key material without ever transmitting it in plaintext, using RSA key wrapping" | Whether export can be disabled per key. If not, I-80 rests on access policy alone |
| Reconciliation of root key use with the audit chain | Log Data Platform | Lifecycle events are logged | Whether every use, not only lifecycle events, is logged |
| CrabNebula-operated HSM over PKCS#11 | Managed HSM (OVHcloud Labs) | The Labs page lists a dedicated partition and a PKCS#11 driver, with an Alpha phase | Current status. A PKCS#11 client crate would join ADR-001 Tier A only after review |

Recommendation for ADR-004: use KMS on HSM over its REST API with mutual TLS as the EU-operated backend, once non-exportable creation is confirmed. The REST client and its JSON responses use `fstp-json`, with a fuzz target in M3. A KMIP client would need an in-house TTLV parser with its own fuzz target, so REST is the smaller surface.

Sources:

- [OVHcloud: PostgreSQL secure connection with TLS](https://docs.ovhcloud.com/en/guides/public-cloud/databases/postgresql-secure-connection-tls.md)
- [OVHcloud: Capabilities and limitations of Public Cloud Databases for PostgreSQL](https://docs.ovhcloud.com/en/guides/public-cloud/databases/postgresql-capabilities.md)
- [OVHcloud Key Management Service](https://www.ovhcloud.com/en/identity-security-operations/key-management-service/)
- [OVHcloud Labs: Managed HSM](https://labs.ovhcloud.com/en/managed-hsm/)
- [OVHcloud Labs: Shared HSM](https://labs.ovhcloud.com/en/shared-hsm/)
- [OVHcloud: Object Storage endpoints and geoavailability](https://docs.ovhcloud.com/en/guides/storage-and-backup/object-storage/s3-location)
- [OVHcloud: Object Storage, managing object immutability with Object Lock](https://docs.ovhcloud.com/en/guides/storage-and-backup/object-storage/s3-managing-object-lock)
- [OVHcloud: Object Storage compliance](https://docs.ovhcloud.com/en/guides/storage-and-backup/object-storage/s3-s3-compliancy)
- [OVHcloud: Load Balancer concepts](https://docs.ovhcloud.com/en/guides/public-cloud/network-services/load-balancer-concepts)
- [OVHcloud: Public Cloud Load Balancer product page](https://www.ovhcloud.com/en/public-cloud/load-balancer/)
- [OVHcloud press release: Aiven partnership for PaaS and DBaaS](https://corporate.ovhcloud.com/en/newsroom/news/aiven-partnership-paas-dbaas/)

The object storage, load balancer and Aiven rows were read on 2026-10-28 through search summaries and one direct page read (the concepts page). They need a direct read of each page before ADR-005 quotes them.

---

## 8. Test plan

### 8.1 Conventions

The M2 conventions carry over (m2-design 6.1):

- every test names the identifiers it verifies, in its name or doc comment;
- one `check`, `check_machine` or `fstp_mc::check` per test function;
- exhaustive model runs with `with_stop_when_decided(false)` and a `max_states` tripwire at twice the measured count;
- `reachable` witnesses in every model and two-way postconditions in every machine;
- independent references in the testkit, written from the spec text by a different agent from the one writing the code they check;
- start states built from genesis through production commands;
- one teeth test per model and machine, with faults injected through public parts or alternative adapters, never production hooks;
- synthetic fixtures only, shaped like the corpus variants (sybil, excluded affiliation, minor, repeat applicant). Canaries are generated strings such as `CANARY-ID-7f3a`.

TypeScript unit and property tests run on the in-house runner `web/test/runner.ts`, under the Node.js host (Q7).

### 8.2 Exit criteria other than invariants

**SuperSAFE built in the creator**

- `r_pg_01_supersafe_fixture_matches_policy_defaults` and `r_pg_01_supersafe_fixture_compiles_and_validates`. The second asserts a clean report under recording-fake probes and the synthetic wording profile.
- `r_pg_02_supersafe_built_through_creator_api`: A1 opens, M1 walks every step through `dispatch`, and the compiled draft equals the fixture in canonical form. A2 activates.
- `r_pc_03_builder_authorship_survives_activation`: M1, who set P-01, cannot approve the first call's publication.
- Playwright `web/e2e/creator/supersafe.spec.ts`: the same in the browser. It compares `GET /api/v1/programmes/{p}/draft` with the fixture.
- Playwright `web/e2e/creator/import.spec.ts`: a synthetic annex, every value resolved one by one before activation.

**Call cycle to NEGOTIATION**

- `e2e_supersafe_call_cycle_to_negotiation` in Rust runs J0 to J8 through `dispatch` on the fake cell, and later on `fstp-cell`. It asserts that X and V reach NEGOTIATION, Z is INELIGIBLE, W is NOT_SELECTED below the cut-off, and V without consent stays in IRC_REVIEW (I-18). It runs every M2 invariant check on the final ledger.
- `r_ev_03_exactly_75_percent_does_not_pass_through_the_interface`: Y in the second programme with the 0 to 4 scale.
- Playwright `web/e2e/cycle/supersafe_to_negotiation.spec.ts`: one browser context per person. Passkeys use the Chromium virtual authenticator. Deadlines pass through the `fstp-e2e-cell` clock route. A canary scan runs on every Judging page DOM.
- Playwright `web/e2e/cycle/supersafe_to_negotiation_via_agent.spec.ts`: an in-house TypeScript MCP client drafts the applicant steps. Under P-77 "draft only", the user confirms each binding action in the platform.

**Authorisation matrix**

- Defined in section 8.3.

### 8.3 Authorisation matrix

**Dimensions.**

| Dimension | Values |
| --- | --- |
| Operation | Every entry of `OPS`: 37 routed command ops, about 12 creator and bridge ops, about 10 tenant ops, the finding mark and import upload ops, about 40 reads, agent, pending, M3 port and public ops |
| Principal | Anonymous. Account with no binding. Tenant admin with and without a second admin. Each of the 14 roles of `Role::ALL`. Derived relations: lead, team member, guardian, assigned, released and conflicted reviewer, IRC assignee, recused and delegating committee member. Builder and non-builder on a draft. A role in another programme. Ended, suspended and voided bindings |
| State | Each of the 16 proposal states, built from genesis with `Scenario`; call drafted, approved, published open and published closed; programme Draft and Active; onboarding steps. Every read has a rule in every state (D11) |
| Policy | P-10 (three options), P-11, P-28, P-75 and P-77 (two each), P-74 on, off and role-limited. Full product for P-10 on read rows, a pairwise set for the others (Q34) |
| Session and channel | Passkey, magic link, OPAQUE; step-up fresh, stale (P-71 plus 1 µs) and absent; `Via::Web` and `Via::Mcp` with and without the scope |

The product of operation, principal and state is full, as `test-plan.md` requires for "every role, action and state combination".

**Reference.** `fstp_api_testkit::reference::authz::expected(op, principal, state, policy) -> Expected` returns `Allow`, `Pending` or `Deny(AuthClass)`. The classes are `Actor`, `Visibility`, `Conflict`, `Scope`, `P74`, `LoginStrength`, `StepUp`, `NotExposed` and `Draft`. It is written from the `roles-and-sod.md` roles table, the `state-machine.md` actor column, P-10 NOTE 1, the `mcp-server.md` capability table, the `authentication.md` high-risk list, P-11, P-74, P-75, P-77, I-17 and I-21. It shares only id types with production. It reads neither `ACTOR_RULES` nor `READ_RULES`.

**Two-way check.** For `Deny(c)`, the system refuses with a rule that maps to `c`. For `Allow`, it does not refuse with an authorisation rule. The generator builds valid inputs per cell, so guard refusals that depend on unrelated data, such as a wrong id, do not occur.

**Channels.** Every cell runs through `dispatch` directly, through HTTP routes over `fstp_rt::duplex`, and through the MCP JSON-RPC handler over `duplex` when the op has a tool.

| Test | Asserts |
| --- | --- |
| `t_authz_matrix_direct` | Every cell through `dispatch` equals the reference, both ways |
| `t_authz_matrix_http` | The same through HTTP |
| `i84_t_authz_matrix_mcp_equals_channel_policy_of_web` | For every tool cell, the MCP outcome equals `channel_policy` applied to the web outcome |
| `t_authz_matrix_covers_every_rule` | Every `OPS`, `READ_RULES` and actor-rule row appears at least once as allowed and once as denied |
| `t_authz_denial_has_no_effect` | Every denial leaves the ledger head, outbox, workspace, pending and token tables unchanged |
| `r_au_01_allowed_ops_record_the_act` | Every allowed command appends its record; every content read appends `ContentRead` |
| `t_authz_matrix_pg_sample` | A stratified sample of 2,000 cells on `PgRecordStore` over `fstp-pgtest` |
| `t_authz_teeth_extra_cell_is_caught` | A mutant registry grants one denied cell, and the matrix fails |
| `t_authz_teeth_missing_cell_is_caught` | A mutant denies one allowed cell, and the matrix fails |
| `t_authz_teeth_reference_flip_is_caught` | Flipping one reference cell fails the comparison |

**Cost, with every dimension.** The figures are estimates. W6 measures the real times as the M2 audit did.

| Factor | Size | Applies to |
| --- | --- | --- |
| Operation × principal × state | about 125 × 40 × 25 = 125,000 | Every channel |
| Login method | 3 | Account principals, about 39 of 40 |
| Step-up: fresh, stale, absent | 3 | High-risk ops only, about 22 |
| Scope present or absent | 2 | MCP cells of the about 36 tool ops |
| Policy rows | A covering array of 9 rows over P-10 and P-74 (three values each) and P-11, P-28, P-75 and P-77 (two each). Read ops also run every P-10 value at each row | Every op |

That gives about 500,000 session-expanded cells at one policy row, direct or HTTP, of which about 120,000 are reads. MCP adds about 216,000 cells. Over the 9 rows, the direct channel has about 3.4 million non-read cells and 3.2 million read cells.

At 0.2 ms per direct cell and 1 ms per duplex cell:

- direct, full session product, every policy row: about 22 minutes of CPU;
- HTTP and MCP, full session product, at the SuperSAFE policy row: about 12 minutes;
- HTTP and MCP at the other 8 rows, only for cells whose reference outcome depends on policy, estimated at a quarter: about 24 minutes.

That is about 58 minutes of CPU. Sharded over 4 cores in its own CI job, it takes about 15 minutes of wall time. The M2 job already takes 18 to 26 minutes of its 60-minute timeout (`m2-exit-audit.md`, Timing), so the matrix runs as a separate job with its own 60-minute timeout. Playwright is a third job.

The fallback, if measured time exceeds 30 minutes of wall time, first adds shards. Then it runs HTTP and MCP at the SuperSAFE row only, keeping every policy row in the direct channel. No operation, principal or state cell is ever dropped. That fallback changes what "full" means for the exit criterion, so it needs your agreement (Q34, blocking). Playwright samples one cell per operation and role. The full matrix stays in Rust.

### 8.4 Per exit invariant

**I-65**

| Test | Kind |
| --- | --- |
| `i65_creator_and_domain_cannot_reach_import` | Layering, rule A3 |
| `i65_import_proposals_never_alter_draft` | Twin machine. Twin B also receives `RegisterDocument` and `RecordProposals` for every field, with havoc values, injection phrases and profile conflicts. With no resolution, both twins have equal creator and core projections, and equal ledgers after removing import records |
| `i65_every_imported_value_has_named_pm_resolution` | Machine over proposals, resolutions by programme managers, non-managers, ended bindings and tenant admins, saves and activations. Every `Provenance::Import` field has a `ProposalResolved` by an account with an active programme manager binding at that instant |
| `i65_resolution_shown_digest_must_match` | Property: a stale or forged digest is refused |
| `i65_profile_conflict_is_flagged_never_adjusted` | Property, with P-05 400000.00 against a smaller synthetic P-58 (L-10 shape) |
| `i65_injected_annex_changes_no_value_without_confirmation` | Corpus-style direct and hidden injection documents (T-PG-IMPORT) |
| `i65_m_import` | Model M-IMPORT: `always("I-65")`, `transition("I-65")`. Witnesses: a confirmed value reaches the active policy; an edited value differs from its proposal |
| `i65_teeth_auto_applied_proposal_is_caught` | Teeth: an alternative bridge applies a proposal directly |
| `web/e2e/creator/import.spec.ts` | Every proposal shows its evidence span; activation stays unavailable while any is unresolved |

**I-66**

| Test | Kind |
| --- | --- |
| `i66_seeded_failure_never_activates` | Property: generated drafts with seeded failures from every `CheckId` of severity Failure; activation is refused and names the check |
| `i66_r_pg_01_cap_above_ceiling_names_both_values` | R-PG-01 AC |
| `i66_unacknowledged_warning_blocks_activation`, `i66_edit_after_report_voids_clearance` | Machine |
| `i66_probes_run_at_approval` | A probe that passes at request and fails at approval blocks activation |
| `i66_unresolved_import_is_a_failure`, `i66_pending_legal_wording_is_a_failure` | Pure (Q30, Q6) |
| `i66_fold_refuses_unpaired_programme_activated` | Engine fold (D2e) |
| `i66_execute_refuses_core_activate_programme` | Engine decider (D2e) |
| `i66_no_route_or_tool_reaches_activate_programme` | Registry |
| `i66_m_activate` | Model M-ACTIVATE: `always("I-66")` (every `ProgrammeActivated` names a revision whose recomputed report is clean), `transition("I-66")` |
| `i66_witnesses_cannot_be_forged` | Compile-fail twins in `fstp-creator/src/twins.rs` for `CleanReport`, `ActivationClearance` and `ActivationApproved`, each with a `no_run` twin |
| `i66_teeth_stale_report_accepted_is_caught` | Teeth |

**I-67**

| Test | Kind |
| --- | --- |
| `i67_approver_is_never_a_builder` | Machine: random creator, policy, grant and acknowledgement actions; every approver is outside the reference builder set, computed from raw records |
| `i67_core_guard_refuses_builder_even_if_creator_does_not` | Property with a mutant creator: defence in depth |
| `i67_sybil_builder_and_approver_refused` | Machine with `sybil_pair` (Q2, T-SOD-SYBIL) |
| `i67_unverified_builder_or_approver_refused` | Property: an unverified second account of a builder, as approver, is refused; an unverified builder gives `BuilderUnverified` (Q2) |
| `i67_preview_vault_answers_are_recorded` | Property: every vault answer of a preview or dry run appears in the audit log as a digest and a bit (`overview.md` NOTE 5) |
| `i67_m_activate` | M-ACTIVATE: `transition("I-67")`. Witnesses: activation by a non-builder admin; refusal of an admin who acknowledged a warning; refusal of an admin who granted a draft binding |
| `i67_teeth_builder_approval_is_caught` | Teeth |
| `web/e2e/creator/second_person.spec.ts` | A builder sees no approve action; a forged API call is refused |

**I-84**

| Test | Kind |
| --- | --- |
| `i84_t_authz_matrix_mcp_equals_channel_policy_of_web` | Matrix parity |
| `i84_every_tool_has_a_web_route`, `i84_every_tool_maps_to_one_op` | Registry |
| `i84_adapters_cannot_name_engine_types` | Layering rules A1, A2 and A2b |
| `i84_principal_has_no_public_fields` | Compile-fail twin |
| `i84_one_tool_table` | `fstp-mcp` serves exactly `fstp_api_core::meta::tools()`, and a source scan finds no other `ToolDef` value outside `fstp-access` |
| `i84_applicant_reads_own_proposal_through_mcp_with_p75_off` | D6 team exception: the MCP outcome equals the web outcome |
| `i84_audit_entries_match_modulo_channel_and_client` | Property: random sequences run once per channel give equal audit entries after removing `via` and `agent`; MCP entries carry the agent |
| `i84_mcp_audit_records_refusals_too` | Property |
| `i84_roles_reevaluated_per_call` | Machine: ending a binding between two MCP calls refuses the second |
| `i84_anonymous_handles_through_mcp`, `i84_no_drafts_of_others_through_mcp` | P-11, I-21 |
| `i84_m_parity` | Model M-PARITY |
| `i84_teeth_mcp_only_shortcut_is_caught` | Teeth: an alternative dispatcher skips the dry run for one tool |

**I-85**

| Test | Kind |
| --- | --- |
| `i85_every_high_risk_op_prepares_through_mcp` | Every routed high-risk op × every principal × every MCP token: an op with a prepare-only tool gives `Pending` or a refusal, never completion; an op without a tool gives `Deny(NotExposed)` |
| `i85_prepared_publication_completes_only_after_web_confirmation` | Machine over `fstp_prepare_call_publication`: the call is published only by a confirmation through the web with a fresh digest-bound step-up |
| `i85_p77_draft_only_binding_ops_prepare` | Matrix slice over P-77 values |
| `i85_domain_refuses_high_risk_via_mcp_when_dispatch_is_bypassed` | Bypass twin: `AsyncEngine::execute` with `Via::Mcp` for every `high_risk()` kind in `CommandKind::ALL`, routed or not; expects `RuleRef::I85` |
| `i85_confirmation_needs_fresh_digest_bound_step_up` | Property: no proof, a proof older than P-71, a proof for another digest, a proof from another session, and a consumed proof are all refused |
| `i85_confirmation_replays_stored_request` | Property: the executed request equals the stored one |
| `i85_magic_link_session_cannot_connect_agent` | I-77, I-78 |
| `i85_m_prep` | Model M-PREP |
| `i85_teeth_confirm_without_digest_check_is_caught` | Teeth |
| `web/e2e/agents/confirm_high_risk.spec.ts` | An agent prepares the call publication through `fstp_prepare_call_publication`; M2 confirms with a virtual-authenticator step-up |

**I-86**

| Test | Kind |
| --- | --- |
| `i86_mcp_cannot_reach_vault_types` | Layering rule A5 |
| `i86_identity_types_are_not_mcp_safe` | Compile-fail twins for `VaultBound<T>`, `IdentityAttribute`, `BankDetails`, `VaultOutcomeRow` and `AccountContact` |
| `i86_canary_crawl_over_every_tool_role_and_state` | The canary vault holds synthetic identity attributes, bank-shaped strings, emails and vault facts. Every tool is called for every principal in every state, including NEGOTIATION. No canary appears in any MCP response body or error |
| `i86_no_canary_in_logs_or_metrics` | The same scan over captured logs (R-NF-02) |
| `i86_declared_country_never_reaches_app_tables` | PostgreSQL suite: after `state_country`, a full dump of the application database holds no canary country (R-NG-01) |
| `i86_teeth_identity_field_leak_is_caught` | Teeth: a mutant read model adds a vault field |

**I-87**

| Test | Kind |
| --- | --- |
| `i87_public_tools_equal_public_view` | Property over generated programmes in every proposal state, minors, hidden and absent choices, and grant counts on both sides of P-54. Each tool's JSON equals `select` over `public_view` |
| `i87_feed_equals_pages` | P-52 on and off |
| `i87_page_render_trace_equals_view_leaves` | The `fstp-html` test sink records every dynamic text node. The multiset equals the leaves of the page's part of `PublicView`. No HTML parser is needed |
| `i87_every_view_leaf_reaches_its_page` | Every leaf carries a unique canary, and each appears on its page |
| `i87_equal_views_give_equal_page_bytes` | Property |
| `i87_authenticated_public_tools_equal_public_endpoint` | Both endpoints |
| `i87_two_cells_never_cross` | Isolation, M3 harness (T-ISO) |
| `i41_i42_i43_p54_public_view_filters_hold_in_every_state` | Supporting property; claimed in M9 |
| `i87_m_public` | Model M-PUBLIC |
| `i87_teeth_tool_reads_state_directly_is_caught`, `i87_teeth_filter_skipped_for_feed_is_caught` | Teeth |

### 8.5 Models

| Model | Universe | Properties | Witnesses |
| --- | --- | --- | --- |
| M-IMPORT | 1 draft, 2 importable fields, programme managers m1 and m2, tenant admin t; 2 proposals, 2 resolutions, 1 binding end; truthful and havoc proposers | I-65 always and per transition | Confirmed value active; edited value active |
| M-ACTIVATE | Tenant admins tA and tB, programme managers m1 and m2; 1 draft; 1 failure an edit can fix; 1 warning; 1 probe flip; 2 edits, 1 acknowledgement, 2 approval attempts; with and without a Sybil pair | I-66, I-67, `replay(ledger) == state` | Activation by a non-builder; refusal after acknowledgement |
| M-PARITY | 2 accounts, 1 proposal from genesis to STAGE2, P-77 both values, each op once per channel | Direct exposures: MCP outcome equals web outcome. Pending exposures: MCP gives `Pending`, and its web confirmation equals the direct web outcome | One pending confirmed; one direct MCP success |
| M-PREP | 2 accounts, 1 agent, 1 high-risk op with a prepare-only tool (call publication), 1 binding op under "draft only", 1 plain op; prepare, confirm with and without proofs, stale and foreign proofs, expire, discard, revoke, end binding, clock across P-71 and expiry | No high-risk or draft-only binding op completes except by a web confirmation of the same account; each pending action executes at most once; executed request equals stored | Confirmed high-risk action; expired action; direct plain op through MCP |
| M-PUBLIC | 1 programme, 3 proposals (one minor), states DRAFT to COMPLETED, synthetic choices Hidden to Full, P-50, P-51 and P-54 at two values | View equals the reference filter from `public-transparency.md`; each tool equals its page data | A full-level finished grant; an aggregate at exactly P-54 |
| M-BALLOT | 4 committee members and a chair, one recused, one delegation, one round | Each counted ballot was cast by its voter or its single delegate; recused members neither vote nor count; P-16 NOTE 8 outcome | A decided round; a chair casting vote |
| M-OAUTH | 1 client, 1 account; authorise, token, refresh, reuse, revoke, expiry | No token after revocation; reuse revokes the family; no code used twice | A rotation; a reuse detection |

Each model's first run records its state count in its tripwire constant.

### 8.6 Isolation and database tests

- `i87_two_cells_never_cross` and `t_iso_public_rate_limit_keys_are_per_cell` on the M3 multi-cell harness.
- `t_db_m4_migrations_forward_only` and `t_db_app_role_has_no_ledger_update`.
- `i85_concurrent_confirmations_execute_once` on PostgreSQL: two transactions confirm one pending action, and one fails.
- `t_authz_matrix_pg_sample` and `i86_declared_country_never_reaches_app_tables`.

### 8.7 Playwright and accessibility

- Journey specs: `creator/supersafe`, `creator/import`, `creator/second_person`, `cycle/supersafe_to_negotiation`, `cycle/supersafe_to_negotiation_via_agent`, `agents/consent`, `agents/confirm_high_risk` and `onboarding`.
- `roles/<role>`: allowed actions are present. Denied ones are absent, and refused when called through `fetch` from the page.
- `xss_canary`: payloads in proposal, narrative and stage 2 text never run, and a `window` sentinel stays unset.
- `public_no_script`: with JavaScript off, every public page renders, with no `Set-Cookie` and no third-party request.
- Passkey flows run in Chromium, which offers a virtual authenticator. Firefox and WebKit run applicant flows with magic links and the public pages.
- Determinism: the `fstp-e2e-cell` clock, no sleeps, waits on accessible names, retries off for invariant journeys.
- Accessibility (R-NF-03): in-house checks inside every journey for landmarks, labels, keyboard order, focus visibility and the computed contrast of the default tokens, plus a manual review (Q21).

### 8.8 Supporting tests, not exit claims

`d3_preview_grant_equals_grant_on_activated_copy`, `d9_ranking_view_has_weighted_criterion_scores` (R-EV-08), `d10_requested_totals_effective_plan_after_revision` (I-09), `d11_every_read_has_a_rule_in_every_state`, `d13_sweep_expires_stage2_at_p07` (R-EV-07), `r_pg_01_tenant_defaults_prefill_but_never_set_parameters`, `r_au_01_applicant_reads_append_content_read`, `r_cf_04_notifiable_conflict_draft_reaches_coordinator`, `r_ir_02_concern_reaches_applicant_notices`, `r_ev_04_not_selected_notice_recorded`, `r_ng_06_negotiation_notice_shown_and_acknowledged`, `r_lg_04_sessions_listed_and_ended`, `r_mc_03_agent_activity_lists_own_entries`, `r_lg_03_tenant_settings_need_step_up`, `sod07_self_grant_needs_second_admin_approval`, `i77_grant_ends_weak_sessions`, `i51_live_p05_edit_leaves_guide_bytes_unchanged`, `i52_publication_recomputes_clean_report`, `i70_contrast_bounds_enclose_f64_values`, `a9b_no_synthetic_marker_in_shipped_profiles`, `mcp_missing_origin_accepted_foreign_origin_refused`, `th46_provisioning_refused_without_operator_review`, `th49_template_links_shown_as_text_until_accepted`, `th27_assignment_refused_on_proximity_and_org_count`, `r_cf_02_declaration_precedes_every_content_read`, `r_pc_03_builder_pm_cannot_approve_first_call`, `r_pg_04_impact_matches_reference`, `r_pb_04_public_pages_scriptless`, `r_ng_01_country_statement_goes_only_to_vault`, `r_ng_06_submit_carries_shown_notice_version`, `r_ir_03_irc_case_has_no_deliberation`, `r_mc_03_revocation_is_immediate`, `r_sb_01_no_form_field_for_identity_dob_or_payment`, `r_la_08_ai_disclosure_on_call_page_and_guide`, `r_tn_01_onboarding_steps_validate_in_order`, `r_lg_03_role_grant_fails_without_fresh_step_up`, `r_ev_08_cutoff_with_unbroken_tie_is_rejected_from_the_interface`, `r_ev_09_ballots_are_cast_by_members`, `o43_p10_operator_staff_only_coordinator_reads_after_declaration`, `i51_i52_guide_bindings_and_sections`, `i48_call_package_complete`, `i50_cap_above_ceiling_blocks_activation`, `i70_default_tokens_meet_aa_in_both_themes`, `r_ga_01_frozen_change_changes_every_place_in_guide`.

Tests named after a design change (`d3_`, `d9_` and so on), a layering rule (`a9b_`) or a transport rule (`mcp_`) name the I- or R- identifiers they verify in their doc comments, as the M2 convention allows.

---

## 9. Fuzz targets

Every target exists from its crate's first commit. Each crate joins `deps/fuzz-required.txt`, and `tools/fuzz-all.sh` runs it.

| Crate | Target | Checks |
| --- | --- | --- |
| `fstp-programme` | `spec_decode` | Never panics; unknown members rejected; round trip; amounts only as ADR-006 strings |
| `fstp-programme` | `spec_compile` | `compile` never panics; accepted specs round-trip through `decompile` |
| `fstp-programme` | `field_value_decode` | Strict per-field decoding |
| `fstp-creator` | `creator_command_decode`, `creator_record_decode` | Never panic; round trip |
| `fstp-creator` | `validate_total` | `validate` is total over arbitrary drafts and inputs |
| `fstp-import` | `import_text_decode` | Arbitrary bytes per media type; output is valid UTF-8 within limits; spans stay in bounds (T-FUZZ-IMPORT, T-FUZZ-UPLOAD) |
| `fstp-import` | `proposal_decode` | Proposer output; `UntrustedValue` kept byte for byte |
| `fstp-import` | `import_record_decode` | Round trip |
| `fstp-html` | `message_format_parse`, `accept_language_parse` | Catalogue syntax; header |
| `fstp-html` | `html_wellformed_check` | The well-formedness checker never panics on arbitrary bytes; it accepts every document the writer produces |
| `fstp-guide` | `guide_template_parse` | Unknown placeholders rejected; template round trip |
| `fstp-guide` | `guide_markdown_parse` | The Markdown subset parser never panics; constructs outside the subset are refused, never passed through |
| `fstp-guide` | `guide_render` | Never panics over arbitrary bindings; output passes the `fstp-html` well-formedness check |
| `fstp-public` | `public_query_parse` | Query strings of public routes |
| `fstp-tenant` | `tenant_command_decode`, `tenant_record_decode` | Round trip |
| `fstp-signup` | `signup_form_decode` | The server-rendered sign-up and agreement forms: duplicate fields, unknown fields, bad percent-encoding and over-long values are refused |
| `fstp-signup` | `cp_record_decode` | Control plane records round trip |
| `fstp-api-core` | `api_request_decode` | Every op's decoder, selected by the first byte; JSON numbers for amounts rejected |
| `fstp-api-core` | `query_params_decode`, `cursor_decode`, `pending_request_decode` | Query strings, cursors, stored pending requests decoded again at confirmation |
| `fstp-oauth` | `url_parse` | Strict RFC 3986 subset; normalisation never changes the match result |
| `fstp-oauth` | `form_urlencoded_decode`, `authorize_query_decode`, `token_request_decode`, `client_metadata_decode`, `bearer_header_parse`, `base64url_decode` | OAuth surfaces; duplicate parameters rejected |
| `fstp-mcp` | `jsonrpc_decode`, `mcp_message_decode`, `tool_args_decode`, `mcp_headers_decode` | Envelope, method params, every tool's input, transport headers |
| `fstp-mcp` | `mcp_http_post` | Raw HTTP into the decoder, then the MCP handler over a stub dispatch, through `fstp_rt::scripted` |
| `fstp-web` | `origin_header_parse`, `web_op_request` | Headers; route, headers and body into the adapter over a stub dispatch |
| `fstp-web-assets` | `asset_manifest_decode`, `static_path_resolve` | Manifest; asset paths |
| `fstp-engine` | `envelope_decode` (extended) | New envelope variants |
| `tools/deps-check` | `ts_token_scan`, `npm_lock_parse` | TypeScript source tokens; `package-lock.json` |

`fstp-access` holds no parser, and `fstp-api-testkit` is test code. Property tests cover `fstp-html` escaping: escaped text never closes an element or attribute.

**TypeScript parsers (Q33).** cargo-fuzz cannot reach TypeScript, and ADR-003 allowlists no TypeScript fuzzer. The interim is an in-house harness in `web/fuzz/`, compiled by tsc and run on the Node.js host (Q7). It mutates seed corpora with byte-level and token-level mutations, from a seeded generator, so every failure replays. It has no coverage feedback, which is why Q33 asks. Each target exists from the module's first commit:

| Module | Target | Checks |
| --- | --- | --- |
| `money.ts` | `money_parse.fuzz.ts` | Never throws an untyped error; accepts exactly what `fstp-money` accepts on a shared corpus (differential) |
| `dom.ts` `safeUrl` | `safe_url.fuzz.ts` | Only same-origin paths and `https:` pass; agrees with the `fstp-oauth` URL subset on a shared corpus |
| `router.ts` | `router_match.fuzz.ts` | Every path matches at most one route; no match ever runs a handler with unchecked segments |
| `gen/api.ts` validators | `validators.fuzz.ts` | Arbitrary JSON values never pass a validator unless they fit the generated type |
| `i18n.ts` | `message_format.fuzz.ts` | Agrees with `fstp-html` `message_format_parse` on a shared corpus |
| `auth/next.ts` `isReturnPath` | `return_path.fuzz.ts` | Added 2026-11-04, review finding F2 of lane m4home, pending Daniel on whether this list is closed. An accepted `?next=` value resolves on the cell origin below `/app/` with no segment dropped; the login page lands on it as given, and on the home page otherwise |

The corpora are shared with the Rust targets, so a grammar change in one breaks the other's tests.

---

## 10. Third-party tools, packages and ADRs

No new Rust crate is added.

| Item | Status | Action before use |
| --- | --- | --- |
| `typescript` (npm) | Allowlisted in ADR-003, "recorded at first use" | Record exact version (at least two weeks old), integrity hash and resolved tree in ADR-003 |
| `@playwright/test`, `playwright`, `playwright-core` and pinned browser builds | Allowlisted in ADR-003 | Record versions, integrity hashes and browser builds; fetch browsers in a controlled CI step |
| Node.js as host for tsc, Playwright and the TypeScript test runner | Not named in any ADR | Q7: an ADR-003 amendment naming an exact LTS version, build and test time only |
| `axe-core` or another accessibility checker | Not allowlisted | Not used unless Daniel adds it (Q21) |
| A coverage-guided TypeScript fuzzer | Not allowlisted | Not used; the in-house harness in `web/fuzz/` stands in (Q33) |
| npm lockfile gate | New in-house check | `tools/deps-check/src/npm.rs`, `npm ci --ignore-scripts`, `deps/npm-allowlist.txt` |

ADRs needed before implementation:

- **ADR-013: MCP protocol and OAuth profile.** The pinned MCP revision, the transport subset, client registration mode, token formats and lifetimes, scopes and consent texts (Q8, Q25). It governs `fstp-mcp` and `fstp-oauth`.
- **ADR-014: Frontend architecture and delivery.** No framework and no bundler, the generated operation types, the DOM rules, CSP and Trusted Types, the asset manifest, the source scan and the in-house test runner. It governs `web/` and `fstp-web-assets`.
- **ADR-003 amendment and records.** The Node.js host decision (Q7) and the tsc and Playwright records.
- **ADR-005 completion (M3)** with OVHcloud, the database mode and the backup provider (section 7.1). M4 depends on it only for deployment.
- **ADR-004 completion (M3)** with the custody backend (section 7.2). M4 does not depend on it.

No M4 decision is marked "ADR-required" in the spec. The ADRs above are needed because they put tools or protocol profiles on record.

---

## 11. Risks

1. **Scope.** M4 is the largest milestone so far. Lanes own disjoint files, the fake cell lets lanes start before M3 lands, and Q29 offers a split.
2. **M2 perturbation.** D1 to D13 touch closed code, including generators that issue `CreateProgramme`. Tests come first. Every M2 suite stays green, every tripwire is re-measured, and count changes are reported.
3. **M3 interfaces drift.** Ports live in one module, adapters in one file, and a contract test runs fakes and real implementations through one suite.
4. **Matrix size and CI time.** Section 8.3 estimates and shards it. W6 measures it.
5. **Readings without a spec answer.** Builders, the approver, the pre-declaration summary and the ranking and IRC views are interim readings. Each sits in one function (Q1, Q9, Q16).
6. **Validation needs later milestones.** Channel and sending-domain checks fail closed until M6 and M8. SuperSAFE's P-32 names Matrix and WhatsApp, so production activation of SuperSAFE waits for M8. This is safe, and Q5 asks Daniel to accept it.
7. **Legal wording.** `LegalWordingPending` blocks real activation until legal review (Q6). The synthetic wording profile is test-only and labelled as not legal text.
8. **MCP specification churn.** ADR-013 pins one revision. Recorded transcripts are conformance fixtures.
9. **In-house OAuth and URL parsing.** Strict subsets, exact matching and fuzzing from the first commit. H-23 reviews them in M10.
10. **Frontend without a framework.** The small core, the source scan, Trusted Types, accessibility checks in every journey and manual review.
11. **Node.js supply chain (TH-15).** Build and test only, pinned, scripts off, lockfile gate.
12. **Managed PostgreSQL may not meet ADR-005 D2.** Section 7.1. This is M3's decision, with a self-managed plan.
13. **Passkeys in one browser engine.** Management flows run in Chromium only.
14. **Import before M7.** The fake proposer proves I-65, not import quality.
15. **Dry-run vault questions.** The live SoD check and the prepare path ask the vault without committing. Each answer is now recorded as a digest and a bit, and these questions have their own rate limit (H-07). The platform still learns from them, which Q13 asks you to confirm.
16. **Open decisions on the exit path.** Q23, Q32, Q33, Q34, Q35, Q37 and Q38 each touch an exit test. Each has a strict interim, so lanes can start, but the exit claim waits for the answers.

---

## 12. Readings

### 12.1 Resolved by the source-of-truth order

Order from `.claude/CLAUDE.md`: `SPEC/02-domain/invariants.md`, then `SPEC/01-requirements/`, then `SPEC/02-domain/`, then `SPEC/03-architecture/`.

1. **Activation is a separate step.** I-66 and I-67 need an activation that a validation report and a second person gate. `authentication.md` (lower rank) says creating counts as activating. Both hold if creating and activating each need a step-up (Q10).
2. **"Named programme manager" in I-65** means an account with an active programme manager binding on the draft. That needs a programme to bind to, which D1 provides.
3. **I-84 "same audit logging".** The web audits refusals, so MCP audits refusals too.
4. **I-86 covers the caller's own data.** The invariant has no exception, so the caller's own email and name are never returned through MCP (Q15).
5. **I-87 filters.** `mcp-server.md` names I-41, I-42, I-43 and P-54 as the filters. So the filter is built and tested in M4, although M9 claims I-41 to I-43.
6. **R-CF-02 before content.** The declaration view comes before every content read in every journey, as I-03 requires.
7. **R-IR-03 over the state machine.** The IRC view holds no deliberation field, whatever the state.
8. **P-10 "operator staff only" (O-43).** `policy-parameters.md` NOTE 1, decided 2026-10-25, outranks the M2 code that refuses the read (D4).
9. **R-GA-01 makes publication depend on the Guide,** so the Guide is generated at publication in M4. R-GA-02's PDF waits for M5.

### 12.2 Readings that satisfy every source at once

1. **Builder authorship survives activation.** Builders set policy through `EditPolicy`, so they are last authors of P-01 and P-09 (R-PC-03 NOTE). Activation changes no policy.
2. **"Person" means tenant account** (`00-scope.md`). I-67 adds the vault check only as a strict extra (Q2).
3. **Ballots per member.** R-EV-09 and P-16 NOTE 8 hold under either recording model. Per-member casting also prevents one session from stating others' votes (Q4).
4. **SuperSAFE P-32 as written.** The fixture keeps email, Matrix and WhatsApp. Tests use recording-fake probes, which `test-plan.md` already prescribes for channels.

### 12.3 Interim strict readings

| Topic | Interim reading | Question |
| --- | --- | --- |
| Activation approver | A tenant admin outside the builder set | Q1 |
| Builder set | Opener, every policy author, every creator record author, every import resolver, every acknowledger, every grantor of a draft binding | Q1 |
| Second person | Account, plus `SameIdentityAsAny` false | Q2 |
| Ballots | Cast by each member | Q4 |
| Checks of later milestones | Fail closed | Q5 |
| `TODO(legal)` wording | Failure; synthetic wording in test cells only | Q6 |
| Pre-declaration view | Title and an applicant-written, length-limited neutral summary | Q9 |
| Step-up | On `CreateProgramme` and on activation; on every tenant setting change and admin invitation | Q10 |
| Live SoD check | `preview_grant` with vault questions; every answer recorded; rate-limited; refusal names the rule only | Q13 |
| Clean report at publication | Built: publication recomputes the report and refuses unless clean (I-52) | Q12 |
| Prepare-only tools | `fstp_prepare_call_publication` only | Q32 |
| TypeScript parsers | In-house seeded fuzz harness with differential corpora | Q33 |
| Matrix | Covering array of 9 policy rows; full session product; separate CI job | Q34 |
| New vault queries | Synthetic vault only; production fails closed | Q35 |
| Parameters with no creator step | Placed as in section 3.1 | Q36 |
| P-05 and P-13 tightening after publication | Refused while no corrigendum machinery exists; enforcement of the stricter value is unchanged | Q37 |
| P-23 pre-check in the Guide | `PrecheckUnavailable` fails without a `Precheck` port | Q38 |
| Content reads in RANKED, DEFERRED and terminal states | Team only | Q39 |
| Workspace drafts in exports | Neither built; M9 waits for the answer | Q40 |
| P-74 role limits | Refuse when any acting role is disallowed | Q42 |
| MCP `serverInfo.name` | Verified domain label only | Q43 |
| Findings through MCP, P-75 off | Metadata, no `statement` | Q14 |
| Ranking rows with a viewer conflict | "Recused" only | Q16 |
| MCP tools | Capability table only | Q8 |
| Public rate-limit key | IP prefix (/24, /48) hashed with a daily in-memory salt, never logged or stored | Q19 |
| Unresolved import | Failure; one resolution per value | Q30 |
| Minor flag | Self-declared yes or no at draft creation, to the domain and the vault; no date of birth; a verified minor without consent is caught at NEGOTIATION to GRANTED (M5). This leaves a gap at NEGOTIATION entry, so Q23 blocks | Q23 |
| Proposal attachments | None in M4 | Q24 |

### 12.4 Corrections to the proposals

| Proposal text | Correct reading | Source |
| --- | --- | --- |
| Proposal 3: 15 roles | 14 roles | `fstp-domain/src/roles/mod.rs`, `Role::ALL` |
| Proposal 3: domain record built from a creator witness | Dependency cycle; the engine holds the single path | Crate graph, section 3.4 |
| Proposal 3: scopes for payments, grants, finance and reporting | No M4 operation uses them | `mcp-server.md`, M4 scope |
| Proposal 3: PostgreSQL "versions 14 to 18" from a US support article | The EU capabilities page, read 2026-10-28, lists 15 to 18 | Section 7.1 |
| Proposal 3: SSE frames scanned | JSON responses only | Section 3.8 |
| Proposal 2: gate admission is the domain's actor rule | `admits_actor_kind` checks only the actor kind | `fstp-domain/src/engine.rs` |
| Proposal 2: snapshot schema `public` | PostgreSQL already has a `public` schema; this design has no snapshot table | Section 3.10 |
| Proposal 2: Ed25519 directory signatures in M4 | Directory deferred; ADR-001 uses composite signatures for long-lived platform trust | ADR-001, Q17 |
| Proposal 1: `fstp-dns` in M4 | `fstp_rt::Runtime` has TCP only; sending-domain checks belong with M6 channels | `fstp-rt/src/runtime.rs` |
| Proposal 1: approver becomes last author | `CreateProgramme` sets both last authors to its actor | `fstp-domain/src/policy/mod.rs` |
| Proposals 1 and 3: placeholder `{{P-04.min}}` only | The template also uses record placeholders such as `{{call.deadline}}` and `{{timeline.table}}` | `SPEC/profiles/horizon-europe/guide-for-applicants.md` |
| Revision 1: P-45 is tenant-level | P-45 is programme level, as are P-18 and P-21 | `fstp-domain/src/rules.rs` `CATALOGUE` |
| Revision 1: `fstp-public` on `fstp-engine` keeps A4 | `fstp-engine` depends on `fstp-findings` and re-exports its types | `crates/fstp-engine/Cargo.toml`, `src/lib.rs` |
| Revision 1: `Scenario::programme()` | No such function exists; setup goes through `Scenario::execute` | `fstp-domain-testkit/src/scenario.rs` |
| Revision 1: M4 needs no moduletto | Level 3 keys are wrapped with hybrid ML-KEM-768 from moduletto | ADR-001 Uses, ADR-004 |
| Revision 1: "No parser in TypeScript" | Five TypeScript modules parse input | Section 3.9 |
| Revision 1: `ranking_view` is complete | It returns empty `criterion_scores` and totals the submitted plan only | `fstp-domain/src/visibility.rs` |

### 12.5 Critique points rejected in part

Every critique point is accepted at least in part. These are the parts I did not adopt, with the reason.

- **Point 31, desktop client.** The critique says the `Origin` check, the `__Host-` cookie and the CSP would block a Tauri client. They are kept, because they protect the browser channel. The desktop client is an M9 deliverable and signs in through OAuth with bearer tokens, to which none of the three applies (section 3.9).
- **Point 35, `serverInfo.name`.** The critique reads it as tenant-controlled text that must not reach agents. `mcp-server.md` says white-labelling covers the server's name, so the name is kept white-labelled. It is reduced to a checked domain label with no free text, which meets TH-63 too (Q43).
- **Point 6, P-73.** The critique asks for a step-up on database mode changes. This design goes further: P-73 cannot be set from the cell at all in M4, because the mode is provisioned in the control plane under ADR-005.
- **Point 8, Q13 blocking.** The critique asks that Q13 block or be built strictly. It is built strictly, so it stays among the questions that can follow, as a confirmation.
- **Point 19, Q12.** Built, as the critique asks. The question remains only as a confirmation.
- **Point 26, workspace drafts.** The critique reads their exclusion from export as against R-TD-01 and I-22. Including them would let tenant admins read drafts, against I-21. This is a conflict between two invariants, so I neither include nor exclude them. I ask you instead (Q40).

---

## 13. Work plan

Tests come first in every step. They compile against stubs that refuse with `NotImplemented`, so each step starts red without `todo!` or panics. Each lane has two agents: one writes references, predicates and tests, the other writes production code. In each lane, the test agent owns the lane's test files and testkit files, and the production agent owns its `src/**`. No two agents own the same file at the same time.

Ownership rules:

- **W0 runs alone and merges before any other step starts.** It creates every new crate's `Cargo.toml` and `fuzz/` scaffold, every shared `mod` line with its stub file, and the CI workflow. After W0, each crate lane owns its own `Cargo.toml` and `fuzz/**`, and the lead owns the shared files listed below.
- **Shared files stay with the lead.** `Cargo.toml`, `deps/*`, `.github/workflows/**`, `fstp-domain-testkit/src/{mc,reference}/mod.rs`, `fstp-api-testkit/src/lib.rs`, the `mod` lines of `fstp-engine/src/lib.rs`, and `web/playwright.config.ts`. A lane that needs a change to one asks the lead, who makes it between steps.
- **Generated files belong to their generator's lane.** `web/src/gen/api.ts` is written only by `tools/gen-ts`, owned by W3a, and checked with `--check` in CI.
- **Sequential hand-over is recorded.** `fstp-domain-testkit/src/activation.rs` passes from W1b to W2e at the start of W2e (section 3.4, D8 sequencing). No other file changes owner.
- **Test files carry the crate path.** Every test path below names its crate, so no two patterns overlap.

| Step | Lane (agents) | Owns | Tests first | Depends on |
| --- | --- | --- | --- | --- |
| W0 | lead (1) | The shared files above; `crates/*/Cargo.toml` and `crates/*/fuzz/**` scaffolds of new crates until W0 merges; `tools/deps-check/src/{layering,web_scan,npm}.rs` and `tools/deps-check/fuzz/**`; `docs/adr/ADR-013*`, `docs/adr/ADR-014*`, the ADR-003 record draft; `web/{package.json,package-lock.json,tsconfig.json}`; `crates/fstp-api-core/src/port.rs`; the stub `web/src/gen/api.ts` | Layering tests for A1 to A10, A2b and A9b; every fuzz target builds; the npm gate rejects an unpinned package; the web scan rejects `innerHTML` | M2 merged with I-12 closed; answers to Q7 and Q8 |
| W1a | L-SPEC (2) | `crates/fstp-programme/**` | `r_pg_01_creator_table_maps_to_fields`, `r_pg_01_every_programme_parameter_has_one_field`, round trip, `r_pg_01_supersafe_fixture_matches_policy_defaults` | W0 |
| W1b | L-DOM (2) | `crates/fstp-domain/src/{programme,visibility,command,rules,refusal,decision,record,engine}.rs`, `src/policy/{mod,activation}.rs`, `src/roles/commands.rs`, `src/proposal/{draft,intake}.rs`, `src/codec/**`, `crates/fstp-domain/tests/**`; testkit `src/{scenario.rs,activation.rs}` (until W2e), `src/gen/*.rs`, `src/mc/{life_model,findings_model}.rs`, `src/reference/{review,policy}.rs`, testkit `tests/{core_activation_*,o43_*,r_ev_09_*,d3_*,d9_*,d10_*,d11_*,i12_mcp_binding_reads_the_frozen_p77,i12_policy_validation}.rs`; `crates/fstp-engine/fuzz/fuzz_targets/decide_sequence.rs` | D1 to D12 except D2e; core I-67 guard; Draft refusals; `preview_grant` equivalence; O-43 reads; M-BALLOT; every M2 suite unchanged; tripwires re-measured | W0 |
| W1c | L-WEBCORE (2) | `web/src/core/**`, `web/test/**`, `web/fuzz/**` | DOM builder refuses unsafe input; router and store tests; money strings only; the TypeScript fuzz targets of section 9 | W0 |
| W1d | L-HTML (1) | `crates/fstp-html/**` | Escaping properties; render-trace sink self-test; well-formedness checker | W0 |
| W1e | L-OAUTH (2) | `crates/fstp-oauth/**`, `fstp-api-testkit/src/mc/oauth_model.rs`, `fstp-api-testkit/tests/th61_*` | M-OAUTH; PKCE, redirect matching, rotation and reuse | W0 |
| W2a | L-CREATOR (2) | `crates/fstp-creator/**`, `fstp-api-testkit/src/{reference/creator.rs,mc/activate_model.rs}`, `fstp-api-testkit/tests/{i66_*,i67_*}` | Section 8.4 I-66 and I-67 | W1a, W1b |
| W2b | L-IMPORT (2) | `crates/fstp-import/**`, `crates/fstp-engine/src/bridge.rs`, `fstp-api-testkit/src/mc/import_model.rs`, `fstp-api-testkit/tests/i65_*` | Section 8.4 I-65 | W1a, W2a (the bridge emits `SaveFields`) |
| W2c | L-GUIDE-PUBLIC (2) | `crates/fstp-guide/**`, `crates/fstp-public/**`, `fstp-api-testkit/profiles/synthetic-wording/**`, `fstp-api-testkit/src/mc/public_model.rs`, `fstp-api-testkit/tests/{i87_filters*,i87_pages*,i41_i42_i43_p54_*,i51_*,i52_*}` | Guide template equality; I-51 and I-52; P-05 snapshot; page and filter properties; M-PUBLIC | W1a, W1d, W2e (the publication composition) |
| W2d | L-TENANT (1) | `crates/fstp-tenant/**` | Step order; two-admin rule; per-parameter settings; inference record | W0 |
| W2e | L-ENGINE (1) | `crates/fstp-engine/src/{lib,driver,compose,sweep}.rs` except the W0 `mod` lines; testkit `src/activation.rs` from its start | Replay and append-only over new variants; `i66_fold_refuses_unpaired_programme_activated`; `i66_execute_refuses_core_activate_programme`; publication pairing; D13 sweep | W2a, W2b; the W0 stubs of `fstp-guide` and `fstp-tenant` |
| W2f | L-CP (2) | `crates/fstp-signup/**`, `fstp-api-testkit/tests/th46_*` | Form decoder; operator review gate; agreement records | W1d |
| W3a | L-ACCESS (2) | `crates/fstp-access/**`, `tools/gen-ts/**`, `web/src/gen/api.ts`, `fstp-api-testkit/src/{reference/authz.rs,matrix.rs}` | Registry tests; `t_authz_matrix_direct` red against stubs; generator `--check` | W1b, W2a, W2d, W2e |
| W3b | L-API (2) | `crates/fstp-api-core/src/**` except `port.rs`, `fstp-api-testkit/src/fake/**`, `fstp-api-testkit/src/mc/prep_model.rs`, `fstp-api-testkit/tests/i85_*` | Pending actions; digest-bound step-up; recorded dry-run vault answers; M-PREP; bypass twin | W3a |
| W3c | L-MCP (2) | `crates/fstp-mcp/**`, `fstp-api-testkit/tests/{i84_*,i86_*,i87_public_tools*,th6*,mcp_*}` | `i84_t_authz_matrix_mcp_equals_channel_policy_of_web`, canary crawl, `tools/list` stability | W3a, W3b, W1e |
| W4a | L-UI-CREATOR (2) | `web/src/{onboarding,creator,people}/**`, `web/e2e/creator/**`, `web/e2e/onboarding*` | Creator and onboarding specs | W1c, W3b |
| W4b | L-UI-APPLY (2) | `web/src/{calls,applicant}/**`, `web/e2e/applicant/**` | Applicant specs | W1c, W3b |
| W4c | L-UI-REVIEW (2) | `web/src/{coordinator,reviewer,committee,irc}/**`, `web/e2e/review/**` | Reviewer, committee and IRC specs | W1c, W3b |
| W4d | L-UI-ADMIN (2) | `web/src/{admin,auditor,agents}/**`, `web/e2e/agents/**` | Admin, auditor and agent specs, including I-85 confirmation and the J10 approval screens | W1c, W3b, W3c |
| W4e | L-WEB (2) | `crates/fstp-web/**`, `crates/fstp-web-assets/**`, `fstp-api-testkit/tests/{t_authz_matrix_http*,r_pb_04_*}` | Headers and CSP; CSRF; assets; HTTP matrix | W3b, W3c |
| W5 | L-E2E (2) | `crates/fstp-api-testkit/src/bin/fstp-e2e-cell.rs`, `web/e2e/cycle/**`, `web/e2e/{roles,xss_canary,public_no_script,a11y}*`, `fstp-api-testkit/tests/e2e_*` | Section 8.2 and 8.7 | W4a to W4e, W2f |
| W6 | lead plus L-M3INT (2) | `crates/fstp-cell/src/routes/m4.rs`, M4 migrations, `fstp-api-testkit/tests/{t_db_*,i85_concurrent_*,t_authz_matrix_pg_sample}.rs`, cross-cutting `fstp-api-testkit/tests/teeth_*`, CI timing notes | Fakes replaced by M3 implementations; PostgreSQL suites; tripwires measured; matrix timing | W5, M3 merged |
| W7 | review and verification | as in M1 and M2 | Independent review with executable reproducers for medium and higher findings; fixes with regression tests that failed first; an adversarial verification pass; `docs/handoff/m4-exit-audit.md` | W6 |
| W8 | lead | Milestone report, staged commits with proposed messages, staged spec proposals | All exit tests green in CI | W7 |

Spec proposals staged for Daniel's review, not edits:

- the step-up wording in `authentication.md` once Q10 is answered, and the strict extra high-risk settings;
- the two new vault queries in the `overview.md` query table (Q35);
- the pre-declaration summary wording in `roles-and-sod.md` (Q9);
- per-member ballots in `policy-parameters.md` NOTE 8 or the state machine (Q4);
- TW-1 to TW-9 as TH ids in `threat-model.md` (Q26);
- milestone claims for I-48 and I-50 to I-52 in `09-milestones.md` (Q11);
- the matrix dimensions row in `test-plan.md` (Q34);
- the minor flag wording in `functional.md` R-ID-04 and R-NG-01, per the Q23 answer;
- a `tenant.ndjson` file in `SPEC/schemas/README.md` for onboarding records, settings, the admin set and the inference record;
- a capability table row for prepare-only tools in `mcp-server.md`, if Q32 is answered B;
- the placement of parameters with no creator step in `programme-creator.md` (Q36).

---

## 14. Exit checklist

Every test below is green in CI, each model run is exhaustive, and each teeth test fails its property as expected.

| Criterion | Property, pure and integration tests | Models | Teeth | Blocked on |
| --- | --- | --- | --- | --- |
| SuperSAFE built in the creator | `r_pg_01_supersafe_fixture_matches_policy_defaults`, `r_pg_01_supersafe_fixture_compiles_and_validates`, `r_pg_01_every_programme_parameter_has_one_field`, `r_pg_02_supersafe_built_through_creator_api`, `r_pc_03_builder_authorship_survives_activation`, `d3_preview_grant_equals_grant_on_activated_copy`, `web/e2e/creator/supersafe.spec.ts` | none | none | Q1, Q5, Q6, Q35, Q36, Q38 |
| Call cycle to NEGOTIATION | `e2e_supersafe_call_cycle_to_negotiation`, `r_ev_03_exactly_75_percent_does_not_pass_through_the_interface`, `i52_publication_recomputes_clean_report`, `d13_sweep_expires_stage2_at_p07`, `web/e2e/cycle/supersafe_to_negotiation.spec.ts`, `..._via_agent.spec.ts` | none | none | Q4, Q9, Q23, Q37, M3 |
| Authorisation matrix | `t_authz_matrix_direct`, `t_authz_matrix_http`, `i84_t_authz_matrix_mcp_equals_channel_policy_of_web`, `t_authz_matrix_covers_every_rule`, `t_authz_denial_has_no_effect`, `t_authz_matrix_pg_sample`, `d11_every_read_has_a_rule_in_every_state` | none | `t_authz_teeth_extra_cell_is_caught`, `t_authz_teeth_missing_cell_is_caught`, `t_authz_teeth_reference_flip_is_caught` | Q1, Q8, Q9, Q16, Q34, Q39, Q42 |
| I-65 | `i65_creator_and_domain_cannot_reach_import`, `i65_import_proposals_never_alter_draft`, `i65_every_imported_value_has_named_pm_resolution`, `i65_resolution_shown_digest_must_match`, `i65_profile_conflict_is_flagged_never_adjusted`, `i65_injected_annex_changes_no_value_without_confirmation` | `i65_m_import` | `i65_teeth_auto_applied_proposal_is_caught` | Q30 |
| I-66 | `i66_seeded_failure_never_activates`, `i66_r_pg_01_cap_above_ceiling_names_both_values`, `i66_unacknowledged_warning_blocks_activation`, `i66_edit_after_report_voids_clearance`, `i66_probes_run_at_approval`, `i66_fold_refuses_unpaired_programme_activated`, `i66_execute_refuses_core_activate_programme`, `i66_no_route_or_tool_reaches_activate_programme`, `i66_witnesses_cannot_be_forged` | `i66_m_activate` | `i66_teeth_stale_report_accepted_is_caught` | Q5, Q6, Q30, Q35, Q38 |
| I-67 | `i67_approver_is_never_a_builder`, `i67_core_guard_refuses_builder_even_if_creator_does_not`, `i67_sybil_builder_and_approver_refused`, `i67_unverified_builder_or_approver_refused`, `i67_preview_vault_answers_are_recorded` | `i67_m_activate` | `i67_teeth_builder_approval_is_caught` | Q1, Q2, Q31 |
| I-84 | `i84_t_authz_matrix_mcp_equals_channel_policy_of_web`, `i84_every_tool_has_a_web_route`, `i84_adapters_cannot_name_engine_types`, `i84_principal_has_no_public_fields`, `i84_one_tool_table`, `i84_applicant_reads_own_proposal_through_mcp_with_p75_off`, `i84_audit_entries_match_modulo_channel_and_client`, `i84_mcp_audit_records_refusals_too`, `i84_roles_reevaluated_per_call` | `i84_m_parity` | `i84_teeth_mcp_only_shortcut_is_caught` | Q8, Q42 |
| I-85 | `i85_every_high_risk_op_prepares_through_mcp`, `i85_every_high_risk_tool_is_prepare_only`, `i85_prepared_publication_completes_only_after_web_confirmation`, `i85_p77_draft_only_binding_ops_prepare`, `i85_domain_refuses_high_risk_via_mcp_when_dispatch_is_bypassed`, `i85_confirmation_needs_fresh_digest_bound_step_up`, `i85_confirmation_replays_stored_request`, `i85_concurrent_confirmations_execute_once` | `i85_m_prep` | `i85_teeth_confirm_without_digest_check_is_caught` | Q32, M3 step-up |
| I-86 | `i86_mcp_cannot_reach_vault_types`, `i86_identity_types_are_not_mcp_safe`, `i86_canary_crawl_over_every_tool_role_and_state`, `i86_no_canary_in_logs_or_metrics`, `i86_declared_country_never_reaches_app_tables` | none | `i86_teeth_identity_field_leak_is_caught` | Q14, Q15 |
| I-87 | `i87_public_tools_equal_public_view`, `i87_feed_equals_pages`, `i87_page_render_trace_equals_view_leaves`, `i87_every_view_leaf_reaches_its_page`, `i87_equal_views_give_equal_page_bytes`, `i87_authenticated_public_tools_equal_public_endpoint`, `i87_two_cells_never_cross` | `i87_m_public` | `i87_teeth_tool_reads_state_directly_is_caught`, `i87_teeth_filter_skipped_for_feed_is_caught` | Q27 |

Every fuzz target of section 9, Rust and TypeScript, exists and runs in CI (Q33).

Requirements covered in M4:

- Fully: R-PG-01, R-PG-03, R-PG-04, R-MC-01, R-MC-02, R-MC-03 (with agent activity), R-MC-05, R-LG-03 (through M4 operations), R-LG-04 (through the M3 port).
- Fully, through the interfaces, with the rule enforced by the M2 domain core: R-AC-01, R-AN-01, R-IR-01, R-IR-03, R-CF-01, R-CF-02, R-CF-03, R-EV-01, R-EV-02, R-EV-05, R-EV-06, R-EV-08, R-EV-09, R-LA-03 (no finding exists, and every decision op takes a named actor), R-NG-02 (I-18 at entry, subject to Q23), R-PC-01, R-PC-02, R-SB-01, R-SB-02, R-SB-05.
- Partly:
  - R-TN-01: every step is walked, but six of nine steps record data and fail closed until M5 to M9 add their machinery.
  - R-PG-02: blank, clone and template fully; import with the fake proposers in tests and only `NoProposer` in production until M7.
  - R-PG-05: tenant-private templates only.
  - R-SB-03: withdrawal up to and through NEGOTIATION; "before contract signature" completes with contracts in M5.
  - R-EV-04: the NOT_SELECTED notice is recorded at once; sending within P-08 arrives with M6.
  - R-EV-07: the D13 sweep issues `ExpireStage2`; M6 replaces it.
  - R-IR-02: the concern reaches the applicant's notices; email in M6.
  - R-CF-04: the notification draft reaches the coordinator; sending stays outside the platform.
  - R-MC-04: per-cell public tools; the directory depends on Q17.
  - R-GA-01 and R-GA-02: HTML only, pending Q28.
  - R-PB-01 and R-PB-04: open calls; grants hidden until M9.
  - R-PB-02, R-PB-03 and R-PB-05: filter built, choices in M9.
  - R-NG-01 (country statement), R-NG-06 (notices at submission and negotiation, wording `TODO(legal)`), R-SB-04 (request recorded, sent in M6).
  - R-ID-01, R-LA-04 and R-EX-03: the selections are captured as tenant defaults or settings; verification, inference and payments use them from M3, M7 and M5.
  - R-LA-08 (Guide and call page), R-WL-04 (default package).
  - R-NF-02, R-NF-03 and R-NF-04 for the interfaces; R-AU-01 for every content read, applicant reads included, and every operation.

---

## 15. Questions for Daniel

Each question lists options and a recommendation. Until you answer, the design builds the interim reading in section 12.3. Revision 2 moved Q17, Q23, Q28 and Q31 into 15.1 and added Q32 to Q44. The numbers are kept, so references stay valid.

Settled through the M3 answers of 2026-10-28 (`m3-design.md` section 21.0): Q7 by M3 Q39 A (Node.js and npm under an ADR-003 amendment), and Q23 by M3 Q13 A (an over-18 attestation in the vault before NEGOTIATION, not a date of birth). M3 Q10 A places EUDI login and verification in M4.

### 15.0 Daniel's answers (2026-10-29)

Daniel started M4 on 2026-10-29, before M3 closes, so that M4 pages exist for a demo on 2026-10-30. His answers:

| Question | Answer | Effect on this design |
| --- | --- | --- |
| Every question of sections 15.1 and 15.2 | Each recommendation is built as an interim reading | Each is marked "Interim, pending Daniel" where it is built, listed in the exit audit, and reversible. A later answer replaces it |
| ADR numbering | M3 has since used ADR-008 to ADR-012 | This design's ADR-008 (MCP protocol and OAuth profile) becomes ADR-013, and its ADR-009 (frontend architecture and delivery) becomes ADR-014. Every later reference here means the new number |
| ADR-014, frontend | Accepted as section 3.9 describes it | No framework, no bundler, tsc only, the DOM rules, CSP with Trusted Types, generated operation types, the asset manifest, the source scan and the in-house test runner. W0 writes the ADR text from section 3.9 |
| ADR-013, MCP and OAuth | Answered 2026-10-31: Q8 registration A (open dynamic, rate-limited, no metadata fetch), the design tool set, the newest dated MCP revision with 2025-06-18 as the floor; Q25 the design lifetimes | ADR-013 is accepted for these rows. W1e and W3c can start. The lane records the exact pinned revision after checking its text |
| Q7 Node.js host | Answered under M3 Q39 A | ADR-003 amendment of 2026-10-28, with Node.js 24.11.1 and npm 11.6.2 recorded on 2026-10-29 |
| Q23 minor flag | Answered under M3 Q13 A and the answers of 2026-10-29 | `state-machine.md` NOTE 14 |
| Review depth | One review round per lane for the demo path, no adversarial verify pass | Deferred findings are logged for W7, which runs in full before M4 closes |
| D2e for every programme (2026-10-30) | Strict now | D2e of section 3.4 applies to every programme, not only to drafted ones. `DomainDecider` refuses every core `ActivateProgramme` through `execute` with `RuleRef::I66`, and the fold refuses every `ProgrammeActivated` without its `Creator(ActivationApproved)`. Every M2 test setup and e2e seed reaches an active programme through the creator path or a paired entry the test kit owns. `review_d2e_undrafted` must pass |
| Home page and landing after sign-in (2026-10-31) | Not yet answered. Interim, pending Daniel, after his report: "the demo is useless. I don't do anything except register a passkey; the only route that works is auth" | Section 2.2 names no home page, and every sign-in ended on the account page, which led nowhere. Every sign-in now lands on `/app/`, "Your work". A login page with a safe `?next=/app/...` returns there instead, and a deep `/app/` page without a session opens that login page. The home page lists one link per piece of work for each role the caller holds, and offers the open calls to a person with no role. The read behind it is `me.roles` (`ReadKind::ListMyRoles`, `ReadRule::Own`, web only, no tool). It gives the caller's own active bindings, the titles of the published calls they reach, the open rounds of the caller's committee calls, the caller's programme manager programmes that hold a creator draft, and the tenant admin flag. It never names another account (I-86). Every `/app/` page follows the approved sidebar layout of `docs/design/01-navigation-home.md` (2026-11-01): a top bar, then a sidebar with the role chip and a navigation of Home, every page the caller may open without an id, and Account. Daniel asked on 2026-10-31 for all links to routes in the top row. The home page lists the pages that need an id, in one card per role group. The account page carries the same links. The demo lists M1 and says under each person what they can do in the scene, counting only work whose page still opens |
| Profile page (2026-10-31) | One page at `/app/me` with a Profile part and a Security part; fields split by sensitivity; bundle-ready, no bundles yet | The Profile part holds: a display handle and preferences (interface language under R-NF-04, accessibility, notification channel and timing), stored in the cell as account-owned records; a name, an organisation and declared affiliations, stored as vault facts and shown or changed only on the vault origin (I-17, I-86), with the affiliations feeding R-NG-01; the verification status, read-only (`me.get_verification`); and the roles held per programme, read-only. The Security part holds passkeys, sessions, sign-out and recovery; `/auth/account` keeps only the ceremonies that must run on the auth pages. Each self-declared field is typed so an M9 profile bundle can export a chosen subset (R-PS-02). No export or import is built in M4 |
| I-50 timing (2026-10-31) | Refuse at save | A creator save or import resolution that would put P-05 above P-58 is refused with I-50, naming both values, so no draft holds such a cap. The reference models of the I-65 and I-66 suites take this reading. The `CapAboveCeiling` report row stays as a second line of defence. The engine refusal carries both values as `RefusalDetail::CapAboveCeiling`. The API body names them as ADR-006 strings in a `values` member, such as `{"P-05":"60000.01","P-58":"60000.00"}`. That member shape is interim, pending Daniel |
| Re-granting a role (2026-10-31) | Refused while the same binding is active, allowed after it ends | A domain guard in `GrantRole` refuses a grant while the account holds a binding of the same role on the programme that has not ended. The reference models follow it. Reading of 2026-11-04, the literal one: a binding under a conflict-of-interest suspension has not ended, since `ReinstateBinding` can make it active again, so it counts. A voided binding does not count. `held_binding_of` and `reference/sod.rs` both take this reading, replacing the interim exemption |
| P-77 "draft only" and MCP saves (2026-10-31) | An agent may save creator drafts through MCP | An `EditPolicy` the engine composes from a creator save on a drafted programme counts as drafting, so P-77 "draft only" admits it through MCP. Activation still needs a human approver with a step-up |
| Demo sign-in (2026-11-04) | Daniel: "for the demo it makes NO SENSE to have to use and generate passkeys. that is just overengineering." Lane m4/site builds it, with the reactive site of the same day | `fstp-e2e-cell --demo-signin`, test only (rule A9): the demo page gives each person a "Sign in as" link with a single-use token of at most five minutes of cell clock, redeemed once at `/auth/demo-signin` on the cell origin. A demo session is a passkey session in the fake port, so every guard holds; its step-up shows a plain Confirm button, and `/auth/stepup` records the proof for a demo session only. Every `/app/` page of it, and `/auth/account`, says "Demo sign-in" in the top bar. Without the flag the route and the demo modules answer 404 and nothing changes. `tools/demo/run.sh` starts the demo with the flag (`FSTP_DEMO_SIGNIN=off` turns it off). The same lane makes `/app/` one document with in-app navigation, restyles every page on the design tokens, and builds the screens whose operations exist (`docs/handoff/m4-demo.md`) |
| Public pages and Guide previews, lane W2c (2026-11-05) | Not yet answered. Interim, pending Daniel, built as section 3.10 describes | `fstp-public` builds the view, the pages, the feed and the tools, and `/p` serves them through `ApiCore::dispatch` with no credential, so the session cookie is never read. Readings: GRANTED and IN_EXECUTION are funded under P-50, COMPLETED is finished under P-51, and TERMINATED shows nowhere. The P-50 and P-51 tokens are `hidden`, `project`, `project_and_grantee` and `full`, and a value that does not decode reads as closed. An aggregate counts only the grants the view shows (Q27). It is withheld when the grants it counts with a hidden amount number from 1 to max(P-54, 2) minus 1, so its total never reveals one hidden amount (I-43, R-PB-05). Page leaves compare as sets, where section 8.4 says multiset. A programme's slug, name and narrative come from its creator draft. A programme with no draft is public under its id in decimal, named "Programme" and its id, and any programme is also found by its id. A segment of digits names only that id. A draft slug of digits only, or one another active programme also names, names no programme, which is then public under its id. Texts are read only through `TextStore::get_public`. The public route decoder lives in `fstp-api-core` (`decode_public_page`), since rule A1 keeps `fstp-public` out of `fstp-web`. `creator.preview` answers text blocks, never markup: the Guide preview walks the template with one marker per placeholder that has no value, and the public preview names the draft. Seams: the contract placeholder preview answers `not_implemented` until a contract renderer exists (M8). The cell links no Guide yet, since no port supplies the data protection summary and the privacy statement address. `published_guide` binds the frozen values from the call, P-05 and P-13 from the snapshot and every other live value from the core head, never from the caller's spec. It is the Guide at publication only: storing its bytes with `GuidePublished { digest }` is the engine's publication seam, and the pages serve only a stored Guide (I-53). No `/p` stylesheet exists. Deviations: the approved `fstp_domain::view::proposal_minor_flagged` (I-42), and new `ReadModel::Public` and `CreatorModel::Preview` variants. No `svg` element exists in `fstp-html`, so R-JV-06 is not tested |
| Journey projector and diary visibility (lane j2, 2026-11-05) | Not yet answered. Interim, pending Daniel. The readings are the lane's test references, `fstp_domain_testkit::reference::{diary, projection}` | The matrix of `SPEC/12-journey-ui.md` section 7.2 maps roles to columns: Applicant and team member, committee member and chair, coordinator and programme manager, the three finance and operations roles, and the auditor. The guardian sees only the guardian steps that name them (O-60). IRC members see only the state transitions of a proposal they are assigned to, and get no route strip (O-58). Call drafters and tenant admins see no diary entry. Financial and legal signatories see no diary entry and are no journey readers, since section 7.2 names neither and both bind tenant-wide with no programme (NOTE 5). "Within P-10" and "as P-10 allows" follow `fstp_domain::visibility`: an assignment, or a committee member's declaration under "all committee members". Under "operator staff only" no committee member reads another reviewer's score or the route, only their own scores (review J2-R3). "Per P-10" for scores admits only the FSTP coordinator under "operator staff only". "Grants only" shows finance and operations roles the leg into GRANTED and later legs, never the evaluation legs, in the diary and the journey legs alike (review J2-R5). The diary reference holds the section 7.2 table as data, one spec phrase per cell, and spec-pinned cases fix verdicts as literals (review J2-R4). A coordinator sees no entry of a proposal before declaring no conflict on it, only per-state counts (O-57). Scores reach the team once the route holds NOT_SELECTED, DECLINED or GRANTED (O-54). The overlay carries opaque parameters by id only, never their text, since it is part of the journey reply (I-97). The projector's state is its rows: a restart resumes from the stored rows, and a tail that skips or repeats an entry is refused (I-92). ADR-015 grants the `app` role INSERT and SELECT only, so the cursor and the legs are append-only rows. Implementer readings: the cursor gains one row per folded ledger entry, keyed by projector and sequence number, which replaces the section 11 key on `projector` alone. Migration 4 adds `journey.leg`, `journey.route_start` (the creation call, which drives the overlay of a deferred proposal, NOTE 8) and `journey.assignment` (score and conflict records name only the assignment). Each ledger record gives at most one entry, whose id is the first 16 bytes of a labelled SHA-256 of its sequence number, so a rebuild is byte-identical. No complaint or agent action record exists, and a `VaultOutcome` names no subject, so those kinds have no entry yet. `CallDrafted` and `CallEdited` record a call before publication, so they give no entry (R-AC-01, review J2-R2). "Deadline set or moved" comes from timeline events once that source exists. `KnockOutRecorded` and the committee records fit no kind of section 7.2 and give no entry. The deadline zone table ships in `fstp-journey` and only grows at its end. `proposal.journey` and `proposal.diary` are web only. They admit the team and every holder of a section 7.2 role in the programme, and refuse staff on a DRAFT, and on any route that never reached SUBMITTED, such as a draft withdrawn before submission (I-21, review J2-R1). A caller reads through every role they hold there, and an entry shows when one role admits it. The position shows where a state transition would, else R-CF-02, I-03 or R-AC-01. The reads take the ledger from a new `AsyncEngine::ledger` seam, which fails closed by default. The erasure log has no API port, so texts are served as references |
| Signatory roles (2026-11-04) | Daniel's SA-01 and SA-02, applied to the spec on 2026-11-04 as SoD-14 to SoD-18 and NOTE 5. Lane m4/roles builds them. Interim readings, pending Daniel | `Role` gains Financial signatory and Legal signatory in the Operations group, in the order of the roles table. Both are tenant-wide: `fstp-tenant` holds their bindings as it holds the admin set, and the core refuses a programme `GrantRole` of either (NOTE 5). `tenant.list_signatories`, `tenant.grant_signatory` and `tenant.end_signatory` serve them at `/admin/signatories`. A grant or an end is high-risk (I-78), web only, and needs no verified identity (SoD-09). A grant to one's own account is refused under SoD-07, since no tenant-wide approval shape exists: a second tenant admin grants it instead. A second grant of a held role is refused, as the re-grant row above reads it. A holder of a Receiving binding is refused under SoD-03, as for tenant admin. The Administrators step validates only with a holder of each role. Activation is `tenant.request_activation` by one admin and `tenant.approve_activation` by another (SoD-18), at `/admin/activation`. Neither is high-risk, since the high-risk table of `authentication.md` names programme activation only. The approval names the open request. Both check SoD-14 and SoD-15 against the holders of that instant, and the approval checks the steps again. A request stays open until approved. While the organisation is active, ending the last holder of either role is refused (SoD-17). `tenant.complete` stays, and no longer activates. Each refusal names its rule. Seam for M5: what the signatories approve, such as payment instructions and contracts, has no command yet. No test names those acts. The reverse order holds too: the shell attests a signatory holder to the core as it attests a tenant admin (`Ctx::binds_tenant_admin`), so a holder who is added as a team member or guardian, or who opens a draft, is refused under SoD-03 |
| Route renderer and voyager surface (lane j3, 2026-11-05) | Not yet answered. Interim, pending Daniel | `fstp_html::route` renders the map and its ordered list from the definition and one viewer's position and legs, through the escaping writer, deterministic for equal inputs. The checker accepts the closed SVG subset it emits and nothing else: no script, style, event attribute, foreign object or animation element, markers inside the document only, and `fill` of `currentColor` or `none`. Text inside `svg` escapes quotes too. Node links are `{page}#node-STATE`, since `SafeUrl` refuses a fragment-only URL. A node label wraps at spaces into at most three lines after the catalogue resolves it (`Lines`), so a terminology override wraps too. The `/app/` pages run under Trusted Types with no HTML sink, so the web app builds the same tree with `createElementNS` (`web/src/journey/svg.ts`). A shared snapshot, `crates/fstp-html/testdata/route_stage2.svg`, fails a test on either side if the two drift. The progress page shows the map, "Progress as a list", one help panel per node (what happens now, who acts, deadline, what you can do, what you cannot see), and the withdrawal note below them. The activity log builds each sentence from a catalogue key and the read's parameters. It shows an erased text as the section 7.3 placeholder, and marks the submission entry as a receipt with "Anchor pending", since the read carries no anchor (O-56). The full map, its list, its help panels and the withdrawal note show only to a caller whom the team read `proposal.list_own` names on the proposal, and the withdrawal note to its lead alone (review J3-R2). Any other reader sees the strip the read gives and a refusal. A `map` flag on `proposal.journey` would say this in the read itself, but its reply fixture lives in `fstp-api-core/src/model.rs`, outside the lane. The "Proposal status" strip shows on a reviewer's assignment pages once the reviewer has declared, when `proposal.journey` gives `strip`. Before the declaration the read refuses (R-CF-02), so the page asks for none. Review J3-R3 was refuted on this ground. Coordinator and IRC pages get none, as `docs/design/04-reviewer-committee-irc.md` gives it to reviewers and committee members only (O-57, O-58). A stage that every route to the position or to a visible leg passes is completed, so a "grants only" reader sees the evaluation stages as passed while their legs stay hidden. RANKED stays upcoming then, since DEFERRED leads from STAGE2 to IRC_REVIEW (review J3-R4). The guardian reaches the activity log from the home card and the guardian page (O-60, review J3-R1). The demo needs no new seed: every scene runs from genesis through production commands, so the ledger already holds each route |
| Programme role invitations, lane inv (2026-11-06) | Not yet answered. Interim, pending Daniel. The readings are the lane's test reference, `fstp_api_testkit::reference::invitations` | `creator.invite` draws a 32-byte link token through `fstp-crypto`. The invitation id is the first 16 bytes of the labelled SHA-256 of the token in its link spelling, so the ledger holds the token's digest and never the token (ADR-007), and no record shape changes. Once the invitation is appended, the token and the email go to M3 through the accounts port (`InviteKind::ProgrammeRole`), and to nothing else (I-86). The landing `people.get_invitation` finds the invitation by the token's digest and names the role, the terms version, the P-75 and P-77 choices of a Judging role and the state, never the programme, as the existing model test reads it. A choice the draft does not hold yet reads `null`. An unknown token, a withdrawn invitation and one another account accepted get one refusal, `not_found` with rule `Input`. The first enrolled account that accepts with the token takes the invitation, since no port says which account M3 bound to the address. The acceptance names the shown terms version, today 1, whose wording is `TODO(legal)`. The shell stores the terms as shown, with the bound P-75 and P-77 choices, as a confidential text of the programme. The creator command `AcceptInvitation` decides it, and the engine appends the new core record `TermsAccepted`, which the core projection ignores and the creator folds into the invitation (`observe_terms_accepted`). A second acceptance is refused. `people.begin_verification` is the acceptor's, through `VerificationPurpose::ProgrammeRole`. A Drafting or Judging `roles.grant` is composed only from a `TermsAccepted` of a live invitation of that role and account (`fstp_engine::compose::terms_accepted`), whose stored terms become its confidentiality text. The refusal names `J2`, since the spec section has no ID. Operations grants need none. The driver does not refuse a core `GrantRole` without the record, since M2 setups grant with no invitation. The grant by `{invitation, approval?}` is built in dispatch, but its body still fails the strict `roles.grant` decoder in `forms.rs`, outside the lane. `people::check_grant_by_invitation` is the check that decoder needs for this body |
| Accepted terms bind exactly, lane invfin (2026-11-06) | Not yet answered. Interim, pending Daniel | The landing's `terms_version` identifies the exact terms text shown: the wording version and, for a Judging role, each P-75 and P-77 choice as undecided, on or off (`people::shown_version`). A Drafting role, or Judging terms with both choices undecided, reads version 1. An acceptance whose version no longer matches the terms, as after a change of P-75 or P-77 since the landing, is refused with rule `J2`. So the recorded terms are always the terms shown. Every Drafting or Judging `roles.grant`, by invitation or by account, and a confirmed pending one, binds the accepted terms text as its confidentiality. A request that names its own confidentiality text for such a grant is refused with rule `J2` |
| Server-rendered map (lane j4, 2026-11-06) | Daniel, 2026-11-06: the read returns the Rust renderer's checked element tree as data, the browser only builds that tree against the closed SVG subset, and ADR-015 is amended to say so. Readings below are interim, pending Daniel | ADR-015 "Rendering" carries the amendment. `fstp_html::route::tree` renders the map through the escaping writer in a page, runs the well-formedness checker on it, and resolves the same element as data. It refuses the tree unless its markup equals the rendered bytes. On the wire an element is `{tag, attrs: [{name, value}], children}` and a text is `{text}`, never empty and never beside another text. `route::statuses` gives each node's status in route order, so the list and the help panels need no layout of the browser's own. `proposal.journey` gains `map`, true for an active Receiving binding on the team (section 8.1), and `withdraw`, true for the lead in a NOTE 10 state. The guardian gets no map. The progress page draws the map, list, help panels and withdrawal only from these flags and no longer reads `proposal.list_own` (review J3-R2). Judging roles keep the strip and IRC members get none (O-58). The tree comes from a separate read, `proposal.route_map` at `GET /proposals/{proposal}/route-map`, with `{proposal, tree, nodes}`, so `proposal.journey` stays a reply of tokens (I-97). Its read rule is `Team`, and the dispatch also refuses a caller whose journey `map` is false, so the guardian gets no tree. The map is of the caller's own projection, in the English plain pack, with no overlay. No `Shape` kind states a tree, so the reply has no `REPLIES` row and is unshaped, as the creator's draft spec is. `readRouteMap` in `web/src/journey/model.ts` reads it, and `readRouteTree` in `web/src/journey/tree.ts` validates the tree against the subset and refuses it whole. `buildRouteTree` builds it with `createElementNS`. The reader has the fuzz target `route_tree`. The progress page draws only that tree, and its list shows the reply's node statuses verbatim. The browser layout of `svg.ts` and its snapshot test are gone. The web build of the server's tree still serialises to `route_stage2.svg`, byte for byte. The public call page shows the route from `route::public_svg` as static SVG in `section#route`. It shows no position, no node link and no arrow head, since the public pages hold no `url(` reference. `/p` links no stylesheet, and an unpainted SVG shape or text fills black. So the public map paints itself: shapes and edges stroke in `currentColor` with no fill, and texts fill in `currentColor` at a whole `font-size`. The closed subset gains `stroke` and `font-size` for this, and `fill` on `rect`, `circle` and `text`, with the same value rules in the checker and the web reader (review J4-REV-1, I-70). The `/app/` map carries none of this paint and keeps its token classes. Its formal names and glyphs are `Node::fixed` code constants, which the I-87 trace leaves out as it leaves out the skeleton. The public route is the domain's state list and transition table, read in `fstp-public/src/route.rs`, outside the files of rule A6. Daniel, 2026-11-06, on the conflict this lane raised: at a terminal state (WITHDRAWN, NOT_SELECTED, DECLINED, INELIGIBLE, COMPLETED, TERMINATED) the Receiving bindings still end (`roles-and-sod.md` line 98, `terminal_ends`). The former team keeps a read-only view of its own journey, route map and activity log, so it sees the outcome and can export the chronicle (design 02 lines 129 to 133, O-59). No command is possible after the end. Built as `ReadRule::FormerTeam`: a lead or team member whose binding was active when it ended, on a proposal in a terminal state, as `own_proposals` serves its final-state read. It admits `proposal.journey`, `proposal.diary` and `proposal.route_map`, and revives no binding. The view is the one of a bound member, so O-54 still hides the scores of a WITHDRAWN proposal. `map` stays true and `withdraw` is false. Reading, interim: the guardian gets no such view, since the decision names the lead and the team members. `r_sb_03_note10_withdraw_flag_clears_once_withdrawn` passes unchanged, and `r_jv_former_team_reads.rs` pins the rest |
| Planning Studio (lane studio, 2026-11-06) | Not yet answered. Interim, pending Daniel | `web/src/studio` groups the 11 creator steps under the five studios of `SPEC/12-journey-ui.md` section 8.2, with the plain headings and the studio names as a secondary line. A step's state comes from `creator.get_report`. A step opens once every earlier step has no failure, and warnings never lock a step. A step opened by URL before then still renders, says it is not open, and the server keeps deciding every save. "Approval and publication" shows the I-66 gate and links the request on the review step. It lists the published calls of `me.roles` with `calls.get` state and `open`. A programme manager gets approve and publish controls that take a call number, since no read lists a DRAFT or APPROVED call and `call.draft` names no drawn call. A call drafter gets none (R-PC-03). The P-01 and P-09 editors of an active programme carry the return-to-DRAFT note. No call edit page exists, so the call text note shows on the approval page. The impact read runs on request, since it answers 501 for a programme with calls. The home page links the studio as "Programme set-up" and the review as "Validation report" |
| Vocabulary packs (lane vocab, 2026-11-06) | Not yet answered. Interim, pending Daniel | `fstp_journey::vocab` reads the plain and Voyage packs of `crates/fstp-journey/vocab` through `fstp-json`, with the fuzz target `vocab_parse`. A pack names only keys of `LABEL_KEYS`, the design 07 rows without a placeholder, so no approved or legal text has a key (I-72, I-94). A label is 1 to 200 bytes with no brace, angle bracket or control character. The plain pack names every key. A Voyage pack may leave a key out, and then shows no secondary line for it. The negative outcomes and the withdrawal action keep the wording of `FIXED` in both packs. Catalogue 3 takes each spec name as its Voyage label, with a capital first letter. `Vocabulary` gives the plain label first, the Voyage label only with the switch on and only where it differs, and each state's formal name (I-96). On the web, `createI18n` takes the pack as `secondary` and refuses it for approved text. `web/src/vocab` draws the `voyage-label` line. Seams: no tenant setting holds the switch yet. A new `tenant.*` operation needs rows in `fstp-api-testkit`, and a new `me.roles` member breaks its key-set test, so pages use `vocabOptions("plain")` until one exists. Label edits by tenants wait for terminology overrides in M9 (R-WL-05, B-09). The web `journey.withdraw.action` reads "Withdraw on the proposal page", where design 07 says "Withdraw this proposal". R-JV-09 scans the Guide templates and the web approved texts, the only templates so far |
| Q37, P-05 and P-13 tightening after publication (2026-11-06) | C | Build the effective-limits record (D12) and numbered corrigendum generation in M4. Notification dispatch follows in M6, so I-53 is claimed later. I-51 is claimed in M4 for P-05 and P-13 |
| Q23, the minor flag before NEGOTIATION (2026-11-06) | B | The applicant states a date of birth at submission, to the vault only. The vault derives the flag against the call deadline and answers one bit. A false statement is grounds to decline at verification. `TODO(legal)` under L-02. `r_sb_01` changes to allow this vault-only field |
| Q34, what "full" means for the authorisation matrix (2026-11-06) | B | The full product of operation, principal and state in every channel, with the full session product. The full policy product runs in the direct channel only. The HTTP and MCP channels use the policy covering array |
| CI off the laptop, lane ci (2026-11-06) | Daniel: the full test suite must stop running on the laptop | CI runs on pushes to `main` and `batch/**` and on demand. The `test` job runs parallel parts: the workspace in three, the HTTP matrix in 4 `FSTP_MATRIX_SHARD` shards and the direct matrix in 12. Each part runs `test-gate --partial` on its own log, which calls a listed test stale only when its binary ran and the part's libtest filters select it. Per Q34 B, `direct_matrix` runs the full product of 144 policies and `matrix` the covering array. A known-red entry whose binary no part runs is no longer reported as stale |
| Q38, P-23 pre-check in the SuperSAFE Guide (2026-11-06) | C, and the pre-check must run | The Guide keeps its pre-check section with a note that the pre-check is not yet available. The pre-check stays a firm deliverable (M7). The e2e cell runs the pre-check path with a fake provider now |
| Q32, prepare-only MCP tools (2026-11-06) | A | `fstp_prepare_call_publication` is the only prepare-only tool in M4. Every other high-risk op gets `Deny(NotExposed)` |
| Q33, fuzzing TypeScript parsers (2026-11-06) | B, with Jazzer.js | An ADR-003 amendment allowlists Jazzer.js as a dev-only tool with its pinned version and resolved tree. The TypeScript parsers get coverage-guided targets. It never ships in runtime artifacts |
| Q35, two new vault queries (2026-11-06) | A | `classes_defined` and `proximity_lists_declared` join the decided vault query set through a spec change. Each answers one bit and names no account |
| Q28, Guide PDF (2026-11-06) | PDF in M5 | Online signing in M5 builds on a vendored copy of LibPDF-js/core (MIT, with an Apache-2.0 font module), which the project then enhances and secures. An ADR comes first. The signing cryptography still comes from ADR-001 |
| Roles lane questions (2026-11-06) | Answered | Approving a programme's activation is high-risk and needs a step-up. The domain core refuses a Receiving binding to a signatory role holder in the same tenant. `me.roles` includes the two signatory roles. The onboarding Channels step shows Matrix and WhatsApp disabled, marked "coming later" (B-05, B-03). Lane mroles: `me.roles` gains `signatories`, the held roles Financial first. The home page names each held role in `#home-signatory`, without a link, since what signatories approve has no page until M5. The Channels save sends `matrix_homeserver: null` and `whatsapp: false` |
| Guide data protection summary and privacy address (2026-11-06) | Platform default, tenant override | Daniel provides a platform default, with `TODO(legal)` wording until he supplies it. A tenant may override both values |
| Guide at publication, lane mguide (2026-11-06) | Not yet answered. Interim, pending Daniel, built under Q37 C, Q38 C and the data protection answer above | A core `PublishCall` decided with the shell's `GuideFacts` carries `GuidePublished { call, version: 1, digest }` in its entry. The engine binds and renders the Guide over the state with the publication folded, and refuses with I-52 when a section is missing or a placeholder does not resolve. The record holds the canonical document and the page, since the engine cannot reach a text store and I-53 makes the Guide immutable. The digest is SHA-256 of the canonical document, through `fstp-crypto`, passed in by the shell. The domain fold refuses a second `GuidePublished`, and the engine fold refuses one outside its publication entry. Corrigenda are the numbered entries of the D12 record. Each restates P-05 and P-13 in full, worded by the Guide's resolvers, and is rendered after the stored page inside its `main` element. `public.guide` and `calls.guide` serve that page and never bind again. The Guide follows the pre-check step with a fixed note that it is not yet available. The platform default summary is `TODO(legal)` wording, its address a reserved `.invalid` name, and `TenantCommand::SetGuideNotice` overrides both. Lane mguidefin: the fake shell supplies `GuideFacts`, reading a set SuperSAFE spec for a programme with no creator draft, so the e2e cell stores the Guide. `tenant.set_guide_notice` (tenant admin, web only, high-risk, step-up) stores the summary as a public text, and the tenant core refuses a non-`https:` address as `InvalidAddress`, named R-GA-01. Under Q38 C, `PrecheckUnavailable` is a warning that needs acknowledgement. `calls.guide` answers `{call, version, digest, html}`. Seams: the production cell decides with no creator environment (`fstp-cell-core`), the applicant Guide page still reads sections, and the strict D2e fold is lane m4d2e-cont's |
| Progress map rendering (2026-11-06) | Server tree as data | The journey read returns the Rust renderer's checked element tree, and the browser builds it against the closed SVG subset. ADR-015 is amended (lane j4) |
| MCP server, lane W3c (2026-11-06) | Q32 answered A by Daniel on 2026-11-06: `fstp_prepare_call_publication` is the only prepare-only tool. The rest is not yet answered. Interim, pending Daniel | `fstp-mcp` serves the design's methods at the ADR-013 floor revision 2025-06-18, since revision 2026-07-28 removes `initialize`, `ping` and sessions (open point for Daniel). Checks run in this order: `GET` 405, the `Origin` rule, the bearer (401 with the RFC 9728 challenge, 400 if malformed), media types, the JSON-RPC body, then the session. Every request but `initialize` names a session of the same endpoint (400 without, 404 unknown) and the negotiated `MCP-Protocol-Version` (400 otherwise). Tool methods wait for `notifications/initialized`. A session carries no right and is stored as a labelled digest. At most 4096 are held, and the oldest is evicted. Every call goes through `ApiCore::dispatch`, with no credential on `/mcp/public`. A refusal is `isError` with the API refusal body. `untrusted` lists every string of `data`. A tool call whose token resolves to no grant gets 401 `invalid_token`. `ApiCore::tool_rights` resolves a bearer token to its principal with no operation. `/mcp` refuses a token with no grant at `initialize` and `tools/list` with 401 `invalid_token`, and lists the public tools plus those whose scope the token holds and whose operation one of its roles performs (TH-63). `proposal.view` runs `ReadContent` by the team, so the read appends a `ContentRead` through the web and MCP alike (R-AU-01). The matrix MCP channel calls each tool through `McpServer::call_tool`, since the fake tokens fit no HTTP field. An operation with no tool is called by its name, which the server refuses as `NotExposed`. `FSTP_MATRIX_OPS` narrows `compare_grouped` to named operations. The test-only feature `test-cell` of `fstp-oauth` and `fstp-web` adds `WebConfig::test_cell`, which admits a plain `http` issuer under `.localhost`. Only the e2e cell sets it, and a production configuration still refuses such an issuer |
| Public cells of the authorisation matrix (lane mpub, 2026-11-06) | Not yet answered. Interim, pending Daniel | `FSTP_MATRIX_OPS` narrows a local matrix run: a comma-separated list where an entry ending in `.` is a prefix and any other entry is an exact operation name. Unset, every cell runs, and a kept cell is judged as in the full matrix. Reading of section 3.10 "Routes": the open-call list, the deadlines and the eligibility have no page under `/p`, so they are public research tools only (`mcp-server.md`) and the matrix gives them MCP cells only. Every other public operation keeps its web cells. Before this lane every web cell of a public operation was `NotFound("route")` and every MCP cell agreed. The harness now sends a public page as the `/p` router serves it: the programme page at `/p/{slug}/` and the feed at `/p/{slug}/feed.json`. Its direct channel decodes a `GET` under `/p/` with `decode_public_page`, as `fstp-web`'s router does. The registry routes, the router and every verdict are unchanged. With `FSTP_MATRIX_OPS=public.`, all nine public operations agree on both channels, direct and HTTP, with no failure (lane mpubfin, 2026-11-06). Before activation every page answers not found, which is right, since only an active programme is public. The programme, funded, finished and feed pages are then served. A world now opens over a copy of the start's texts as well as its ledger, so the P-09 wording stored during the start resolves and the open call page is served (lane mpubfin2). The Guide page still answers not found in every state. That is the M4 seam of `dispatch/public.rs`, which fails closed, so its web cell agrees with `Allow` only as a not found guard. `i87_r_pb_04_direct_public_pages_are_served_once_active` pins that answer and fails once the seam lands. `review_authz_direct_public_page_cell_is_not_vacuous` now picks a cell of an active programme, since a draft programme rightly answers not found |
| Review and committee matrix readings (lane mrev, 2026-11-06) | Daniel answered the two open points on 2026-11-06. The other readings are interim, pending Daniel | The matrix reference takes four readings. The scores a suspended reviewer gave carry a notifiable conflict (Identity discovery, R-CF-04), so from the stage 1 close on I-03 refuses its reads of the proposal. Recusal from a cut-off vote holds only while a proposal of the call is RANKED, so a ballot on a recorded round is refused by its state (R-EV-09). Under P-10 "all committee members" a committee member makes the proposal-level declaration, as the coordinator does (Conflict declarations); the chair does not. The team's content read of a DRAFT shows its latest workspace (R-AC-01, I-21). Every review and committee command refuses the actor before the state (test plan, authorisation matrix): an outsider under the actor rule, a conflicted person under I-03, and an undeclared one under R-CF-02. A conflict fact recuses a member before the ballot's own checks. Daniel (a): after a terminal state the former lead and team member keep a read-only view of `proposal.view`, `stage2.view` and their own `review.read_content` (`ReadRule::FormerTeam`, as lane j4 reads it). No binding revives and every command stays refused. The guardian, whom the answer does not name, reads nothing there. O-54 still hides scores and comments. Daniel (b): a declared conflict is final. A second declaration on the same proposal, at proposal level or on an assignment, is refused under I-03, and the person stays recused. `review.mark_finding` takes `{"mark": "Agreed" or "Disputed"}`. `review.findings` lists the findings on the assignment's proposal from its call, each with the reader's own mark |
| Creator matrix and Studio reads (lane mcreator, 2026-11-06) | Q35 A and the step-up answer above. Interim readings, pending Daniel | `overview.md` NOTE 8 records the two Q35 queries. Their table rows wait for `QueryKind`, which the table test reads. `creator.impact` lists the calls that some change of a policy field to its head value reaches (R-PG-04), since the read names no change. A published call whose limits do not read refuses the read. `me.add_passkey` asks for its step-up, then answers `not_implemented` until a port registers a credential. A creator command and the four call commands judge the actor before the state (test plan, authorisation matrix row). A creator command on an active programme, and a second approval of a call, are refused by the transition row. `call.list` lists a programme's calls to its call staff, with `may_approve` per R-PC-03. `call.draft` answers the drawn call id |

### 15.1 These block the milestone

**Q1. Who approves activation, and who counts as a builder (I-67)?** The spec names no approving role.

- A: A tenant admin outside the builder set. Builders are the opener, every policy author, every creator record author, every import resolver, every acknowledger and every grantor of a draft binding.
- B: As A, but a programme manager bound to the draft may also approve.
- C: Only a programme manager bound to the draft.
- Recommendation: A. It is the narrowest set, mirrors the `CreateProgramme` actor and fits the two-admin rule of SoD-07. With A1 opening and A2 approving, it works for every tenant that completed onboarding.

**Q2. Does "second person" in I-67 also mean a second verified identity?** `00-scope.md` says a person is a tenant account, and only I-06 lifts that. A `SameIdentityAsAny` answer means something only when every account in it is verified. Tenant admins hold no Drafting or Judging role, so SoD-09 never verifies them.

- A: Account only.
- B: Also require `IsVerified` for the approver and every builder, then refuse when `SameIdentityAsAny(approver, builders)` holds. Tenant admins verify their identity at onboarding.
- Recommendation: B. It closes the Sybil path of TH-03 for tenant admins too. The cost is one vault verification per admin and a few recorded queries per activation.

**Q3. A draft programme in the domain core (D1 to D3, D8).**

- A: `CreateProgramme` creates a `Draft` programme, a new `ActivateProgramme` activates it, and M2 scenarios add the activation.
- B: Keep the draft in the creator only. Activation creates the programme with an authors map, and builders hold no programme manager binding while they build.
- Recommendation: A. "Named programme manager" in I-65 then has its literal meaning, and SoD-09 applies to builders. B needs a second authorship mechanism for R-PC-03.

**Q4. Committee ballots (R-EV-09, D5).** M2's `RecordCutOff` takes every ballot from one recorder.

- A: Each member casts or delegates their own ballot. `RecordCutOff` counts only cast ballots.
- B: Keep one recorder who enters every ballot.
- Recommendation: A. Under B, one member's session states every other member's vote.

**Q5. Validation checks whose machinery arrives later (channels, sending domain).**

- A: Fail closed. Production activation of SuperSAFE waits for M8, because P-32 names Matrix and WhatsApp. Tests use recording-fake probes.
- B: A warning that needs acknowledgement until the milestone lands.
- C: Build SuperSAFE with P-32 as email only, and add channels later by a live edit.
- Recommendation: A. It weakens nothing, no production release comes before M10, and the fixture stays equal to the spec column.

**Q6. `TODO(legal)` wording in the Guide, the agreement texts, the reviewer terms and the notices.**

- A: Pending wording is a validation failure. A profile variant with "SYNTHETIC TEST WORDING. NOT LEGAL TEXT." loads only in the end-to-end cell, from `fstp-api-testkit`. In production, approved wording ships in the profile after your legal review.
- B: A warning at activation and a failure at call publication.
- C: Publication with the markers visible.
- Recommendation: A. Please also say who records the approval: CrabNebula in the platform profile, or each tenant.

**Q7. Host runtime for tsc, Playwright, the TypeScript test runner and the TypeScript fuzz harness.** ADR-003 allowlists tsc and Playwright but names no host.

- A: An exact Node.js LTS version, named in an ADR-003 amendment, used at build and test time only, with `npm ci --ignore-scripts` and the lockfile gate.
- B: Deno.
- C: Bun.
- Recommendation: A. Both allowlisted tools are distributed for it.

**Q8. MCP and OAuth profile (ADR-013).**

- Revision: pin the newest dated revision at W0 after checking its text, with 2025-06-18 as the floor.
- Registration A: open dynamic registration, rate-limited, with no metadata fetch.
- Registration B: pre-registered clients only.
- Registration C: client ID metadata documents, which need outbound fetches from the cell.
- Tools: only the capability table of `mcp-server.md`, plus the prepare-only tool of Q32, with no coordinator, ballot, IRC or tenant admin tools.
- Recommendation: registration A, tools as listed. Connecting already needs a step-up.

**Q9. The pre-declaration "neutral summary" (R-CF-02).** `roles-and-sod.md` shows reviewers "the title and a neutral summary" before they read, and says the ranking-view summary is written by assigned reviewers.

- A: The applicant writes a short neutral summary in a length-limited field labelled "do not identify yourself". It is shown with the title before declaration and covered by canary tests.
- B: Title only before declaration.
- C: The coordinator writes it after the knock-out read.
- Recommendation: A, which keeps the spec text. B is stricter on content but drops the summary the spec promises.

**Q17. Cross-tenant templates (I-73) and the P-76 directory.** The M9 row of `09-milestones.md` lists neither. R-MC-04 asks for the directory as part of the public research tools, which are M4 scope.

- A: Both in M4, through the control plane publication path.
- B: Both deferred to M9, with an amendment to `09-milestones.md` that names them there. M4 has shipped templates, clones and tenant-private templates.
- C: The directory in M4 and template publication in M9.
- Recommendation: B. Both use the control plane publication path, which needs composite or Ed25519 signing (ADR-001) and a personal data scan. Both also bear on the DSA position while L-16 is open (Q44). R-MC-04 stays partial in M4.

**Q23. The minor flag before NEGOTIATION (I-18, R-ID-04, R-NG-01, R-SB-01, R-SB-02, L-02).** The sources conflict. I-18 needs the flag before NEGOTIATION. R-ID-04 asks for a flag derived relative to the call deadline, not a self-declaration. R-NG-01 collects identity attributes only in NEGOTIATION, and L-02 is open on a minor's data before consent. A self-declared "no" from a minor lets the proposal enter NEGOTIATION without consent. The state machine then catches it at NEGOTIATION to GRANTED, where identity and consent are verified, but I-18 is already broken at entry.

- A: Self-declared yes or no at draft creation, to the domain and the vault. A false "no" is grounds to decline at verification. This is the interim, and it leaves the entry gap above.
- B: The applicant states a date of birth at submission, to the vault only, like the country under NOTE 9. The vault derives the flag relative to the call deadline and answers one bit. A false statement is grounds to decline at verification. This extends the R-NG-01 exception and needs `TODO(legal)` under L-02.
- C: Verify age, and consent where needed, before NEGOTIATION through the vault. This meets I-18 fully but collects identity attributes before NEGOTIATION, against R-NG-01.
- Also: guardian verification for I-18 must happen before NEGOTIATION under every option, which already collects the guardian's attributes early. Source order puts I-18 above R-NG-01, so this design collects them only once the minor's proposal is nominated (IRC_REVIEW), and only in the vault.
- Recommendation: B. It gives the derived flag R-ID-04 asks for, keeps attributes in the vault, and closes the entry gap for honest statements. It needs your legal decision under L-02, and the `r_sb_01_no_form_field_for_identity_dob_or_payment` test changes to allow the vault-only field.

**Q28. Guide PDF (R-GA-02).** R-GA-02 asks for accessible HTML and a PDF.

- A: HTML in M4 and the PDF in M5, with the deterministic PDF writer that contracts need.
- B: An in-house PDF writer for the Guide in M4, with its own fuzz target for any PDF it reads back.
- Recommendation: A. One PDF writer serves the Guide and contracts. R-GA-02 stays partial in M4.

**Q31. Owner of the tenant admin set.** It decides the attested `Ctx` under I-67 and SoD-07.

- A: `fstp-tenant` records in the cell ledger, with M3 provisioning the first admin. SoD-07 approvals and their audit trail live in the ledger.
- B: M3 tenant configuration owns the set, and M4 reads it through `TenantConfig`.
- Recommendation: A. The admin set then has the ledger's replay and append-only guarantees, and the I-67 checks read one source.

**Q32. Prepare-only MCP tools for high-risk actions (I-85).** I-85 says an agent can prepare high-risk actions. Without a high-risk tool, the prepare path has nothing to exercise.

- A: Prepare-only tools only where a capability table row covers the action. In M4 that is `fstp_prepare_call_publication` for programme staff ("call drafting").
- B: As A, plus prepare-only tools for tenant admin actions such as role grants and activation approval, with a new capability table row.
- C: No high-risk tool. I-85 rests on the bypass twin and `channel_policy` tests alone.
- Recommendation: A. It follows the capability table, gives I-85 a real preparation path, and adds no new agent powers. B widens the agent surface for the most sensitive actions.

**Q33. Fuzzing TypeScript parsers.** CLAUDE.md requires a fuzz target for every in-house parser. cargo-fuzz cannot reach TypeScript, and no TypeScript fuzzer is allowlisted.

- A: The in-house seeded harness in `web/fuzz/` with differential corpora shared with the Rust targets (section 9). No coverage feedback.
- B: Add a coverage-guided TypeScript fuzzer through an ADR-003 amendment.
- C: Move every parse out of TypeScript: the server sends pre-validated, display-ready values, and the client only renders.
- Recommendation: A now, with C applied wherever it is cheap. The differential corpora give the harness much of what coverage feedback would. Please confirm that A meets the CLAUDE.md rule for TypeScript.

**Q34. What "full" means for the authorisation matrix.** `test-plan.md` asks for every role, action and state combination.

- A: The full product of operation, principal and state in every channel, with the full session product, and a 9-row covering array for policy (section 8.3).
- B: As A, with the full policy product in the direct channel only.
- C: The full product of every dimension in every channel, in a nightly job, with A on every push.
- Recommendation: A on every push, and C nightly. The fallback in section 8.3 keeps every operation, principal and state cell, and changes only policy coverage in the HTTP and MCP channels.

**Q35. Two new vault queries.** `ExclusionClassUnknown` and `ProximityListMissing` need `classes_defined` and `proximity_lists_declared`. `overview.md` says "The query set was decided on 2026-10-25".

- A: Add both one-bit queries to the decided set through a spec change.
- B: Drop both checks. An unknown P-13 class then fails closed at the first I-04 query, after activation.
- C: Keep the checks against programme-side data only, such as class ids in the funder profile, with no vault query.
- Recommendation: A. Each answer is one bit and names no account. B finds a missing class only when a person is already affected. C cannot tell whether the vault knows the class.

**Q37. P-05 and P-13 tightening after publication (NOTE 7, O-52, I-51, I-53).** NOTE 7 allows a tightening after publication and requires a numbered corrigendum. Corrigenda (I-53) are planned for later milestones, so a tightening in M4 would leave the Guide unequal to the effective limits.

- A: Refuse a tightening of P-05 or P-13 on a programme with a published call until corrigenda exist. This is the interim. It also blocks a protective P-13 addition, which would void bindings under I-04.
- B: Allow the tightening and do not claim I-51 in M4.
- C: Build the effective-limits record (D12) and numbered corrigendum generation in M4. Notification dispatch follows in M6, so I-53 is claimed later.
- Recommendation: C. It keeps the protective P-13 path open and makes I-51 true in M4 for P-05 and P-13. The cost is one record kind and a Guide corrigendum renderer.

**Q38. The P-23 pre-check in the SuperSAFE Guide.** SuperSAFE's P-23 is "Enabled", but the pre-check arrives in M7. A Guide that describes it would be false.

- A: `PrecheckUnavailable` fails validation in any cell without a pre-check provider. Production activation of SuperSAFE then waits for M7, as Q5 already makes it wait for M8.
- B: Build SuperSAFE with P-23 disabled until M7. The fixture then departs from the spec column.
- C: Keep the Guide section, with a note that the pre-check is not yet available.
- Recommendation: A. It keeps the fixture equal to the spec and never publishes a false statement. The e2e cell uses a fake provider so the journey runs.

### 15.2 These shape the milestone but can follow

**Q10. Step-up on both `CreateProgramme` and activation.** `authentication.md` says creating counts as activating (confirmed 2026-10-25), before an activation step existed. Recommendation: keep both high-risk, the strict reading.

**Q11. Milestone claims for unclaimed invariants.** `09-milestones.md` claims none of I-45 to I-64, I-72 or I-73. Recommendation: M4 claims I-48, I-50 and I-52, which its checks enforce. It claims I-51 too if Q37 is answered C, since otherwise a later tightening can break it. I-49 and I-45 to I-47 go to M5. I-53, I-72 and I-73 go to M9. I-41 to I-43 stay in M9 as planned, with M4's supporting properties.

**Q12. A clean report at publication.** Built: the engine recomputes the report at publication and refuses unless it is clean, because the Guide is generated then and I-52 must hold then. Please confirm.

**Q13. The live SoD check in creator step 9.** Built strictly: `preview_grant` asks the vault, records every answer as a digest and a bit (NOTE 5), and is rate-limited. A refusal names only the rule.

- A: Keep this.
- B: Local rules only, with vault rules at the grant.
- Recommendation: A. It matches "live separation of duties checks", and the grant checks again anyway. Please confirm that the platform may ask these questions before any grant.

**Q14. Findings through MCP with P-75 off.** `mcp-server.md` allows "findings that quote no submission text", which the platform cannot verify. Recommendation: metadata only, without `statement`, until M7 can mark quoting findings.

**Q15. The caller's own identity data through MCP.** Recommendation: never, including the caller's own name and email, the literal reading of I-86.

**Q16. Ranking and IRC views.** Recommendation: ranking rows of proposals where the viewer has a conflict show "recused" only. The IRC case shows content and outcome with no scores, ballots or rationale.

**Q18. Horizon Europe profile overlap with M9.** Recommendation: M4 ships only the Guide template, the parameter bounds and the flow-down obligation identifiers that SuperSAFE needs. M9 owns the profile bundle format and the other funder outputs.

**Q19. Public rate-limit key while R-NF-02 is open on IP addresses.**

- A: An IP prefix (/24 for IPv4, /48 for IPv6), hashed with a daily random salt held in memory, never logged or stored.
- B: A client-chosen anonymous id only.
- Recommendation: A, which also settles the M1 open point for this use. Behind a TCP load balancer, the client address needs PROXY protocol (section 7.1).

**Q20. Public pages in a separate process.** One proposal served public pages from a separate binary with a SELECT-only database role on a snapshot table. Recommendation: render in the cell from the engine snapshot in M4, and revisit the separate process with M9's public transparency pages.

**Q21. Accessibility tooling.** Recommendation: in-house checks plus a manual review in M4. Revisit an ADR for axe-core after the first audit.

**Q22. Onboarding data split.** Recommendation: the control plane keeps the legal entity, billing address, contracting signatory, agreement acceptances and the operator review. The cell keeps the data protection contact and contract signatories.

**Q24. Attachments and import formats.** Recommendation: no proposal attachments, and text or Markdown imports only, until M7's sandboxed extraction and metadata stripping exist (TH-07, TH-16).

**Q25. Lifetimes.** Recommendation: 10-minute access tokens, rotating refresh tokens bounded by the P-72 absolute lifetime, and pending actions that expire after 24 hours with no batch confirmation.

**Q26. Threat model and timing.** Recommendation: add TW-1 to TW-9 as TH ids, and show applicants reviewer question times at day granularity (TH-08).

**Q27. Do hidden grants count towards P-54?** Recommendation: aggregates count only published grants, so no hidden grant contributes to a public figure. M4 shows no aggregates.

**Q29. Milestone shape.**

- A: One milestone with the lanes above.
- B: M4a (creator, public pages, role interfaces, matrix through web, I-65 to I-67) and M4b (OAuth, MCP, I-84 to I-87).
- Recommendation: B if M3 lands late, since M4a needs only the fake cell. A otherwise.

**Q30. Import resolution.** Recommendation: an unresolved proposal is a validation failure, and each value is resolved on its own, with no "accept all". A per-step confirmation that lists every value can follow if this proves slow.

**Q36. Placement of programme parameters that no creator step names.** P-06, P-12, P-19, P-22, P-39, P-42, P-43 and P-46 to P-49 are programme level in `CATALOGUE` but appear in no "Bounded by" cell. P-18, P-21 and P-45 appear in onboarding but are programme level.

- A: The placement in section 3.1, with onboarding values as tenant defaults that prefill drafts.
- B: A separate "Advanced" step for the unlisted parameters.
- C: Make P-18, P-21 and P-45 tenant level, changing `policy-parameters.md`.
- Recommendation: A, with a staged change to the creator table that lists them. C would change a decided parameter level.

**Q39. Content reads in RANKED, DEFERRED and the terminal states.** The spec states no reader for these states. M2 refuses them, and its audit left 1,436 RANKED reads unjudged.

- A: Applicant team only, as M2 does. Committee members use the ranking view.
- B: Also the assigned reviewers of the proposal in RANKED, for the cut-off deliberation.
- Recommendation: A, the strict reading. B can follow if committees need it.

**Q40. Workspace drafts in tenant exports (R-TD-01, I-21, I-22).** I-22 wants an export plus import to give an equivalent tenant. I-21 keeps drafts from operator roles, and tenant admins read exports.

- A: Exclude drafts, and define I-22 equivalence modulo private workspace drafts, by a spec change.
- B: Include drafts as ciphertext with their wrapped keys, re-wrapped for the target cell, so no tenant admin can read them.
- C: Include drafts in clear.
- Recommendation: B if the M9 export design can carry wrapped keys without giving tenant admins the unwrap key. Otherwise A. C breaks I-21. This must be answered before M9, not before the M4 exit.

**Q41. Who owns the recovery and break-glass approval flows?** I-79 is an M3 exit invariant. SoD-08 break-glass is claimed nowhere.

- A: M3 owns both flows and their invariants. M4 adds the approval screens and registry rows (J10).
- B: M4 owns the break-glass flow too.
- Recommendation: A. The flows touch authentication and key custody, which are M3's.

**Q42. P-74 "limit it to some roles".** An account can hold roles that P-74 allows and roles it does not.

- A: Refuse an MCP op when any role through which it can act is disallowed. This is the interim.
- B: Allow it when any role through which it can act is allowed.
- Recommendation: A, the strict reading. A tenant that limits MCP to applicants then never exposes a reviewer action through an account that also applies elsewhere.

**Q43. The MCP server's white-labelled name.** `mcp-server.md` says white-labelling covers the server's name. TH-63 says tenant text must not alter tools.

- A: `serverInfo.name` is the verified domain label only, and no `title` or `instructions` is sent.
- B: The tenant's display name, length-limited and charset-checked.
- Recommendation: A. It is white-labelled and carries no free text to agents.

**Q44. DSA and AI Act positions.** `dsa.md` ties online platform status partly to the public MCP tools, which M4 ships per cell. `ai-act.md` lists a reassessment trigger when P-77 allows agents to record scores.

- A: Ship both as designed, record the AI Act trigger as an acknowledged warning, and leave a `TODO(legal)` on the DSA position until L-16 is settled.
- B: Hold the public MCP tools until L-16 is settled.
- Recommendation: A. These are legal questions for you, and this design draws no legal conclusion.

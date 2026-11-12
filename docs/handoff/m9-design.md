# M9 design: post-quantum signatures, branding, public pages, funder profiles and SBOM

Milestone M9 in `SPEC/09-milestones.md`: "moduletto ML-DSA-65 integration with ACVP and differential tests, composite signatures, branding tokens and terminology overrides, public transparency pages, funder profiles with the Horizon Europe profile, SBOM". Exit: I-41 to I-44, I-68 to I-70 and I-90 green.

Deferred by Daniel on 2026-11-04 and out of scope: custom domains and full white-label packages (B-09, so I-71 is not claimed), tenant export and import (B-07), profile bundles (B-08), self-hosted packaging (B-06), the desktop client (B-04).

Status: short build design for one-agent lanes, written 2026-11-06. Lane labels such as `C1` exist only in this document. Every `I-`, `R-`, `P-` and `ADR-` identifier is quoted from the repository. Crate, record, op and file names marked new are proposals.

Sources read: `09-milestones.md`, `02-domain/{invariants,public-transparency,policy-parameters}.md`, `03-architecture/{white-labelling,funder-reporting}.md`, `07-test-plan/test-plan.md`, `SPEC/profiles/horizon-europe/`, ADR-001 (with A2 and the pin move record of 2026-10-29), `docs/handoff/{m4,m5}-design.md`, `docs/design/{08-design-tokens,09-tenant-admin,10-post-grant-screens}.md`, and the code of `fstp-crypto`, `fstp-celltest`, `fstp-public`, `fstp-journey` (`vocab.rs`), `fstp-creator` (`theme.rs`), `fstp-tenant` and `tools/deps-check`.

---

## 1. Scope

### 1.1 What already exists

| Exists on `main` | M9 adds |
| --- | --- |
| `fstp-crypto::mldsa` forwards to `moduletto::dsa::ml_dsa_65` at pin `6c1ae92` (moduletto PR #13, merged 2026-10-29) | Nothing new in the primitive. A claim run and one cross-crate I-90 sweep (lane C1) |
| ML-DSA-65 ACVP subset in `crates/fstp-crypto/tests/mldsa_acvp.rs`; differential tests both ways in `fstp_celltest::reference::hybrid` (`t_cr_mldsa_differential_*`) | Random-input count raised for the claim run; the exit report names the implementation each test ran against |
| `composite` (draft 19, Ed25519 from aws-lc-rs, ML-DSA-65 from moduletto), used by audit anchors, witness receipts, release metadata, recovery codes | The companion signature on contractual notices (lane C2) |
| `fstp_public::public_view_with` filters by I-41, I-42 and I-43 over a `GrantChoices` map that M4 cells leave empty | Grantee choice records, their ops and screens, so real grants can appear (lanes P1 to P3) |
| `fstp_creator::theme`: integer WCAG check `meets_aa`, `MandatoryElement::ALL`, the default tokens | Tenant brand tokens checked by the same code (lanes B1, B2) |
| `fstp_journey::vocab`: plain and Voyage packs over the closed `LABEL_KEYS` list | A tenant terminology pack over the same list (lane T1) |
| M5 lane L-RPT: `fstp-report`, the five Horizon Europe outputs, I-44 at closure | A versioned funder profile format that drives those outputs, and the I-44 rerun (lane F1) |
| `tools/deps-check`: resolved tree, allowlist, Tier B release gate (I-74) | An in-house SBOM generator (lane S1) |

### 1.2 moduletto: what the platform needs

- ML-DSA-65 (FIPS 204) is already in moduletto at the pinned commit `6c1ae92`. Its ACVP keyGen, sigGen and sigVer vectors run in moduletto and in platform CI. No further moduletto pull request blocks M9.
- Every M9 lane proceeds against the current pin. No lane changes the pin, the features (`default` only) or the resolved tree.
- Still needed before a release, not before M9 exit: a Mythos-tier confirmation of `moduletto 0.1.0` at `6c1ae92` in `deps/tier-b-confirmations.txt` (I-74, M10). `deps-check --release` stays red until then, as intended.
- Optional asks for a later moduletto pull request, none blocking: a tagged release so the pin can name a tag and a commit, and keeping the ACVP vector files in moduletto CI at each tag.
- aws-lc-rs ML-DSA stays a test oracle in `fstp-celltest` only (ADR-001 A6). Nothing falls back to it or to Ed25519 alone (I-75, I-90).

### 1.3 Interim scope decisions, pending Daniel

These keep lanes small. Each one narrows scope and weakens no invariant.

| # | Decision | Reason |
| --- | --- | --- |
| D1 | Brand tokens are the tenant name and the brand colour family only: `brand`, `brand-hover`, `brand-text`, `on-brand`, `focus`, in light and dark. Surfaces, text and state colours stay platform tokens | These are the tokens tenants recolour. It keeps the I-70 pair table small and exact |
| D2 | Typography is a closed token with one value, `system`, in M9. Logos, favicons and font files arrive with the full package (B-09) | Image re-encoding and font parsing would each need a new in-house parser. B-09 is deferred |
| D3 | Funder profiles are shipped and versioned. A programme pins one version through P-53. Tenant-authored profiles wait for a later decision | M4 rule A9b loads shipped profiles only. Tenant-authored templates would reopen approved wording (I-72) |
| D4 | The M4 I-42 rule stays: a minor-flagged proposal never appears, at any level. The Q26 reading (Project level allowed for a team with a minor) is not built | Stricter than I-42 and already tested |
| D5 | The SBOM format is CycloneDX 1.6 JSON, generated in-house. `TODO(legal)`: whether CRA implementing acts name a format (`05-compliance/cra.md`) | No third-party tool is allowlisted. JSON goes through `fstp-json` |
| D6 | The notice companion signature uses a new composite key purpose `Purpose::NoticeCompanion` in `fstp-keys` custody, separate from the anchor key. Its context string is `fstp-notice-companion-v1` | Key separation per artifact kind. Lane C2 adds the ADR-004 record line |

---

## 2. Records and ops

### 2.1 Records

| Where | Record | Fields | IDs |
| --- | --- | --- | --- |
| `fstp-domain/src/publicity.rs` (new) | `PublicChoiceSet` | proposal, phase (`funded` or `finished`), level (`hidden`, `project`, `project_and_grantee`, `full`), title text ref, summary text ref, grantee name text ref, deliverable refs (finished only), actor | R-PB-02, R-PB-03, I-43 |
| same | `PublicChoiceWithdrawn` | proposal, phase, actor | I-43 |
| `fstp-tenant` | `TenantRecord::BrandingSet` | tokens (typed), tokens digest, actor | I-68, I-70 |
| same | `TenantRecord::TerminologySet` | pack bytes digest, pack (typed labels), actor | I-72 |
| `fstp-report` | `ReportGenerated` gains `profile { id, version, digest }` | from the pinned P-53 | R-RP-01, I-44 |
| `fstp-contract` notice builder | `NoticeCompanionSigned` | notice, notice digest, composite public key digest, signature | ADR-001 Post-quantum signatures |

Rules for the records:

- A choice above the programme maximum is stored as chosen. The filter applies the lower of the two at read time, so lowering P-50 or P-51 narrows pages at once (I-43).
- Title and summary texts are grantee-written public texts (`TextStore::get_public`). The op refuses a text ref that points at proposal content (R-PB-03).
- `GrantChoices` is folded from the two publicity records. `public_view_with` is then the only filter, as in M4 (I-87).
- Public responses already carry `Cache-Control: no-store`. Withdrawal therefore reaches pages and the feed on the next request.
- Brand tokens are typed values: `PlainText` name (1 to 80 bytes, no control characters, no angle brackets) and `Rgb` colours. No record holds CSS, markup, a URL or a script.

### 2.2 Ops

| Op | Who | Records | Guard |
| --- | --- | --- | --- |
| `grant.publicity.view` | Grantee lead | none | Current choice, P-50, P-51, minor flag (disables levels) |
| `grant.publicity.set` | Grantee lead | `PublicChoiceSet` | State GRANTED or later for `funded`, COMPLETED for `finished` (I-41); texts are public texts |
| `grant.publicity.withdraw` | Grantee lead | `PublicChoiceWithdrawn` | none |
| `tenant.branding.check` | Tenant admin | none | Returns failing pairs and missing mandatory elements, never saves |
| `tenant.branding.set` | Tenant admin | `BrandingSet` | Refused with the failing pairs listed when any pair fails (I-70) |
| `tenant.terminology.set` | Tenant admin | `TerminologySet` | Parsed by `fstp_journey::vocab` with pack kind `tenant`; keys in `LABEL_KEYS`; `FIXED` keys unchanged |
| `programme.funder_profile.view` | Programme staff | none | Shows the pinned P-53 version and its outputs |

Public routes are unchanged: `/p/{slug}/...` pages, the feed when P-52 is on, and the public MCP tools, all over `PublicView`. New route: `GET /brand/{digest}.css`, generated from tokens, served `text/css` with `Cache-Control: public, max-age=31536000, immutable`.

### 2.3 Generated CSS (I-68)

`fstp_brand::css(tokens)` emits exactly `:root{` then one `--color-<key>:#rrggbb;` per token, then a `@media (prefers-color-scheme: dark){:root{...}}` block, then `}`. The key list is closed. Hex digits come from `Rgb`, never from input text. The tenant name reaches pages only through `fstp-html` text nodes. CSP gains `style-src 'self'` on `/p` and keeps `script-src 'none'` there.

### 2.4 Mandatory elements (I-69)

The page layout renders the footer after branding is applied, from platform data. No brand token can name, hide, size or reorder a footer element. The footer holds one element per `MandatoryElement::ALL`, each with a stable `data-mandatory` attribute. The funder visibility element comes from the pinned funder profile. Its wording carries `TODO(legal)` (L-08, L-09) until Daniel supplies approved text. The attribution link uses `brand-text` on `surface-0`, which is one of the checked pairs.

### 2.5 Funder profile format (D3)

One I-JSON file per version under `crates/fstp-report/profiles/<id>/profile.v<n>.json`, parsed only through `fstp-json`, fuzz target `funder_profile_parse`.

| Member | Value |
| --- | --- |
| `funder_profile_version` | the integer 1 |
| `id`, `version` | `horizon-europe`, 1 |
| `outputs` | the five kinds of `funder-reporting.md`, each with a template ref and a field list |
| `fields[].figure` | a closed enum of ledger folds: paid in period, committed, released commitment, recipient count, and the like. No literal number |
| `visibility_elements` | keys of required funder visibility elements, wording refs marked `TODO(legal)` |
| `reporting_periods` | a reference to the Data Sheet parameter, never dates in the file |

Because a field can name only a ledger fold, no profile can introduce a figure that does not reconcile (I-44).

---

## 3. Tests per invariant

Each test names its ID. Property tests are written before the code they constrain.

| ID | Test | Lane |
| --- | --- | --- |
| I-41 | `i41_never_granted_never_public`: generated programmes in every state, with random choice records including records for never-granted proposals; no page, feed item or public tool answer names them. Choice ops on a never-granted proposal are refused | P3, P1 |
| I-42 | `i42_minor_never_named`: generated teams with minors and random choices at every level; no minor's name or any minor-flagged proposal appears on pages, feed or tools | P3 |
| I-43 | `i43_lower_of_max_and_choice`: random P-50, P-51 and choices; each grant shows exactly the fields of `min(max, choice)`, none without a record. `i43_withdrawal_and_narrowing_immediate`: after withdraw or lower P-50, the next page and feed request no longer show the grant. Aggregates below P-54 are withheld (R-PB-05) | P3 |
| I-44 | `i44_profile_fields_are_ledger_folds`: every field of every shipped profile names a fold. `i44_seeded_mismatch_fails_generation`: generated ledgers with a seeded discrepancy fail generation and list it, under HE v1 and a second synthetic test profile | F1 |
| I-68 | `i68_fuzzed_branding_is_data`: fuzzed branding input is refused or yields typed tokens; generated CSS matches the grammar of 2.3 byte for byte; the name appears only escaped. Fuzz target `branding_parse`. `i68_csp_unchanged`: every route keeps its CSP, `/p` keeps `script-src 'none'` | B1, B2 |
| I-69 | `i69_footer_survives_any_branding`: for every page kind and random accepted tokens, each `data-mandatory` element is present, non-empty and uses a checked colour pair | B2 |
| I-70 | `i70_accepted_iff_all_pairs_pass`: random tokens are accepted exactly when every pair passes `meets_aa` in both modes; a refusal lists exactly the failing pairs. The M4 bound test `i70_contrast_bounds_enclose_f64_values` stays | B1 |
| I-72, I-94 | `i72_tenant_pack_labels_only`: a tenant pack mapping every key to a canary string; the canary appears in labels and never in the Guide, contract text, notices, funder documents or email bodies that exist on `main` | T1 |
| I-75 | `i75_pq_only_through_hybrids`: source scan; `fstp_crypto::mldsa` and `fstp_crypto::mlkem` are named only by `fstp-crypto` and `fstp-celltest` | C1 |
| I-90 | `i90_every_verifier_rejects_one_half`: one table of every composite verifier (audit anchors, witness receipts, release metadata, recovery codes, notice companion); each rejects a signature with a valid Ed25519 half and a corrupted ML-DSA half, and the reverse. A source scan fails if a new `composite::verify*` call site is missing from the table. Differential tests run both ways on at least 1000 random inputs in the claim run | C1, C2 |
| R-NF-07 | `r_nf_07_sbom_matches_tree`: SBOM components equal the deps-check resolved tree; build-time tools (Node.js, npm, tsc, Playwright) are marked build-time (ADR-003); Tier B components carry their confirmation status; two runs give identical bytes | S1 |

---

## 4. Lanes

At most three lanes run at once (medium mode). Each lane owns its files and starts when its needs have merged into `main`. Files marked shared are append-only for M9: add rows at the end and rebase on conflict.

| Lane | Builds | Owns | Needs |
| --- | --- | --- | --- |
| C1 | I-75 scan, I-90 verifier sweep, claim run of ACVP and differential tests | `crates/fstp-celltest/tests/i90_every_verifier.rs` (new), `crates/fstp-crypto/tests/i75_pq_only_through_hybrids.rs` (new) | None |
| S1 | `deps-check sbom`, CycloneDX 1.6 JSON, CI job that writes the SBOM as a build artifact, ADR-003 record line | `tools/deps-check/src/sbom.rs` (new), `tools/deps-check/tests/sbom.rs` (new), `.github/workflows/ci.yml` (sbom job), `docs/adr/ADR-003-build-and-test-tools.md` (record line) | None |
| B1 | New pure crate `fstp-brand`: token types, parser, fuzz target, contrast check over the pair table, `BrandingSet` record, `tenant.branding.{check,set}` decisions | `crates/fstp-brand/**` (new), `crates/fstp-tenant/src/{command,codec,decide}.rs` (branding rows), `deps/fuzz-required.txt`, `tools/deps-check/src/layering_m4.rs` (pure crate list), shared | None |
| P1 | Publicity records, fold into `GrantChoices`, `grant.publicity.*` ops and reads, cell wiring of real choices | `crates/fstp-domain/src/publicity.rs` (new), `crates/fstp-domain/src/{command,record}.rs` and `codec/` (shared), `crates/fstp-access/src/{registry,reads}.rs` (shared), `crates/fstp-api-core/src/publicity.rs` (new) | M5 L-DOM and L-API merged |
| T1 | Tenant pack kind in `vocab.rs`, `TerminologySet`, `tenant.terminology.set`, label lookup order tenant then plain, I-72 canary test | `crates/fstp-journey/src/vocab.rs`, `crates/fstp-journey/tests/i72_tenant_pack.rs` (new), `crates/fstp-tenant/src/` terminology rows (shared with B1) | B1 (tenant record rows) |
| B2 | `/brand/{digest}.css` route, CSP `style-src 'self'` on `/p`, footer of mandatory elements in the app shell and public pages, I-68 CSP and I-69 tests | `crates/fstp-brand/src/css.rs`, `crates/fstp-web/src/brand.rs` (new), `crates/fstp-public/src/html.rs` (footer only), `web/src/shell/brand.ts` (new) | B1 |
| P2 | Screens: `grantee-visibility`, public funded and finished lists with deliverables, admin branding and terminology | `web/src/grant/visibility/**`, `web/src/admin/branding/**` (new), `crates/fstp-public/src/{html,feed}.rs` (lists only) | P1, B2, T1 |
| P3 | Property tests I-41, I-42, I-43, P-54 over the cell with real records; two-cell test; M-PUBLIC model gains choice actions | `crates/fstp-api-testkit/tests/i41_i42_i43_m9_*.rs` (new), `crates/fstp-api-testkit/src/mc/public_model.rs` | P1 |
| F1 | Profile format, parser and fuzz target, HE v1 file, P-53 pinning, `fstp-report` outputs driven by profile fields, synthetic second profile, I-44 rerun | `crates/fstp-report/src/profile/**` (new), `crates/fstp-report/profiles/**`, `crates/fstp-report/fuzz/fuzz_targets/funder_profile_parse.rs` (new), `crates/fstp-api-testkit/profiles/synthetic-funder/**` (new) | M5 L-RPT merged |
| C2 | Notice companion signature, `NoticeCompanion` key purpose, ADR-004 record line, verifier row for C1's table | `crates/fstp-contract/src/notice_companion.rs` (new), `crates/fstp-keys/src/hierarchy.rs` (one `Purpose` variant), `docs/adr/ADR-004-key-custody.md` (record line), `crates/fstp-celltest/tests/i90_every_verifier.rs` (one row) | M5 L-CON merged, C1 |
| X1 | Exit: claims run, `docs/handoff/m9-exit-audit.md`, milestone note listing R-IDs and I-IDs | `docs/handoff/m9-exit-audit.md` (new), `SPEC/09-milestones.md` (one NOTE) | All above |

Waves:

1. C1, S1, B1. None depends on M5.
2. T1, B2, and F1 or P1 as soon as the M5 lane each needs has merged.
3. P1 or F1 (whichever waited), P3, C2.
4. P2, then X1.

For the Brussels demo, the shortest visible path is B1, B2, P1, P2: a tenant recolours, a grantee opts in, and the grant shows on the public page.

### 4.1 Claims at exit

- R-IDs: R-PB-01 to R-PB-05, R-WL-03, R-WL-04, R-WL-05, R-RP-01, R-RP-02, R-NF-07.
- I-IDs claimed: I-41, I-42, I-43, I-44 (rerun under profiles), I-68, I-69, I-70, I-72, I-90. Supporting: I-75, I-87, I-94.
- Not claimed: I-71 (B-09), I-73 (cross-tenant templates, M4 Q17), I-74 (stays red for release until the Mythos confirmation in M10).

---

## 5. Security notes

- Branding, terminology packs and profile files are untrusted input. Each has an in-house parser with a fuzz target from its first commit.
- Public summaries and deliverable texts are grantee data. They pass through `fstp-html` escaping and never reach a model as instructions.
- Choice ops refuse any text ref that is not a public text, so proposal content cannot leak through a summary (R-PB-03, I-87).
- Composite signing stays inside `fstp-crypto`. C2 only calls `CompositeSigningKey::sign_with_context` through custody.

---

## 6. Questions for Daniel

No question blocks a lane. Lanes build the interim decisions D1 to D6 of section 1.3. Each can be widened later without a data migration, because the records are typed and versioned.

One item needs Daniel before the public pages go live, not before the lanes start:

- **Funder visibility wording (I-69, L-08).** The Horizon Europe profile needs the approved acknowledgement text and emblem rules. Lanes render a `TODO(legal)` placeholder element. Recommendation: Daniel supplies the text from the SuperSAFE grant agreement, and F1 adds it as a profile wording ref. Accepted by Daniel on 2026-11-13. The placeholder stays until he supplies the text.

---

## P lanes: decisions taken

Lanes P1, P3 and P2, built 2026-11-13. Each decision below is interim, pending Daniel. None weakens an invariant. D1 to D6 of section 1.3 stand.

| # | Decision | Reason |
| --- | --- | --- |
| PD1 | Records and commands spell phase and level as the domain variant names: `Funded`, `Finished`, `Hidden`, `Project`, `ProjectAndGrantee`, `Full`. The read model and the public tools keep the tokens `hidden` to `full` | The codec writes every fieldless enum by its variant name. The level tokens of P-50 and P-51 are unchanged |
| PD2 | Only the grant's lead makes its choices: through an active Applicant binding, or through the Applicant binding that a terminal state ended normally. One rule serves the read (`ReadRule::ChoiceMaker`) and both commands (`fstp_domain::publicity::is_choice_maker`) | COMPLETED ends the Receiving bindings, and the finished choice is made there. A voided binding admits nothing |
| PD3 | A funded choice is set in GRANTED, IN_EXECUTION or COMPLETED, and a finished choice in COMPLETED. TERMINATED refuses both under I-41. `grant.publicity.view` is open in GRANTED, IN_EXECUTION and COMPLETED | A terminated grant shows nowhere, so a choice there has no effect |
| PD4 | A withdrawal needs a current choice of that phase, else it is refused under I-41. Section 2.2 named no guard | Test plan section 3 has every choice op refused on a never-granted proposal. A choice exists only from GRANTED on |
| PD5 | A minor-flagged grant takes `Hidden` only. Any higher level is refused under I-42. The screen disables those levels | D4. The flag fails closed, as the filter reads it |
| PD6 | The set op takes the title, summary and grantee name as text, never as a reference. The API core stores each one as a public text owned by the proposal. A client text reference is refused as a malformed request | R-PB-03. The domain holds no text class, so the op is where the check can hold |
| PD7 | Each phase has its own texts. The view takes the texts of the phase the grant's state is in, and `GrantChoice` keeps one text set | The M4 filter and its reference stay unchanged |
| PD8 | A finished choice may include accepted deliverables of its grant only. The public pages show each one's licence and evidence snapshot digest. The domain's deliverable fold now keeps the snapshot it already received | `public-transparency.md` names licences and evidence snapshots. No record changed |
| PD9 | A level above the programme maximum stays selectable and is stored as chosen. The screen marks it "above the programme maximum" and shows the effective level | Section 2.1 rule: the filter applies the lower of the two at read time |
| PD10 | Operation names and routes: `grant.publicity.view` (`GET /grants/{proposal}/publicity`), `grant.publicity.set` (`POST` on the same path) and `grant.publicity.withdraw` (`POST .../publicity/withdrawal`). Web only, no MCP tool. Both commands are binding under P-77 | As every M5 grant command (I-85) |
| PD11 | The authorisation matrix classes I-41 and I-42 refusals as guard rules | They judge the grant's state, its choice and its minor flag, never the actor |
| PD12 | The licence reference classes both choice commands as Evaluation, so no licence state blocks them (I-39 strict reading) | A withdrawal must never wait |

Open questions for Daniel:

- The Full level also names "milestone status" in `public-transparency.md`. The pages show the granted amount only. Which milestone facts may be public?
- The wording of the screen's two notes (`public-transparency.md` NOTE 1 and NOTE 3) carries `TODO(legal)`.
- `interface_no_command_kind_reaches_not_implemented` in `fstp-domain-testkit` fails on `main` at 0ede3ef7: the walk accepts no `RequestCopy`. This lane adds the two choice kinds to that walk, and they pass.

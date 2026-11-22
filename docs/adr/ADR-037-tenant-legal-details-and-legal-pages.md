# ADR-037: Tenant legal details and the legal pages behind the footer

Status: Proposed. Drafted 2026-11-22 by lane L36 (`prod/legal-pages`) before its code, as CLAUDE.md asks. Rows marked "Interim, pending Daniel" wait for his answer.

The number: ADR-035 is on `main`. Lane L35 (`prod/legal-wording`) works in parallel and will probably take ADR-036, so this lane takes ADR-037.

## Context

- Daniel answered two questions of `legal/README.md` on 2026-11-22.
  - Q4: the tenant values the legal texts need are a tenant setting. A non-technical operator fills them in the web app, on the admin settings page next to Branding.
  - Q6: each footer element becomes a link to a real page. The page renders the matching `legal/` draft with the tenant values filled in. Each page carries a clear banner "Draft, not yet approved" until Daniel approves that text.
- `legal/` holds the drafts of lane L14. They name tenant values as `{{controller.*}}` and `{{tenant.*}}` placeholders. They mark every open legal point as `TODO(legal)` and every rule the code does not carry out as `[NOT BUILT: ...]`.
- ADR-034 stores the funding card defaults as a tenant ledger record (`FundingDefaultsSet`), set through `tenant.set_funding_defaults` on the branding page. This ADR follows the same shape.
- Footers today show plain text spans with no page behind them (`legal/15-footer-texts.md`). They sit in `crates/fstp-public/src/html.rs` and in five places under `web/src` (`shell/brand.ts`, `creator/frame.ts`, `applicant/ui.ts`, `auth/layout.ts`, `auth/appshell.ts`).
- Binding rules: I-68 (tenant data is data only, never markup), I-69 (mandatory footer elements stay), I-70 (AA contrast in both themes), R-PB-04 (public pages work without script), R-NF-03 and R-NF-04 (accessibility), CLAUDE.md (every in-house parser gets a fuzz target from its first commit; no new dependency).
- Lane L35 builds the wording store, the approved funding acknowledgement, the emblem rules and the per-outcome emails. This ADR builds none of them.

## Decision

### 1. The legal details (Q4)

| Topic | Decision |
| --- | --- |
| Type | `fstp_brand::legal::LegalDetails`: one optional plain-text value per field of the table below. A value is 1 to 300 bytes, with no control character, no angle bracket and no outer white space (I-68). An empty field is unset |
| Record | `TenantRecord::LegalDetailsSet { details, by }` in the tenant ledger. The tenant state keeps the latest set in `TenantSettings::legal_details`. Each save replaces the whole set |
| Operation | `tenant.set_legal_details`, `PUT /admin/settings/legal-details`, body `{field: string, ...}` with every field key present (an empty string clears it). Role: tenant admin. High-risk by the strict reading of tenant settings, so it asks for a step-up and runs on the web only, like `tenant.set_funding_defaults`. No MCP tool |
| Why high-risk | A changed privacy contact would send data subject requests elsewhere. The step-up is the same one the admin already gives for the funding card |
| Read | `GET /legal/details`: a JSON object of the set values, sent with `no-store` and no session needed. Every value is shown on the public legal pages anyway. The branding page reads it to fill the form |
| Where | A "Legal details" section on the admin branding page (`/app/admin/branding`), after "Funding card". Plain labels, one short hint per field, one save button |
| Demo | The demo cell seeds CrabNebula Ltd's values, supplied by Daniel on 2026-11-22 (section 5). Shared code holds no value |

| Field key | Form label | Placeholders it fills |
| --- | --- | --- |
| `legal_name` | Organisation's legal name | `controller.legal_name`, `tenant.legal_name` |
| `address` | Postal address | `controller.address`, `tenant.address` |
| `registered_address` | Registered address | `tenant.registered_address` |
| `privacy_contact` | Privacy contact | `controller.privacy_contact`, `tenant.privacy_contact` |
| `dpo_name` | Data Protection Officer (DPO) | `controller.dpo_name`, `tenant.dpo_name` |
| `dpo_contact` | DPO contact | `controller.dpo_contact`, `tenant.dpo_contact` |
| `supervisory_authority` | Data protection supervisory authority | `controller.supervisory_authority`, `tenant.supervisory_authority` |
| `accessibility_contact` | Accessibility contact | `tenant.accessibility_contact` |
| `company_number` | Company registration number | `tenant.company_number` |
| `vat_number` | VAT number | `tenant.vat_number` |
| `transparency_register` | EU Transparency Register number | `tenant.transparency_register` |
| `governing_law` | Governing law | `tenant.governing_law` |

Interim, pending Daniel: the controller of a tenant's programmes is the tenant itself (Q1), so the `controller.*` and `tenant.*` names read the same values. A tenant that needs a different controller per programme needs a programme setting later.

### 2. The legal pages (Q6)

| Text | Path | Draft |
| --- | --- | --- |
| Privacy notice | `/legal/privacy` | `legal/01-privacy-notice.md` |
| Accessibility statement | `/legal/accessibility` | `legal/07-accessibility-statement.md` |
| Imprint | `/legal/imprint` | `legal/06-imprint.md` |
| Terms of use | `/legal/terms` | `legal/04-terms-of-use.md` |
| Data Act information | `/legal/data-act` | `legal/16-data-act-information.md` |

| Topic | Decision |
| --- | --- |
| Serving | The web adapter serves a new `/legal` surface with the public CSP of `/p` (`script-src 'none'`). The cell front sends every `/legal/` path to the web adapter, as it does for `/brand/`. No cookie is read, so the pages work signed out |
| Before activation | Served. Admins sign in and read the privacy notice during onboarding. Interim, pending Daniel |
| Source | Each draft is embedded at build time with `include_str!`. The page shows the part after the draft's first `---` line. The part above it is drafting notes for Daniel, which each draft says is not part of the text |
| Renderer | `fstp_public::legal`: an in-house parser of the Markdown subset the drafts use (headings, paragraphs, flat lists, tables, rules, `**strong**`, `` `code` ``, `[text](target)` as text). Fuzz target `legal_markdown` in `crates/fstp-public/fuzz` from the first commit. Its output goes through the escaping writer of `fstp-html`, so every draft byte and tenant value is text, never markup (I-68) |
| Placeholders | `{{name}}` becomes the tenant value as text. An unset or unknown name becomes the visible marker "[not set: name]". Raw template syntax never reaches the page |
| Pending points | Each `TODO(legal)` becomes a visible marker "Pending legal review", followed by the line's own text. Each `[NOT BUILT: ...]` becomes a visible marker "Not built yet", followed by its text. Nothing is hidden |
| Banner | Every page opens with a `role="note"` banner "Draft, not yet approved", until the text is approved (section 3). The banner also counts the marked points |
| Themes | Banner and markers use the colour tokens of `web/src/site/tokens.css`, so they follow `prefers-color-scheme` in light and dark. Each pair meets AA (I-70). No script runs |
| Page | `lang="en"`, one `main` with one `h1` (the text's name), the banner, the text, and a short footer with links to the other four pages |

Interim, pending Daniel: policy parameters (`{{P-41}}`, `{{P-46}}`, `{{P-72.idle}}`, `{{P-72.absolute}}`) and page values (`{{platform.url}}`, `{{programme.name}}`, `{{statement.date}}`, `{{statement.review_date}}`, `{{tenant.accessibility_response_time}}`) show as "[not set: ...]". They are not tenant legal details. A later lane can fill them from the settings and the programme.

### 3. Approval flag

| Topic | Decision |
| --- | --- |
| Where | `legal/page-approvals.json`, one member per text key (`privacy`, `accessibility`, `imprint`, `terms`, `data_act`). Its value is `null` (not approved) or `{"approved_on": "YYYY-MM-DD", "sha256": "<hex digest of the draft file>"}` |
| Effect | The banner goes when the recorded digest equals the SHA-256 of the embedded draft file, and the shown part holds no `TODO(legal)` and no `[NOT BUILT` marker. Otherwise the banner stays |
| Why a digest | Approval binds the exact text Daniel read. Any later edit brings the banner back until he approves again |
| How Daniel approves | Run `shasum -a 256 legal/06-imprint.md`, paste the digest and the date into the file, and release. No code changes. A test fails while a recorded digest does not match its draft, and its message prints the current digest |
| Digest | `fstp_crypto::sha256` (ADR-001, aws-lc-rs), computed once per process in `fstp-api-core` |

Interim, pending Daniel: approval ships with a release, since the drafts are embedded. A runtime switch would let a cell show text that no release reviewed.

### 4. Footer links

- Every footer element for the privacy notice, the accessibility statement and the Data Act information becomes a link to its page. The footers also gain "Imprint" and "Terms of use" links. The `data-mandatory` keys stay, and two are added: `imprint` and `terms_of_use` (I-69).
- The link names are the plain names from `legal/15-footer-texts.md`: "Privacy notice", "Accessibility statement", "Imprint", "Terms of use", "Data Act information". The draft status shows on each page, not in the footer.
- The platform attribution, the AI disclosure and the funding card are unchanged. Lane L35 owns the funding acknowledgement.
- Lead note of 2026-11-22: lane L35 shows the approved acknowledgement inside the funding card. So the footer no longer adds the placeholder of the profile's `acknowledgement` visibility element, on public and app pages (`fstp_public::html::card_carries`, `CARD_ELEMENT` in `web/src/shell/brand.ts`). The `emblem` element stays as it was.

### 5. The demo values

Supplied by Daniel on 2026-11-22, for the demo cell only:

| Field | Value |
| --- | --- |
| Legal name | CrabNebula Ltd |
| Postal address | 27 Triq it-Tramuntana, Birgu BRG1160, Malta |
| Registered address | 27 Triq it-Tramuntana, Birgu BRG1160, Malta |
| Privacy contact | privacy@crabnebula.dev |
| DPO | Daniel Thompson-Yvetot |
| DPO contact | privacy@crabnebula.dev |
| Supervisory authority | Information and Data Protection Commissioner (IDPC), Malta |
| Accessibility contact | not set (none supplied) |
| Company registration number | C 103590 |
| VAT number | MT29710913 |
| EU Transparency Register number | 3419964101239-38 |
| Governing law | Maltese law |

### 6. Draft edits

`legal/06-imprint.md` gains a section "This programme portal" with the tenant placeholders of section 1, above the platform operator's section. The section names fields only and states no legal fact. No other draft is changed.

## Consequences

- One new tenant record, one new operation, one new web surface, one new parser with its fuzz target. No new crate, no new table, no new dependency and no MCP tool.
- The PostgreSQL authorisation sample may pick a different set of operations. Any gap it shows is fixed in production code or the test world, never by leaving a cell out.
- Tests carry ADR-037, I-68, I-69, I-70, R-PB-04 and R-NF-04 in their names.

## Open questions for Daniel

1. Interim, pending Daniel: the `controller.*` and `tenant.*` placeholders read the same tenant values (section 1).
2. Interim, pending Daniel: the legal pages are served before the organisation is activated (section 2).
3. Interim, pending Daniel: policy parameters and page values show "[not set: ...]" (section 2).
4. Interim, pending Daniel: approval ships with a release, bound to the draft's digest (section 3).
5. Interim, pending Daniel: `tenant.set_legal_details` asks for a step-up like the other tenant settings (section 1).
6. Interim, pending Daniel: the imprint shows the tenant's governing law beside its company facts (section 6). TODO(legal): whether an imprint should state it.
7. Interim, pending Daniel: the accessibility response time (`tenant.accessibility_response_time`) is not a field yet.
8. Interim, pending Daniel: a tenant with its own privacy notice (`01-privacy-notice.md` section 3) has no setting to link it yet. The platform notice shows.

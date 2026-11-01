# 09. Tenant admin screens

Status: draft, 2026-11-01. Sources: `SPEC/02-domain/roles-and-sod.md`, `programme-creator.md` (onboarding steps) and `white-labelling.md`. The spec wins over this document.

## Purpose and role

The tenant admin runs one tenant, here the synthetic organisation Horizon Bridges.

- The role is tenant-wide. It is not bound to a programme, and the shell attests it.
- A tenant admin grants Drafting, Judging and Operations roles per programme (O-47).
- Each programme role binds a tenant account to one programme, with a start date and an optional end date.
- At least two tenant admins exist at all times.
- A tenant admin who grants a role to their own account needs a second admin's approval (SoD-07).
- Drafting and Judging bindings require verified identity at binding time (SoD-09).

Tenant admin is an operations role, not an applicant-facing surface. The admin screens therefore use plain grant language only. They carry no Voyage labels, not even as a secondary line.

## Shell

The five screens use the same shell as every other prototype: skip link, `header` with the main navigation, one `main` landmark and the shared footer.

- Brand: "Horizon Bridges" with the sr-only suffix "FSTP home".
- Role chip: "Signed in as Tenant admin". The account is `a.chen@horizon-bridges.example`.
- Navigation: Home, Organisation, Members and roles, Branding, Domains and email. All links are relative within `design/prototypes/`.
- Stylesheet: `../tokens.css`. From `design/prototypes/` this is the same file as `../../design/tokens.css`. The shared test requires the shorter form on every page.
- `tokens-showcase.html` already used the admin role. Its navigation now shows the new admin items, with Branding as the current page.

## The five screens

| Screen | File | What it captures |
| --- | --- | --- |
| Administration home | `home-admin.html` | Two summary cards (Organisation settings, Branding and infrastructure). Members and roles and Domains and email sections. A programme table for SuperSAFE and OpenTech Fund, with member counts and links to Programme set-up (`planning-studio.html`). The footer adds "Platform attribution: FSTP platform (TODO(legal))." |
| Organisation settings | `admin-org.html` | Read-only definition lists for legal entity, registered address, data protection contact and two signatories. A disabled Edit button beside each section heading. An Agreements table: SaaS terms and data processing agreement (signed, 14 Sep 2026) and the sub-processor list link. The SoD-07 note on legal entity changes. |
| Members and roles | `admin-members.html` | Account table with Name, Email, Tenant admin, Programmes and roles, and a per-row Grant role button. Two tenant admins (a.chen and m.diop) and one reviewer (p.novak). The signed-in admin's row is highlighted with the SoD-07 note. One pending invitation for r.gomez@example.org as Call drafter on OpenTech Fund. The SoD-09 identity note. |
| Branding | `admin-branding.html` | Brand identity with three static upload slots. A colour token table with one failing pair (`--color-muted-text`, "Fails WCAG 2.2 AA"). Self-hosted Inter for body and headings. The mandatory elements checklist. Two terminology overrides. A disabled Save button blocked by the contrast failure. |
| Domains and email | `admin-domains.html` | Custom domains table: two active and verified, one pending with a link to the DNS TXT instructions. A disabled Add domain button. The sending domain with SPF, DKIM and DMARC passing, the sender address and a disabled Re-check button. The ACME certificate note. |

Every disabled button has a `TODO(js)` comment and an `aria-describedby` reason. Agreement descriptions are `TODO(legal)` comments beside a neutral placeholder. No TODO marker renders as text inside `main`.

## Key rules

- **O-47.** The tenant admin grants Drafting, Judging and Operations roles per programme. The members table shows each binding with its programme, start date and optional end date.
- **SoD-07.** A self-grant needs a second tenant admin. Changes to legal entity details also need a second tenant admin. The onboarding step Administrators requires at least two tenant admins.
- **SoD-09.** Drafting and Judging bindings check identity status before confirmation. The pending Call drafter invitation is confirmed only after the invitee verifies their identity.
- **I-68.** Branding is data only. No tenant-supplied script, style or markup executes. Fonts are self-hosted. SVG is rasterised or passed through an allowlist sanitiser. Other images are re-encoded on upload.
- **I-69.** Branding cannot remove funder visibility, AI disclosure, privacy notice, accessibility statement or platform attribution. The checklist shows all five. The screen brief named four. The accessibility statement is added because I-69 lists it.
- **I-70.** Every text colour pair must meet WCAG 2.2 AA in light and dark themes. A package with failing pairs is rejected, and the failing pairs are listed. Save stays disabled while a failure exists.
- **I-71.** A custom domain serves traffic only after verified ownership. Certificates are issued through ACME after the ownership check.
- **I-72.** Terminology overrides apply to interface labels only. Contracts and notices keep their approved wording.

## Accessibility

- The failing colour values appear only as code text and `aria-hidden` swatches. Table text keeps the platform palette, so the screen itself still meets WCAG 2.2 AA.
- Pass and fail carry a glyph and a word, never colour alone.
- The highlighted self row also carries a "You" badge and a text note.

## Open question

**Q24.** Are the onboarding steps (Organisation through Channels, `programme-creator.md`) a separate onboarding wizard prototype, or are they folded into `admin-org.html` and `admin-branding.html`?

Today the screens cover Organisation, Agreements, Branding, Domains and email, and Administrators. Identity (P-45, P-18), Inference (P-21), Payments (P-20) and Channels have no screen yet. Recommendation: a separate step-based wizard for first-time onboarding, then the five admin screens for later changes. See `spec-questions.md` item 24.

## Spec IDs

O-47, SoD-07, SoD-09, I-68, I-69, I-70, I-71, I-72, P-18, P-20, P-21, P-45.

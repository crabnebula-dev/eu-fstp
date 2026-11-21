# Accessibility statement (template for a tenant portal)

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Responsible data officer: Daniel Thompson-Yvetot.

Used where: the page behind the footer element "Accessibility statement" (`public.footer.accessibility` in `crates/fstp-public/src/html.rs`, `footer.accessibility` in `web/src/auth/messages.en.ts` and `web/src/applicant/messages.en.ts`, `footer.accessibility_statement` in `web/src/creator/messages.en.ts`). `{{tenant.*}}` values come from the tenant.

What the code does:

- R-NF-03 sets WCAG 2.2 level AA as the target.
- Brand packages are refused when a text colour pair fails AA contrast in light or dark theme (I-70, `crates/fstp-brand`).
- Unit tests check landmarks, labels and navigation (`web/test/a11y.test.ts`, `web/test/navigation.test.ts`). The route map has a text alternative (R-JV-05).
- Public pages work without script (R-PB-04). The Guide is offered as HTML and PDF (R-GA-02).
- No full manual audit against WCAG 2.2 AA is recorded in the repository.

TODO(legal): which accessibility law applies to a tenant portal (a public sector body, a private funder, or neither), and so whether this statement is mandatory and which form it must take. Daniel verifies before approval.

TODO(legal): the conformance status to state. "Partially conformant" is the honest choice until an audit is done.

---

## Accessibility statement for {{programme.name}}

{{tenant.legal_name}} wants everyone to be able to use this programme portal. The portal runs on the FSTP platform of CrabNebula Ltd.

### Conformance status

This portal aims to meet the Web Content Accessibility Guidelines (WCAG) 2.2 at level AA. It is partially conformant: some parts may not yet meet the standard. TODO(legal): status after an audit.

### What we do

- Pages use headings, landmarks and labelled form fields.
- Every action can be reached with a keyboard.
- Text colours meet AA contrast in light and dark themes. A theme that fails is refused.
- Public pages and the Guide for Applicants work without JavaScript.
- The Guide for Applicants is also offered as a PDF.
- The route map of a proposal has a full text alternative.

### Known limits

- Signing in needs a passkey, which needs a supported browser or device. If you cannot use a passkey, contact us and we will help.
- Documents that applicants upload may not be accessible.
- TODO(legal): further limits found in the audit.

### Feedback and contact

If something on this portal is hard to use, tell us at {{tenant.accessibility_contact}}. We aim to reply within {{tenant.accessibility_response_time}}.

For problems with the platform itself, you can also write to CrabNebula Ltd at TODO(legal): accessibility contact email.

### Enforcement

TODO(legal): the enforcement body or complaint route, where the applicable law requires one.

### About this statement

This statement was prepared on {{statement.date}}. It was last reviewed on {{statement.review_date}}. The method was TODO(legal): self-assessment or third-party audit.

# SaaS terms (CrabNebula Ltd and a tenant organisation)

Status: draft outline for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Data Protection Officer (DPO): Daniel Thompson-Yvetot.

Replaces: `agreements.text.saas_terms` in `crates/fstp-signup/src/render.rs` ("TODO(legal): the text of the SaaS terms is pending."). The tenant accepts a version during onboarding. The control plane records the version only (`crates/fstp-signup/src/types.rs`). Request item P1.

Wiring note: the agreement form renders each text as one approved catalogue message. A full contract does not fit one message. Daniel chooses between a link to a versioned document and a longer rendered text. Either way, a new text needs a new version in `AgreementVersions`.

---

## 1. Parties

- CrabNebula Ltd, 27 Triq it-Tramuntana, Birgu BRG1160, Malta, company number TODO(legal): company registration number and register ("CrabNebula").
- The organisation named at sign-up, with the legal name, billing address and contracting signatory it gave ("the Customer").

## 2. The service

CrabNebula provides the FSTP platform as a hosted service. The Customer uses it to run funding programmes for third parties: open calls, evaluation, contracts, payments records, reporting and public pages.

- Each Customer gets its own database cell and its own identity vault.
- The platform records payments. It never holds or moves funds. The Customer's own bank executes every payment (I-16).
- The Customer chooses its AI provider and model, and its mail relay.

## 3. The Customer's responsibilities

- The Customer runs its programmes and takes every decision in them.
- The Customer is responsible for the content of its calls, Guides, contracts and notices, and for approving legal wording in them.
- The Customer keeps its tenant admins' accounts secure. Two tenant admins approve sensitive actions where the platform requires it.
- The Customer makes sure its mail relay and AI provider are lawful choices for its programmes.

## 4. Data protection

The data processing agreement (`dpa.md`) governs programme data. The sub-processor list (`sub-processors.md`) is part of it. The Customer is the controller of its programme data and CrabNebula is its processor (README.md, Q1, answered).

## 5. Availability and support

TODO(legal): the service level, maintenance windows, support channel and response times. The specification sets no figures.

## 6. Fees

TODO(legal): fees, invoicing and payment terms. No figure is in the repository.

## 7. Intellectual property and licences

- CrabNebula keeps all rights in the platform.
- The Customer keeps all rights in its data and content.
- TODO(legal): the platform licence notice (PolyForm, request 05) and how it applies to a SaaS customer.

## 8. Switching and exit

- The Customer can switch provider at any time, with no notice period and no switching charge.
- See `16-data-act-information.md` for the transition and retrieval periods.
- [NOT BUILT: the export tool is deferred (B-07).]
- TODO(legal): L-04, the switching clause in full.

## 9. Security

CrabNebula keeps the measures described in the data processing agreement, annex 2.

## 10. Liability

TODO(legal): limits and exclusions of liability, and any cap.

## 11. Term and termination

TODO(legal): the term, termination for convenience and for cause, and the effect on running programmes and signed grant contracts.

## 12. Changes to these terms

CrabNebula gives the Customer notice of a change before it applies. A changed text is a new version, which the Customer accepts on the platform. TODO(legal): the notice period, and the Customer's right to end the contract if it does not accept.

## 13. Governing law and courts

TODO(legal): the governing law and the competent courts.

Version: TODO(legal): version and date.

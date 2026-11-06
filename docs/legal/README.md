# Legal requests

The codebase marks every open legal point with `TODO(legal)`. This folder groups them into five requests for a legally trained reviewer. Each request is self-contained: paste it as the prompt, attach the files it lists, and save the answer.

| Request | Topic | Open checks it covers |
| --- | --- | --- |
| [01](requests/01-grant-agreement.md) | The SuperSAFE grant agreement and the Guide for Applicants | L-06, L-08 to L-13, amount rounding, Guide sections, signature levels |
| [02](requests/02-data-protection.md) | Data protection | L-01, L-02, L-07, country collection, calibration consent, retention and anonymisation, rate limiting, reviewers' relatives, privacy notices |
| [03](requests/03-platform-contracts-and-regulation.md) | Platform contracts and EU digital regulation | SaaS terms, DPA, sub-processors, L-03, L-04, L-05, L-15, L-16, L-17, CRA vulnerability handling |
| [04](requests/04-product-wording.md) | Wording shown in the product | AI disclosure, invitee and reviewer terms, date-of-birth field, complaints and L-14, negotiation notices, accessibility statement, footer, contract outline |
| [05](requests/05-licensing.md) | Licensing | PolyForm notice, vendored LibPDF and PDFBox notices, OFL font, EUPL-1.2 tooling |

## Bringing the answers back

Save each answer as `docs/legal/answers/<request number>.md`, for example `answers/02.md`, and tell the implementing agent. Every item keeps its ID, such as `D2`, so each answer can be traced to the markers it closes.

Answers from a model are advice for Daniel, not approved text. Daniel decides what is adopted. The code keeps a `TODO(legal)` marker until Daniel approves the wording or the decision.

## Facts the requests rely on

- The hosting provider is OVHcloud, named by Daniel on 2026-10-28 (ADR-005). The contracting entity is not confirmed yet.
- The reference programme is the SuperSAFE Annexe FSTP, call HORIZON-CL4-2026-04-DATA-02.
- Daniel fills in the seat of CrabNebula Ltd where a request marks `[seat of CrabNebula Ltd]`.

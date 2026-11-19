# Compliance disclosures

Draft started 2026-11-19. Statements marked `TODO(legal)` need legal review before this file is published or relied on. Items marked `TODO(Daniel)` need facts only Daniel holds.

## Summary

- CrabNebula Ltd operates this service on a not-for-profit basis.
- The service is not sold, and no fee is charged for its use.
- It is not placed or made available on the market as a product or a commercial service.
- It is purpose built for the Financial Support to Third Parties (FSTP) needs of the EU-funded actions listed below, and is currently used only for them.
- CrabNebula Ltd funds the build itself. Its costs are not recovered from the grant actions.
- A commercial offer may follow in the future. None exists today, and this file will be revised before one starts.

## EU funding

| Action | Funding programme and call | Grant agreement number |
| --- | --- | --- |
| ELFA | TODO(Daniel): programme and call | TODO(Daniel) |
| SuperSAFE | Horizon Europe, call HORIZON-CL4-2026-04-DATA-02 | TODO(Daniel) |
| SuperAPPS | TODO(Daniel): programme and call | TODO(Daniel) |
| SuperFOSS | TODO(Daniel): programme and call | TODO(Daniel) |

TODO(legal): insert the EU funding acknowledgement and disclaimer wording that the signed grant agreements require (L-08).

## Scope of the service

- Operator: CrabNebula Ltd.
- Purpose: open calls, evaluation, contracts and milestone payments for the FSTP programmes of the actions above.
- Users: consortium partners of those actions, applicants, reviewers and members of the independent review committee.
- No other organisation runs a programme on the service.
- No self-hosted distribution, desktop client or other software package is supplied to anyone. Self-hosted packaging (B-06) and the desktop client (B-04) are deferred.
- The source code is licensed under PolyForm Noncommercial 1.0.0 (`LICENSE.md`). It is not offered for sale.

## Cyber Resilience Act (Regulation (EU) 2024/2847)

- The hosted service alone is not a product with digital elements (`SPEC/05-compliance/cra.md`).
- No product with digital elements is currently made available on the market by CrabNebula Ltd through this project.
- TODO(legal): confirm this reading and cite the CRA provisions it relies on, including the meaning of commercial activity.
- The project still follows the CRA design outcomes in `SPEC/05-compliance/cra.md`: vulnerability handling, an SBOM per release, secure defaults and security updates.
- Security contact for vulnerability reports: TODO(Daniel).

## Digital Services Act (Regulation (EU) 2022/2065)

- The service stores information that its users provide, such as proposals, reviews and messages.
- The specification treats the service as a hosting service with CrabNebula Ltd as provider (`SPEC/05-compliance/dsa.md`).
- The service is provided without remuneration from its users.
- TODO(legal): confirm whether not-for-profit operation for the listed grant actions only takes the service outside the DSA, or which duties still apply. Cite the provisions relied on.
- Until that is confirmed, the duties in `SPEC/05-compliance/dsa.md` stay in scope (G-12 to G-22, L-16, L-17).
- Single point of contact for authorities and for recipients of the service: TODO(Daniel).

## Changes that end these statements

Each of the following changes the position above. This file must be reviewed before any of them happens.

- Charging any fee for use of the service, including charging use to a grant action.
- Running a programme for an organisation outside the listed actions.
- Supplying a self-hosted distribution, desktop client or any other software package.
- Offering the service as a commercial SaaS.

## Relation to the specification

- `SPEC/05-compliance/cra.md` describes the self-hosted distribution as made available in the course of a commercial activity. That position applies to a possible future commercial offer. It does not describe current operation.
- `SPEC/05-compliance/other.md` (O-03) records that the build is self-funded and is never reported as a result of a grant action. This matches the summary above: the platform is purpose built for the actions' FSTP needs, and its costs are not recovered from them.

# Cyber Resilience Act (Regulation (EU) 2024/2847)

## Position

- The hosted SaaS alone is not a product with digital elements.
- The self-hosted distribution is a product with digital elements made available in the course of a commercial activity. CrabNebula is its manufacturer.
- PolyForm Noncommercial 1.0.0 is not a free and open-source licence, so the open-source steward regime does not apply.
- Core functionality is grant programme management. Proposed category: default, assessed under Module A. The identity vault is a component, not the core functionality.

## Design outcomes

- Vulnerability handling and reporting from the first release. Reporting obligations already apply since 11 September 2026.
- SBOM per release (R-NF-07).
- Secure defaults and security updates (R-NF-05, R-NF-06).
- Threat model and hardening outputs serve as evidence in the technical documentation, not as requirements in themselves.

## To confirm

- Category reading against the core functionality test, given the identity management component.
- The update and licence services are treated as within scope of the self-hosted product (`03-architecture/self-hosted-services.md`).

## Desktop client and own libraries

NOTE: The desktop client is deferred by Daniel on 2026-11-04 (B-04). The rules below on own libraries still apply.

- The desktop client is a second product with digital elements, alongside the self-hosted cell.
- moduletto is a component of both. Its own CRA status as stewarded open source is documented in its repository, and its release-gated confirmations sit in ADR-001. qrtc joins when realtime sessions return (backlog B-01).

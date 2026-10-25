# Hardening plan (Mythos-tier phase)

## Model tier

Record which Mythos-tier model is used before scoping. Claude Fable 5.1 carries additional cybersecurity safeguards that may limit offensive testing activities. Claude Mythos 5.1 does not share those safeguards.

## Entry criteria

- Milestones M1 to M6 closed.
- Threat model updated against the implemented system.
- All invariant, authorisation and privacy tests green.

## Activities

| ID | Activity | Threats |
| --- | --- | --- |
| H-01 | Authorisation bypass across roles, states and programmes | TH-03, TH-05, TH-17 |
| H-02 | Cross-cell and control plane isolation | TH-06, TH-18 |
| H-03 | Assessor red-team with corpus expansion for new injection classes | TH-01, TH-12 |
| H-04 | Pre-check oracle probing | TH-02 |
| H-05 | Every in-house parser and protocol implementation, including HTTP, JSON, MIME, SMTP, PostgreSQL wire protocol, PDF and Matrix events | TH-10, TH-11, TH-16, TH-26 |
| H-06 | Payment flow tampering | TH-09 |
| H-07 | Identity vault query surface and side channels | TH-04, TH-07 |
| H-08 | Reviewer de-anonymisation | TH-08 |
| H-09 | Audit log integrity | TH-14 |
| H-10 | Supply chain and build pipeline | TH-15 |
| H-11 | Self-hosted default configuration review | R-NF-05 |
| H-12 | Messaging adapters and group membership | TH-19, TH-22, TH-25 |
| H-13 | Timeline engine and dispatcher abuse, including notification floods | TH-21 |
| H-14 | Contract integrity, payment requests and bank detail phishing paths | TH-20, TH-23, TH-24 |
| H-15 | Qualified signature validation, trusted list handling and PDF signature attacks | TH-31 |
| H-16 | Update and licence services, including signing keys and rollback handling | TH-32, TH-33 |
| H-17 | White-label packages, custom domains, document import and the template library | TH-45 to TH-49 |
| H-18 | Review and confirmation of every Tier B crate version: moduletto and the RustCrypto formats crates | TH-50, I-74 |
| H-19 | Hybrid constructions: TLS group, key encapsulation combiner, envelope format, composite signatures | TH-50, TH-51, TH-67, TH-68 |
| H-20 | Desktop client | TH-54 |
| H-21 | Authentication, step-up, recovery and session handling | TH-55 to TH-57 |
| H-22 | Key custody, rotation, shredding and database isolation | TH-58, TH-59 |
| H-23 | MCP server and client: authorisation, scopes, injection, policy parity, public tools and outbound data | TH-60 to TH-66 |

## Rules

- Every finding gets a regression test before closure.
- New injection classes found in H-03 are added to the synthetic corpus.
- Findings are tracked under the CRA vulnerability handling process from the start.

## Exit criteria

- No open critical or high findings.
- Every Tier B crate version in the release has a recorded confirmation in ADR-001 (I-74).
- All regression tests merged and green.
- Hardening report available as evidence for the CRA technical documentation.

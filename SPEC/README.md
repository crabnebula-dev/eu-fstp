# FSTP Platform Specification

Specification for a multi-tenant platform that runs Financial Support to Third Parties (FSTP) programmes. The reference process is the SuperSAFE Annexe FSTP (call HORIZON-CL4-2026-04-DATA-02). Other programmes run the same process with their own policy parameters.

Status: design draft for handoff to Claude Code. Design work runs on Claude Opus 5.5. Platform hardening runs on a Mythos-tier model (see `08-hardening/`).

## Reading order

1. `../.claude/CLAUDE.md`: rules for the implementing agent
2. `00-scope.md`: purpose, boundaries, actors, glossary
3. `02-domain/invariants.md`: properties that must hold at all times
4. `01-requirements/`: outcome requirements with acceptance criteria
5. `02-domain/`: state machine, roles and separation of duties, policy parameters, contracts, payment requests
6. `03-architecture/`: cells, control plane, identity vault, payments, inference, notifications, messaging, EUDI Wallet, self-hosted services, funder reporting
7. `04-llm-assessment/`: submission assessment and applicant pre-check
8. `05-compliance/`: Data Act, GDPR, CRA, AI Act, messaging and other notes
9. `06-threat-model/`
10. `07-test-plan/`
11. `08-hardening/`
12. `09-milestones.md`
    12a. `12-journey-ui.md`: the journey UI layer, its vocabulary pack, route map and Passage Diary
13. `10-open-questions.md`
    13a. `11-backlog.md`: deferred features and reserved identifiers
14. `schemas/`: tenant export schema (separately open-licensed)
15. `profiles/`: funder profile templates, starting with the Horizon Europe Guide for Applicants
16. `../docs/adr/`: architecture decision records

## Conventions

Paths in this specification are relative to this `SPEC/` folder. Paths to files outside it start with `../`.

Requirements state outcomes, not implementations. Each requirement is short. Explanatory detail sits in NOTEs.

Documentation is never a requirement. It can only serve as evidence that a requirement is met.

Identifier prefixes:

| Prefix | Meaning |
| --- | --- |
| R- | Requirement |
| I- | Invariant |
| P- | Policy parameter |
| SoD- | Separation of duties rule |
| TH- | Threat |
| T- | Test |
| H- | Hardening activity |
| O- | Open question |
| ADR- | Architecture decision record |
| L- | Legal check tracked for Daniel |

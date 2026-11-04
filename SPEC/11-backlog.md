# Backlog

Features designed but deferred past v1. Identifiers here are reserved, so they keep their meaning when a feature returns to scope.

## B-01: Realtime sessions on qrtc

Deferred by Daniel on 2026-10-10. The design is kept in `03-architecture/realtime-sessions.md`.

Scope when resumed:

- Audio and video for mentoring, consortium presentations, stage 2 clarification, and group calls from Matrix rooms.
- qrtc as the WebRTC engine, with DTLS 1.3 and X25519MLKEM768 through moduletto.
- Calls in the desktop client, once the desktop client returns (B-04).

Reserved identifiers:

| ID | Content |
| --- | --- |
| I-76 | No realtime session connects an applicant with a reviewer while P-11 is anonymous |
| R-RT-01 to R-RT-03 | Session types, post-quantum indication, recording consent |
| TH-52, TH-53 | Video breaking reviewer anonymity; TURN relay abuse |
| O-38 | Media relay for group calls beyond a small mesh |
| O-39 | aws-lc-rs feature for TURN over TLS in qrtc |

When this returns to scope, qrtc rejoins Tier B in ADR-001 and falls under the release gate (I-74).

## B-02: Captain's notes

Deferred by Daniel on 2026-11-01 (`12-journey-ui.md` section 15). Private voyager notes attached to diary entries. Before it returns to scope it needs a retention rule and a check against I-27.

## B-03: WhatsApp notifications

Deferred by Daniel on 2026-11-04, for now. The design is kept in `03-architecture/messaging.md` (sections "WhatsApp" and "WhatsApp account ownership") and `05-compliance/messaging.md`.

Scope when resumed: individual notifications through the WhatsApp Business Platform, each tenant on its own account, after the per-tenant assessment. Groups stay on Matrix. The adapter's payload parser gets a fuzz target in its first commit.

Reserved identifiers:

| ID | Content |
| --- | --- |
| R-WA-01, R-WA-02 | WhatsApp enablement after assessment; explicit opt-in per programme |
| O-21, O-29 | WhatsApp in v1 after assessment; tenant-owned Business account |

## B-04: Desktop client

Deferred by Daniel on 2026-11-04, for now. The design is kept in `03-architecture/desktop-client.md` and `05-compliance/cra.md`.

Scope when resumed: a white-labelled desktop client built with Tauri, with its own SBOM and vulnerability handling, signed updates (I-91) and no offline proposal content.

Reserved identifiers:

| ID | Content |
| --- | --- |
| R-DC-01 | White-labelled desktop client |
| TH-54, H-20 | Lost devices caching confidential content; its hardening item |

## B-05: Matrix group messaging

Deferred by Daniel on 2026-11-04, for now, to reach M4 exit and the journey UI sooner. The design is kept in `03-architecture/messaging.md` and `05-compliance/messaging.md`.

Scope when resumed: the Matrix adapter, the four group types and membership that follows role bindings. Email carries every notice meanwhile.

Reserved identifiers:

| ID | Content |
| --- | --- |
| R-MG-01 to R-MG-03 | Matrix adapter, group types and membership, private announcements |
| I-28, I-29 | Group composition and membership |

## B-06: Self-hosted packaging and installation

Deferred by Daniel on 2026-11-04, for now, to reach M4 exit and the journey UI sooner. The design is kept in `03-architecture/` (self-hosted sections), ADR-004 file custody and ADR-011 local mode.

Scope when resumed: packaging, the installer and the full suite on a self-hosted cell. The self-hosted code already built in M3 stays in the tree.

Reserved identifiers:

| ID | Content |
| --- | --- |
| I-91 (self-hosted part) | Signed updates on self-hosted cells |
| M9 exit | Self-hosted cell passes the full suite |

## B-07: Tenant export, import and switching

Deferred by Daniel on 2026-11-04, for now, to reach M4 exit and the journey UI sooner. The design is kept in `03-architecture/` export sections and `SPEC/schemas/`.

Scope when resumed: the EUPL-1.2 export and import executable, the documented schema, switching and post-switch erasure.

TODO(legal): the spec ties switching to the EU Data Act (I-69 lists the Data Act tenant information). Daniel to confirm whether a SaaS pilot may run before export and switching exist.

Reserved identifiers:

| ID | Content |
| --- | --- |
| R-TD-01 to R-TD-04 | Export, import, tooling licence |
| R-SW-01, R-SW-02 | Switching and erasure after the retrieval period |
| I-22 | Export and import give an equivalent tenant |

## B-08: Profile bundles

Deferred by Daniel on 2026-11-04, for now, to reach M4 exit and the journey UI sooner. The design is kept in `03-architecture/overview.md` (Profile bundle).

Scope when resumed: user-held profile bundles across tenants. The profile fields stay bundle-ready (`12-journey-ui.md`, profile page).

Reserved identifiers:

| ID | Content |
| --- | --- |
| R-PS-01 to R-PS-03 | Bundle export, field choice, self-declared import |
| TH-11 | Forged bundle |

## B-09: Custom domains and full white-label packages

Deferred by Daniel on 2026-11-04, for now, to reach M4 exit and the journey UI sooner. The design is kept in `03-architecture/white-labelling.md`.

Scope when resumed: white-label packages for every interface, document and email, and custom domains with certificates. Branding tokens, terminology overrides (R-WL-05), the contrast rule (I-70) and the platform attribution (R-WL-04) stay in scope.

Reserved identifiers:

| ID | Content |
| --- | --- |
| R-WL-01, R-WL-02 | White-label package; custom domains |
| I-71 | Custom domains serve only their own cell |

## B-10: External MCP integrations

Deferred by Daniel on 2026-11-04, for now, to reach M4 exit and the journey UI sooner. The design is kept in `03-architecture/mcp-client.md`.

Scope when resumed: connections from the platform to external MCP servers. The platform's own MCP server stays in M4.

Reserved identifiers:

| ID | Content |
| --- | --- |
| R-MC-06 | Tenants connect external MCP servers |
| I-88, I-89 | Read-only external calls; declared fields only |

## B-11: Bank payment execution

Deferred by Daniel on 2026-11-04, for now, to reach M4 exit and the journey UI sooner. The design is kept in `02-domain/payment-requests.md` and the payment adapter design.

Scope when resumed: execution payment mode with bank interfaces. Meanwhile every tenant runs record-only (P-20): the funder pays outside the platform, which records requests, approvals and releases.

Reserved identifiers:

| ID | Content |
| --- | --- |
| P-20 execution mode | Payment execution through a bank interface |

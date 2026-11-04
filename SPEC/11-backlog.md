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

# Backlog

Features designed but deferred past v1. Identifiers here are reserved, so they keep their meaning when a feature returns to scope.

## B-01: Realtime sessions on qrtc

Deferred by Daniel on 2026-10-10. The design is kept in `03-architecture/realtime-sessions.md`.

Scope when resumed:

- Audio and video for mentoring, consortium presentations, stage 2 clarification, and group calls from Matrix rooms.
- qrtc as the WebRTC engine, with DTLS 1.3 and X25519MLKEM768 through moduletto.
- Calls in the desktop client.

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

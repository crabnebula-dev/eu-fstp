# Realtime sessions (backlog B-01)

Status: deferred past v1 (`11-backlog.md`). Nothing in this file is implemented in v1.

Realtime audio and video sessions run on qrtc, CrabNebula's WebRTC engine, with post-quantum hybrid key agreement.

## Session types

| Session | Participants | Condition |
| --- | --- | --- |
| Mentoring | Mentor and grantee team | Support programme assignment exists |
| Consortium presentation | Grantee team and consortium members | Slot booked through the timeline engine |
| Stage 2 clarification | Assigned reviewers and applicant team | Only when P-11 is named |
| Project group call | Members of a project group | Grant is GRANTED or later |
| Committee call | Committee group members | Coordination only, no proposal content |

## Rules

- **I-76** No realtime session connects an applicant with a reviewer while P-11 is anonymous.
- Sessions follow the same membership rules as messaging groups (I-28, I-29).
- Sessions are never authoritative. Decisions and acceptances happen only in the platform.
- Sessions are not recorded by default. Recording needs every participant's consent at the start, and recordings follow P-22 retention.
- Session membership is checked when a participant joins, not only when the session is created.

## Transport

- Native clients and server-side components use qrtc, with DTLS 1.3 and X25519MLKEM768.
- Browser clients use their built-in WebRTC. Where the browser negotiates the hybrid group, the session is post-quantum. Otherwise it falls back to classical DTLS, and the interface shows which applies.
- STUN and TURN are tenant-configurable. CrabNebula-operated servers are offered to SaaS tenants. Self-hosted cells configure their own.

## Group calls in Matrix

Committee and project rooms can start calls from Matrix. Small groups connect as a mesh. Larger groups need a media relay, open under O-38.

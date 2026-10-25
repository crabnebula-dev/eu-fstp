# Group messaging channels

## Channels

| Channel | Status | Default use |
| --- | --- | --- |
| Matrix | In scope | All group types and individual notifications |
| WhatsApp | In scope for v1 | Individual notifications. Groups stay on Matrix |
| Signal | Dropped | Not offered |

NOTE: Signal was dropped because it offers no official business interface and its reference library is AGPL-3.0, which conflicts with PolyForm Noncommercial distribution.

## Group types (P-32)

SuperSAFE enables all four.

| Group type | Members | Content |
| --- | --- | --- |
| Programme announcements | Anyone opted in | One-way notices. Delivered as individual messages, never a shared group |
| Committee group | Judging roles of one programme, excluding IRC members | Coordination only, no proposal content |
| Grantee cohort | Opted-in grantees in GRANTED or later | Community and peer exchange |
| Project group | Grantee team and programme contact for one grant; assigned reviewers only when P-11 is named | Delivery coordination |

NOTE 1: IRC members are excluded from the committee group to preserve their independence (SoD-02).

NOTE 2: The committee group carries coordination only. Proposal discussion happens in the platform, where P-10 applies.

## Rules

- Announcements fan out as individual messages, so no member list is exposed.
- No shared group contains an applicant before NEGOTIATION (I-28).
- A group mixes Receiving and Judging roles only when P-11 is named and the proposal is GRANTED or later (I-28).
- Membership follows role bindings and opt-ins. Ended bindings remove membership within P-35 (I-29). Failed removals retry and alert the tenant admin.
- In encrypted Matrix rooms, the platform rotates its outbound group session on every removal, so removed members cannot read later messages.
- Group messages are never authoritative. Decisions, acceptances and contract notices happen only in the platform and by email.
- By default the platform sends and does not store inbound group messages (P-37).

## Matrix

The client-server specification is open and implemented in-house over HTTP and JSON. The platform acts as a bot account on a homeserver chosen or run by the tenant. Group rooms are encrypted using ADR-001 crates for Olm and Megolm.

## WhatsApp

The sanctioned route is the WhatsApp Business Platform operated by Meta. Business-initiated messages outside the customer service window need pre-approved templates, and recipients must opt in. Meta's processing terms and third-country transfer need assessment (O-21).

NOTE: Phone numbers can be visible to other members of WhatsApp groups. Groups therefore default to Matrix even after O-21 resolves.

## WhatsApp account ownership (O-29)

Each tenant uses its own WhatsApp Business account and contracts with Meta directly. The tenant handles template approval and its own assessment. The cell stores the tenant's access credentials as cell secrets. They never reach the control plane. Meta is therefore not a sub-processor of CrabNebula. Self-hosted cells work the same way.

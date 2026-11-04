# Messaging and email

## Position per channel

- **Email:** durable channel for contractual notices. The tenant is controller; CrabNebula processes as part of the SaaS.
- **Matrix:** open specification. A tenant-run homeserver keeps message data under tenant control.
- **Signal:** dropped. No official business interface, and the reference library licence conflicts with PolyForm Noncommercial distribution.
- **WhatsApp:** deferred by Daniel on 2026-11-04 (B-03); the text below applies when it returns. Enabled in v1 through the Business Platform for individual notifications. Before a tenant enables it, assess Meta's role under its processing terms, the third-country transfer basis, opt-in capture and template approval. Each tenant uses its own WhatsApp Business account (O-29).

## Design outcomes

- Opt-in per user for every channel except email.
- Minimal content, links to the authenticated platform (I-27).
- No authoritative decisions or contract notices through group channels.
- Messaging handles stored in the vault and released only to adapters.

## To confirm

- Per-tenant WhatsApp assessment before enabling (O-21).
- Contractual notices are sealed PDFs in the platform plus email (O-20). Check each contract template refers to that form.

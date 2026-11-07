# ADR-018: Mail submission egress

Status: Proposed. Drafted 2026-11-07 by lane L6-EGR of `docs/handoff/m6-design.md` (section 5.4, Q1 and Q2). It amends ADR-009 "Outbound destinations" once Daniel accepts it. Until then, the code is built as the interim reading below, and no production cell names a relay.

## Context

- **I-16** The platform never holds or controls funds. No egress reaches a payment service.
- **I-26** At most one end of DATA exists per message (M6 design section 5.1).
- **I-38** Calls from a self-hosted cell to CrabNebula-hosted services carry no tenant data.
- **R-NF-09** All network traffic between components is encrypted and mutually authenticated.
- **R-NT-03** Each event reaches each recipient on each channel at most once.
- ADR-009 closes `Destination` of `fstp-cell`. "A new variant needs an amendment of this ADR. Email in M6 ... add theirs that way."
- Q1 (trust roots) was answered by Daniel on 2026-11-06: allowlist a public root store. The ADR-001 amendment of 2026-11-06 adds webpki-roots, used through `fstp_tls::ClientConfig::public_roots`. A per-tenant pinned CA stays optional.
- Q2 (new destination) recommends option A: `MailSubmission { host }`, port 465 only, the host from tenant configuration, refused for CrabNebula hosts. Option B, a CrabNebula-run relay in the control plane, would put message content in the control plane.

## Decision

| Topic | Decision | Basis |
| --- | --- | --- |
| Destination | `Destination::MailSubmission { host: MailHost }` | Q2 A |
| Port | 465 only, implicit TLS (RFC 8314). No STARTTLS, so no downgrade path | M6 design 5.2 |
| Host | The tenant's relay host from its mail settings. A DNS host name, never an address literal | Q2 A |
| CrabNebula | A CrabNebula host is never a relay, in either mode | I-38 |
| Addresses | Every resolved address must be public unicast. One private, loopback, link-local or reserved address refuses the relay | Interim, pending Daniel |
| Trust | The public root store plus the tenant's pinned CA when it names one. The host name is always checked. Verification is never disabled | Q1, ADR-001 amendment of 2026-11-06 |
| Credential | SMTP AUTH PLAIN with a credential held as a cell secret. The tenant setting names the secret and never holds it | M6 design 5.2 |
| R-NF-09 | Not claimed. The relay authenticates the cell by its credential over server-authenticated TLS, as the other external links of ADR-009 do | ADR-009 (Q34 interim) |
| Setting | `tenant.set_mail_relay`, a tenant admin's high-risk operation: fresh step-up, web only | R-LG-03, I-78, I-85, strict reading of settings |
| DKIM | A seam. The per-tenant key in cell custody (ADR-004) lands with M6 design 5.3 behind its flag | M6 design 5.3 |

```rust
// fstp-cell, added to ADR-009's enum
pub enum Destination {
    // ... the members of ADR-009 ...
    MailSubmission { host: MailHost },   // the tenant's relay, port 465 only
}
```

## Connector

- `MailHost::parse` takes lowercase LDH labels of 1 to 63 bytes, at most 253 bytes in all. It refuses an all-digit last label, so no IPv4 literal passes. It refuses a port, a path and a CrabNebula host.
- `check_host` refuses a CrabNebula host and any host other than the configured relay. `check_port` refuses every port but 465. `check_mode` admits the destination in SaaS and self-hosted cells alike.
- `mail_tls` builds the TLS client: `ClientConfig::public_roots()`, or `public_roots_builder().also_trust_pem(ca)` with a pinned CA. An invalid pinned CA is a configuration fault, never a fallback.
- `TcpMailTransport` opens port 465 only, resolves the host, refuses non-public addresses, and connects within 30 seconds.
- `MailEgress` is the only way the cell opens the relay. It checks the destination, opens the transport, and runs `fstp_smtp::SmtpClient::stage` over the stream. The SMTP client verifies the server against `mail_tls` with the relay host as SNI and name. The commit point of I-26 stays in `fstp-smtp`.

## Tenant mail settings

- `TenantCommand::SetMailRelay { relay: Option<MailRelay> }` records `MailRelaySet { relay, by }`. `None` clears the relay, which stops sending.
- `MailRelay` holds `host` (a fully qualified host name), `credential` (the name of the cell secret) and `ca` (a text reference to the pinned CA PEM, or none).
- The tenant core refuses a host that is not a fully qualified host name, a CrabNebula host, or an empty secret name (`InvalidMailRelay`, named I-38 by the API). The fold refuses such a record.
- `PUT /admin/settings/mail-relay` takes `{host, credential, ca_pem}`. An empty `ca_pem` pins no CA. The PEM goes to the cell's text store as a public text of the tenant once the command is admitted, so a refused call stores nothing.
- No port is stored, so no port can be chosen.

## Tests

- `adr018_mail_submission_refuses_every_port_but_465`, `i38_mail_submission_refuses_crabnebula_hosts`, `adr018_mail_host_is_a_host_name`, `adr018_mail_tls_is_public_roots_plus_optional_pin` and `adr018_tcp_mail_transport_refuses_other_ports_and_private_addresses` in `fstp-cell`.
- `adr018_send_through_mail_egress_reaches_the_test_sink`, `r_nf_09_mail_egress_refuses_an_unknown_ca`, `i38_mail_egress_refuses_crabnebula_relays_and_bad_pins`, `i78_set_mail_relay_needs_a_step_up` and `i38_set_mail_relay_refuses_a_crabnebula_host_before_step_up` in `fstp-api-testkit`.
- `r_lg_03_mail_relay_set_is_high_risk_with_step_up`, `i38_mail_relay_refuses_crabnebula_and_non_host_names` and `adr007_mail_relay_codec_round_trip` in `fstp-tenant`. `r_lg_03_set_mail_relay_needs_step_up` in `fstp-access`.
- `i16_cell_egress_has_no_payment_destination` enumerates the new member.

## Open points

- Daniel's acceptance of this ADR. On acceptance, ADR-009 gains an amendment section that points here.
- Cell secrets: no cell secret store exists yet. The dispatcher resolves the named credential through a seam until one does.
- DKIM key custody stays a seam (M6 design 5.3).
- The address rule refuses a relay that the tenant runs on a private network next to a self-hosted cell. A self-hosted exception waits for B-06.
- `TODO(legal)`: the tenant's relay operator as a processor of message content, and its place in the DPIA (`gdpr.md`).

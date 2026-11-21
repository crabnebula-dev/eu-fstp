# Sub-processor list

Status: draft for Daniel's review, 2026-11-21. Not approved. Not wired into the product.

Legal party: CrabNebula Ltd. Responsible data officer: Daniel Thompson-Yvetot.

Replaces: `agreements.text.sub_processors` in `crates/fstp-signup/src/render.rs` ("TODO(legal): the sub-processor list is pending."). Request items P2 and P3 (L-15).

---

## Sub-processors of CrabNebula Ltd for the FSTP platform

| Sub-processor | Service | Data | Location | Contract |
| --- | --- | --- | --- | --- |
| OVHcloud, TODO(legal): contracting entity and address | Compute hosting and managed infrastructure for the cells, the identity vaults and the control plane | All programme data, encrypted at rest | European Union. TODO(legal): data centre locations | TODO(legal): L-15, the sub-processor terms |
| OVHcloud Object Storage, same entity | Encrypted backups, with object lock | Encrypted backups of the databases and keystores | European Union. TODO(legal): region | TODO(legal): L-15 |
| TODO(legal): second backup provider (Scaleway, Hetzner, IONOS, or a second OVHcloud region, per ADR-012) | Second copy of encrypted backups | Encrypted backups | European Union | Not chosen yet (Q25) |

## Providers the Customer chooses

These providers are chosen and contracted by the Customer, not by CrabNebula Ltd. They appear here for transparency.

| Provider | Service | Data | Note |
| --- | --- | --- | --- |
| The Customer's mail relay | Sends the emails of the Customer's programmes | Recipient addresses, and emails that hold ids, times and links only | ADR-018. A CrabNebula host is never a relay |
| The Customer's AI provider | Runs the AI assessment and the pre-check | Proposal text with personal details replaced by placeholders | ADR-019. The default protocol is Anthropic's Messages API. An EU-hosted or local open-weight model is also supported |

TODO(legal): confirm that the mail relay and AI provider are the Customer's processors, not CrabNebula's sub-processors (ADR-018, ADR-019, ADR-009).

## Changes

We announce a change to this list on the platform and by email to the Customer's tenant admins TODO(legal): the notice period before the change applies.

Version: TODO(legal): version and date.

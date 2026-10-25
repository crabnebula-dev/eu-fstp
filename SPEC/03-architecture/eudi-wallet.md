# EUDI Wallet integration

## Relying party modes (P-45)

| Mode | Registered party | Where it runs |
| --- | --- | --- |
| Tenant registration | The tenant operator | Inside the tenant cell |
| Intermediary | CrabNebula Ltd, acting on behalf of the tenant | Stateless intermediary service in the SaaS |

## Rules

- The wallet request shows the tenant as the party on whose behalf data is requested, in both modes.
- In intermediary mode, the intermediary service passes results straight into the tenant's identity vault and retains no transaction content. TODO(legal): confirm the intermediary obligations in the amended eIDAS Regulation and its implementing acts.
- Self-hosted cells use tenant registration only. Intermediary mode would send identity data to a CrabNebula service, which I-38 forbids.
- Requested attributes are limited to what the verification step needs. Age is requested as an over-18 attestation where the wallet supports it, rather than a date of birth.
- Signature requests follow the same modes (`02-domain/contracts.md`).

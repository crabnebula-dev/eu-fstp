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

## Yivi (decided 2026-11-13)

The Yivi app is an accepted wallet for the steps below. `../../docs/adr/ADR-021-yivi-wallet.md` holds the protocol profile and the record of what Yivi's documentation states.

| Step | Requirement | What the wallet discloses |
| --- | --- | --- |
| Over-18 attestation by the lead | R-NG-01, R-ID-04 | An over-18 attribute, never a date of birth |
| Guardian verification and consent | R-NG-01, R-NG-02, I-18 | The guardian's identity attributes |
| Identity verification in NEGOTIATION | R-NG-01, I-17, P-18 | Only the attributes the verification step needs |

Rules:

- Yivi is accepted for all three steps. The legal confirmation of its assurance level runs in parallel and does not gate the build. TODO(legal): confirm that a Yivi credential meets the level the programme needs for identity verification and guardian consent.
- Both relying party modes of P-45 apply to Yivi. In tenant registration the tenant is the registered Yivi verifier. In intermediary mode CrabNebula Ltd is, and the request still shows the tenant as the party on whose behalf data is requested.
- Self-hosted cells use tenant registration only (I-38).
- The verifier is in-house and speaks OpenID4VP. No Yivi server component or wallet library runs in a cell, a vault or the intermediary service.
- Disclosure happens on the vault origin, and only the vault receives the attributes (R-NG-01, I-17).
- The vault records the wallet scheme and the relying party mode beside the fields of R-ID-02. It stores no attribute value beyond the derived answer, and no wallet identifier that is stable across tenants (I-20).
- The other P-18 methods stay available as a fallback.
- Yivi counts under the P-18 method "EUDI Wallet". Interim, pending Daniel: whether P-18 gains a separate value for it.
- Signing with Yivi is investigated with this work (O-62). Until that closes, P-30 and `02-domain/contracts.md` are unchanged.
- Login with Yivi is not part of this decision.

The Yivi Business Wallet, for organisation identity and mandates, is deferred (`11-backlog.md`, B-12).

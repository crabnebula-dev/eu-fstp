# ADR-020: Yivi wallet verification

Status: Proposed. Drafted 2026-11-13 from Daniel's decisions of that day (issue #7). The rows marked "Decided" are his. Rows marked "Proposed" or "Open" wait for him, and no implementation starts on them before this ADR is accepted.

## Context

- `SPEC/03-architecture/eudi-wallet.md` sets the relying party modes (P-45) and, since 2026-11-13, accepts the Yivi app as a wallet.
- **R-NG-01** Identity attributes are collected only in NEGOTIATION, with the over-18 and guardian exceptions, and only the identity vault receives them.
- **R-ID-02** The vault stores verification outcome, method, document type, checks performed, time and verifier, and no document numbers.
- **R-ID-04** A proposal is minor-flagged unless its lead has an effective verified over-18 attestation at the call deadline.
- **I-17** Judging roles cannot read identity attributes before negotiation.
- **I-18** A minor-flagged proposal cannot enter negotiation without a verified guardian consent record.
- **I-20** The platform stores no link between tenant accounts in different tenants.
- **I-38** Calls from a self-hosted cell to CrabNebula-hosted services carry no tenant data.
- ADR-008 placed EUDI Wallet login and verification in M4.
- The dependency policy allows no third-party crate without an ADR, and ADR-001 forbids in-house cryptographic primitives.

## Decision record

| Date | Who | Decision |
| --- | --- | --- |
| 2026-11-13 | Daniel | The Yivi app comes first. The Yivi Business Wallet is deferred (B-12), and CrabNebula joins its design partner programme |
| 2026-11-13 | Daniel | Yivi is accepted for the over-18 attestation, guardian verification and identity verification. The legal check on its assurance level is a confirmation, not a gate |
| 2026-11-13 | Daniel | Both P-45 modes are designed and built from the start. The legal check on intermediary mode runs in parallel (L-05) |
| 2026-11-13 | Daniel | Signing with Yivi is investigated and designed with this work (O-62) |
| 2026-11-13 | Daniel | The work is built in M4, with EUDI Wallet verification |

## What the Yivi documentation states

Read on 2026-11-13 from the pages under "Sources". Paraphrased, not quoted. Nothing here was written from memory.

| Topic | Statement |
| --- | --- |
| Protocol | The app is compatible with a subset of OpenID4VP 1.0. Verifiers send DCQL queries |
| Formats | `dc+sd-jwt` from app 7.10.0, `mso_mdoc` from app 8.3.0, `vc+sd-jwt` from app 8.4.0. Each format answers only its own queries |
| Verifier identity | A verifier needs an X.509 certificate on the Yivi Trust List. It comes from becoming a Trusted Verifier in the Yivi portal, then a manual step with Yivi support |
| Certificate content | The certificate is tied to the verifier's hostname. It embeds JSON with the organisation's details and every attribute the verifier may request. Wildcards are not supported yet |
| Verifier key | The published certificate request script generates an EC key on `prime256v1` |
| Client identifier | The prefixes `x509_san_dns` and `x509_hash` |
| Request forms | By reference (`request_uri`), by value (`request`), or unsigned parameters with the `redirect_uri` prefix. The app shows an unsigned verifier as unverified |
| Response modes | `direct_post` and `direct_post.jwt` |
| Links | `openid4vp://` and `eudi-openid4vp://`. A universal link at `https://open.yivi.app/-/openid4vp` wraps the same query string, and only Yivi can claim it |
| Over-18 | The example verifier JSON lists an `over18` attribute |
| Reference backend | The documented verifier backend is `eudi-srv-verifier-endpoint` of the EUDI Wallet project. Its frontend-facing API is not part of OpenID4VP |
| Idemix | OpenID4VP disclosure covers SD-JWT VCs. Idemix credentials are issued over the IRMA protocol |

## Decision

| Topic | Decision | Basis |
| --- | --- | --- |
| Steps covered | Over-18 attestation, guardian verification and consent, identity verification in NEGOTIATION | Decided |
| Verifier | One in-house OpenID4VP verifier, built on `fstp-http`, `fstp-json`, `fstp-tls` and `fstp-crypto`. It also serves other wallets that speak the same profile | Proposed. Dependency policy |
| New crates | None. `eudi-srv-verifier-endpoint`, `irmago` and OpenID4VP libraries are not used | Proposed. Dependency policy |
| First format | `dc+sd-jwt`. `mso_mdoc` follows, reusing the CBOR subset of `fstp-webauthn` where it fits. `vc+sd-jwt` is not planned | Proposed |
| Idemix | Not accepted. Verifying it would need an in-house cryptographic primitive | Proposed. ADR-001 |
| Request | A signed request object served by reference, with the `x509_san_dns` prefix and the chain in `x5c` | Proposed |
| Response mode | `direct_post` over TLS first. `direct_post.jwt` only once this ADR records that aws-lc-rs covers its key agreement and content encryption | Open |
| Cryptography | Request signing, issuer signature checks and key-binding checks through `fstp-crypto` on aws-lc-rs. The verifier key is EC P-256 | Proposed. ADR-001 |
| Verifier key custody | The verifier key sits in key custody (ADR-004), in the cell for tenant registration and in the intermediary service for intermediary mode | Proposed |
| Wallet link | The Yivi universal link for same-device use, and a QR code for cross-device use. The vault origin renders both with no third-party script | Proposed. ADR-014 |
| Method in P-18 | Yivi counts under "EUDI Wallet" | Interim, pending Daniel |
| Fallback | The other P-18 methods stay available | Decided |
| Login | Not covered. P-70 keeps refusing the EUDI Wallet method until its own decision | ADR-008 |

### Verification checks

The verifier accepts a presentation only when every check below passes. A failed check gives a typed refusal and no vault fact.

- The response belongs to an open request of this vault session, and the request has not been answered before.
- The nonce and the audience equal the values of that request.
- The credential type is on the allowlist for the step.
- The issuer signature verifies against the pinned issuer trust list of the tenant. Nothing in the presentation adds a trust anchor.
- The key-binding proof verifies against the key the credential names.
- The credential is inside its validity period.
- The credential status is good, where the issuer offers a status mechanism.
- Every disclosure matches a digest in the signed credential, and no disclosure is used twice.

### Relying party modes (P-45)

| Mode | Registered Yivi verifier | Certificate hostname | Where the result goes |
| --- | --- | --- | --- |
| Tenant registration | The tenant | The tenant's vault origin | The tenant's vault |
| Intermediary | CrabNebula Ltd | The intermediary service | Straight into the tenant's vault. The service keeps no transaction content |

- The request names the tenant as the party on whose behalf data is requested, in both modes.
- Self-hosted cells use tenant registration only (I-38).
- A Yivi certificate lists every attribute its holder may request. The intermediary's certificate therefore covers the union of what its tenants may request, and each request still asks only for what its step needs.
- TODO(legal): confirm the intermediary obligations (L-05). The build does not wait for it. Enabling intermediary mode for a live programme does.

### Vault record

The vault stores the fields of R-ID-02, with method `wallet`, plus the wallet scheme (`yivi`), the relying party mode, the credential type and the issuer. It stores the derived answer of the step, for example "over 18 at the deadline: yes". It stores no other attribute value, no presentation, and no wallet or credential identifier that is stable across tenants (I-20).

### Parsers and fuzz targets

Each parser below is in-house and has a fuzz target from its first commit.

| Parser | Property |
| --- | --- |
| SD-JWT compact form and disclosures | Returns a credential or a typed error. Bounded size, count and depth |
| Key-binding JWT | Returns a proof or a typed error |
| Authorization response (`direct_post` form body) | Returns a response or a typed error. Unknown or duplicate members are refused |
| DCQL codec | The encoder output parses back to the same query |

### Signing (O-62)

The pages read for this ADR do not describe a signing interface. This part is an investigation until it closes.

- Find out whether the Yivi app can create a signature over a document digest, in which format, and under which certificate or attribute.
- Find out whether such a signature can reach the qualified level. TODO(legal): the level decides its place in the P-30 cascade.
- The rules of `SPEC/02-domain/contracts.md` stay: the signer's wallet creates the signature, never the platform, and the server validates it.
- A format other than CMS over the PDF byte range needs an amendment here that says how it is embedded and validated.
- P-30 and `contracts.md` do not change until O-62 is resolved.

## Threats

`SPEC/06-threat-model/threat-model.md` gains TH-69 to TH-73: replay, relay to another person's wallet, hostile responses, issuer or verifier key compromise, and capture of the URI scheme.

## Tests

Written before the code they constrain, each naming its ID.

- I-17, R-NG-01: no route outside the vault origin receives a disclosed attribute.
- I-18, R-NG-02: a guardian verified through Yivi yields the consent record the gate needs.
- I-20: no stored field links one wallet across two tenants.
- I-38: a self-hosted cell refuses intermediary mode.
- R-ID-02: the vault record holds no attribute value beyond the derived answer.
- R-ID-04: only a verified over-18 presentation clears the minor flag.
- Intermediary mode: the service retains no transaction content after forwarding.
- Fixtures use synthetic issuer keys and credentials only.

## Open points

| Point | Owner |
| --- | --- |
| Which Yivi credential and issuer carry the over-18 attribute and the identity attributes, from the Yivi attribute index | Lane that builds the verifier |
| The signature algorithms of those issuers, and confirmation that aws-lc-rs covers them | Lane that builds the verifier |
| Trusted Verifier onboarding with Yivi for a staging vault hostname and the intermediary hostname | Daniel |
| Whether P-18 gains a separate value for Yivi | Daniel |
| Response encryption (`direct_post.jwt`) | This ADR, before use |
| Assurance level of Yivi credentials. TODO(legal) | Daniel (`SPEC/10-open-questions.md`, legal checks) |
| Signing with Yivi | O-62 |

## Sources

- <https://docs.yivi.app/openid4vp-verifier-integration>
- <https://docs.yivi.app/openid4vp-disclosure>
- <https://yivi.app/en/business_wallet/>, for the Business Wallet deferred as B-12.

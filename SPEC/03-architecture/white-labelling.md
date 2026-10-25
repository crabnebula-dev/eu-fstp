# White-labelling

Every tenant can present the platform entirely under its own brand. The same package applies on the SaaS and in self-hosted cells.

## White-label package

| Element | Applies to |
| --- | --- |
| Name and logo, in light and dark variants | All interfaces, public pages, documents, emails |
| Colour tokens | Interfaces and public pages |
| Typography | Interfaces, public pages, documents |
| Favicon and app icons | Browser and installed web app |
| Custom domains | Applicant, reviewer and public interfaces |
| Email sender domain and templates | All email |
| Document templates | Guide for Applicants, contracts, notices, funder documents |
| Matrix bot name and avatar | Messaging |
| Legal pages | Imprint, privacy notice, terms of use, accessibility statement |
| Terminology overrides | Interface labels only, such as "subgrant", "call" or "milestone" |

The package is part of the tenant export (`schemas/README.md`).

## Rules

- **I-68** Branding is data only. No tenant-supplied script, style rule or markup executes in any interface. Colours, fonts and images pass through fixed tokens and sanitisers.
- **I-69** Branding cannot remove mandatory elements: funder visibility elements required by the funder profile, the AI assessment disclosure, the privacy notice, the accessibility statement, the Data Act information for tenants and the platform attribution (P-68).
- **I-70** Every colour pair used for text meets WCAG 2.2 level AA contrast in light and dark themes. Packages that fail are rejected with the failing pairs listed.
- **I-71** A custom domain serves traffic only after verified ownership, and only for its own tenant cell.
- Fonts are self-hosted from the cell. No third-party font, analytics or asset hosts are loaded.
- Images are re-encoded on upload. SVG is rasterised or passed through an allowlist sanitiser.
- **I-72** Terminology overrides apply to interface labels only. Contracts, notices, the Guide for Applicants, funder documents and emails keep their approved wording.

## Domains and TLS

The control plane maps custom domains to cells. It holds routing data only, never tenant content. Certificates are issued automatically through ACME after the ownership check, using ADR-001 crates. Self-hosted cells use the same mechanism or a certificate the tenant supplies.

## Platform attribution

Every interface and public page shows a platform attribution in the footer (P-68). It is a mandatory element under I-69.

- The attribution is a plain link with no tracking parameters and no referrer beyond the default browser policy.
- It uses the tenant's colour tokens, so it fits the brand while staying legible (I-70).
- Documents, emails and messaging carry no attribution, so contracts and notices stay entirely under the tenant's name.
- Self-hosted cells show the same attribution.

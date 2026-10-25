# Desktop client

A native desktop client, built with Tauri, gives reviewers, grantees and programme staff the platform in a dedicated app. Calls are backlogged (B-01).

## Scope

- The same interfaces as the web frontend, served from the tenant cell through the same API.
- White-labelled per tenant, using the tenant's package (`white-labelling.md`).
- No offline copies of proposal content. Cached data is limited to interface assets and the user's own drafts.

## Rules

- The client authenticates to one tenant cell at a time. Switching tenants means switching accounts, preserving I-20.
- Updates are signed and verified as for self-hosted cells (`self-hosted-services.md`).
- Releases of the client are subject to the Tier B release gate (I-74).

## CRA

The desktop client is a product with digital elements in its own right. It needs its own SBOM, vulnerability handling and conformity assessment, alongside the self-hosted cell.

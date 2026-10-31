# ADR-013: MCP protocol and OAuth profile

Status: Accepted 2026-10-31 (Daniel Thompson-Yvetot) for the Q8 and Q25 rows: open dynamic registration, the design tool set, the newest dated MCP revision with 2025-06-18 as the floor, and the design lifetimes. Rows marked Open stay open until the lane that builds them records them.

The M4 design numbered this ADR ADR-008. M3 had already used ADR-008 to ADR-012, so it is ADR-013 (`docs/handoff/m4-design.md` section 15.0). Daniel has not answered Q8 or Q25 yet. Lanes W1e (`fstp-oauth`) and W3c (`fstp-mcp`) wait for this ADR. The pages path of the demo does not need it.

Each row below names its basis:

- **Design** means the M4 design states it (sections 3.6 and 3.8).
- **Interim, pending Daniel** means the design's recommendation is written in as the proposed decision (section 15.0). Daniel has not answered it.
- **Open** means this draft cannot state it yet.

## Context

- `SPEC/03-architecture/mcp-server.md` describes the MCP server, its capability table and white-labelling.
- I-84: every MCP tool has an equivalent web route under the same authorisation.
- I-85: an agent can prepare high-risk actions, and only the user confirms them in the platform with a step-up.
- I-86: no identity attribute reaches an MCP response.
- I-78: approving an agent connection links a device, so it needs a step-up.
- P-72 sets the absolute session lifetime. It is marked "(proposed)" in `policy-parameters.md`.

## MCP revision

| Topic | Proposed decision | Basis |
| --- | --- | --- |
| Pinned revision | The newest dated MCP revision at the time of acceptance, with 2025-06-18 as the floor | Decided by Daniel on 2026-10-31 (Q8) |
| Revision facts | The design believes that 2025-06-18 removed JSON-RPC batching, requires the `MCP-Protocol-Version` header after initialisation, and requires RFC 9728 metadata and RFC 8707 resource indicators. It also believes a later revision changed client registration guidance. These are unverified. The published text must be checked before this ADR is accepted | Open |

## Transport

| Topic | Proposed decision | Basis |
| --- | --- | --- |
| Endpoints | Streamable HTTP at `https://{tenant domain}/mcp` and `/mcp/public` | Design |
| `POST` | Takes one JSON-RPC message and answers `application/json` only. No SSE frame exists | Design |
| `GET` | Answers 405, so no server-initiated stream exists | Design |
| `DELETE` | Ends the MCP session | Design |
| `Origin` | A request without `Origin` is accepted, on the bearer token alone for `/mcp`. A present `Origin` must equal one of the tenant's own origins, or the request gets 403. A duplicated or unparsable `Origin` is refused | Design |
| `Mcp-Session-Id` | 128 random bits from `fstp_crypto::random_bytes`, stored hashed | Design |
| Methods | `initialize`, `notifications/initialized`, `ping`, `tools/list` and `tools/call`. No resources, prompts, sampling or elicitation in M4 | Design |
| `serverInfo.name` | The first label of the tenant's verified domain, matched against `^[a-z0-9][a-z0-9-]{0,30}$`. No `instructions` field is sent. `serverInfo.title` is not sent (Q43) | Design |

## Tools

| Topic | Proposed decision | Basis |
| --- | --- | --- |
| Tool table | Names, descriptions and input schemas are `const` data in the `OPS` registry of `fstp-access`, the only tool table. `fstp-mcp` serves `fstp_api_core::meta::tools()` and defines no tool of its own (TH-63) | Design |
| Tool set | Only the capability table of `mcp-server.md`, plus the prepare-only tool `fstp_prepare_call_publication` (Q32). No coordinator, ballot, IRC or tenant admin tools | Interim, pending Daniel (Q8, Q32) |
| High-risk operations | `channel_policy` returns `Prepare` for every high-risk operation that has a tool. Every other high-risk operation has no tool and gets `Deny(NotExposed)` | Design |
| Results | The read model goes in `structuredContent.data`, with `classification` and `untrusted`, the JSON pointers to user-supplied text. The `content` text block is a fixed sentence naming the classification and never holds user text (TH-60) | Design |
| MCP safety | MCP response construction requires `fstp_api_core::McpSafe`, implemented by hand for identity-free read models only (I-86) | Design |

## OAuth 2.1

| Topic | Proposed decision | Basis |
| --- | --- | --- |
| Metadata | Protected resource metadata (RFC 9728) at `/.well-known/oauth-protected-resource`. Authorisation server metadata (RFC 8414) at `/.well-known/oauth-authorization-server`. A missing token gets 401 with `WWW-Authenticate: Bearer resource_metadata="..."` | Design |
| Authorisation | `/oauth/authorize` with the authorisation code grant and PKCE `S256` only. The `resource` parameter must equal this cell's MCP URL | Design |
| Redirect URIs | Exact match, except the port of loopback URIs for native clients (RFC 8252). The URL parser accepts a strict subset and rejects userinfo, fragments and non-ASCII hosts | Design |
| Consent | Lists every scope in fixed plain-language text. Shows the client name as untrusted text with an "unverified" label, and the redirect host. Approving needs a step-up (I-78), so a magic-link session cannot connect an agent | Design |
| Registration | Open dynamic registration (RFC 7591), rate-limited. A client has no rights until a consent. Client metadata documents fetched from URLs are off, because the cell would fetch arbitrary URLs | Decided by Daniel on 2026-10-31 (Q8) |
| Token endpoint | `/oauth/token` with the authorisation code and refresh grants. Codes are single use and live 60 seconds | Design |
| Lifetimes | Access tokens live 10 minutes. Refresh tokens rotate, reuse revokes the family, and the family never outlives the P-72 absolute lifetime | Decided by Daniel on 2026-10-31 (Q25) |
| Pending actions | Expire after 24 hours, with no batch confirmation | Decided by Daniel on 2026-10-31 (Q25) |
| Revocation | `/oauth/revoke` (RFC 7009) and `POST /api/v1/me/agents/{client}/revocation` take effect at once (R-MC-03) | Design |
| Token format | 256-bit values from `fstp_crypto::random_bytes`, stored as SHA-256 hashes and compared with `constant_time_eq`. Bound to account, client, scopes, audience and cell | Design |
| Roles | Re-evaluated on every call, so no token outlives a role | Design |
| Strength | MCP tokens inherit the strength of the session that consented to them | Design |

## Scopes

Issued in M4: `calls:read`, `proposals:read`, `proposals:draft`, `proposals:binding`, `stage2:draft`, `review:read`, `review:draft`, `ranking:read`, `findings:read`, `creator:draft`, `calls:draft` and `audit:read`. Each has consent text. A scope never adds a right that the roles lack. Scopes for M5 and later are reserved names and are never issued. Basis: Design.

The consent texts are not written yet. They are open.

## Open items before acceptance

- Q8: the pinned revision, after a check of its published text; the registration mode; the tool set.
- Q25: the token, refresh and pending-action lifetimes.
- The consent text of each scope.
- The checks the design marks "I believe", listed under MCP revision above.

## Consequences

- `fstp-mcp` and `fstp-oauth` stay W0 stubs that refuse with `NotImplemented` until Daniel accepts this ADR.
- A later answer that changes a row amends this ADR first, then the code.

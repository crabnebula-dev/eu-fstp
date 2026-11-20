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
| Pinned revision record | MCP revision 2026-07-28, the current revision on 2026-10-31. Source: https://modelcontextprotocol.io/specification/versioning, with the text at https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization, its subpages and https://modelcontextprotocol.io/specification/2026-07-28/changelog | Recorded by lane W1e on 2026-10-31 |
| Revision facts | Checked against the 2026-07-28 text, paraphrased and not quoted. See "Record of lane W1e" below for each fact and the open points it raises | Recorded by lane W1e on 2026-10-31 |

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
| Tool set | Only the capability table of `mcp-server.md`, plus the prepare-only tool `fstp_prepare_call_publication` (Q32). No coordinator, ballot, IRC or tenant admin tools | Decided by Daniel on 2026-10-31 (Q8, with the Q32 prepare-only tool) |
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

## Record of lane W1e (2026-10-31)

Lane W1e built `fstp-oauth` against this ADR and checked the authorisation text of the pinned revision. Every fact below is a paraphrase. No specification text is quoted.

### Facts of revision 2026-07-28 that `fstp-oauth` meets

| Fact | Where it is built |
| --- | --- |
| A protected MCP server publishes RFC 9728 metadata naming at least one authorisation server | `AuthorizationServer::resource_metadata` |
| The authorisation server publishes RFC 8414 metadata. Clients refuse a server whose metadata lacks `code_challenge_methods_supported` | `server_metadata` lists `S256` only |
| Clients send `resource` in both the authorisation and the token request. The server accepts only tokens issued for itself | `resource` must equal the MCP URL; `authenticate` checks the audience on every call |
| Servers should send the RFC 9207 `iss` parameter on every authorisation response, errors included, and then advertise it | Every redirect carries `iss`; the metadata sets `authorization_response_iss_parameter_supported` |
| Redirect URIs are validated exactly against registered values. Redirect URIs are `https` or loopback | `parse_url` and `redirect_matches` |
| Refresh tokens of public clients rotate. Access tokens should be short-lived | Rotation with reuse detection; 10-minute access tokens |
| An invalid or expired token gets 401. A token lacking a scope gets 403 `insufficient_scope` naming the scopes needed | `authenticate`; `insufficient_scope` |
| The consent shows the redirect host | `ConsentRequest::redirect_host` and `loopback_redirect` |

### Differences from the pinned revision, open for Daniel

- **Dynamic registration is deprecated in 2026-07-28.** It stays a permitted mechanism for backwards compatibility. Client ID metadata documents are now the recommended mechanism. Q8 chose open dynamic registration with no metadata fetch, and this lane keeps that decision. Before the deprecation window ends, Daniel decides whether the cell adds metadata documents with a guarded fetch.
- **Resource case.** The revision recommends accepting an uppercase scheme or host in `resource`. This ADR requires `resource` to equal the MCP URL, so `fstp-oauth` compares exactly. A client that uppercases the host is refused.
- **Scope in the 401 challenge.** The revision recommends a `scope` parameter in the 401 challenge. `fstp-oauth` cannot know the operation, so its 401 carries none. `fstp-mcp` can add one per operation through `insufficient_scope`.
- **Transport rows (lane W3c).** Revision 2026-07-28 removes the `initialize` handshake, `notifications/initialized`, `ping`, protocol sessions and `Mcp-Session-Id`. It adds a mandatory `server/discover`, the protocol version in each request's `_meta`, the `Mcp-Method` and `Mcp-Name` headers and a `resultType` on every result. The Transport rows above predate this. This lane changes no Transport row. Daniel and lane W3c decide how the rows meet the pinned revision.

### Interim readings built by lane W1e, pending Daniel

| Topic | Reading | Basis |
| --- | --- | --- |
| Lifetimes at the edge | A code, token, consent or family is valid while younger than its lifetime and dead at exactly that age | Repository convention, as for step-up proofs |
| Failed redemption | Any failed redemption of a fresh code burns it. A second redemption of a redeemed code revokes the family it started | OAuth 2.1 recommends the revocation |
| RFC 7009 revocation | A refresh token revokes its whole family. An access token revokes itself only. An unknown token or one of another client still gets 200 | RFC 7009 allows both |
| Access token cap | Every access token expires at the earlier of 10 minutes and the end of its family, so none outlives P-72 | Q25 |
| Refresh scope | A refresh may ask for a subset of the family's scopes. The family keeps its scopes | OAuth 2.1 |
| Pending consents | A consent lives 10 minutes and approves once. A refused step-up keeps the consent for a retry. The shell passes a browser session key. Each session holds at most 4 pending consents per client, and a fifth evicts its own oldest. Each client holds at most 16. Past that, the oldest consent of the session holding the most is evicted, but never a session's only one. When every session holds one, a new session gets 503 `temporarily_unavailable` | ADR-013 states no lifetime; fix round review finding 4 |
| Registration limits | Defaults of 10 attempts per rate key per hour, refused ones included, then 429. At most 10 000 clients, then 503. The cell sets both | Q8 states no figures |
| Unused clients | `purge` drops a client 24 hours after registration when it holds no consent, code or family, so its place under the cap is freed | Fix round review finding 3 |
| Refresh cap | A family issues at most 2048 refresh tokens. The refresh past that revokes the family. This bounds the retired hashes kept for reuse detection. Twelve hours of 10-minute access tokens need about 72 | Fix round review finding 4 |
| Errors before consent | Every error found at `/oauth/authorize` before the user acts is refused to the user with its OAuth error code, and never redirects. Registration is open, so no registered redirect URI is trusted. Only an approval or a denial redirects, with `iss` | TW-4; RFC 9700 section 4.11.2; fix round review finding 1 |
| Numeric hosts | A DNS host whose last label is all digits, or `0x` with hexadecimal digits or none, is refused. A WHATWG browser reads such a host as IPv4, so the consent page would show another host than the one reached | TW-8; fix round review finding 5 |
| Agent reads | `agents_of`, `client_id_of` and `revoke_agent_by_number` serve the API core's `Tokens` port. A grant keeps the `LoginMethod` of the consenting session, and its strength follows from that method | R-MC-03; Strength row; fix round review finding 2 |
| Debug output | The Debug text of `Reply` shows the status, header names and body length only. A redirect shows its origin only. Neither shows a code or token | R-NF-02; design section 5.4; fix round review finding 6 |
| Loopback hosts | `http` is accepted to `127.0.0.1`, `[::1]` and `localhost` only. RFC 8252 discourages `localhost`, but the pinned revision allows it for redirect URIs | RFC 8252, MCP 2026-07-28 |
| Client names | 1 to 64 characters, with no control character and no bidirectional or zero-width format character (TW-8) | Design section 5.2 |
| Metadata location | Every 401 challenge names `/.well-known/oauth-protected-resource` at the cell's origin, as the Metadata row says | This ADR |
| Token storage | Each code, token and consent handle is 32 random bytes as 43 characters of base64url. The server keeps SHA-256 of a per-kind label and the bytes, indexed by its first 16 bytes and compared in full with `constant_time_eq` | This ADR, Token format row |
| Records | The server holds its records in memory. A restart ends every grant, which fails closed. Storing them in the cell's `mcp` schema is a seam for the lead | Design section 4.1 |

## Record of lane m4/api-gaps (2026-11-15)

Daniel decided on 2026-11-15 to wire `agents.consent` to the real flow. This record states how. It changes no row above.

| Topic | Reading | Basis |
| --- | --- | --- |
| Consent operation | `agents.consent` is `POST /api/v1/oauth/consent` with the body `{consent}`, the handle of a consent the authorize flow left. It answers `{redirect}`: the client's redirect URI with the code, `state` and `iss` | Consent row; Daniel 2026-11-15 |
| Step-up binding | The API core takes the step-up bound to its own request digest, which covers the handle (I-78). The token port then attests that step-up to `AuthorizationServer::approve`, bound to the consent's own digest, which `consent_step_up_digest` reads for a live handle. The server still checks the attested proof itself | Consent row; I-78 |
| Order | A magic-link session is refused first (I-77), then the channel (web only, I-85), then the step-up. A handle the server does not hold is refused under `Input` after the step-up | Design section 3.7 |
| Shell | The API core's `Tokens::approve_consent` port reaches the server. The test cells' fake port holds a real `fstp-oauth` server. `fstp-web` still answers `/oauth/**` with the typed refusal of this ADR, so the authorize, token and revocation endpoints wait for the lane that mounts the server with its token store | Consequences |

## Record of lane mcp-demo (2026-11-20)

Daniel asked that Claude Code and claude.ai act on the demo cell through its MCP server. This record states what the current Claude Code sends, and what the lane built so that both it and the pinned revision work. Every fact about the revision is a paraphrase. No specification text is quoted.

### Evidence

- The client was the real Claude Code CLI, version 2.1.328 for darwin arm64, run with its own configuration directory so no setting of Daniel's changed.
- The first capture used `nc` as a listener, before the cell served anything. Every later fact comes from the e2e cell started with `--log-requests`, which writes method, path, MCP fields and status, and never a query, body, cookie or token.
- The browser side of the OAuth flow was played with `curl`: the demo sign-in of programme manager M1, the consent page, the approval and the demo step-up. Claude Code's own loopback callback then received the code and redeemed it.
- One non-interactive `claude -p` call with the model Haiku then called two tools against the cell, with an access token passed in a temporary MCP configuration.

### What Claude Code 2.1.328 sends

| Step | Observed |
| --- | --- |
| First request | `POST /mcp` with the method `server/discover`, the string id `server-discover-probe-1`, `_meta` naming revision 2026-07-28 and the client's identity and capabilities. The headers carry `MCP-Protocol-Version: 2026-07-28` and `Mcp-Method: server/discover`, and accept both JSON and an event stream |
| Discovery after a 401 | It reads `resource_metadata` from the challenge, then fetches the protected resource metadata and the authorisation server metadata. These two GETs carry `MCP-Protocol-Version: 2025-11-25` |
| Discovery without a 401 | `claude mcp login` asks first for the path form `/.well-known/oauth-protected-resource/mcp`. When that failed, it fell back to the server metadata at the root, then sent the authorisation request with neither `resource` nor `scope`, which the server refused as `invalid_target` |
| Registration | Open registration succeeds. The client names itself `Claude Code (<server name>)` and registers one redirect URI, `http://localhost:<random port>/callback` |
| Authorisation | PKCE `S256`, a `state`, `resource` equal to the MCP URL, and `scope` listing every scope of `scopes_supported` |
| Token | It refuses to send a token request to a plain `http` endpoint unless the host is `localhost`, `127.0.0.1` or `::1`. A `.localhost` subdomain such as `a.fstp.localhost` is not exempt |
| After the token | `server/discover`, then `tools/list`, both modern, with no session id. Each `tools/call` carries `Mcp-Name` equal to the tool name |
| Legacy fallback | Before this lane the server spoke the legacy revision only. `claude mcp list` still reported `/mcp/public` as connected, which matches the fallback to `initialize` on a 400 that carries no modern error |
| A restarted cell | The client keeps the `client_id` it registered. A restarted cell no longer knows it and refuses the request as `invalid_client`. `claude mcp logout <name>` drops it, and the next login registers again |
| User agents | `claude-code/2.1.328 (...)` on `/mcp`, and `Bun/1.4.4` on discovery, registration and the token endpoint |

### Facts of revision 2026-07-28 used here

- A modern request names its protocol version in `_meta`. The `MCP-Protocol-Version` header must equal it.
- Each request names its method in `Mcp-Method`. A tool call names its tool in `Mcp-Name`. A missing or different value gets 400 with JSON-RPC error -32020.
- A version the server does not serve gets 400 with error -32022. Its data lists the supported versions and the requested one.
- A method the server does not offer gets 404 with -32601.
- `server/discover` is mandatory. It answers the supported versions, the capabilities and the server's identity under `_meta`.
- Every result names its `resultType`. No session exists, and a server ignores a session id it receives.
- A server may serve both eras on one endpoint. A request with modern `_meta` is served without a session, and `initialize` selects the legacy rules.
- A client that meets a 400 without a recognised modern error falls back to `initialize`.

### What the lane built

| Topic | Reading | Basis |
| --- | --- | --- |
| Two eras | `fstp-mcp` serves a request with a `_meta` protocol version as a modern request of 2026-07-28. Every other request keeps the legacy rules of the floor revision, with `initialize` and a session. The Transport rows above hold for legacy requests | Pinned revision; Claude Code 2.1.328 |
| Modern rules | The shared rules run first: `GET` gets 405, then `Origin`, then the bearer token on `/mcp`, then media types and the JSON-RPC body. Then the header checks, the version check, and the method | Pinned revision |
| Modern methods | `server/discover`, `tools/list` and `tools/call`. `server/discover` and `tools/list` on `/mcp` judge the token like `initialize` does. Any other method, the legacy `ping` included, gets 404 | Pinned revision; Methods row |
| Discovery result | `supportedVersions` names 2026-07-28 only, since the legacy floor is reached through `initialize`. The capabilities offer tools. The white-labelled name sits under `_meta`. No `instructions` member is sent | Q43; `serverInfo.name` row |
| `Mcp-Name` | Compared byte for byte. A Base64 sentinel value is refused as a mismatch, since no tool name of the registry needs it | Interim, pending Daniel |
| Unsupported version | Its error data echoes the requested version. The header admits only visible ASCII of at most 32 bytes, so the echo stays bounded | Interim, pending Daniel |
| Resource metadata | `fstp-web` also serves it at `/.well-known/oauth-protected-resource/mcp`, the RFC 9728 path form. Challenges still name the root form, as the "Metadata location" reading says | RFC 9728; Claude Code 2.1.328 |
| OAuth endpoints | The e2e cell mounts `/oauth/register`, `/oauth/authorize`, `/oauth/token` and `/oauth/revoke` over the `fstp-oauth` server of its token port. `fstp-web` keeps the typed refusal, so the production cell is unchanged | Consequences; lane m4/api-gaps record |
| Token port | The fake token port resolves access tokens of its `fstp-oauth` server for the API core, so dispatch judges a real token on every call (I-84) | I-84; Roles row |
| Consent page | Server-rendered, with no script. It shows the client name as unverified text, the redirect host and each scope in plain words. Approval calls `agents.consent` through the cell's own API with the browser's session, so I-77, I-85 and I-78 run there | Consent row |
| Form posts | A plain form cannot send `X-FSTP-Request`. The consent forms are admitted only when `Origin` is the cell origin and `Sec-Fetch-Site`, when present, is `same-origin` | Interim, pending Daniel |
| Demo step-up | Only with `--demo-signin`, and only for a session a demo sign-in opened, the step-up of a consent confirms with a button. Without the flag the route answers 404, which a test proves | Layering rule A9; I-78 |
| Consent texts | The e2e cell writes its own plain-language text per scope | Interim, pending Daniel; consent texts open |
| Public origin | `--public-origin <origin>` makes cell `a` name that origin as its page origin, `Origin` rule, issuer and MCP resource. It admits `https`, or `http` to `localhost`, `127.0.0.1`, `[::1]` or a `.localhost` host | Claude Code token rule; claude.ai needs https |
| Local demo origin | For Claude Code the demo cell runs with `--public-origin http://localhost:<port>`, so the token endpoint is on an exempt host | Claude Code 2.1.328 |
| Grants on a reset | A reset or a new scene replaces the cell's accounts. The authorisation server then ends every consent, code and token, and keeps the registered clients, through `AuthorizationServer::end_all_grants` | R-MC-03 |
| Registration limit | The test cell admits 200 registrations per rate key and hour. Every client behind a tunnel shares one loopback peer | Interim, test cell only |

### Not verified, open for Daniel

- **claude.ai custom connector.** Not exercised, since it needs a public tunnel and Daniel's claude.ai account. The flow it uses was checked by design: the 401 challenge, both metadata documents under the public origin, and an `https` redirect URI within the URL subset. Three points are unknown. Its registration may ask for a token endpoint authentication method other than `none`, which the decoder refuses. Its servers may send an `Origin` header, which gets 403 unless it is the tenant origin. Which era it speaks is not known; both are served.
- **Transport rows.** This record adds the modern era next to the rows and changes none. Daniel decides whether the rows are amended to name both eras.
- **Production cell.** `fstp-cell` still refuses `/oauth/**`. It needs a token store port, the endpoints above, and a consent page in the platform that runs the passkey step-up.
- **Restarts.** The e2e cell keeps its records in memory, so a restart forces `claude mcp logout` before the next login. The `mcp` schema seam of the W1e record would remove this.

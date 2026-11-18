# ADR-024: Rate limits and per-peer caps

Status: Proposed, pending Daniel's acceptance. Drafted 2026-11-17 for issue 6 (fast-pass security review of 2026-11-12).

The number is the next free one after ADR-023.

## Context

- Issue 6 lists five medium findings with one cause: missing rate limits and per-peer caps (M4, M6, M7, M8, M9). Two low findings fit the same pattern (L9, L13).
- `SPEC/03-architecture/mcp-server.md` requires that public tools are rate-limited per client, and that per-token and per-user limits apply.
- ADR-009 allows the client address from the tunnel header in memory only, for rate limits, at the edge and in the cell. It is never stored or logged. Its `TODO(legal)` on the basis stays open (Q19).
- ADR-013 requires that open client registration is rate-limited.
- The API core already holds sliding-window counters per account, session, token and client (`crates/fstp-api-core/src/rate.rs`). Their values are interim. A caller with no credential is charged against no key.
- The design reads I-24 as "every call leaves one audit entry". An anonymous caller can therefore write audit rows without bound.

## Decision

One rule serves every surface: each resource an unauthenticated party can consume has a bound per peer, and a bound in total that no single peer can fill.

| Topic | Decision | Closes |
| --- | --- | --- |
| Peer | The peer is the client address the listener holds: the tunnel header address in a cell, the socket address elsewhere. An IPv6 address counts by its /64 prefix. An IPv4 address counts whole | ADR-009 |
| Peer key handling | The peer key lives in memory only. It never enters a log line, an audit entry, a ledger record, an error text or a metric label | ADR-009 |
| Unknown peer | A surface that holds no client address charges one shared key, so the limit still applies | Fail closed |
| Counters | Sliding windows, as `fstp-api-core/src/rate.rs` has them: a refused call counts against no key, and idle keys are swept. Each crate keeps its own small counter. No shared crate is added | Existing design 3.7 step 4 |
| API calls with no account | A call with no account is charged against the peer key, on the web and on MCP alike | M7 |
| Audit rows of rate refusals | A call refused by a rate limit writes one audit entry for the first refusal of a key in a window. Later refusals of that key in that window write none. The entry names the limit, never the peer | M7 |
| MCP sessions | Authenticated and anonymous sessions live in separate tables. Opening an anonymous session never evicts an authenticated one. One peer holds a bounded share of the anonymous table | M4 |
| HTTP connections | One peer holds a bounded share of the connection slots. Every connection has a total lifetime, after which the server closes it once the current response ends | M6 |
| Public auth routes | Login start, login finish, magic-link request and recovery start are limited per peer. Magic-link and recovery requests are also limited per target address digest. Expired login challenges are purged, and the challenge table has a cap | M8 |
| `PutText` | Only an account that may write the text's owning object may put a text. Puts are limited per account and bounded in size per account per day | M9 |
| OAuth registration | Registration is limited per peer key. The total cap stays | L9 |
| Key daemon usage log | Usage records are limited per client connection, and the log has a size bound. At the bound the daemon refuses usage-writing requests and still serves create and destroy | L13 |

### Interim values, pending Daniel

The design names these limits and no values. The values below are a first reading. Each is one named constant beside its counter.

| Limit | Value |
| --- | --- |
| API calls per peer with no account | 120 per minute |
| MCP anonymous sessions per peer | 64 of 4096 |
| HTTP connections per peer | 64 of 1024 |
| HTTP connection total lifetime | 10 minutes |
| Login start and finish per peer | 30 per minute |
| Magic-link and recovery requests per peer | 10 per minute |
| Magic-link and recovery requests per target | 5 per hour |
| Login challenges held | 4096, purged at expiry |
| `PutText` per account | 120 per minute |
| OAuth registrations per peer | 10 per hour |
| Key daemon usage log size | 64 MiB. Create and destroy are served until twice that |
| Key daemon usage records per client socket | 6000 per minute |

### As built on 2026-11-17

- A full login challenge table answers 503 and evicts nothing.
- A per-target refusal of a magic-link or recovery request answers like an accepted request, so it reveals no account.
- The audit rule for rate refusals applies to every rate limit of the API core, not only the peer key.
- `PutText` has the per-account rate limit only. The command carries no owning object and no size, so the ownership rule and the daily size bound wait on a design decision.
- No production listener mounts the MCP server or the OAuth registration route yet. Each takes the peer through `McpServer::serve_from` and `RateKey::from_ip` once mounted.

## Consequences

- An office behind one address shares one peer budget for anonymous calls. Signed-in calls are charged per account and session, so sign-in lifts the shared bound.
- The audit log no longer holds one row per rate-refused call. This narrows the design's reading of I-24 for rate refusals only. I-24 itself (tamper evidence) is unchanged. Daniel decides whether the narrowing stands.
- A cell behind the edge sees the client address only through the tunnel header. A listener without that header falls back to the shared key.
- Every bound has a regression test named after its finding in issue 6.

## Open points for Daniel

- Accept or change each interim value.
- Accept the audit narrowing for rate refusals, or choose a counted summary entry per window.
- The `TODO(legal)` of ADR-009 on client addresses (Q19) covers the peer key here too.

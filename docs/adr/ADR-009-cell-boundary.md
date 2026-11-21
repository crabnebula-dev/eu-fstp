# ADR-009: Cell boundary

Status: Accepted 2026-10-28 (Daniel Thompson-Yvetot).

Labels such as `Q7` refer to the questions in `docs/handoff/m3-design.md` section 21. Rule labels B1 to B12 come from design section 1.2. Each decision below names its basis:

- **Answered** means Daniel answered the question on 2026-10-28 (design section 21.0).
- **Interim, pending Daniel** means the design's interim reading (section 17.2) is written in as the proposed decision. Daniel has not answered it yet.

Daniel accepted this ADR on 2026-10-28. The interim readings in it are built as written, but each stays interim, pending Daniel, until he answers it. A later answer that changes one amends this ADR first, then the code (design section 18).

## Context

- **I-16** The platform never holds or controls funds.
- **I-17** Judging roles cannot read identity attributes of an applicant before the proposal enters negotiation.
- **I-19** No tenant data crosses a cell boundary except through a tenant export, a user-held profile bundle or a template the tenant published (I-73).
- **I-20** The platform stores no link between tenant accounts in different tenants.
- **I-38** Calls from a self-hosted cell to CrabNebula-hosted services carry no tenant data.
- **I-83** Identity vault databases never share a cluster with application databases.
- **R-NF-08** All data at rest in a cell is encrypted with cell-specific keys. Vault keys are separate from application keys.
- **R-NF-09** All network traffic between components is encrypted and mutually authenticated.
- `overview.md` says the vault answers the application only through its queries. Its section "Operations other than queries" names writes, releases, acknowledgements and negotiation facts, and places the vault origin in this ADR (decided 2026-10-28).
- I-19 does not say whether counters, health states, anchor links, edge logs and metrics are tenant data (design gap G26).
- Object storage, the witness's second-provider bucket and the licence and update services offer server-authenticated TLS only, as far as the pages the design read show (design gap G27).

## Decision summary

| Topic | Decision | Basis |
| --- | --- | --- |
| Trust domains | One trust domain per cell, with its own CA, databases, root epochs and processes | Design section 1, accepted with this ADR |
| Identity attributes | The vault origin with signed single-use tickets. Attributes, the P-17 country and documents go browser to vault | Answered (Q7 A) |
| I-19 tenant data | Everything except a closed metadata register of coarse metadata | Answered (Q36 A) |
| Self-hosted install | Local install agent, cluster CA keys in local custody | Answered (Q15) |
| R-NF-09 external links | Claimed for links between platform components. External services authenticated by request credentials | Interim, pending Daniel (Q34) |
| Vault ticket lifetime | 5 minutes, an ADR constant | Interim, pending Daniel (Q37) |
| Public certificates | Per-cell keys. Production issuance through an in-house ACME client with M4 onboarding | Interim, pending Daniel (Q30) |
| Client addresses | Memory only, for rate limits | Interim, pending Daniel (Q19) |
| Root on cell hosts | Accept the residual risk under separate host staff, two-person access, no standing root and tenant-visible access events (risk R16). Confidential computing evaluated in L-15 | Answered (Q35, 2026-10-28) |
| Deployment unit | An application host and a vault host per cell in SaaS, one node when self-hosted | Interim, pending Daniel (Q26) |

## Trust domains

| Domain | Processes | Storage | Keys | Who can talk to it |
| --- | --- | --- | --- | --- |
| Cell application | `fstp-cell` | Database `c_<cell>` on an application cluster | App chain root epochs in custody. App, ledger and text group keys in memory | Users through the edge. Its own vault. Its custody backend. The control plane through `CellToCp` |
| Cell vault | `fstp-vault` | Database `v_<cell>` on a vault cluster | Vault chain root epochs in a separate custody entry with its own credential. Its own `Anchor` key | Its own cell over mTLS. Browsers on the vault origin, through the edge, with tickets only |
| Control plane | `fstp-control`, and `fstp-pgagent` on each database host | Database `cp` on the control cluster | Cluster CAs, the control-plane CA, staff assertion and operator ticket keys | Staff with passkeys. Cells through `CellToCp` |
| Witness | `fstp-witness` | Its own database on its own cluster, plus an object-lock bucket at a second provider | Witness receipt key (composite) | Cells and vaults, each with a chain-bound certificate. `fstp-control` for restore declarations only, with a control-plane CA certificate (ADR-012, interim, pending Daniel). Auditors for reads |
| Edge | `fstp-edge` | None | Edge tunnel certificate from the control-plane CA | The public internet on port 443 |
| CrabNebula release services | `fstp-licence-svc`, `fstp-update-svc` | Licence registry and release metadata | Licence signing key (Ed25519) | Self-hosted cells, through `fstp-release::egress` only |
| Custody backend | OVHcloud KMS, `fstp-keyd`, or the test simulator | Provider-held, or the keyd file | Root epochs and CA signing keys | Only the process of the owning domain, each with its own credential |

## Boundary rules

- **B1.** Each cell has its own internal CA, created at provisioning. `fstp-cell` and `fstp-vault` trust only that CA for internal peers. A database cluster trusts its cluster CA, which signs only role certificates of that cluster.
- **B2.** Cell data lives only in the cell's two databases, its object storage prefix and its processes. Each is named by the random `CellId`, never by a tenant name.
- **B3.** Every byte of tenant data a cell writes to storage is sealed under a cell key first. Random ids, sequence numbers, times, enums and keyed digests may stay in clear, as the ADR-007 catalogue lists.
- **B4.** A cell opens connections only to the members of `Destination` (below). The host firewall enforces the same list.
- **B4a.** A vault opens connections only to the members of `VaultDestination` (below). It answers its own cell and the vault origin, and calls neither.
- **B5.** The edge never terminates tenant TLS.
- **B6.** The control plane holds no tenant account identifier, no tenant content and no identity attribute. Its crates cannot depend on a crate that defines those types (layering rule 4).
- **B7.** Database roles, pools and certificates are per cell. No role, pool or certificate serves two cells (ADR-005).
- **B8.** A vault database is never placed on a cluster that holds or may hold an application database (I-83).
- **B9.** Root epochs are per cell and per chain. The vault chain uses a custody entry and credential separate from the application chain (ADR-004).
- **B10.** Logs and metrics are typed `fstp-obs` events. No field can hold free text, content, identity attributes or key bytes (R-NF-02).
- **B11.** Session tokens carry the cell id, and every other cell refuses them. Passkeys use the exact tenant host as RP id (ADR-008).
- **B12.** A self-hosted cell is the same cell with no control plane. It reaches CrabNebula only through `fstp-release::egress`.

Sealed bytes under a cell's keys on a shared cluster, or in a cluster backup, stay inside that cell's trust domain. Only that cell's custody entries can open them (B3, B9).

## Certificate authorities

| CA | Created by | Signing key held in | Issues |
| --- | --- | --- | --- |
| Cluster CA, one per self-operated PostgreSQL cluster | `fstp-control` at cluster registration. `fstp-install` when self-hosted | Control-plane custody as an EC secp256r1 sign key. Local custody (`fstp-keyd`) when self-hosted (Q15) | The server certificate, with the cluster kind in the subject OU. Client certificates with CN equal to a role, 7-day lifetime |
| Cell CA, one per cell | The cell at first start, in the custody entry that provisioning created | The cell's application custody entry, as an EC secp256r1 sign key | `cell-app`, `cell-vault`, `cell-backup`, `cell-witness` and `vault-witness` client certificates for internal links only, 7-day lifetime, renewed daily |
| Control-plane CA, one per environment | Once, at environment set-up | Control-plane custody | `CellToCp` client certificates, edge tunnel certificates, witness server certificates |

- No CA is shared between cells. No regional CA signs leaves for several cells (I-19, TH-06).
- CA keys stay in custody and sign through the custody `sign` operation. CA rollover is yearly with overlap.
- Components generate their own key pairs. They send the public key with a proof of possession over a fresh challenge. No certificate signing request is parsed.
- Each cell role's password is generated by the cell. Only the SCRAM-SHA-256 verifier goes to `fstp-pgagent`. The control plane relays the verifier and the public key, and never learns the password or the private key.
- `fstp-pki` writes X.509 v3 certificates and PEM in-house and parses nothing. Tests validate every output with rustls-webpki and with a real PostgreSQL server.
- The witness pins each cell CA's public key, registered at provisioning or at install. It accepts `cell-witness` only for the App chain and `vault-witness` only for the Vault chain of that cell.
- **Public certificates.** `<cell host>` and `id.<cell host>` need a browser-trusted CA. Each cell generates its own key pairs, so no private key is shared across cells. A wildcard certificate for the platform domain is refused. M3 tests use a test root. Interim, pending Daniel (Q30): production issuance uses an in-house, fuzzed ACME client built with tenant onboarding in M4. Custom domains are M9 (I-71).

## Transports

- All component traffic uses `fstp-tls`: TLS 1.3 only, X25519MLKEM768 preferred, both sides authenticated.
- Database links follow ADR-005. The client verifies the server with verify-full, and PostgreSQL checks a client certificate on every `hostssl` line. The group is classical until ADR-005 D3 is settled.
- Session resumption follows ADR-001: at most 1 hour after the full handshake.
- Certificates of one cell are refused by every other cell's vault and databases (`i19_foreign_cell_certificates_are_refused`).

## Edge and tunnel

- `fstp-edge` reads the SNI from the ClientHello and never holds a tenant TLS key. A source scan refuses any TLS server configuration constructor in it (layering rule 5).
- `parse_client_hello_sni` reads at most 16 KiB and is fuzzed (`client_hello_sni`).
- No SNI, an unknown host or a malformed hello closes the connection.
- A ClientHello that carries the `encrypted_client_hello` extension is routed on its outer SNI, like any other hello, and its bytes pass unchanged (Daniel, 2026-10-29). Chromium-family browsers send a GREASE extension of that type by default, so closing such hellos would close those browsers. The edge never tries to tell GREASE from real ECH. The cell's TLS server holds no ECH keys and answers the outer hello.
- The route table holds verified hosts only. Each host maps to exactly one cell and one kind: application or vault origin.
- The edge opens one mTLS tunnel per client connection, with its tunnel certificate from the control-plane CA.
- The first tunnel frame is a fixed-length header: version, address family, client address, port and the routed host. The client's TLS stream follows unchanged (`i19_edge_forwards_bytes_after_client_hello_unchanged`).
  - Daniel kept the host field on 2026-10-29. The receiver refuses a tunnel whose header host differs from the SNI its own TLS server sees, and never trusts the header host over it.
  - Recorded at first use (lane W2i, 2026-10-29), version 1, `TUNNEL_HEADER_LEN` = 274 bytes: offset 0, version (1 byte); 1, address family, 4 or 6 (1); 2, client address, IPv4 as IPv4-mapped (16); 18, client port, big-endian (2); 20, host length, 1 to 253 (1); 21, the routed host in lowercase LDH, then zero bytes to the end (253). One spelling: the decoder refuses any other family, padding or host form.
- `decode_tunnel_header` lives in `fstp-edge` and is fuzzed (`tunnel_header_decode`). `fstp-cell` and `fstp-vault` call it.
- The edge logs host, cell id, byte counts and timings only, in the forms the metadata register sets.
- **Client addresses.** Interim, pending Daniel (Q19). The address in the tunnel header serves in-memory rate limits only, at the edge and in the cell. It is never stored or logged. `TODO(legal)`: the basis for short-lived in-memory rate limiting on client addresses. It has no L- item yet. It is listed for Daniel under "Legal checks awaiting an L- number" in `SPEC/10-open-questions.md`, and this marker names the number once he assigns it.
- **Self-hosted.** A local `fstp-edge` routes `<host>` and `id.<host>` by SNI, as in SaaS. The issuer of its tunnel certificate is an open point.

## Listeners

| Process | Listener | Accepts |
| --- | --- | --- |
| `fstp-cell` | Tunnel port | Edge tunnel certificates only |
| `fstp-cell` | Loopback health | `GET /healthz`, fixed body |
| `fstp-vault` | Internal mTLS port | Its own cell's `cell-app` certificate from the cell CA only |
| `fstp-vault` | Tunnel port for the vault origin | Edge tunnel certificates only |

Correction to design section 2.3: it lists an internal mTLS port on `fstp-cell` "for the vault". Under B4a the vault never calls its cell, so `fstp-cell` has no listener for the vault.

## Pilot edge configuration

Written by lane L9 `prod/edgerun` before its code, for gap G12 of `docs/handoff/production-mcp-design.md`. Rows marked "interim, pending Daniel" are the lane's own readings. The grammar follows ADR-026 "Configuration". This is a pilot, not a release.

| Topic | Decision | Basis |
| --- | --- | --- |
| Deployment | Decided by Daniel on 2026-11-21, superseding the interim reading of lane L9. The D1 pilot runs one `fstp-edge` and a minimal `fstp-control` that serves only the signed route feed. The edge polls the feed (`RouteFeed`) and changes routes without a restart, a SIGHUP or file watching. It reads no route file. "Pilot route feed" below records the design | D1; G12; Daniel 2026-11-21 |
| TLS role | Pass-through by SNI, as "Edge and tunnel" above says. The edge terminates no client TLS and holds no origin key (B5). The cell holds the origin certificate of its host (`origin.pem`, ADR-026). This lane adds no TLS role | B5; layering rule 5 |
| File | One JSON object in the file that `FSTP_EDGE_CONFIG` names, at most 4 KiB, decoded by `fstp_json` with depth, member and string limits. The member set is closed. An unknown member, a member given twice or a missing required member is refused | ADR-026 "File" |
| Members | `credentials_dir` (an absolute path), `listen` (`public`, a socket address), `feed` (the route feed source, "Pilot route feed" below; lane L15 replaced the member `routes`, the path of a route file) and `limits` (optional: `connections`, `per_client`, `hello_seconds`, `open_seconds`, `lifetime_seconds`). No member holds a secret | ADR-026 "Members" |
| Public listen address | Interim, pending Daniel. `listen.public` is the address the edge binds. The public origin is `https://<tenant domain>` with no port, since WebAuthn and claude.ai need it. So the address the tenant domain resolves to must accept TCP port 443 and reach this listener, directly or through a TCP forwarder that passes the ClientHello byte for byte. The edge cannot see the public port, so it does not check it | ADR-008; ADR-013; "OVHcloud verify items" |
| Origin agreement | The cell derives its origin, its OAuth issuer and resource, and its WebAuthn relying party id from the `host` of its configuration. A route's `host` must equal that `host` byte for byte, in lowercase. The cell refuses a tunnel whose header host is not its host, and a ClientHello whose SNI differs from the header, so a mismatch fails closed | ADR-026 "Members"; "Edge and tunnel" |
| Route file | Interim, pending Daniel. Since lane L15 the operator gives this file to `fstp-control route add`, with exactly one route, and the edge reads no route file. One JSON object `{"routes": [...]}`, at most 64 KiB and 64 routes. Each route has `cell` (32 lowercase hex digits), `host`, and the endpoints `app` and `vault`. Each endpoint has `address`, `server_name` and `cert_sha256`. The rules of `RouteTable::add_cell` hold: a host maps to one cell and one kind, `id.<host>` goes to the vault, a cell has one host, and no tunnel address serves two routes. Two endpoints never share a pin | I-19; design section 1.5 |
| Decoders | `fstp_edge::config::decode_config` and `fstp_edge::config::decode_routes`, fuzzed by `edge_config_decode` and `edge_routes_decode`. A refusal names its rule and never quotes the input | CLAUDE.md fuzz rule; R-NF-02 |
| Credentials | The credentials directory holds, by fixed name, readable by the edge's OS user only: `tunnel.pem` and `tunnel.key`, the edge's tunnel client chain and key; `tunnel-ca.pem`, the CA of the cells' and vaults' tunnel server certificates. In the cell's directory, `tunnel-ca.pem` is the CA of the edge's client certificate. So in each process it names the CA of the peer's tunnel certificate | ADR-026 "Secrets" |
| Pilot tunnel CA | Interim, pending Daniel. A pilot has no control-plane CA. The operator's own tunnel CA stands in for it. It issues the edge's client certificate and the tunnel server certificate of each cell and vault. It is kept apart from the cell CA and from the public origin CA. Its custody is the open point "Self-hosted issuers" below | "Certificate authorities"; D1 |
| Tunnel server pin | Interim, pending Daniel. `cert_sha256` is the SHA-256 of the DER of the tunnel server's end-entity certificate. The handshake first verifies the chain to `tunnel-ca.pem` and the name `server_name`. The edge then compares the digest of the leaf it received, and closes on a mismatch before it writes the tunnel header. So a certificate the tunnel CA issued in error never receives a client's bytes. A pin over the certificate keeps an X.509 reader out of the edge. Since lane L15 the pins come with the signed route feed. A renewed tunnel certificate needs a new pin through `fstp-control route add`, and no restart of the edge | I-19; B5 |
| Limits | Interim, pending Daniel. `connections`: open client connections, default 1024, 1 to 65536. `per_client`: open connections per client IP address, default 64, at most `connections`. `hello_seconds`: the ClientHello deadline, default 10, 1 to 60. `open_seconds`: the tunnel open deadline, handshake and pin included, default 10, 1 to 60. `lifetime_seconds`: the life of one connection, default 7200, 60 to 86400. A connection over a cap closes before any byte is read. The client address lives in memory only and is never logged | Q19; ADR-024 |
| Process | One tokio runtime through `fstp-rt` (ADR-002). SIGTERM or SIGINT stops the accept loop. Open connections get 20 seconds to end, and then the process exits with status 0. Logs are typed events only: `Started`, `ShuttingDown`, `Drained` or `DrainTimedOut`, with no host and no address. A refused configuration exits with status 2, any other failure with status 1, as `fstp-cell` does | ADR-002; R-NF-02 |

Tests of this section:

- `adr009_l9_edge_config_refuses_bad_input` and `adr009_l9_route_file_refuses_bad_input`.
- `r_nf_02_edge_config_refusals_never_quote_input`.
- `i19_pilot_unknown_sni_gets_no_route` and `i19_pilot_two_tenants_never_cross`.
- `i19_tunnel_pin_mismatch_opens_no_tunnel`.
- `crates/fstp-celltest/tests/i19_edge_binary_e2e.rs`: the `fstp-edge` binary, started from its file, in front of the `fstp-cell` binary of `World::start_external`. An HTTPS request with the tenant SNI reaches the protected resource metadata, which names `https://<host>/mcp` with no port.

## Pilot route feed (record of lane L15)

Written by lane L15 `prod/route-feed` before its code. Daniel decided on 2026-11-21 that the pilot edge must change routes without a restart, and not by SIGHUP or file watching. He chose the release design for it: a minimal `fstp-control` serves the signed route feed, and the edge polls it (`RouteFeed`). Certificate pins (`cert_sha256`) stay. There are no SPKI pins, since the `spki` crate is an unconfirmed Tier B crate (I-74). Rows marked "Interim, pending Daniel" are this lane's own readings. The route feed of ADR-004 (record of lane m3/erase-prod, "Route table polling") is the base. This section changes its bytes to carry the pins.

| Topic | Decision | Basis |
| --- | --- | --- |
| Route changes | Decided by Daniel on 2026-11-21. A route added or removed in `fstp-control` reaches every running edge through the signed route feed. No restart, SIGHUP or file watching is involved. Certificate pins stay, as the SHA-256 of the DER of the end-entity certificate. No SPKI pin | D1 amended; I-74 |
| What runs on the pilot | Interim, pending Daniel. `fstp-control route-feed` runs the feed listener, the operator socket and the feed signing key, and nothing else. The pilot runs no `CellToCp` listener, no `cp` database, no placement, no provisioning, no `fstp-pgagent` link, no operator passkey login, no erasure job, no isolation auditor and no CA. The pilot `fstp-control` knows routes and edge ids only, never a tenant name or account (B6) | D1; B6 |
| Feed configuration | Interim, pending Daniel. `FSTP_CONTROL_CONFIG` names one JSON object of at most 4 KiB with a closed member set: `credentials_dir`, `edges` (1 to 16 edge ids, 32 lowercase hex digits each, no id twice), `feed_listen` (a socket address), `keyd_socket`, `operator_socket` and `state_dir` (absolute paths). No member holds a secret. `fstp_control::route_feed::decode_feed_config` decodes it, fuzzed by `route_feed_decode` | ADR-026 "File"; CLAUDE.md fuzz rule |
| Credentials | `credentials_dir` holds, readable by the OS user of `fstp-control` only: `control-ca.pem`, the CA of the edges' client certificates (the pilot tunnel CA); `control.pem` and `control-key.pem`, the feed listener's certificate chain and key; `route-feed.key`, the sealed feed signing key | "Pilot tunnel CA" above |
| Feed signing key | Interim, pending Daniel. A composite key from `fstp_crypto::composite` (ML-DSA-65 with Ed25519, I-75, I-90, ADR-001). `fstp-control init-route-feed <out dir>` generates it and seals it under a fresh seal key `S(e)` with AES-256-GCM. `fstp-keyd` wraps `S(e)` under a root of the ControlPlane chain, epoch 1. The file has the layout of the witness receipt key file with the magic `fstp-route-feed-key-v1`, and its decoder is fuzzed. The command writes the public key as one hex line to `<out dir>/route-feed.pub`. The open key exists only in the memory of `fstp-control` | ADR-004 part 2; I-80; R-NF-08 |
| `fstp-keyd` socket | Interim, pending Daniel. `fstp-keyd` gains the client role `control`: socket `control.sock`, group variable `FSTP_KEYD_GROUP_CONTROL`, the ControlPlane chain only, and no sign key. The ControlPlane entry of a self-hosted witness stays an open point of `fstp-keyd` | ADR-004 part 2 "Access to `fstp-keyd`" |
| Table state | Interim, pending Daniel. The current signed table is the whole state: `<state_dir>/route-table.signed`. Each change is written there atomically before any edge can fetch it. At start `fstp-control` verifies the file under its own key with the edge's own decoder. A missing file, or one that does not verify, stops the start. `init-route-feed` writes the first, empty table when none exists | I-90; TH-48 |
| Versions | Interim, pending Daniel. A change takes the version `max(previous + 1, Unix time in milliseconds)`. So a table that `init-route-feed` writes again after a lost state still rises above every version an edge served, unless the host clock ran back | R-SW-02 |
| Operator command | Interim, pending Daniel. `fstp-control route add <route file>` and `fstp-control route remove <cell id>`. The route file has the grammar of the L9 route file ("Route file" above) with exactly one route. The command reaches the running process over `operator_socket`, a Unix socket of mode 0600, so only the OS user of `fstp-control` and root can use it. A local socket guarded by its file mode stands in for the operator passkey login and step-up of ADR-008 and ADR-011, which the pilot does not run | ADR-008; ADR-011 |
| Operator bytes | Interim, pending Daniel. One request per connection: `"FRO1"`, an operation byte (1 add, 2 remove), then for an add one route in the route grammar of the feed, and for a remove the 16-byte cell id. The reply is `"FRA1"`, a status byte (0 stored, 1 refused route, 2 failed) and the version as `u64`. The request decoder is fuzzed by `route_feed_decode`. Exit status 0 means the new version is stored and served, 2 a refused route, 1 any other failure | CLAUDE.md fuzz rule |
| Checks before signing | `fstp-control` builds each new table through `RouteTable::add_cell` and the pin rule before it signs. So it never signs a table that an edge refuses. An add for a cell that has a route replaces it, which is how a renewed tunnel certificate gets its new pin. A host held by another cell is refused | I-19; TH-48 |
| Feed bytes | Interim, pending Daniel. Version 2 of the bytes of ADR-004: magic `"FRT2"`, signature context `fstp-route-table-v2`. Each endpoint is followed by its 32-byte pin. Two endpoints never share a pin. Version 1 without pins is no longer read | I-19; B5 |
| Transport | One exchange per connection over mutual TLS 1.3 (`fstp_control::exchange`). The listener requires a client certificate that chains to `control-ca.pem`, whose one subject CN `edge_<32 hex digits>` names a configured edge. Any other peer gets no table. R-NF-09 is claimed for this link | R-NF-09; ADR-004 (2026-11-15 night) |
| How the edge pins the control plane | Interim, pending Daniel. Three checks. The feed public keys in `route-feed.pub` of the edge's credentials directory, one or two hex lines (the current and the next key), are the authority over routes. The TLS handshake verifies the chain to `tunnel-ca.pem` and the name `feed.server_name`. The SHA-256 of the control plane's end-entity certificate must equal `feed.cert_sha256`, so a certificate issued in error never answers a poll. A renewed feed certificate needs a new pin and an edge restart | I-90; I-74 |
| Edge configuration | The member `routes` is gone. `feed` is an object: `address`, `server_name`, `cert_sha256` (64 lowercase hex digits) and the optional `poll_seconds`. The edge's client certificate `tunnel.pem` carries the subject CN `edge_<32 hex digits>` that the feed configuration lists | ADR-026 "Members" |
| Poll interval | Interim, pending Daniel. The edge polls at start and then every `poll_seconds`, default 5, 1 to 60. One poll may take 10 seconds. Each poll reports the version the edge serves | R-SW-02 |
| Unreachable or refused feed | The edge keeps serving the last verified table. It never applies an unsigned or unverified table, and never falls back to a file. A refused table changes nothing. The edge logs a typed `Refused` event on the route template `/edge/route-feed` with the rule: `I-90` for a signature, `I-19` for a route rule or the encoding, `R-SW-02` for a rollback, `R-NF-09` for a failed exchange. No event names a host or an address | I-90; R-NF-02 |
| Rollback | A verified table whose version is lower than the one the edge serves is refused. A table of the same version changes nothing | R-SW-02; TH-48 |
| Start of the edge | The edge binds at once and serves no route until the first verified table arrives. Until then every connection closes as an unknown host | I-19 |
| Removed route | A connection whose ClientHello arrives after the edge applied a table without the route closes as an unknown host. A tunnel already open runs on until either end closes it or `lifetime_seconds` ends. The tunnel opener takes the pin from the table that is current when the tunnel opens, so a route removed between the hello and the open opens no tunnel | TH-48; I-19 |
| Static route file | Interim, pending Daniel. Removed as an input of the edge, not kept as a bootstrap. An unsigned initial table would be a second source of routes outside the version rule. An edge restarted while `fstp-control` is unreachable could then serve a route the control plane had removed, for example an erased cell's (TH-48). The cost: an edge that starts while `fstp-control` is down serves no route until it is back | TH-48; I-90 |
| Process | `fstp-control route-feed` runs one tokio runtime through `fstp-rt` (ADR-002). SIGTERM or SIGINT stops the listener, drains for 30 seconds and exits with status 0. A refused configuration or state exits with status 2, any other failure with status 1. Logs are typed events only | ADR-002; R-NF-02 |

Tests of this section, each named with its ID:

- `crates/fstp-edge/tests/route_feed.rs`: the version 2 bytes with pins, `r_sw_02_feed_rollback_is_refused_and_keeps_the_table`, `i90_tampered_or_foreign_feed_keeps_the_last_good_table` and `i19_feed_contents_follow_the_route_table_rules`.
- `crates/fstp-edge/tests/l15_feed_run.rs`: `i19_r_sw_02_feed_route_reaches_a_running_edge` and `th48_removed_route_closes_new_connections_and_lets_open_ones_finish`, through the real accept loop and the pinned opener.
- `crates/fstp-control/tests/r_sw_02_route_feed_pilot.rs`: the feed configuration, the key file, the persisted state and its resume, the operator socket, and `i19_publisher_never_signs_a_table_the_edge_refuses`.
- `crates/fstp-celltest/tests/i19_route_feed_e2e.rs`: the `fstp-control` and `fstp-edge` binaries in front of the `fstp-cell` binary. A route added by `fstp-control route add` reaches the running edge, a removal closes new connections while an open one finishes, and a restarted `fstp-control` resumes its version.

Open for Daniel, each interim until he answers:

- The operator socket guarded by its file mode, in place of a passkey login with step-up.
- The `control` role of `fstp-keyd` for the feed key.
- Versions from the clock, so a lost state recovers without an edge restart.
- No edge-side cache of the last signed table. An edge that starts while `fstp-control` is down serves no route. A signed cache would keep the version rule, at the cost of a writable state directory on the edge.
- The 5-second default poll interval.
- The pin on the control plane's certificate, which needs an edge restart when that certificate is renewed.
- No `route list` command yet. The operator sees the routes only in the route files they gave.

## Outbound destinations

Each process opens connections only through one closed enum. Its connector refuses every other address, and the host firewall holds the same list.

```rust
// fstp-cell
pub enum Destination {
    AppDatabase,                 // c_<cell> on its application cluster, one pool per role
    Vault,                       // its own vault, internal mTLS
    Custody,                     // its own App and CellBackup custody entries
    ControlPlane,                // SaaS only: CellToCp
    Witness,                     // App chain prepares, aborts and receipts
    CrabNebula(CnCall),          // self-hosted only, built only by fstp-release::egress (I-38)
    KeystoreSnapshots,           // proposed by ADR-012, pending Daniel: <cell>/keystore/ prefix only
}

// fstp-vault
pub enum VaultDestination {
    VaultDatabase,               // v_<cell> on its vault cluster
    Custody,                     // its own Vault custody entry, with its own credential
    Witness,                     // Vault chain prepares, aborts and receipts
    KeystoreSnapshots,           // proposed by ADR-012, pending Daniel: <cell>/keystore/ prefix only
}
```

- **Keystore snapshots.** Proposed by ADR-012 (Keystore snapshots), interim, pending Daniel. ADR-004 erasure step 5 needs each process to upload and fetch back its own keystore snapshot. Each `KeystoreSnapshots` member reaches object storage with a per-cell credential limited to `<cell>/keystore/` where the service allows it (ADR-005 V15). It allows `PutObject`, the multipart calls, `GetObject` and `HeadObject` only. No connector builds either member before Daniel accepts it.

- No variant reaches a payment service or names a platform account (I-16). `i16_cell_egress_has_no_payment_destination` enumerates `Destination`.
- `CrabNebula` accepts only the two `CnCall` variants of design section 10.1: the update check and the licence refresh. `i38_only_egress_reaches_crabnebula_hosts` checks that no other caller reaches those hosts.
- A SaaS cell never builds `CrabNebula`. A self-hosted cell never builds `ControlPlane`.
- A new variant needs an amendment of this ADR. Email in M6 and payment adapters in M5 each add theirs that way.
- **Vault documents.** Design sections 4.3 and 4.8 keep sealed identity documents in object storage, and `vault.document` holds a sealed object reference. B4a gives the vault no object storage connection. This conflict is an open point. Strict interim: no `VaultDestination` variant is added, and the vault stores sealed document bytes in its own database.

### Amendment: assessor egress (M7, accepted by Daniel on 2026-11-07)

Drafted 2026-11-06 by lane L-SEAM of `docs/handoff/m7-design.md` (section 3.1, Q1 and Q2), with ADR-019. Daniel accepted this amendment and ADR-019 on 2026-11-07, so connectors may build these members.

The assessor is a separate process, `fstp-assessor`, spawned by the cell. It has no database credential and no ledger access. It opens connections only through its own closed enum:

```rust
// fstp-assessor
pub enum AssessorDestination {
    Inference,                   // the tenant's P-21 endpoint from its inference record, POST only (ADR-019)
    Retrieval,                   // the retrieval proxy; the fixture server only in M7 (Q2)
}
```

- `Inference` reaches only the URL of the tenant's inference record. A self-hosted cell may name a local endpoint (R-LA-04).
- The TLS client trusts only the PEM anchors the inference record pins (Q2, interim). No public root store is added.
- No variant reaches a payment service, a CrabNebula host, the vault or a database (I-16, I-38).
- `Destination` of `fstp-cell` gains no member. Submission text reaches the assessor over the child's stdin, after PII stripping in the cell.
- R-NF-09 is not claimed for `Inference`. A hosted endpoint authenticates the cell by a bearer credential over server-authenticated TLS, as the other external links of the R-NF-09 table do.
- Tests, before the code: `i16_assessor_egress_has_no_payment_destination` enumerates `AssessorDestination`, and `b4_assessor_connector_refuses_every_address_outside_its_destination`.
- `TODO(legal)`: the inference provider as a sub-processor and the DPIA (`gdpr.md`) before a production tenant enables P-21.

## Vault origin

Answered (Q7 A). The vault origin is `https://id.<cell host>`, a web origin of the vault, separate from the application origin and inside the cell (`overview.md`).

- It serves three route groups only: `POST /w` (write), `POST /r` (release), and the static pages and scripts for those two.
- It keeps no sessions and sets no cookies. It accepts no request without a ticket.
- Each route has a body limit per ticket kind. The ticket signature is checked before any other field is used.
- Its decoders are fuzzed: `ticket_decode`, `origin_write_decode` and `fact_body_decode`.
- The write pages run same-origin scripts only. The cell origin's CSP has `form-action 'self'`, so no form on the cell origin posts to the vault origin.
- **Delivery.** The browser opens `https://id.<cell host>/w#<ticket>` or `/r#<ticket>`. The fragment never reaches a server log. A same-origin loader script reads it and posts it with the request body.
- **Release responses.** The vault renders released fields server-side, with `Content-Security-Policy: default-src 'none'` and `Cache-Control: no-store`. The document that shows released fields runs no script. Design section 11.2 says release pages allow no script, and this ADR reads that as the response document, not the loader.
- The application origin cannot read the vault origin (`i17-vault-origin-release.spec.ts`).

### Tickets

- **Format.** Canonical JSON `{kind, cell, account, proposal, scope, issued_at, expires_at, nonce}`, signed with Ed25519 by the cell's `Ticket` key.
- **Key.** The `Ticket` key sits under the App chain, purpose `Ticket`. It rotates yearly and on suspicion. The vault pins the current and the next public key at provisioning.
- **Lifetime.** At most 5 minutes. Interim, pending Daniel (Q37): an ADR constant with no P- id.
- **Single use.** The vault inserts the ticket id into `vault.ticket_used`. A second use violates the primary key and is refused.
- **Binding.** The vault refuses a ticket for another cell, an expired or future ticket, and a ticket whose kind does not match the route.
- **Logging.** Issuing any ticket is a ledger record in the cell (R-AU-01). The vault logs each use in its own chain.
- `i17_vault_refuses_forged_stale_replayed_or_foreign_tickets` checks these refusals.

### Write kinds

A write ticket admits one write of one kind. The cell receives only the resulting epoch change, through the change query. Every kind becomes effective under the NOTE 4 commit protocol. The kind names below are proposals, as the design's names are.

| Kind | Writer | Collected | Basis |
| --- | --- | --- | --- |
| `CountryStated` (P-17) | The applicant | At submission | `overview.md` NOTE 6, R-NG-01 |
| `AffiliationDeclared` | The applicant or team member | When declared | Design section 6.5 |
| `AdultAttestation` | The lead | From submission until NEGOTIATION | R-NG-01, R-ID-04, `overview.md` NOTE 7 (decided 2026-10-28). `TODO(legal)`: L-02 |
| `GuardianConsent` with the guardian's identity | The guardian, a Receiving account added by `AddGuardian` | At the IRC_REVIEW to NEGOTIATION gate | R-NG-01, R-NG-02 (decided 2026-10-28). `TODO(legal)`: L-02 |
| `DocumentUpload` | The account being verified | Before a manual check | P-18, P-19, R-ID-03 |
| `VerificationRecorded` | The recorder of ADR-008. For the first tenant admin, the platform operator with two staff (ADR-008, First tenant admin verification) | At a manual check | Q14, `roles-and-sod.md` Manual identity checks. Release window as ADR-008 sets it for tenant recorders |
| `ProximityListDeclared` | The programme manager, with a step-up, for a partner | At programme start | Interim, pending Daniel (Q31) |
| `ReviewerDeclaration` | The Judging-role holder | At binding time | Interim, pending Daniel (Q31). `TODO(legal)`: the basis for storing reviewers' relatives. No L- item yet; listed for Daniel in `SPEC/10-open-questions.md` (Legal checks awaiting an L- number) |
| `PartnerStaffDeclared` | The person | At binding or verification | Interim, pending Daniel (Q31) |

- `RecordRelationship` (I-54) is not a browser write. The cell sends it over internal mTLS, with account ids only. It carries no identity attribute (`overview.md`).
- Phone numbers and messaging handles have no write or release kind until M8. They go only to channel adapters.

### Releases

- `release::issue_ticket` issues a release ticket only to an Operations role holder of the programme, for a proposal in NEGOTIATION or later (I-17, `overview.md`). Issuing it appends `IdentityReleaseIssued`.
- **Second guard.** The vault refuses a release unless its own negotiation fact lists the subject. The cell pushes that fact when NEGOTIATION opens.
- A download is the high-risk action `IdentityDownload` (ADR-008).
- Record, lane m3/cell-routes, 2026-11-15 (interim, pending Daniel): the cell's `POST /api/v1/vault-tickets` commits the issue record, then signs the ticket of that record with its `Ticket` key and answers `{expires_at, kind, ticket, url}`. `url` is `https://id.<cell host>/r#<ticket>` for a release and `.../w#<ticket>` for a write.
  - The claims come from the ledger record, never from the request. The nonce is the record's ticket id, so a retry under the same command id signs a ticket the vault still admits once. A ticket lives for the five-minute bound.
  - A release names the proposal's lead as its subject and the proposal's programme as its scope. The request names no subject, so only the lead's identity is released. Releasing a team member or a guardian needs a subject member and a rule for it. Daniel decided on 2026-11-15 to keep the release to the lead for now. The coordinator unmask (ADR-023) covers the other parties.
  - A write ticket names its holder as the writer, the proposal and the programme scope. `decide` issues only the guardian consent write today, so every other write kind and `/api/v1/verifications` are refused before any ticket exists.
  - A download answers 501 after the gate and before the engine: the vault has no ticket kind for the download scope yet.

## Metadata register

Answered (Q36 A). Tenant data is content, accounts, identity attributes and anything derived from them. The only exception is an entry in the closed register `fstp_cp_proto::METADATA_REGISTER`. Each entry has a closed type, a destination and its coarsest useful form.

| Entry | Destination | Form |
| --- | --- | --- |
| Heartbeat product version | Control plane | `ProductVersion`, a closed grammar |
| Heartbeat health | Control plane | `Health`, a closed enum with no free text |
| Metering counters | Control plane | `(CounterKind, u64)` counts per day |
| Edge connection metadata | Edge logs | Cell id and host. Byte counts and timings bucketed to powers of two |
| Operator metrics | Shared metric sink | Metric names from a closed enum, values labelled by cell id only |
| Anchor fields | Witness | `cell`, `chain`, `n`, `link`, `at` and the signature. `link` is a SHA-256 value over sealed rows |

- `n` and `at` show the witness how often and when a chain grows. They are signed, so they cannot be coarsened. This ADR records that disclosure for Daniel.
- **Infrastructure fields.** `RoleCredential`, `CertRenewal`, `CpToCell` messages, operator tickets and break-glass requests carry certificates, SPKI digests, SCRAM verifiers, opaque case references and closed enums. None is derived from tenant data. Proposed: the register lists them in a second class, `Infrastructure`. `i19_only_registered_metadata_crosses` can then check every capture against the register.
- The same class would also cover the `cp` records that are not register entries today: staff records, job records, operator-ticket records, and the base backup records of ADR-012. Daniel has not settled this class. Until he does, the ADR-005 amendment does not claim that `cp` holds only registered metadata.
- Canaries cannot see metadata, so `i19_only_registered_metadata_crosses` carries this part of I-19. `i19_cp_proto_fields_are_declared` and `i19_control_plane_columns_are_declared` pin the types and columns.
- A new entry needs an amendment of this ADR.

## R-NF-09 reading

Interim, pending Daniel (Q34). R-NF-09 is read as covering links between platform components. Links to external services are authenticated by request credentials instead. Until Daniel accepts a wording for R-NF-09, M3 claims it for internal links only.

| Link | Authentication | R-NF-09 claim |
| --- | --- | --- |
| Edge to cell and edge to vault origin | mTLS tunnel | Claimed |
| Cell to vault | mTLS, cell CA | Claimed |
| Cell and vault to their databases | TLS verify-full plus client certificate and SCRAM (ADR-005) | Claimed |
| Cell and vault to the witness | mTLS, chain-bound certificates | Claimed |
| Cell to control plane, `fstp-control` to `fstp-pgagent` | mTLS, control-plane CA | Claimed |
| Edge to `fstp-control`, the route feed (lane L15) | mTLS, control-plane CA, the operator's tunnel CA on the pilot | Claimed |
| `fstp-control` to the witness, for restore declarations | mTLS, control-plane CA (ADR-012, interim, pending Daniel) | Claimed once ADR-012's proposal is accepted |
| Cell and vault to object storage, for keystore snapshots | SigV4 over server-authenticated TLS (ADR-012, interim, pending Daniel) | Not claimed. Request credentials only |
| Cell and vault to OKMS | Access certificate over mutual TLS on REST (Q11 A), otherwise KMIP with certificates (Q11 B) | Claimed once the verify item is settled. Whether REST accepts an access certificate as mutual TLS is a question to OVHcloud |
| Control plane to its managed databases | SCRAM over server-authenticated TLS (Q3 C) | Not claimed. Request credentials only |
| `fstp-backup` to object storage | SigV4 over server-authenticated TLS | Not claimed. Request credentials only |
| Witness to its second-provider bucket | Provider request credentials over server-authenticated TLS | Not claimed. Request credentials only |
| Self-hosted cell to the licence service | Licence id and the signed token it refreshes | Not claimed |
| Self-hosted cell to the update service | Anonymous by design | Not claimed |

- Browser traffic is user traffic, not a link between components. Users authenticate through ADR-008.
- ADR-005 D2 speaks of database connections "from a cell component". The control-plane databases fall outside that wording, and the ADR-005 amendment records the provider's operator role over them.

## Root on cell hosts

Answered (Q35). On 2026-10-28 Daniel accepted the recommendation: option A in M3, with confidential computing evaluated in L-15.

- A person with root on a cell or vault host can read unwrapped group keys from process memory (risk R16). Sandboxing and swap-off do not stop root.
- Mitigation in M3: separate host-administration staff with no control-plane rights, and no standing root. Root comes from short-lived SSH certificates issued per case with two-person approval. Sessions are recorded, and host access events are shown to the tenant.
- Confidential computing is evaluated with L-15. Its availability at OVHcloud is not checked, so it is a question on the verify list.

## Consequences

- Identity attributes never enter the application, so the I-17 storage check is a check for absence.
- The vault becomes reachable from browsers through the edge (risk R13). Three route groups, no sessions, tickets checked first and fuzzed decoders bound that surface.
- Every outbound connection is visible in two closed enums, which the I-16, I-19 and I-38 tests enumerate.
- The control plane and witness see only registered metadata and infrastructure fields.
- Several external links rest on request credentials, not on mutual TLS, until Daniel settles Q34.

## Tests

Each test names its ID, as `.claude/CLAUDE.md` requires. Design section 14.4 lists them in full.

- I-17: `i17_canary_attributes_never_reach_judging_responses`, `i17_app_database_holds_no_identity_attribute`, `i17_release_ticket_only_for_operations_in_negotiation`, `i17_vault_refuses_release_without_negotiation_fact`, `i17_vault_refuses_forged_stale_replayed_or_foreign_tickets`, `i17_logs_and_metrics_hold_no_attribute`, Playwright `i17-vault-origin-release.spec.ts`, and the teeth tests.
- I-19: `t_iso_i19_no_canary_crosses_a_cell_boundary`, `i19_control_plane_columns_are_declared`, `i19_cp_proto_fields_are_declared`, `i19_edge_forwards_bytes_after_client_hello_unchanged`, `i19_foreign_cell_certificates_are_refused`, `i19_session_of_one_cell_is_refused_by_another`, `i19_cell_process_serves_one_cell`, `i19_only_registered_metadata_crosses`, and the teeth tests.
- I-20: `t_iso_i20_no_shared_identifier_across_tenants`, `i20_control_plane_and_witness_hold_no_account_id`, `i20_vault_match_keys_differ_across_cells`.
- I-16: `i16_cell_egress_has_no_payment_destination`.
- I-38: `i38_only_egress_reaches_crabnebula_hosts`.
- New with this ADR, to be written before the code they constrain:
  - `b4a_vault_connector_refuses_every_address_outside_vault_destination`;
  - `i17_release_response_document_runs_no_script`;
  - `r_nf_09_every_internal_link_requires_a_client_certificate`.

## Open points

- **Vault documents.** Object storage for sealed documents (design sections 4.3, 4.8) against B4a. Option A: documents in the vault database, as the strict interim. Option B: a `VaultDestination::DocumentStore` variant with a vault-only prefix and its own credential.
- **Self-hosted issuers.** The design names no issuer for the local edge's tunnel certificate or the local witness's server certificate. One option is an install-time CA in local custody, kept apart from the cell CA. Daniel decides before ADR-011 fixes the install.
- **Root on hosts.** Settled by Daniel on 2026-10-28 (Q35 A). Confidential computing stays an L-15 evaluation item.
- **Legal markers.** Two `TODO(legal)` markers in this ADR have no L- number: rate limiting on client addresses, and storing reviewers' relatives. Both are listed in `SPEC/10-open-questions.md` for Daniel to number.
- **Keystore snapshot destinations.** The two `KeystoreSnapshots` members proposed by ADR-012, and `fstp-control` as a witness client for restore declarations. Both wait for Daniel with ADR-012.
- **Assessor egress.** The `AssessorDestination` members of ADR-019 for M7. Accepted by Daniel on 2026-11-07.
- **Q34 wording.** A wording proposal for R-NF-09 is with Daniel (Q28).
- **OVHcloud verify items.** Whether OKMS REST accepts an access certificate as mutual TLS. Whether the Public Cloud Load Balancer's TCP listener forwards the ClientHello unchanged and can pass the client address. Whether OVHcloud offers confidential computing for cell and vault hosts. None of these is assumed here.

## Record

| Item | Value | Recorded |
| --- | --- | --- |
| Third-party crates added by this ADR | None | 2026-10-28 |
| Tunnel header layout and `TUNNEL_HEADER_LEN` | Version 1, 274 bytes, with the routed host ("Edge and tunnel") | Recorded 2026-10-29 (lane W2i); host field kept by Daniel |
| `METADATA_REGISTER` entries as built | Record at first use | Record at first use |

## Decided by Daniel, 2026-11-15 (late)

These interim readings are accepted as decided: Q37 (vault ticket lifetime at most 5 minutes, an ADR constant), Q26 (an application host and a vault host per cell in SaaS, one node when self-hosted), Q30 (per-cell keys, production issuance through an in-house, fuzzed ACME client), Q34 (R-NF-09 claimed for links between platform components) and Q19 (client addresses in memory only, for rate limits). The `TODO(legal)` on the basis for Q19 stays.

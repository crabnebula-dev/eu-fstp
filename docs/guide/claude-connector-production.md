# Connect Claude to a production cell

This guide is for two readers. Sections 1 to 5 are for the operator who runs the cell and its edge. Sections 6 to 8 are for a programme manager who connects Claude to it.

**A pilot is not a release.** Daniel decided on 2026-11-20 that a clearly labelled pilot may have real users, since moduletto is confirmed for release. A release still needs the Mythos confirmation of the Tier B formats crates `der`, `spki`, `x509-cert` and `cms` (I-74), and the legal wording marked `TODO(legal)`. Label every pilot cell as a pilot to its users. `deps-check --release` fails on such a build.

The design is in `docs/handoff/production-mcp-design.md`. The configuration is ADR-026 "Configuration". The key file is ADR-004, record of lane L4. The vault's configuration and keystore are the records of lane L8 in ADR-026 and ADR-004. The MCP and OAuth profile is ADR-013. The demo cell has its own guide, `docs/guide/claude-connector-demo.md`.

## 1. What the operator supplies

The pilot is one host in SaaS mode, with `fstp-keyd` custody and no control plane link (D1). R-KY-01 is not claimed. The operator supplies:

- **Host.** A Linux host in the EU. The `fstp-keyd` volumes sit on ext4 or XFS (I-81).
- **DNS.** A tenant domain, for example `grants.example.eu`, pointing at the edge.
- **Public TLS.** An origin certificate for that domain from a public CA. Browsers and claude.ai need it. WebAuthn needs `https` with no port.
- **PostgreSQL.** An application cluster and a vault cluster, each with a server certificate whose OU names its kind. Each login role has its own client certificate and password (I-82, I-83). The SPKI digests of the clusters go into `registered_servers`.
- **Custody.** Two `fstp-keyd` entries for the cell, and one for the vault (section 3a). Each has its own socket and passphrase as a systemd credential. One serves the cell's App chain. The other holds only the dedicated root of the cell key file. The cell refuses to start when both name the same socket.
- **Witness.** `fstp-witness` from its own configuration, with the cell CA and the cell's anchor public key registered.
- **Vault.** The `fstp-vault` binary, with its own configuration, keystore and custody entry. It pins the cell's ticket public key (section 3a).
- **Edge.** The `fstp-edge` binary, which routes the tenant domain to the cell's tunnel listener by SNI. Section 5 sets it up.
- **Mail.** An account on a submission relay for proof mail: sign-up proofs, magic links and recovery proofs (D3). A tenant's own relay replaces it once the tenant sets one (ADR-018).
- **Backups.** Object storage under ADR-012. The S3 client of `fstp-backup` is still a stub.
- **claude.ai.** A claude.ai plan that allows custom connectors, if staff use claude.ai. The claude.ai trace of D9 is still open, so claude.ai is not yet verified against a production cell.

## 2. Configure the cell

The cell reads one JSON file, named by `FSTP_CELL_CONFIG`. It holds no secret. Every member is checked, and an unknown member is refused.

```json
{
  "assets_dir": "/opt/fstp/web",
  "cell": "<32 lowercase hex digits>",
  "credentials_dir": "/etc/fstp/cell",
  "database": {"dbname": "c_<the same 32 hex digits>", "host": "db.internal", "port": 5432},
  "host": "grants.example.eu",
  "key_file_keyd_socket": "/run/fstp-keyd/cell-keys.sock",
  "keyd_socket": "/run/fstp-keyd/cell.sock",
  "listen": {"health": "127.0.0.1:9090", "internal": "0.0.0.0:7444", "tunnel": "0.0.0.0:7443"},
  "mail": {"relay": "smtp.example.eu", "sender": "noreply@grants.example.eu", "username": "cell"},
  "mode": "saas",
  "organisation_active": true,
  "registered_servers": [{"kind": "application", "spki_sha256": "<64 hex digits>"},
                         {"kind": "vault", "spki_sha256": "<64 hex digits>"}],
  "vault": {"address": "10.0.0.6:7445"},
  "version": "0.3.0",
  "witness": {"address": "10.0.0.5:7443", "ca_spki_sha256": "<64 hex digits>", "server_name": "witness.internal"}
}
```

Notes on the members:

- `database.dbname` must be `c_` followed by the cell id. The cell logs in as `<dbname>_writer`, `<dbname>_app` and `<dbname>_keys`.
- `listen.health` must be a loopback address.
- `assets_dir` holds `auth/` (the compiled auth pages, with `shell.html` and the stylesheets beside them) and `app/` (the packed journey UI with its `asset-manifest.json`). Without it, the cell serves the API, `/mcp` and the OAuth endpoints with an empty `/app` page and no sign-in pages.
- `mail.address` may pin the relay's socket address in place of a DNS lookup. Interim, pending Daniel: the public address and port 465 rules of ADR-018 then do not apply. Leave it out for a public relay.
- `organisation_active` is an interim reading, pending Daniel. A pilot cell records no tenant provisioning, since no control plane runs. Without this member, the ADR-021 gate refuses every programme operation, so no draft can be prepared.

The credentials directory holds these files, readable by the cell's OS user only:

| File | Holds |
| --- | --- |
| `db-ca.pem` | The CA of the application cluster's server certificate |
| `writer.pem`, `writer.key`, `writer.password` | The writer login |
| `app.pem`, `app.key`, `app.password` | The app login |
| `keys.pem`, `keys.key`, `keys.password` | The keystore login |
| `tunnel.pem`, `tunnel.key`, `tunnel-ca.pem` | The tunnel listener's certificate, and the CA of the edge's client certificate |
| `origin.pem`, `origin.key` | The public origin certificate of `host` |
| `internal.pem`, `internal.key`, `cell-ca.pem` | The internal listener and the cell CA |
| `witness.pem`, `witness.key`, `witness-ca.pem` | The cell's witness client certificate and the witness CA |
| `witness-receipt-keys` | The witness receipt public keys, one lowercase hex line each |
| `vault.pem`, `vault.key`, `vault-ca.pem` | The cell's vault client certificate and the vault's CA |
| `cell-keys.sealed` | The sealed cell key file, made by `fstp-cell init-keys` |
| `mail.password` | The relay password, with `mail` |
| `mail-ca.pem` | Optional: a pinned CA of the relay, beside the public roots |

## 3. Start the cell

Create the key file once, at genesis. The command creates the dedicated root in the key file's custody entry, seals the cell's keys under it, and writes two public keys into the directory you name:

```sh
FSTP_CELL_CONFIG=/etc/fstp/cell.json fstp-cell init-keys /root/cell-public
```

- `anchor.pub` is the composite anchor public key. Register it with the witness for the App chain.
- `ticket.pub` is the ticket public key. The vault pins it.

The command refuses to overwrite an existing key file. Never delete that file: it holds every ledger key generation, and the cell cannot read its ledger without it.

Then start the cell, for example as a systemd service:

```sh
FSTP_CELL_CONFIG=/etc/fstp/cell.json fstp-cell
```

Each start opens the key file through its custody entry, draws a new ledger key generation, and rewrites the file before it seals anything. The first start on an empty database creates the keystore. The cell is ready when `GET /healthz` on the health listener answers 200. SIGTERM drains it. A refused configuration exits with status 2, and any other failure with status 1. Log lines name a rule, never a secret.

## 3a. Configure and start the vault

The vault runs as its own binary, `fstp-vault`, in its own process under its own OS user. It never shares a process or a database with the cell (R-NG-01, I-83). The configuration is ADR-026, record of lane L8. The keystore is ADR-004, record of lane L8.

The vault needs, beside the cell's parts:

- **Database.** The vault database `v_<cell id>` on the vault cluster. The vault logs in as `<dbname>_vault` to serve and as `<dbname>_keys` for its keystore. Both connections refuse a server whose certificate OU is not `vault` or whose SPKI is not registered for a vault cluster.
- **Custody.** A third `fstp-keyd` entry, with a socket of the `vault` client role. That role reaches the Vault chain only. Never point the vault at a cell socket.
- **Certificates.** An internal server certificate from the cell CA, which names the vault's internal address. A `vault-witness` client certificate from the cell CA, for the witness. A tunnel certificate for the edge, and the public origin certificate of `id.<host>`.

The vault reads one file, named by `FSTP_VAULT_CONFIG`. It holds no secret. It must be the canonical JSON form: members in key order, no spaces, on one line. One trailing line break is allowed. Every member is checked, and an unknown member is refused. Shown here with line breaks for reading only:

```json
{"cell":"<32 lowercase hex digits>",
 "credentials_dir":"/etc/fstp/vault",
 "database":{"dbname":"v_<the same 32 hex digits>","host":"vdb.internal","port":5432},
 "internal_listen":"10.0.0.6:7445",
 "keyd_socket":"/run/fstp-keyd/vault.sock",
 "origin_host":"id.grants.example.eu",
 "origin_listen":"10.0.0.6:7446",
 "registered_servers":[{"kind":"application","spki_sha256":"<64 hex digits>"},{"kind":"vault","spki_sha256":"<64 hex digits>"}],
 "ticket_keys":["<the 64 hex digits of the cell's ticket.pub>"],
 "witness":{"address":"10.0.0.5:7443","ca_spki_sha256":"<64 hex digits>","receipt_keys":["<hex>"],"server_name":"witness.internal"}}
```

Notes on the members:

- `database.dbname` must be `v_` followed by the cell id. A cell database is refused before any connection.
- `internal_listen` is the address the cell's `vault.address` names. Only the cell's `cell-app` certificate reaches it.
- `origin_listen` is the tunnel listener the edge routes `id.<host>` to.
- `ticket_keys` holds one to four keys. Put the cell's `ticket.pub` here. Add the next key before the cell rotates it.
- `witness.receipt_keys` holds the witness receipt public keys, the same keys as the cell's `witness-receipt-keys` file.

The credentials directory holds these files, readable by the vault's OS user only:

| File | Holds |
| --- | --- |
| `db-ca.pem` | The CA of the vault cluster's server certificate |
| `vault.pem`, `vault.key`, `vault.password` | The `<dbname>_vault` login |
| `keys.pem`, `keys.key`, `keys.password` | The `<dbname>_keys` login |
| `internal.pem`, `internal.key`, `cell-ca.pem` | The internal listener and the cell CA, the only client root |
| `tunnel.pem`, `tunnel.key`, `tunnel-ca.pem` | The tunnel listener's certificate, and the CA of the edge's client certificate |
| `origin.pem`, `origin.key` | The public origin certificate of `origin_host` |
| `witness.pem`, `witness.key`, `witness-ca.pem` | The vault's `vault-witness` client certificate and the witness CA |

Create the keystore once, at genesis, after `fstp-cell init-keys` wrote `ticket.pub`:

```sh
FSTP_VAULT_CONFIG=/etc/fstp/vault.json fstp-vault init-keys /root/vault-public
```

The command checks the database first, as the start does. It creates the root in the vault's custody entry and writes the keystore rows in one transaction. It refuses a keystore that exists. It writes `anchor.pub`, the Vault chain anchor public key. Register it with the witness for the Vault chain, beside the cell's `anchor.pub` for the App chain.

Then start the vault before the cell:

```sh
FSTP_VAULT_CONFIG=/etc/fstp/vault.json fstp-vault
```

Each start runs the database check, opens the keystore through its custody entry, and verifies the vault chain at the witness before it listens. A start never creates a keystore. SIGTERM drains the vault within 20 seconds. A refused configuration exits with status 2, and any other failure with status 1. Log lines name a rule, never a secret.

The vault does not yet rotate its keys when an identity is erased (ADR-004, record of lane L8, row "Not built"). Do not erase identities on a pilot vault until that is built.

## 4. Create the first admin

Stop the cell first. Then run:

```sh
FSTP_CELL_CONFIG=/etc/fstp/cell.json fstp-cell first-admin /root/first-admin.token
```

The command starts the cell with its listeners on loopback, records the first admin's invitation, and writes the token once to the new file, with mode 0600 (D4). On a SaaS cell the file holds two lines, one for each half. Hand each half to the first admin through a different staff channel. The command refuses an existing file, and a cell whose first admin is already invited or enrolled. Start the cell again afterwards.

The first admin opens `https://<host>/auth/invite#<first half><second half>` and enrols a passkey. The first admin then invites the other staff from the platform.

The first admin has no login email after this step, so recovery by email does not apply to that account. A second tenant admin can approve its recovery.

## 5. Run the edge

The edge is the only public listener. It reads the SNI of each browser's ClientHello and passes the whole TLS connection through to the cell's tunnel listener. It never terminates the browser's TLS and holds no origin key: the cell does, with `origin.pem` and `origin.key`. The grammar is ADR-009 "Pilot edge configuration". A pilot edge reads its routes from a file, since no control plane runs.

**Public origin.** The cell's origin is `https://<host>`, with no port. WebAuthn and claude.ai need exactly that. So:

- the DNS name `host` of the cell configuration resolves to the edge's host;
- that address accepts TCP port 443. Either the edge listens on port 443 itself, or a TCP forwarder in front passes the ClientHello byte for byte;
- the route file names the same `host`, in lowercase, as the cell configuration. The cell refuses a tunnel for any other host.

**Tunnel CA.** A pilot has no control-plane CA, so you run your own tunnel CA. Keep it apart from the cell CA and from the public origin CA. It issues three certificates:

- the edge's client certificate (client authentication);
- the cell's tunnel server certificate, `tunnel.pem` of the cell, for a server name such as `cell.tunnel.internal`;
- the vault's tunnel server certificate, for its own server name.

Put the tunnel CA's certificate into the cell's credentials directory as `tunnel-ca.pem`, and into the edge's as well. In each process, `tunnel-ca.pem` is the CA of the peer's tunnel certificate.

**Credentials directory**, readable by the edge's OS user only:

| File | Holds |
| --- | --- |
| `tunnel.pem`, `tunnel.key` | The edge's tunnel client certificate chain and key |
| `tunnel-ca.pem` | The tunnel CA, which issued the cell's and the vault's tunnel server certificates |

**Pins.** The edge pins each tunnel server's certificate. A pin is the SHA-256 of the certificate in DER, as 64 lowercase hex digits:

```sh
openssl x509 -in tunnel.pem -outform der | sha256sum
```

When you renew a tunnel certificate, update its pin in the route file and restart the edge.

**Route file**, for example `/etc/fstp/edge-routes.json`. One route per cell. `host` routes to `app`, the cell's tunnel listener (`listen.tunnel` of the cell). `id.<host>` routes to `vault`, the vault's tunnel listener for the vault origin.

```json
{"routes": [
  {"cell": "<the cell id, 32 lowercase hex digits>",
   "host": "grants.example.eu",
   "app":   {"address": "10.0.0.4:7443", "server_name": "cell.tunnel.internal",
             "cert_sha256": "<64 hex digits>"},
   "vault": {"address": "10.0.0.6:7446", "server_name": "vault.tunnel.internal",
             "cert_sha256": "<64 hex digits>"}}
]}
```

The edge refuses a host, a cell or a tunnel address given twice, a cell whose two endpoints share an address, and two endpoints with one pin.

**Configuration**, named by `FSTP_EDGE_CONFIG`. It holds no secret. `limits` and each of its members are optional; the values below are the defaults.

```json
{
  "credentials_dir": "/etc/fstp/edge",
  "limits": {"connections": 1024, "per_client": 64, "hello_seconds": 10,
             "open_seconds": 10, "lifetime_seconds": 7200},
  "listen": {"public": "0.0.0.0:443"},
  "routes": "/etc/fstp/edge-routes.json"
}
```

- `connections` caps open connections, and `per_client` caps them per client IP address. The address stays in memory and is never logged.
- `hello_seconds` bounds the wait for the ClientHello, `open_seconds` the tunnel handshake and pin check, and `lifetime_seconds` one connection.

**Start** it, for example as a systemd service with the capability to bind port 443:

```sh
FSTP_EDGE_CONFIG=/etc/fstp/edge.json fstp-edge
```

The edge logs `Started` once it listens. SIGTERM stops it from accepting, gives open connections 20 seconds, and exits with status 0. A refused configuration, route file or credential exits with status 2, any other failure with status 1. A change of the route file needs a restart.

**Check** it from outside, with the public CA your browsers trust:

```sh
curl https://grants.example.eu/.well-known/oauth-protected-resource/mcp
```

The answer names `"resource": "https://grants.example.eu/mcp"`, with no port. A host the route file does not name gets no answer at all: the edge closes the connection.

## 6. Install the plugin (programme manager)

You need an account on the cell with a programme staff or tenant admin role, and a passkey. Your operator gives you the cell's MCP URL, `https://<cell domain>/mcp`.

In Claude Code:

```sh
claude plugin marketplace add crabnebula-dev/eu-fstp
claude plugin install fstp-programmes@eu-fstp
```

Claude Code asks for the cell MCP URL when you enable the plugin. The plugin is in `integrations/claude/fstp-programmes/` of the repository. Its `programme-setup` skill guides Claude through programme setup.

On claude.ai, add a custom connector with the same URL, and upload the skill as `integrations/claude/fstp-programmes/README.md` describes.

## 7. Connect and approve

In Claude Code, run `/mcp`, choose `fstp` and sign in. Your browser opens the cell's consent page. It shows the agent's name as unverified text, the host the browser returns to, and each permission in plain words.

Sign in with your passkey if the page asks. Choose **Approve**. The cell asks for a passkey step-up, since connecting an agent links a new device. A magic-link session cannot approve.

## 8. Work with Claude and confirm in the platform

Ask Claude, for example: "Set up a new programme draft called Green Valleys 2027". Claude prepares the draft. Nothing changes until you confirm.

Each `fstp_prepare_*` tool leaves a pending action with a path such as `/app/pending/<id>`. Open it in the platform and confirm it. A high-risk action asks for a fresh passkey step-up. Each action can be confirmed once. Pending actions survive a restart of the cell.

Access tokens live 10 minutes. Claude refreshes them while your grant lasts, also across a restart of the cell. When you recover your account, every agent grant of your account ends at once (I-79). Connect Claude again afterwards with your new passkey. To end Claude's access yourself, run `claude mcp logout fstp`, or remove the claude.ai connector.

## Checked by

`crates/fstp-celltest/tests/prod_mcp_e2e.rs` runs sections 3, 4, 7 and 8 against the `fstp-cell` binary over local PostgreSQL. `crates/fstp-celltest/tests/g12_vault_run_e2e.rs` runs section 3a: the `fstp-vault` binary from its file beside the `fstp-cell` binary, with a restart of the vault and a vault answer that reaches the cell. `crates/fstp-celltest/tests/i19_edge_binary_e2e.rs` runs section 5: the `fstp-edge` binary from its files in front of that binary. `tools/devstack/run.sh external-cell` starts the same stack for a manual check with Claude Code.

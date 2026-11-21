# Connect Claude to a production cell

This guide is for two readers. Sections 1 to 5 are for the operator who runs the cell and its edge. Sections 6 to 8 are for a programme manager who connects Claude to it.

**A pilot is not a release.** Daniel decided on 2026-11-20 that a clearly labelled pilot may have real users, since moduletto is confirmed for release. A release still needs the Mythos confirmation of the Tier B formats crates `der`, `spki`, `x509-cert` and `cms` (I-74), and the legal wording marked `TODO(legal)`. Label every pilot cell as a pilot to its users. `deps-check --release` fails on such a build.

The design is in `docs/handoff/production-mcp-design.md`. The configuration is ADR-026 "Configuration". The key file is ADR-004, record of lane L4. The vault's configuration and keystore are the records of lane L8 in ADR-026 and ADR-004. The MCP and OAuth profile is ADR-013. The demo cell has its own guide, `docs/guide/claude-connector-demo.md`.

## 1. What the operator supplies

The pilot is one host in SaaS mode, with `fstp-keyd` custody and no control plane link from the cell (D1). A minimal `fstp-control` serves only the edge's route feed (section 5). R-KY-01 is not claimed. The operator supplies:

- **Host.** A Linux host in the EU. The `fstp-keyd` volumes sit on ext4 or XFS (I-81).
- **DNS.** A tenant domain, for example `grants.example.eu`, pointing at the edge.
- **Public TLS.** An origin certificate for that domain from a public CA. Browsers and claude.ai need it. WebAuthn needs `https` with no port.
- **PostgreSQL.** An application cluster and a vault cluster, each with a server certificate whose OU names its kind. Each login role has its own client certificate and password (I-82, I-83). The SPKI digests of the clusters go into `registered_servers`.
- **Custody.** Two `fstp-keyd` entries for the cell, and one for the vault (section 3a). Each has its own socket and passphrase as a systemd credential. One serves the cell's App chain. The other holds only the dedicated root of the cell key file. The cell refuses to start when both name the same socket.
- **Witness.** `fstp-witness` from its own configuration, with the cell CA and the cell's anchor public key registered.
- **Vault.** The `fstp-vault` binary, with its own configuration, keystore and custody entry. It pins the cell's ticket public key (section 3a).
- **Edge.** The `fstp-edge` binary, which routes the tenant domain to the cell's tunnel listener by SNI, and the `fstp-control` binary, which serves it a signed route feed. Section 5 sets both up.
- **Mail.** An account on a submission relay for proof mail: sign-up proofs, magic links and recovery proofs (D3). A tenant's own relay replaces it once the tenant sets one (ADR-018).
- **Backups.** Object storage under ADR-012, and `fstp-backup` per self-operated cluster. The section "Backups and restore (operator)" sets it up.
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

### Erase an identity

An identity erasure rotates the Vault chain once (design section 3.5, ADR-004 record of lane L11). It erases the identity's attribute tuple and makes its match key unlinkable, in the live store and in every backup (I-81, G24). It does not erase the facts the vault holds under its `Fact` data key, or anything in the cell.

Stop the vault first. The running vault holds a lock on its keystore, and the command refuses while it does. Then run, with the account id from the cell as 32 hex digits or in the UUID form:

```sh
systemctl stop fstp-vault
FSTP_VAULT_CONFIG=/etc/fstp/vault.json fstp-vault erase-identity 01234567-89ab-cdef-0123-456789abcdef
systemctl start fstp-vault
```

The service name is your own. What the operator sees:

- The command runs the same database check as a start, and needs the vault's `fstp-keyd` entry and the witness. It writes no output.
- Exit status 0 means the batch is complete. The old root epoch is destroyed in custody, its `keystore.root` row is marked destroyed with the receipt, and the Vault chain holds one entry with `KeyEpochDestroyed` and `IdentityErased`. Each erasure raises the epoch by one.
- Exit status 2 means the argument was refused. Status 1 means another failure: the vault still runs, the account has no identity, the identity has no stored attribute tuple, or custody, the database or the witness failed.
- A failure after the request is not lost. The request is stored, and the next start of the vault, or the next run of the command, completes the batch before anything else. Until then the tuple is refused for open.
- The live identities keep their ids. Their match keys move to the new `Match` key, and the query digest key changes with it.

An identity whose attribute tuple the vault never stored cannot be erased this way, and the command refuses it with status 1. No route of the vault registers identities with their tuples yet (ADR-004 record of lane L11, row "Not built"), so a pilot vault holds no erasable identity until the recorder route of ADR-008 exists.

## 4. Create the first admin

Stop the cell first. Then run:

```sh
FSTP_CELL_CONFIG=/etc/fstp/cell.json fstp-cell first-admin /root/first-admin.token
```

The command starts the cell with its listeners on loopback, records the first admin's invitation, and writes the token once to the new file, with mode 0600 (D4). On a SaaS cell the file holds two lines, one for each half. Hand each half to the first admin through a different staff channel. The command refuses an existing file, and a cell whose first admin is already invited or enrolled. Start the cell again afterwards.

The first admin opens `https://<host>/auth/invite#<first half><second half>` and enrols a passkey. The first admin then invites the other staff from the platform.

The first admin has no login email after this step, so recovery by email does not apply to that account. A second tenant admin can approve its recovery.

## 5. Run the edge

The edge is the only public listener. It reads the SNI of each browser's ClientHello and passes the whole TLS connection through to the cell's tunnel listener. It never terminates the browser's TLS and holds no origin key: the cell does, with `origin.pem` and `origin.key`. The grammar is ADR-009 "Pilot edge configuration" and "Pilot route feed".

The edge reads no route file. A minimal `fstp-control` serves a signed route feed, and the edge polls it. You propose a route change with an `fstp-control` command, and a staff member approves it with a passkey step-up on the operator page of `fstp-control`. The edge then follows without a restart. Daniel decided this design on 2026-11-21. The pilot `fstp-control` runs the feed, the operator page and nothing else: no cell link, no `cp` database, no provisioning and no erasure.

**Public origin.** The cell's origin is `https://<host>`, with no port. WebAuthn and claude.ai need exactly that. So:

- the DNS name `host` of the cell configuration resolves to the edge's host;
- that address accepts TCP port 443. Either the edge listens on port 443 itself, or a TCP forwarder in front passes the ClientHello byte for byte;
- the route you add names the same `host`, in lowercase, as the cell configuration. The cell refuses a tunnel for any other host.

**Tunnel CA.** A pilot has no control-plane CA, so you run your own tunnel CA. Keep it apart from the cell CA and from the public origin CA. It issues four certificates:

- the edge's client certificate (client authentication), with the subject CN `edge_<32 lowercase hex digits>`. Choose the 32 digits at random. They are the edge id;
- the cell's tunnel server certificate, `tunnel.pem` of the cell, for a server name such as `cell.tunnel.internal`;
- the vault's tunnel server certificate, for its own server name;
- the feed certificate of `fstp-control` (server authentication), for a server name such as `control.tunnel.internal`.

Put the tunnel CA's certificate into the cell's credentials directory as `tunnel-ca.pem`, into the edge's as well, and into the control plane's as `control-ca.pem`.

**Operator page certificate.** The operator page is served at `https://<operator host>`, for example `https://control.example.eu`, with no port. Give it a certificate for that host from a CA your staff's browsers trust: a public CA, or your own CA installed in those browsers. The tunnel CA does not issue it.

**Pins.** The edge pins each tunnel server's certificate and the feed certificate. A pin is the SHA-256 of the certificate in DER, as 64 lowercase hex digits:

```sh
openssl x509 -in tunnel.pem -outform der | sha256sum
```

### 5.1 Custody for the feed key

The feed signing key is a composite key (ML-DSA-65 with Ed25519). It is sealed in `route-feed.key`, and `fstp-keyd` wraps the seal key under a ControlPlane root. Give `fstp-control` an `fstp-keyd` socket of the `control` client role, `control.sock`: set `FSTP_KEYD_GROUP_CONTROL` to the group id of the OS user of `fstp-control`. That role reaches the ControlPlane chain only. Keep the key volume of that `fstp-keyd` entry recoverable as for the other custody volumes. Without it the feed key does not open, and every edge needs a new key and a restart.

### 5.2 Configure and start `fstp-control`

**Credentials directory**, readable by the OS user of `fstp-control` only:

| File | Holds |
| --- | --- |
| `control-ca.pem` | The tunnel CA, which issued the edge's client certificate |
| `control.pem`, `control-key.pem` | The feed certificate chain and key |
| `operator.pem`, `operator-key.pem` | The operator page certificate chain and key, for the operator host |
| `route-feed.key` | The sealed feed signing key, made by `fstp-control init-route-feed` |

**Configuration**, named by `FSTP_CONTROL_CONFIG`. It holds no secret. `edges` lists the edge ids that may poll, 1 to 16. `assets_dir` is the compiled `web/dist` of the release, which holds the operator page (`routefeed/`) and the ceremony code it uses (`auth/`). `staff` starts empty; section 5.4 fills it.

```json
{
  "assets_dir": "/usr/share/fstp/web",
  "credentials_dir": "/etc/fstp/control",
  "edges": ["<the edge id, 32 lowercase hex digits>"],
  "feed_listen": "10.0.0.2:7350",
  "keyd_socket": "/run/fstp-keyd/control.sock",
  "operator_host": "control.example.eu",
  "operator_listen": "127.0.0.1:7351",
  "operator_socket": "/run/fstp-control/routes.sock",
  "staff": [],
  "state_dir": "/var/lib/fstp-control"
}
```

**Create the key and the first table** once, as the OS user of `fstp-control`:

```sh
FSTP_CONTROL_CONFIG=/etc/fstp/control.json fstp-control init-route-feed /tmp/feed
```

It writes `route-feed.key` and the first, empty table `route-table.signed` in `state_dir`. It writes the public key to `/tmp/feed/route-feed.pub`, one hex line, which the edge pins. After a lost `route-table.signed`, run it again. It writes a new empty table with a higher version and keeps the key. Then add your routes again.

**Start** it, for example as a systemd service:

```sh
FSTP_CONTROL_CONFIG=/etc/fstp/control.json fstp-control route-feed
```

It logs `Started` once it serves. SIGTERM stops it, gives open polls 30 seconds, and exits with status 0. A refused configuration, a `route-table.signed` that does not verify under the key, or an audit log whose chain is broken exits with status 2, any other failure with status 1. The table survives a restart.

**Reach the operator page.** `operator_listen` should be an admin address, not a public one. A browser must open it as `https://<operator host>` on port 443, since the WebAuthn origin carries no port. For example, from an admin machine, map the operator host to `127.0.0.1` in `/etc/hosts`, and forward port 443 there:

```sh
sudo ssh -L 443:127.0.0.1:7351 admin@pilot-host
```

### 5.3 Configure and start the edge

**Credentials directory**, readable by the edge's OS user only:

| File | Holds |
| --- | --- |
| `tunnel.pem`, `tunnel.key` | The edge's client certificate chain and key, CN `edge_<id>`. It serves the tunnels and the feed |
| `tunnel-ca.pem` | The tunnel CA, which issued the cell's, the vault's and the feed certificates |
| `route-feed.pub` | The feed public key from `init-route-feed`. A second line may hold the next key |

**State directory**, writable by the edge's OS user only, for example `/var/lib/fstp-edge`. The edge keeps its signed cache there: the last table it verified, as `fstp-control` signed it.

**Configuration**, named by `FSTP_EDGE_CONFIG`. It holds no secret. `limits`, each of its members and `feed.poll_seconds` are optional; the values below are the defaults.

```json
{
  "credentials_dir": "/etc/fstp/edge",
  "feed": {"address": "10.0.0.2:7350", "cert_sha256": ["<pin of control.pem>"],
           "poll_seconds": 5, "server_name": "control.tunnel.internal"},
  "limits": {"connections": 1024, "per_client": 64, "hello_seconds": 10,
             "open_seconds": 10, "lifetime_seconds": 7200},
  "listen": {"public": "0.0.0.0:443"},
  "state_dir": "/var/lib/fstp-edge"
}
```

- `feed.cert_sha256` holds one or two pins of the feed certificate: the current one and the next.
- `feed.poll_seconds` is the time between two polls, 1 to 60.
- `connections` caps open connections, and `per_client` caps them per client IP address. The address stays in memory and is never logged.
- `hello_seconds` bounds the wait for the ClientHello, `open_seconds` the tunnel handshake and pin check, and `lifetime_seconds` one connection.

**Start** it, for example as a systemd service with the capability to bind port 443:

```sh
FSTP_EDGE_CONFIG=/etc/fstp/edge.json fstp-edge
```

The edge logs `Started` once it listens. It serves its signed cache at once, verified again under `route-feed.pub`, or no route without a cache. A newer table from the feed replaces the cache at the first poll. SIGTERM stops it from accepting, gives open connections 20 seconds, and exits with status 0. A refused configuration, feed key file or credential exits with status 2, any other failure with status 1.

**When the feed fails.** The edge keeps serving the last table it verified. It never serves an unsigned table, a table that fails verification, or a table older than the one it serves. It logs a `Refused` event on `/edge/route-feed` with the rule: `I-90` for a signature, `I-19` for a route or the encoding, `R-SW-02` for an older table, `R-NF-09` for an unreachable control plane, `TH-48` for a cache it cannot write. A table it cannot cache, it does not apply.

**Renewing the feed certificate.** Add the pin of the new certificate as the second entry of `feed.cert_sha256` on every edge, and restart each edge once, ahead of time. Then switch `fstp-control` to the new certificate. Remove the old pin at the next convenient restart.

### 5.4 Staff passkeys, route changes and the audit log

**Enrol a staff passkey** once per staff member. Open `https://<operator host>` and choose "Enrol a new passkey". The page shows one staff entry, `{"cose_key": ..., "credential_id": ..., "staff": ...}`. It grants nothing yet. Add it to `staff` in the configuration of `fstp-control`, and restart `fstp-control`. A pinned passkey must verify the user, for example with a PIN or a fingerprint.

**Route file**, for example `/etc/fstp/routes/grants.json`. One route per file. `host` routes to `app`, the cell's tunnel listener (`listen.tunnel` of the cell). `id.<host>` routes to `vault`, the vault's tunnel listener for the vault origin.

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

**Propose** the route while `fstp-control` runs, as its OS user:

```sh
FSTP_CONTROL_CONFIG=/etc/fstp/control.json fstp-control route add /etc/fstp/routes/grants.json
```

**Approve** it. Open the operator page, log in with your passkey, and check the waiting change: its host, cell, addresses and pins. Choose "Approve with a passkey step-up" and confirm with your passkey again. One step-up approves exactly that one change. Only then does `fstp-control` sign and serve the new table, and the edges take it at their next poll.

The command waits for the approval and exits with status 0 once the change is served. It exits with status 2 at once for a route that every edge would refuse: a host held by another cell, a cell whose two endpoints share an address, a tunnel address or a pin of another route, and two endpoints with one pin. It exits with status 1 when no one approved the change within 5 minutes. Nothing changes then.

An add for a cell that has a route replaces it. So when you renew a tunnel certificate, update its pin in the route file, propose the file again and approve it. No restart is needed.

**Remove** every route of a cell, with the same approval:

```sh
FSTP_CONTROL_CONFIG=/etc/fstp/control.json fstp-control route remove <the cell id>
```

After the next poll, a new connection for the host or its vault origin closes at the edge. A connection already open runs on until it ends.

**List** the served routes:

```sh
FSTP_CONTROL_CONFIG=/etc/fstp/control.json fstp-control route list /tmp/routes.json
```

It writes `{"routes": [...], "version": n}` with each route in the route file form. A list needs no step-up: only the OS user of `fstp-control` can use the operator socket, and that user can read the table itself. The operator page shows the same list after a login.

**Audit log.** Each approved change appends one record to `route-audit.log` in `state_dir` before the new table is stored. It names the time, the staff member, the operation, the cell, the version and the change digest, and it keeps the step-up assertion, which verifies again under the pinned passkey. The records form a hash chain, and `fstp-control` checks the whole chain at start. Keep a copy of the log off the host.

**Check** it from outside, with the public CA your browsers trust:

```sh
curl https://grants.example.eu/.well-known/oauth-protected-resource/mcp
```

The answer names `"resource": "https://grants.example.eu/mcp"`, with no port. A host with no route gets no answer at all: the edge closes the connection.

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

`crates/fstp-celltest/tests/prod_mcp_e2e.rs` runs sections 3, 4, 7 and 8 against the `fstp-cell` binary over local PostgreSQL. `crates/fstp-celltest/tests/g12_vault_run_e2e.rs` runs section 3a: the `fstp-vault` binary from its file beside the `fstp-cell` binary, with a restart of the vault and a vault answer that reaches the cell. `crates/fstp-celltest/tests/i19_edge_binary_e2e.rs` and `i19_route_feed_e2e.rs` run section 5: the `fstp-control route-feed` and `fstp-edge` binaries from their files in front of that binary. Routes are proposed with `fstp-control route` and approved with a passkey step-up on the operator page while the edge runs. `fstp-control` restarts with its table, and the edge restarts from its signed cache. `tools/devstack/run.sh external-cell --route-feed` starts the route feed for a manual check. `crates/fstp-celltest/tests/adr012_backup_agent_pg.rs` runs the backup section: a base backup and WAL from a configuration file, and two restores to the same ledger head. `tools/devstack/run.sh external-cell` starts the same stack for a manual check with Claude Code.

## Backups and restore (operator)

Written by lane L10 `prod/backup`. The design is ADR-012, and its record of lane L10 holds the readings this section follows. Every item marked interim waits for Daniel.

`fstp-backup` seals each base backup part and each WAL segment to the cluster's ClusterBackup group key before it leaves the host. Each container has a fresh data key, sealed through the hybrid KEM (X25519 plus ML-KEM-768, R-CR-01). The agent that writes backups holds the public key only. Opening a backup needs the custody root, so an erasure that destroys a key also holds in every backup (I-81). The primary copy goes to OVHcloud Object Storage. The recovery point objective is about one minute, from `archive_timeout`.

Run one agent per self-operated cluster, so one for the application cluster and one for the vault cluster. Each has its own configuration, key file, cluster id and state directory.

### What the operator supplies

- **Bucket.** An OVHcloud Object Storage bucket in an EU region, with object lock and versioning (ADR-005 V14). Set a lifecycle rule for old versions. The agent never deletes an object. Retention is open (Q25).
- **Object store credentials.** An access key id and secret, scoped to the bucket where the service allows it (V15).
- **Replication login.** The role `fstp_repl` on the cluster, with its client certificate, key and password, and the single `pg_hba` line `hostssl replication fstp_repl 127.0.0.1/32 scram-sha-256 clientcert=verify-full` (ADR-005).
- **Custody.** The `fstp-keyd` console socket, which serves the ClusterBackup chain. Only `init-keys`, `restore` and `wal-restore` use it, and they run as root.

### Configure

Write one JSON file per cluster, for example `/etc/fstp/backup-app.json`. It holds no secret, and an unknown member is refused.

```json
{
  "cluster": "<32 lowercase hex digits, a random id of this cluster>",
  "credentials_dir": "/etc/fstp/backup-app",
  "state_dir": "/var/lib/fstp-backup/app",
  "pg_bindir": "/usr/lib/postgresql/16/bin",
  "database": {"host": "127.0.0.1", "port": 5432},
  "object_store": {"endpoint": "s3.<region>.io.cloud.ovh.net", "region": "<region>", "bucket": "<bucket>"},
  "keyd_socket": "/run/fstp-keyd/console.sock"
}
```

- `database.host` must be a loopback address.
- `object_store.port` is optional and defaults to 443.
- `keyd_socket` is needed only for `init-keys` and the restore commands.

The credentials directory holds these files:

| File | Holds | Read by |
| --- | --- | --- |
| `s3-access-key-id`, `s3-secret-access-key` | The object store credentials, one line each | Every command |
| `s3-ca.pem` | Optional: a CA to trust beside the public roots | Every command |
| `repl.pem`, `repl.key`, `repl.password`, `db-ca.pem` | The `fstp_repl` login and the cluster CA | `base-backup` |
| `cluster-backup.key` | The ClusterBackup key file, made by `init-keys` | Every command |

`archive_command` runs as the `postgres` OS user, and `base-backup` as the `fstp-backup` OS user. Give each user read access to the files of its commands only. The `fstp_repl` files stay readable by the `fstp-backup` user alone (ADR-005).

### Create the key

Once, as root:

```sh
FSTP_BACKUP_CONFIG=/etc/fstp/backup-app.json fstp-backup init-keys
```

It creates the ClusterBackup root through the console socket and writes `cluster-backup.key` with mode 0600. It refuses to overwrite an existing key file.

The root of that key lives in this host's `fstp-keyd`. If the host and its key volume are lost, no backup of this cluster opens again. Keep the key volume of that `fstp-keyd` entry, and `cluster-backup.key`, recoverable off the host by the procedure for custody volumes. Interim, pending Daniel: the pilot has no second custody for this root.

### Archive WAL continuously

In `postgresql.conf` of the cluster:

```text
wal_level = replica
archive_mode = on
archive_timeout = 60
archive_command = 'FSTP_BACKUP_CONFIG=/etc/fstp/backup-app.json /usr/local/bin/fstp-backup wal-archive %p %f'
```

Restart PostgreSQL. A segment already in the bucket is not uploaded again. Timeline history files are archived too. Backup history files and `.partial` files are skipped. A failed upload exits with status 1, and PostgreSQL retries it.

### Take base backups

Run `fstp-backup base-backup` from a timer as the `fstp-backup` user, for example daily. Interim, pending Daniel: the frequency is decided with retention (Q25).

```sh
FSTP_BACKUP_CONFIG=/etc/fstp/backup-app.json fstp-backup base-backup
```

It runs `pg_basebackup` over loopback, cuts the tar stream into parts of 64 MiB, seals and uploads each part, and only then appends a line to `<state_dir>/base-backups.index`. Each line holds the cluster id, the backup id, the time and the size in bytes. Copy that file off the host after each run. A restore on a new host needs a backup id and its size.

### Restore

Stop the server that will use the restored directory. Then, as root:

```sh
FSTP_BACKUP_CONFIG=/etc/fstp/backup-app.json fstp-backup restore /var/lib/postgresql/16/restored
FSTP_BACKUP_CONFIG=/etc/fstp/backup-app.json fstp-backup restore /var/lib/postgresql/16/restored <backup id> <size>
```

- The first form takes the newest backup in the local index. The second names one from an index line.
- The directory must be new or empty.
- The command checks every part, extracts the tar with the host's `tar`, and fetches each archived segment from the backup's start into `pg_wal`, until the next one is absent.
- Give the directory to the `postgres` user and start PostgreSQL on it. It replays the fetched WAL, so the copy reaches the newest archived position.
- Then follow the restore rule of ADR-012: the cell verifies its chain against the witness, and lost receipted entries are reported, never hidden.

For archive recovery driven by PostgreSQL itself, `restore_command = 'FSTP_BACKUP_CONFIG=... fstp-backup wal-restore %f %p'` fetches one file and exits with status 1 when the bucket lacks it. It opens the key through the console socket, so it must run as root. Interim, pending Daniel: the pilot has no continuous standby, and a restore across a timeline switch is not built.

Exit status: 0 on success, 2 for a refused configuration or argument, 1 for any other failure. No line names a secret.

### What is not built yet

- A second provider (Q25). One `object_store` only.
- Keystore snapshots written by `fstp-cell` and `fstp-vault` (ADR-012 "Keystore snapshots").
- Rotation of the ClusterBackup root, and a key held outside this host.
- Declared restores at the witness and the monthly restore drill.

### Checked by

`crates/fstp-backup/tests/s3_agent.rs` runs the S3 client and the agent against a fake S3 that verifies every SigV4 signature on its own. `crates/fstp-celltest/tests/adr012_backup_agent_pg.rs` takes a base backup of a PostgreSQL world from a configuration file, archives its WAL, restores two copies and starts PostgreSQL on each. It checks the ledger head, that no stored object holds plaintext (R-CR-01), and that erased texts stay unreadable from the restored keystores (I-81).

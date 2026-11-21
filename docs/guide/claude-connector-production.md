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
- **Backups.** Object storage under ADR-012, and `fstp-backup` per self-operated cluster. The section "Backups and restore (operator)" sets it up.
- **Second custodian.** Another machine with its own `fstp-keyd` entry. It holds its own custody of the ClusterBackup chain and the off-host copies of the pilot's custody entries (section "Backups and restore (operator)").
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
- `organisation_active` stands for the organisation's activation on a ledger with no tenant part. Daniel decided on 2026-11-21 that `fstp-cell provision-tenant` (section 3, "Provision the tenant") replaces it. Until a provisioned pilot can be activated, keep the member and do not provision (interim, pending Daniel, ADR-026 row "Organisation port until onboarding runs"). Without it, the ADR-021 gate refuses every programme operation, so no draft can be prepared.

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

### Provision the tenant

`fstp-cell provision-tenant` records the tenant part of the cell's ledger (`TenantProvisioned`), as the control plane does on a SaaS cell. The ADR-021 setup gate then reads the real organisation: not active until onboarding completes and a second tenant admin approves the activation. The design is ADR-026 "Tenant provisioning", decided by Daniel on 2026-11-21.

**Not yet on a pilot.** A provisioned pilot cannot be activated today, so it could prepare no programme draft. No second tenant admin can join the tenant part, the cell's onboarding prober fails every probe, and no pilot vault route verifies an admin's identity. Until those exist, skip this step and keep `organisation_active` (section 2). Once a cell is provisioned, `organisation_active` has no effect on it.

When the step applies, stop the cell and run it after `init-keys` and before `first-admin`:

```sh
FSTP_CELL_CONFIG=/etc/fstp/cell.json fstp-cell provision-tenant --agreements 1,1,1
```

- `--agreements` names the versions of the SaaS terms, the data processing agreement and the sub-processor list that the tenant accepted, in that order. A SaaS cell needs it. A self-hosted cell refuses it. The agreement texts are `TODO(legal)`.
- The command draws the first admin's account. `first-admin` then invites exactly that account.
- It refuses a ledger that holds a tenant part, so it records once. It writes no output. Exit status 0 means the tenant part is recorded.

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

Each start runs the database check, opens the keystore through its custody entry, and verifies the vault chain at the witness before it listens. A start never creates a keystore. A start also refuses a vault database that holds bank details or hardship evidence sealed under the shared `Fact` data key, since no erasure could make them unreadable (ADR-004 record of lane L13, row "Existing facts"). Only a pilot vault from before lane L13 can hold them, and only synthetic ones. Recreate such a vault: a fresh vault database, then `init-keys`. SIGTERM drains the vault within 20 seconds. A refused configuration exits with status 2, and any other failure with status 1. Log lines name a rule, never a secret.

### Erase an identity

### Register an identity

The vault seals an account's bank details and hardship evidence under its identity's own fact key, so an erasure of that identity reaches them (ADR-004 record of lane L13). The vault therefore refuses those writes, with 403 on the vault origin, until the account is registered.

The cell registers an account on the vault's internal listener, `POST /v1/identity`, with its `cell-app` certificate. The request names the account and its attribute tuple. The vault resolves the identity from the tuple, stores the sealed tuple in its keystore, and binds the account. The reply is `acked` and names no identity. A repeat changes nothing. Two accounts with the same tuple share one identity. An account bound to one identity is never moved to another: such a request is refused as malformed.

No cell command sends this request yet (ADR-004 record of lane L13, row "Cell side"). The vault intake of ADR-026 is still refused, so a pilot vault takes no bank details from a browser until a cell flow registers the account.

### Erase an identity

An identity erasure rotates the Vault chain once (design section 3.5, ADR-004 records of lanes L11 and L13). It erases the identity's attribute tuple and makes its match key unlinkable, in the live store and in every backup (I-81, G24). It erases the bank details and hardship evidence of the identity's accounts with it: their fact key derives from the tuple's data key, which the rotation destroys. It does not erase the other facts the vault holds under its shared `Fact` data key, such as countries, affiliations and verifications, or anything in the cell.

Stop the vault first. The running vault holds a lock on its keystore, and the command refuses while it does. Then run, with the account id from the cell as 32 hex digits or in the UUID form. The command finds the identity through the account's registration, or else through its verification:

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
- From the next start, the erased identity's bank details and hardship evidence are gone from the vault's state. A grant whose bank details were erased is never releasable until its lead registers again and enters new details (I-33). No copy opens them: not the live rows, not a keystore snapshot, not a restored backup.
- The erased identity's accounts lose their registration. A new registration with the same tuple gives a new identity.

An identity whose attribute tuple the vault never stored cannot be erased this way, and the command refuses it with status 1. Registration through `POST /v1/identity` stores the tuple, so every registered identity is erasable.

## 4. Create the first admin

Stop the cell first. Then run, with the first admin's own address:

```sh
FSTP_CELL_CONFIG=/etc/fstp/cell.json fstp-cell first-admin --email admin@grants.example.eu /root/first-admin.token
```

The command starts the cell with its listeners on loopback, records the first admin's login email and invitation, and writes the token once to the new file, with mode 0600 (D4). The address is sealed and fingerprinted as every login email is (ADR-026 "First admin email", decided by Daniel on 2026-11-21). `--email` is optional. On a SaaS cell the file holds two lines, one for each half. Hand each half to the first admin through a different staff channel. The command refuses an existing file, and a cell whose first admin is already invited or enrolled. Start the cell again afterwards.

The first admin opens `https://<host>/auth/invite#<first half><second half>` and enrols a passkey. The first admin then invites the other staff from the platform.

With `--email`, recovery by email works for the first admin from day one. Before the first admin enrols, the address opens nothing: no magic link and no recovery case. Only both token halves enrol the first admin. Without `--email`, the first admin has no login email, and a second tenant admin approves its recovery. The command refuses an address that is another account's login email.

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

Sign in with your passkey if the page asks. Choose **Approve**. The cell asks for a passkey step-up, since connecting an agent links a new device. Each step-up approves one consent only (I-78). A magic-link session cannot approve.

## 8. Work with Claude and confirm in the platform

Ask Claude, for example: "Set up a new programme draft called Green Valleys 2027". Claude prepares the draft. Nothing changes until you confirm.

Each `fstp_prepare_*` tool leaves a pending action with a path such as `/app/pending/<id>`. Open it in the platform and confirm it. A high-risk action asks for a fresh passkey step-up. Each action can be confirmed once. Pending actions survive a restart of the cell.

Access tokens live 10 minutes. Claude refreshes them while your grant lasts, also across a restart of the cell. When you recover your account, every agent grant of your account ends at once (I-79). Connect Claude again afterwards with your new passkey. To end Claude's access yourself, run `claude mcp logout fstp`, or remove the claude.ai connector.

## Checked by

`crates/fstp-celltest/tests/prod_mcp_e2e.rs` runs sections 3, 4, 7 and 8 against the `fstp-cell` binary over local PostgreSQL. `crates/fstp-celltest/tests/g12_vault_run_e2e.rs` runs section 3a: the `fstp-vault` binary from its file beside the `fstp-cell` binary, with a restart of the vault and a vault answer that reaches the cell. `crates/fstp-celltest/tests/i19_edge_binary_e2e.rs` runs section 5: the `fstp-edge` binary from its files in front of that binary. `crates/fstp-celltest/tests/adr012_backup_agent_pg.rs` runs the backup section: a base backup and WAL from a configuration file, and two restores to the same ledger head. `crates/fstp-celltest/tests/l12_cell_decisions_pg.rs` runs the tenant provisioning of section 3 and the first admin email of section 4 on a world cell. `tools/devstack/run.sh external-cell` starts the same stack for a manual check with Claude Code.

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

The root of that key lives in this host's `fstp-keyd`. Decided by Daniel on 2026-11-21: a backup must still open after the loss of this host. Two measures carry that, and the pilot uses both. A second custodian on another machine holds its own custody of the ClusterBackup chain ("Second custodian" below). An off-host sealed copy of each `fstp-keyd` entry keeps the App and Vault roots ("Off-host copy of a custody entry" below). The rows inside a backup open only with those roots.

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

### Second custodian

Written by lane L16 `prod/backup-custody` (ADR-012 record of lane L16). Every item waits for Daniel unless it says otherwise.

The second custodian is another machine, outside the pilot host. It runs its own `fstp-keyd` entry with its own key volume, passphrase and console socket. It never receives a root of the pilot host. It creates its own ClusterBackup root, and the pilot host seals the group secret to a key that root protects.

Set up the second host:

- An `fstp-keyd` entry as on the pilot (section 1), on a Linux ext4 or XFS volume.
- `fstp-backup` and a configuration file with the pilot's `cluster` and `object_store`, and `keyd_socket` set to this host's console socket.
- The object store credentials. Give this host a read-only credential where the service allows it.
- A copy of the pilot's `cluster-backup.key`. It holds the public key and a secret sealed under the pilot's root only, so it opens nothing here by itself.

The key ceremony, as root on each host:

1. On the second host, run `FSTP_BACKUP_CONFIG=/etc/fstp/backup-app.json fstp-backup custodian-init`. It creates this host's ClusterBackup root and writes `custodian.key` and `custodian.pub` into the credentials directory. It refuses to overwrite either.
2. Carry `custodian.pub` to the pilot host. It holds no secret. Compare `sha256sum custodian.pub` on both hosts over a second channel, such as a phone call between the two operators.
3. On the pilot host, run `FSTP_BACKUP_CONFIG=/etc/fstp/backup-app.json fstp-backup custodian-escrow /root/custodian.pub /root/cluster-backup.escrow`. It opens the group secret through the console socket and seals it to the second custodian's key. It refuses a request for another cluster.
4. Carry `cluster-backup.escrow` to the second host's credentials directory, with mode 0600. It is sealed to that host's key, so only that host's `fstp-keyd` opens it.
5. Run a restore drill on the second host into a scratch directory (section "Restore after the loss of the host", step 2). Delete the escrow copy from the pilot host once the drill passes.

On a host whose credentials directory holds `cluster-backup.escrow`, `restore` and `wal-restore` open `custodian.key` through the console socket and then the escrow. They check that it names the group key of `cluster-backup.key`.

The second custodian holds only a ClusterBackup root. ClusterBackup is never rotated or destroyed by an erasure, so no erased key is ever held there (I-81).

### Off-host copy of a custody entry

Written by lane L16 (ADR-004 record of lane L16). Every item waits for Daniel unless it says otherwise.

Each `fstp-keyd` entry of the pilot gets an off-host sealed copy: the cell's entry, the cell key file's entry and the vault's entry. A copy holds the key table and the key files of live keys, as sealed as on the volume, inside one more seal under the entry's passphrase. It also carries the entry's usage log, so reconciliation after a restore covers the time before the loss. It never holds a root in the clear (I-80). Only `fstp-keyd` makes or opens it.

Make a copy while the entry is stopped, as root:

```sh
systemctl stop fstp-keyd
fstp-keyd export /var/lib/fstp-keyd /root/keyd-cell-2026-11-21.fkx
systemctl start fstp-keyd
```

- The command reads the passphrase as the service does: the systemd credential, or else `systemd-ask-password`. It refuses while the entry serves.
- It writes the copy with mode 0600 and refuses an existing file. Move it off the host at once, for example to the second custodian.
- The copy's id stands in clear in bytes 26 to 41 of the file: `od -An -tx1 -j26 -N16 /root/keyd-cell-2026-11-21.fkx | tr -d ' \n'`. Note it beside the copy.
- After each erasure, make a new copy, destroy every older copy, and retire each older id (below). Decided by Daniel on 2026-11-21. A copy made before an erasure still holds the erased key, and whoever holds it with the passphrase can open that key outside our tools.

The entry records each copy in `exports.log` on its volume. While a copy that is not retired holds a key that has since been destroyed, the entry starts at reduced I-81 assurance with the reason "an off-host copy holds a destroyed key". Once every copy of an old id is destroyed, record it:

```sh
fstp-keyd retire-export /var/lib/fstp-keyd <copy id>
```

The entry reports full assurance again at its next start, if nothing else reduces it.

### Restore after the loss of the host

On a fresh host, as root, in this order:

1. Install each `fstp-keyd` entry with the passphrase of the entry it replaces. Import its newest copy onto an empty key volume: `fstp-keyd import /root/keyd-cell-2026-11-21.fkx /var/lib/fstp-keyd`. A wrong passphrase, a changed byte and a volume that already holds a key table are refused, and nothing is written.
2. Start the entries. An imported entry is held: it answers only unwraps on the backup chains, so `fstp-backup restore` runs and no cell or vault opens a key. Run `fstp-backup restore` for each cluster (section "Restore"). If the pilot host's ClusterBackup root is gone with its entry, run the restore on the second custodian instead, and carry the restored directory over.
3. Start PostgreSQL on each restored directory, without the cell and the vault. Read the current epoch of each erasable chain as the PostgreSQL superuser over the local socket: `SELECT chain, max(epoch) FROM keystore.root WHERE state = 1 GROUP BY chain;` in `c_<cell>` gives the App chain (1), and in `v_<cell>` the Vault chain (2).
4. Stop each entry and release it with those epochs, for example `fstp-keyd release /var/lib/fstp-keyd app=7` for the cell's entry and `fstp-keyd release /var/lib/fstp-keyd vault=3` for the vault's. Release destroys every older epoch of each named chain. The cell key file's entry holds no erasable chain, so release it with no epoch.
5. If release refuses, the copy is older than the last erasure. It has destroyed the erased epochs and keeps the hold. The data under the current epoch does not open from this copy. Import a newer copy onto a fresh volume and release again.
6. Start the entries, the cell and the vault. Then follow the restore rule of ADR-012: each verifies its chain against the witness, and lost receipted entries are reported, never hidden.

### Copies of the cell key file and the witness receipt key file

Decided by Daniel on 2026-11-21 (ADR-004 record of lane L16, Q-L16-3). The cell key file `cell-keys.sealed` and the witness receipt key file `receipt.key` live in credentials directories, outside the key volumes. A restore needs copies of them too. Make each copy with its owner's command, as root:

```sh
FSTP_CELL_CONFIG=/etc/fstp/cell.json fstp-cell copy-key-file /root/cell-keys-2026-11-21.sealed
FSTP_WITNESS_CONFIG=/etc/fstp/witness.json fstp-witness copy-key-file /root/receipt-2026-11-21.key
```

- Each command opens the file through its owner's `fstp-keyd` entry, writes the sealed bytes with mode 0600, and records the copy in `cell-keys.copies` or `receipt.copies` beside the file. Copy that register off the host with the copy.
- Each command also writes the copy's id as 32 hex digits to `<out>.id`, for example `/root/cell-keys-2026-11-21.sealed.id`. Keep it beside the copy.
- At each start the owner compares the register with its live keys. While a copy that is not retired holds a key it has since replaced, it logs `key_file_assurance` at reduced assurance, with the reason "an off-host copy of a key file holds a replaced key".
- Once every copy of an id is destroyed, record it with `fstp-cell retire-key-file-copy <id>` or `fstp-witness retire-key-file-copy <id>`.
- On the fresh host, put each copy back under its file name in the owner's credentials directory before step 6.

### What is not built yet

- A second provider (Q25). One `object_store` only.
- Keystore snapshots written by `fstp-cell` and `fstp-vault` (ADR-012 "Keystore snapshots").
- Rotation of the ClusterBackup root and group. A new group generation needs a new escrow for each custodian.
- A copy bound to a guard key that the second custodian destroys at each erasure. Decided by Daniel on 2026-11-21: a release item, built before a release (ADR-004 record of lane L16, Q-L16-1).
- Declared restores at the witness and the monthly restore drill.

### Checked by

`crates/fstp-backup/tests/s3_agent.rs` runs the S3 client and the agent against a fake S3 that verifies every SigV4 signature on its own. `crates/fstp-celltest/tests/adr012_backup_agent_pg.rs` takes a base backup of a PostgreSQL world from a configuration file, archives its WAL, restores two copies and starts PostgreSQL on each. It checks the ledger head, that no stored object holds plaintext (R-CR-01), and that erased texts stay unreadable from the restored keystores (I-81).

`crates/fstp-backup/tests/second_custodian.rs` runs the key ceremony between two custodies and a restore through the second custodian after the first is dropped (I-80, I-81). `crates/fstp-keyd/tests/offhost_copy.rs` runs `fstp-keyd` on a volume, copies it, loses the volume and imports the copy onto a fresh one. It checks the hold and the release, that an older copy is re-erased before anything serves, the register's reduced assurance, and that a wrong passphrase or a changed byte is refused.

The copy test also checks that a restored entry answers the usage records made before the copy (Q-L16-2). `crates/fstp-custody/tests/copy_register.rs`, and the `key_copy` tests of `fstp-cell` and `fstp-witness`, check that a copy of a key file lowers the owner's assurance once the owner replaces a key the copy holds, until the copy is retired (Q-L16-3).

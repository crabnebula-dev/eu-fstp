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

The edge is the only public listener. It passes each browser's TLS connection through to the cell by SNI, and holds no origin key. It takes its routes from a signed route feed that a small `fstp-control` serves. You change routes with one command on the host, and the edge follows within seconds, with no restart. The reference is ADR-009 "Pilot edge configuration" and "Pilot route feed".

### 5.1 Before you start

- **DNS and port 443.** The cell's `host` resolves to the edge, and that address accepts TCP port 443.
- **Tunnel CA.** Your own CA, kept apart from the cell CA and the public origin CA. It issues four certificates: the edge's client certificate with the CN `edge_<32 random lowercase hex digits>` (the edge id), the cell's and the vault's tunnel server certificates, and the feed certificate of `fstp-control`, for example for `control.tunnel.internal`.
- **Custody.** An `fstp-keyd` socket of the `control` role, `control.sock`. Set `FSTP_KEYD_GROUP_CONTROL` to the group id of the `fstp-control` OS user.
- **Pins.** A pin is the SHA-256 of a certificate in DER:

```sh
openssl x509 -in tunnel.pem -outform der | sha256sum
```

### 5.2 Start `fstp-control`

Put these files in `/etc/fstp/control`, readable by the `fstp-control` user only: `control-ca.pem` (the tunnel CA), `control.pem` and `control-key.pem` (the feed certificate and key). Write `/etc/fstp/control.json`:

```json
{
  "credentials_dir": "/etc/fstp/control",
  "edges": ["<the edge id>"],
  "feed_listen": "10.0.0.2:7350",
  "keyd_socket": "/run/fstp-keyd/control.sock",
  "operator_socket": "/run/fstp-control/routes.sock",
  "state_dir": "/var/lib/fstp-control"
}
```

Once, as the `fstp-control` user, create the feed key and the first table. It writes the public key to `/tmp/feed/route-feed.pub`:

```sh
FSTP_CONTROL_CONFIG=/etc/fstp/control.json fstp-control init-route-feed /tmp/feed
```

Then run it, for example as a systemd service:

```sh
FSTP_CONTROL_CONFIG=/etc/fstp/control.json fstp-control route-feed
```

If `route-table.signed` is ever lost, run `init-route-feed` again and add your routes again.

### 5.3 Start the edge

Put these files in `/etc/fstp/edge`, readable by the edge user only: `tunnel.pem` and `tunnel.key` (the edge's client certificate and key), `tunnel-ca.pem` (the tunnel CA), and `route-feed.pub` from 5.2. Create `/var/lib/fstp-edge`, writable by the edge user. Write `/etc/fstp/edge.json`:

```json
{
  "credentials_dir": "/etc/fstp/edge",
  "feed": {"address": "10.0.0.2:7350", "cert_sha256": ["<pin of control.pem>"],
           "server_name": "control.tunnel.internal"},
  "listen": {"public": "0.0.0.0:443"},
  "state_dir": "/var/lib/fstp-edge"
}
```

Run it with the capability to bind port 443:

```sh
FSTP_EDGE_CONFIG=/etc/fstp/edge.json fstp-edge
```

Optional members: `feed.poll_seconds` (default 5), and `limits` as ADR-009 "Pilot edge configuration" lists them. The edge keeps a signed copy of its last routes in `state_dir`. So it keeps serving them after a restart while `fstp-control` is down, and it never serves an unsigned or older table.

### 5.4 Add, remove and list routes

Write one route per file, for example `/etc/fstp/routes/grants.json`. `app` is the cell's tunnel listener and `vault` the vault's:

```json
{"routes": [
  {"cell": "<the cell id>", "host": "grants.example.eu",
   "app":   {"address": "10.0.0.4:7443", "server_name": "cell.tunnel.internal",
             "cert_sha256": "<pin of the cell's tunnel.pem>"},
   "vault": {"address": "10.0.0.6:7446", "server_name": "vault.tunnel.internal",
             "cert_sha256": "<pin of the vault's tunnel certificate>"}}
]}
```

Run these as root or as the `fstp-control` user. Each one applies at once:

```sh
export FSTP_CONTROL_CONFIG=/etc/fstp/control.json
fstp-control route add /etc/fstp/routes/grants.json   # add, or replace the cell's route
fstp-control route remove <the cell id>              # remove every route of the cell
fstp-control route list /tmp/routes.json             # write the served routes
```

Exit status 0 means done, 2 means the input or the route was refused, and 1 means anything else failed. The commands never prompt. A route is refused when it would clash with another: the same host, tunnel address or pin, or a cell whose two endpoints share an address.

When you renew a tunnel certificate, put its new pin in the route file and run `route add` again. When you renew the feed certificate, first add its pin as a second entry of `feed.cert_sha256` on each edge and restart the edge once.

Every change is logged in `/var/lib/fstp-control/route-audit.log`: the time, the operation, the cell, the version and the user who ran it. Copy the log off the host from time to time.

**Check** from outside:

```sh
curl https://grants.example.eu/.well-known/oauth-protected-resource/mcp
```

The answer names `"resource": "https://grants.example.eu/mcp"`. A host with no route gets no answer.

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

`crates/fstp-celltest/tests/prod_mcp_e2e.rs` runs sections 3, 4, 7 and 8 against the `fstp-cell` binary over local PostgreSQL. `crates/fstp-celltest/tests/g12_vault_run_e2e.rs` runs section 3a: the `fstp-vault` binary from its file beside the `fstp-cell` binary, with a restart of the vault and a vault answer that reaches the cell. `crates/fstp-celltest/tests/i19_edge_binary_e2e.rs` and `i19_route_feed_e2e.rs` run section 5: the `fstp-control route-feed` and `fstp-edge` binaries from their files in front of that binary. Routes change with `fstp-control route` while the edge runs. `fstp-control` restarts with its table, and the edge restarts from its signed cache. `tools/devstack/run.sh external-cell --route-feed` starts the route feed for a manual check. `crates/fstp-celltest/tests/adr012_backup_agent_pg.rs` runs the backup section: a base backup and WAL from a configuration file, and two restores to the same ledger head. `tools/devstack/run.sh external-cell` starts the same stack for a manual check with Claude Code.

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

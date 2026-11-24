# Production reference: each service by hand

This is the per-service reference behind `fstp-admin` (ADR-028). The how-to is `docs/guide/claude-connector-production.md`: on a host, `fstp-admin setup` does every step below, writes every file below from `/etc/fstp/fstp.json`, and `fstp-admin status` says what to do next. Read on only to understand a file `fstp-admin` wrote, or to run a part by hand. Sections 1 to 5 describe the operator's parts. Sections 6 to 8 are for a programme manager who connects Claude.

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
  "registered_servers": [{"kind": "application", "spki_sha256": "<64 hex digits>"},
                         {"kind": "vault", "spki_sha256": "<64 hex digits>"}],
  "shell": {"dkim_selector": "fstp", "platform_url": "https://grants.example.eu", "resolver": "10.0.0.53:53"},
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
- `shell` names the DNS resolver, the DKIM selector and the platform address the onboarding checks and the Guide use (ADR-027). The Domains and email step checks the SPF, DKIM and DMARC records of the domain the admin types, with this DKIM selector. The Channels step checks that the `mail` relay greets the cell. The resolver listens on TCP port 53. Only tests and the devstack use a loopback resolver on another port (lead reading, 2026-11-22).
- The member `organisation_active` is gone. A file that names it is refused. The organisation opens only through onboarding (ADR-026 record of lane L18).

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

Every pilot runs this step. Stop the cell and run it after `init-keys` and before `first-admin`:

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

Each start runs the database check, opens the keystore through its custody entry, and verifies the vault chain at the witness before it listens. A start never creates a keystore. A start also refuses a vault database that holds bank details or hardship evidence sealed under the shared `Fact` data key, since no erasure could make them unreadable (ADR-004 record of lane L13, row "Existing facts"). Only a pilot vault from before lane L13 can hold them, and only synthetic ones. Recreate such a vault: a fresh vault database, then `init-keys`. A start, and `verify-first-admin`, also refuse a vault that stores an identity tuple of the earlier label `fstp-identity-tuple-v1` (ADR-004 row "Normalisation"). Names in the tuple are NFKC and case folded since lane L21 (ADR-029), so an old tuple would give its person a second identity. Only a pilot vault that verified someone before lane L21 holds one. Recreate it the same way. SIGTERM drains the vault within 20 seconds. A refused configuration exits with status 2, and any other failure with status 1. Log lines name a rule, never a secret.

The running vault holds a lock on its keystore through its `<dbname>_keys` connection. It checks that connection every 5 seconds. If the connection drops, the vault takes the lock again on a new one and keeps serving. If another process took the lock meanwhile, such as an `erase-identity` run, the vault stops serving at once. Every request then answers 503, the log shows `{"event":"serving_stopped","rule":"I-81"}`, and the process drains and exits with status 1. Start it again once the other process is done (ADR-004 record of lane L13b).

### Verify the first admins

The technical admin verifies the first admins on the host (ADR-008, decided by Daniel on 2026-11-21). Check the person's identity document yourself. Then write the details into a file, as root, with no document number:

```json
{
  "method": "manual",
  "document_type": "passport",
  "checks": ["document_authentic", "document_valid", "photo_match"],
  "identity": {
    "family_names": "Example",
    "given_names": "Alex",
    "birth_date": "1990-01-31",
    "issuing_state": "DEU"
  }
}
```

`document_type` is `passport`, `identity_card` or `residence_permit`. `checks` names one or more of `data_match`, `document_authentic`, `document_valid` and `photo_match`. `issuing_state` is the three-letter code of the state that issued the document. Then, with the vault stopped:

```sh
systemctl stop fstp-vault
FSTP_VAULT_CONFIG=/etc/fstp/vault.json fstp-vault verify-first-admin 01234567-89ab-cdef-0123-456789abcdef /root/admin.json
systemctl start fstp-vault
shred -u /root/admin.json
```

- The command asks nothing and prints nothing. Exit status 0 means the verification is recorded. Running it again for the same person changes nothing. Status 2 means a refused argument or file. Status 1 means another failure, such as a vault that still runs.
- It verifies at most two accounts per vault, the first admins. The verifier of record is the operator.
- The cell learns of the verification when the vault serves again.

### Record a verification on the web

People ask for their ID check themselves: "Start verification" on their identity page records a request, with no identity data, and tells them "We will contact you to check your ID, in person or by video call" (ADR-026 record of lane L24). A tenant admin then sees "ID checks waiting (n)" in the navigation, and the person on "Members" marked "asked for an ID check". When the cell has a mail relay, each tenant admin who may record also gets one email, "A person is waiting for an ID check", with a link to Members and no name. A staff request shows at once; an applicant's only once the proposal is in negotiation. Check the ID in person or by video call, then record it as below. The request closes once the vault confirms the check; an unused form link leaves it open. Until then the person's identity page reads that the request is pending.

A verified tenant admin records everyone else. On "Members" (`/app/admin/members`), choose "Record verification" next to the person. People of proposals in negotiation or later are listed in a section of their own on the same page, each with the button. The vault's form opens for that person. Type only the identity details from their document, and save. The vault registers the person's identity and records the verification in one step. The cell never sees these details. A failed save keeps the link valid, and saving again completes it.

The cell offers the form only to a verified tenant admin with no Judging role, never for themselves or a person who shares their identity. An applicant is verified only once their proposal is in NEGOTIATION, under a ticket for that proposal (ADR-004 record of lane L13b, row "Ticket").

The vault serves its form pages when its configuration names `assets_dir`, such as `"assets_dir":"/opt/fstp/web"`. That directory holds `vault/` (the compiled `web/dist/vault/*.js` and `web/src/vault/shell.html`) and `auth/` (`dom.js`, `encoding.js`, `i18n.js`, `tokens.css` and `auth.css`), as the cell's `auth/` does. A missing file refuses the start.

### Register an identity

The vault seals an account's bank details and hardship evidence under its identity's own fact key, so an erasure of that identity reaches them (ADR-004 record of lane L13). The vault therefore refuses those writes, with 403 on the vault origin, until the account is registered. A verification registers the account. So bank details work once the person is verified.

The cell can also register an account on the vault's internal listener, `POST /v1/identity`, with its `cell-app` certificate. The request names the account and its attribute tuple. The reply is `acked` and names no identity. A repeat changes nothing. An account bound to one identity is never moved to another.

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

The first admin opens `https://<host>/auth/invite#<first half><second half>` and enrols a passkey.

With `--email`, recovery by email works for the first admin from day one. Before the first admin enrols, the address opens nothing: no magic link and no recovery case. Only both token halves enrol the first admin. Without `--email`, the first admin has no login email, and a second tenant admin approves its recovery. The command refuses an address that is another account's login email.

## 4a. Open the organisation

The organisation stays closed until onboarding is done and a second admin approved its opening (ADR-021, SoD-18). The admins see a checklist on "Onboarding summary" (`/app/admin/onboarding/summary`). It says what is done, who does the next item, and the next step in plain words. The order (ADR-026 record of lane L18):

1. **Web, first admin.** Invite the second admin by email on the checklist. This needs a passkey confirmation and the `mail` relay.
2. **Web, second admin.** Open the mailed link within 72 hours and create a passkey. That makes them a tenant admin.
3. **Host, technical admin.** Verify both admins with `fstp-vault verify-first-admin` (section 3a, "Verify the first admins", from lane L13b). The checklist shows each admin's account number in the form the command takes.
4. **Web.** One admin grants Financial and Legal signatory to the other. Nobody can grant a role to themselves (SoD-07).
5. **Web.** Save each onboarding step. Domains and email passes once the domain's SPF, DKIM and DMARC records are in DNS. Channels passes once the relay greets the cell.
6. **Web.** One admin asks to open the organisation, and the other approves it.

Only then can anyone prepare a programme draft, through the platform or through Claude.

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

Sign in with your passkey if the page asks. Choose **Approve**. The cell asks for a passkey step-up, since connecting an agent links a new device. Each step-up approves one consent only (I-78). A magic-link session cannot approve.

## 8. Work with Claude and confirm in the platform

Ask Claude, for example: "Set up a new programme draft called Green Valleys 2027". Claude prepares the draft. Nothing changes until you confirm.

Each `fstp_prepare_*` tool leaves a pending action with a path such as `/app/pending/<id>`. Open it in the platform and confirm it. A high-risk action asks for a fresh passkey step-up. Each action can be confirmed once. Pending actions survive a restart of the cell.

Access tokens live 10 minutes. Claude refreshes them while your grant lasts, also across a restart of the cell. When you recover your account, every agent grant of your account ends at once (I-79). Connect Claude again afterwards with your new passkey. To end Claude's access yourself, run `claude mcp logout fstp`, or remove the claude.ai connector.

## Checked by

`crates/fstp-celltest/tests/prod_mcp_e2e.rs` runs sections 3, 4, 7 and 8 against the `fstp-cell` binary over local PostgreSQL. `crates/fstp-celltest/tests/g12_vault_run_e2e.rs` runs section 3a: the `fstp-vault` binary from its file beside the `fstp-cell` binary, with a restart of the vault and a vault answer that reaches the cell. `crates/fstp-celltest/tests/i19_edge_binary_e2e.rs` and `i19_route_feed_e2e.rs` run section 5: the `fstp-control route-feed` and `fstp-edge` binaries from their files in front of that binary. Routes change with `fstp-control route` while the edge runs. `fstp-control` restarts with its table, and the edge restarts from its signed cache. `tools/devstack/run.sh external-cell --route-feed` starts the route feed for a manual check. `crates/fstp-celltest/tests/adr012_backup_agent_pg.rs` runs the backup section: a base backup and WAL from a configuration file, and two restores to the same ledger head. `crates/fstp-celltest/tests/l12_cell_decisions_pg.rs` runs the tenant provisioning of section 3 and the first admin email of section 4 on a world cell. `tools/devstack/run.sh external-cell` starts the same stack for a manual check with Claude Code.

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

### The guard of the copies (F-018)

Written by lane `m10/guard-key` (ADR-004 "The guard key of Q-L16-1 (F-018)", ADR-028 record of lane `m10/guard-key`). Decided by Daniel on 2026-11-23: the second custodian is required, and it guards every copy above.

- The second custodian's `fstp-keyd` also listens on TCP port 7460 over mutual TLS (`FSTP_KEYD_GUARD_LISTEN`). It holds one guard per pilot entry: a hybrid KEM key pair, X25519 with ML-KEM-768.
- `fstp-keyd export` on a pilot entry with `FSTP_KEYD_GUARD` and `FSTP_KEYD_GUARD_ENTRY` set seals the copy once more to that entry's guard. The file then starts with `FGC1`, and its id stands in bytes 12 to 27. `fstp-admin backup-keys` sets both and writes the id beside the copy, so no `od` is needed. In production `export` refuses without a custodian.
- Every destroy the entry serves replaces its guard before the receipt goes out. A copy made before the destroy then opens nowhere. While the custodian does not answer, the destroy answers "the guard of the key copies is not yet replaced" and the erasure waits.
- `fstp-keyd import` of a guarded copy asks the custodian to open the outer seal. It needs the same two variables and, in `$CREDENTIALS_DIRECTORY`, `guard-ca.pem`, `guard-client.pem` and `guard-client.key` of that entry beside the passphrase. They are in `/etc/fstp/keyd-guard` once the new host is paired. In production `import` refuses a plain `FKX1` copy.
- `fstp-keyd guard-check <volume>`, with the same variables, exits 0 when the custodian answers, 3 when a guard rotation is owed, 4 when it does not answer and 5 when none is configured. `fstp-admin status` and `setup` run it.
- The custodian's own key volume is never copied: `export` refuses it.
- After each rotation the pilot entry sends a fresh guarded copy to the custodian by itself (ADR-004 "The custodian's copy", decided by Daniel on 2026-11-24). The custodian keeps one per entry, `held-<entry>.fgc`, sealed to the live guard, and drops it at the next rotation. It cannot open it without the pilot's passphrase. A copy that does not arrive stays owed and is retried at the next start, at every destroy and every ten minutes. `guard-check` then exits 6.
- `fstp-keyd fetch-copy <file>`, with the same variables, writes the custodian's copy of the entry. It exits 7 when the custodian holds none.
- Production refuses a plain pre-guard `FKX1` copy at import (decided by Daniel on 2026-11-24, Q-F018-3).

### Restore after the loss of the host

On a fresh host, as root, in this order:

0. Pair the new host with the same second custodian (`fstp-admin pair-custodian`, then `fstp-admin custodian <file>` on the custodian). The custodian keeps its guards, so the newest copies open. On a host set up with `fstp-admin`, `fstp-admin restore-keys <dir>` then does steps 1 and 2 for every entry, and `fstp-admin restore` does steps 3 to 6. The steps below describe what they run.
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

### Keystore snapshots

Written by lanes L17 and L27 (ADR-012 records of lanes L17 and L27, ADR-028 record of lane L27). Every item waits for Daniel unless it says otherwise.

The cell and the vault each keep a sealed copy of their keys in the backup bucket, under `<cell>/keystore/`. A base backup and the WAL archive hold the keys too. A snapshot also covers the case where the restored database is older than the last erasure.

- `fstp-admin setup` turns them on with `backup`: it writes `object_store` into `cell.json` and `vault.json` and copies `s3-access-key-id` and `s3-secret-access-key` into `/etc/fstp/cell` and `/etc/fstp/vault`. Without `backup`, neither takes snapshots.
- Each process creates its own snapshot key file at its next start: `cell-snapshot.key` and `vault-snapshot.key` in its credentials directory. `backup-keys` copies these with the other key files.
- The bucket must be versioned, which object lock needs anyway. Each process writes the pointer `latest-app` or `latest-vault` again after each verified snapshot, and a versioned bucket keeps every version (lead reading, 2026-11-22).
- Each process takes a snapshot when an erasure rotates its keys, and once a day: a minute after its start, then every 24 hours, and an hour after a failure. Each snapshot is fetched back and opened before it counts. An erasure destroys the old keys only after its snapshot opens.
- Each process writes `keystore-snapshot.status` in its credentials directory and logs `keystore_snapshot` with `verified` or `failed`. `fstp-admin status` shows the last verified snapshot of each, and names a failure as the next thing to do. The page System shows the same to the web admins, in the row "Key store snapshots": amber when a snapshot is over 36 hours old, red when the last one failed.

`fstp-admin restore` runs, after the two database restores and with both services stopped:

```sh
FSTP_VAULT_CONFIG=/etc/fstp/vault.json fstp-vault restore-keystore
FSTP_CELL_CONFIG=/etc/fstp/cell.json fstp-cell restore-keystore
```

- Each takes the restored database's keys, or the newest snapshot when the database is older than the last erasure. It keeps the newest copy that opens, whole, and never mixes two.
- Give a snapshot id as 32 hex digits to take another snapshot than the newest.
- Each prints nothing. Exit status 0 when a copy opens, 1 when none does, 2 for a wrong argument or configuration.
- Keys erased before the snapshot stay unreadable from it (I-81).

### What is not built yet

- A second provider (Q25). One `object_store` only.
- A yearly re-wrap of the snapshot keys (lead reading, 2026-11-22: a later item).
- Rotation of the ClusterBackup root and group. A new group generation needs a new escrow for each custodian.
- Built since 2026-11-23: the guard of the copies, above (F-018).
- Declared restores at the witness and the monthly restore drill.

### Checked by

`crates/fstp-backup/tests/s3_agent.rs` runs the S3 client and the agent against a fake S3 that verifies every SigV4 signature on its own. `crates/fstp-celltest/tests/adr012_backup_agent_pg.rs` takes a base backup of a PostgreSQL world from a configuration file, archives its WAL, restores two copies and starts PostgreSQL on each. It checks the ledger head, that no stored object holds plaintext (R-CR-01), and that erased texts stay unreadable from the restored keystores (I-81).

`crates/fstp-backup/tests/second_custodian.rs` runs the key ceremony between two custodies and a restore through the second custodian after the first is dropped (I-80, I-81). `crates/fstp-keyd/tests/offhost_copy.rs` runs `fstp-keyd` on a volume, copies it, loses the volume and imports the copy onto a fresh one. It checks the hold and the release, that an older copy is re-erased before anything serves, the register's reduced assurance, and that a wrong passphrase or a changed byte is refused.

The copy test also checks that a restored entry answers the usage records made before the copy (Q-L16-2). `crates/fstp-custody/tests/copy_register.rs`, and the `key_copy` tests of `fstp-cell` and `fstp-witness`, check that a copy of a key file lowers the owner's assurance once the owner replaces a key the copy holds, until the copy is retired (Q-L16-3).

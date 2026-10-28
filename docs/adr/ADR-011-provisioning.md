# ADR-011: Database provisioning

Status: Proposed (drafted 2026-10-28), awaiting Daniel's acceptance.

Labels such as Q4, Q15, G4 and W2h exist only in `docs/handoff/m3-design.md`. They are not spec identifiers. ADR-008 to ADR-012 are proposed numbers, drafted on the same date. Items marked "interim, pending Daniel" are proposals that no answer of 2026-10-28 settles.

## Context

- **I-82** No database role can read across databases of different cells. **I-83** Identity vault databases never share a cluster with application databases.
- ADR-005 D2 requires `clientcert=verify-full` on every `hostssl` line, with the CN equal to the role and SCRAM-SHA-256-PLUS on top.
- Daniel decided Q4 A with R1 on 2026-10-28. The superuser and the replication role log in only over loopback on the database host. No remote role has CREATEROLE or CREATEDB. Destructive jobs need two operators. The ADR-005 amendment records the reading of I-82. This ADR applies the remote-role rule to the self-operated clusters it covers. The managed control cluster conflicts with it, and the ADR-005 amendment raises that to Daniel.
- Daniel answered yes to all seven parts of Q15 on 2026-10-28. One part is the self-hosted install: a local `fstp-install` and a local `fstp-pgagent`, with cluster CA keys in local custody.
- PostgreSQL 16 gives a CREATEROLE role ADMIN OPTION on the roles it creates. So no role with CREATEROLE or CREATEDB may log in from the network.
- `CREATE DATABASE` cannot run inside a transaction block or a DO block. It therefore cannot go through a checked server-side function, and its identifiers cannot be bound as parameters.
- This ADR covers the self-operated clusters: `application`, `vault` and `witness`. The managed `control` cluster is set up once per environment, as described below.

## Decision

### `fstp-pgagent`

- A binary of the `fstp-control` crate. One instance runs on each self-operated database host, as its own OS user.
- It listens on the control-private port over mutual TLS. It accepts only a client certificate that the control-plane CA issued to `fstp-control`.
- It connects only to its local server, over loopback, as `fstp_super`. Its OS user is the only one that can read that role's certificate, key and password.
- It runs only typed jobs. A job is a value of a closed enum. No SQL text crosses the wire, and no job field holds free text.
- The job decoder `pgagent_job_decode` is fuzzed from the first commit.
- Each job is recorded in `cp.job` with its kind, cluster, state and approvals. `fstp-pgagent` also logs each job as a typed `fstp-obs` event.
- Every job is idempotent, so a retried job after a crash leaves the same state.

| Job | Effect | Destructive |
| --- | --- | --- |
| `CreateCellDatabases` | `CREATE DATABASE` for `c_<cell>` or `v_<cell>`, as the cluster kind allows | No |
| `CreateRoles` | The cell's roles as NOLOGIN, from the role plan | No |
| `WriteHba` | Renders `pg_hba.conf` from the plan and reloads the server configuration | No, unless it removes the line of a live role |
| `ApplyRevocations` | `REVOKE CONNECT ... FROM PUBLIC`, and the revocations of cross-database statistics views (G14) | No |
| `SetRoleCredential` | Sets a role's SCRAM verifier and LOGIN | No |
| `ApplyGrants` | Calls `fstp_meta.apply_grant` once per grant row of the plan, after migrations | No |
| `PrivilegeAudit` | Reads `pg_roles`, `pg_auth_members`, `pg_database.datacl`, `pg_extension`, view grants and `pg_hba_file_rules` for the isolation auditor | No |
| `SetNoLogin` | Ends a role at once | Yes |
| `DropCellDatabases`, `DropRoles` | `DROP DATABASE` and `DROP ROLE` for one cell, used by cell erasure (R-SW-02) | Yes |
| `DeclareRestore` | Run by `fstp-control`, not by `fstp-pgagent`. Sends `RestoreDeclared` to the witness before a restored cell or vault serves (ADR-012). Interim, pending Daniel | Yes |

- The job list above is interim, pending Daniel. `m3-design.md` names the effects but not the job enum. `DeclareRestore` is proposed by ADR-012. Which jobs carry the production restore itself is an ADR-012 open point.
- `PrivilegeAudit` needs superuser in PostgreSQL 16, because `pg_hba_file_rules` does. It runs hourly in production and is the test oracle in CI.
- The auditor expands array columns on the server, through `aclexplode(datacl)` and `unnest()`. It receives scalar text, integer and boolean values only, so no array parser exists. A source scan refuses an array type in the auditor's queries.

### The cell role plan

- `fstp_control::pg::cell_role_plan(cell)` is the only source of roles, role attributes, CONNECT grants, `pg_hba` lines, revocations and grant rows for a cell. It has one owner (lane W2h). SaaS provisioning and the self-hosted install both call it.
- No cell role is SUPERUSER, CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS.
- No cell role is a member of `pg_read_all_data`, `pg_write_all_data`, `pg_read_all_stats`, `pg_monitor`, `pg_signal_backend`, `pg_read_server_files`, `pg_write_server_files` or `pg_execute_server_program`.
- `dblink`, `postgres_fdw` and every other extension are absent. `CREATE EXTENSION` is refused for every cell role.
- `pg_hba.conf` has one `hostssl <db> <role> <cell subnet> scram-sha-256 clientcert=verify-full` line per role and database. It adds the loopback lines for `fstp_super` and `fstp_repl` (ADR-005 amendment). It has no remote `all` line and ends with a reject line.

### DDL identifier grammar

| Identifier | Grammar |
| --- | --- |
| Application database | `^c_[0-9a-f]{32}$` |
| Vault database | `^v_[0-9a-f]{32}$` |
| Application role | The database name, `_`, and one of `migrator`, `writer`, `app`, `keys`, `auditor` |
| Vault role | The database name, `_`, and one of `migrator`, `vault`, `keys` |

- The 32 hex digits are the random `CellId`. The longest role name has 43 bytes, below PostgreSQL's 63-byte limit.
- `DbIdent` and `RoleIdent` are built only from a `CellId` and a closed suffix enum, or by parsing input against the grammar. They have no constructor from an unchecked string.
- The renderer takes only these typed values and renders each as a double-quoted identifier. The grammar admits no quote character, so quoting is a second line of defence, not the first.
- In `m3-design.md`, only `CREATE DATABASE` and `DROP DATABASE` are rendered this way, and grants go through `apply_grant`. Interim, pending Daniel: the same renderer also writes `CREATE ROLE ... NOLOGIN`, `ALTER ROLE ... LOGIN`, `ALTER ROLE ... NOLOGIN`, `DROP ROLE`, `GRANT CONNECT` and `REVOKE CONNECT`. Each template has typed slots only.
- A SCRAM verifier is rendered as a single-quoted literal in `ALTER ROLE ... PASSWORD`. It must match the closed `ScramVerifier` grammar on decode: `SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>`, with base64 fields. The grammar admits no quote and no backslash. A cleartext password never reaches the agent.
- The minimum iteration count accepted in a verifier: Record at first use.
- Property, checked by the fuzz target `ddl_identifier_render`: rendered DDL never contains an input byte outside the grammar, and any identifier outside the grammar is refused.

### `fstp_meta.apply_grant`

Grants on objects run through one owner function. Its text is `fstp_migrate::catalogue::APPLY_GRANT_SQL`, shared by the application and vault migration sets, so both define the same function. It follows the M1 `set_config` pattern.

```sql
CREATE FUNCTION fstp_meta.apply_grant(privs text, object text, suffix text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE cell text := current_setting('fstp.cell');
BEGIN
  IF cell !~ '^[0-9a-f]{32}$' THEN RAISE EXCEPTION 'bad cell id'; END IF;
  IF privs !~ '^(SELECT|INSERT|UPDATE|DELETE)(, (SELECT|INSERT|UPDATE|DELETE))*$' THEN RAISE EXCEPTION 'bad privileges'; END IF;
  IF object !~ '^[a-z_]{1,30}\.[a-z_]{1,30}$' THEN RAISE EXCEPTION 'bad object'; END IF;
  IF suffix !~ '^(migrator|writer|app|keys|auditor|vault)$' THEN RAISE EXCEPTION 'bad role'; END IF;
  EXECUTE format('GRANT %s ON %I.%I TO %I', privs, split_part(object, '.', 1), split_part(object, '.', 2),
                 left(current_database(), 1) || '_' || cell || '_' || suffix);
END $$;
```

- `fstp-pgagent` sets `fstp.cell` with `set_config` in its session, then calls the function once per grant row of `cell_role_plan`, after the migrations ran.
- The role name is derived from the current database and the cell setting, never taken from a caller.
- The function is not `SECURITY DEFINER`, so it grants only what its caller may grant. `fstp-pgagent` calls it as `fstp_super`.
- Interim, pending Daniel: the same migration runs `REVOKE EXECUTE ON FUNCTION fstp_meta.apply_grant(text, text, text) FROM PUBLIC`. A cell role that called it could only grant what it could grant anyway. The revoke removes that path as well. `m3-design.md` does not contain this line.
- The migration sets only define the function. The grant rows come only from `cell_role_plan`.
- Naming: `m3-design.md` section 4.6 calls this function `fstp_meta.grant_cell_roles`. Sections 4.1 and 18 call it `apply_grant`. This ADR uses `apply_grant`, and section 4.6 is to be corrected.

### Two-operator approval

Daniel decided on 2026-10-28 that destructive jobs need two operators (Q4 A).

- A destructive job is one marked so in the job table above. Erasing a cell (`fstp-control erase-cell`, R-SW-02) and deregistering a cluster are destructive too.
- A destructive job runs only with approvals from two distinct staff members. The requester counts as one of them.
- Each approval is a passkey assertion with user verification over the job digest. The digest covers the job kind, the cluster and every argument. An approval is single-use and expires after a fixed lifetime.
- Interim, pending Daniel: that lifetime is 5 minutes, a fixed control-plane constant. It matches the proposed value of P-71, but P-71 is a tenant-level parameter and staff hold no tenant binding (Q37).
- `fstp-control` checks both approvals before it sends the job.
- Interim, pending Daniel: `fstp-pgagent` checks both approvals again itself, against a staff key set pinned at its installation. The `cp` database sits on the managed control cluster, where the provider's operator role can write rows (ADR-005 amendment). So an approval count read from `cp` is not enough.
- A change to the pinned staff key set is itself a destructive job.
- Non-destructive jobs run on one operator's request with a passkey and a step-up, as `provision-cell` does.
- The same two-person rule applies to the one-time set-up of the managed control cluster below.

### Provisioning a cell in SaaS

`fstp-control provision-cell --org <ref> --mode shared|dedicated` is run by an operator with a passkey and a step-up. Each step is idempotent and recorded in `cp.job`.

1. Draw a `CellId` of 128 random bits.
2. `Placement::new(app_cluster, vault_cluster)` refuses equal clusters, wrong kinds and any `control` or `witness` cluster (I-83).
3. Create custody entries for the App, Vault and CellBackup chains. The Vault chain uses a separate credential (ADR-004).
4. `fstp-pgagent` creates both databases, the roles as NOLOGIN, the `pg_hba` lines and the revocations, from `cell_role_plan(cell)`.
5. Issue the public host certificates for `<cell host>` and `id.<cell host>` to keys the cell generates (Q30). The cell creates its CA key in its custody entry at first start.
6. Start the cell and the vault. Each generates its role key pairs and passwords, and sends `RoleCredential` messages. `fstp-pgagent` sets the SCRAM verifiers and LOGIN. The cluster CA issues the role certificates.
7. Run migrations and grants. Write `fstp_meta.placement` in both databases.
8. Create epoch 1 for each chain. Write the genesis chain rows and the first anchors.
9. Publish the routes for `<cell host>` and `id.<cell host>` to the edge.
10. The cell creates the first tenant admin invitation as two halves, delivered by two staff members over two channels (ADR-008, Q35 interim). The control plane keeps no copy and never learns the account id or the full token.

At start, `fstp-vault` refuses a database whose `fstp_meta.placement` kind is not vault, or whose server certificate OU is not `vault`. `fstp-cell` makes the mirror checks.

### The managed control cluster

`fstp-pgagent` does not run there. The service gives no host access and no superuser (ADR-005 amendment).

- The `cp` and `licence` databases and the roles `cp_service`, `cp_migrator`, `licence_service` and `licence_migrator` are created once per environment. The provider's admin user `avnadmin` does this, since it has CREATEDB and CREATEROLE.
- The same set-up revokes CONNECT from PUBLIC on both databases and grants CONNECT per database (verify item V7 of ADR-005).
- Interim, pending Daniel: the `avnadmin` password is held under two-person control and is used only for this set-up and for later role changes. No running service holds it.
- Each service role authenticates with SCRAM over server-authenticated TLS (ADR-005 amendment). Its password sits in a file readable only by the service's OS user.
- `avnadmin` is a remote role with CREATEDB, CREATEROLE and REPLICATION. That conflicts with the Q4 A rule that no remote role has CREATEROLE or CREATEDB. This ADR does not settle the conflict. The ADR-005 amendment raises it to Daniel, with the proposal that the rule covers the self-operated clusters only.

### Self-hosted install (Q15, decided 2026-10-28)

A self-hosted cell has no control plane. The steps that `fstp-control` performs in SaaS run locally. `fstp-install` is a one-shot binary of `fstp-control`, run as root on the node. It reuses `Placement`, `cell_role_plan` and the DDL renderer, so both modes share one implementation.

1. Check the node: two PostgreSQL 16 data directories with separate OS users and ports, the `fstp-keyd` key volume (ADR-004, Q32), and swap disabled.
2. Start `fstp-keyd`. It creates the App, Vault and CellBackup chain entries, and one EC secp256r1 sign key per cluster CA. The cluster CA keys therefore live in local custody.
3. Create both cluster CAs and server certificates, with the kind in the OU. Write `pg_hba.conf` from the same generator as SaaS, plus the loopback superuser and replication lines.
4. Run `fstp-pgagent` in local mode over loopback for the databases, NOLOGIN roles and revocations. Each component generates its own role key pair and password. `fstp-pgagent` sets the SCRAM verifiers and LOGIN, and signs role certificates with the local cluster CA through `fstp-keyd`.
5. Run migrations and grants. Write `fstp_meta.placement` in both databases.
6. Start `fstp-witness` locally, and register the cell CA's public key with it (Q9).
7. Configure the local `fstp-edge` route table for `<host>` and `id.<host>`, so the vault origin is routed by SNI as in SaaS.
8. Start the cell and the vault. The cell writes the first-admin token once to a root-only file.

- Renewal: a `fstp-pgagent` timer in local mode renews role certificates daily. The cell CA renews internal certificates as in SaaS.
- No step needs a CrabNebula host (I-38). Every credential is generated at install, and no file holds a fixed value (R-NF-05).
- Local mode has no staff and no control plane, so the two-operator rule has no second operator to draw on. Interim, pending Daniel: destructive local jobs run only from the root console and are logged in the cell's audit chain.
- `install_config_decode` is fuzzed from the first commit.

## Consequences

- No third-party crate is added. Everything above uses `fstp-pgwire`, `fstp-migrate`, `fstp-pki`, `fstp-custody`, `fstp-tls` and `fstp-obs`.
- Fuzz targets of `fstp-control`: `cp_api_decode`, `pgagent_job_decode`, `ddl_identifier_render` and `install_config_decode`.
- Tests: `i82_privilege_graph_has_no_cross_cell_path`, `i82_generated_hba_has_no_remote_superuser_and_no_all_line`, `i82_replication_role_has_loopback_line_only_and_no_connect`, `i82_no_remote_role_has_createrole_or_createdb`, `i82_names_reveal_nothing`, `i82_teeth_seeded_connect_grant_is_caught`, `i83_placement_never_mixes_kinds`, `i83_cluster_kind_is_immutable`, `i83_self_hosted_layout_runs_two_instances`, `i83_teeth_first_free_cluster_is_caught`, `r_nf_05_self_hosted_install_has_no_default_credentials` and `t_db_iso_i82_every_role_refused_on_foreign_cell_database`.
- `i82_no_remote_role_has_createrole_or_createdb` covers the self-operated clusters only (ADR-005 amendment, Open points for Daniel).
- Lane W2h starts only after Daniel accepts this ADR and the ADR-005 amendment.

## Open points

- The job enum, the extra DDL templates, the `apply_grant` revoke and the pinned staff key set in `fstp-pgagent` are proposals of this draft. Daniel accepts or changes each.
- Whether a self-hosted install needs a second person for destructive local jobs.
- Self-hosted issuers, raised in ADR-009. `m3-design.md` names no issuer for the local edge's tunnel certificate or the local witness's server certificate. ADR-009 offers an install-time CA in local custody, kept apart from the cell CA and the cluster CAs. Daniel decides before this ADR is accepted, and steps 6 and 7 of the install then name the issuer.
- The minimum SCRAM iteration count: Record at first use.

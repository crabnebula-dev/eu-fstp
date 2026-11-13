//! The R-NF requirement tests that M3 runs (design section 14.5): R-NF-05
//! (no default credentials), R-NF-08 (data at rest and nonces) and
//! R-NF-09 (mutual authentication of internal links).
//!
//! Tests that other lanes own live with them: `r_nf_02_*` in
//! `crates/fstp-obs/tests` (lane W2l), and the seal limit
//! `r_nf_08_seal_count_limit_refuses_at_two_to_the_24` in
//! `crates/fstp-crypto/tests/aead.rs` (lane W1h). `r_nf_03_*` and
//! `r_nf_04_*` cover the TypeScript pages of lane W3c.
//!
//! Lane W1f wrote these tests before the production code. They are red
//! until every catalogue (lanes W2d, W2e, W2g, W2h and W2j) and the cell
//! runtime (lane W3a) land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use fstp_celltest::egress::Peer;
use fstp_celltest::mc::place_model::db;
use fstp_celltest::scan::{CellDump, PublicConstants, StoreSet, shared_identifiers};
use fstp_celltest::world::{
    ClusterHandle, ClusterKind, CycleScript, DbMode, VaultLayout, World, WorldSpec,
};
use fstp_migrate::catalogue::{ColumnClass, TableClass, TableSpec};

fn world(cells: u8, self_hosted: bool, process_mode: bool) -> World {
    World::start(WorldSpec {
        cells,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted,
        process_mode,
    })
    .unwrap_or_else(|e| panic!("the world did not start: {e}"))
}

fn agent_clusters(w: &World) -> Vec<&ClusterHandle> {
    w.clusters()
        .iter()
        .filter(|c| c.kind() != ClusterKind::Control)
        .collect()
}

fn ca_pem(c: &ClusterHandle) -> Vec<u8> {
    c.server().cluster_ca().unwrap().cert_pem().to_vec()
}

// ---------------------------------------------------------------------------
// R-NF-05: no default credentials.

/// Passwords a default install might ship with.
const DEFAULTS: [&str; 6] = ["", "postgres", "password", "admin", "changeme", "fstp"];

/// The R-NF-05 breaches of one cluster, one line each: a login role
/// without a SCRAM verifier, two roles with one verifier, or a cell role
/// that logs in with a default password and a valid client certificate.
fn default_credentials(c: &ClusterHandle) -> Vec<String> {
    let s = c.server();
    let mut out = Vec::new();
    let rows = s
        .psql(
            "postgres",
            "SELECT rolname || '|' || coalesce(rolpassword, '') FROM pg_authid \
             WHERE rolcanlogin ORDER BY 1",
        )
        .unwrap();
    let mut verifiers: BTreeMap<String, String> = BTreeMap::new();
    for line in rows.lines() {
        let (role, verifier) = line.split_once('|').unwrap();
        if !verifier.starts_with("SCRAM-SHA-256$") {
            out.push(format!("{}: {role} has no SCRAM verifier", c.name()));
        }
        if let Some(other) = verifiers.insert(verifier.to_owned(), role.to_owned()) {
            out.push(format!("{}: {role} and {other} share a verifier", c.name()));
        }
    }
    let ca = ca_pem(c);
    for role in db::cell_login_roles(s).unwrap() {
        let issued = s.cluster_ca().unwrap().issue_role(&role).unwrap();
        let dbname = role.rsplit_once('_').map(|(d, _)| d.to_owned()).unwrap();
        for password in DEFAULTS
            .iter()
            .map(|p| (*p).to_owned())
            .chain([role.clone()])
        {
            let cred = db::Credential {
                role: role.clone(),
                password: password.clone(),
                cert_pem: issued.cert_pem.clone(),
                key_pem: issued.key_pem.clone(),
            };
            if db::run_as(s, &ca, &cred, true, &dbname, "SELECT 1").is_ok() {
                out.push(format!("{}: {role} logs in with {password:?}", c.name()));
            }
        }
    }
    out
}

/// R-NF-05: after the first start of a SaaS cell, every login role of
/// every self-operated cluster has its own SCRAM verifier, and no cell
/// role logs in with a default password.
#[test]
fn r_nf_05_first_start_has_no_default_credentials() {
    let w = world(1, false, false);
    let found: Vec<String> = agent_clusters(&w)
        .into_iter()
        .flat_map(default_credentials)
        .collect();
    assert!(found.is_empty(), "{found:#?}");
}

/// The files an install writes outside its database clusters (design
/// section 9.5).
#[derive(Clone, Debug, Default)]
struct InstallFiles {
    /// Configuration: the `fstp-install` configuration, the route table
    /// and every other file that may hold fixed, public settings.
    config: StoreSet,
    /// Credentials: the first-admin token file (design section 8.3), the
    /// `fstp-keyd` credential and key volume, and each component's role key
    /// pair and password (design section 9.5, step 4). Every byte of each
    /// is generated at install.
    credentials: StoreSet,
}

/// The install files of `w`, as `World::install_files` reads them back
/// from each cell's install directory (lane F-SELF).
///
/// Gap: B-06 defers `fstp-install`, so the world plays it and runs no
/// `fstp-keyd`. The files hold the configuration, the first-admin token
/// file and the role keys and passwords, but no `fstp-keyd` credential or
/// key volume yet.
fn install_files(w: &World) -> Result<InstallFiles, fstp_celltest::NotImplemented> {
    let f = w
        .install_files()
        .unwrap_or_else(|e| panic!("the install files: {e}"));
    Ok(InstallFiles {
        config: f.config,
        credentials: f.credentials,
    })
}

/// Words that mark a configuration setting as a credential.
const CREDENTIAL_WORDS: [&str; 5] = ["password", "passphrase", "secret", "token", "key"];

/// The credential settings of a configuration store: each `name = value`
/// or `name: value` line whose name holds a [`CREDENTIAL_WORDS`] word, as
/// `(name, value)`.
fn credential_settings(bytes: &[u8]) -> BTreeSet<(String, String)> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let Some(at) = line.find(['=', ':']) else {
            continue;
        };
        let (name, value) = (line[..at].trim(), line[at + 1..].trim());
        let lower = name.to_ascii_lowercase();
        if !value.is_empty() && CREDENTIAL_WORDS.iter().any(|w| lower.contains(w)) {
            out.insert((name.to_owned(), value.to_owned()));
        }
    }
    out
}

/// The fixed values that two installs' files show, one line each: a
/// credential file with the same bytes in both, or a credential setting of
/// a configuration file with the same value in both. The identifier
/// comparison misses a fixed password such as a lowercase passphrase, so
/// this check compares the bytes themselves.
fn fixed_install_values(a: &InstallFiles, b: &InstallFiles) -> Vec<String> {
    let mut out = Vec::new();
    let creds: BTreeMap<&str, &Vec<u8>> = b
        .credentials
        .stores
        .iter()
        .map(|(n, v)| (n.as_str(), v))
        .collect();
    for (name, bytes) in &a.credentials.stores {
        if creds.get(name.as_str()) == Some(&bytes) {
            out.push(format!(
                "the credential {name} has the same bytes in both installs"
            ));
        }
    }
    let settings: BTreeSet<(String, String)> = b
        .config
        .stores
        .iter()
        .flat_map(|(_, v)| credential_settings(v))
        .collect();
    for (name, bytes) in &a.config.stores {
        for (key, value) in credential_settings(bytes) {
            if settings.contains(&(key.clone(), value)) {
                out.push(format!("{name}: {key} has the same value in both installs"));
            }
        }
    }
    out
}

/// The identifiers of every credential of the install `w`: its credential
/// files, every store that holds a private key, and the SCRAM verifier of
/// every login role of its clusters.
fn credential_identifiers(w: &World, f: &InstallFiles) -> BTreeSet<Vec<u8>> {
    let mut creds = f.credentials.clone();
    let stores = w
        .stores()
        .unwrap_or_else(|e| panic!("the install stores: {e}"));
    for (name, bytes) in stores.stores {
        if bytes.windows(11).any(|x| x == b"PRIVATE KEY") {
            creds.push(name, bytes);
        }
    }
    for c in w.clusters() {
        let verifiers = c
            .server()
            .psql(
                "postgres",
                "SELECT coalesce(rolpassword, '') FROM pg_authid WHERE rolcanlogin ORDER BY 1",
            )
            .unwrap();
        creds.push(format!("{}/verifiers", c.name()), verifiers.into_bytes());
    }
    let mut secret = StoreSet::default();
    for (name, bytes) in creds.stores {
        secret.push(name, without_certificates(&bytes));
    }
    CellDump::from_stores(&secret).identifiers
}

/// `bytes` without its PEM certificate blocks. A certificate is public,
/// so its extension bytes, which provisioning writes alike, stay in the
/// baseline. Its key and serial are generated, so no baseline holds them.
fn without_certificates(bytes: &[u8]) -> Vec<u8> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let find = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).position(|w| w == needle);
    let mut out = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some(i) = find(rest, BEGIN) {
        out.extend_from_slice(&rest[..i]);
        match find(&rest[i..], END) {
            Some(j) => rest = &rest[i + j + END.len()..],
            None => {
                rest = &[];
            }
        }
    }
    out.extend_from_slice(rest);
    out
}

/// The identifiers of the install `w`: its cluster stores and its install
/// files.
fn install_dump(w: &World, f: &InstallFiles) -> CellDump {
    let mut all = w
        .stores()
        .unwrap_or_else(|e| panic!("the install stores: {e}"));
    all.stores.extend(f.config.stores.clone());
    all.stores.extend(f.credentials.stores.clone());
    CellDump::from_stores(&all)
}

/// What every install of one build holds alike: the identifiers two more
/// provisioned installs share, such as catalog and WAL bytes that
/// provisioning writes alike and the X.509 extension bytes of client
/// certificates. Daniel decided on 2026-11-13 (M3 exit audit, section 7,
/// item 10) that the baseline is a provisioned cluster. No credential is a
/// constant: every identifier of a credential of either baseline install
/// is left out, so a credential two installs share is still reported.
///
/// The baseline installs start while `tested` are alive, so they take
/// other install slots and never reuse a tested install's servers.
fn build_constants(tested: &[&World]) -> PublicConstants {
    let x = world(1, true, false);
    let y = world(1, true, false);
    for base in [&x, &y] {
        for t in tested {
            for (cb, ct) in base.clusters().iter().zip(t.clusters()) {
                assert!(
                    !std::ptr::eq(cb.server(), ct.server()),
                    "the baseline install shares the cluster {}, so the comparison is vacuous",
                    ct.name()
                );
            }
        }
    }
    let files = |w: &World| install_files(w).unwrap_or_else(|e| panic!("{e}"));
    let (fx, fy) = (files(&x), files(&y));
    let mut public = PublicConstants::baseline(&install_dump(&x, &fx), &install_dump(&y, &fy));
    let creds: BTreeSet<Vec<u8>> = credential_identifiers(&x, &fx)
        .into_iter()
        .chain(credential_identifiers(&y, &fy))
        .collect();
    public.values.retain(|v| !creds.contains(v));
    public
}

/// R-NF-05, R-NF-01, design section 9.5: every credential is generated at
/// install, and no file holds a fixed value. Two fresh self-hosted
/// installs share no identifier beyond the constants of the build, which
/// two more provisioned installs give ([`build_constants`]), over their
/// cluster stores and their install files. No credential file, and
/// no credential setting of a configuration file, is the same in both. As
/// a second line, each instance passes the default-password check.
#[test]
fn r_nf_05_self_hosted_install_has_no_default_credentials() {
    let a = world(1, true, false);
    let b = world(1, true, false);
    assert_eq!(a.clusters().len(), 2);
    // Gap, reported by lane W1f: `cluster_plan` names the clusters of a
    // self-hosted world by kind alone, so a second world in one process
    // reuses the first one's servers. The two installs must be distinct.
    for (ca, cb) in a.clusters().iter().zip(b.clusters()) {
        assert!(
            !std::ptr::eq(ca.server(), cb.server()),
            "the two installs share the cluster {}, so the comparison is vacuous",
            ca.name()
        );
    }
    let mut found: Vec<String> = a
        .clusters()
        .iter()
        .chain(b.clusters())
        .flat_map(default_credentials)
        .collect();
    let files = |w: &World| install_files(w).unwrap_or_else(|e| panic!("{e}"));
    let (fa, fb) = (files(&a), files(&b));
    found.extend(fixed_install_values(&fa, &fb));
    let (dump_a, dump_b) = (install_dump(&a, &fa), install_dump(&b, &fb));
    let shared = shared_identifiers(&dump_a, &dump_b, &build_constants(&[&a, &b])).unwrap();
    found.extend(
        shared
            .iter()
            .map(|id| format!("both installs hold the fixed value {}", hex(id))),
    );
    assert!(found.is_empty(), "{found:#?}");
}

/// R-NF-05 teeth: a fixed passphrase in a credential file, and the same
/// value of a credential setting in a configuration file, are each
/// reported. Generated credentials and equal public settings are not.
#[test]
fn r_nf_05_teeth_fixed_install_value_is_caught() {
    let fixed = b"fstp-selfhosted-install-2026".to_vec();
    let random = || {
        let mut r = [0u8; 24];
        fstp_crypto::random_bytes(&mut r).unwrap();
        hex(&r).into_bytes()
    };
    let install = |token: Vec<u8>, config: Vec<u8>| {
        let mut f = InstallFiles::default();
        f.credentials.push("install/first-admin-token", token);
        f.credentials.push("install/keyd/credential", random());
        f.config.push("install/fstp-install.conf", config);
        f
    };
    let config = |secret: &[u8]| {
        let mut c = b"port = 5432\nhost: id.example.test\nkeyd_secret = ".to_vec();
        c.extend_from_slice(secret);
        c.push(b'\n');
        c
    };
    let clean = fixed_install_values(
        &install(random(), config(&random())),
        &install(random(), config(&random())),
    );
    assert!(clean.is_empty(), "{clean:#?}");
    let found = fixed_install_values(
        &install(fixed.clone(), config(&fixed)),
        &install(fixed.clone(), config(&fixed)),
    );
    assert_eq!(found.len(), 2, "{found:#?}");
}

// ---------------------------------------------------------------------------
// R-NF-08: the catalogue (design section 4.5).

/// Column names that hold content, so their class must be `Sealed`.
const CONTENT_NAMES: [&str; 8] = [
    "body", "envelope", "text", "name", "email", "address", "title", "note",
];

/// The migration runner's ledger: tooling metadata, not content. The
/// content-name rule exempts it by exact schema and table name only
/// (Daniel, 2026-11-07, m4-design section 15.0).
const MIGRATION_LEDGER: (&str, &str) = ("fstp_migrate", "schema_migrations");

/// The R-NF-08 breaches of one catalogue, one line each.
fn clear_content(set: &str, cat: &[TableSpec]) -> Vec<String> {
    let mut out = Vec::new();
    for t in cat {
        let ledger = (t.schema, t.name) == MIGRATION_LEDGER;
        for c in t.columns {
            match c.class {
                None => out.push(format!(
                    "{set}: {}.{}.{} has no class",
                    t.schema, t.name, c.name
                )),
                Some(class) => {
                    let content = CONTENT_NAMES
                        .iter()
                        .any(|n| c.name == *n || c.name.ends_with(&format!("_{n}")));
                    if content && !ledger && class != ColumnClass::Sealed {
                        out.push(format!(
                            "{set}: {}.{}.{} holds content as {class:?}",
                            t.schema, t.name, c.name
                        ));
                    }
                }
            }
        }
        if matches!(
            t.class,
            TableClass::SealedContent | TableClass::LedgerRecord
        ) && !t
            .columns
            .iter()
            .any(|c| c.class == Some(ColumnClass::Sealed))
        {
            out.push(format!(
                "{set}: {}.{} is {:?} with no sealed column",
                t.schema, t.name, t.class
            ));
        }
    }
    out
}

/// R-NF-08, B3, design section 4.5: the union of the five catalogues
/// lists the application and vault tables, every column has a class, every
/// content column is sealed, and every sealed-content or ledger table has
/// a sealed column. The database comparison is `i16_schemas_have_no_fund_class`.
#[test]
fn r_nf_08_catalogue_has_no_clear_content_column() {
    let mut found = Vec::new();
    for s in db::migration_sets() {
        if s.catalogue.is_empty() {
            found.push(format!("{}: the catalogue of {} is empty", s.set, s.krate));
        }
        found.extend(clear_content(s.set, s.catalogue));
    }
    assert!(found.is_empty(), "{found:#?}");
}

/// R-NF-08 teeth: a clear `body` column, an unclassed column and a ledger
/// table with no sealed column are each reported.
#[test]
fn r_nf_08_teeth_clear_content_column_is_caught() {
    use fstp_migrate::catalogue::ColumnSpec;
    const BAD: &[TableSpec] = &[
        TableSpec {
            schema: "ops",
            name: "outbox",
            class: TableClass::Operational,
            columns: &[
                ColumnSpec {
                    name: "body",
                    class: Some(ColumnClass::Enum),
                },
                ColumnSpec {
                    name: "dest",
                    class: None,
                },
            ],
        },
        TableSpec {
            schema: "ledger",
            name: "entry",
            class: TableClass::LedgerRecord,
            columns: &[ColumnSpec {
                name: "seq",
                class: Some(ColumnClass::Sequence),
            }],
        },
    ];
    assert_eq!(
        clear_content("teeth", BAD).len(),
        3,
        "{:?}",
        clear_content("teeth", BAD)
    );
}

/// R-NF-08 teeth, m4-design section 15.0 (row "R-NF-08 catalogue rule",
/// 2026-11-07): the content-name rule exempts the runner's ledger
/// `fstp_migrate.schema_migrations` by exact schema and table name only.
/// A content-named clear column anywhere else is still reported, even in
/// a table whose schema or name is close to the ledger's.
#[test]
fn r_nf_08_teeth_ledger_exemption_is_exact() {
    use fstp_migrate::catalogue::ColumnSpec;
    const NAME: &[ColumnSpec] = &[ColumnSpec {
        name: "name",
        class: Some(ColumnClass::Enum),
    }];
    let at = |schema: &'static str, name: &'static str| TableSpec {
        schema,
        name,
        class: TableClass::Migration,
        columns: NAME,
    };
    let ledger = [at("fstp_migrate", "schema_migrations")];
    assert!(
        clear_content("teeth", &ledger).is_empty(),
        "{:?}",
        clear_content("teeth", &ledger)
    );
    let near = [
        at("public", "schema_migrations"),
        at("fstp_migrate", "schema_migration"),
        at("fstp_migrate", "other"),
        at("ops", "outbox"),
    ];
    let found = clear_content("teeth", &near);
    assert_eq!(found.len(), near.len(), "{found:#?}");
    let unclassed = [TableSpec {
        schema: "fstp_migrate",
        name: "schema_migrations",
        class: TableClass::Migration,
        columns: &[ColumnSpec {
            name: "name",
            class: None,
        }],
    }];
    assert_eq!(
        clear_content("teeth", &unclassed).len(),
        1,
        "R-NF-08: the exemption never covers an unclassed column"
    );
}

// ---------------------------------------------------------------------------
// R-NF-08: nonces.

/// The length of an AES-256-GCM nonce.
const NONCE_LEN: usize = 12;

/// How many bytes after a nonce tell one ciphertext from another.
const AFTER_LEN: usize = 16;

/// The length of a sealed key (ADR-004 "Sealed key format").
const SEALED_KEY_LEN: usize = 1210;

/// The offset of the nonce in a sealed key: header 30, `E` 32, `ct_M`
/// 1088 (ADR-004).
const SEALED_KEY_NONCE_AT: usize = 1150;

/// One stored seal: where it was found, its nonce, and the bytes that
/// follow the nonce, all in hex.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Seal {
    place: String,
    nonce: String,
    after: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// The offset of the nonce in `value`, a value of a sealed column of
/// `table`.
///
/// - A sealed key (ADR-004): 1210 bytes that start with `FSK1`, nonce at
///   offset 1150.
/// - The bodies of a table with a `key_ix` column, such as `ledger.entry`
///   and `ops.checkpoint`: "random nonce 12 || ciphertext || tag" (design
///   section 4.2), nonce at offset 0.
///
/// Gap, reported by lane W1f and raised to the lead: the layout of every
/// other sealed blob belongs to the ADR that owns its table (ADR-004,
/// "Sealed blobs"), and `fstp_keys::envelope::SealedBlob` exposes no nonce.
/// A nonce accessor there would close this seam. Until then such a value
/// is reported as unread, so the test never passes over a seal it cannot
/// see.
fn nonce_offset(table: &TableSpec, value: &[u8]) -> Result<usize, fstp_celltest::NotImplemented> {
    if value.len() == SEALED_KEY_LEN && value.starts_with(b"FSK1") {
        return Ok(SEALED_KEY_NONCE_AT);
    }
    if table.columns.iter().any(|c| c.name == "key_ix") {
        return Ok(0);
    }
    Err(fstp_celltest::NotImplemented::new(
        "the nonce of a sealed blob outside the key_ix tables \
         (a nonce accessor on fstp_keys::envelope::SealedBlob; gap raised by lane W1f)",
    ))
}

/// The seal of `value` found at `place`, or `None` when the value is too
/// short to hold a nonce and the bytes after it.
fn seal_at(place: String, value: &[u8], at: usize) -> Option<Seal> {
    let nonce = value.get(at..at + NONCE_LEN)?;
    let after = value.get(at + NONCE_LEN..at + NONCE_LEN + AFTER_LEN)?;
    Some(Seal {
        place,
        nonce: hex(nonce),
        after: hex(after),
    })
}

/// The committed seals of every sealed column of `catalogue` in database
/// `dbname` on `server`, and one line for each value whose nonce cannot be
/// read.
fn committed_seals(
    server: &fstp_pgtest::PgServer,
    dbname: &str,
    catalogue: &[TableSpec],
) -> (Vec<Seal>, Vec<String>) {
    let (mut seals, mut unread) = (Vec::new(), Vec::new());
    for t in catalogue {
        for c in t
            .columns
            .iter()
            .filter(|c| c.class == Some(ColumnClass::Sealed))
        {
            let (table, col) = (format!("{}.{}", t.schema, t.name), c.name);
            let out = server
                .psql(
                    dbname,
                    &format!("SELECT encode({col}, 'hex') FROM {table} WHERE {col} IS NOT NULL"),
                )
                .unwrap();
            for line in out.lines().filter(|l| !l.is_empty()) {
                let value = unhex(line);
                let place = format!("{dbname} {table}.{col}");
                match nonce_offset(t, &value) {
                    Ok(at) => match seal_at(place.clone(), &value, at) {
                        Some(s) => seals.push(s),
                        None => {
                            unread.push(format!("{place}: a sealed value of {} bytes", value.len()))
                        }
                    },
                    Err(e) => unread.push(format!("{place}: {e}")),
                }
            }
        }
    }
    (seals, unread)
}

/// Every place where a nonce of `committed` occurs in the WAL stores of
/// `stores`, with the bytes that follow it. A seal whose append aborted
/// left its tuple in the WAL, so a retry that reused its nonce shows here
/// with other bytes after the nonce.
fn wal_seals(stores: &StoreSet, committed: &[Seal]) -> Vec<Seal> {
    let nonces: BTreeSet<Vec<u8>> = committed.iter().map(|s| unhex(&s.nonce)).collect();
    let mut first = vec![false; 1 << 16];
    for n in &nonces {
        first[usize::from(n[0]) << 8 | usize::from(n[1])] = true;
    }
    let mut out = Vec::new();
    for (name, bytes) in stores
        .stores
        .iter()
        .filter(|(n, _)| n.contains("/data/pg_wal/"))
    {
        // Every offset whose nonce and following bytes fit, the last one
        // included.
        for (i, w) in bytes.windows(NONCE_LEN + AFTER_LEN).enumerate() {
            if !first[usize::from(w[0]) << 8 | usize::from(w[1])] {
                continue;
            }
            if nonces.contains(&w[..NONCE_LEN])
                && let Some(s) = seal_at(format!("{name}@{i}"), bytes, i)
            {
                out.push(s);
            }
        }
    }
    out
}

/// The nonces that `seals` show with two different ciphertexts, one line
/// each. The same seal found in a row, a dump and the WAL is one seal.
fn nonce_reuses(seals: &[Seal]) -> Vec<String> {
    let mut by: BTreeMap<&str, BTreeMap<&str, &str>> = BTreeMap::new();
    for s in seals {
        by.entry(&s.nonce)
            .or_default()
            .entry(&s.after)
            .or_insert(&s.place);
    }
    by.into_iter()
        .filter(|(_, afters)| afters.len() > 1)
        .map(|(n, afters)| {
            let places: Vec<&str> = afters.values().copied().collect();
            format!("nonce {n} seals {} ciphertexts: {places:?}", places.len())
        })
        .collect()
}

/// R-NF-08, design section 3.2, ADR-004 "Nonce rule": a run with forced
/// aborts, retries and a replayed step-up leaves no two ciphertexts under
/// one nonce. Every sealed column of the application and vault
/// catalogues is read, and the WAL of every cluster is searched for each
/// committed nonce, so the seal of an aborted append is seen too.
///
/// The WAL holds the tuple of an aborted insert, so it shows a nonce that
/// a retry reused. A seal that never reached any store is not seen. A
/// seal recorder in the harness (lane W1a) would close that last gap.
#[test]
fn r_nf_08_aborted_append_never_reuses_a_nonce() {
    let w = world(1, false, false);
    let script = CycleScript {
        steps: [
            "login",
            "abort-next-append",
            "create-programme",
            "retry",
            "replay-step-up",
            "publish-call",
            "abort-next-append",
            "submit-proposal",
            "retry",
        ]
        .map(str::to_owned)
        .to_vec(),
    };
    w.run_cycle(0, &script)
        .result
        .unwrap_or_else(|e| panic!("the cycle did not run: {e}"));
    let sets = db::migration_sets();
    let (mut seals, mut unread) = (Vec::new(), Vec::new());
    for d in w.databases().unwrap() {
        let set = match d.name.get(..2) {
            Some("c_") => "app",
            Some("v_") => "vault",
            _ => continue,
        };
        let cat = sets.iter().find(|s| s.set == set).unwrap().catalogue;
        let c = w.clusters().iter().find(|c| c.name() == d.cluster).unwrap();
        let (s, u) = committed_seals(c.server(), &d.name, cat);
        seals.extend(s);
        unread.extend(u);
    }
    assert!(
        seals.len() >= 2,
        "the run sealed fewer than two readable values: {seals:?}"
    );
    let mut all = wal_seals(&w.stores().unwrap(), &seals);
    all.extend(seals);
    let mut found = nonce_reuses(&all);
    found.extend(unread);
    assert!(found.is_empty(), "{found:#?}");
}

/// R-NF-08 teeth: a counter nonce that restarts after an abort repeats
/// with another ciphertext, and the check reports it. Random nonces of
/// the same run do not, and one seal seen in two stores is one seal.
#[test]
fn r_nf_08_teeth_counter_nonce_is_caught() {
    let seal = |i: u64, after: u8, place: &str| Seal {
        place: place.to_owned(),
        nonce: format!("{i:024x}"),
        after: hex(&[after; AFTER_LEN]),
    };
    // Three seals, an abort that loses the counter, then three more.
    let mut seals: Vec<Seal> = (0..3).map(|i| seal(i, 0xA0, "first")).collect();
    seals.extend((1..4).map(|i| seal(i, 0xB0, "second")));
    assert_eq!(nonce_reuses(&seals).len(), 2, "{:?}", nonce_reuses(&seals));
    let once = vec![seal(9, 0xC0, "row"), seal(9, 0xC0, "wal")];
    assert!(nonce_reuses(&once).is_empty());
    let random: Vec<Seal> = (0..6)
        .map(|_| {
            let mut n = [0u8; NONCE_LEN + AFTER_LEN];
            fstp_crypto::random_bytes(&mut n).unwrap();
            seal_at("random".to_owned(), &n, 0).unwrap()
        })
        .collect();
    assert!(nonce_reuses(&random).is_empty());
}

/// R-NF-08 teeth for the WAL search: a nonce and its following bytes that
/// end exactly at the end of a WAL store are found, as is one at offset
/// 0. A store too short to hold them gives nothing.
#[test]
fn r_nf_08_teeth_wal_search_reaches_the_last_offset() {
    let mut nonce = [0u8; NONCE_LEN];
    fstp_crypto::random_bytes(&mut nonce).unwrap();
    let committed = vec![Seal {
        place: "row".to_owned(),
        nonce: hex(&nonce),
        after: hex(&[0xA0; AFTER_LEN]),
    }];
    let mut tail = vec![0x55u8; 40];
    tail.extend_from_slice(&nonce);
    tail.extend_from_slice(&[0xB0; AFTER_LEN]);
    let mut head = nonce.to_vec();
    head.extend_from_slice(&[0xC0; AFTER_LEN]);
    let mut stores = StoreSet::default();
    stores.push("application/data/pg_wal/tail", tail);
    stores.push("application/data/pg_wal/head", head);
    stores.push("application/data/pg_wal/short", nonce.to_vec());
    let found = wal_seals(&stores, &committed);
    let at = |place: &str, after: u8| Seal {
        place: place.to_owned(),
        nonce: hex(&nonce),
        after: hex(&[after; AFTER_LEN]),
    };
    assert_eq!(
        found,
        vec![
            at("application/data/pg_wal/tail@40", 0xB0),
            at("application/data/pg_wal/head@0", 0xC0),
        ]
    );
}

/// R-NF-08 teeth on a real cluster: a seal whose insert aborts, then a
/// committed seal that reuses its nonce, leave one committed row. The WAL
/// search finds the aborted seal, and the check reports the reuse. A
/// retry under a fresh nonce is clean.
#[test]
fn r_nf_08_teeth_nonce_reused_after_an_abort_is_caught() {
    use fstp_migrate::catalogue::ColumnSpec;
    const SEALS: &[TableSpec] = &[TableSpec {
        schema: "public",
        name: "seal",
        class: TableClass::LedgerRecord,
        columns: &[
            ColumnSpec {
                name: "key_ix",
                class: Some(ColumnClass::Sequence),
            },
            ColumnSpec {
                name: "body",
                class: Some(ColumnClass::Sealed),
            },
        ],
    }];
    let c = ClusterHandle::start_named(ClusterKind::Application, "w1f_teeth_nonce").unwrap();
    let s = c.server();
    let random_hex = |n: usize| {
        let mut b = vec![0u8; n];
        fstp_crypto::random_bytes(&mut b).unwrap();
        hex(&b)
    };
    let check = |dbname: &str, aborted: &str, committed: &str| {
        s.psql(
            dbname,
            &format!(
                "CREATE TABLE seal (key_ix integer NOT NULL, body bytea NOT NULL);\n\
                 BEGIN; INSERT INTO seal VALUES (1, '\\x{aborted}'); ROLLBACK;\n\
                 INSERT INTO seal VALUES (1, '\\x{committed}');"
            ),
        )
        .unwrap();
        let (seals, unread) = committed_seals(s, dbname, SEALS);
        assert!(unread.is_empty(), "{unread:?}");
        assert_eq!(seals.len(), 1, "{seals:?}");
        let stores = fstp_celltest::world::cluster_stores(c.name(), s).unwrap();
        let mut all = wal_seals(&stores, &seals);
        assert!(!all.is_empty(), "the committed seal is not in the WAL");
        all.extend(seals);
        nonce_reuses(&all)
    };
    let nonce = random_hex(NONCE_LEN);
    let reused = check(
        &db::fresh_database(s, "w1f_teeth_nonce").unwrap(),
        &format!("{nonce}{}", random_hex(32)),
        &format!("{nonce}{}", random_hex(32)),
    );
    assert_eq!(reused.len(), 1, "{reused:#?}");
    let fresh = check(
        &db::fresh_database(s, "w1f_teeth_nonce").unwrap(),
        &random_hex(NONCE_LEN + 32),
        &random_hex(NONCE_LEN + 32),
    );
    assert!(fresh.is_empty(), "{fresh:#?}");
}

/// Test-only crates, which never ship.
const TEST_ONLY: [&str; 2] = ["fstp-celltest", "fstp-domain-testkit"];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The public functions of `source` that take a caller nonce, as their
/// names. A function whose name starts with `open` or `decrypt` takes the
/// stored nonce of a sealed value, which is not a caller nonce.
fn nonce_apis(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in source.match_indices("pub fn ") {
        let rest = &source[i + 7..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let sig_end = rest.find(['{', ';']).unwrap_or(rest.len());
        let sig = &rest[..sig_end];
        let Some(open) = sig.find('(') else { continue };
        let params = &sig[open..];
        let takes = params
            .split([',', '('])
            .map(str::trim)
            .any(|p| p.starts_with("nonce:") || p.starts_with("iv:") || p.contains("Nonce"));
        if takes && !name.starts_with("open") && !name.starts_with("decrypt") {
            out.push(name);
        }
    }
    out
}

/// The public functions that take a nonce which is no seal nonce, as
/// `(crate, function)`, each with its reason.
///
/// - `fstp-pgwire` `with_nonce`: the SCRAM client nonce of an M1
///   known-answer test entry point. It seals nothing at rest.
const NOT_SEALS: [(&str, &str); 1] = [("fstp-pgwire", "with_nonce")];

/// R-NF-08, design section 3.2: no public function of a shipped crate
/// takes a nonce from its caller for sealing. Every seal draws its own.
#[test]
fn r_nf_08_no_api_takes_a_caller_nonce() {
    let mut found = Vec::new();
    let mut scanned = 0usize;
    for e in std::fs::read_dir(db::workspace_root().join("crates")).unwrap() {
        let c = e.unwrap().path();
        let name = c.file_name().unwrap().to_string_lossy().into_owned();
        if TEST_ONLY.contains(&name.as_str()) {
            continue;
        }
        let mut files = Vec::new();
        rust_files(&c.join("src"), &mut files);
        for f in files {
            scanned += 1;
            let text = std::fs::read_to_string(&f).unwrap();
            for api in nonce_apis(&text) {
                if !NOT_SEALS.contains(&(name.as_str(), api.as_str())) {
                    found.push(format!("{}: {api}", f.display()));
                }
            }
        }
    }
    assert!(scanned > 100, "only {scanned} files were scanned");
    assert!(found.is_empty(), "{found:#?}");
}

/// R-NF-08 teeth: the scan finds a seal that takes a nonce, across lines,
/// and passes an open that takes the stored one.
#[test]
fn r_nf_08_teeth_caller_nonce_api_is_caught() {
    let src = "pub fn seal_with(\n    key: &Key,\n    nonce: [u8; 12],\n) -> Vec<u8> {}\n\
               pub fn open(key: &Key, nonce: &[u8; 12]) -> Vec<u8> {}\n\
               pub fn encrypt(k: &Key, n: aead::Nonce) {}\n";
    assert_eq!(nonce_apis(src), vec!["seal_with", "encrypt"]);
}

// ---------------------------------------------------------------------------
// R-NF-09 (ADR-009 "R-NF-09 reading", Q34).

/// R-NF-09, ADR-005 D2, ADR-009: on every self-operated cluster each
/// accepting `pg_hba` line requires `hostssl` and `clientcert=verify-full`,
/// and every cell role is refused without a client certificate while its
/// own certificate logs it in.
#[test]
fn r_nf_09_every_internal_link_requires_a_client_certificate() {
    let w = world(1, false, false);
    let mut found = Vec::new();
    for c in agent_clusters(&w) {
        for h in db::hba_rows(c.server()).unwrap() {
            if h.rule.method != "reject"
                && (h.rule.kind != "hostssl"
                    || !h.options.split(',').any(|o| o == "clientcert=verify-full"))
            {
                found.push(format!("{}: {h:?}", c.name()));
            }
        }
        let ca = ca_pem(c);
        for role in db::cell_login_roles(c.server()).unwrap() {
            let cred = db::take_over(c.server(), &role).unwrap();
            let dbname = role.rsplit_once('_').map(|(d, _)| d.to_owned()).unwrap();
            if db::run_as(c.server(), &ca, &cred, false, &dbname, "SELECT 1").is_ok() {
                found.push(format!(
                    "{}: {role} logged in without a certificate",
                    c.name()
                ));
            }
            if db::run_as(c.server(), &ca, &cred, true, &dbname, "SELECT 1").is_err() {
                found.push(format!(
                    "{}: {role} cannot log in with its certificate",
                    c.name()
                ));
            }
        }
    }
    assert!(found.is_empty(), "{found:#?}");
}

/// The component links ADR-009 claims for R-NF-09, by egress peer.
const CLAIMED: [Peer; 3] = [Peer::Vault, Peer::ControlPlane, Peer::Witness];

/// The external links ADR-009 lists as not claimed, or claimed only once
/// a verify item settles (Q34, Q11): custody (OKMS) and CrabNebula hosts.
const EXCEPTIONS: [Peer; 2] = [Peer::Custody, Peer::CrabNebula];

/// One recorded TLS handshake of a world: the peer, and whether the
/// client presented a certificate that the peer verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Handshake {
    peer: Peer,
    client_certificate_verified: bool,
}

/// The TLS handshakes of `w`, one per connection.
///
/// Lane F-ISO wired the record: each link of a world cell runs through a
/// recording relay (`fstp_celltest::relay`), which records every
/// handshake with whether the cell presented a client certificate that
/// verified under the cell CA. A failed handshake is recorded as not
/// verified.
fn handshakes(w: &World) -> Result<Vec<Handshake>, fstp_celltest::NotImplemented> {
    Ok(w.egress()
        .handshakes()
        .into_iter()
        .map(|h| Handshake {
            peer: h.route.to,
            client_certificate_verified: h.client_certificate_verified,
        })
        .collect())
}

/// The R-NF-09 breaches of the peers contacted and the handshakes
/// recorded, one line each: a peer that is neither claimed nor a listed
/// exception, a claimed peer contacted with no handshake recorded, and a
/// handshake to a claimed peer without a verified client certificate.
fn handshake_breaches(peers: &[Peer], shakes: &[Handshake]) -> Vec<String> {
    let mut out = Vec::new();
    for p in peers {
        if !CLAIMED.contains(p) && !EXCEPTIONS.contains(p) {
            out.push(format!(
                "{p:?} is neither a claimed link nor a listed exception"
            ));
        }
        if CLAIMED.contains(p) && !shakes.iter().any(|h| h.peer == *p) {
            out.push(format!("{p:?} was contacted with no handshake recorded"));
        }
    }
    for h in shakes {
        if CLAIMED.contains(&h.peer) && !h.client_certificate_verified {
            out.push(format!(
                "{:?} accepted a client with no certificate",
                h.peer
            ));
        }
    }
    out
}

/// R-NF-09, ADR-009: in a world in process mode, every peer a component
/// contacts is a claimed internal link or a listed exception, and each
/// claimed link's handshake shows a verified client certificate.
#[test]
fn r_nf_09_every_internal_link_is_mutually_authenticated() {
    let w = world(1, false, true);
    let script = CycleScript {
        steps: ["login", "create-programme", "submit-proposal"]
            .map(str::to_owned)
            .to_vec(),
    };
    w.run_cycle(0, &script)
        .result
        .unwrap_or_else(|e| panic!("the cycle did not run: {e}"));
    let peers = w.egress().peers_contacted();
    assert!(
        peers.iter().any(|p| CLAIMED.contains(p)),
        "the cycle contacted no claimed link, so the check is vacuous: {peers:?}"
    );
    let found = match handshakes(&w) {
        Ok(shakes) => handshake_breaches(&peers, &shakes),
        Err(e) => vec![format!("{e}; peers contacted: {peers:?}")],
    };
    assert!(found.is_empty(), "{found:#?}");
}

/// R-NF-09 teeth: a claimed peer with no handshake and a handshake with no
/// client certificate are each reported. Mutual handshakes to claimed
/// peers and a contact with an exception are not. Every `Peer` is claimed
/// or an exception, so no unclaimed peer can be built.
#[test]
fn r_nf_09_teeth_handshake_breaches_are_caught() {
    let mutual = |peer| Handshake {
        peer,
        client_certificate_verified: true,
    };
    let clean = handshake_breaches(
        &[Peer::Vault, Peer::Witness, Peer::Custody],
        &[mutual(Peer::Vault), mutual(Peer::Witness)],
    );
    assert!(clean.is_empty(), "{clean:#?}");
    let found = handshake_breaches(
        &[Peer::Vault, Peer::ControlPlane, Peer::Witness],
        &[
            mutual(Peer::Vault),
            Handshake {
                peer: Peer::Witness,
                client_certificate_verified: false,
            },
        ],
    );
    assert_eq!(found.len(), 2, "{found:#?}");
}

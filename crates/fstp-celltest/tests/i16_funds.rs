//! I-16: the platform never holds or controls funds (design section 14.4,
//! ADR-009 "Outbound destinations").
//!
//! The claim in M3 is structural (Q33): no crate builds a payment
//! instruction, no schema has a class for a balance or a held amount, no
//! configuration type names a debtor account, and no outbound destination
//! reaches a payment service. Payment adapters arrive in M5 and must take
//! their credentials from the tenant's vault.
//!
//! Lane W1f wrote these tests before the production code. The schema test
//! is red until every migration set exists and matches its catalogue
//! (lanes W2d, W2e, W2g, W2h and W2j). The structural tests hold on the
//! stubs already, and their teeth show that each scan can fail.
//! `i16_teeth_seeded_instruction_crate_is_caught` for the `funds` rule of
//! `tools/deps-check` lives in `tools/deps-check/tests/m3_rules.rs` (lane
//! W0).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};

use fstp_cell::Destination;
use fstp_celltest::mc::place_model::db;
use fstp_celltest::world::ClusterHandle;
use fstp_migrate::catalogue::TableClass;
use fstp_release::egress::CnCall;
use fstp_vault::VaultDestination;

// ---------------------------------------------------------------------------
// Source scans.

/// The payment terms no crate may name: ISO 20022 pain.001 element names,
/// its document namespace, and payment account and credential type names.
/// The same list as the fixture of the `funds` rule (design section 2.4
/// rule 11), transcribed here on its own.
const PAYMENT_TERMS: [&str; 17] = [
    "CstmrCdtTrfInitn",
    "CdtTrfTxInf",
    "PmtInf",
    "DbtrAcct",
    "CdtrAcct",
    "DbtrAgt",
    "CdtrAgt",
    "InstdAmt",
    "ReqdExctnDt",
    "urn:iso:std:iso:20022:tech:xsd:pain.",
    "DebtorAccount",
    "CreditorAccount",
    "PaymentInstruction",
    "CreditTransferInstruction",
    "PaymentInitiation",
    "BankCredential",
    "PaymentCredential",
];

fn root() -> PathBuf {
    db::workspace_root()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Every shipped source file of every crate under `crates/`: `src/**` and
/// `build.rs`, as `(crate, path)`.
fn crate_sources() -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let mut crates: Vec<PathBuf> = std::fs::read_dir(root().join("crates"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.join("Cargo.toml").is_file())
        .collect();
    crates.sort();
    for c in crates {
        let name = c.file_name().unwrap().to_string_lossy().into_owned();
        let mut files = Vec::new();
        rust_files(&c.join("src"), &mut files);
        if c.join("build.rs").is_file() {
            files.push(c.join("build.rs"));
        }
        out.extend(files.into_iter().map(|f| (name.clone(), f)));
    }
    out
}

/// Every payment term in `text`, as `(line, term)`.
fn payment_terms_in(text: &str) -> Vec<(usize, &'static str)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        for term in PAYMENT_TERMS {
            if line.contains(term) {
                out.push((i + 1, term));
            }
        }
    }
    out
}

/// The crates `deps/funds-allowed.txt` lists.
fn funds_allowed() -> Vec<String> {
    let text = std::fs::read_to_string(root().join("deps/funds-allowed.txt")).unwrap_or_default();
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// I-16, design section 14.4: no crate names a SEPA credit transfer element
/// or a payment account or credential type, and `deps/funds-allowed.txt`
/// is empty in M3.
#[test]
fn i16_no_crate_builds_payment_instructions() {
    assert!(
        funds_allowed().is_empty(),
        "deps/funds-allowed.txt lists {:?} in M3",
        funds_allowed()
    );
    let sources = crate_sources();
    assert!(
        sources.iter().any(|(c, _)| c == "fstp-cell"),
        "the scan found no fstp-cell source, so it scans nothing"
    );
    let mut hits = Vec::new();
    for (krate, path) in sources {
        let text = std::fs::read_to_string(&path).unwrap();
        for (line, term) in payment_terms_in(&text) {
            hits.push(format!("{krate}: {}:{line} names {term}", path.display()));
        }
    }
    assert!(hits.is_empty(), "{hits:#?}");
}

/// I-16 teeth: the source scan finds a seeded pain.001 element and a
/// payment account type, and passes a source with neither.
#[test]
fn i16_teeth_seeded_instruction_source_is_caught() {
    let seeded = "pub struct Tx { inf: CdtTrfTxInf }\nfn pay(_: DebtorAccount) {}\n";
    let hits = payment_terms_in(seeded);
    assert_eq!(hits, vec![(1, "CdtTrfTxInf"), (2, "DebtorAccount")]);
    assert!(payment_terms_in("pub fn approve_payment() {}\n").is_empty());
}

// ---------------------------------------------------------------------------
// Configuration types.

/// Words a configuration field type may not hold: a payment account, a
/// bank identifier or a payment credential.
const ACCOUNT_WORDS: [&str; 8] = [
    "Iban", "IBAN", "Bic", "BIC", "Bank", "Debtor", "Creditor", "Payment",
];

/// The field types of `struct name { ... }` in `source`, as written.
fn field_types(source: &str, name: &str) -> Option<Vec<String>> {
    let start = source.find(&format!("pub struct {name} {{"))?;
    let body = source.get(start..)?;
    let open = body.find('{')?;
    let close = body.find("\n}")?;
    let fields = body.get(open + 1..close)?;
    Some(
        fields
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//") && !l.starts_with('#') && l.contains(':'))
            .filter_map(|l| {
                l.split_once(':')
                    .map(|(_, t)| t.trim().trim_end_matches(',').to_owned())
            })
            .collect(),
    )
}

/// The account words and payment terms in `types`.
fn account_types(types: &[String]) -> Vec<String> {
    types
        .iter()
        .filter(|t| {
            ACCOUNT_WORDS.iter().any(|w| t.contains(w))
                || PAYMENT_TERMS.iter().any(|w| t.contains(w))
        })
        .cloned()
        .collect()
}

/// I-16, design section 14.4: `CellConfig` and `ControlConfig` have no
/// field of a payment account or credential type.
#[test]
fn i16_config_types_hold_no_debtor_account() {
    for (file, name) in [
        ("crates/fstp-cell/src/config.rs", "CellConfig"),
        ("crates/fstp-control/src/lib.rs", "ControlConfig"),
    ] {
        let source = std::fs::read_to_string(root().join(file)).unwrap();
        let types = field_types(&source, name)
            .unwrap_or_else(|| panic!("{file} defines no `pub struct {name}`"));
        assert!(
            !types.is_empty(),
            "{name} has no field, so the scan is vacuous"
        );
        let bad = account_types(&types);
        assert!(bad.is_empty(), "{name} holds {bad:?}");
    }
}

/// I-16 teeth: the configuration scan finds a seeded debtor account field.
#[test]
fn i16_teeth_config_scan_catches_a_debtor_account_field() {
    let seeded = "pub struct CellConfig {\n    /// The cell.\n    pub cell: CellId,\n    \
                  pub payout: Option<DebtorAccount>,\n    pub iban: IbanText,\n}\n";
    let types = field_types(seeded, "CellConfig").unwrap();
    assert_eq!(types, vec!["CellId", "Option<DebtorAccount>", "IbanText"]);
    assert_eq!(
        account_types(&types),
        vec!["Option<DebtorAccount>", "IbanText"]
    );
}

// ---------------------------------------------------------------------------
// Outbound destinations (ADR-009).

/// What an outbound destination reaches, as ADR-009 lists it. Closed, and
/// no member is a payment service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    /// The cell's or vault's own database.
    OwnDatabase,
    /// The cell's own vault.
    OwnVault,
    /// The process's own custody entries.
    OwnCustody,
    /// The control plane, SaaS only.
    ControlPlane,
    /// The witness.
    Witness,
    /// The CrabNebula update service, self-hosted only.
    UpdateService,
    /// The CrabNebula licence service, self-hosted only.
    LicenceService,
    /// The `<cell>/keystore/` object storage prefix.
    KeystorePrefix,
    /// The tenant's mail submission relay (ADR-018). It carries mail only.
    MailRelay,
}

/// The exhaustive map of `Destination`. A new variant fails to compile
/// here, so it cannot arrive without a review against ADR-009.
fn cell_reach(d: &Destination) -> Reach {
    match d {
        Destination::AppDatabase => Reach::OwnDatabase,
        Destination::Vault => Reach::OwnVault,
        Destination::Custody => Reach::OwnCustody,
        Destination::ControlPlane => Reach::ControlPlane,
        Destination::Witness => Reach::Witness,
        Destination::CrabNebula(CnCall::Update(_)) => Reach::UpdateService,
        Destination::CrabNebula(CnCall::Licence(_)) => Reach::LicenceService,
        Destination::KeystoreSnapshots => Reach::KeystorePrefix,
        Destination::MailSubmission { .. } => Reach::MailRelay,
    }
}

/// The exhaustive map of `VaultDestination`.
fn vault_reach(d: &VaultDestination) -> Reach {
    match d {
        VaultDestination::VaultDatabase => Reach::OwnDatabase,
        VaultDestination::Custody => Reach::OwnCustody,
        VaultDestination::Witness => Reach::Witness,
        VaultDestination::KeystoreSnapshots => Reach::KeystorePrefix,
    }
}

/// I-16, B4, B4a, ADR-009: every member of the closed outbound enums of the
/// cell and the vault reaches a platform component, the process's own
/// custody or storage, or a CrabNebula release service. None reaches a
/// payment service or names a platform account.
#[test]
fn i16_cell_egress_has_no_payment_destination() {
    let cell = [
        Destination::AppDatabase,
        Destination::Vault,
        Destination::Custody,
        Destination::ControlPlane,
        Destination::Witness,
        Destination::KeystoreSnapshots,
        Destination::MailSubmission {
            host: fstp_cell::egress::MailHost::parse("smtp.relay.example").unwrap(),
        },
    ];
    let reached: Vec<Reach> = cell.iter().map(cell_reach).collect();
    assert_eq!(
        reached,
        vec![
            Reach::OwnDatabase,
            Reach::OwnVault,
            Reach::OwnCustody,
            Reach::ControlPlane,
            Reach::Witness,
            Reach::KeystorePrefix,
            Reach::MailRelay,
        ]
    );
    let vault = [
        VaultDestination::VaultDatabase,
        VaultDestination::Custody,
        VaultDestination::Witness,
        VaultDestination::KeystoreSnapshots,
    ];
    let reached: Vec<Reach> = vault.iter().map(vault_reach).collect();
    assert_eq!(
        reached,
        vec![
            Reach::OwnDatabase,
            Reach::OwnCustody,
            Reach::Witness,
            Reach::KeystorePrefix,
        ]
    );
    let source = std::fs::read_to_string(root().join("crates/fstp-cell/src/egress.rs")).unwrap();
    assert!(payment_terms_in(&source).is_empty());
}

// ---------------------------------------------------------------------------
// Schemas (design section 4.5).

/// Words no table or column of a cell or control-plane schema may hold: a
/// balance, a held amount, a wallet or a payment account.
const FUND_WORDS: [&str; 9] = [
    "balance", "held", "escrow", "wallet", "funds", "iban", "debtor", "creditor", "payout",
];

/// The fund words in the names of `tables`, one line each.
fn fund_names(tables: &std::collections::BTreeMap<(String, String), Vec<String>>) -> Vec<String> {
    let mut out = Vec::new();
    for ((s, t), cols) in tables {
        for name in std::iter::once(t).chain(cols) {
            let lower = name.to_ascii_lowercase();
            if let Some(w) = FUND_WORDS.iter().find(|w| lower.contains(*w)) {
                out.push(format!("{s}.{t}: {name} holds {w}"));
            }
        }
    }
    out
}

/// Whether a table class can hold funds. The match is exhaustive, so a new
/// class fails to compile until it is reviewed (I-16).
fn class_holds_funds(c: TableClass) -> bool {
    match c {
        TableClass::LedgerRecord
        | TableClass::AuditEvent
        | TableClass::SealedContent
        | TableClass::KeyMaterial
        | TableClass::Operational
        | TableClass::Migration
        | TableClass::Placement => false,
    }
}

/// I-16, R-NF-08, design section 4.5: every migration set applied to a
/// fresh database of its cluster kind creates exactly the tables and
/// columns of its owner's catalogue. No table class holds funds, and no
/// table or column is named for a balance or a held amount.
#[test]
fn i16_schemas_have_no_fund_class() {
    let mut failures = Vec::new();
    for set in db::migration_sets() {
        for t in set.catalogue {
            assert!(!class_holds_funds(t.class), "{}.{}", t.schema, t.name);
        }
        let cluster = ClusterHandle::start(set.kind).unwrap();
        let name = match db::migrated(cluster.server(), &set) {
            Ok(n) => n,
            Err(e) => {
                failures.push(e);
                continue;
            }
        };
        let tables = db::table_columns(cluster.server(), &name).unwrap();
        for d in db::catalogue_diff(&tables, &db::catalogue_columns(set.catalogue)) {
            failures.push(format!("{}: {d}", set.set));
        }
        failures.extend(fund_names(&tables));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// I-16 teeth: a seeded balance table is reported as uncatalogued and as a
/// fund name.
#[test]
fn i16_teeth_seeded_balance_table_is_caught() {
    let mut tables = std::collections::BTreeMap::new();
    tables.insert(
        ("ops".to_owned(), "account_balance".to_owned()),
        vec!["id".to_owned(), "held_amount".to_owned()],
    );
    let diff = db::catalogue_diff(&tables, &db::catalogue_columns(fstp_control::CATALOGUE));
    assert!(
        diff.iter()
            .any(|d| d == "ops.account_balance is not catalogued"),
        "{diff:?}"
    );
    assert_eq!(fund_names(&tables).len(), 2, "{:?}", fund_names(&tables));
}

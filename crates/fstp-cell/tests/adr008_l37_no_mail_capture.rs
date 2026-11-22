//! The production cell cannot capture mail or serve a demo inbox (ADR-008
//! record of lane L37, layering rule A9). Lane L37.
//!
//! The demo emulates its email links in the test-only binary
//! `fstp-e2e-cell`, behind its `--demo-signin` flag. The production cell
//! keeps its mail path: no argument, configuration member or route of
//! `fstp-cell` turns a capture on, and no production source names the
//! inbox. Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

const CELL: &str = "000102030405060708090a0b0c0d0e0f";

/// A complete SaaS configuration file, with `extra` members added and the
/// `mail` member `mail`.
fn file(extra: &str, mail: &str) -> String {
    let spki = "ab".repeat(32);
    format!(
        r#"{{"cell":"{CELL}","credentials_dir":"/etc/fstp/cell","database":{{"dbname":"c_{CELL}","host":"db.internal","port":5432}},"host":"grants.example.test","key_file_keyd_socket":"/run/fstp-keyd/cell-keys.sock","keyd_socket":"/run/fstp-keyd/cell.sock","listen":{{"health":"127.0.0.1:9090","internal":"0.0.0.0:7444","tunnel":"0.0.0.0:7443"}},"mail":{{"relay":"smtp.example.test","sender":"noreply@example.test","username":"synthetic"{mail}}},"mode":"saas","registered_servers":[{{"kind":"application","spki_sha256":"{spki}"}}],"vault":{{"address":"127.0.0.1:4100"}},"version":"0.3.0","witness":{{"address":"10.0.0.5:7443","ca_spki_sha256":"{spki}","server_name":"witness.internal"}}{extra}}}"#
    )
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_owned()).collect()
}

/// Every `.rs` file under `dir`.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// ADR-008 (lane L37), layering rule A9: the production cell refuses
/// every demo flag and every configuration member that would capture mail,
/// so its mail path stays the relay. Its sources name no demo inbox, and
/// it does not depend on the test kit that holds the demo cell.
#[test]
fn adr008_l37_production_cell_cannot_capture_mail() {
    // No argument turns a capture or the demo sign-in on.
    for flag in [
        "--demo-signin",
        "--demo-inbox",
        "--capture-mail",
        "--mail-capture",
    ] {
        assert!(
            fstp_cell::run::parse_args(&args(&[flag])).is_err(),
            "fstp-cell takes {flag}"
        );
        assert!(
            fstp_cell::run::parse_args(&args(&["first-admin", flag, "out"])).is_err(),
            "fstp-cell first-admin takes {flag}"
        );
    }
    // The configuration file: the plain file decodes, and no member that
    // would capture mail does, at the top or in `mail`.
    assert!(
        fstp_cell::config::decode_file(file("", "").as_bytes()).is_ok(),
        "the plain file decodes"
    );
    for member in ["demo_signin", "demo_inbox", "capture_mail", "mail_capture"] {
        let top = file(&format!(r#","{member}":true"#), "");
        assert!(
            fstp_cell::config::decode_file(top.as_bytes()).is_err(),
            "the file takes {member}"
        );
        let in_mail = file("", &format!(r#","{member}":true"#));
        assert!(
            fstp_cell::config::decode_file(in_mail.as_bytes()).is_err(),
            "the mail member takes {member}"
        );
    }
    // No production source names the inbox or its route.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    sources(&root.join("src"), &mut files);
    assert!(!files.is_empty());
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        for needle in ["/demo/inbox", "Demo inbox", "--demo-signin"] {
            assert!(!text.contains(needle), "{} names {needle}", f.display());
        }
    }
    // The cell does not depend on the test kit that holds the demo cell.
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .and_then(|s| s.split("\n[").next())
        .unwrap();
    assert!(
        !deps.contains("fstp-api-testkit"),
        "fstp-cell depends on the test kit"
    );
}

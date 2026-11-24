//! Each service's own configuration file, written from the host
//! configuration (ADR-028 "Service configs are generated, never parsed
//! back"). The forms are those of ADR-026 (cell, vault), ADR-010 open
//! point 6 (witness), ADR-009 "Pilot edge configuration" (edge) and
//! ADR-012 (backup). The vault's file is written in its canonical
//! one-line form.

use std::path::Path;

use crate::config::quote;
use crate::layout::{Cluster, Entry, Layout};
use crate::pki::hex;

/// The witness server name the cell and the vault pin.
pub const WITNESS_NAME: &str = "witness.fstp.internal";
/// The cell's tunnel server name.
pub const CELL_TUNNEL_NAME: &str = "cell.tunnel.fstp.internal";
/// The vault's tunnel server name.
pub const VAULT_TUNNEL_NAME: &str = "vault.tunnel.fstp.internal";

/// What the renderers need beyond the layout.
#[derive(Clone, Debug)]
pub struct Facts {
    /// The cell id.
    pub cell: [u8; 16],
    /// The SPKI digest of the application cluster's server certificate.
    pub app_server_spki: [u8; 32],
    /// The SPKI digest of the vault cluster's server certificate.
    pub vault_server_spki: [u8; 32],
    /// The SPKI digest of the witness CA.
    pub witness_ca_spki: [u8; 32],
    /// The witness receipt public keys, hex.
    pub receipt_keys: Vec<String>,
    /// The cell's ticket public key, hex, once `init-keys` wrote it.
    pub ticket_key: Option<String>,
    /// Whether the web assets are installed.
    pub assets: bool,
    /// The edge id of the route feed (lane L15), 32 hex digits.
    pub edge_id: Option<String>,
}

fn p(path: &Path) -> String {
    quote(&path.display().to_string())
}

fn registered(f: &Facts) -> String {
    format!(
        "[{{\"kind\":\"application\",\"spki_sha256\":\"{}\"}},{{\"kind\":\"vault\",\"spki_sha256\":\"{}\"}}]",
        hex(&f.app_server_spki),
        hex(&f.vault_server_spki)
    )
}

/// The `object_store` member of `cell.json` and `vault.json`, with its
/// trailing comma: the backups' bucket, when `fstp.json` names one
/// (ADR-028 record of lane L27, row "Turned on with backups").
fn object_store(l: &Layout) -> String {
    l.cfg.backup.as_ref().map_or_else(String::new, |b| {
        format!(
            "\"object_store\":{{\"bucket\":{},\"endpoint\":{},\"port\":{},\"region\":{}}},",
            quote(&b.bucket),
            quote(&b.endpoint),
            b.port,
            quote(&b.region)
        )
    })
}

/// `cell.json` (ADR-026 "Configuration").
#[must_use]
pub fn cell(l: &Layout, f: &Facts) -> String {
    let m = &l.cfg.mail;
    let address = m
        .address
        .map(|a| format!("\"address\":\"{a}\","))
        .unwrap_or_default();
    let assets = if f.assets {
        format!("\"assets_dir\":{},", p(&l.assets()))
    } else {
        String::new()
    };
    // ADR-026 section of lane `m10/checks-runner`: the forge allowlist of
    // the payment checks, when the host names one.
    let checks = if l.cfg.forges.is_empty() {
        String::new()
    } else {
        let hosts: Vec<String> = l.cfg.forges.iter().map(|h| quote(h)).collect();
        format!("\"checks\":{{\"forge_hosts\":[{}]}},", hosts.join(","))
    };
    format!(
        "{{{assets}\"cell\":\"{cell}\",{checks}\"credentials_dir\":{creds},\
         \"database\":{{\"dbname\":\"c_{cell}\",\"host\":\"127.0.0.1\",\"port\":{app_port}}},\
         \"host\":{host},\"host_status\":{status},\"key_file_keyd_socket\":{kf},\"keyd_socket\":{keyd},\
         \"listen\":{{\"health\":\"{health}\",\"internal\":\"{internal}\",\"tunnel\":\"{tunnel}\"}},\
         \"mail\":{{{address}\"relay\":{relay},\"sender\":{sender},\"username\":{user}}},\
         \"mode\":\"saas\",{os}\"registered_servers\":{reg},\
         \"vault\":{{\"address\":\"{vault}\"}},\"version\":{version},\
         \"witness\":{{\"address\":\"{waddr}\",\"ca_spki_sha256\":\"{wca}\",\"server_name\":\"{WITNESS_NAME}\"}}}}\n",
        cell = hex(&f.cell),
        creds = p(&l.creds("cell")),
        app_port = l.pg_port(Cluster::App),
        host = quote(&l.cfg.domain),
        status = p(&l.host_status()),
        kf = p(&l.keyd_socket(Entry::CellKeys, "cell")),
        keyd = p(&l.keyd_socket(Entry::Cell, "cell")),
        health = l.cell_health(),
        internal = l.cell_internal(),
        tunnel = l.cell_tunnel(),
        relay = quote(&m.relay),
        sender = quote(&m.sender),
        user = quote(&m.username),
        reg = registered(f),
        vault = l.vault_internal(),
        os = object_store(l),
        version = quote(&l.cfg.version),
        waddr = l.witness(),
        wca = hex(&f.witness_ca_spki),
    )
}

/// `vault.json` in its canonical one-line form (ADR-026 record of lane
/// L8). `None` until the cell's ticket key exists.
#[must_use]
pub fn vault(l: &Layout, f: &Facts) -> Option<String> {
    let ticket = f.ticket_key.as_ref()?;
    let receipts: Vec<String> = f.receipt_keys.iter().map(|k| format!("\"{k}\"")).collect();
    let text = format!(
        "{{\"cell\":\"{cell}\",\"credentials_dir\":{creds},\
         \"database\":{{\"dbname\":\"v_{cell}\",\"host\":\"127.0.0.1\",\"port\":{port}}},\
         \"internal_listen\":\"{internal}\",\"keyd_socket\":{keyd},\"origin_host\":{origin},\
         \"origin_listen\":\"{olisten}\",{os}\"registered_servers\":{reg},\"ticket_keys\":[\"{ticket}\"],\
         \"witness\":{{\"address\":\"{waddr}\",\"ca_spki_sha256\":\"{wca}\",\"receipt_keys\":[{rk}],\"server_name\":\"{WITNESS_NAME}\"}}}}",
        cell = hex(&f.cell),
        creds = p(&l.creds("vault")),
        port = l.pg_port(Cluster::Vault),
        internal = l.vault_internal(),
        keyd = p(&l.keyd_socket(Entry::Vault, "vault")),
        origin = quote(&l.vault_host()),
        olisten = l.vault_origin(),
        reg = registered(f),
        os = object_store(l),
        waddr = l.witness(),
        wca = hex(&f.witness_ca_spki),
        rk = receipts.join(","),
    );
    let canonical = fstp_json::parse(text.as_bytes())
        .ok()?
        .to_canonical()
        .ok()?;
    Some(format!("{canonical}\n"))
}

/// `witness.json`, the self-hosted file-store form.
#[must_use]
pub fn witness(l: &Layout) -> String {
    format!(
        "{{\"credentials_dir\":{},\"keyd_socket\":{},\"listen\":\"{}\",\"mode\":\"self_hosted\",\"store_dir\":{}}}\n",
        p(&l.creds("witness")),
        p(&l.keyd_socket(Entry::Witness, "witness")),
        l.witness(),
        p(&l.witness_store()),
    )
}

/// `edge.json`, the route-file form of `main` (ADR-009 "Pilot edge
/// configuration").
#[must_use]
pub fn edge(l: &Layout) -> String {
    format!(
        "{{\"credentials_dir\":{},\"listen\":{{\"public\":\"{}\"}},\"routes\":{}}}\n",
        p(&l.creds("edge")),
        l.edge_public(),
        p(&l.edge_routes()),
    )
}

/// The feed server name of the pilot `fstp-control` (lane L15).
pub const FEED_NAME: &str = "control.tunnel.fstp.internal";

/// `control.json`, the pilot route feed of lane L15 ([`crate::route::ROUTE_FEED`]).
#[must_use]
pub fn control(l: &Layout, edge_id: &str) -> String {
    format!(
        "{{\"credentials_dir\":{},\"edges\":[\"{edge_id}\"],\"feed_listen\":\"{}\",\"keyd_socket\":{},\"operator_socket\":{},\"state_dir\":{}}}\n",
        p(&l.creds("control")),
        l.feed(),
        p(&l.keyd_socket(Entry::Control, "control")),
        p(&l.state("control").join("routes.sock")),
        p(&l.state("control")),
    )
}

/// `edge.json` in the route feed form of lane L15: the feed address and
/// the pin of the feed certificate.
#[must_use]
pub fn edge_feed(l: &Layout, feed_pin: &str) -> String {
    format!(
        "{{\"credentials_dir\":{},\"feed\":{{\"address\":\"{}\",\"cert_sha256\":[\"{feed_pin}\"],\"server_name\":\"{FEED_NAME}\"}},\"listen\":{{\"public\":\"{}\"}},\"state_dir\":{}}}\n",
        p(&l.creds("edge")),
        l.feed(),
        l.edge_public(),
        p(&l.state("edge")),
    )
}

/// One route of the edge: the cell's host to its two tunnel listeners.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// The cell id, 32 hex digits.
    pub cell: String,
    /// The host.
    pub host: String,
    /// The cell's tunnel listener.
    pub app: String,
    /// The pin of the cell's tunnel certificate.
    pub app_pin: String,
    /// The vault's tunnel listener.
    pub vault: String,
    /// The pin of the vault's tunnel certificate.
    pub vault_pin: String,
}

/// One route as the object of a route file.
#[must_use]
pub fn route_object(r: &Route) -> String {
    format!(
        "{{\"app\":{{\"address\":\"{}\",\"cert_sha256\":\"{}\",\"server_name\":\"{CELL_TUNNEL_NAME}\"}},\"cell\":\"{}\",\"host\":{},\"vault\":{{\"address\":\"{}\",\"cert_sha256\":\"{}\",\"server_name\":\"{VAULT_TUNNEL_NAME}\"}}}}",
        r.app,
        r.app_pin,
        r.cell,
        quote(&r.host),
        r.vault,
        r.vault_pin
    )
}

/// A route file of `routes`.
#[must_use]
pub fn routes(routes: &[Route]) -> String {
    let items: Vec<String> = routes.iter().map(route_object).collect();
    format!("{{\"routes\":[\n{}\n]}}\n", items.join(",\n"))
}

/// The routes of a route file this module wrote. Lines it did not write
/// are ignored.
#[must_use]
pub fn parse_routes(text: &str) -> Vec<Route> {
    let Ok(v) = fstp_json::parse(text.as_bytes()) else {
        return Vec::new();
    };
    let Some(items) = v.get("routes").and_then(|r| r.as_array()) else {
        return Vec::new();
    };
    let s = |v: &fstp_json::Value, a: &str, b: Option<&str>| -> String {
        let x = match b {
            Some(b) => v.get(a).and_then(|o| o.get(b)),
            None => v.get(a),
        };
        x.and_then(|x| x.as_str()).unwrap_or_default().to_owned()
    };
    items
        .iter()
        .map(|r| Route {
            cell: s(r, "cell", None),
            host: s(r, "host", None),
            app: s(r, "app", Some("address")),
            app_pin: s(r, "app", Some("cert_sha256")),
            vault: s(r, "vault", Some("address")),
            vault_pin: s(r, "vault", Some("cert_sha256")),
        })
        .collect()
}

/// `backup-<cluster>.json` (ADR-012). `None` without an object store.
#[must_use]
pub fn backup(l: &Layout, c: Cluster, cluster_id: &str) -> Option<String> {
    let b = l.cfg.backup.as_ref()?;
    let entry = match c {
        Cluster::App => Entry::Cell,
        Cluster::Vault => Entry::Vault,
    };
    Some(format!(
        "{{\"cluster\":\"{cluster_id}\",\"credentials_dir\":{},\"database\":{{\"host\":\"127.0.0.1\",\"port\":{}}},\
         \"keyd_socket\":{},\"object_store\":{{\"bucket\":{},\"endpoint\":{},\"port\":{},\"region\":{}}},\
         \"pg_bindir\":{},\"state_dir\":{}}}\n",
        p(&l.creds(&format!("backup-{}", c.name()))),
        l.pg_port(c),
        p(&l.keyd_socket(entry, "console")),
        quote(&b.bucket),
        quote(&b.endpoint),
        b.port,
        quote(&b.region),
        p(&l.cfg.paths.pg_bin),
        p(&l.backup_state(c)),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use crate::config::decode;

    fn layout() -> Layout {
        Layout::new(
            decode(
                br#"{"domain":"grants.example.eu","operator_email":"admin@example.eu",
                "mail":{"relay":"smtp.example.eu","username":"cell"},
                "backup":{"endpoint":"s3.gra.io.cloud.ovh.net","region":"gra","bucket":"fstp-b"}}"#,
            )
            .unwrap(),
        )
    }

    fn facts() -> Facts {
        Facts {
            cell: [0xab; 16],
            app_server_spki: [1; 32],
            vault_server_spki: [2; 32],
            witness_ca_spki: [3; 32],
            receipt_keys: vec!["0a0b".into()],
            ticket_key: Some("cd".repeat(32)),
            assets: true,
            edge_id: None,
        }
    }

    /// ADR-028: every rendered file is one JSON object, and the vault's
    /// is canonical: one line, no spaces outside strings.
    #[test]
    fn adr028_rendered_files_are_json_and_the_vault_file_is_canonical() {
        let l = layout();
        let f = facts();
        for text in [
            cell(&l, &f),
            witness(&l),
            edge(&l),
            backup(&l, Cluster::App, &"11".repeat(16)).unwrap(),
        ] {
            assert!(
                fstp_json::parse(text.as_bytes())
                    .unwrap()
                    .as_object()
                    .is_some(),
                "{text}"
            );
        }
        let v = vault(&l, &f).unwrap();
        assert_eq!(v.lines().count(), 1);
        let canonical = fstp_json::parse(v.as_bytes())
            .unwrap()
            .to_canonical()
            .unwrap();
        assert_eq!(v.trim_end(), canonical);
        assert!(v.contains(&format!("\"dbname\":\"v_{}\"", "ab".repeat(16))));
        let mut g = facts();
        g.ticket_key = None;
        assert!(vault(&l, &g).is_none());
    }

    /// ADR-028 record of lane L27, row "Turned on with backups": with a
    /// backup bucket, `cell.json` and `vault.json` name it as their
    /// `object_store`, the vault's still canonical. Without one, neither
    /// names an object store.
    #[test]
    fn adr028_setup_turns_snapshots_on_with_backups() {
        let l = layout();
        let f = facts();
        let v = vault(&l, &f).unwrap();
        for text in [cell(&l, &f), v.clone()] {
            let j = fstp_json::parse(text.as_bytes()).unwrap();
            let os = j.get("object_store").unwrap();
            assert_eq!(os.get("bucket").and_then(|b| b.as_str()), Some("fstp-b"));
            assert_eq!(os.get("region").and_then(|b| b.as_str()), Some("gra"));
        }
        let canonical = fstp_json::parse(v.as_bytes())
            .unwrap()
            .to_canonical()
            .unwrap();
        assert_eq!(v.trim_end(), canonical);
        let none = Layout::new(
            decode(
                br#"{"domain":"grants.example.eu","operator_email":"admin@example.eu",
                "mail":{"relay":"smtp.example.eu","username":"cell"}}"#,
            )
            .unwrap(),
        );
        assert!(!cell(&none, &f).contains("object_store"));
        assert!(!vault(&none, &f).unwrap().contains("object_store"));
    }

    /// ADR-028 "Plain route changes": a route file reads back.
    #[test]
    fn adr028_route_files_read_back() {
        let r = Route {
            cell: "ab".repeat(16),
            host: "grants.example.eu".into(),
            app: "127.0.0.1:7440".into(),
            app_pin: "01".repeat(32),
            vault: "127.0.0.1:7444".into(),
            vault_pin: "02".repeat(32),
        };
        assert_eq!(parse_routes(&routes(std::slice::from_ref(&r))), vec![r]);
    }

    /// ADR-028 record of lane L20: `cell.json` names the host status file,
    /// so the cell's System page reads what `fstp-admin report` writes.
    #[test]
    fn adr028_l20_cell_json_names_the_status_file() {
        let l = layout();
        let v = fstp_json::parse(cell(&l, &facts()).as_bytes()).unwrap();
        assert_eq!(
            v.get("host_status").and_then(fstp_json::Value::as_str),
            Some("/var/lib/fstp/status/host.json")
        );
    }
}

#[cfg(test)]
mod forge_tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use crate::config::{ConfigError, Problem, decode};

    fn host(forges: &str) -> Result<crate::config::HostConfig, ConfigError> {
        decode(
            format!(
                r#"{{"domain":"grants.example.eu","operator_email":"admin@example.eu",
                "mail":{{"relay":"smtp.example.eu","username":"cell"}}{forges}}}"#
            )
            .as_bytes(),
        )
    }

    fn facts() -> Facts {
        Facts {
            cell: [0xab; 16],
            app_server_spki: [1; 32],
            vault_server_spki: [2; 32],
            witness_ca_spki: [3; 32],
            receipt_keys: vec!["0a0b".into()],
            ticket_key: None,
            assets: false,
            edge_id: None,
        }
    }

    /// ADR-026 section of lane `m10/checks-runner`, I-32: the host file's
    /// `forges` becomes `checks.forge_hosts` of `cell.json`. Without it the
    /// cell file names no forge, and the cell's allowlist is empty.
    #[test]
    fn adr026_forges_render_as_the_cell_forge_allowlist() {
        let with = Layout::new(host(r#","forges":["codeberg.org","forge.example.eu"]"#).unwrap());
        let text = cell(&with, &facts());
        let v = fstp_json::parse(text.trim_end().as_bytes()).unwrap();
        let hosts: Vec<String> = v
            .as_object()
            .and_then(|o| o.get("checks"))
            .and_then(|c| c.as_object())
            .and_then(|c| c.get("forge_hosts"))
            .and_then(|h| h.as_array())
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(hosts, vec!["codeberg.org", "forge.example.eu"]);
        let without = Layout::new(host("").unwrap());
        assert!(!cell(&without, &facts()).contains("checks"));
    }

    /// ADR-026 section of lane `m10/checks-runner`: `forges` is a list of
    /// at most 16 different lowercase host names. Anything else is refused
    /// by name, with its fix.
    #[test]
    fn adr026_forges_refuses_what_the_cell_would_refuse() {
        let many: Vec<String> = (0..17).map(|i| format!("\"f{i}.example\"")).collect();
        for bad in [
            r#","forges":"codeberg.org""#.to_owned(),
            r#","forges":["Codeberg.org"]"#.to_owned(),
            r#","forges":["https://codeberg.org"]"#.to_owned(),
            r#","forges":["a.example","a.example"]"#.to_owned(),
            format!(r#","forges":[{}]"#, many.join(",")),
        ] {
            let e = host(&bad).unwrap_err();
            assert_eq!(
                (e.field.as_str(), e.problem),
                ("forges", Problem::BadForges),
                "{bad}"
            );
        }
    }
}

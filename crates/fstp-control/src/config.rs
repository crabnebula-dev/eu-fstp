//! The process configurations of `fstp-control` and `fstp-pgagent` (design
//! sections 2.3, 9.1 and 9.2, ADR-011).
//!
//! Each configuration is one JSON object with a closed member set. Unknown
//! members, duplicate members, a missing member and any other JSON form
//! are refused. No member holds a credential. TLS keys and the
//! superuser's password sit in files under `credentials_dir`, under the
//! fixed names of [`AGENT_FILES`] and [`CONTROL_FILES`], readable only by
//! the process's OS user.
//!
//! Both decoders are fuzzed: `pgagent_config_decode` and
//! `control_config_decode`.
//!
//! An agent configuration:
//!
//! ```json
//! {"cell_subnet": "10.1.0.0/24", "cluster_kind": "application",
//!  "credentials_dir": "/etc/fstp-pgagent", "hba_file": "/var/lib/postgresql/16/main/pg_hba.conf",
//!  "listen": "10.0.0.5:7400", "postgres_port": 5432}
//! ```
//!
//! An agent configuration may add the member `approvals`, the approvers
//! it checks destructive jobs against (ADR-011): `{"cluster_id": "<32
//! hex>", "operator_host": "control.example.eu", "staff": [...]}`, with
//! staff entries as in a control plane configuration. Without it the
//! agent refuses every destructive job.
//!
//! The agent connects only to its local server, over loopback, as
//! `fstp_super` (ADR-011), so neither the host nor the role is a member.
//!
//! A control plane configuration:
//!
//! ```json
//! {"cell_listen": "10.0.0.2:7300", "clusters": [{"id": "<32 hex>", "kind": "vault"}],
//!  "credentials_dir": "/etc/fstp-control", "operator_host": "control.example.eu",
//!  "staff": [{"staff": "<32 hex>", "credential_id": "<hex>", "cose_key": "<hex>"}]}
//! ```

use std::net::{IpAddr, SocketAddr};

use fstp_json::{ParseLimits, Value};
use fstp_webauthn::RelyingParty;

use crate::ControlConfig;
use crate::ControlError;
use crate::approval::PinnedApprovers;
use crate::operator::StaffCredential;
use crate::pg::CellSubnet;
use crate::placement::{Cluster, ClusterId, ClusterKind};

/// The longest configuration, in bytes.
pub const MAX_CONFIG_LEN: usize = 64 * 1024;

/// The longest path member, in bytes.
pub const MAX_PATH_LEN: usize = 1024;

/// The most registered clusters and the most pinned staff credentials.
pub const MAX_ENTRIES: usize = 256;

/// The longest credential id, in bytes (WebAuthn Level 3 allows 1023).
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;

/// The members of an agent configuration, in key order.
pub const AGENT_MEMBERS: [&str; 6] = [
    "cell_subnet",
    "cluster_kind",
    "credentials_dir",
    "hba_file",
    "listen",
    "postgres_port",
];

/// The optional member of an agent configuration: the pinned approvers of
/// destructive jobs, as `{"cluster_id": <32 hex>, "operator_host": <host>,
/// "staff": [<staff entry>, ...]}` (ADR-011 "Two-operator approval").
pub const AGENT_APPROVALS: &str = "approvals";

/// The members of a control plane configuration, in key order.
pub const CONTROL_MEMBERS: [&str; 5] = [
    "cell_listen",
    "clusters",
    "credentials_dir",
    "operator_host",
    "staff",
];

/// The files an agent reads from its `credentials_dir`: the control-plane
/// CA it accepts `fstp-control` from, its listener certificate and key,
/// the cluster CA of its server, and the `fstp_super` client certificate,
/// key and password.
pub const AGENT_FILES: [&str; 7] = [
    "control-ca.pem",
    "pgagent.pem",
    "pgagent-key.pem",
    "cluster-ca.pem",
    "fstp_super.pem",
    "fstp_super-key.pem",
    "fstp_super.password",
];

/// The files `fstp-control` reads from its `credentials_dir`: the
/// control-plane CA it accepts cells from, and its `CellToCp` listener
/// certificate and key.
pub const CONTROL_FILES: [&str; 3] = ["control-ca.pem", "control.pem", "control-key.pem"];

/// A decoded `fstp-pgagent` configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PgagentConfig {
    /// The subnet the cells' components connect from, for every `pg_hba`
    /// line the agent writes. Interim, pending Daniel: one subnet per
    /// cluster.
    pub cell_subnet: CellSubnet,
    /// The kind of the agent's cluster (I-83). Never `control`.
    pub cluster_kind: ClusterKind,
    /// The directory of [`AGENT_FILES`].
    pub credentials_dir: String,
    /// The `pg_hba.conf` path. The agent writes it only if the server
    /// reports the same path as its `hba_file` setting.
    pub hba_file: String,
    /// The control-private address the agent listens on.
    pub listen: SocketAddr,
    /// The port of the local server on `127.0.0.1`.
    pub postgres_port: u16,
    /// The approvers the agent checks destructive jobs against (ADR-011),
    /// from the optional member `approvals`. Without it the agent refuses
    /// every destructive job.
    pub approvals: Option<PinnedApprovers>,
}

fn bad(rule: &'static str) -> ControlError {
    ControlError::Config(rule)
}

/// Parses `bytes` as one JSON object with exactly the members `members`.
fn closed_object<'a>(
    value: &'a Value,
    members: &[&str],
    rule: &'static str,
) -> Result<&'a fstp_json::Object, ControlError> {
    let obj = value.as_object().ok_or(bad(rule))?;
    if obj.len() != members.len() || obj.keys().any(|k| !members.contains(&k)) {
        return Err(bad(rule));
    }
    Ok(obj)
}

fn parse(bytes: &[u8]) -> Result<Value, ControlError> {
    if bytes.len() > MAX_CONFIG_LEN {
        return Err(bad("too long"));
    }
    let limits = ParseLimits::default()
        .with_max_input_bytes(MAX_CONFIG_LEN)
        .with_max_depth(4)
        .with_max_container_len(MAX_ENTRIES)
        .with_max_string_bytes(MAX_CONFIG_LEN);
    fstp_json::parse_with(bytes, &limits).map_err(|_| bad("json"))
}

fn string<'a>(
    obj: &'a fstp_json::Object,
    name: &str,
    rule: &'static str,
) -> Result<&'a str, ControlError> {
    obj.get(name).and_then(Value::as_str).ok_or(bad(rule))
}

/// Whether `path` is absolute, at most [`MAX_PATH_LEN`] bytes of printable
/// ASCII without a space, and has no empty, `.` or `..` segment.
pub fn is_config_path(path: &str) -> bool {
    path.len() <= MAX_PATH_LEN
        && path.len() > 1
        && path.bytes().all(|b| b.is_ascii_graphic())
        && path.strip_prefix('/').is_some_and(|rest| {
            rest.split('/')
                .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        })
}

fn path(obj: &fstp_json::Object, name: &str, rule: &'static str) -> Result<String, ControlError> {
    let p = string(obj, name, rule)?;
    if !is_config_path(p) {
        return Err(bad(rule));
    }
    Ok(p.to_owned())
}

/// A socket address in its one spelling, as `SocketAddr` displays it.
fn socket_addr(
    obj: &fstp_json::Object,
    name: &str,
    rule: &'static str,
) -> Result<SocketAddr, ControlError> {
    let s = string(obj, name, rule)?;
    let addr: SocketAddr = s.parse().map_err(|_| bad(rule))?;
    if addr.to_string() != s || addr.port() == 0 {
        return Err(bad(rule));
    }
    Ok(addr)
}

/// A `pg_hba` subnet `addr/prefix` in its one spelling.
fn subnet(s: &str) -> Result<CellSubnet, ControlError> {
    let (addr, prefix) = s.split_once('/').ok_or(bad("cell_subnet"))?;
    let addr: IpAddr = addr.parse().map_err(|_| bad("cell_subnet"))?;
    if prefix.is_empty() || prefix.len() > 3 || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("cell_subnet"));
    }
    let prefix: u8 = prefix.parse().map_err(|_| bad("cell_subnet"))?;
    let net = CellSubnet::new(addr, prefix).map_err(|_| bad("cell_subnet"))?;
    if net.to_string() != s {
        return Err(bad("cell_subnet"));
    }
    Ok(net)
}

/// The value of one lowercase hex digit. Upper case is refused, so each
/// byte string has one spelling.
pub(crate) fn lower_hex_digit(b: u8) -> Option<u8> {
    if b.is_ascii_uppercase() {
        return None;
    }
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// Lowercase hex digits to bytes: an even count, at most `max` bytes.
pub(crate) fn lower_hex(s: &str, max: usize) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) || s.len() / 2 > max {
        return None;
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| match p {
            [h, l] => Some(lower_hex_digit(*h)? << 4 | lower_hex_digit(*l)?),
            _ => None,
        })
        .collect()
}

fn hex_bytes(s: &str, max: usize, rule: &'static str) -> Result<Vec<u8>, ControlError> {
    lower_hex(s, max).ok_or(bad(rule))
}

fn id16(s: &str, rule: &'static str) -> Result<[u8; 16], ControlError> {
    let b = hex_bytes(s, 16, rule)?;
    b.try_into().map_err(|_| bad(rule))
}

/// Decodes an agent configuration. Fuzzed (`pgagent_config_decode`).
///
/// # Errors
///
/// [`ControlError::Config`] naming the rule broken. A `control` cluster
/// kind is refused, since the control cluster has no agent (ADR-011).
pub fn decode_pgagent_config(bytes: &[u8]) -> Result<PgagentConfig, ControlError> {
    let value = parse(bytes)?;
    let obj = value.as_object().ok_or(bad("members"))?;
    let approvals = match obj.get(AGENT_APPROVALS) {
        Some(a) => Some(pinned_approvers(a)?),
        None => None,
    };
    let wanted = AGENT_MEMBERS
        .len()
        .saturating_add(usize::from(approvals.is_some()));
    if obj.len() != wanted
        || obj
            .keys()
            .any(|k| !AGENT_MEMBERS.contains(&k) && k != AGENT_APPROVALS)
    {
        return Err(bad("members"));
    }
    let cluster_kind = match string(obj, "cluster_kind", "cluster_kind")? {
        "application" => ClusterKind::Application,
        "vault" => ClusterKind::Vault,
        "witness" => ClusterKind::Witness,
        _ => return Err(bad("cluster_kind")),
    };
    let port = obj
        .get("postgres_port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p != 0)
        .ok_or(bad("postgres_port"))?;
    Ok(PgagentConfig {
        cell_subnet: subnet(string(obj, "cell_subnet", "cell_subnet")?)?,
        cluster_kind,
        credentials_dir: path(obj, "credentials_dir", "credentials_dir")?,
        hba_file: path(obj, "hba_file", "hba_file")?,
        listen: socket_addr(obj, "listen", "listen")?,
        postgres_port: port,
        approvals,
    })
}

/// The pinned approvers of an agent configuration. The staff entries are
/// those of a control plane configuration, and at least one is needed.
fn pinned_approvers(value: &Value) -> Result<PinnedApprovers, ControlError> {
    let obj = closed_object(
        value,
        &["cluster_id", "operator_host", "staff"],
        "approvals",
    )?;
    let operator_host = string(obj, "operator_host", "approvals")?;
    RelyingParty::new(operator_host).map_err(|_| bad("approvals"))?;
    let staff = staff_list(obj)?;
    if staff.is_empty() {
        return Err(bad("approvals"));
    }
    Ok(PinnedApprovers {
        cluster: ClusterId(id16(string(obj, "cluster_id", "approvals")?, "approvals")?),
        operator_host: operator_host.to_owned(),
        staff,
    })
}

/// The member `staff`: a list of `{"cose_key": <hex>, "credential_id":
/// <hex>, "staff": <32 hex>}`, with distinct credential ids.
fn staff_list(obj: &fstp_json::Object) -> Result<Vec<StaffCredential>, ControlError> {
    let mut staff: Vec<StaffCredential> = Vec::new();
    for s in obj
        .get("staff")
        .and_then(Value::as_array)
        .ok_or(bad("staff"))?
        .iter()
    {
        let s = closed_object(s, &["cose_key", "credential_id", "staff"], "staff")?;
        let credential_id = hex_bytes(
            string(s, "credential_id", "staff")?,
            MAX_CREDENTIAL_ID_LEN,
            "staff",
        )?;
        let cose = hex_bytes(string(s, "cose_key", "staff")?, MAX_CONFIG_LEN, "staff")?;
        let key = fstp_webauthn::parse_cose_key(&cose).map_err(|_| bad("staff"))?;
        if staff.iter().any(|k| k.credential_id == credential_id) {
            return Err(bad("staff"));
        }
        staff.push(StaffCredential {
            staff: fstp_cp_proto::StaffRef(id16(string(s, "staff", "staff")?, "staff")?),
            credential_id,
            key,
        });
    }
    Ok(staff)
}

/// Decodes a control plane configuration. Fuzzed
/// (`control_config_decode`).
///
/// A cluster entry is `{"id": <32 hex>, "kind": <kind>}`, with distinct
/// ids. A staff entry is `{"cose_key": <hex>, "credential_id": <hex>,
/// "staff": <32 hex>}`, with distinct credential ids. The COSE key goes
/// through the fuzzed `fstp_webauthn::parse_cose_key`.
///
/// # Errors
///
/// [`ControlError::Config`] naming the rule broken.
pub fn decode_control_config(bytes: &[u8]) -> Result<ControlConfig, ControlError> {
    let value = parse(bytes)?;
    let obj = closed_object(&value, &CONTROL_MEMBERS, "members")?;
    let mut clusters: Vec<Cluster> = Vec::new();
    for c in obj
        .get("clusters")
        .and_then(Value::as_array)
        .ok_or(bad("clusters"))?
        .iter()
    {
        let c = closed_object(c, &["id", "kind"], "clusters")?;
        let id = ClusterId(id16(string(c, "id", "clusters")?, "clusters")?);
        let kind = match string(c, "kind", "clusters")? {
            "application" => ClusterKind::Application,
            "vault" => ClusterKind::Vault,
            "control" => ClusterKind::Control,
            "witness" => ClusterKind::Witness,
            _ => return Err(bad("clusters")),
        };
        if clusters.iter().any(|k| k.id == id) {
            return Err(bad("clusters"));
        }
        clusters.push(Cluster { id, kind });
    }
    let operator_host = string(obj, "operator_host", "operator_host")?;
    RelyingParty::new(operator_host).map_err(|_| bad("operator_host"))?;
    let staff = staff_list(obj)?;
    Ok(ControlConfig {
        clusters,
        cell_listen: socket_addr(obj, "cell_listen", "cell_listen")?,
        credentials_dir: path(obj, "credentials_dir", "credentials_dir")?,
        operator_host: operator_host.to_owned(),
        staff,
    })
}

/// The longest credential file, in bytes.
pub const MAX_FILE_LEN: usize = 64 * 1024;

/// Reads `name` from `dir`, at most [`MAX_FILE_LEN`] bytes. A longer file
/// is refused after one byte past the limit.
///
/// # Errors
///
/// [`ControlError::Io`] when the file cannot be read, and
/// [`ControlError::Config`] when it is too long.
pub fn read_credential(dir: &str, name: &str) -> Result<Vec<u8>, ControlError> {
    use std::io::Read as _;
    let file = std::fs::File::open(std::path::Path::new(dir).join(name))
        .map_err(|e| ControlError::Io(e.kind()))?;
    let limit = u64::try_from(MAX_FILE_LEN)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut out = Vec::new();
    file.take(limit)
        .read_to_end(&mut out)
        .map_err(|e| ControlError::Io(e.kind()))?;
    if out.len() > MAX_FILE_LEN {
        return Err(bad("credential file too long"));
    }
    Ok(out)
}

/// Reads the configuration file named by the environment variable `var`.
///
/// # Errors
///
/// [`ControlError::Config`] when the variable is unset or the file too
/// long, and [`ControlError::Io`] when the file cannot be read.
pub fn read_config_file(var: &str) -> Result<Vec<u8>, ControlError> {
    let path = std::env::var(var).map_err(|_| bad("configuration path unset"))?;
    let (dir, name) = match path.rsplit_once('/') {
        Some(("", name)) => ("/", name),
        Some((dir, name)) => (dir, name),
        None => (".", path.as_str()),
    };
    read_credential(dir, name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const AGENT: &str = r#"{"cell_subnet":"10.1.0.0/24","cluster_kind":"application","credentials_dir":"/etc/fstp-pgagent","hba_file":"/var/lib/postgresql/16/main/pg_hba.conf","listen":"10.0.0.5:7400","postgres_port":5432}"#;

    /// ADR-011: the documented agent form decodes.
    #[test]
    fn adr011_agent_config_decodes_the_documented_form() {
        let c = decode_pgagent_config(AGENT.as_bytes()).unwrap();
        assert_eq!(c.cluster_kind, ClusterKind::Application);
        assert_eq!(c.postgres_port, 5432);
        assert_eq!(c.cell_subnet.to_string(), "10.1.0.0/24");
    }

    /// ADR-011, R-NF-05: unknown or missing members, a control cluster, a
    /// relative path, a second spelling of an address and a subnet with a
    /// host bit are refused.
    #[test]
    fn adr011_agent_config_refuses_unknown_members_and_other_forms() {
        let swap = |from: &str, to: &str| AGENT.replacen(from, to, 1);
        for bad in [
            swap(
                "\"postgres_port\":5432",
                "\"postgres_port\":5432,\"password\":\"x\"",
            ),
            swap(",\"postgres_port\":5432", ""),
            swap("\"application\"", "\"control\""),
            swap("\"/etc/fstp-pgagent\"", "\"etc/fstp-pgagent\""),
            swap("\"/etc/fstp-pgagent\"", "\"/etc/../root\""),
            swap("10.1.0.0/24", "10.1.0.1/24"),
            swap("10.1.0.0/24", "10.1.0.0/024"),
            swap("10.0.0.5:7400", "010.0.0.5:7400"),
            swap("5432", "0"),
            swap("5432", "70000"),
            "[]".to_owned(),
        ] {
            assert!(decode_pgagent_config(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    /// An agent configuration with the `approvals` member of one staff
    /// passkey, an Ed25519 COSE key.
    fn with_approvals(approvals: &str) -> String {
        AGENT.replacen(
            "\"postgres_port\":5432",
            &format!("\"postgres_port\":5432,\"approvals\":{approvals}"),
            1,
        )
    }

    fn cose_hex() -> String {
        let key = fstp_crypto::sig::Ed25519SigningKey::generate().unwrap();
        let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
        cose.extend_from_slice(&key.public_key());
        cose.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// ADR-011 "fstp-pgagent checks both approvals again itself, against
    /// a staff key set pinned at its installation": the optional member
    /// `approvals` pins the agent's cluster, the control-plane host and
    /// the staff passkeys. Without it the agent has no approvers.
    #[test]
    fn adr011_agent_config_pins_the_approvers() {
        assert_eq!(
            decode_pgagent_config(AGENT.as_bytes()).unwrap().approvals,
            None
        );
        let staff = format!(
            "{{\"cose_key\":\"{}\",\"credential_id\":\"a1a1\",\"staff\":\"{}\"}}",
            cose_hex(),
            "01".repeat(16)
        );
        let good = format!(
            "{{\"cluster_id\":\"{}\",\"operator_host\":\"control.example.eu\",\"staff\":[{staff}]}}",
            "31".repeat(16)
        );
        let c = decode_pgagent_config(with_approvals(&good).as_bytes()).unwrap();
        let p = c.approvals.unwrap();
        assert_eq!(p.cluster, ClusterId([0x31; 16]));
        assert_eq!(p.operator_host, "control.example.eu");
        assert_eq!(p.staff.len(), 1);
        assert_eq!(p.staff[0].credential_id, vec![0xa1, 0xa1]);
        for bad in [
            good.replacen(&format!("[{staff}]"), "[]", 1),
            good.replacen(&format!("[{staff}]"), &format!("[{staff},{staff}]"), 1),
            good.replacen("control.example.eu", "not a host", 1),
            good.replacen(&"31".repeat(16), &"31".repeat(15), 1),
            good.replacen("\"cluster_id\"", "\"cluster\"", 1),
            good.replacen("}", ",\"extra\":1}", 1),
            "{}".to_owned(),
            "[]".to_owned(),
        ] {
            assert!(
                decode_pgagent_config(with_approvals(&bad).as_bytes()).is_err(),
                "{bad}"
            );
        }
    }
}

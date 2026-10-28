//! Several named servers per test binary, any role name and per-database
//! `pg_hba` lines (M3 design sections 2.2 and 4.1).
//!
//! A named server trusts only its own cluster CA ([`crate::certs::ClusterCa`]).
//! Its `pg_hba.conf` holds the superuser line, one
//! `hostssl <db> <role> 127.0.0.1/32 scram-sha-256 clientcert=verify-full`
//! line per database and role, one `hostssl replication <role>` line per
//! replication role, and a final reject line. No accepting line names the
//! role `all`.
//!
//! Role and database names follow `^[a-z_][a-z0-9_]{0,62}$`, so they need
//! no quoting in SQL or `pg_hba.conf`. The `pg_hba` keywords `all`,
//! `sameuser`, `samerole`, `samegroup` and `replication` are refused as
//! names. A rewrite of `pg_hba.conf` waits until the server has reloaded
//! it, so the next connection already meets the new lines.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::certs::{CertError, ClusterCa, is_identifier};
use crate::server::{ConnParams, Error, PgServer, ServerTls, StartPlan, random_hex, start_planned};

/// A login role minted on a named server: its random password and a
/// client certificate from the server's cluster CA, CN equal to the role.
#[derive(Clone, PartialEq, Eq)]
pub struct RoleLogin {
    /// The role name.
    pub role: String,
    /// The role's random password. Printable ASCII.
    pub password: String,
    /// The role's client certificate (PEM).
    pub cert_pem: Vec<u8>,
    /// The private key of [`RoleLogin::cert_pem`] (PEM).
    pub key_pem: Vec<u8>,
}

impl RoleLogin {
    /// Connection parameters for this role to `dbname` on `server`, the
    /// named server that minted it. The client trusts the server's cluster
    /// CA.
    ///
    /// `ConnParams` borrows its certificates for the rest of the process,
    /// so each call leaks one copy of the certificate and the key. Test
    /// use only.
    #[must_use]
    pub fn conn_params(&self, server: &PgServer, dbname: &str) -> ConnParams {
        let cert: &'static [u8] = Box::leak(self.cert_pem.clone().into_boxed_slice());
        let key: &'static [u8] = Box::leak(self.key_pem.clone().into_boxed_slice());
        ConnParams {
            host: server.host().to_owned(),
            port: server.port(),
            user: self.role.clone(),
            password: self.password.clone(),
            dbname: dbname.to_owned(),
            client_cert_pem: cert,
            client_key_pem: key,
            server_ca_pem: server.server_ca_pem(),
        }
    }
}

impl fmt::Debug for RoleLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoleLogin")
            .field("role", &self.role)
            .field("password", &"<redacted>")
            .field("key_pem", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// The address every line admits. The server listens on it only.
const HBA_ADDRESS: &str = "127.0.0.1/32";

/// Words `pg_hba.conf` reads as keywords in the database or role column.
const HBA_KEYWORDS: [&str; 5] = ["all", "sameuser", "samerole", "samegroup", "replication"];

/// The `pg_hba` database keyword of replication connections. Only
/// [`PgServer::create_replication_role`] writes it, since database names
/// may not take it.
const REPLICATION: &str = "replication";

/// How long a `pg_hba.conf` reload may take.
const RELOAD_WAIT: Duration = Duration::from_secs(20);

/// The state only a named server has.
pub(crate) struct NamedState {
    name: String,
    ou: String,
    ca: ClusterCa,
    /// The `(database, role)` pairs of the accepting lines, in order.
    lines: Mutex<Vec<(String, String)>>,
}

impl NamedState {
    /// The whole `pg_hba.conf` for `lines`.
    fn hba(&self, lines: &[(String, String)]) -> String {
        let mut out = format!(
            "# Written by fstp-pgtest for the named server {} ({}).\n",
            self.name, self.ou
        );
        out.push_str(&hba_line("all", "fstp_super"));
        for (db, role) in lines {
            out.push_str(&hba_line(db, role));
        }
        out.push_str("host all all all reject\n");
        out
    }
}

fn hba_line(db: &str, role: &str) -> String {
    format!("hostssl {db} {role} {HBA_ADDRESS} scram-sha-256 clientcert=verify-full\n")
}

/// One slot per name: the OU it was first asked with and its server.
type Slot = (String, &'static OnceLock<Result<PgServer, Error>>);

fn slots() -> MutexGuard<'static, BTreeMap<String, Slot>> {
    static SLOTS: OnceLock<Mutex<BTreeMap<String, Slot>>> = OnceLock::new();
    SLOTS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn cert_error(context: &str, e: &CertError) -> Error {
    Error::new(format!("{context}: {e}"))
}

/// Whether `name` may appear in a `pg_hba.conf` database or role column.
fn is_hba_name(name: &str) -> bool {
    is_identifier(name) && !HBA_KEYWORDS.contains(&name)
}

/// Starts the named server `name` whose certificate carries `ou`.
fn start_named(name: &str, ou: &str) -> Result<PgServer, Error> {
    let ca = ClusterCa::generate(&format!("fstp-pgtest cluster CA {name}"))
        .map_err(|e| cert_error("cannot create the cluster CA", &e))?;
    let server_cert = ca
        .issue_server(ou)
        .map_err(|e| cert_error("cannot issue the server certificate", &e))?;
    let superuser = ca
        .issue_role(crate::Role::Superuser.name())
        .map_err(|e| cert_error("cannot issue the superuser certificate", &e))?;
    // The server lives in a static for the rest of the process, and
    // `ConnParams` borrows the superuser's certificate for that long.
    let superuser_cert: &'static [u8] = Box::leak(superuser.cert_pem.into_boxed_slice());
    let superuser_key: &'static [u8] = Box::leak(superuser.key_pem.into_boxed_slice());
    let state = NamedState {
        name: name.to_owned(),
        ou: ou.to_owned(),
        ca,
        lines: Mutex::new(Vec::new()),
    };
    let hba = state.hba(&[]);
    // `ConnParams::server_ca_pem` borrows the CA certificate for as long.
    let ca_pem: &'static [u8] = Box::leak(state.ca.cert_pem().to_vec().into_boxed_slice());
    start_planned(
        StartPlan {
            tls: ServerTls::Required,
            ca_pem,
            server_cert_pem: &server_cert.cert_pem,
            server_key_pem: &server_cert.key_pem,
            superuser_cert_pem: superuser_cert,
            superuser_key_pem: superuser_key,
            hba,
            app_role: false,
        },
        Some(state),
    )
}

impl PgServer {
    /// The named server `name` shared by every test in this test binary.
    /// It starts on first use with its own cluster CA, and its server
    /// certificate carries `server_ou` as the subject OU. Each name gets its
    /// own server. A later call with the same name and another OU fails.
    ///
    /// Names follow `^[a-z][a-z0-9_]{0,30}$`. OUs are 1 to 32 lowercase
    /// ASCII letters.
    ///
    /// # Errors
    ///
    /// Returns the start error. Every later call for the name returns the
    /// same error.
    pub fn shared_named(name: &str, server_ou: &str) -> Result<&'static PgServer, Error> {
        let name_ok = name.len() <= 31
            && name.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && is_identifier(name);
        if !name_ok {
            return Err(Error::new(format!("invalid server name {name:?}")));
        }
        if server_ou.is_empty()
            || server_ou.len() > 32
            || !server_ou.bytes().all(|b| b.is_ascii_lowercase())
        {
            return Err(Error::new(format!("invalid server OU {server_ou:?}")));
        }
        let slot = {
            let mut slots = slots();
            let (ou, slot) = slots.entry(name.to_owned()).or_insert_with(|| {
                let fresh: &'static OnceLock<Result<PgServer, Error>> =
                    Box::leak(Box::new(OnceLock::new()));
                (server_ou.to_owned(), fresh)
            });
            if ou != server_ou {
                return Err(Error::new(format!(
                    "the named server {name:?} started with OU {ou:?}, not {server_ou:?}"
                )));
            }
            *slot
        };
        slot.get_or_init(|| start_named(name, server_ou))
            .as_ref()
            .map_err(Clone::clone)
    }

    /// The server's own cluster CA. Only named servers have one. The other
    /// servers trust the fixture CA of `fstp-tls`.
    #[must_use]
    pub fn cluster_ca(&self) -> Option<&ClusterCa> {
        self.named.as_ref().map(|n| &n.ca)
    }

    /// Creates the login role `role` with a random password and mints its
    /// client certificate from the server's cluster CA. The role has no
    /// special rights. Role names follow `^[a-z_][a-z0-9_]{0,62}$`.
    ///
    /// # Errors
    ///
    /// Fails for a name outside the grammar, an existing role, or a server
    /// without a cluster CA.
    pub fn create_login_role(&self, role: &str) -> Result<RoleLogin, Error> {
        let named = self.named_state()?;
        if !is_hba_name(role) {
            return Err(Error::new(format!("invalid role name {role:?}")));
        }
        let issued = named
            .ca
            .issue_role(role)
            .map_err(|e| cert_error("cannot issue the role certificate", &e))?;
        let password = random_hex(24)?;
        // The role name follows the grammar and the password is hex, so
        // neither needs quoting. The statement goes to psql's standard
        // input only, since it holds the password.
        self.psql(
            "postgres",
            &format!(
                "CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                 NOREPLICATION NOBYPASSRLS PASSWORD '{password}'"
            ),
        )?;
        Ok(RoleLogin {
            role: role.to_owned(),
            password,
            cert_pem: issued.cert_pem,
            key_pem: issued.key_pem,
        })
    }

    /// Creates the database `dbname`, revokes CONNECT from PUBLIC, grants
    /// CONNECT to each of `roles`, and adds one `pg_hba` line per role
    /// before the final reject line. The server reloads its configuration
    /// before this returns.
    ///
    /// # Errors
    ///
    /// Fails for a name outside the grammar, an unknown role, a server
    /// without a cluster CA, or a reload that does not take effect.
    pub fn create_database_for(&self, dbname: &str, roles: &[&str]) -> Result<(), Error> {
        let named = self.named_state()?;
        if !is_hba_name(dbname) {
            return Err(Error::new(format!("invalid database name {dbname:?}")));
        }
        for role in roles {
            if !is_hba_name(role) {
                return Err(Error::new(format!("invalid role name {role:?}")));
            }
            let known = self.psql(
                "postgres",
                &format!("SELECT count(*) FROM pg_roles WHERE rolname = '{role}'"),
            )?;
            if known != "1" {
                return Err(Error::new(format!("no role {role:?} on this server")));
            }
        }
        let mut sql = format!(
            "CREATE DATABASE {dbname};\nREVOKE CONNECT, TEMPORARY ON DATABASE {dbname} FROM PUBLIC;\n"
        );
        for role in roles {
            sql.push_str(&format!("GRANT CONNECT ON DATABASE {dbname} TO {role};\n"));
        }
        self.psql("postgres", &sql)?;
        let mut lines = lock(&named.lines);
        let mut next = lines.clone();
        for role in roles {
            let pair = ((*dbname).to_owned(), (*role).to_owned());
            if !next.contains(&pair) {
                next.push(pair);
            }
        }
        self.write_hba_and_reload(&named.hba(&next))?;
        *lines = next;
        Ok(())
    }

    /// Creates the replication role `role`, with LOGIN and REPLICATION and
    /// no other special right, and mints its client certificate from the
    /// server's cluster CA. It adds the line `hostssl replication <role>
    /// 127.0.0.1/32 scram-sha-256 clientcert=verify-full` before the final
    /// reject line (design section 4.1, the `fstp_repl` loopback line), so
    /// `pg_basebackup` can connect. The server reloads its configuration
    /// before this returns.
    ///
    /// # Errors
    ///
    /// Fails for a name outside the grammar, an existing role, a server
    /// without a cluster CA, or a reload that does not take effect.
    pub fn create_replication_role(&self, role: &str) -> Result<RoleLogin, Error> {
        let named = self.named_state()?;
        if !is_hba_name(role) {
            return Err(Error::new(format!("invalid role name {role:?}")));
        }
        let issued = named
            .ca
            .issue_role(role)
            .map_err(|e| cert_error("cannot issue the role certificate", &e))?;
        let password = random_hex(24)?;
        self.psql(
            "postgres",
            &format!(
                "CREATE ROLE {role} LOGIN REPLICATION NOSUPERUSER NOCREATEDB \
                 NOCREATEROLE NOBYPASSRLS PASSWORD '{password}'"
            ),
        )?;
        let mut lines = lock(&named.lines);
        let mut next = lines.clone();
        let pair = (REPLICATION.to_owned(), role.to_owned());
        if !next.contains(&pair) {
            next.push(pair);
        }
        self.write_hba_and_reload(&named.hba(&next))?;
        *lines = next;
        Ok(RoleLogin {
            role: role.to_owned(),
            password,
            cert_pem: issued.cert_pem,
            key_pem: issued.key_pem,
        })
    }

    fn named_state(&self) -> Result<&NamedState, Error> {
        self.named
            .as_ref()
            .ok_or_else(|| Error::new("only a named server has a cluster CA"))
    }

    /// Writes `hba` as `pg_hba.conf`, reloads the server and waits until
    /// the reload took effect. The caller holds the lines lock.
    fn write_hba_and_reload(&self, hba: &str) -> Result<(), Error> {
        let before = self.psql("postgres", "SELECT pg_conf_load_time()")?;
        let path = self.dir().join("data").join("pg_hba.conf");
        std::fs::write(&path, hba)
            .map_err(|e| Error::new(format!("cannot write {}: {e}", path.display())))?;
        let errors = self.psql(
            "postgres",
            "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL",
        )?;
        if errors != "0" {
            return Err(Error::new(format!(
                "the new pg_hba.conf has {errors} bad lines"
            )));
        }
        self.psql("postgres", "SELECT pg_reload_conf()")?;
        // Each psql run is a new backend, forked after the postmaster
        // finished any reload it had started, so a new load time means the
        // new lines are in force.
        let start = Instant::now();
        loop {
            let now = self.psql("postgres", "SELECT pg_conf_load_time()")?;
            if now != before {
                return Ok(());
            }
            if start.elapsed() >= RELOAD_WAIT {
                return Err(Error::new("the server did not reload pg_hba.conf"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hba_keywords_are_not_names() {
        for word in HBA_KEYWORDS {
            assert!(!is_hba_name(word), "{word}");
        }
        assert!(is_hba_name("c_0123456789abcdef0123456789abcdef_app"));
    }

    #[test]
    fn hba_line_shape() {
        assert_eq!(
            hba_line("db1", "r1"),
            "hostssl db1 r1 127.0.0.1/32 scram-sha-256 clientcert=verify-full\n"
        );
    }
}

//! The `Origin` rule against DNS rebinding and the white-labelled server
//! name (design section 3.8, ADR-013 "Transport", TH-63, Q43).

/// What an accepted `Origin` check saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginSeen {
    /// No `Origin` field: a native client.
    Absent,
    /// One `Origin` field equal to a tenant origin.
    Tenant,
}

/// Why the `Origin` check refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginRefusal {
    /// The one `Origin` is not a tenant origin (403).
    Foreign,
    /// More than one `Origin` field (400).
    Duplicated,
    /// The value is not one serialised origin (400).
    Unparsable,
}

impl OriginRefusal {
    /// The HTTP status of the refusal (interim, pending Daniel): 403 for
    /// a foreign origin, as ADR-013 states, and 400 for a field that is
    /// not one origin.
    pub const fn status(self) -> u16 {
        match self {
            OriginRefusal::Foreign => 403,
            OriginRefusal::Duplicated | OriginRefusal::Unparsable => 400,
        }
    }
}

/// Whether `v` is one serialised origin (RFC 6454 section 6.1) in the
/// form a browser sends: `http` or `https`, `://`, a host of lowercase
/// letters, digits, `-` and `.`, and an optional port from 1 to 65535 with
/// no leading zero. `null` is an opaque origin, which is well-formed and
/// never a tenant origin.
fn well_formed(v: &[u8]) -> bool {
    if v == b"null" {
        return true;
    }
    let rest = if let Some(r) = v.strip_prefix(b"https://") {
        r
    } else if let Some(r) = v.strip_prefix(b"http://") {
        r
    } else {
        return false;
    };
    let (host, port) = match rest.iter().position(|b| *b == b':') {
        Some(i) => (
            rest.get(..i).unwrap_or_default(),
            Some(rest.get(i.saturating_add(1)..).unwrap_or_default()),
        ),
        None => (rest, None),
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'.')
        && !host.starts_with(b".")
        && !host.ends_with(b".")
        && !host.windows(2).any(|w| w == b"..");
    let port_ok = match port {
        None => true,
        Some(p) => {
            !p.is_empty()
                && p.len() <= 5
                && p.iter().all(u8::is_ascii_digit)
                && !p.starts_with(b"0")
                && std::str::from_utf8(p)
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok())
                    .is_some()
        }
    };
    host_ok && port_ok
}

/// The DNS rebinding rule (design section 3.8). `values` are the raw
/// values of every `Origin` field of the request, and `tenant_origins` the
/// tenant's own serialised origins, such as `https://tenant.fstp.test`.
/// Fuzzed (`mcp_headers_decode`).
///
/// No field is accepted, since native clients send none. Two or more
/// fields are refused, a value that is not one origin is refused, and one
/// origin must equal a tenant origin byte for byte.
pub fn check_origin(
    values: &[&[u8]],
    tenant_origins: &[String],
) -> Result<OriginSeen, OriginRefusal> {
    let one = match values {
        [] => return Ok(OriginSeen::Absent),
        [one] => *one,
        _ => return Err(OriginRefusal::Duplicated),
    };
    if !well_formed(one) {
        return Err(OriginRefusal::Unparsable);
    }
    if tenant_origins.iter().any(|t| t.as_bytes() == one) {
        Ok(OriginSeen::Tenant)
    } else {
        Err(OriginRefusal::Foreign)
    }
}

/// The name a server whose domain has no fitting first label takes.
const FALLBACK_NAME: &str = "fstp";

/// Whether `s` matches `^[a-z0-9][a-z0-9-]{0,30}$`.
fn fits(s: &str) -> bool {
    let b = s.as_bytes();
    b.first()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && b.len() <= 31
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// The white-labelled `serverInfo.name`: the first label of the tenant's
/// verified domain when it matches `^[a-z0-9][a-z0-9-]{0,30}$` (TH-63,
/// Q43). It never carries free text. A label that does not match gives
/// the fixed name `fstp` (interim, pending Daniel).
pub fn server_name(verified_domain: &str) -> String {
    let label = verified_domain.split('.').next().unwrap_or_default();
    if fits(label) {
        label.to_owned()
    } else {
        FALLBACK_NAME.to_owned()
    }
}

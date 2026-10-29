//! The session cookie of the cell route layer (B11, ADR-008 "Sessions",
//! design sections 1.2, 8.2 and 15).
//!
//! `fstp_auth::codec` holds the cookie's byte form: the 16-byte cell id,
//! then the 32-byte token. Its text armour in a `Set-Cookie` and a
//! `Cookie` field belongs to the route layer, which these tests check.
//! They do not fix the armour. They check what any armour must give: the
//! attributes of design section 8.2, cookie-octets only, a round trip, and
//! a refusal of another cell's cookie before any lookup.
//!
//! Lane W3a's test author wrote them before the HTTP layer exists. They
//! reach it through `http_common::{set_cookie, read_cookie}`, which refuse
//! until production writes and reads the cookie, so each is red for that
//! reason only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod http_common;

use fstp_prop::{Gen, prop_assert, prop_assert_eq};

use http_common::{CELL_A, CELL_B, COOKIE_NAME, CookieRead, read_cookie, set_cookie};

/// A token for the fixed-value tests. Synthetic.
const TOKEN: [u8; 32] = [0x5A; 32];

/// The `Set-Cookie` value for cell A and [`TOKEN`].
fn set_a() -> String {
    let v = set_cookie(CELL_A, &TOKEN).unwrap_or_else(|e| panic!("{e}"));
    String::from_utf8(v).unwrap_or_else(|_| panic!("the Set-Cookie value is not UTF-8"))
}

/// A `Set-Cookie` value split into its name, value and attributes
/// (RFC 6265 section 5.2).
struct SetCookie {
    name: String,
    value: String,
    attrs: Vec<(String, Option<String>)>,
}

fn parse_set_cookie(s: &str) -> SetCookie {
    let mut parts = s.split(';');
    let pair = parts.next().unwrap_or_default();
    let (name, value) = pair
        .split_once('=')
        .unwrap_or_else(|| panic!("the Set-Cookie value has no name=value pair"));
    let attrs = parts
        .map(|a| {
            let a = a.trim();
            match a.split_once('=') {
                Some((k, v)) => (k.trim().to_ascii_lowercase(), Some(v.trim().to_owned())),
                None => (a.to_ascii_lowercase(), None),
            }
        })
        .collect();
    SetCookie {
        name: name.trim().to_owned(),
        value: value.trim().to_owned(),
        attrs,
    }
}

/// The `Cookie` field value a browser sends for a `Set-Cookie` value.
fn cookie_field(set: &[u8]) -> Vec<u8> {
    let s = std::str::from_utf8(set).unwrap_or_else(|_| panic!("not UTF-8"));
    let c = parse_set_cookie(s);
    format!("{}={}", c.name, c.value).into_bytes()
}

/// ADR-008 "Sessions", design section 8.2: the session cookie is named
/// `__Host-fstp`, with that exact case.
#[test]
fn adr008_set_cookie_names_host_prefixed_fstp() {
    assert_eq!(parse_set_cookie(&set_a()).name, COOKIE_NAME);
}

/// ADR-008 "Sessions", design section 8.2: the cookie carries `Secure`,
/// `HttpOnly`, `SameSite=Strict` and `Path=/`, each exactly once.
#[test]
fn adr008_set_cookie_is_secure_httponly_samesite_strict_path_root() {
    let c = parse_set_cookie(&set_a());
    let count = |k: &str| c.attrs.iter().filter(|(n, _)| n == k).count();
    for k in ["secure", "httponly", "samesite", "path"] {
        assert_eq!(count(k), 1, "attribute {k} in {:?}", c.attrs);
    }
    let get = |k: &str| {
        c.attrs
            .iter()
            .find(|(n, _)| n == k)
            .and_then(|(_, v)| v.clone())
    };
    assert_eq!(get("secure"), None);
    assert_eq!(get("httponly"), None);
    assert_eq!(get("samesite").as_deref(), Some("Strict"));
    assert_eq!(get("path").as_deref(), Some("/"));
}

/// ADR-008, RFC 6265bis `__Host-` prefix: the cookie has no `Domain`
/// attribute. With one, a browser would drop it, or a sibling host could
/// read it.
#[test]
fn adr008_set_cookie_has_no_domain_attribute() {
    let c = parse_set_cookie(&set_a());
    assert!(c.attrs.iter().all(|(n, _)| n != "domain"), "{:?}", c.attrs);
}

/// ADR-008, RFC 6265 section 4.1.1: the cookie value is written in
/// cookie-octets only, so no browser or proxy reads it differently.
#[test]
fn adr008_set_cookie_value_uses_cookie_octets_only() {
    let c = parse_set_cookie(&set_a());
    assert!(!c.value.is_empty());
    let octet = |b: u8| matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E);
    assert!(
        c.value.bytes().all(octet),
        "the value holds a byte outside cookie-octet"
    );
}

/// B11, ADR-008 "Sessions": a cookie the cell set reads back on the same
/// cell as the same cell id and token, for any token.
#[test]
fn b11_session_cookie_round_trips_on_its_own_cell() {
    fstp_prop::check(
        "b11_session_cookie_round_trips_on_its_own_cell",
        |g: &mut Gen| {
            let cell: [u8; 16] = g.bytes(16..=16).try_into().unwrap();
            let token: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
            let set = set_cookie(cell, &token).map_err(|e| e.to_string())?;
            let field = cookie_field(&set);
            let read = read_cookie(cell, &[field.as_slice()]).map_err(|e| e.to_string())?;
            prop_assert_eq!(read, CookieRead::Session { cell, token });
            Ok(())
        },
    );
}

/// B11, I-19, design section 8.2: a cookie set by another cell is refused
/// by the cell, before any lookup. It never reads as a session, even when
/// the token matches one of the cell's own sessions.
#[test]
fn b11_cookie_of_another_cell_is_refused() {
    fstp_prop::check("b11_cookie_of_another_cell_is_refused", |g: &mut Gen| {
        let own: [u8; 16] = g.bytes(16..=16).try_into().unwrap();
        let mut other: [u8; 16] = g.bytes(16..=16).try_into().unwrap();
        if other == own {
            other[0] ^= 1;
        }
        let token: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
        let set = set_cookie(other, &token).map_err(|e| e.to_string())?;
        let field = cookie_field(&set);
        let read = read_cookie(own, &[field.as_slice()]).map_err(|e| e.to_string())?;
        prop_assert_eq!(read, CookieRead::Refused);
        Ok(())
    });
}

/// ADR-008: only the exact name `__Host-fstp` is the session cookie. A
/// valid value under `fstp`, `__host-fstp` or `__Secure-fstp` reads as no
/// session. A sibling host or an old browser can set those names without
/// the `__Host-` guarantees.
#[test]
fn adr008_cookie_without_the_exact_host_prefix_is_not_a_session() {
    let set = set_cookie(CELL_A, &TOKEN).unwrap_or_else(|e| panic!("{e}"));
    let s = std::str::from_utf8(&set).unwrap_or_else(|_| panic!("not UTF-8"));
    let value = parse_set_cookie(s).value;
    for name in [
        "fstp",
        "__host-fstp",
        "__HOST-fstp",
        "__Secure-fstp",
        "__Host-fstp2",
    ] {
        let field = format!("{name}={value}");
        let read = read_cookie(CELL_A, &[field.as_bytes()]).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            !matches!(read, CookieRead::Session { .. }),
            "{name} read as a session"
        );
    }
}

/// ADR-008, cookie tossing: two session cookies in one request are refused,
/// whether they share a `Cookie` field or come in two fields. The cell
/// never picks one.
#[test]
fn adr008_two_session_cookies_are_refused() {
    let one = cookie_field(&set_cookie(CELL_A, &TOKEN).unwrap_or_else(|e| panic!("{e}")));
    let two = cookie_field(&set_cookie(CELL_A, &[0x6B; 32]).unwrap_or_else(|e| panic!("{e}")));
    let joined = [one.as_slice(), b"; ", two.as_slice()].concat();
    let cases: [Vec<&[u8]>; 3] = [
        vec![joined.as_slice()],
        vec![one.as_slice(), two.as_slice()],
        vec![one.as_slice(), one.as_slice()],
    ];
    for fields in cases {
        let read = read_cookie(CELL_A, &fields).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(read, CookieRead::Refused, "{} fields", fields.len());
    }
}

/// B11, ADR-008: other cookies beside the session cookie leave it intact,
/// and a request with none reads as no session, not as a refusal.
#[test]
fn adr008_other_cookies_do_not_disturb_the_session_cookie() {
    let one = cookie_field(&set_cookie(CELL_A, &TOKEN).unwrap_or_else(|e| panic!("{e}")));
    let field = [b"theme=dark; ".as_slice(), one.as_slice(), b"; lang=en"].concat();
    let read = read_cookie(CELL_A, &[field.as_slice()]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        read,
        CookieRead::Session {
            cell: CELL_A,
            token: TOKEN
        }
    );
    let none = read_cookie(CELL_A, &[b"theme=dark".as_slice()]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(none, CookieRead::Absent);
}

/// B11, TH-26, design section 15: a session cookie value of cell A that
/// is cut, extended or corrupted by one byte never reads as a session of
/// another cell. It may still read as cell A with another token, which
/// the lookup then refuses. Each mutation is one byte of the value.
#[test]
fn b11_mutated_cookie_values_never_read_as_another_cells_session() {
    fstp_prop::check(
        "b11_mutated_cookie_values_never_read_as_another_cells_session",
        |g: &mut Gen| {
            let token: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
            let set = set_cookie(CELL_A, &token).map_err(|e| e.to_string())?;
            let mut field = cookie_field(&set);
            let start = COOKIE_NAME.len() + 1;
            prop_assert!(field.len() > start, "the cookie value is empty");
            let at = g.usize_in(start..=field.len() - 1);
            match g.usize_in(0..=2) {
                0 => field.truncate(at),
                1 => field.insert(at, *g.pick(b"0aA-_=+/%")),
                _ => field[at] = field[at].wrapping_add(g.u8_in(1..=255)),
            }
            let read = read_cookie(CELL_A, &[field.as_slice()]).map_err(|e| e.to_string())?;
            prop_assert!(
                !matches!(read, CookieRead::Session { cell, .. } if cell != CELL_A),
                "a mutated cookie of cell A read as {read:?}"
            );
            Ok(())
        },
    );
}

/// B11: the cookie for cell B read by cell A, with the fixed ids of the
/// HTTP fixtures. The property above covers random ids.
#[test]
fn b11_cookie_of_cell_b_is_refused_by_cell_a() {
    let field = cookie_field(&set_cookie(CELL_B, &TOKEN).unwrap_or_else(|e| panic!("{e}")));
    let read = read_cookie(CELL_A, &[field.as_slice()]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(read, CookieRead::Refused);
}

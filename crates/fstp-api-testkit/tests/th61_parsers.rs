//! ADR-013, TH-61 (TW-4) and TH-26: the `fstp-oauth` decoders accept the
//! strict subset and refuse the rest (M4 design sections 3.8 and 9).
//!
//! These call the production decoders directly, with no reference twin.
//! Each one gets inputs it must accept and inputs it must refuse, so a
//! decoder that refuses everything fails. The fuzz targets of design
//! section 9 cover the same decoders for panics.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_api_testkit::mc::oauth_model::{b64url, form};
use fstp_oauth::OauthError;
use fstp_prop::{check, prop_assert};

fn accepts<T: std::fmt::Debug>(what: &str, input: &[u8], r: Result<T, OauthError>) {
    if let Err(e) = r {
        panic!("{what} refused {:?}: {e}", String::from_utf8_lossy(input));
    }
}

fn refuses<T: std::fmt::Debug>(what: &str, input: &[u8], r: Result<T, OauthError>) {
    if let Ok(v) = r {
        panic!(
            "{what} accepted {:?} as {v:?}",
            String::from_utf8_lossy(input)
        );
    }
}

const URL_OK: [&str; 5] = [
    "https://agent.example/cb",
    "https://agent.example:8443/a/b?x=1",
    "http://127.0.0.1:8080/cb",
    "http://[::1]:53127/cb",
    "https://cell-a.example/mcp",
];

const URL_BAD: [&str; 12] = [
    "https://user@agent.example/cb",
    "https://user:pw@agent.example/cb",
    "https://agent.example/cb#x",
    "https://agent.example/cb#",
    "https://ag\u{e9}nt.example/cb",
    "https://agent.\u{0435}xample/cb",
    "https://agent.example/c b",
    "agent.example/cb",
    "//agent.example/cb",
    "javascript:alert(1)",
    "https://agent.example:99999/cb",
    "https://agent.example/cb\r\nX: y",
];

/// ADR-013, TW-4: the URL parser accepts absolute `https` and loopback
/// `http` URIs, and refuses userinfo, fragments, non-ASCII hosts, spaces,
/// control characters, relative references, other schemes and bad ports.
#[test]
fn adr013_url_parser_accepts_the_subset_only() {
    for u in URL_OK {
        accepts(
            "parse_url",
            u.as_bytes(),
            fstp_oauth::parse_url(u.as_bytes()),
        );
    }
    for u in URL_BAD {
        refuses(
            "parse_url",
            u.as_bytes(),
            fstp_oauth::parse_url(u.as_bytes()),
        );
    }
}

/// ADR-013, design section 9: the form decoder refuses duplicate
/// parameters and bad percent-encoding, and accepts a plain body.
#[test]
fn adr013_form_decoder_refuses_duplicates_and_bad_encoding() {
    let ok: [&[u8]; 3] = [
        b"a=1&b=2",
        b"token=abc&token_type_hint=refresh_token",
        b"a=%20x+y",
    ];
    let bad: [&[u8]; 4] = [b"a=1&a=2", b"a=%zz", b"a=%2", b"a=\xff"];
    for b in ok {
        accepts(
            "decode_form_urlencoded",
            b,
            fstp_oauth::decode_form_urlencoded(b),
        );
    }
    for b in bad {
        refuses(
            "decode_form_urlencoded",
            b,
            fstp_oauth::decode_form_urlencoded(b),
        );
    }
}

fn valid_authorize() -> Vec<(&'static str, String)> {
    vec![
        ("response_type", "code".to_owned()),
        ("client_id", "client-1".to_owned()),
        ("redirect_uri", "https://agent.example/cb".to_owned()),
        ("code_challenge", b64url(&[7; 32])),
        ("code_challenge_method", "S256".to_owned()),
        ("scope", "calls:read".to_owned()),
        ("resource", "https://cell-a.example/mcp".to_owned()),
        ("state", "s".to_owned()),
    ]
}

fn encode(pairs: &[(&str, String)]) -> Vec<u8> {
    let refs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    form(&refs)
}

/// ADR-013, design section 9: the authorisation query decoder accepts a
/// valid request and refuses any duplicated parameter.
#[test]
fn adr013_authorize_query_decoder_refuses_duplicates() {
    check("adr013_authorize_query_decoder_refuses_duplicates", |g| {
        let pairs = valid_authorize();
        let q = encode(&pairs);
        prop_assert!(
            fstp_oauth::decode_authorize_query(&q).is_ok(),
            "a valid query is refused: {:?}",
            fstp_oauth::decode_authorize_query(&q)
        );
        let i = g.usize_in(0..=pairs.len() - 1);
        let mut dup = pairs.clone();
        let extra = dup[i].clone();
        dup.push(extra);
        let q = encode(&dup);
        match fstp_oauth::decode_authorize_query(&q) {
            Ok(v) => Err(format!("a duplicated {} was accepted: {v:?}", pairs[i].0)),
            Err(_) => Ok(()),
        }
    });
}

/// ADR-013, design section 9: the token request decoder accepts both
/// grants and refuses any duplicated parameter.
#[test]
fn adr013_token_request_decoder_refuses_duplicates() {
    check("adr013_token_request_decoder_refuses_duplicates", |g| {
        let code = vec![
            ("grant_type", "authorization_code".to_owned()),
            ("code", b64url(&[1; 32])),
            ("redirect_uri", "https://agent.example/cb".to_owned()),
            ("client_id", "client-1".to_owned()),
            ("code_verifier", "v".repeat(43)),
            ("resource", "https://cell-a.example/mcp".to_owned()),
        ];
        let refresh = vec![
            ("grant_type", "refresh_token".to_owned()),
            ("refresh_token", b64url(&[2; 32])),
            ("client_id", "client-1".to_owned()),
        ];
        let pairs = if g.bool() { code } else { refresh };
        let body = encode(&pairs);
        prop_assert!(
            fstp_oauth::decode_token_request(&body).is_ok(),
            "a valid token request is refused: {:?}",
            fstp_oauth::decode_token_request(&body)
        );
        let i = g.usize_in(0..=pairs.len() - 1);
        let mut dup = pairs.clone();
        let extra = dup[i].clone();
        dup.insert(0, extra);
        match fstp_oauth::decode_token_request(&encode(&dup)) {
            Ok(v) => Err(format!("a duplicated {} was accepted: {v:?}", pairs[i].0)),
            Err(_) => Ok(()),
        }
    });
}

/// ADR-013, RFC 7591: the client metadata decoder accepts a registration
/// and refuses a duplicated member, a missing or empty `redirect_uris`,
/// and a non-object.
#[test]
fn adr013_client_metadata_decoder_is_strict() {
    let ok: [&[u8]; 2] = [
        br#"{"redirect_uris":["https://agent.example/cb"]}"#,
        br#"{"redirect_uris":["http://127.0.0.1/cb"],"client_name":"A","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}"#,
    ];
    let bad: [&[u8]; 6] = [
        br#"{"redirect_uris":["https://a.example/cb"],"redirect_uris":["https://b.example/cb"]}"#,
        br#"{"client_name":"A"}"#,
        br#"{"redirect_uris":[]}"#,
        br#"{"redirect_uris":"https://agent.example/cb"}"#,
        br#"["https://agent.example/cb"]"#,
        b"{",
    ];
    for b in ok {
        accepts(
            "decode_client_metadata",
            b,
            fstp_oauth::decode_client_metadata(b),
        );
    }
    for b in bad {
        refuses(
            "decode_client_metadata",
            b,
            fstp_oauth::decode_client_metadata(b),
        );
    }
}

/// ADR-013, RFC 6750: the bearer header parser accepts one `Bearer`
/// credential and refuses other schemes, an empty credential, a
/// second credential and a trailing line break.
#[test]
fn adr013_bearer_header_parser_is_strict() {
    let token = b64url(&[9; 32]);
    let ok = format!("Bearer {token}");
    let bad = [
        String::new(),
        "Bearer".to_owned(),
        "Bearer ".to_owned(),
        format!("Basic {token}"),
        format!("Bearer {token} {token}"),
        format!("Bearer {token},Bearer {token}"),
        format!("Bearer {token}\r\n"),
    ];
    accepts(
        "parse_bearer_header",
        ok.as_bytes(),
        fstp_oauth::parse_bearer_header(ok.as_bytes()),
    );
    for b in &bad {
        refuses(
            "parse_bearer_header",
            b.as_bytes(),
            fstp_oauth::parse_bearer_header(b.as_bytes()),
        );
    }
}

/// ADR-013: the base64url decoder accepts every unpadded encoding and
/// refuses padding, the standard alphabet's `+` and `/`, and a length of
/// one modulo four.
#[test]
fn adr013_base64url_decoder_accepts_unpadded_only() {
    check("adr013_base64url_decoder_accepts_unpadded_only", |g| {
        let bytes = g.bytes(0..=64);
        let text = b64url(&bytes);
        prop_assert!(
            fstp_oauth::decode_base64url(text.as_bytes()).is_ok(),
            "{text:?} is refused: {:?}",
            fstp_oauth::decode_base64url(text.as_bytes())
        );
        let bad = match g.u8_in(0..=3) {
            0 => format!("{text}="),
            1 => format!("{text}+"),
            2 => format!("/{text}"),
            _ => {
                let mut t = text.clone();
                while t.len() % 4 != 1 {
                    t.push('A');
                }
                t
            }
        };
        match fstp_oauth::decode_base64url(bad.as_bytes()) {
            Ok(v) => Err(format!("{bad:?} was accepted as {v:?}")),
            Err(_) => Ok(()),
        }
    });
}

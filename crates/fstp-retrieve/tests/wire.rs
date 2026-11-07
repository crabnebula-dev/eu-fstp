//! The retrieval result wire form (M7 design section 3.2). The fixture
//! files are the interface the assessor lane (L-PROC) reads.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_json::{parse, to_compact};
use fstp_retrieve::{Outcome, Refusal, SourceUrl, query_for, url_param};

fn fixture(name: &str) -> String {
    let path = format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).unwrap()
}

/// TH-12: both fixture files decode, and re-encode to the same JSON.
#[test]
fn th12_wire_fixtures_round_trip() {
    for name in ["result-retrieved.json", "result-refused.json"] {
        let v = parse(fixture(name).as_bytes()).unwrap();
        let o = Outcome::from_json(&v).unwrap();
        assert_eq!(to_compact(&o.to_json()), to_compact(&v), "{name}");
    }
    let v = parse(fixture("result-refused.json").as_bytes()).unwrap();
    assert_eq!(
        Outcome::from_json(&v).unwrap(),
        Outcome::Refused(Refusal::HttpStatus(404))
    );
}

/// TH-12: unknown members fail, so a reply cannot smuggle extra fields.
#[test]
fn th12_wire_refuses_unknown_members() {
    for bad in [
        r#"{"chain":["http://repo.test/"],"text":"x","truncated":false,"verified":true}"#,
        r#"{"refusal":"timeout","status":500}"#,
        r#"{"refusal":"nonsense"}"#,
        r#"{"chain":[],"text":"x","truncated":false}"#,
        r#"{"chain":["ftp://repo.test/"],"text":"x","truncated":false}"#,
    ] {
        assert!(
            Outcome::from_json(&parse(bad.as_bytes()).unwrap()).is_err(),
            "{bad}"
        );
    }
}

/// TH-12: the query for a URL decodes back to that URL, and a repeated or
/// badly escaped parameter is refused.
#[test]
fn th12_query_round_trip() {
    let u = SourceUrl::parse("https://repo.test/a%20b/%C3%A9?x=1&y=2").unwrap();
    assert_eq!(url_param(&query_for(&u)).as_deref(), Some(u.as_str()));
    assert_eq!(url_param("url=a&url=b"), None);
    assert_eq!(url_param("url=%zz"), None);
    assert_eq!(url_param("other=1"), None);
}

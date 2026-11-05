//! The public query parser (TH-26, H-05, I-87; M4 design section 9).
//!
//! The grammar is the module documentation of `src/query.rs`. Every
//! refusal must be the parser's own `PublicError::Query`, never the stub's
//! refusal. Every text is synthetic.
//!
//! Status: red. The W0 stub of `parse_public_query` refuses every input
//! with `PublicError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_prop::check;
use fstp_public::query::{MAX_QUERY_BYTES, MAX_SEARCH_BYTES};
use fstp_public::{PublicError, PublicPart, PublicQuery, parse_public_query};

fn q(part: PublicPart, search: Option<&str>) -> PublicQuery {
    PublicQuery {
        part,
        search: search.map(str::to_owned),
    }
}

/// TH-26: each accepted spelling gives its query.
#[test]
fn th26_public_query_accepts_the_grammar() {
    let cases: Vec<(&[u8], PublicQuery)> = vec![
        (b"part=programme", q(PublicPart::Programme, None)),
        (b"part=open_calls", q(PublicPart::OpenCalls, None)),
        (
            b"part=open_calls&q=well%20being",
            q(PublicPart::OpenCalls, Some("well being")),
        ),
        (
            b"part=open_calls&q=well+being",
            q(PublicPart::OpenCalls, Some("well being")),
        ),
        (
            b"q=%c3%a9t%C3%A9&part=open_calls",
            q(PublicPart::OpenCalls, Some("\u{e9}t\u{e9}")),
        ),
        (
            b"part=call&call=12",
            q(PublicPart::Call("12".to_owned()), None),
        ),
        (
            b"call=7&part=guide",
            q(PublicPart::Guide("7".to_owned()), None),
        ),
        (b"part=deadlines", q(PublicPart::Deadlines, None)),
        (b"part=eligibility", q(PublicPart::Eligibility, None)),
        (b"part=funded", q(PublicPart::Funded, None)),
        (b"part=finished", q(PublicPart::Finished, None)),
    ];
    for (input, want) in cases {
        assert_eq!(
            parse_public_query(input),
            Ok(want),
            "{:?}",
            String::from_utf8_lossy(input)
        );
    }
}

/// TH-26: every input outside the grammar is refused by the parser.
#[test]
fn th26_public_query_refuses_everything_else() {
    let long_search = format!("part=open_calls&q={}", "a".repeat(MAX_SEARCH_BYTES + 1));
    let long_input = format!("part=programme&{}", "x".repeat(MAX_QUERY_BYTES));
    let cases: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"part".to_vec(),
        b"part=".to_vec(),
        b"=programme".to_vec(),
        b"part=other".to_vec(),
        b"part=Programme".to_vec(),
        b"part=call".to_vec(),
        b"part=guide".to_vec(),
        b"part=programme&call=1".to_vec(),
        b"part=call&call=012".to_vec(),
        b"part=call&call=0".to_vec(),
        b"part=call&call=abc".to_vec(),
        b"part=call&call=123456789012345678901234567890123456789".to_vec(),
        b"part=funded&q=x".to_vec(),
        b"part=open_calls&q=".to_vec(),
        b"part=open_calls&q=%0A".to_vec(),
        b"part=open_calls&q=%7F".to_vec(),
        b"part=open_calls&q=%zz".to_vec(),
        b"part=open_calls&q=%4".to_vec(),
        b"part=open_calls&q=%E2%82".to_vec(),
        b"part=programme&part=funded".to_vec(),
        b"part=open_calls&q=a&q=b".to_vec(),
        b"part=programme&x=1".to_vec(),
        b"part=programme&".to_vec(),
        b"&part=programme".to_vec(),
        b"part=programme&&part=funded".to_vec(),
        "part=open_calls&q=\u{e9}".as_bytes().to_vec(),
        b"part=open_calls&q=a b".to_vec(),
        long_search.into_bytes(),
        long_input.into_bytes(),
    ];
    for input in cases {
        let r = parse_public_query(&input);
        assert!(
            matches!(r, Err(PublicError::Query(_))),
            "{:?} gave {r:?}",
            String::from_utf8_lossy(&input)
        );
    }
}

/// A generated query: any part, a call id of 1 to 38 digits, and a search
/// text of printable characters with spaces, `&`, `=`, `%`, `+` and
/// non-ASCII letters.
fn gen_query(g: &mut fstp_prop::Gen) -> PublicQuery {
    let digits = g.usize_in(1..=38);
    let mut id = String::from(char::from(*g.pick(b"123456789")));
    for _ in 1..digits {
        id.push(char::from(*g.pick(b"0123456789")));
    }
    let part = match g.u8_in(0..=7) {
        0 => PublicPart::Programme,
        1 => PublicPart::OpenCalls,
        2 => PublicPart::Call(id),
        3 => PublicPart::Guide(id),
        4 => PublicPart::Deadlines,
        5 => PublicPart::Eligibility,
        6 => PublicPart::Funded,
        _ => PublicPart::Finished,
    };
    let search = (part == PublicPart::OpenCalls && g.bool()).then(|| {
        let alphabet = [
            'a', 'Z', '0', ' ', '&', '=', '%', '+', '~', '\u{e9}', '\u{4e16}',
        ];
        let mut s = String::new();
        let n = g.usize_in(1..=40);
        for _ in 0..n {
            let c = *g.pick(&alphabet);
            if s.len().saturating_add(c.len_utf8()) <= MAX_SEARCH_BYTES {
                s.push(c);
            }
        }
        s
    });
    PublicQuery { part, search }
}

/// TH-26, fuzz target `public_query_parse`: the canonical spelling of
/// every query parses to an equal query and fits the size bound.
#[test]
fn th26_public_query_round_trips_through_its_canonical_spelling() {
    check("th26_public_query_round_trips", |g| {
        let want = gen_query(g);
        let text = want.to_query_string().map_err(|e| e.to_string())?;
        if text.len() > MAX_QUERY_BYTES {
            return Err(format!("{} bytes", text.len()));
        }
        match parse_public_query(text.as_bytes()) {
            Ok(got) if got == want => Ok(()),
            other => Err(format!("{text:?} gave {other:?}, not {want:?}")),
        }
    });
}

/// TH-26: the canonical spelling uses only `A-Z a-z 0-9 - . _ ~`, `=`, `&`
/// and upper-case percent escapes, in the order part, call, q.
#[test]
fn th26_public_query_canonical_spelling() {
    let text = q(PublicPart::OpenCalls, Some("a b&\u{e9}"))
        .to_query_string()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(text, "part=open_calls&q=a%20b%26%C3%A9");
    let text = q(PublicPart::Guide("42".to_owned()), None)
        .to_query_string()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(text, "part=guide&call=42");
}

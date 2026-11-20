//! The two Q35 creator queries on the wire (Q35 A, `overview.md` NOTE 8,
//! ADR-027): codes 13 and 14, canonical arguments, and one bit per answer.

#![allow(clippy::unwrap_used, reason = "test code")]

use std::collections::BTreeSet;

use fstp_vault_proto::{
    Query, QueryKind, WireAnswer, WireClass, WireProgramme, WireQuery, check_answers, decode_query,
};

fn wq(kind: u16, args: &str) -> WireQuery {
    WireQuery {
        kind,
        args: args.as_bytes().to_vec(),
    }
}

/// Q35: `ClassesDefined` is code 13 and `ProximityListsDeclared` code 14,
/// the indexes of the domain's `QueryKind::ALL`.
#[test]
fn q35_queries_take_codes_13_and_14() {
    assert_eq!(QueryKind::ClassesDefined.code(), 13);
    assert_eq!(QueryKind::ProximityListsDeclared.code(), 14);
    assert_eq!(QueryKind::from_code(13), Some(QueryKind::ClassesDefined));
    assert_eq!(
        QueryKind::from_code(14),
        Some(QueryKind::ProximityListsDeclared)
    );
}

/// Q35: the arguments are canonical, round-trip, and take the empty set.
#[test]
fn q35_queries_round_trip_on_the_wire() {
    let q = Query::ClassesDefined {
        programme: WireProgramme(7),
        classes: BTreeSet::from([WireClass(2), WireClass(10)]),
    };
    let w = q.to_wire().unwrap();
    assert_eq!(w.kind, 13);
    assert_eq!(
        w.args,
        b"{\"classes\":[\"2\",\"10\"],\"programme\":\"7\"}".to_vec()
    );
    assert_eq!(decode_query(&w).unwrap(), q);
    let l = Query::ProximityListsDeclared {
        programme: WireProgramme(7),
        lists: BTreeSet::new(),
    };
    let w = l.to_wire().unwrap();
    assert_eq!(w.kind, 14);
    assert_eq!(w.args, b"{\"lists\":[],\"programme\":\"7\"}".to_vec());
    assert_eq!(decode_query(&w).unwrap(), l);
}

/// Q35: another kind's members, a missing member or a number id are
/// refused.
#[test]
fn q35_query_args_are_checked_against_their_kind() {
    for (kind, args) in [
        (13, "{\"lists\":[],\"programme\":\"7\"}"),
        (14, "{\"classes\":[],\"programme\":\"7\"}"),
        (13, "{\"classes\":[]}"),
        (14, "{\"lists\":[1],\"programme\":\"7\"}"),
    ] {
        assert!(decode_query(&wq(kind, args)).is_err(), "{kind} {args}");
    }
}

/// Q35, NOTE 5: an answer to either query that lists accounts is refused.
#[test]
fn q35_answers_name_no_account() {
    let q = Query::ClassesDefined {
        programme: WireProgramme(7),
        classes: BTreeSet::new(),
    }
    .to_wire()
    .unwrap();
    let bit = WireAnswer {
        holds: true,
        accounts: None,
        epoch: 1,
    };
    assert!(check_answers(std::slice::from_ref(&q), std::slice::from_ref(&bit)).is_ok());
    let listed = WireAnswer {
        accounts: Some(Vec::new()),
        ..bit
    };
    assert!(check_answers(&[q], &[listed]).is_err());
}

//! TH-26, H-05: migration list validation on arbitrary lists.
//!
//! The input decodes into limits and a list of (version, name, SQL)
//! entries. A reference model of the structural rules runs alongside
//! `validate_entries`, and the two must agree:
//!
//! - the first structural problem (count, version sequence, duplicate
//!   version, name syntax, duplicate name) is the error returned, unless an
//!   earlier entry's SQL fails first;
//! - SQL that does not split, or splits into nothing, fails at its entry
//!   with the splitter's own error;
//! - a statement led by a transaction control keyword, `DEALLOCATE` or
//!   `DISCARD`, or holding a NUL character, makes its entry fail at that
//!   statement or an earlier one;
//! - when such a statement is the one that fails, the error names the
//!   matching rule;
//! - an accepted list keeps every entry, with the SHA-256 of its SQL and
//!   the splitter's statements.
//!
//! Layout: byte 0 selects the limits. The rest is entries separated by
//! 0xFF, which never occurs in UTF-8. An entry is a version mode byte, a
//! name mode byte, a name length byte, the name bytes and the SQL bytes.

#![no_main]

use std::collections::HashMap;

use fstp_migrate::{
    MigrationLimits, SplitLimits, StatementRule, ValidationError, split_statements,
    validate_entries,
};

/// Leading words that drop the session state of the runner's connection.
const SESSION_WORDS: &[&str] = &["DEALLOCATE", "DISCARD"];
use libfuzzer_sys::fuzz_target;

const NAME_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
const TRANSACTION_WORDS: &[&str] = &[
    "BEGIN",
    "START",
    "COMMIT",
    "END",
    "ROLLBACK",
    "ABORT",
    "SAVEPOINT",
    "RELEASE",
];
const MAX_ENTRIES: usize = 24;

fn limits(selector: u8) -> MigrationLimits {
    let s = usize::from(selector);
    MigrationLimits {
        max_migrations: if s & 1 == 0 { 10_000 } else { (s >> 1) & 15 },
        max_name_len: 1 + ((s >> 3) & 15) * 4,
        split: SplitLimits {
            max_input_bytes: 256 << ((s >> 6) & 3),
            max_statements: 4 + (s & 7),
            ..SplitLimits::default()
        },
    }
}

/// One decoded entry with owned text.
struct Entry {
    version: u32,
    name: String,
    sql: String,
}

fn decode(data: &[u8]) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    for chunk in data.split(|&b| b == 0xFF).take(MAX_ENTRIES) {
        let expected = u32::try_from(out.len())
            .unwrap_or(u32::MAX)
            .saturating_add(1);
        let (vmode, rest) = chunk.split_first().map_or((0, &[][..]), |(a, r)| (*a, r));
        let (nmode, rest) = rest.split_first().map_or((0, &[][..]), |(a, r)| (*a, r));
        let (nlen, rest) = rest.split_first().map_or((1, &[][..]), |(a, r)| (*a, r));
        let nlen = usize::from(nlen % 16).min(rest.len());
        let (name_bytes, sql_bytes) = rest.split_at(nlen);
        let version = match vmode % 6 {
            1 => expected.saturating_add(1),
            2 => expected.saturating_sub(1),
            3 => u32::from(vmode),
            4 => u32::MAX,
            _ => expected,
        };
        let name = if nmode % 3 == 2 {
            String::from_utf8_lossy(name_bytes).into_owned()
        } else {
            name_bytes
                .iter()
                .map(|&b| char::from(NAME_ALPHABET[usize::from(b) % NAME_ALPHABET.len()]))
                .collect()
        };
        out.push(Entry {
            version,
            name,
            sql: String::from_utf8_lossy(sql_bytes).into_owned(),
        });
    }
    out
}

fn valid_name(name: &str, max: usize) -> bool {
    !name.is_empty()
        && name.len() <= max
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The leading word of a statement, as the splitter's scanner sees it.
fn leading_word(stmt: &str) -> &str {
    let bytes = stmt.as_bytes();
    if !bytes
        .first()
        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_' || *b >= 0x80)
    {
        return "";
    }
    let end = bytes
        .iter()
        .position(|&b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80))
        .unwrap_or(bytes.len());
    &stmt[..end]
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let limits = limits(selector);
    let entries = decode(rest);
    let list: Vec<(u32, &str, &str)> = entries
        .iter()
        .map(|e| (e.version, e.name.as_str(), e.sql.as_str()))
        .collect();
    let result = validate_entries(list.iter().copied(), &limits);

    if list.len() > limits.max_migrations {
        assert!(matches!(
            result,
            Err(ValidationError::TooManyMigrations { .. })
        ));
        return;
    }
    let mut names: HashMap<&str, u32> = HashMap::new();
    for (position, &(version, name, sql)) in list.iter().enumerate() {
        let expected = u32::try_from(position).unwrap() + 1;
        if version != expected {
            let want = if version >= 1 && version < expected {
                ValidationError::DuplicateVersion { position, version }
            } else {
                ValidationError::VersionOutOfSequence {
                    position,
                    expected,
                    found: version,
                }
            };
            assert_eq!(result, Err(want));
            return;
        }
        if !valid_name(name, limits.max_name_len) {
            assert_eq!(result, Err(ValidationError::InvalidName { version }));
            return;
        }
        if let Some(&first) = names.get(name) {
            assert_eq!(
                result,
                Err(ValidationError::DuplicateName { version, first })
            );
            return;
        }
        names.insert(name, version);
        let statements = match split_statements(sql, &limits.split) {
            Ok(s) => s,
            Err(error) => {
                assert_eq!(result, Err(ValidationError::Split { version, error }));
                return;
            }
        };
        if statements.is_empty() {
            assert_eq!(result, Err(ValidationError::Empty { version }));
            return;
        }
        // The first statement that must be rejected, by an independent
        // check of the simplest rules.
        let led_by = |text: &str, words: &[&str]| {
            let word = leading_word(text);
            words.iter().any(|k| word.eq_ignore_ascii_case(k))
        };
        let must_reject = statements.iter().position(|s| {
            s.text().contains('\0')
                || led_by(s.text(), TRANSACTION_WORDS)
                || led_by(s.text(), SESSION_WORDS)
        });
        if let Err(ValidationError::Statement {
            version: v,
            statement,
            line,
            rule,
        }) = &result
            && *v == version
        {
            assert!(*statement >= 1 && *statement <= statements.len());
            assert_eq!(*line, statements[statement - 1].line());
            if let Some(j) = must_reject {
                assert!(*statement <= j + 1, "a required rejection came too late");
            }
            let text = statements[statement - 1].text();
            if text.contains('\0') {
                assert_eq!(*rule, StatementRule::NulCharacter);
            } else if led_by(text, TRANSACTION_WORDS) {
                assert_eq!(*rule, StatementRule::TransactionControl);
            } else if led_by(text, SESSION_WORDS) {
                assert_eq!(*rule, StatementRule::SessionState);
            }
            return;
        }
        assert!(
            must_reject.is_none(),
            "statement {:?} of migration {version} was not rejected",
            must_reject
        );
    }
    let checked = result.expect("a list that passes the reference must validate");
    assert_eq!(checked.len(), list.len());
    for (m, &(version, name, sql)) in checked.iter().zip(&list) {
        assert_eq!((m.version(), m.name(), m.sql()), (version, name, sql));
        assert_eq!(m.checksum(), &fstp_crypto::sha256(sql.as_bytes()));
        let again = split_statements(sql, &limits.split).unwrap();
        assert_eq!(m.statements(), again.as_slice());
    }
});

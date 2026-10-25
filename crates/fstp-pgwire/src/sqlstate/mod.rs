//! SQLSTATE codes and their standard condition names.
//!
//! The table comes from a real PostgreSQL server, never from memory.
//! `tools/gen-sqlstate.sh` raises every condition name in PL/pgSQL on a
//! throwaway server and writes `generated.rs`; the header of that file
//! names the server version and the date. Regenerate it with
//! `bash tools/gen-sqlstate.sh` after a server upgrade. `--check` fails
//! when the committed table differs from the server's answers.
//!
//! [`DbError`](crate::DbError) uses the table for its Display and Debug
//! output, for example `ERROR 23505 unique_violation`.

// The generator writes the table; rustfmt must not change it, so that
// `gen-sqlstate.sh --check` can compare it byte for byte.
#[rustfmt::skip]
mod generated;

/// Every SQLSTATE code with a standard condition name, as `(code, name)`
/// pairs sorted by code. A name can stand for more than one code.
#[must_use]
pub fn conditions() -> &'static [(&'static str, &'static str)] {
    generated::CONDITIONS
}

/// The standard condition name of `code`, for example
/// `unique_violation` for `23505`. `None` for a code without one.
#[must_use]
pub fn condition_name(code: &str) -> Option<&'static str> {
    lookup(generated::CONDITIONS, code)
}

/// The condition name of `code`'s class: the name of the code made of its
/// first two characters and `000`. For example
/// `integrity_constraint_violation` for any `23` code. `None` when the
/// class has no condition name or `code` is shorter than two characters.
#[must_use]
pub fn class_name(code: &str) -> Option<&'static str> {
    lookup(generated::CLASSES, code.get(..2)?)
}

fn lookup(table: &'static [(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    let i = table.binary_search_by(|(k, _)| (*k).cmp(key)).ok()?;
    table.get(i).map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Binary search needs strictly increasing keys, and each row must be
    /// a well-formed code and name.
    #[test]
    fn tables_are_sorted_and_well_formed() {
        assert!(generated::CONDITIONS.len() >= 100);
        for pair in generated::CONDITIONS.windows(2) {
            if let [(a, _), (b, _)] = pair {
                assert!(a < b, "{a} >= {b}");
            }
        }
        for (code, name) in generated::CONDITIONS {
            assert_eq!(code.len(), 5, "{code}");
            assert!(
                code.bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase()),
                "{code}"
            );
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{name}"
            );
            assert_eq!(condition_name(code), Some(*name));
        }
        for pair in generated::CLASSES.windows(2) {
            if let [(a, _), (b, _)] = pair {
                assert!(a < b, "{a} >= {b}");
            }
        }
    }

    /// The class table holds exactly the codes that end in 000.
    #[test]
    fn classes_are_the_codes_ending_in_000() {
        let from_conditions: Vec<(String, &str)> = generated::CONDITIONS
            .iter()
            .filter_map(|(code, name)| {
                code.strip_suffix("000")
                    .map(|class| (class.to_owned(), *name))
            })
            .collect();
        let classes: Vec<(String, &str)> = generated::CLASSES
            .iter()
            .map(|(class, name)| ((*class).to_owned(), *name))
            .collect();
        assert_eq!(classes, from_conditions);
    }

    #[test]
    fn lookups() {
        assert_eq!(condition_name("23505"), Some("unique_violation"));
        assert_eq!(class_name("23505"), Some("integrity_constraint_violation"));
        assert_eq!(condition_name("23P99"), None);
        assert_eq!(class_name("23P99"), Some("integrity_constraint_violation"));
        assert_eq!(condition_name("ZZ999"), None);
        assert_eq!(class_name("ZZ999"), None);
        assert_eq!(class_name("2"), None);
        assert_eq!(class_name(""), None);
        assert_eq!(condition_name("23505x"), None);
        // A multibyte character at the class boundary is no class.
        assert_eq!(class_name("2\u{e9}"), None);
    }
}

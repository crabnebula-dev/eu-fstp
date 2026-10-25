#!/usr/bin/env bash
# Generates src/sqlstate/generated.rs, the table of SQLSTATE codes and
# their standard condition names, from a real PostgreSQL server.
#
# Nothing in the table comes from memory or from a copied list. The script:
#
# 1. Extracts candidate names from the strings of the server's PL/pgSQL
#    library (plpgsql.so), which embeds the condition name map that
#    PL/pgSQL uses. The linker stores a name that ends another string only
#    once, inside the longer one (active_sql_transaction inside
#    no_active_sql_transaction). So every suffix of every string that is a
#    lowercase identifier becomes a candidate.
# 2. Starts a throwaway server from the same installation. It listens on a
#    Unix socket in a private temporary directory only, with peer
#    authentication, and is stopped and deleted on exit.
# 3. For each candidate, runs a PL/pgSQL block that raises it with
#    RAISE ... USING ERRCODE = <name> and reads RETURNED_SQLSTATE with
#    GET STACKED DIAGNOSTICS. A name the server does not recognise raises a
#    different error, which the block detects by its message.
# 4. Finds every code each name stands for. A few names cover two codes
#    (for example a warning and an error), and RAISE reports only the
#    first. So the script raises every code in each class seen in step 3,
#    all 46656 subclasses of it, and records which name's exception
#    handler catches it. Handlers for class names (codes ending in 000)
#    are left out of this step, because they catch a whole class.
# 5. Reads errcodes.txt from the same installation (pg_config --sharedir).
#    PL/pgSQL has no condition names for some classes (in PostgreSQL 16:
#    00 successful completion, 01 warning and 02 no data), so the server
#    cannot raise them by name. Rows of those classes come from
#    errcodes.txt, and the header names the classes. For every other
#    class, the server's answers must equal errcodes.txt exactly, or the
#    run fails.
# 6. Writes the Rust table sorted by code, plus the class names: the codes
#    ending in 000, keyed by their first two characters.
#
# Usage:
#   bash tools/gen-sqlstate.sh           regenerate src/sqlstate/generated.rs
#   bash tools/gen-sqlstate.sh --check   regenerate into a temporary file and
#                                        fail if anything but the date and
#                                        server version lines differs
#
# The PostgreSQL binaries come from FSTP_PG_BIN, else from pg_config. When
# run as root, the throwaway server runs as the postgres user.
# Requires: bash, strings (binutils), grep, sed, sort, diff and PostgreSQL.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate="$(dirname "$here")"
out="$crate/src/sqlstate/generated.rs"

mode="write"
case "${1:-}" in
    "") ;;
    --check) mode="check" ;;
    *)
        echo "usage: bash tools/gen-sqlstate.sh [--check]" >&2
        exit 2
        ;;
esac

if [ -n "${FSTP_PG_BIN:-}" ]; then
    bindir="$FSTP_PG_BIN"
else
    bindir="$(pg_config --bindir)"
fi
for b in initdb pg_ctl psql pg_config; do
    if [ ! -x "$bindir/$b" ]; then
        echo "$bindir/$b not found; set FSTP_PG_BIN" >&2
        exit 1
    fi
done
pkglibdir="$("$bindir/pg_config" --pkglibdir)"
sharedir="$("$bindir/pg_config" --sharedir)"
plpgsql="$pkglibdir/plpgsql.so"
if [ ! -f "$plpgsql" ]; then
    echo "$plpgsql not found" >&2
    exit 1
fi

tmp="$(mktemp -d)"
run=()
if [ "$(id -u)" = 0 ]; then
    chown postgres:postgres "$tmp"
    run=(runuser -u postgres --)
fi
cleanup() {
    if [ -f "$tmp/data/postmaster.pid" ]; then
        "${run[@]}" "$bindir/pg_ctl" -D "$tmp/data" -m immediate -s stop > /dev/null 2>&1 || true
    fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT

# Step 1: candidate names from the PL/pgSQL library, with every suffix.
strings -n 3 "$plpgsql" \
    | awk '{ for (i = 1; i <= length($0) - 2; i++) print substr($0, i) }' \
    | grep -E '^[a-z][a-z0-9_]{2,62}$' | LC_ALL=C sort -u > "$tmp/candidates"
chmod 0644 "$tmp/candidates"

# Step 2: a throwaway server on a private Unix socket.
"${run[@]}" "$bindir/initdb" -D "$tmp/data" --auth-local=peer --auth-host=reject \
    --encoding=UTF8 --locale=C --no-sync --no-instructions > "$tmp/initdb.log" 2>&1
"${run[@]}" "$bindir/pg_ctl" -D "$tmp/data" -l "$tmp/server.log" -w -s \
    -o "-c listen_addresses='' -c unix_socket_directories='$tmp' -c fsync=off" start

psql() {
    "${run[@]}" "$bindir/psql" -X -q -A -t -v ON_ERROR_STOP=1 -h "$tmp" -d postgres "$@"
}

server_version="$(psql -c 'SHOW server_version')"
server_version_num="$(psql -c 'SHOW server_version_num')"

# Steps 3 and 4 run in one session, so the temporary objects stay visible.
{
    cat <<'SQL'
CREATE TEMP TABLE candidate (name text PRIMARY KEY);
SQL
    echo "COPY candidate (name) FROM STDIN;"
    cat "$tmp/candidates"
    echo '\.'
    cat <<'SQL'
-- Step 3: the code that RAISE reports for each recognised name. A name the
-- server does not recognise fails with another message, so it yields NULL.
CREATE FUNCTION pg_temp.raise_name(n text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
    code text;
    msg text;
BEGIN
    RAISE EXCEPTION USING ERRCODE = n, MESSAGE = 'fstp-sqlstate-probe';
EXCEPTION WHEN OTHERS OR query_canceled OR assert_failure THEN
    GET STACKED DIAGNOSTICS code = RETURNED_SQLSTATE, msg = MESSAGE_TEXT;
    IF msg = 'fstp-sqlstate-probe' THEN
        RETURN code;
    END IF;
    RETURN NULL;
END
$f$;
CREATE TEMP TABLE raised AS
    SELECT name, pg_temp.raise_name(name) AS code FROM candidate;
DELETE FROM raised WHERE code IS NULL;

-- Step 4: a function whose handlers name every specific condition. Class
-- names are left out, because their handlers catch a whole class.
DO $d$
DECLARE
    body text := '';
    r record;
BEGIN
    FOR r IN SELECT name FROM raised WHERE right(code, 3) <> '000' ORDER BY name LOOP
        body := body || format('WHEN %s THEN RETURN %L; ', r.name, r.name);
    END LOOP;
    EXECUTE format(
        'CREATE FUNCTION pg_temp.catch_code(c text) RETURNS text LANGUAGE plpgsql AS %L',
        'BEGIN RAISE EXCEPTION USING ERRCODE = c, MESSAGE = ''fstp-sqlstate-probe''; '
        || 'EXCEPTION ' || body
        || 'WHEN OTHERS OR query_canceled OR assert_failure THEN RETURN NULL; END');
END
$d$;
CREATE TEMP TABLE alphabet AS
    SELECT chr(c) AS ch FROM generate_series(48, 57) c
    UNION ALL SELECT chr(c) FROM generate_series(65, 90) c;
CREATE TEMP TABLE caught AS
    SELECT code, pg_temp.catch_code(code) AS name
    FROM (
        SELECT DISTINCT left(r.code, 2) || a.ch || b.ch || c.ch AS code
        FROM raised r, alphabet a, alphabet b, alphabet c
    ) all_codes;
DELETE FROM caught WHERE name IS NULL;

-- Every code: specific codes from step 4, class codes from step 3.
CREATE TEMP TABLE result AS
    SELECT code, name FROM caught
    UNION
    SELECT code, name FROM raised WHERE right(code, 3) = '000';
SQL
    # Sanity checks, each printed as one line for the script to test.
    cat <<'SQL'
SELECT 'check-raised-found ' || count(*) FROM raised r
    WHERE NOT EXISTS (SELECT 1 FROM result x WHERE x.code = r.code AND x.name = r.name);
SELECT 'check-duplicate-codes ' || count(*) FROM (
    SELECT code FROM result GROUP BY code HAVING count(*) > 1) d;
SELECT 'check-wide-names ' || count(*) FROM (
    SELECT name FROM result GROUP BY name HAVING count(*) > 2) w;
SELECT 'row ' || code || ' ' || name FROM result ORDER BY code COLLATE "C";
SQL
} > "$tmp/probe.sql"
chmod 0644 "$tmp/probe.sql"

psql -f "$tmp/probe.sql" > "$tmp/probe.out"

for check in check-raised-found check-duplicate-codes check-wide-names; do
    n="$(sed -n "s/^$check //p" "$tmp/probe.out")"
    if [ "$n" != "0" ]; then
        echo "sanity check $check failed: $n" >&2
        exit 1
    fi
done
sed -n 's/^row //p' "$tmp/probe.out" > "$tmp/rows"
rows="$(wc -l < "$tmp/rows")"
if [ "$rows" -lt 100 ]; then
    echo "only $rows conditions found; the probe did not work" >&2
    exit 1
fi
if grep -Ev '^[0-9A-Z]{5} [a-z][a-z0-9_]*$' "$tmp/rows" > /dev/null; then
    echo "malformed row in the probe output" >&2
    exit 1
fi

# Step 5: errcodes.txt from the same installation. Rows of the classes the
# server answered for must equal the server's rows. Rows of the classes
# that PL/pgSQL has no names for are taken from it.
errcodes="$sharedir/errcodes.txt"
if [ ! -f "$errcodes" ]; then
    echo "$errcodes not found" >&2
    exit 1
fi
grep -E '^[0-9A-Z]{5} +[EWS] +[A-Z_0-9]+ +[a-z_0-9]+$' "$errcodes" \
    | awk '{ print $1 " " $4 }' | LC_ALL=C sort > "$tmp/errcodes"
cut -c1-2 "$tmp/rows" | LC_ALL=C sort -u > "$tmp/probed-classes"
awk 'NR == FNR { seen[$0] = 1; next } (substr($1, 1, 2) in seen)' \
    "$tmp/probed-classes" "$tmp/errcodes" > "$tmp/errcodes-probed"
if ! diff "$tmp/errcodes-probed" "$tmp/rows" > "$tmp/crosscheck.diff"; then
    echo "the server's answers differ from $errcodes:" >&2
    cat "$tmp/crosscheck.diff" >&2
    exit 1
fi
awk 'NR == FNR { seen[$0] = 1; next } !(substr($1, 1, 2) in seen)' \
    "$tmp/probed-classes" "$tmp/errcodes" > "$tmp/errcodes-only"
only_classes="$(cut -c1-2 "$tmp/errcodes-only" | LC_ALL=C sort -u | tr '\n' ' ' | sed 's/ $//')"
LC_ALL=C sort "$tmp/rows" "$tmp/errcodes-only" > "$tmp/all"
probed="$(wc -l < "$tmp/rows")"
from_file="$(wc -l < "$tmp/errcodes-only")"
total="$(wc -l < "$tmp/all")"
classes="$(grep -c '^..000 ' "$tmp/all")"

# Step 6: the Rust table.
generated="$tmp/generated.rs"
{
    cat <<EOF2
// @generated by crates/fstp-pgwire/tools/gen-sqlstate.sh. Do not edit.
//
// Generated on $(date -u +%Y-%m-%d) from PostgreSQL $server_version
// (server_version_num $server_version_num), queried through psql.
// $probed codes: raised by condition name in PL/pgSQL on that server, as
// the generator's header describes. They equal errcodes.txt of the same
// installation for their classes.
// $from_file codes: classes $only_classes, which have no PL/pgSQL condition
// names. Taken from that errcodes.txt.
// $total codes in all, of which $classes are class codes.

/// Every SQLSTATE code with a standard condition name, sorted by code.
pub(super) const CONDITIONS: &[(&str, &str)] = &[
EOF2
    while read -r code name; do
        printf '    ("%s", "%s"),\n' "$code" "$name"
    done < "$tmp/all"
    cat <<'EOF2'
];

/// The class conditions: the first two characters of each code that ends
/// in 000, with its condition name, sorted by class.
pub(super) const CLASSES: &[(&str, &str)] = &[
EOF2
    grep '^..000 ' "$tmp/all" | while read -r code name; do
        printf '    ("%s", "%s"),\n' "${code:0:2}" "$name"
    done
    echo "];"
} > "$generated"

if [ "$mode" = check ]; then
    # The date and server version lines may differ, for example on another
    # PostgreSQL 16 minor release in CI. The table itself must not.
    header='^// (Generated on |\(server_version_num )'
    if diff <(grep -Ev "$header" "$out") <(grep -Ev "$header" "$generated"); then
        echo "$out is up to date ($total codes)"
    else
        echo "$out differs from the server's answers" >&2
        exit 1
    fi
else
    mkdir -p "$(dirname "$out")"
    cp "$generated" "$out"
    echo "wrote $out ($total codes, $classes classes; $from_file from errcodes.txt, classes $only_classes)"
fi

#!/usr/bin/env bash
# Compiles the auth pages, then builds and runs fstp-devstack: one
# SaaS-mode world on localhost, with its PostgreSQL 16 clusters, a cell,
# the vault and the witness (M3 design sections 0.1, 2.3 and 11.2). Local
# development only.
#
# Usage: tools/devstack/run.sh
#
# The pages of web/src are compiled by the pinned tsc that
# web/node_modules already holds (ADR-003). This script never runs
# npm install. The cell serves web/dist/auth with the shell and stylesheet
# of web/src/auth under the cell CSP.
#
# The stack prints one "<name> <url>" line for each of cell, vault,
# witness, health and enrol, then "ready". SIGTERM or Ctrl-C stops it.
#
# Environment:
#   FSTP_PG_BIN        a PostgreSQL 16 bin directory (fstp-pgtest finds one
#                      through pg_config when it is unset)
#   CARGO_TARGET_DIR   where cargo builds (default: <repo>/target)
#   CARGO_INCREMENTAL  defaults to 0 here, to keep the build small
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target="${CARGO_TARGET_DIR:-$root/target}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

tsc="$root/web/node_modules/.bin/tsc"
if [ ! -x "$tsc" ]; then
  echo "run.sh: $tsc is missing; the pinned TypeScript compiler of web/package-lock.json is not installed" >&2
  exit 1
fi
"$tsc" -p "$root/web/tsconfig.json"

cd "$root"
cargo build --locked -p fstp-celltest --bin fstp-devstack

# exec, so that SIGTERM reaches the stack itself.
exec "$target/debug/fstp-devstack"

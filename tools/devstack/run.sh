#!/usr/bin/env bash
# Builds and runs fstp-devstack: one SaaS-mode world on localhost, with its
# PostgreSQL 16 clusters, a cell, the vault and the witness (M3 design
# sections 0.1 and 2.3). Local development only.
#
# Usage: tools/devstack/run.sh
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

cd "$root"
cargo build --locked -p fstp-celltest --bin fstp-devstack

# exec, so that SIGTERM reaches the stack itself.
exec "$target/debug/fstp-devstack"

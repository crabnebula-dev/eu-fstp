#!/usr/bin/env bash
# Compiles the auth pages, then builds and runs fstp-devstack: one
# SaaS-mode world on localhost, with its PostgreSQL 16 clusters, a cell,
# the vault, the witness and the edge (M3 design sections 0.1, 2.3 and
# 11.2). Local development only.
#
# Usage: tools/devstack/run.sh
#
# The pages of web/src are compiled by the pinned tsc that
# web/node_modules already holds (ADR-003). This script never runs
# npm install. The cell serves web/dist/auth with the shell and stylesheet
# of web/src/auth under the cell CSP.
#
# The stack prints one "<name> <url>" line for each of cell, vault,
# witness, health and enrol, then "ready". Before them it prints
# "origin-ca <path>": the CA certificate of the cell and vault origins.
# SIGTERM or Ctrl-C stops it.
#
# Port 443. The relying party origin carries no port, so a browser must
# reach the cell at https://<cell host>/ on loopback port 443. The edge
# binds 127.0.0.1:443 when it may. macOS lets only root bind a port below
# 1024 on loopback, so the edge then listens on FSTP_EDGE_PORT, and a
# forwarder run as root carries 127.0.0.1:443 there. Start it first, in
# another terminal, and leave it running:
#
#   sudo "$CARGO_TARGET_DIR/debug/fstp-devstack" forward 443 18443
#
# The stack refuses to print URLs that 127.0.0.1:443 does not reach.
#
# Logging in through a browser:
#
#   1. Trust the origin CA once, for example on macOS:
#      sudo security add-trusted-cert -d -r trustRoot \
#        -k /Library/Keychains/System.keychain <origin-ca path>
#      WebAuthn refuses a page with a certificate error, so this is
#      needed. Remove it again with `sudo security delete-certificate`.
#   2. Open the enrol link. It enrols the first tenant admin's passkey
#      through the split invitation and opens the account page, which
#      sends the browser to the login page.
#   3. Log in with the passkey on the login page.
#
# Environment:
#   FSTP_PG_BIN        a PostgreSQL 16 bin directory (fstp-pgtest finds one
#                      through pg_config when it is unset)
#   FSTP_EDGE_PORT     the edge port when 443 cannot be bound (default 18443)
#   CARGO_TARGET_DIR   where cargo builds (default: <repo>/target)
#   CARGO_INCREMENTAL  defaults to 0 here, to keep the build small
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target="${CARGO_TARGET_DIR:-$root/target}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export FSTP_EDGE_PORT="${FSTP_EDGE_PORT:-18443}"

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

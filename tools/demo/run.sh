#!/usr/bin/env bash
# Builds and runs the M4 demo: the compiled pages served by fstp-e2e-cell
# on loopback, with the synthetic SuperSAFE tenant seeded (M4 design
# sections 1.2, 2 and 8.7). Test only: the cell holds synthetic data, and
# its control routes never exist in a shipped cell (layering rule A9).
#
# Usage: tools/demo/run.sh [start]          build, start, seed the default stage
#        tools/demo/run.sh seed review <stage>
#        tools/demo/run.sh seed applicant <at>
#        tools/demo/run.sh seed grant <scene>   the post-grant lifecycle (M5)
#        tools/demo/run.sh seed setup           M1 holds a fully built programme
#                                               draft (the creator review)
#        tools/demo/run.sh clock <to>           grant clock: milestone_start p36
#                                               due_minus_14 due due_plus_7
#        tools/demo/run.sh forge-fail           the fake forge answers 404 once
#        tools/demo/run.sh reset            a fresh cell with its first admin link
#        tools/demo/run.sh advance <minutes>
#        tools/demo/run.sh mail <email>
#        tools/demo/run.sh stop
#        tools/demo/run.sh e2e [playwright args...]   every spec but the M3
#                                               ones (project demo)
#
# Review stages:   submitted stage1 stage1_scored stage2 ranked ranked_tie irc_review
# Applicant states: OPEN_CALL STAGE2 IRC_REVIEW_MINOR NEGOTIATION NOT_SELECTED
#                   DEFERRED_AFTER_CONCERN INELIGIBLE
# Grant scenes:    NEGOTIATION_READY SENT EFFECTIVE IN_EXECUTION UNDER_REVIEW PAID
#                   ALL_CLOSED (x from negotiation to a closed grant with its
#                   five funder outputs, through the real operations)
#                   HARDSHIP (x in execution, the lead filed a hardship
#                   request, finance verifies its evidence on the vault page)
#
# Every seed replaces the cell's state and prints one-time enrolment links
# for its people. Open a link in Chromium or Chrome to enrol a passkey and
# sign in. A name under .localhost is a secure context there, so passkeys
# work over plain HTTP. See docs/handoff/m4-demo.md for the click paths.
#
# Environment:
#   FSTP_DEMO_PORT   first port (default 8640): cell a on it, its control
#                    base on the next, then cell b and its control
#   FSTP_DEMO_STATE  directory for the pid, the log and the stack manifest
#                    (default: target/demo)
#   FSTP_DEMO_SEED   the default seed of `start` (default: "review stage1")
#   FSTP_DEMO_SIGNIN `on` (default) starts the cell with --demo-signin: the
#                    demo page signs each person in with one click, no
#                    passkey. `off` starts it as the e2e suite runs it.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PORT=${FSTP_DEMO_PORT:-8640}
STATE=${FSTP_DEMO_STATE:-$ROOT/target/demo}
SEED=${FSTP_DEMO_SEED:-review stage1}
SIGNIN=${FSTP_DEMO_SIGNIN:-on}
CONTROL="http://127.0.0.1:$((PORT + 1))"
ORIGIN="http://a.fstp.localhost:$PORT"
CELL_BIN="$ROOT/target/debug/fstp-e2e-cell"

die() {
  printf 'run.sh: %s\n' "$*" >&2
  exit 1
}

usage() {
  sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'
  exit 64
}

# Prints the members of a JSON reply that a person needs, with node,
# which the web build needs anyway (ADR-003). No Python (CLAUDE.md).
show() {
  node -e '
    let s = "";
    process.stdin.on("data", (d) => (s += d)).on("end", () => {
      const v = JSON.parse(s);
      if (v.code) { console.error("refused: " + JSON.stringify(v)); process.exit(1); }
      if (v.first_admin) {
        console.log("First tenant admin: " + v.first_admin.email);
        console.log("  enrol: " + v.first_admin.url);
        return;
      }
      if (v.scene === "programme_setup") {
        console.log("Programme set-up: draft programme " + v.programme + " (SuperSAFE), every step validates");
        for (const [k, p] of Object.entries(v.people)) {
          console.log(("  " + k).padEnd(6) + p.label.padEnd(22) + p.invite_url);
        }
        return;
      }
      if (v.people) {
        console.log("Call " + v.call + " of programme " + v.programme + " (SuperSAFE)");
        for (const [k, p] of Object.entries(v.people)) {
          console.log(("  " + k).padEnd(6) + p.label.padEnd(22) + p.invite_url);
        }
        for (const [k, p] of Object.entries(v.proposals)) {
          console.log("  proposal " + k + " = " + p.id + " (" + p.state + ") " + p.title);
        }
        return;
      }
      if (v.grant_at) {
        console.log("Grant scene " + v.grant_at + ": proposal " + v.proposal + ", " + v.title);
        console.log("  agreed plan " + v.plan + ", milestone " + v.milestone + " (for the determination and payment forms)");
        if (v.contract) console.log("  contract " + v.contract);
        if (v.request) console.log("  payment request " + v.request);
        if (v.bank) console.log("  bank details entered " + v.bank.entered + ", " + (v.bank.verified ? "verified" : "not verified") + "; P-36 hold of " + v.bank.hold_days + " days ends " + v.bank.hold_ends + (v.bank.hold_passed ? " (passed)" : " (release refused until then, I-33)"));
        for (const r of v.reports) console.log("  funder report " + r.report + " (" + r.kind + ")");
        console.log("  open " + process.argv[2] + "/demo and choose Sign in as for each person");
        return;
      }
      if (v.at) {
        console.log("Call " + v.call.id + ": " + v.call.title + ", deadline " + v.call.deadline);
        if (v.lead) console.log("  lead      " + v.lead.enrol_url);
        if (v.guardian) console.log("  guardian  " + v.guardian.enrol_url);
        if (v.proposal) console.log("  proposal " + v.proposal + ": " + v.title);
        if (v.at === "OPEN_CALL") console.log("  applicants sign up at " + process.argv[1] + "/auth/signup");
      }
    });' "$ORIGIN" "$CONTROL"
}

control() {
  local method=$1 path=$2 body=${3:-}
  if [[ -n $body ]]; then
    curl -fsS -X "$method" "$CONTROL$path" -H 'content-type: application/json' -d "$body"
  else
    curl -fsS -X "$method" "$CONTROL$path"
  fi
}

build() {
  command -v node >/dev/null || die "node is needed for the web build (ADR-003)"
  [[ -x $ROOT/web/node_modules/.bin/tsc ]] || die "run npm ci in web/ first"
  echo "Building the pages (tsc) and the asset manifest"
  "$ROOT/web/node_modules/.bin/tsc" -p "$ROOT/web/tsconfig.json"
  "$ROOT/web/node_modules/.bin/tsc" -p "$ROOT/web/build"
  node "$ROOT/web/dist/build/pack.js" "$ROOT/web/dist" "$ROOT/web/src" "$ROOT/web/dist/app" shell/main.js
  echo "Building fstp-e2e-cell and fstp-assessor"
  (cd "$ROOT" && CARGO_INCREMENTAL=0 cargo build -q --locked -p fstp-api-testkit --bin fstp-e2e-cell -p fstp-assessor --bin fstp-assessor)
}

stop() {
  if [[ -f $STATE/pid ]]; then
    kill "$(cat "$STATE/pid")" 2>/dev/null || true
    rm -f "$STATE/pid"
  fi
}

start() {
  build
  stop
  mkdir -p "$STATE"
  rm -f "$STATE/stack.json"
  local flags=()
  case $SIGNIN in
    on) flags=(--demo-signin) ;;
    off) ;;
    *) die "FSTP_DEMO_SIGNIN is on or off, not $SIGNIN" ;;
  esac
  "$CELL_BIN" --port "$PORT" --web "$ROOT/web" --manifest-out "$STATE/stack.json" ${flags[@]+"${flags[@]}"} \
    >"$STATE/cell.log" 2>&1 &
  echo $! >"$STATE/pid"
  for _ in $(seq 1 100); do
    [[ -s $STATE/stack.json ]] && break
    kill -0 "$(cat "$STATE/pid")" 2>/dev/null || die "fstp-e2e-cell stopped, see $STATE/cell.log"
    sleep 0.1
  done
  [[ -s $STATE/stack.json ]] || die "fstp-e2e-cell wrote no manifest"
  echo
  echo "fstp-e2e-cell runs (pid $(cat "$STATE/pid")), synthetic data only."
  echo "  cell origin   $ORIGIN   (sign in: $ORIGIN/auth/login)"
  echo "  control base  $CONTROL"
  echo "  demo page     $CONTROL/demo   (the front door: people, scenes, mailbox; open this first)"
  if [[ $SIGNIN == on ]]; then
    echo "  demo sign-in  on: choose \"Sign in as\" on the demo page, no passkey needed"
  fi
  echo "  manifest      $STATE/stack.json"
  echo
  # shellcheck disable=SC2086
  seed $SEED
}

seed() {
  local kind=${1:-} what=${2:-}
  if [[ $kind == setup ]]; then
    control POST /test/scenario/setup | show
    return
  fi
  [[ -n $kind && -n $what ]] || usage
  case $kind in
    review) control POST /test/scenario/review "{\"stage\":\"$what\"}" | show ;;
    applicant) control POST /test/scenario/applicant "{\"at\":\"$what\"}" | show ;;
    grant) control POST /test/scenario/grant "{\"at\":\"$what\"}" | show ;;
    *) usage ;;
  esac
}

case ${1:-start} in
  start) start ;;
  seed) shift; seed "$@" ;;
  reset) control POST /test/reset | show ;;
  clock)
    [[ -n ${2:-} ]] || usage
    curl -fsS -o /dev/null "$CONTROL/demo/clock?to=$2"
    echo "clock moved to $2"
    ;;
  forge-fail)
    curl -fsS -o /dev/null "$CONTROL/demo/forge/fail"
    echo "the next submission checks fail on the forge 404"
    ;;
  advance)
    [[ ${2:-} =~ ^[0-9]+$ ]] || usage
    control POST /test/clock/advance "{\"micros\":\"$(($2 * 60 * 1000000))\"}"
    echo
    ;;
  mail)
    [[ -n ${2:-} ]] || usage
    curl -fsS -G "$CONTROL/test/mailbox" --data-urlencode "to=$2"
    echo
    ;;
  stop) stop ;;
  e2e)
    shift
    [[ -s $STATE/stack.json ]] || die "start the demo first"
    cd "$ROOT/e2e" && FSTP_E2E_STACK="$STATE/stack.json" node_modules/.bin/playwright test --project=demo "$@"
    ;;
  -h | --help) usage ;;
  *) usage ;;
esac

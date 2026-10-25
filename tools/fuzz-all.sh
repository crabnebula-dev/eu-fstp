#!/usr/bin/env bash
# Runs every cargo-fuzz target under crates/*/fuzz and tools/*/fuzz for a
# fixed time. It fails if any target crashes, times out on an input or runs
# out of memory (TH-26, H-05, ADR-003). It also fails if a fuzz project's
# Cargo.lock is out of date or changes during the run, because cargo-fuzz
# has no --locked option.
#
# Usage: tools/fuzz-all.sh [-j N] [--crate NAME]... <seconds>
#        tools/fuzz-all.sh --list
#        tools/fuzz-all.sh --print-toolchain
#
# Each target runs from its crate directory as
#   cargo +<toolchain> fuzz run <target> <corpus> fuzz/seeds/<target> -- \
#     -max_total_time=<seconds> -rss_limit_mb=<mb> -timeout=<s>
# The corpus directory is writable. The seeds directory is read-only input.
#
# Environment:
#   FSTP_FUZZ_TOOLCHAIN  toolchain to use (default: the pin below)
#   FSTP_FUZZ_RSS_MB     libFuzzer -rss_limit_mb (default 2048)
#   FSTP_FUZZ_TIMEOUT    libFuzzer -timeout per input, in seconds (default 30)
#   FSTP_FUZZ_WORK       if set, writable corpora go to
#                        $FSTP_FUZZ_WORK/<crate>/<target> instead of
#                        <crate dir>/fuzz/corpus/<target>
#   FSTP_FUZZ_LOGS       directory for per-target logs (default: a temp dir)
set -euo pipefail

# The nightly toolchain recorded in ADR-003. CI installs exactly this one.
FUZZ_TOOLCHAIN="nightly-2026-10-24"

usage() {
  # Prints the comment block at the top of this file.
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
}

die() {
  echo "fuzz-all: $*" >&2
  exit 2
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain="${FSTP_FUZZ_TOOLCHAIN:-$FUZZ_TOOLCHAIN}"
rss_mb="${FSTP_FUZZ_RSS_MB:-2048}"
input_timeout="${FSTP_FUZZ_TIMEOUT:-30}"
parallel=1
seconds=""
mode="run"
crates=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -j)
      [[ $# -ge 2 ]] || die "-j needs a value"
      parallel="$2"
      shift 2
      ;;
    --crate)
      [[ $# -ge 2 ]] || die "--crate needs a value"
      crates+=("$2")
      shift 2
      ;;
    --list) mode="list"; shift ;;
    --print-toolchain) mode="toolchain"; shift ;;
    -h | --help) usage; exit 0 ;;
    -*) die "unknown option $1" ;;
    *)
      [[ -z "$seconds" ]] || die "unexpected argument $1"
      seconds="$1"
      shift
      ;;
  esac
done

if [[ "$mode" == "toolchain" ]]; then
  echo "$FUZZ_TOOLCHAIN"
  exit 0
fi

is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }
is_uint "$parallel" && ((parallel >= 1)) || die "-j must be a positive integer"
is_uint "$rss_mb" || die "FSTP_FUZZ_RSS_MB must be an integer"
is_uint "$input_timeout" || die "FSTP_FUZZ_TIMEOUT must be an integer"
if [[ "$mode" == "run" ]]; then
  [[ -n "$seconds" ]] || { usage >&2; exit 2; }
  is_uint "$seconds" && ((seconds >= 1)) || die "seconds must be a positive integer"
fi

# Discover fuzz projects: crates/<crate>/fuzz and tools/<tool>/fuzz.
# deps-check fails on a cargo project anywhere else. Each project is named
# after its crate directory, which must be unique.
projects=()
declare -A project_dir=()
for manifest in "$repo_root"/crates/*/fuzz/Cargo.toml "$repo_root"/tools/*/fuzz/Cargo.toml; do
  [[ -f "$manifest" ]] || continue
  crate_dir="$(dirname "$(dirname "$manifest")")"
  name="$(basename "$crate_dir")"
  [[ -z "${project_dir[$name]:-}" ]] || die "two fuzz projects are named $name"
  project_dir[$name]="${crate_dir#"$repo_root"/}"
  if [[ ${#crates[@]} -gt 0 ]]; then
    keep=0
    for c in "${crates[@]}"; do [[ "$c" == "$name" ]] && keep=1; done
    ((keep)) || continue
  fi
  projects+=("$name")
done
[[ ${#projects[@]} -gt 0 ]] || die "no fuzz projects found under crates/*/fuzz or tools/*/fuzz"

# Prove that each lockfile is current before cargo-fuzz touches it. cargo
# metadata --locked fails instead of rewriting a stale lockfile.
declare -A lock_sum=()
for name in "${projects[@]}"; do
  dir="${project_dir[$name]}"
  cargo "+$toolchain" metadata --locked --format-version 1 \
    --manifest-path "$repo_root/$dir/fuzz/Cargo.toml" >/dev/null \
    || die "$dir/fuzz/Cargo.lock is missing or out of date"
  lock_sum[$name]="$(sha256sum "$repo_root/$dir/fuzz/Cargo.lock" | cut -d' ' -f1)"
done

# Fails if any lockfile changed since the check above.
check_locks() {
  local name dir now
  for name in "${projects[@]}"; do
    dir="${project_dir[$name]}"
    now="$(sha256sum "$repo_root/$dir/fuzz/Cargo.lock" | cut -d' ' -f1)"
    [[ "$now" == "${lock_sum[$name]}" ]] || die "$dir/fuzz/Cargo.lock changed during the run"
  done
}

# List targets per project with cargo-fuzz itself, so discovery matches what
# cargo-fuzz would build.
declare -a pairs=()
for name in "${projects[@]}"; do
  dir="${project_dir[$name]}"
  list="$(cd "$repo_root/$dir" && cargo "+$toolchain" fuzz list)" \
    || die "cargo fuzz list failed in $dir"
  found=0
  while IFS= read -r target; do
    [[ -n "$target" ]] || continue
    pairs+=("$name $target")
    found=1
  done <<<"$list"
  ((found)) || die "$dir/fuzz has no targets"
done
check_locks

if [[ "$mode" == "list" ]]; then
  printf '%s\n' "${pairs[@]}"
  exit 0
fi

work=""
if [[ -n "${FSTP_FUZZ_WORK:-}" ]]; then
  mkdir -p "$FSTP_FUZZ_WORK"
  work="$(cd "$FSTP_FUZZ_WORK" && pwd)"
fi
logs="${FSTP_FUZZ_LOGS:-$(mktemp -d)}"
mkdir -p "$logs"
echo "fuzz-all: ${#pairs[@]} targets in ${#projects[@]} projects, ${seconds}s each, toolchain $toolchain, -j $parallel"
echo "fuzz-all: logs in $logs"

# Build each project once, sequentially, so parallel runs never compile.
for name in "${projects[@]}"; do
  dir="${project_dir[$name]}"
  echo "fuzz-all: building $dir/fuzz"
  (cd "$repo_root/$dir" && cargo "+$toolchain" fuzz build) \
    || die "build failed for $dir/fuzz"
done
check_locks

run_one() {
  local name="$1" target="$2"
  local log="$logs/$name.$target.log"
  local corpus seeds=()
  if [[ -n "$work" ]]; then
    corpus="$work/$name/$target"
  else
    corpus="fuzz/corpus/$target"
  fi
  local crate_dir="$repo_root/${project_dir[$name]}"
  [[ -d "$crate_dir/fuzz/seeds/$target" ]] && seeds=("fuzz/seeds/$target")
  local rc=0
  (
    cd "$crate_dir"
    mkdir -p "$corpus"
    # The outer timeout is a backstop for a hung process; libFuzzer stops
    # itself after max_total_time.
    exec timeout --kill-after=30 "$((seconds + 300))" \
      cargo "+$toolchain" fuzz run "$target" "$corpus" "${seeds[@]}" -- \
      -max_total_time="$seconds" -rss_limit_mb="$rss_mb" -timeout="$input_timeout"
  ) >"$log" 2>&1 || rc=$?
  echo "$rc" >"$logs/$name.$target.rc"
}

for pair in "${pairs[@]}"; do
  read -r name target <<<"$pair"
  while (($(jobs -rp | wc -l) >= parallel)); do
    wait -n || true
  done
  echo "fuzz-all: start $name/$target"
  run_one "$name" "$target" &
done
wait
check_locks

# Summarise from libFuzzer's final lines and fail on any non-zero exit.
failed=0
printf '\n%-14s %-28s %-6s %s\n' "crate" "target" "result" "final libFuzzer stats"
for pair in "${pairs[@]}"; do
  read -r name target <<<"$pair"
  rc="$(cat "$logs/$name.$target.rc" 2>/dev/null || echo missing)"
  log="$logs/$name.$target.log"
  done_line="$(grep -E '^Done [0-9]+ runs in' "$log" | tail -n 1 || true)"
  cov_line="$(grep -E '^#[0-9]+[[:space:]]+DONE' "$log" | tail -n 1 || true)"
  if [[ "$rc" == "0" ]]; then
    printf '%-14s %-28s %-6s %s | %s\n' "$name" "$target" "ok" "$done_line" "$cov_line"
  else
    failed=1
    printf '%-14s %-28s %-6s exit %s\n' "$name" "$target" "FAIL" "$rc"
  fi
done

if ((failed)); then
  for pair in "${pairs[@]}"; do
    read -r name target <<<"$pair"
    rc="$(cat "$logs/$name.$target.rc" 2>/dev/null || echo missing)"
    [[ "$rc" == "0" ]] && continue
    echo
    echo "==== $name/$target failed (exit $rc); last 80 lines of $logs/$name.$target.log"
    tail -n 80 "$logs/$name.$target.log" || true
    dir="${project_dir[$name]}"
    if [[ -d "$repo_root/$dir/fuzz/artifacts/$target" ]]; then
      echo "---- artifacts in $dir/fuzz/artifacts/$target:"
      ls -la "$repo_root/$dir/fuzz/artifacts/$target" || true
    fi
  done
  echo
  echo "fuzz-all: FAIL"
  exit 1
fi
echo
echo "fuzz-all: PASS"

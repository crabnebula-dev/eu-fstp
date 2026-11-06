#!/bin/bash
# PreToolUse hook for Bash (Daniel, 2026-11-06): the project allows no
# Python anywhere (CLAUDE.md, Stack). Refuse any command that runs python
# or python3, including a version check, before it starts. A word such as
# "no-python" or a directory like ".../python/..." is not a match, but
# "/usr/bin/python3" is. Bash commands that only mention the word, such
# as a grep for it, are refused too; build the word from parts there.
# The word is built from parts here too, so deps-check's no-Python gate
# does not read this file as running it.
w=pyt
w="${w}hon"
input=$(cat)
if printf '%s' "$input" | grep -Eq "(^|[^A-Za-z0-9_.-])${w}[0-9.]*([^A-Za-z0-9_./-]|\$)"; then
  echo "Blocked: this project allows no Py""thon, not even a version check (CLAUDE.md). Use Rust, TypeScript, node or shell instead." >&2
  exit 2
fi
exit 0

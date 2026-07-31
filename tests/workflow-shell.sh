#!/bin/sh
# Extract every multiline `run: |` block in release.yml and parse it with
# Bash. actionlint validates workflow structure, but an unmatched shell group
# inside a YAML scalar otherwise survives until the one-time release run.
set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
workflow="$root/.github/workflows/release.yml"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/sevra-workflow-shell.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM

expected="$(
  grep -Ec '^[[:space:]]+run: [|][+-]?$' "$workflow"
)"

awk -v output="$tmp" '
BEGIN {
  count_file = output "/count"
}
function indentation(value, found) {
  found = match(value, /[^ ]/)
  return found == 0 ? length(value) : found - 1
}
function finish() {
  if (active) {
    close(file)
    active = 0
  }
}
{
  line = $0
  indent = indentation(line)
  if (active) {
    if (line !~ /^[ ]*$/ && indent <= run_indent) {
      finish()
    } else {
      if (content_indent < 0 && line !~ /^[ ]*$/) content_indent = indent
      if (content_indent >= 0) {
        if (line ~ /^[ ]*$/) print "" >> file
        else print substr(line, content_indent + 1) >> file
      }
      next
    }
  }
  if (line ~ /^[ ]+run: [|][+-]?$/) {
    active = 1
    run_indent = indent
    content_indent = -1
    count++
    file = output "/run-" count ".bash"
  }
}
END {
  finish()
  print count + 0 > count_file
}
' "$workflow"

actual="$(cat "$tmp/count")"
[ "$actual" = "$expected" ] || {
  printf 'workflow shell extraction mismatch: expected %s, extracted %s\n' \
    "$expected" "$actual" >&2
  exit 1
}

for block in "$tmp"/run-*.bash; do
  bash -n "$block"
done
printf 'release workflow shell syntax: %s multiline blocks OK\n' "$actual"

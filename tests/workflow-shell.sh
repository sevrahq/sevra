#!/bin/sh
# Extract every multiline `run: |` block in the release workflows and parse
# each Bash block. actionlint validates workflow structure, but an unmatched
# shell group inside a YAML scalar otherwise survives until the one-time
# release run.
set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/sevra-workflow-shell.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM

check_workflow() {
  workflow="$1"
  workflow_name="$(basename "$workflow")"
  output="$tmp/$workflow_name"
  mkdir "$output"
  expected="$(
    grep -Ec '^[[:space:]]+run: [|][+-]?$' "$workflow"
  )"

  awk -v output="$output" '
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
  if (line ~ /^[ ]+- (name|uses):/) step_shell = ""
  if (line ~ /^[ ]+shell: bash$/) step_shell = "bash"
  if (line ~ /^[ ]+shell: pwsh$/) step_shell = "pwsh"
  if (line ~ /^[ ]+run: [|][+-]?$/) {
    active = 1
    run_indent = indent
    content_indent = -1
    count++
    extension = step_shell == "bash" ? ".bash" : ".other"
    file = output "/run-" count extension
  }
}
END {
  finish()
  print count + 0 > count_file
}
' "$workflow"

  actual="$(cat "$output/count")"
  [ "$actual" = "$expected" ] || {
    printf '%s shell extraction mismatch: expected %s, extracted %s\n' \
      "$workflow_name" "$expected" "$actual" >&2
    exit 1
  }

  bash_blocks=0
  for block in "$output"/run-*.bash; do
    bash -n "$block"
    bash_blocks=$((bash_blocks + 1))
  done
  printf '%s shell syntax: %s/%s Bash multiline blocks OK\n' \
    "$workflow_name" "$bash_blocks" "$actual"
}

for workflow in \
  "$root/.github/workflows/release.yml" \
  "$root/.github/workflows/smoke.yml"
do
  check_workflow "$workflow"
done

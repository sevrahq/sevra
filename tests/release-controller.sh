#!/bin/sh
# Hermetic release-controller regressions. Nothing here contacts GitHub or
# mutates git: PATH-fronted fakes model the two interruption boundaries that
# must remain resumable.
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/sevra-release-controller.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT HUP INT TERM
mkdir -p "$fixture/bin"

# The first half exercises the immutable historical v0.2.9 controller even
# after Cargo.toml advances. Run it from a minimal exact-version checkout so a
# current package bump cannot silently turn these retirement tests into early
# version-mismatch exits.
original_root="$fixture/original-repo"
mkdir -p "$original_root/scripts"
cp "$repo_root/scripts/release.sh" "$original_root/scripts/release.sh"
cat >"$original_root/Cargo.toml" <<'EOF'
[package]
name = "sevra"
version = "0.2.9"
EOF

sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export SEVRA_TEST_SHA="$sha"
export SEVRA_TEST_LOG="$fixture/calls.log"

cat >"$fixture/bin/git" <<'EOF'
#!/bin/sh
printf 'git %s\n' "$*" >>"$SEVRA_TEST_LOG"
case "$1 $2" in
  "rev-parse --show-toplevel") pwd -P ;;
  "branch --show-current") printf '%s\n' main ;;
  "status --porcelain=v1") ;;
  "remote get-url") printf '%s\n' git@github.com:sevrahq/sevra.git ;;
  "fetch --quiet") ;;
  "rev-parse HEAD"|"rev-parse origin/main") printf '%s\n' "$SEVRA_TEST_SHA" ;;
  "rev-parse --absolute-git-dir") printf '%s\n' "$SEVRA_TEST_STATE" ;;
  "ls-remote origin")
    if [ "$SEVRA_TEST_MODE" = resume ] || [ "$SEVRA_TEST_MODE" = partial_resume ]; then
      printf '%s\trefs/tags/%s\n' "$SEVRA_TEST_SHA" "${SEVRA_TEST_TAG:-v0.2.9}"
    fi
    ;;
  "show-ref --verify")
    [ "$SEVRA_TEST_MODE" = resume ] || [ "$SEVRA_TEST_MODE" = partial_resume ]
    ;;
  "rev-list -n") printf '%s\n' "$SEVRA_TEST_SHA" ;;
  "tag v0.2.9"|"tag v0.2.10") ;;
  "push origin") ;;
  *) printf 'unexpected fake git invocation: %s\n' "$*" >&2; exit 98 ;;
esac
EOF
chmod +x "$fixture/bin/git"

cat >"$fixture/bin/gh" <<'EOF'
#!/bin/sh
printf 'gh %s\n' "$*" >>"$SEVRA_TEST_LOG"
write_release_files() {
  output_dir="$1"
  mkdir -p "$output_dir"
  for asset in \
    sevra-darwin-aarch64 \
    sevra-darwin-x86_64 \
    sevra-linux-aarch64-musl \
    sevra-linux-x86_64-musl \
    sevra-windows-x86_64.exe
  do
    printf '%s\n' "$asset" >"$output_dir/$asset"
    printf 'signature\n' >"$output_dir/$asset.sig"
  done
  (
    cd "$output_dir"
    sha256sum \
      sevra-darwin-aarch64 \
      sevra-darwin-x86_64 \
      sevra-linux-aarch64-musl \
      sevra-linux-x86_64-musl \
      sevra-windows-x86_64.exe >SHA256SUMS
  )
}
command_name="$1"
shift
case "$command_name" in
  auth) exit 0 ;;
  release)
    subcommand="$1"
    shift
    case "$subcommand" in
      view)
        case "$SEVRA_TEST_MODE" in
          resume|partial_resume) exit 0 ;;
          checkpoint_success)
            [ -e "$SEVRA_TEST_STATE/workflow_done" ]
            ;;
          *) exit 1 ;;
        esac
        ;;
      download)
        write_release_files .
        ;;
      delete)
        rm -f "$SEVRA_TEST_STATE/final"
        : >"$SEVRA_TEST_STATE/draft_deleted"
        ;;
      create)
        : >"$SEVRA_TEST_STATE/draft"
        ;;
      upload) ;;
      edit)
        : >"$SEVRA_TEST_STATE/final"
        ;;
      *) printf 'unexpected fake gh release invocation\n' >&2; exit 98 ;;
    esac
    ;;
  secret)
    subcommand="$1"
    shift
    case "$subcommand" in
      list)
        case "$*" in
          *"--env release-signing"*)
            if [ "${SEVRA_TEST_BRIDGE:-0}" = 1 ] &&
              [ ! -e "$SEVRA_TEST_STATE/signer_deleted" ]
            then
              printf '%s\n' SEVRA_CLI_SIGNING_KEY_NEXT
            fi
            ;;
          *)
            if [ "${SEVRA_TEST_BRIDGE:-0}" != 1 ] &&
              { [ "$SEVRA_TEST_MODE" = interrupt ] ||
              [ "$SEVRA_TEST_MODE" = after_start ] ||
              [ "$SEVRA_TEST_MODE" = checkpoint_success ]; } &&
              [ ! -e "$SEVRA_TEST_STATE/signer_deleted" ]
            then
              printf '%s\n' SEVRA_CLI_SIGNING_KEY
            fi
            ;;
        esac
        ;;
      set)
        # Model interruption inside the injection process itself. The
        # controller's EXIT trap must already be armed when this fails.
        exit 97
        ;;
      delete)
        case "$*" in
          *"SEVRA_CLI_SIGNING_KEY_NEXT"*"--env release-signing"*)
            : >"$SEVRA_TEST_STATE/signer_deleted"
            ;;
          *"--env release-signing"*) ;;
          *"SEVRA_CLI_SIGNING_KEY"*) : >"$SEVRA_TEST_STATE/signer_deleted" ;;
        esac
        ;;
      *) exit 98 ;;
    esac
    ;;
  run)
    subcommand="$1"
    shift
    case "$subcommand" in
      list)
        case "$*" in
          *"--workflow ci.yml"*) printf '%s\n' 111 ;;
          *"--workflow release.yml"*) printf '%s\n' 222 ;;
          *) exit 98 ;;
        esac
        ;;
      view)
        case "$*" in
          *"--json attempt"*) printf '%s\n' 1 ;;
          *"--json status,conclusion"*)
            case "$SEVRA_TEST_MODE" in
              resume|checkpoint_success) printf '%s\n' completed:success ;;
              after_start|partial_resume) printf '%s\n' completed:failure ;;
              *) printf '%s\n' in_progress: ;;
            esac
            ;;
          *"--json jobs"*)
            case "$SEVRA_TEST_MODE" in
              after_start|partial_resume|checkpoint_success) printf '%s\n' completed ;;
              *) printf '%s\n' queued ;;
            esac
            ;;
          *) exit 98 ;;
        esac
        ;;
      watch)
        : >"$SEVRA_TEST_STATE/workflow_done"
        case "$SEVRA_TEST_MODE" in
          after_start|partial_resume) exit 1 ;;
        esac
        ;;
      download)
        case "$SEVRA_TEST_MODE" in
          resume|partial_resume|checkpoint_success)
            destination=""
            while [ "$#" -gt 0 ]; do
              if [ "$1" = "--dir" ]; then
                destination="$2"
                break
              fi
              shift
            done
            [ -n "$destination" ] || exit 98
            write_release_files "$destination"
            ;;
          *) exit 1 ;;
        esac
        ;;
      *) exit 98 ;;
    esac
    ;;
  api)
    case "$*" in
      *"immutable-releases"*) printf '%s\n' true ;;
      *"pending_deployments"*)
        if [ "$SEVRA_TEST_MODE" = interrupt ]; then
          printf '%s\n' 77
        fi
        ;;
      *"releases/tags/v0.2."*)
        case "$*" in
          *".assets"*)
            printf '%s\n' \
              SHA256SUMS \
              sevra-darwin-aarch64 \
              sevra-darwin-aarch64.sig \
              sevra-darwin-x86_64 \
              sevra-darwin-x86_64.sig \
              sevra-linux-aarch64-musl \
              sevra-linux-aarch64-musl.sig \
              sevra-linux-x86_64-musl \
              sevra-linux-x86_64-musl.sig \
              sevra-windows-x86_64.exe \
              sevra-windows-x86_64.exe.sig
            ;;
          *".immutable"*)
            case "$SEVRA_TEST_MODE" in
              resume|checkpoint_success) printf '%s\n' true ;;
              partial_resume)
                if [ -e "$SEVRA_TEST_STATE/final" ]; then
                  printf '%s\n' true
                else
                  printf '%s\n' false
                fi
                ;;
              *) printf '%s\n' false ;;
            esac
            ;;
          *"--jq .draft"*)
            if [ -e "$SEVRA_TEST_STATE/final" ] ||
              [ "$SEVRA_TEST_MODE" = resume ] ||
              [ "$SEVRA_TEST_MODE" = checkpoint_success ]
            then
              printf '%s\n' false
            else
              printf '%s\n' true
            fi
            ;;
          *) printf '%s\n' true ;;
        esac
        ;;
      *"git/ref/tags/v0.2."*) printf '%s\n' "$SEVRA_TEST_SHA" ;;
      *) exit 98 ;;
    esac
    ;;
  attestation) ;;
  *) printf 'unexpected fake gh invocation: %s\n' "$command_name $*" >&2; exit 98 ;;
esac
EOF
chmod +x "$fixture/bin/gh"

cat >"$fixture/bin/node" <<'EOF'
#!/bin/sh
printf 'node checkpoint-verify\n' >>"$SEVRA_TEST_LOG"
exit 0
EOF
chmod +x "$fixture/bin/node"

run_controller() {
  mode="$1"
  shift
  : >"$SEVRA_TEST_LOG"
  rm -rf "$fixture/state"
  mkdir -p "$fixture/state"
  SEVRA_TEST_MODE="$mode" PATH="$fixture/bin:$PATH" \
    SEVRA_TEST_STATE="$fixture/state" \
    sh -c 'cd "$1" && shift && sh scripts/release.sh "$@"' \
      sh "$original_root" "$@"
}

# Fresh v0.2.9 reaches the protected environment, then the secret-injection
# process is interrupted. Both environment secrets must be deleted by EXIT.
if run_controller interrupt v0.2.9 >"$fixture/interrupt.out" 2>&1; then
  printf '%s\n' "expected interrupted injection to fail" >&2
  exit 1
fi
grep -Fq \
  "gh secret set SEVRA_RELEASE_AUTHORIZATION --repo sevrahq/sevra --env release-signing" \
  "$SEVRA_TEST_LOG"
grep -Fq \
  "gh secret delete SEVRA_RELEASE_AUTHORIZATION --repo sevrahq/sevra --env release-signing" \
  "$SEVRA_TEST_LOG"
grep -Fq \
  "gh secret delete SEVRA_CLI_SIGNING_KEY --repo sevrahq/sevra --env release-signing" \
  "$SEVRA_TEST_LOG"
immutable_line="$(
  grep -nF 'gh api -H Accept: application/vnd.github+json -H X-GitHub-Api-Version: 2026-03-10 repos/sevrahq/sevra/immutable-releases --jq .enabled' \
    "$SEVRA_TEST_LOG" | sed -n '1s/:.*//p'
)"
tag_push_line="$(
  grep -nF 'git push origin refs/tags/v0.2.9' "$SEVRA_TEST_LOG" |
    sed -n '1s/:.*//p'
)"
if [ -z "$immutable_line" ] || [ -z "$tag_push_line" ] ||
  [ "$immutable_line" -ge "$tag_push_line" ]; then
  printf '%s\n' "immutable-release enforcement was not proved before tag creation" >&2
  cat "$SEVRA_TEST_LOG" >&2
  exit 1
fi

# A protected job that starts but fails before the signed checkpoint must keep
# the repository signer. Starting the job alone is never a retirement gate.
if run_controller after_start v0.2.9 >"$fixture/after-start.out" 2>&1; then
  printf '%s\n' "expected pre-checkpoint workflow failure to fail closed" >&2
  exit 1
fi
grep -Fq "retained because no durable verified signed checkpoint exists" \
  "$fixture/after-start.out"
if grep -Fxq \
  "gh secret delete SEVRA_CLI_SIGNING_KEY --repo sevrahq/sevra" \
  "$SEVRA_TEST_LOG"
then
  printf '%s\n' "repository signer was deleted before a durable checkpoint" >&2
  exit 1
fi

# Once the signed checkpoint and attestations verify, the signer is removed.
# The call order is part of the security property: download/verification must
# precede repository-secret deletion.
if ! run_controller checkpoint_success v0.2.9 >"$fixture/checkpoint.out" 2>&1; then
  cat "$fixture/checkpoint.out" >&2
  cat "$SEVRA_TEST_LOG" >&2
  exit 1
fi
checkpoint_line="$(
  grep -nF "gh run download 222 --repo sevrahq/sevra --name transitional-signed-v0.2.9" \
    "$SEVRA_TEST_LOG" | sed -n '1s/:.*//p'
)"
delete_line="$(
  grep -nFx "gh secret delete SEVRA_CLI_SIGNING_KEY --repo sevrahq/sevra" \
    "$SEVRA_TEST_LOG" | sed -n '1s/:.*//p'
)"
if [ -z "$checkpoint_line" ] || [ -z "$delete_line" ] ||
  [ "$checkpoint_line" -ge "$delete_line" ]; then
    printf '%s\n' "signer deletion did not follow checkpoint verification" >&2
    cat "$SEVRA_TEST_LOG" >&2
    exit 1
fi
grep -Fq "verified durable signed checkpoint; deleted the transitional repository signer" \
  "$fixture/checkpoint.out"

# The v0.2.10 bridge uses signer A from the protected environment, verifies a
# distinct exact-version checkpoint, and only then deletes that environment
# signer. This is the final Actions-held private-key transition.
bridge_root="$fixture/bridge-repo"
mkdir -p "$bridge_root/scripts"
cp "$repo_root/scripts/release.sh" "$bridge_root/scripts/release.sh"
cat >"$bridge_root/Cargo.toml" <<'EOF'
[package]
name = "sevra"
version = "0.2.10"
EOF
: >"$SEVRA_TEST_LOG"
rm -rf "$fixture/state"
mkdir -p "$fixture/state"
if ! SEVRA_TEST_MODE=checkpoint_success \
  SEVRA_TEST_BRIDGE=1 \
  SEVRA_TEST_TAG=v0.2.10 \
  PATH="$fixture/bin:$PATH" \
  SEVRA_TEST_STATE="$fixture/state" \
  sh -c 'cd "$1" && sh scripts/release.sh v0.2.10' sh "$bridge_root" \
  >"$fixture/bridge.out" 2>&1
then
  cat "$fixture/bridge.out" >&2
  cat "$SEVRA_TEST_LOG" >&2
  exit 1
fi
bridge_checkpoint_line="$(
  grep -nF "gh run download 222 --repo sevrahq/sevra --name compatibility-signed-v0.2.10" \
    "$SEVRA_TEST_LOG" | sed -n '1s/:.*//p'
)"
bridge_delete_line="$(
  grep -nF "gh secret delete SEVRA_CLI_SIGNING_KEY_NEXT --repo sevrahq/sevra --env release-signing" \
    "$SEVRA_TEST_LOG" | sed -n '1s/:.*//p'
)"
if [ -z "$bridge_checkpoint_line" ] || [ -z "$bridge_delete_line" ] ||
  [ "$bridge_checkpoint_line" -ge "$bridge_delete_line" ]
then
  printf '%s\n' "bridge signer deletion did not follow checkpoint verification" >&2
  cat "$SEVRA_TEST_LOG" >&2
  exit 1
fi
grep -Fq "verified durable signed checkpoint; deleted compatibility signer A" \
  "$fixture/bridge.out"

# Exact-SHA resume needs no signer. Model a failed workflow with an existing
# partial draft and a durable checkpoint: the controller discards the partial
# draft, recreates it from the checkpoint, and publishes the exact set.
if ! run_controller partial_resume --resume v0.2.9 >"$fixture/partial.out" 2>&1; then
  cat "$fixture/partial.out" >&2
  cat "$SEVRA_TEST_LOG" >&2
  exit 1
fi
for expected_call in \
  "gh release delete v0.2.9 --repo sevrahq/sevra --yes" \
  "gh release create v0.2.9 --repo sevrahq/sevra --verify-tag --draft --title sevra v0.2.9 --generate-notes" \
  "gh release upload v0.2.9" \
  "gh release edit v0.2.9 --repo sevrahq/sevra --draft=false"
do
  grep -Fq "$expected_call" "$SEVRA_TEST_LOG" || {
    printf 'missing resumable draft call: %s\n' "$expected_call" >&2
    cat "$SEVRA_TEST_LOG" >&2
    exit 1
  }
done
if grep -Eq '^gh secret set |^gh secret delete SEVRA_CLI_SIGNING_KEY --repo sevrahq/sevra$' \
  "$SEVRA_TEST_LOG"
then
  printf '%s\n' "partial-draft resume unexpectedly required signing material" >&2
  exit 1
fi

# Resume after the exact run succeeded and the one-time repository signer was
# already deleted. It must not push, authorize, or mutate the immutable release.
if ! run_controller resume --resume v0.2.9 >"$fixture/resume.out" 2>&1; then
  cat "$fixture/resume.out" >&2
  cat "$SEVRA_TEST_LOG" >&2
  exit 1
fi
if grep -Eq '^git push |^gh secret set |^gh release (create|edit|upload|delete) ' \
  "$SEVRA_TEST_LOG"
then
  printf '%s\n' "completed resume unexpectedly mutated release state" >&2
  cat "$SEVRA_TEST_LOG" >&2
  exit 1
fi
grep -Fq "gh run watch 222 --repo sevrahq/sevra --exit-status --compact" \
  "$SEVRA_TEST_LOG"
grep -Fq "gh api repos/sevrahq/sevra/git/ref/tags/v0.2.9 --jq .object.sha" \
  "$SEVRA_TEST_LOG"

# A successor resume must independently rebuild all five targets even when the
# release is already immutable. Model a mutation to the operator checkout
# during `gh run watch`: reproduction must still read the exact archived Git
# object from a private temporary source tree, never the mutated checkout.
successor_root="$fixture/successor-repo"
successor_bin="$fixture/successor-bin"
successor_source="$fixture/successor-source"
mkdir -p "$successor_root/scripts" "$successor_bin" "$successor_source/scripts"
cp "$repo_root/scripts/release.sh" "$successor_root/scripts/release.sh"
cp "$repo_root/scripts/install-pinned-llvm.sh" \
  "$successor_source/scripts/install-pinned-llvm.sh"
cat >"$successor_root/Cargo.toml" <<'EOF'
[package]
name = "sevra"
version = "0.2.11"
build-marker = "trusted"
EOF
cp "$successor_root/Cargo.toml" "$successor_source/Cargo.toml"

cat >"$successor_bin/git" <<'EOF'
#!/bin/sh
printf 'git %s\n' "$*" >>"$SEVRA_TEST_LOG"
case "$1 $2" in
  "rev-parse --show-toplevel") pwd -P ;;
  "branch --show-current") printf '%s\n' main ;;
  "status --porcelain=v1") ;;
  "remote get-url") printf '%s\n' git@github.com:sevrahq/sevra.git ;;
  "fetch --quiet") ;;
  "rev-parse HEAD"|"rev-parse origin/main") printf '%s\n' "$SEVRA_TEST_SHA" ;;
  "rev-parse --absolute-git-dir") printf '%s\n' "$SEVRA_TEST_STATE" ;;
  "ls-remote origin") printf '%s\trefs/tags/v0.2.11\n' "$SEVRA_TEST_SHA" ;;
  "show-ref --verify") exit 0 ;;
  "rev-list -n") printf '%s\n' "$SEVRA_TEST_SHA" ;;
  "show -s") printf '%s\n' 1700000000 ;;
  "archive --format=tar")
    output=""
    for argument in "$@"; do
      case "$argument" in
        --output=*) output="${argument#--output=}" ;;
      esac
    done
    [ -n "$output" ] || exit 98
    "$SEVRA_REAL_TAR" -cf "$output" -C "$SEVRA_SUCCESSOR_SOURCE" .
    ;;
  *) printf 'unexpected successor git invocation: %s\n' "$*" >&2; exit 98 ;;
esac
EOF
chmod +x "$successor_bin/git"

cat >"$successor_bin/gh" <<'EOF'
#!/bin/sh
printf 'gh %s\n' "$*" >>"$SEVRA_TEST_LOG"
write_unsigned_files() {
  output_dir="$1"
  mkdir -p "$output_dir"
  for asset in \
    sevra-darwin-aarch64 \
    sevra-darwin-x86_64 \
    sevra-linux-aarch64-musl \
    sevra-linux-x86_64-musl \
    sevra-windows-x86_64.exe
  do
    printf '%s\n' trusted >"$output_dir/$asset"
  done
}
write_release_files() {
  output_dir="$1"
  write_unsigned_files "$output_dir"
  for asset in \
    sevra-darwin-aarch64 \
    sevra-darwin-x86_64 \
    sevra-linux-aarch64-musl \
    sevra-linux-x86_64-musl \
    sevra-windows-x86_64.exe
  do
    printf '%s\n' signature >"$output_dir/$asset.sig"
  done
  (
    cd "$output_dir"
    sha256sum \
      sevra-darwin-aarch64 \
      sevra-darwin-x86_64 \
      sevra-linux-aarch64-musl \
      sevra-linux-x86_64-musl \
      sevra-windows-x86_64.exe >SHA256SUMS
  )
}
command_name="$1"
shift
case "$command_name" in
  auth) exit 0 ;;
  secret)
    [ "$1" = list ] || {
      printf '%s\n' "successor resume touched signing secrets" >&2
      exit 97
    }
    ;;
  release)
    subcommand="$1"
    shift
    case "$subcommand" in
      view) exit 0 ;;
      download) write_release_files . ;;
      create|upload|edit|delete)
        printf '%s\n' "successor resume mutated an immutable release" >&2
        exit 97
        ;;
      *) exit 98 ;;
    esac
    ;;
  run)
    subcommand="$1"
    shift
    case "$subcommand" in
      list)
        case "$*" in
          *"--workflow ci.yml"*) printf '%s\n' 311 ;;
          *"--workflow release.yml"*) printf '%s\n' 322 ;;
          *) exit 98 ;;
        esac
        ;;
      view)
        case "$*" in
          *"--json attempt"*) printf '%s\n' 1 ;;
          *) exit 98 ;;
        esac
        ;;
      watch)
        # This mutation happens after the controller's clean-tree check. A
        # rebuild from the live checkout would now produce "mutated" bytes.
        cat >"$SEVRA_SUCCESSOR_ROOT/Cargo.toml" <<'MUTATED'
[package]
name = "sevra"
version = "0.2.11"
build-marker = "mutated"
MUTATED
        ;;
      download)
        destination=""
        while [ "$#" -gt 0 ]; do
          if [ "$1" = "--dir" ]; then
            destination="$2"
            break
          fi
          shift
        done
        [ -n "$destination" ] || exit 98
        write_unsigned_files "$destination"
        ;;
      *) exit 98 ;;
    esac
    ;;
  api)
    case "$*" in
      *"immutable-releases"*) printf '%s\n' true ;;
      *"releases/tags/v0.2.11"*".assets"*)
        printf '%s\n' \
          SHA256SUMS \
          sevra-darwin-aarch64 \
          sevra-darwin-aarch64.sig \
          sevra-darwin-x86_64 \
          sevra-darwin-x86_64.sig \
          sevra-linux-aarch64-musl \
          sevra-linux-aarch64-musl.sig \
          sevra-linux-x86_64-musl \
          sevra-linux-x86_64-musl.sig \
          sevra-windows-x86_64.exe \
          sevra-windows-x86_64.exe.sig
        ;;
      *"releases/tags/v0.2.11"*) printf '%s\n' true ;;
      *"git/ref/tags/v0.2.11"*) printf '%s\n' "$SEVRA_TEST_SHA" ;;
      *) exit 98 ;;
    esac
    ;;
  attestation) ;;
  *) printf 'unexpected successor gh invocation: %s %s\n' "$command_name" "$*" >&2; exit 98 ;;
esac
EOF
chmod +x "$successor_bin/gh"

cat >"$successor_bin/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) printf '%s\n' Darwin ;;
  -m) printf '%s\n' arm64 ;;
  *) exit 98 ;;
esac
EOF
cat >"$successor_bin/rustc" <<'EOF'
#!/bin/sh
printf '%s\n' 'rustc 1.96.0 (ac68faa20 2026-05-25)'
EOF
cat >"$successor_bin/rustup" <<'EOF'
#!/bin/sh
printf '%s\n' \
  aarch64-apple-darwin \
  x86_64-apple-darwin \
  x86_64-unknown-linux-musl \
  aarch64-unknown-linux-musl \
  x86_64-pc-windows-msvc
EOF
cat >"$successor_bin/docker" <<'EOF'
#!/bin/sh
[ "$1" = info ]
EOF
cat >"$successor_bin/shasum" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$successor_bin/curl" <<'EOF'
#!/bin/sh
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ] || [ "$1" = --output ]; then
    output="$2"
    break
  fi
  shift
done
[ -n "$output" ] || exit 98
: >"$output"
EOF
cat >"$successor_bin/tar" <<'EOF'
#!/bin/sh
if [ "$1" = -xJf ]; then
  destination=""
  while [ "$#" -gt 0 ]; do
    if [ "$1" = -C ]; then
      destination="$2"
      break
    fi
    shift
  done
  [ -n "$destination" ] || exit 98
  mkdir -p "$destination/bin" "$destination/lib"
  cat >"$destination/bin/llvm-ar" <<'LLVM_AR'
#!/bin/sh
printf '%s\n' 'LLVM version 22.1.8'
LLVM_AR
  chmod +x "$destination/bin/llvm-ar"
  ln -s llvm-ar "$destination/bin/llvm-lib"
  : >"$destination/lib/libLLVM.dylib"
elif [ "$1" = -xzf ]; then
  destination=""
  while [ "$#" -gt 0 ]; do
    if [ "$1" = -C ]; then
      destination="$2"
      break
    fi
    shift
  done
  [ -n "$destination" ] || exit 98
  cat >"$destination/cargo-xwin" <<'XWIN'
#!/bin/sh
if [ "$1" = --version ]; then
  printf '%s\n' 'cargo-xwin 0.23.0'
  exit 0
fi
printf 'xwin cwd=%s args=%s\n' "$(pwd -P)" "$*" >>"$SEVRA_TEST_LOG"
target_dir=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = --target-dir ]; then
    target_dir="$2"
    break
  fi
  shift
done
[ -n "$target_dir" ] || exit 98
marker="$(sed -n 's/^build-marker = "\([^"]*\)"/\1/p' Cargo.toml)"
mkdir -p "$target_dir/x86_64-pc-windows-msvc/release"
printf '%s\n' "$marker" >"$target_dir/x86_64-pc-windows-msvc/release/sevra.exe"
XWIN
  chmod +x "$destination/cargo-xwin"
else
  "$SEVRA_REAL_TAR" "$@"
fi
EOF
cat >"$successor_bin/cargo" <<'EOF'
#!/bin/sh
printf 'cargo cwd=%s args=%s\n' "$(pwd -P)" "$*" >>"$SEVRA_TEST_LOG"
target=""
target_dir=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --target) target="$2"; shift 2 ;;
    --target-dir) target_dir="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$target" ] && [ -n "$target_dir" ] || exit 98
marker="$(sed -n 's/^build-marker = "\([^"]*\)"/\1/p' Cargo.toml)"
mkdir -p "$target_dir/$target/release"
printf '%s\n' "$marker" >"$target_dir/$target/release/sevra"
EOF
cat >"$successor_bin/cross" <<'EOF'
#!/bin/sh
if [ "$1" = --version ]; then
  printf '%s\n' 'cross 0.2.5 (fake)'
  exit 0
fi
printf 'cross cwd=%s args=%s\n' "$(pwd -P)" "$*" >>"$SEVRA_TEST_LOG"
target=""
target_dir=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --target) target="$2"; shift 2 ;;
    --target-dir) target_dir="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$target" ] && [ -n "$target_dir" ] || exit 98
marker="$(sed -n 's/^build-marker = "\([^"]*\)"/\1/p' Cargo.toml)"
mkdir -p "$target_dir/$target/release"
printf '%s\n' "$marker" >"$target_dir/$target/release/sevra"
EOF
cat >"$successor_bin/node" <<'EOF'
#!/bin/sh
printf '%s\n' "node final-signature-verify" >>"$SEVRA_TEST_LOG"
exit 0
EOF
cat >"$successor_bin/op" <<'EOF'
#!/bin/sh
printf '%s\n' "successor resume attempted to read the signing key" >&2
exit 97
EOF
chmod +x "$successor_bin"/*

: >"$SEVRA_TEST_LOG"
real_tar="$(command -v tar)"
if ! (
  cd "$successor_root"
  SEVRA_TEST_MODE=successor_final \
  SEVRA_SUCCESSOR_ROOT="$successor_root" \
  SEVRA_SUCCESSOR_SOURCE="$successor_source" \
  SEVRA_TEST_STATE="$fixture/state" \
  SEVRA_REAL_TAR="$real_tar" \
    PATH="$successor_bin:$PATH" \
    sh scripts/release.sh --resume v0.2.11
) >"$fixture/successor.out" 2>&1
then
  cat "$fixture/successor.out" >&2
  cat "$SEVRA_TEST_LOG" >&2
  exit 1
fi
grep -Fq 'build-marker = "mutated"' "$successor_root/Cargo.toml"
[ "$(grep -Ec '^(cargo|cross|xwin) cwd=.*exact-source ' "$SEVRA_TEST_LOG")" -eq 5 ] || {
  printf '%s\n' "successor did not rebuild all five targets from exact-source" >&2
  cat "$SEVRA_TEST_LOG" >&2
  exit 1
}
if grep -Eq "^(cargo|cross|xwin) cwd=$successor_root " "$SEVRA_TEST_LOG"; then
  printf '%s\n' "successor rebuild consumed the post-check mutable checkout" >&2
  cat "$SEVRA_TEST_LOG" >&2
  exit 1
fi
if grep -Eq '^gh release (create|upload|edit|delete) |^op ' "$SEVRA_TEST_LOG"; then
  printf '%s\n' "immutable successor verification mutated release state or read the signer" >&2
  cat "$SEVRA_TEST_LOG" >&2
  exit 1
fi

printf '%s\n' "release controller checkpoint, retirement, resume, and exact-source tests passed"

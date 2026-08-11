#!/bin/sh
#
# Release one exact, already-green commit. v0.2.8 consumes the transitional
# original signer on one protected GitHub Actions attempt. Every successor
# release keeps the Ed25519 private key local: Actions returns only unsigned,
# tag/SHA-attested binaries; this controller independently reproduces the
# five binaries, signs them from 1Password over stdin, then publishes.
set -eu

repo="sevrahq/sevra"
environment="release-signing"
signing_key_ref="${SEVRA_SIGNING_KEY_REFERENCE:-}"
tag=""
cleanup_only=0
resume=0
ephemeral_secrets_present=0
publish_started=0
original_signer=0
original_signer_deleted=0
checkpoint_ready=0
checkpoint_name="transitional-signed-v0.2.8"
checkpoint_dir=""
preexisting_final=0
tmp_dir=""
binary_assets='sevra-darwin-aarch64
sevra-darwin-x86_64
sevra-linux-aarch64-musl
sevra-linux-x86_64-musl
sevra-windows-x86_64.exe'
expected_release_assets='SHA256SUMS
sevra-darwin-aarch64
sevra-darwin-aarch64.sig
sevra-darwin-x86_64
sevra-darwin-x86_64.sig
sevra-linux-aarch64-musl
sevra-linux-aarch64-musl.sig
sevra-linux-x86_64-musl
sevra-linux-x86_64-musl.sig
sevra-windows-x86_64.exe
sevra-windows-x86_64.exe.sig'

usage() {
  cat <<'EOF'
Usage:
  scripts/release.sh [--resume] [--signing-key-ref op://VAULT/ITEM/FIELD] [vX.Y.Z]
  scripts/release.sh --cleanup-ephemeral-secrets

For v0.2.8 only, the wrapper consumes the transitional repository-scoped
SEVRA_CLI_SIGNING_KEY. It deletes that signer only after the exact signed set
is durable in an immutable Actions artifact and every byte's tag/SHA
provenance, checksum, and Ed25519 signature verify locally. Later releases
require a 1Password secret reference whose value is the base64 of the signer's
PKCS#8 PEM. The value is read only after unsigned artifact provenance and all
five independent reproductions succeed, passed directly to one local Node
process over stdin, and never sent to GitHub or written to disk.
EOF
}

die() {
  printf 'release: %s\n' "$*" >&2
  exit 1
}

have_secret() {
  secret_scope="$1"
  secret_name="$2"
  if [ "$secret_scope" = "environment" ]; then
    secret_names="$(
      gh secret list --repo "$repo" --env "$environment" \
        --json name --jq '.[].name'
    )" || die "could not inspect $environment environment secrets"
  else
    secret_names="$(
      gh secret list --repo "$repo" \
        --json name --jq '.[].name'
    )" || die "could not inspect repository secrets"
  fi
  printf '%s\n' "$secret_names" | grep -Fxq "$secret_name"
}

delete_environment_secret() {
  secret_name="$1"
  gh secret delete "$secret_name" --repo "$repo" --env "$environment" \
    >/dev/null 2>&1 || true
}

cleanup_ephemeral_secrets() {
  delete_environment_secret SEVRA_RELEASE_AUTHORIZATION
  delete_environment_secret SEVRA_CLI_SIGNING_KEY
}

verify_signed_release_set() {
  signed_dir="$1"
  signer_spki="$2"
  [ -d "$signed_dir" ] || return 1
  [ "$(find "$signed_dir" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 11 ] ||
    return 1
  actual_signed_assets="$(
    find "$signed_dir" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; |
      LC_ALL=C sort
  )"
  [ "$actual_signed_assets" = "$expected_release_assets" ] || return 1
  for signed_asset in $expected_release_assets; do
    [ -f "$signed_dir/$signed_asset" ] &&
      [ ! -L "$signed_dir/$signed_asset" ] || return 1
  done

  node -e '
    const { createHash, createPublicKey, verify } = require("node:crypto");
    const { readFileSync, readdirSync } = require("node:fs");
    const { join } = require("node:path");
    const root = process.argv[1];
    const expectedSpki = process.argv[2];
    const binaries = [
      "sevra-darwin-aarch64",
      "sevra-darwin-x86_64",
      "sevra-linux-aarch64-musl",
      "sevra-linux-x86_64-musl",
      "sevra-windows-x86_64.exe",
    ];
    const expected = ["SHA256SUMS", ...binaries, ...binaries.map((name) => name + ".sig")].sort();
    const actual = readdirSync(root).sort();
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error("signed checkpoint has an unexpected file set");
    }
    const manifest = readFileSync(join(root, "SHA256SUMS"), "utf8")
      .trim().split("\n");
    if (manifest.length !== binaries.length) throw new Error("checksum manifest is not exact");
    const checksums = new Map();
    for (const line of manifest) {
      const match = /^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$/.exec(line);
      if (!match || !binaries.includes(match[2]) || checksums.has(match[2])) {
        throw new Error("checksum manifest contains an unsafe or duplicate entry");
      }
      checksums.set(match[2], match[1]);
    }
    const publicKey = createPublicKey({
      key: Buffer.from(expectedSpki, "base64"),
      format: "der",
      type: "spki",
    });
    for (const asset of binaries) {
      const bytes = readFileSync(join(root, asset));
      const digest = createHash("sha256").update(bytes).digest("hex");
      if (checksums.get(asset) !== digest) throw new Error("binary checksum mismatch");
      const encoded = readFileSync(join(root, asset + ".sig"), "utf8").trim();
      const signature = Buffer.from(encoded, "base64");
      if (signature.length !== 64 || signature.toString("base64") !== encoded) {
        throw new Error("detached signature is not canonical base64");
      }
      if (!verify(null, bytes, publicKey, signature)) {
        throw new Error("detached signature does not match the expected signer");
      }
    }
  ' "$signed_dir" "$signer_spki" || return 1
}

verify_transitional_checkpoint() {
  checkpoint="$1"
  verify_signed_release_set \
    "$checkpoint" \
    "MCowBQYDK2VwAyEA+v5mafEPcIwKAU/DO/z8MM/cT9ndgE1saSUfvcrzLKA=" ||
    return 1

  for checkpoint_asset in $expected_release_assets; do
    gh attestation verify "$checkpoint/$checkpoint_asset" \
      --repo "$repo" \
      --signer-workflow "$repo/.github/workflows/release.yml" \
      --source-digest "$release_sha" \
      --source-ref "refs/tags/$tag" \
      --deny-self-hosted-runners >/dev/null 2>&1 || return 1
  done
}

cleanup() {
  status=$?
  if [ "$ephemeral_secrets_present" -eq 1 ]; then
    cleanup_ephemeral_secrets
  fi
  if [ -n "$tmp_dir" ] && [ -d "$tmp_dir" ]; then
    # Exact-source reproduction is deliberately read-only. Restore owner
    # write permission only inside this controller-created mktemp tree so it
    # can be removed without touching the operator's checkout.
    chmod -R u+w "$tmp_dir" >/dev/null 2>&1 || true
    rm -rf -- "$tmp_dir"
  fi
  if [ "$status" -ne 0 ]; then
    if [ "$original_signer" -eq 1 ] && [ "$publish_started" -eq 0 ]; then
      printf '%s\n' \
        "release: the transitional repository signer was retained because the publish job never started" >&2
    elif [ "$original_signer" -eq 1 ] && [ "$checkpoint_ready" -eq 0 ]; then
      printf '%s\n' \
        "release: the transitional repository signer was retained because no durable verified signed checkpoint exists" >&2
    elif [ "$original_signer" -eq 1 ] && [ "$original_signer_deleted" -eq 0 ]; then
      printf '%s\n' \
        "release: URGENT: verify and delete the transitional repository signer" >&2
    fi
    if [ "$original_signer" -eq 1 ]; then
      printf '%s\n' \
        "release: failed; verify the one-run environment secrets are absent; use --cleanup-ephemeral-secrets if GitHub was unreachable" >&2
    else
      printf '%s\n' \
        "release: failed; the successor signer was not sent to GitHub; inspect any draft release and pushed tag before retrying" >&2
    fi
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

while [ "$#" -gt 0 ]; do
  case "$1" in
    --signing-key-ref)
      [ "$#" -ge 2 ] || die "--signing-key-ref requires an op:// reference"
      signing_key_ref="$2"
      shift 2
      ;;
    --cleanup-ephemeral-secrets)
      cleanup_only=1
      shift
      ;;
    --resume)
      resume=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      [ -z "$tag" ] || die "only one release tag may be supplied"
      tag="$1"
      shift
      ;;
  esac
done

command -v gh >/dev/null 2>&1 || die "gh is required"
gh auth status >/dev/null 2>&1 || die "gh is not authenticated"

if [ "$cleanup_only" -eq 1 ]; then
  [ -z "$tag" ] || die "--cleanup-ephemeral-secrets does not accept a tag"
  [ "$resume" -eq 0 ] || die "--cleanup-ephemeral-secrets cannot be combined with --resume"
  cleanup_ephemeral_secrets
  if have_secret environment SEVRA_RELEASE_AUTHORIZATION ||
    have_secret environment SEVRA_CLI_SIGNING_KEY
  then
    die "GitHub still reports an ephemeral signing secret after deletion"
  fi
  printf '%s\n' "release: removed ephemeral release-signing environment secrets"
  exit 0
fi

command -v git >/dev/null 2>&1 || die "git is required"
command -v openssl >/dev/null 2>&1 || die "openssl is required"
command -v node >/dev/null 2>&1 || die "Node.js is required for in-memory Ed25519 signing"

[ "$(git rev-parse --show-toplevel)" = "$(pwd -P)" ] ||
  die "run this wrapper from the repository root"
[ "$(git branch --show-current)" = "main" ] || die "releases must be cut from main"
[ -z "$(git status --porcelain=v1)" ] || die "the worktree must be clean"

origin_url="$(git remote get-url origin)"
case "$origin_url" in
  git@github.com:sevrahq/sevra.git|https://github.com/sevrahq/sevra.git|ssh://git@github.com/sevrahq/sevra.git)
    ;;
  *)
    die "origin is not the canonical sevrahq/sevra repository"
    ;;
esac

git fetch --quiet origin main
release_sha="$(git rev-parse HEAD)"
origin_sha="$(git rev-parse origin/main)"
[ "$release_sha" = "$origin_sha" ] ||
  die "HEAD is not the exact commit currently at origin/main"
printf '%s' "$release_sha" | grep -Eq '^[0-9a-f]{40}$' ||
  die "release commit is not a full lowercase SHA-1"

cargo_version="$(
  sed -n 's/^version = "\([^"]*\)".*/\1/p' Cargo.toml | sed -n '1p'
)"
[ -n "$cargo_version" ] || die "could not resolve Cargo.toml version"
[ -n "$tag" ] || tag="v$cargo_version"
printf '%s' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' ||
  die "tag must be a SemVer release beginning with v"
[ "$tag" = "v$cargo_version" ] ||
  die "$tag does not equal Cargo.toml version v$cargo_version"
if [ "$tag" = "v0.2.8" ]; then
  original_signer=1
fi

remote_tag_sha="$(
  git ls-remote origin "refs/tags/$tag" 2>/dev/null |
    awk 'NR == 1 { print $1 }'
)"
release_exists=0
if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
  release_exists=1
fi
if [ -n "$remote_tag_sha" ]; then
  [ "$resume" -eq 1 ] ||
    die "remote tag $tag already exists (use --resume only after verifying this release attempt)"
  [ "$remote_tag_sha" = "$release_sha" ] ||
    die "remote tag $tag does not point to the exact authorized commit"
elif [ "$release_exists" -eq 1 ]; then
  die "release $tag exists without the exact remote tag"
fi
if [ "$release_exists" -eq 1 ] && [ "$resume" -eq 0 ]; then
  die "release $tag already exists"
fi

ci_run_id="$(
  gh run list --repo "$repo" --workflow ci.yml --commit "$release_sha" \
    --event push --limit 20 \
    --json databaseId,headSha,status,conclusion \
    --jq 'map(select(.headSha == "'"$release_sha"'" and .status == "completed" and .conclusion == "success")) | first | .databaseId // empty'
)"
[ -n "$ci_run_id" ] ||
  die "the exact release commit does not have a successful main-push ci.yml run"

# Publishing a public release is one-way only when repository immutability is
# enabled. Prove that repository control before creating the tag, rather than
# discovering a mutable release after the protected signer has already run.
immutable_releases_enabled="$(
  gh api \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2026-03-10' \
    "repos/$repo/immutable-releases" --jq .enabled
)" || die "could not verify immutable GitHub Releases for $repo"
[ "$immutable_releases_enabled" = true ] ||
  die "immutable GitHub Releases must be enabled before tagging"

if [ "$tag" = "v0.2.8" ]; then
  if have_secret environment SEVRA_RELEASE_AUTHORIZATION ||
    have_secret environment SEVRA_CLI_SIGNING_KEY
  then
    if [ "$resume" -eq 0 ]; then
      die "stale ephemeral environment secrets exist; inspect active runs, then use --cleanup-ephemeral-secrets"
    fi
    cleanup_ephemeral_secrets
    if have_secret environment SEVRA_RELEASE_AUTHORIZATION ||
      have_secret environment SEVRA_CLI_SIGNING_KEY
    then
      die "could not clear stale ephemeral environment secrets before resume"
    fi
  fi
  if [ "$resume" -eq 0 ]; then
    have_secret repository SEVRA_CLI_SIGNING_KEY ||
      die "v0.2.8 requires the transitional original repository signer"
  fi
else
  if have_secret repository SEVRA_CLI_SIGNING_KEY; then
    die "the transitional repository signer still exists; remove it before a successor release"
  fi
  if [ "$release_exists" -eq 1 ]; then
    existing_release_final="$(
      gh api "repos/$repo/releases/tags/$tag" \
        --jq '(.draft == false) and (.prerelease == false) and (.immutable == true)'
    )"
    if [ "$existing_release_final" = "true" ]; then
      preexisting_final=1
    fi
  fi
  if have_secret environment SEVRA_CLI_SIGNING_KEY_NEXT; then
    die "remove legacy SEVRA_CLI_SIGNING_KEY_NEXT after confirming its 1Password Recovery copy"
  fi
  [ "$(uname -s):$(uname -m)" = "Darwin:arm64" ] ||
    die "successor releases must run on the reviewed arm64 macOS controller"
  for release_tool in cross docker rustup curl tar shasum cmp; do
    command -v "$release_tool" >/dev/null 2>&1 ||
      die "$release_tool is required for independent release reproduction"
  done
  rustc +1.96.0 --version | grep -Fxq 'rustc 1.96.0 (ac68faa20 2026-05-25)' ||
    die "the exact Rust 1.96.0 release compiler is required"
  installed_targets="$(rustup target list --installed --toolchain 1.96.0)"
  for release_target in \
    aarch64-apple-darwin \
    x86_64-apple-darwin \
    x86_64-unknown-linux-musl \
    aarch64-unknown-linux-musl \
    x86_64-pc-windows-msvc
  do
    printf '%s\n' "$installed_targets" | grep -Fxq "$release_target" ||
      die "Rust 1.96.0 target is not installed: $release_target"
  done
  docker info >/dev/null 2>&1 ||
    die "the Docker daemon is not available for Linux reproduction"
  if [ "$preexisting_final" -eq 0 ]; then
    [ -n "$signing_key_ref" ] ||
      die "successor releases require --signing-key-ref op://VAULT/ITEM/FIELD"
    case "$signing_key_ref" in
      op://*) ;;
      *) die "the signing-key reference must be an op:// 1Password reference" ;;
    esac
    command -v op >/dev/null 2>&1 || die "the 1Password CLI (op) is required"
  fi
fi

printf 'release: binding %s to %s after green CI run %s\n' \
  "$tag" "$release_sha" "$ci_run_id"
if git show-ref --verify --quiet "refs/tags/$tag"; then
  [ "$(git rev-list -n 1 "$tag")" = "$release_sha" ] ||
    die "local tag $tag does not point to the authorized commit"
else
  git tag "$tag" "$release_sha"
fi
if [ -z "$remote_tag_sha" ]; then
  git push origin "refs/tags/$tag"
  remote_tag_sha="$release_sha"
else
  printf 'release: resuming existing exact tag %s at %s\n' "$tag" "$release_sha"
fi

release_run_id=""
attempt=""
poll=0
while [ "$poll" -lt 180 ]; do
  release_run_id="$(
    gh run list --repo "$repo" --workflow release.yml --commit "$release_sha" \
      --event push --limit 20 \
      --json databaseId,headSha,headBranch,attempt \
      --jq 'map(select(.headSha == "'"$release_sha"'" and .headBranch == "'"$tag"'")) | if length == 1 then .[0].databaseId else empty end'
  )"
  if [ -n "$release_run_id" ]; then
    attempt="$(
      gh run view "$release_run_id" --repo "$repo" \
        --json attempt --jq '.attempt'
    )"
    break
  fi
  poll=$((poll + 1))
  sleep 2
done
if [ -z "$release_run_id" ] || [ -z "$attempt" ]; then
  die "could not resolve one unique release workflow run for exact tag $tag and SHA $release_sha"
fi

if [ "$original_signer" -eq 1 ]; then
  pending_environment_id=""
  run_failed=0
  run_state="$(
    gh run view "$release_run_id" --repo "$repo" --attempt "$attempt" \
      --json status,conclusion --jq '.status + ":" + (.conclusion // "")'
  )"
  case "$run_state" in
    completed:success)
      publish_started=1
      ;;
    completed:*)
      run_failed=1
      ;;
  esac
  if [ "$publish_started" -eq 0 ]; then
    publish_job="$(
      gh run view "$release_run_id" --repo "$repo" --attempt "$attempt" \
        --json jobs \
        --jq '.jobs[] | select(.name == "sign + publish release") | .status'
    )"
    case "$publish_job" in
      in_progress)
        publish_started=1
        ;;
      completed)
        publish_started=1
        ;;
    esac
  fi

  if [ "$publish_started" -eq 0 ]; then
    [ "$run_failed" -eq 0 ] ||
      die "release run failed before the transitional signer job started ($run_state)"
    have_secret repository SEVRA_CLI_SIGNING_KEY ||
      die "the pending v0.2.8 run still needs the transitional repository signer"
    poll=0
    while [ "$poll" -lt 1800 ]; do
      run_state="$(
        gh run view "$release_run_id" --repo "$repo" --attempt "$attempt" \
          --json status,conclusion --jq '.status + ":" + (.conclusion // "")'
      )"
      case "$run_state" in
        completed:success)
          publish_started=1
          break
          ;;
        completed:*)
          run_failed=1
          break
          ;;
      esac
      publish_job="$(
        gh run view "$release_run_id" --repo "$repo" --attempt "$attempt" \
          --json jobs \
          --jq '.jobs[] | select(.name == "sign + publish release") | .status'
      )"
      case "$publish_job" in
        in_progress|completed)
          publish_started=1
          break
          ;;
      esac
      pending_environment_id="$(
        gh api "repos/$repo/actions/runs/$release_run_id/pending_deployments" \
          --jq '.[] | select(.environment.name == "'"$environment"'") | .environment.id' \
          2>/dev/null || true
      )"
      [ -z "$pending_environment_id" ] || break
      poll=$((poll + 1))
      sleep 2
    done
    if [ "$run_failed" -eq 1 ] && [ "$publish_started" -eq 0 ]; then
      die "release run failed before signer approval ($run_state)"
    fi
  fi

  if [ "$publish_started" -eq 0 ]; then
    [ -n "$pending_environment_id" ] ||
      die "release run did not reach the protected signing environment"
    auth_nonce="$(openssl rand -hex 32)"
    printf '%s' "$auth_nonce" | grep -Eq '^[0-9a-f]{64}$' ||
      die "failed to generate the release nonce"
    authorization="$tag:$release_sha:$release_run_id.$attempt:$auth_nonce"
    # Arm cleanup BEFORE the first secret-injection process starts. A signal,
    # pipe failure, or gh crash during this call must still attempt deletion.
    ephemeral_secrets_present=1
    printf '%s' "$authorization" |
      gh secret set SEVRA_RELEASE_AUTHORIZATION \
        --repo "$repo" --env "$environment"
    unset authorization auth_nonce

    approval_payload="$(
      printf '{"environment_ids":[%s],"state":"approved","comment":"Authorized by scripts/release.sh for %s at %s, workflow attempt %s.%s"}' \
        "$pending_environment_id" "$tag" "$release_sha" "$release_run_id" "$attempt"
    )"
    printf '%s' "$approval_payload" |
      gh api --method POST \
        "repos/$repo/actions/runs/$release_run_id/pending_deployments" \
        --input - >/dev/null
    unset approval_payload

    poll=0
    while [ "$poll" -lt 300 ]; do
      publish_job="$(
        gh run view "$release_run_id" --repo "$repo" --attempt "$attempt" \
          --json jobs \
          --jq '.jobs[] | select(.name == "sign + publish release") | .status'
      )"
      case "$publish_job" in
        in_progress|completed)
          publish_started=1
          break
          ;;
      esac
      poll=$((poll + 1))
      sleep 1
    done
    [ "$publish_started" -eq 1 ] || die "publish job did not start"
  fi

  # The per-attempt authorization is useful only to start the protected job.
  # Remove it immediately. The repository signer remains until the signed
  # artifact itself is durable and independently verified below.
  cleanup_ephemeral_secrets
  if have_secret environment SEVRA_RELEASE_AUTHORIZATION ||
    have_secret environment SEVRA_CLI_SIGNING_KEY
  then
    die "GitHub still reports an ephemeral signing secret after deletion"
  fi
  ephemeral_secrets_present=0

  [ -n "$tmp_dir" ] ||
    tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/sevra-release-checkpoint.XXXXXX")"
  checkpoint_dir="$tmp_dir/transitional-checkpoint"
  poll=0
  completed_grace=0
  while [ "$poll" -lt 1800 ]; do
    rm -rf -- "$checkpoint_dir"
    mkdir -p "$checkpoint_dir"
    if gh run download "$release_run_id" --repo "$repo" \
      --name "$checkpoint_name" --dir "$checkpoint_dir" >/dev/null 2>&1 &&
      verify_transitional_checkpoint "$checkpoint_dir"
    then
      checkpoint_ready=1
      break
    fi
    run_state="$(
      gh run view "$release_run_id" --repo "$repo" --attempt "$attempt" \
        --json status,conclusion --jq '.status + ":" + (.conclusion // "")'
    )"
    case "$run_state" in
      completed:success)
        completed_grace=$((completed_grace + 1))
        [ "$completed_grace" -lt 30 ] || break
        ;;
      completed:*) break ;;
    esac
    poll=$((poll + 1))
    sleep 1
  done
  [ "$checkpoint_ready" -eq 1 ] ||
    die "release run ended before a durable, exact-SHA signed checkpoint was verified"

  if have_secret repository SEVRA_CLI_SIGNING_KEY; then
    gh secret delete SEVRA_CLI_SIGNING_KEY --repo "$repo" ||
      die "failed to delete the transitional repository signer"
  fi
  if have_secret repository SEVRA_CLI_SIGNING_KEY; then
    die "GitHub still reports the transitional repository signer after deletion"
  fi
  original_signer_deleted=1
  printf '%s\n' \
    "release: verified durable signed checkpoint; deleted the transitional repository signer"
fi

if ! gh run watch "$release_run_id" --repo "$repo" --exit-status --compact; then
  if [ "$original_signer" -eq 0 ] || [ "$checkpoint_ready" -eq 0 ]; then
    die "release workflow failed without a resumable signed checkpoint"
  fi
  printf '%s\n' \
    "release: workflow failed after the signed checkpoint; resuming release assembly locally"
fi

already_final=0
if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
  release_exists=1
  existing_release_final="$(
    gh api "repos/$repo/releases/tags/$tag" \
      --jq '(.draft == false) and (.prerelease == false) and (.immutable == true)'
  )"
  if [ "$existing_release_final" = "true" ]; then
    already_final=1
    printf '%s\n' "release: exact release is already immutable; verifying it without mutation"
  fi
fi

if [ "$original_signer" -eq 1 ] && [ "$already_final" -eq 0 ]; then
  [ "$checkpoint_ready" -eq 1 ] ||
    die "cannot assemble v0.2.8 without the verified signed checkpoint"
  if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
    existing_draft="$(
      gh api "repos/$repo/releases/tags/$tag" --jq '.draft'
    )"
    [ "$existing_draft" = "true" ] ||
      die "refusing to replace a non-draft v0.2.8 release"
    gh release delete "$tag" --repo "$repo" --yes ||
      die "could not replace the interrupted v0.2.8 draft"
  fi
  gh release create "$tag" \
    --repo "$repo" \
    --verify-tag \
    --draft \
    --title "sevra $tag" \
    --generate-notes
  gh release upload "$tag" "$checkpoint_dir"/* --repo "$repo"
  gh release edit "$tag" --repo "$repo" --draft=false
fi

if [ "$original_signer" -eq 0 ]; then
  cross --version 2>/dev/null | sed -n '1p' |
    grep -Eq '^cross 0\.2\.5 ' ||
    die "cross 0.2.5 is required for Linux reproduction"

  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/sevra-release.XXXXXX")"
  unsigned_dir="$tmp_dir/unsigned"
  release_dir="$tmp_dir/release"
  xwin_dir="$tmp_dir/cargo-xwin"
  darwin_arm_dir="$tmp_dir/reproduce-darwin-aarch64"
  darwin_x86_dir="$tmp_dir/reproduce-darwin-x86_64"
  linux_arm_dir="$tmp_dir/reproduce-linux-aarch64-musl"
  linux_x86_dir="$tmp_dir/reproduce-linux-x86_64-musl"
  windows_dir="$tmp_dir/reproduce-windows-x86_64"
  source_dir="$tmp_dir/exact-source"
  source_archive="$tmp_dir/exact-source.tar"
  mkdir -p "$unsigned_dir" "$release_dir" "$xwin_dir"
  gh run download "$release_run_id" --repo "$repo" \
    --name successor-unsigned --dir "$unsigned_dir"
  [ "$(find "$unsigned_dir" -type f | wc -l | tr -d ' ')" = 5 ] ||
    die "downloaded unsigned artifact set does not contain exactly five files"
  for asset in $binary_assets; do
    if [ ! -f "$unsigned_dir/$asset" ] || [ -L "$unsigned_dir/$asset" ]; then
      die "unsigned artifact is missing or unsafe: $asset"
    fi
    gh attestation verify "$unsigned_dir/$asset" \
      --repo "$repo" \
      --signer-workflow "$repo/.github/workflows/release.yml" \
      --source-digest "$release_sha" \
      --source-ref "refs/tags/$tag" \
      --deny-self-hosted-runners >/dev/null
  done

  # Never reproduce from the operator's checkout after the workflow wait. It
  # may have changed since the clean-tree gate. Materialize the exact
  # authorized Git object in a private temporary tree and make that source
  # read-only before any compiler sees it.
  mkdir -m 0700 "$source_dir"
  git archive --format=tar --output="$source_archive" "$release_sha"
  tar -xf "$source_archive" -C "$source_dir"
  chmod -R a-w "$source_dir"
  source_canonical="$(CDPATH='' cd -- "$source_dir" && pwd -P)"

  xwin_archive="$tmp_dir/cargo-xwin.tar.gz"
  curl -fsSL \
    https://github.com/rust-cross/cargo-xwin/releases/download/v0.23.0/cargo-xwin-v0.23.0.universal2-apple-darwin.tar.gz \
    -o "$xwin_archive"
  printf '%s  %s\n' \
    d78a88f43247a6298d8888dc4c44a8af92801fdf4e5374cc5a359a1e53770993 \
    "$xwin_archive" |
    shasum -a 256 -c - >/dev/null
  tar -xzf "$xwin_archive" -C "$xwin_dir"
  [ "$("$xwin_dir/cargo-xwin" --version)" = "cargo-xwin 0.23.0" ] ||
    die "digest-verified cargo-xwin reported an unexpected version"

  # Rebuild all five targets independently before the successor key is read.
  # Any platform/toolchain nondeterminism is fail-closed: a mismatch leaves
  # the tag unsigned and unpublished for explicit investigation.
  release_cargo_home="${CARGO_HOME:-$HOME/.cargo}"
  RUSTFLAGS="--remap-path-prefix=$source_canonical=/workspace --remap-path-prefix=$release_cargo_home=/cargo --remap-path-prefix=/project=/workspace"
  SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$release_sha")"
  export RUSTFLAGS SOURCE_DATE_EPOCH
  (
    cd "$source_dir"
    cargo +1.96.0 build --release --locked --target aarch64-apple-darwin \
      --target-dir "$darwin_arm_dir"
    cargo +1.96.0 build --release --locked --target x86_64-apple-darwin \
      --target-dir "$darwin_x86_dir"
    RUSTUP_TOOLCHAIN=1.96.0 cross build --release --locked \
      --target aarch64-unknown-linux-musl \
      --target-dir "$linux_arm_dir"
    RUSTUP_TOOLCHAIN=1.96.0 cross build --release --locked \
      --target x86_64-unknown-linux-musl \
      --target-dir "$linux_x86_dir"
    RUSTUP_TOOLCHAIN=1.96.0 \
      RUSTFLAGS="$RUSTFLAGS -C link-arg=/Brepro -C link-arg=/debug:none" \
      XWIN_CACHE_DIR="$tmp_dir/xwin-cache" \
      "$xwin_dir/cargo-xwin" xwin build \
      --release --locked --target x86_64-pc-windows-msvc \
      --target-dir "$windows_dir" \
      --xwin-version 17 \
      --xwin-sdk-version 10.0.26100 \
      --xwin-crt-version 14.44.17.14
  )

  cmp "$darwin_arm_dir/aarch64-apple-darwin/release/sevra" \
    "$unsigned_dir/sevra-darwin-aarch64" >/dev/null ||
    die "independent arm64 Darwin build does not reproduce the attested artifact"
  cmp "$darwin_x86_dir/x86_64-apple-darwin/release/sevra" \
    "$unsigned_dir/sevra-darwin-x86_64" >/dev/null ||
    die "independent x86_64 Darwin build does not reproduce the attested artifact"
  cmp "$linux_arm_dir/aarch64-unknown-linux-musl/release/sevra" \
    "$unsigned_dir/sevra-linux-aarch64-musl" >/dev/null ||
    die "independent arm64 Linux build does not reproduce the attested artifact"
  cmp "$linux_x86_dir/x86_64-unknown-linux-musl/release/sevra" \
    "$unsigned_dir/sevra-linux-x86_64-musl" >/dev/null ||
    die "independent x86_64 Linux build does not reproduce the attested artifact"
  cmp "$windows_dir/x86_64-pc-windows-msvc/release/sevra.exe" \
    "$unsigned_dir/sevra-windows-x86_64.exe" >/dev/null ||
    die "independent x86_64 Windows build does not reproduce the attested artifact"

  if [ "$already_final" -eq 0 ]; then
    for asset in $binary_assets; do
      cp -- "$unsigned_dir/$asset" "$release_dir/$asset"
    done

    # The key flows directly from 1Password into one local process. The shell
    # never captures or exports it, and no byte is written to disk or argv.
    op read "$signing_key_ref" | node -e '
    const { createPrivateKey, createPublicKey, sign, verify } = require("node:crypto");
    const { readFileSync, writeFileSync } = require("node:fs");
    const expectedSpki = "MCowBQYDK2VwAyEAasunxAjcJp8W30eF0ndPlLXqwSjZ/u5raivn3QmaKcc=";
    const encoded = readFileSync(0, "utf8").trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
      throw new Error("the 1Password signing-key field is not one base64 value");
    }
    const decoded = Buffer.from(encoded, "base64");
    if (decoded.toString("base64") !== encoded) {
      throw new Error("the 1Password signing-key field is not canonical base64");
    }
    const key = createPrivateKey(decoded);
    const publicKey = createPublicKey(key);
    const actualSpki = publicKey.export({ type: "spki", format: "der" }).toString("base64");
    if (actualSpki !== expectedSpki) throw new Error("wrong successor release signer");
    for (const asset of process.argv.slice(1)) {
      const bytes = readFileSync(asset);
      const signature = sign(null, bytes, key);
      if (!verify(null, bytes, publicKey, signature)) throw new Error("signature self-check failed");
      writeFileSync(asset + ".sig", signature.toString("base64") + "\n", {
        mode: 0o600,
        flag: "wx",
      });
    }
    ' "$release_dir"/sevra-darwin-aarch64 \
      "$release_dir"/sevra-darwin-x86_64 \
      "$release_dir"/sevra-linux-aarch64-musl \
      "$release_dir"/sevra-linux-x86_64-musl \
      "$release_dir"/sevra-windows-x86_64.exe

    (
      cd "$release_dir"
      : > SHA256SUMS
      if command -v sha256sum >/dev/null 2>&1; then
        for asset in $binary_assets; do
          sha256sum "$asset" >> SHA256SUMS
        done
      else
        for asset in $binary_assets; do
          shasum -a 256 "$asset" >> SHA256SUMS
        done
      fi
    )
    [ "$(find "$release_dir" -type f | wc -l | tr -d ' ')" = 11 ] ||
      die "locally signed release set does not contain exactly eleven files"

    if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
      [ "$resume" -eq 1 ] ||
        die "a release appeared during successor signing; refusing to overwrite it"
      existing_draft="$(
        gh api "repos/$repo/releases/tags/$tag" --jq '.draft'
      )"
      [ "$existing_draft" = "true" ] ||
        die "the existing release is not the resumable draft expected here"
      # The locally signed set is complete and verified. Recreate an interrupted
      # draft rather than mixing it with an unknown partial asset set.
      gh release delete "$tag" --repo "$repo" --yes ||
        die "could not replace the interrupted draft release"
    fi
    gh release create "$tag" \
      --repo "$repo" \
      --verify-tag \
      --draft \
      --title "sevra $tag" \
      --generate-notes
    gh release upload "$tag" "$release_dir"/* --repo "$repo"
    gh release edit "$tag" --repo "$repo" --draft=false
  fi
fi

release_is_final="$(
  gh api "repos/$repo/releases/tags/$tag" \
    --jq '(.draft == false) and (.prerelease == false) and (.immutable == true)'
)"
[ "$release_is_final" = "true" ] ||
  die "release is not published and immutable"

api_tag_sha="$(
  gh api "repos/$repo/git/ref/tags/$tag" --jq '.object.sha'
)"
[ "$api_tag_sha" = "$release_sha" ] ||
  die "published tag no longer points to the authorized commit"

actual_assets="$(
  gh api "repos/$repo/releases/tags/$tag" \
    --jq '.assets | sort_by(.name) | .[].name'
)"
[ "$actual_assets" = "$expected_release_assets" ] ||
  die "published release asset set is not exact"

if [ -z "$tmp_dir" ]; then
  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/sevra-release-verify.XXXXXX")"
fi
verify_dir="$tmp_dir/final-verify"
mkdir -p "$verify_dir"
(
  cd "$verify_dir"
  gh release download "$tag" --repo "$repo"
  if [ "$original_signer" -eq 1 ]; then
    final_signer_spki="MCowBQYDK2VwAyEA+v5mafEPcIwKAU/DO/z8MM/cT9ndgE1saSUfvcrzLKA="
  else
    final_signer_spki="MCowBQYDK2VwAyEAasunxAjcJp8W30eF0ndPlLXqwSjZ/u5raivn3QmaKcc="
  fi
  verify_signed_release_set "$verify_dir" "$final_signer_spki" ||
    die "published release signatures or checksums do not match the expected signer"

  if [ "$original_signer" -eq 1 ]; then
    for asset in $expected_release_assets; do
      cmp "$checkpoint_dir/$asset" "$verify_dir/$asset" >/dev/null ||
        die "published v0.2.8 asset differs from the durable signed checkpoint: $asset"
    done
  elif [ "$already_final" -eq 0 ]; then
    for asset in $expected_release_assets; do
      cmp "$release_dir/$asset" "$verify_dir/$asset" >/dev/null ||
        die "published successor asset differs from the locally signed set: $asset"
    done
  else
    for asset in $binary_assets; do
      cmp "$unsigned_dir/$asset" "$verify_dir/$asset" >/dev/null ||
        die "preexisting successor binary differs from the reproduced attested set: $asset"
    done
  fi

  attest_assets="$binary_assets"
  if [ "$original_signer" -eq 1 ]; then
    attest_assets="$(printf '%s\n' *)"
  fi
  for asset in $attest_assets; do
    gh attestation verify "$asset" \
      --repo "$repo" \
      --signer-workflow "$repo/.github/workflows/release.yml" \
      --source-digest "$release_sha" \
      --source-ref "refs/tags/$tag" \
      --deny-self-hosted-runners >/dev/null
  done
)

printf 'release: %s is immutable, checksummed, and provenance-verified at %s\n' \
  "$tag" "$release_sha"

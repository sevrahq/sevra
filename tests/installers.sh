#!/bin/sh
# Exercise the Unix installer's dual-key verification and fail-closed
# signature option without network access or a real release.
set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
tmp="$(mktemp -d)"
tmp="$(CDPATH='' cd -- "$tmp" && pwd -P)"
trap 'rm -rf "$tmp"' EXIT INT TERM

tools="$tmp/tools"
release="$tmp/release/v9.9.9"
trusted="$tmp/trusted/9.9.9"
install_dir="$tmp/install"
mkdir -p "$tools" "$release" "$trusted"

for command in awk chmod cp curl cut dirname grep head mkdir mktemp mv rm rmdir sha256sum tr uname; do
  path="$(command -v "$command")"
  ln -s "$path" "$tools/$command"
done

case "$(uname -s):$(uname -m)" in
  Linux:x86_64|Linux:amd64) asset="sevra-linux-x86_64-musl" ;;
  Linux:arm64|Linux:aarch64) asset="sevra-linux-aarch64-musl" ;;
  Darwin:x86_64|Darwin:amd64) asset="sevra-darwin-x86_64" ;;
  Darwin:arm64|Darwin:aarch64) asset="sevra-darwin-aarch64" ;;
  *) printf 'unsupported installer-test host\n' >&2; exit 1 ;;
esac

printf %s 'sevra release signing trust-set regression v0.2.8' > "$release/$asset"
printf '%s\n' 'FCNsagdkJcD/ZDs5k0BhL8t23AKGLwO5Zrq0sv1BZr4HN8vHXIXWgrfm6GkV+mnUswY3utnyiCNeCavngLbBDg==' > "$release/$asset.sig"
digest="$(sha256sum "$release/$asset" | awk '{print $1}')"
printf '%s  %s\n' "$digest" "$asset" > "$release/SHA256SUMS"
printf '%s\n' "$digest" > "$trusted/$asset"

# The successor key is already trusted by the compatibility installer. The
# historical fixed fixture is intentionally not executable, so this assertion
# stops after proving the signature gate accepted it and before installation.
if SEVRA_VERSION=9.9.9 \
  SEVRA_INSTALL_BASE="file://$tmp/release" \
  SEVRA_TRUSTED_MANIFEST_BASE="file://$tmp/trusted" \
  SEVRA_INSTALL_DIR="$install_dir" \
  SEVRA_REQUIRE_SIGNATURE=1 \
  /bin/sh "$root/install.sh" >"$tmp/new-key-stdout" 2>"$tmp/new-key-stderr"; then
  printf 'non-executable signature fixture unexpectedly installed\n' >&2
  exit 1
fi
grep -q 'signature: verified (ed25519)' "$tmp/new-key-stdout"
grep -q 'verified binary could not securely install itself' "$tmp/new-key-stderr"
test ! -e "$install_dir/sevra"

# Exercise the real self-install capability. The local test binary is bound to
# its independently served digest; PATH excludes Node/OpenSSL so the synthetic
# fixture needs no unavailable private release key.
real_version=9.9.10
real_release="$tmp/release/v$real_version"
real_trusted="$tmp/trusted/$real_version"
real_binary="$root/target/debug/sevra"
[ -x "$real_binary" ] || cargo build --locked
mkdir -p "$real_release" "$real_trusted"
cp "$real_binary" "$real_release/$asset"
printf 'not-a-release-signature\n' >"$real_release/$asset.sig"
real_digest="$(sha256sum "$real_release/$asset" | awk '{print $1}')"
printf '%s\n' "$real_digest" >"$real_trusted/$asset"
real_install="$tmp/real-install"
PATH="$tools" \
  HOME="$tmp/home" \
  SEVRA_VERSION="$real_version" \
  SEVRA_INSTALL_BASE="file://$tmp/release" \
  SEVRA_TRUSTED_MANIFEST_BASE="file://$tmp/trusted" \
  SEVRA_INSTALL_DIR="$real_install" \
  /bin/sh "$root/install.sh" >"$tmp/real-stdout" 2>"$tmp/real-stderr"
cmp "$real_release/$asset" "$real_install/sevra"

# Dual-key acceptance never bypasses the independent digest root.
printf '%064d\n' 0 > "$trusted/$asset"
if SEVRA_VERSION=9.9.9 \
  SEVRA_INSTALL_BASE="file://$tmp/release" \
  SEVRA_TRUSTED_MANIFEST_BASE="file://$tmp/trusted" \
  SEVRA_INSTALL_DIR="$tmp/bad-digest-install" \
  SEVRA_REQUIRE_SIGNATURE=1 \
  /bin/sh "$root/install.sh" >"$tmp/bad-digest-stdout" 2>"$tmp/bad-digest-stderr"; then
  printf 'installer unexpectedly accepted a bad independent digest\n' >&2
  exit 1
fi
grep -q 'checksum mismatch' "$tmp/bad-digest-stderr"
test ! -e "$tmp/bad-digest-install/sevra"
printf '%s\n' "$digest" > "$trusted/$asset"

# A custom binary origin's colocated SHA256SUMS is never accepted as the
# independent root. An unavailable separate manifest refuses first.
if SEVRA_VERSION=9.9.9 \
  SEVRA_INSTALL_BASE="file://$tmp/release" \
  SEVRA_TRUSTED_MANIFEST_BASE="file://$tmp/missing-trust-root" \
  SEVRA_INSTALL_DIR="$tmp/missing-manifest-install" \
  /bin/sh "$root/install.sh" >"$tmp/missing-manifest-stdout" 2>"$tmp/missing-manifest-stderr"; then
  printf 'installer unexpectedly fell back to colocated SHA256SUMS\n' >&2
  exit 1
fi
grep -q 'request failed' "$tmp/missing-manifest-stderr"
test ! -e "$tmp/missing-manifest-install/sevra"

# A valid signature from an unrelated Ed25519 key must fail.
printf '%s\n' 'OS0fG3e4xQd6KTgUQallkV2RgzZQrB+b/rKAetJi9NWFe6se2U9LMu6GQfbDClgR3KwI36e6X8nWJATMoL2zCg==' > "$release/$asset.sig"
if SEVRA_VERSION=9.9.9 \
  SEVRA_INSTALL_BASE="file://$tmp/release" \
  SEVRA_TRUSTED_MANIFEST_BASE="file://$tmp/trusted" \
  SEVRA_INSTALL_DIR="$tmp/unrelated-install" \
  SEVRA_REQUIRE_SIGNATURE=1 \
  /bin/sh "$root/install.sh" >"$tmp/unrelated-stdout" 2>"$tmp/unrelated-stderr"; then
  printf 'installer unexpectedly trusted an unrelated signer\n' >&2
  exit 1
fi
grep -q 'publisher signature verification failed' "$tmp/unrelated-stderr"
test ! -e "$tmp/unrelated-install/sevra"

# PATH deliberately contains every utility the installer needs except
# Node/OpenSSL; the valid fixture checksum leaves only the mandatory
# publisher-signature gate to stop installation.
printf 'not-a-real-signature\n' > "$release/$asset.sig"
if PATH="$tools" \
  HOME="$tmp/home" \
  SEVRA_VERSION=9.9.9 \
  SEVRA_INSTALL_BASE="file://$tmp/release" \
  SEVRA_TRUSTED_MANIFEST_BASE="file://$tmp/trusted" \
  SEVRA_INSTALL_DIR="$tmp/no-verifier-install" \
  SEVRA_REQUIRE_SIGNATURE=1 \
  /bin/sh "$root/install.sh" >"$tmp/stdout" 2>"$tmp/stderr"; then
  printf 'strict installer unexpectedly succeeded without a verifier\n' >&2
  exit 1
fi
grep -q 'publisher signature verification is required' "$tmp/stderr"
test ! -e "$tmp/no-verifier-install/sevra"

# Reproduce the old predictable-stage exploit exactly. Pause the first
# download after the installer PID is known, plant `$DIR/.sevra.new.$PID` as a
# symlink, then release the download. The hardened installer never opens that
# path and the unrelated victim remains unchanged.
printf '%s\n' 'FCNsagdkJcD/ZDs5k0BhL8t23AKGLwO5Zrq0sv1BZr4HN8vHXIXWgrfm6GkV+mnUswY3utnyiCNeCavngLbBDg==' > "$release/$asset.sig"
race_tools="$tmp/race-tools"
race_gate="$tmp/race-gate"
race_install="$tmp/race-install"
mkdir -p "$race_tools" "$race_gate" "$race_install"
for command in awk chmod cp cut dirname grep head mkdir mktemp mv rm rmdir sha256sum tr uname; do
  ln -s "$(command -v "$command")" "$race_tools/$command"
done
real_curl="$(command -v curl)"
cat >"$race_tools/curl" <<'EOF'
#!/bin/sh
: >"$SEVRA_RACE_GATE/ready"
while [ ! -e "$SEVRA_RACE_GATE/go" ]; do /bin/sleep 0.01; done
exec "$SEVRA_REAL_CURL" "$@"
EOF
chmod +x "$race_tools/curl"
printf 'SAFE\n' >"$tmp/stage-victim"
PATH="$race_tools" \
  SEVRA_RACE_GATE="$race_gate" \
  SEVRA_REAL_CURL="$real_curl" \
  SEVRA_VERSION="$real_version" \
  SEVRA_INSTALL_BASE="file://$tmp/release" \
  SEVRA_TRUSTED_MANIFEST_BASE="file://$tmp/trusted" \
  SEVRA_INSTALL_DIR="$race_install" \
  /bin/sh "$root/install.sh" >"$tmp/race-stdout" 2>"$tmp/race-stderr" &
installer_pid=$!
while [ ! -e "$race_gate/ready" ]; do
  kill -0 "$installer_pid" 2>/dev/null || {
    wait "$installer_pid" || true
    printf 'installer exited before the stage-race gate\n' >&2
    exit 1
  }
  /bin/sleep 0.01
done
ln -s "$tmp/stage-victim" "$race_install/.sevra.new.$installer_pid"
: >"$race_gate/go"
wait "$installer_pid"
test "$(cat "$tmp/stage-victim")" = "SAFE"
test -f "$race_install/sevra"

# Reproduce the parent-swap exploit at the exact last lexical check boundary.
# The old `cd -P "$DIR"` path followed the replacement symlink and overwrote
# the outside binary. The verified binary now acquires a no-follow held
# directory capability and must refuse without touching either location.
swap_tools="$tmp/swap-tools"
swap_gate="$tmp/swap-gate"
swap_parent="$tmp/swap-parent"
swap_parked="$tmp/swap-parent-parked"
swap_outside="$tmp/swap-outside"
mkdir -p "$swap_tools" "$swap_gate" "$swap_parent/bin" "$swap_outside/bin"
for command in awk cp curl cut dirname grep head mkdir mktemp rm sha256sum tr uname; do
  ln -s "$(command -v "$command")" "$swap_tools/$command"
done
real_chmod="$(command -v chmod)"
cat >"$swap_tools/chmod" <<'EOF'
#!/bin/sh
: >"$SEVRA_SWAP_GATE/ready"
while [ ! -e "$SEVRA_SWAP_GATE/go" ]; do /bin/sleep 0.01; done
exec "$SEVRA_REAL_CHMOD" "$@"
EOF
chmod +x "$swap_tools/chmod"
printf 'SAFE\n' >"$swap_outside/bin/sevra"
PATH="$swap_tools" \
  HOME="$tmp/home" \
  SEVRA_SWAP_GATE="$swap_gate" \
  SEVRA_REAL_CHMOD="$real_chmod" \
  SEVRA_VERSION="$real_version" \
  SEVRA_INSTALL_BASE="file://$tmp/release" \
  SEVRA_TRUSTED_MANIFEST_BASE="file://$tmp/trusted" \
  SEVRA_INSTALL_DIR="$swap_parent/bin" \
  /bin/sh "$root/install.sh" >"$tmp/swap-stdout" 2>"$tmp/swap-stderr" &
swap_pid=$!
while [ ! -e "$swap_gate/ready" ]; do
  kill -0 "$swap_pid" 2>/dev/null || {
    wait "$swap_pid" || true
    printf 'installer exited before the parent-swap gate\n' >&2
    exit 1
  }
  /bin/sleep 0.01
done
mv "$swap_parent" "$swap_parked"
ln -s "$swap_outside" "$swap_parent"
: >"$swap_gate/go"
if wait "$swap_pid"; then
  printf 'installer unexpectedly accepted a swapped install parent\n' >&2
  exit 1
fi
grep -q 'verified binary could not securely install itself' "$tmp/swap-stderr"
test "$(cat "$swap_outside/bin/sevra")" = "SAFE"
test ! -e "$swap_parked/bin/sevra"

# The directory may not exist yet. Swap an existing ancestor after all shell
# checks but before the helper starts; no shell mkdir is allowed to follow the
# replacement link, and the helper's no-follow traversal must create nothing
# in either the parked tree or the outside target.
create_tools="$tmp/create-tools"
create_gate="$tmp/create-gate"
create_parent="$tmp/create-parent"
create_parked="$tmp/create-parent-parked"
create_outside="$tmp/create-outside"
mkdir -p "$create_tools" "$create_gate" "$create_parent" "$create_outside"
for command in awk cp curl cut dirname grep head mktemp rm sha256sum tr uname; do
  ln -s "$(command -v "$command")" "$create_tools/$command"
done
cat >"$create_tools/chmod" <<'EOF'
#!/bin/sh
: >"$SEVRA_CREATE_GATE/ready"
while [ ! -e "$SEVRA_CREATE_GATE/go" ]; do /bin/sleep 0.01; done
exec "$SEVRA_REAL_CHMOD" "$@"
EOF
chmod +x "$create_tools/chmod"
PATH="$create_tools" \
  HOME="$tmp/home" \
  SEVRA_CREATE_GATE="$create_gate" \
  SEVRA_REAL_CHMOD="$real_chmod" \
  SEVRA_VERSION="$real_version" \
  SEVRA_INSTALL_BASE="file://$tmp/release" \
  SEVRA_TRUSTED_MANIFEST_BASE="file://$tmp/trusted" \
  SEVRA_INSTALL_DIR="$create_parent/new/deep" \
  /bin/sh "$root/install.sh" >"$tmp/create-stdout" 2>"$tmp/create-stderr" &
create_pid=$!
while [ ! -e "$create_gate/ready" ]; do
  kill -0 "$create_pid" 2>/dev/null || {
    wait "$create_pid" || true
    printf 'installer exited before the missing-root swap gate\n' >&2
    exit 1
  }
  /bin/sleep 0.01
done
mv "$create_parent" "$create_parked"
ln -s "$create_outside" "$create_parent"
: >"$create_gate/go"
if wait "$create_pid"; then
  printf 'installer unexpectedly created through a swapped missing root\n' >&2
  exit 1
fi
grep -q 'verified binary could not securely install itself' "$tmp/create-stderr"
test ! -e "$create_outside/new"
test ! -e "$create_parked/new"

# A preexisting destination symlink to a directory made plain `mv -f` select
# its "move into directory" form and overwrite `<outside>/sevra`. The
# installer must reject the link before the final rename.
destination_link_install="$tmp/destination-link-install"
destination_link_outside="$tmp/destination-link-outside"
mkdir -p "$destination_link_install" "$destination_link_outside"
printf 'SAFE\n' >"$destination_link_outside/sevra"
ln -s "$destination_link_outside" "$destination_link_install/sevra"
if SEVRA_VERSION=9.9.9 \
  SEVRA_INSTALL_BASE="file://$tmp/release" \
  SEVRA_TRUSTED_MANIFEST_BASE="file://$tmp/trusted" \
  SEVRA_INSTALL_DIR="$destination_link_install" \
  SEVRA_REQUIRE_SIGNATURE=1 \
  /bin/sh "$root/install.sh" >"$tmp/destination-link-stdout" 2>"$tmp/destination-link-stderr"; then
  printf 'installer unexpectedly accepted a destination symlink\n' >&2
  exit 1
fi
grep -q 'install destination must not be a symbolic link' "$tmp/destination-link-stderr"
test "$(cat "$destination_link_outside/sevra")" = "SAFE"
test -L "$destination_link_install/sevra"

# Every install-directory component is part of the boundary. A symlinked
# `$DIR` must not become an authority to write into its target.
parent_link_outside="$tmp/parent-link-outside"
parent_link_install="$tmp/parent-link-install"
mkdir -p "$parent_link_outside"
printf 'SAFE\n' >"$parent_link_outside/sevra"
ln -s "$parent_link_outside" "$parent_link_install"
if SEVRA_VERSION=9.9.9 \
  SEVRA_INSTALL_BASE="file://$tmp/release" \
  SEVRA_TRUSTED_MANIFEST_BASE="file://$tmp/trusted" \
  SEVRA_INSTALL_DIR="$parent_link_install" \
  SEVRA_REQUIRE_SIGNATURE=1 \
  /bin/sh "$root/install.sh" >"$tmp/parent-link-stdout" 2>"$tmp/parent-link-stderr"; then
  printf 'installer unexpectedly accepted a symlinked install directory\n' >&2
  exit 1
fi
grep -q 'install directory must not contain symbolic links' "$tmp/parent-link-stderr"
test "$(cat "$parent_link_outside/sevra")" = "SAFE"

# A directory or special entry at the leaf is not an existing install and
# must never trigger mv's directory-target behavior.
directory_leaf_install="$tmp/directory-leaf-install"
mkdir -p "$directory_leaf_install/sevra"
if SEVRA_VERSION=9.9.9 \
  SEVRA_INSTALL_BASE="file://$tmp/release" \
  SEVRA_TRUSTED_MANIFEST_BASE="file://$tmp/trusted" \
  SEVRA_INSTALL_DIR="$directory_leaf_install" \
  SEVRA_REQUIRE_SIGNATURE=1 \
  /bin/sh "$root/install.sh" >"$tmp/directory-leaf-stdout" 2>"$tmp/directory-leaf-stderr"; then
  printf 'installer unexpectedly accepted a directory destination\n' >&2
  exit 1
fi
grep -q 'install destination must be absent or a regular file' "$tmp/directory-leaf-stderr"
test ! -e "$directory_leaf_install/sevra/sevra"

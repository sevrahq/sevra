#!/bin/sh
# sevra installer — the command line for the Sevra hub (the managed home for
# db.md brains).
#
#   curl -fsSL https://www.sevrahq.com/install/sevra.sh | sh
#
# Downloads the signed `sevra` static binary for your platform, verifies its
# SHA-256 against Sevra's independently deployed release manifest (required)
# and its Ed25519 publisher signature when a verifier is present, then drops it
# on your PATH. No runtime, no package manager, no
# dependencies. macOS + Linux (x86_64/arm64); on Windows use the PowerShell
# installer: irm https://www.sevrahq.com/install/sevra.ps1 | iex
#
# Honors: SEVRA_INSTALL_DIR (default ~/.sevra/bin), SEVRA_VERSION (default
# latest), SEVRA_INSTALL_BASE (default GitHub releases),
# SEVRA_TRUSTED_MANIFEST_BASE (defaults to the Sevra origin), and
# SEVRA_REQUIRE_SIGNATURE=1 (refuse when neither Node nor OpenSSL 3 can verify).
# POSIX sh, no bashisms.
set -eu

REPO="sevrahq/sevra"
DIR="${SEVRA_INSTALL_DIR:-$HOME/.sevra/bin}"
BASE="${SEVRA_INSTALL_BASE:-https://github.com/$REPO/releases/download}"
API="https://www.sevrahq.com/api/hub/versions"
TRUSTED_MANIFEST_BASE="${SEVRA_TRUSTED_MANIFEST_BASE:-https://www.sevrahq.com/api/hub/releases/sevra}"

# The pinned publisher keys (Ed25519 SPKI). v0.2.8 is signed by the original
# key while trusting both it and its successor, so clients can cross the
# rotation without a flag day.
PUBKEY_OLD_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+v5mafEPcIwKAU/DO/z8MM/cT9ndgE1saSUfvcrzLKA=
-----END PUBLIC KEY-----'
PUBKEY_NEXT_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAasunxAjcJp8W30eF0ndPlLXqwSjZ/u5raivn3QmaKcc=
-----END PUBLIC KEY-----'

err() { printf 'sevra install: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

reject_install_path_links() {
  check_path="$1"
  while :; do
    [ ! -L "$check_path" ] ||
      err "install directory must not contain symbolic links: $check_path"
    [ "$check_path" = "/" ] && break
    parent_path="$(dirname "$check_path")"
    [ "$parent_path" != "$check_path" ] || break
    check_path="$parent_path"
  done
}

reject_install_leaf() {
  leaf="$1"
  [ ! -L "$leaf" ] ||
    err "install destination must not be a symbolic link: $leaf"
  if [ -e "$leaf" ] && [ ! -f "$leaf" ]; then
    err "install destination must be absent or a regular file: $leaf"
  fi
}

fetch() {
  if have curl; then curl -fsSL "$1" -o "$2" || err "download failed: $1"
  elif have wget; then wget -qO "$2" "$1" || err "download failed: $1"
  else err "need curl or wget"; fi
}
# Print one trusted-origin response to stdout.
fetch_stdout() {
  if have curl; then
    curl -fsSL "$1" || err "request failed: $1"
  elif have wget; then
    wget -qO- "$1" || err "request failed: $1"
  else err "need curl or wget"; fi
}

# Everything below runs through main(), called on the LAST line — a truncated
# `curl | sh` stream can therefore never execute a partial script.
main() {

case "${SEVRA_REQUIRE_SIGNATURE:-0}" in
  0|1) ;;
  *) err "SEVRA_REQUIRE_SIGNATURE must be 0 or 1" ;;
esac

# ── Platform ─────────────────────────────────────────────────────────────────
os="$(uname -s)"; arch="$(uname -m)"
case "$os" in
  Darwin) p_os="darwin" ;;
  Linux)  p_os="linux" ;;
  *) err "unsupported OS: $os (macOS/Linux; on Windows: irm https://www.sevrahq.com/install/sevra.ps1 | iex)" ;;
esac
case "$arch" in
  x86_64|amd64) p_arch="x86_64" ;;
  arm64|aarch64) p_arch="aarch64" ;;
  *) err "unsupported arch: $arch" ;;
esac
if [ "$p_os" = "linux" ]; then target="linux-${p_arch}-musl"; else target="darwin-${p_arch}"; fi

# ── Version ──────────────────────────────────────────────────────────────────
version="${SEVRA_VERSION:-}"
if [ -z "$version" ]; then
  info "Resolving the latest sevra release..."
  version="$(fetch_stdout "$API" | grep -m1 -o '"latest":"[0-9.]*"' | head -1 | cut -d'"' -f4)"
  [ -n "$version" ] || err "could not resolve the trusted latest release; pin SEVRA_VERSION to retry"
fi
asset="sevra-${target}"
url="$BASE/v${version}/${asset}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp" 2>/dev/null || true' EXIT INT TERM

info "Downloading sevra ${version} (${target})..."
fetch "$url" "$tmp/sevra"
fetch "$url.sig" "$tmp/sevra.sig"

# ── Verify checksum against the independently deployed manifest ─────────────
# A custom binary mirror does not get to silently become its own trust root.
# Tests/private mirrors must explicitly set SEVRA_TRUSTED_MANIFEST_BASE to a
# separately controlled bare-digest endpoint with the same path contract.
expected="$(fetch_stdout "$TRUSTED_MANIFEST_BASE/$version/$asset" | tr -d '[:space:]')"
case "$expected" in *[!0-9a-f]*|'') err "no trusted checksum for sevra $version $asset" ;; esac
if have sha256sum; then actual="$(sha256sum "$tmp/sevra" | awk '{print $1}')"
elif have shasum; then actual="$(shasum -a 256 "$tmp/sevra" | awk '{print $1}')"
else err "need sha256sum or shasum to verify the download"; fi
[ "$actual" = "$expected" ] || err "checksum mismatch (expected $expected, got $actual). Refusing to install"
info "checksum: verified (sha256)"

# ── Verify signature (required when a verifier is available) ────────────────
verified_sig=0
verifier_available=0
if have node; then
  verifier_available=1
  if SEVRA_PUBKEY_OLD="$PUBKEY_OLD_PEM" SEVRA_PUBKEY_NEXT="$PUBKEY_NEXT_PEM" node -e '
    const { createPublicKey, verify } = require("node:crypto");
    const { readFileSync } = require("node:fs");
    const message = readFileSync(process.argv[1]);
    const signature = Buffer.from(readFileSync(process.argv[2], "utf8").trim(), "base64");
    const keys = [process.env.SEVRA_PUBKEY_OLD, process.env.SEVRA_PUBKEY_NEXT];
    const ok = keys.some((pem) =>
      verify(null, message, createPublicKey(pem), signature));
    process.exit(ok ? 0 : 1);
  ' "$tmp/sevra" "$tmp/sevra.sig" >/dev/null 2>&1; then verified_sig=1; fi
fi
if [ "$verified_sig" -eq 0 ] && have openssl; then
  for pubkey_pem in "$PUBKEY_OLD_PEM" "$PUBKEY_NEXT_PEM"; do
    printf '%s' "$pubkey_pem" > "$tmp/pub.pem"
    # Capability probe, NOT mere presence: only OpenSSL 3+ can do Ed25519, and
    # stock macOS ships LibreSSL (which cannot even load this key). Gating on
    # `have openssl` alone marked those machines as "verifier available", so a
    # perfectly good download was reported as a failed publisher signature and
    # the install aborted — on exactly the no-Node machines this path exists to
    # serve. If the tool cannot load the key, treat it as no verifier and fall
    # back to the manifest digest; only a CAPABLE verifier's failure is fatal.
    if openssl pkey -pubin -in "$tmp/pub.pem" -noout >/dev/null 2>&1; then
      verifier_available=1
      if base64 -d < "$tmp/sevra.sig" > "$tmp/sig.bin" 2>/dev/null \
         || base64 -D < "$tmp/sevra.sig" > "$tmp/sig.bin" 2>/dev/null; then
        if openssl pkeyutl -verify -pubin -inkey "$tmp/pub.pem" -rawin -in "$tmp/sevra" -sigfile "$tmp/sig.bin" >/dev/null 2>&1; then
          verified_sig=1
          break
        fi
      fi
    fi
  done
fi
if [ "$verified_sig" -eq 1 ]; then
  info "signature: verified (ed25519)"
elif [ "$verifier_available" -eq 1 ]; then
  err "publisher signature verification failed. Refusing to install"
elif [ "${SEVRA_REQUIRE_SIGNATURE:-0}" = "1" ]; then
  err "publisher signature verification is required, but neither Node nor an Ed25519-capable OpenSSL is available. Refusing to install"
else
  info "signature: verifier unavailable; the required SHA-256 came from the independently deployed Sevra manifest"
fi

# ── Install ──────────────────────────────────────────────────────────────────
case "$DIR" in
  /*) ;;
  *) DIR="$(pwd -P)/$DIR" ;;
esac
reject_install_path_links "$DIR"
reject_install_leaf "$DIR/sevra"
chmod +x "$tmp/sevra"
# The verified binary is the installation capability helper. It opens every
# install-directory component without following links, retains that directory
# handle, stages through it, re-hashes stdin, and atomically replaces only the
# held directory's `sevra` entry. A parent rename or symlink swap after the
# lexical courtesy checks therefore cannot redirect the write.
exec 9<"$tmp/sevra"
if ! "$tmp/sevra" __install-verified --dir "$DIR" --sha256 "$expected" <&9; then
  exec 9<&-
  err "the verified binary could not securely install itself"
fi
exec 9<&-
info "sevra ${version} installed to $DIR/sevra"
case ":$PATH:" in
  *":$DIR:"*) info "Next: sevra login   (approve once in your browser)" ;;
  *)
    info "Add it to your PATH, then log in:"
    info "  export PATH=\"$DIR:\$PATH\""
    info "  sevra login" ;;
esac

}
main "$@"

#!/bin/sh
# sevra installer — the command line for the Sevra hub (the managed home for
# db.md brains).
#
#   curl -fsSL https://www.sevrahq.com/install/sevra.sh | sh
#
# Downloads the signed `sevra` static binary for your platform, verifies its
# SHA-256 (required) and its Ed25519 publisher signature (when node or openssl 3
# is present), and drops it on your PATH. No runtime, no package manager, no
# dependencies. macOS + Linux (x86_64/arm64); on Windows use WSL.
#
# Honors: SEVRA_INSTALL_DIR (default ~/.sevra/bin), SEVRA_VERSION (default
# latest), SEVRA_INSTALL_BASE (default GitHub releases),
# SEVRA_REQUIRE_SIGNATURE=1 (fail the install when the Ed25519 signature
# cannot be checked here, instead of relying on SHA-256 + HTTPS alone).
# POSIX sh, no bashisms.
set -eu

REPO="sevrahq/sevra"
DIR="${SEVRA_INSTALL_DIR:-$HOME/.sevra/bin}"
BASE="${SEVRA_INSTALL_BASE:-https://github.com/$REPO/releases/download}"
API="https://api.github.com/repos/$REPO/releases/latest"

# The pinned publisher key (Ed25519 SPKI) — the same key that signs releases in
# CI and is pinned inside the binary for self-update.
PUBKEY_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+v5mafEPcIwKAU/DO/z8MM/cT9ndgE1saSUfvcrzLKA=
-----END PUBLIC KEY-----'

err() { printf 'sevra install: %s\n' "$*" >&2; exit 1; }
info() { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

fetch() {
  if have curl; then curl -fsSL "$1" -o "$2" || err "download failed: $1"
  elif have wget; then wget -qO "$2" "$1" || err "download failed: $1"
  else err "need curl or wget"; fi
}
# The latest-release lookup on api.github.com. An optional GITHUB_TOKEN
# authenticates it (CI runners share rate-limited IPs; unauthenticated is
# 60 req/h per IP). The token is sent ONLY to this hardcoded api.github.com
# URL, never to the download host.
fetch_api() {
  if have curl; then
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      curl -fsSL -H "authorization: Bearer $GITHUB_TOKEN" "$1" || err "request failed: $1"
    else
      curl -fsSL "$1" || err "request failed: $1"
    fi
  elif have wget; then
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      wget -qO- --header="authorization: Bearer $GITHUB_TOKEN" "$1" || err "request failed: $1"
    else
      wget -qO- "$1" || err "request failed: $1"
    fi
  else err "need curl or wget"; fi
}

# Everything below runs through main(), called on the LAST line — a truncated
# `curl | sh` stream can therefore never execute a partial script.
main() {

# ── Platform ─────────────────────────────────────────────────────────────────
os="$(uname -s)"; arch="$(uname -m)"
case "$os" in
  Darwin) p_os="darwin" ;;
  Linux)  p_os="linux" ;;
  *) err "unsupported OS: $os (macOS/Linux only; on Windows use WSL)" ;;
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
  version="$(fetch_api "$API" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name"[^"]*"([^"]+)".*/\1/')"
  version="${version#v}"
  [ -n "$version" ] || err "could not resolve the latest release (rate-limited? set GITHUB_TOKEN, or pin SEVRA_VERSION)"
fi
asset="sevra-${target}"
url="$BASE/v${version}/${asset}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"; rm -f "${staged:-}" 2>/dev/null || true' EXIT INT TERM

info "Downloading sevra ${version} (${target})..."
fetch "$url" "$tmp/sevra"
fetch "$url.sig" "$tmp/sevra.sig"
fetch "$BASE/v${version}/SHA256SUMS" "$tmp/SHA256SUMS"

# ── Verify checksum (required) ───────────────────────────────────────────────
expected="$(grep " ${asset}\$" "$tmp/SHA256SUMS" | awk '{print $1}')"
[ -n "$expected" ] || err "no checksum for $asset in SHA256SUMS"
if have sha256sum; then actual="$(sha256sum "$tmp/sevra" | awk '{print $1}')"
elif have shasum; then actual="$(shasum -a 256 "$tmp/sevra" | awk '{print $1}')"
else err "need sha256sum or shasum to verify the download"; fi
[ "$actual" = "$expected" ] || err "checksum mismatch (expected $expected, got $actual) — refusing to install"
info "checksum: verified (sha256)"

# ── Verify signature (best-effort: node, else openssl 3) ─────────────────────
verified_sig=0
if have node; then
  if SEVRA_PUBKEY="$PUBKEY_PEM" node -e '
    const { createPublicKey, verify } = require("node:crypto");
    const { readFileSync } = require("node:fs");
    const ok = verify(null, readFileSync(process.argv[1]),
      createPublicKey(process.env.SEVRA_PUBKEY),
      Buffer.from(readFileSync(process.argv[2], "utf8").trim(), "base64"));
    process.exit(ok ? 0 : 1);
  ' "$tmp/sevra" "$tmp/sevra.sig" >/dev/null 2>&1; then verified_sig=1; fi
fi
if [ "$verified_sig" -eq 0 ] && have openssl; then
  printf '%s' "$PUBKEY_PEM" > "$tmp/pub.pem"
  if base64 -d < "$tmp/sevra.sig" > "$tmp/sig.bin" 2>/dev/null \
     || base64 -D < "$tmp/sevra.sig" > "$tmp/sig.bin" 2>/dev/null; then
    if openssl pkeyutl -verify -pubin -inkey "$tmp/pub.pem" -rawin -in "$tmp/sevra" -sigfile "$tmp/sig.bin" >/dev/null 2>&1; then
      verified_sig=1
    fi
  fi
fi
if [ "$verified_sig" -eq 1 ]; then
  info "signature: verified (ed25519)"
elif [ "${SEVRA_REQUIRE_SIGNATURE:-}" = "1" ]; then
  err "signature could not be checked (no node or openssl 3) and SEVRA_REQUIRE_SIGNATURE=1 — refusing to install"
else
  info "signature: not checked here (no node or openssl 3); the SHA-256 above was verified over HTTPS, and the binary re-verifies its signature on every self-update. Set SEVRA_REQUIRE_SIGNATURE=1 to make this check mandatory."
fi

# ── Install ──────────────────────────────────────────────────────────────────
mkdir -p "$DIR"
chmod +x "$tmp/sevra"
# Stage inside $DIR, then rename: atomic on the same filesystem, so a running
# `sevra` (or a reinstall over one) never sees a half-written binary — a plain
# cross-device mv from $tmp would write the destination in place.
staged="$DIR/.sevra.new.$$"
cp "$tmp/sevra" "$staged"
chmod +x "$staged"
mv -f "$staged" "$DIR/sevra"
info "sevra ${version} installed to $DIR/sevra"
case ":$PATH:" in
  *":$DIR:"*) info "Next: sevra login --key vc_account_...   (create a key in the dashboard)" ;;
  *)
    info "Add it to your PATH, then log in:"
    info "  export PATH=\"$DIR:\$PATH\""
    info "  sevra login --key vc_account_..." ;;
esac

}
main "$@"

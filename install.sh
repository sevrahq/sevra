#!/bin/sh
# sevra installer.
#
#   curl -fsSL https://www.sevrahq.com/install/sevra.sh | sh
#
# Downloads the sevra CLI (a single self-contained Node script) and drops it
# on your PATH. sevra is the client for the Sevra hub (the managed home for
# db.md brains): it logs in with a key from the dashboard, pushes a local
# db.md store up, and queries a brain. It defaults to https://www.sevrahq.com.
#
# Requires Node.js 18+ (the CLI is a node script). No sudo. Honors
# $SEVRA_INSTALL_DIR (default ~/.sevra/bin) and $SEVRA_INSTALL_BASE
# (default https://www.sevrahq.com — set it to install from another host).
# POSIX sh, no bashisms.
set -e

BASE="${SEVRA_INSTALL_BASE:-https://www.sevrahq.com}"
DIR="${SEVRA_INSTALL_DIR:-$HOME/.sevra/bin}"

err() { echo "sevra install: $1" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have node || err "Node.js 18+ is required (https://nodejs.org). Install it, then re-run."
NODE_MAJOR="$(node -e 'process.stdout.write(String(process.versions.node.split(".")[0]||0))' 2>/dev/null || echo 0)"
# Guard the numeric test: if node emits anything non-numeric, treat it as 0 so
# the comparison fails cleanly instead of printing an "integer expression" error.
case "$NODE_MAJOR" in ''|*[!0-9]*) NODE_MAJOR=0 ;; esac
[ "$NODE_MAJOR" -ge 18 ] || err "Node.js 18+ required (found $(node -v 2>/dev/null || echo none)). Upgrade node, then re-run."

mkdir -p "$DIR"
TMP="$(mktemp)"
URL="$BASE/install/sevra.cjs"

if have curl; then
  curl -fsSL "$URL" -o "$TMP" || err "download failed: $URL"
elif have wget; then
  wget -qO "$TMP" "$URL" || err "download failed: $URL"
else
  err "need curl or wget"
fi

# Sanity: the payload must start with the node shebang, else we downloaded an
# error page, not the CLI.
head -n 1 "$TMP" | grep -q "usr/bin/env node" || err "unexpected payload from $URL (not the CLI)"

# Verify the artifact's Ed25519 signature against the pinned publisher key
# before installing anything — TLS alone trusts whatever the origin's edge
# serves; this refuses a tampered or unsigned payload outright. Verification
# uses node's built-in crypto (node is already required), so no extra tooling.
# The same key is pinned in the CLI itself (self-update verifies too) and
# served at /install/sevra.pub for out-of-band checks.
SIG="$(mktemp)"
if have curl; then
  curl -fsSL "$URL.sig" -o "$SIG" || err "download failed: $URL.sig"
else
  wget -qO "$SIG" "$URL.sig" || err "download failed: $URL.sig"
fi
node -e "
const { createPublicKey, verify } = require('node:crypto');
const { readFileSync } = require('node:fs');
const pub = createPublicKey('-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA+v5mafEPcIwKAU/DO/z8MM/cT9ndgE1saSUfvcrzLKA=\n-----END PUBLIC KEY-----');
const ok = verify(null, readFileSync(process.argv[1]), pub, Buffer.from(readFileSync(process.argv[2], 'utf8').trim(), 'base64'));
process.exit(ok ? 0 : 1);
" "$TMP" "$SIG" || err "signature verification FAILED for $URL — refusing to install (report: https://www.sevrahq.com/security)"
rm -f "$SIG"
echo "signature: verified (ed25519)"

mv "$TMP" "$DIR/sevra"
chmod +x "$DIR/sevra"

echo "sevra installed to $DIR/sevra"
case ":$PATH:" in
  *":$DIR:"*)
    echo "Next: sevra login --key vc_account_...   (create a key in the dashboard)"
    ;;
  *)
    echo "Add it to your PATH, then log in:"
    echo "  export PATH=\"$DIR:\$PATH\""
    echo "  sevra login --key vc_account_...   (create a key in the dashboard)"
    ;;
esac

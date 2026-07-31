# Security policy

## Reporting

Email **security@sevrahq.com**. We read every report. Please include steps to
reproduce and the version (`sevra version`).

## Supply-chain posture

- **Signed releases.** Every release binary is Ed25519-signed
  (`sevra-<target>.sig`, base64 of 64 raw bytes) and covered by a
  `SHA256SUMS` manifest. The publisher public key is pinned in the binary
  (`src/signing.rs`), pinned in `install.sh`, committed as `sevra.pub`, and
  served at https://www.sevrahq.com/install/sevra.pub. v0.2.8 is the sole
  compatibility release signed by the original key on a protected runner.
  Successor keys never enter GitHub: Actions produces exact unsigned,
  tag/SHA-attested binaries, then the local controller independently rebuilds
  and byte-compares all five targets before reading the key from 1Password
  Recovery over stdin-only process memory. It checks the successor SPKI,
  signs locally, and publishes only the complete immutable release.
  GitHub/Sigstore provenance remains present for every binary. Verify with
  `gh attestation verify <binary> --repo sevrahq/sevra`.
- **Verified installs.** `install.sh` always requires the SHA-256 to match —
  the expected value comes from Sevra's independently deployed release
  manifest, never from the binary origin's colocated `SHA256SUMS`. Authorship
  (the Ed25519 signature) is verified when node or openssl 3 is present;
  `SEVRA_REQUIRE_SIGNATURE=1` makes it mandatory (the install fails rather
  than skip the check). Every self-update after install enforces the signature
  unconditionally. Install-directory symlinks, Windows reparse points, and
  non-file destinations are refused; final replacement is same-directory and
  atomic.
- **Verified self-updates.** `sevra` requires both a valid signature against
  the pinned key and the matching digest from Sevra's independently deployed
  manifest. Missing, malformed, unavailable, or mismatched trust data refuses
  the update. A security failure prints a `SECURITY:` line and leaves the
  installed binary untouched.
- **Dependency policy.** Permissive licenses only, advisories denied, enforced
  in CI by `cargo deny` (see `deny.toml`); the inventory is
  `THIRD_PARTY_NOTICES`.

## Scope notes

- The CLI sends your account key only to the configured hub, refuses non-HTTPS
  hubs (loopback exempt), and stores config at `~/.sevra/config.json` mode 0600.
- `--json` output never includes the key. Keys are whitespace-trimmed and
  charset-checked before they touch a request header, so a malformed key is
  refused with a message that never echoes it.
- Human terminal output makes ANSI/OSC and other control sequences inert;
  machine-readable JSON preserves values through standard JSON escaping.
- Asset transport streams through private staged files with a client-owned
  2 GiB ceiling. Oversize declarations, sparse oversize sources, excess body
  bytes, length drift, or SHA-256 drift are refused before upload confirmation
  or destination replacement.

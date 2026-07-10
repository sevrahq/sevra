# Security policy

## Reporting

Email **security@sevrahq.com**. We read every report. Please include steps to
reproduce and the version (`sevra version`).

## Supply-chain posture

- **Signed releases.** Every release binary is Ed25519-signed in CI
  (`sevra-<target>.sig`, base64 of 64 raw bytes) and covered by a
  `SHA256SUMS` manifest. The publisher public key is pinned in the binary
  (`src/signing.rs`), pinned in `install.sh`, committed as `sevra.pub`, and
  served at https://www.sevrahq.com/install/sevra.pub.
- **Verified installs.** `install.sh` requires the SHA-256 to match and
  verifies the signature when node or openssl 3 is available.
- **Verified self-updates.** `sevra` refuses to replace itself with any byte
  stream that fails signature verification against the pinned key. A failure
  prints a `SECURITY:` line and leaves the installed binary untouched.
- **Dependency policy.** Permissive licenses only, advisories denied, enforced
  in CI by `cargo deny` (see `deny.toml`); the inventory is
  `THIRD_PARTY_NOTICES`.

## Scope notes

- The CLI sends your account key only to the configured hub, refuses non-HTTPS
  hubs (loopback exempt), and stores config at `~/.sevra/config.json` mode 0600.
- `--json` output never includes the key.

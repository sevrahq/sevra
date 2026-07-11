# Releasing sevra

The deploy model: release-versioned static binaries; installed CLIs
signed-self-update from GitHub Releases, discovering the latest version via
the hub's `/api/hub/versions`.

## Cut a release

1. Bump `version` in `Cargo.toml` (SemVer) + add a `CHANGELOG.md` entry.
2. `make check` (fmt + clippy -D warnings + tests) and `cargo deny check`.
3. Commit, push, then tag and push the tag:

   ```sh
   git tag vX.Y.Z && git push origin main vX.Y.Z
   ```

4. CI (`release.yml`) runs preflight, cross-builds the 4 targets, then signs
   every binary in the publish job (the `SEVRA_CLI_SIGNING_KEY` secret is
   never exposed to the build jobs or their third-party actions) and publishes
   the GitHub Release with `SHA256SUMS`. The released version MUST equal the
   Cargo.toml version (the version job enforces it for tags AND dispatches).
5. `smoke.yml` installs from the fresh release on macOS + Linux runners and
   runs `sevra version`. Green smoke = the release is live; installed CLIs
   pick it up on their next daily check (or `sevra update`).
6. If `install.sh` changed: copy it to the platform repo's `install/sevra.sh`
   (the hub serves that snapshot at https://www.sevrahq.com/install/sevra.sh)
   and deploy. The two copies must stay byte-identical.

## Key custody

The Ed25519 signing key lives in three places (Vercel production env,
the platform repo's `.env.local`, this repo's Actions secret). Set the
secret by piping to stdin: `gh secret set SEVRA_CLI_SIGNING_KEY -R
sevrahq/sevra` — never `--body -`, which stores a literal dash. Rotation is
additive and order-sensitive: pin the NEW public key in `src/signing.rs` +
`install.sh` + `sevra.pub`, release while still signing with the old key, let
installed binaries update onto the dual-pin build, then swap the private key
and drop the old pin a release later. Full notes: the platform repo's
`infra/README.md`.

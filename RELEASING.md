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

4. CI (`release.yml`) runs preflight, cross-builds the 5 targets (darwin
   x86_64/aarch64, linux x86_64/aarch64 musl, windows x86_64 msvc — the
   Windows asset is `sevra-windows-x86_64.exe`), then signs every binary in
   the publish job (the `SEVRA_CLI_SIGNING_KEY` secret is never exposed to
   the build jobs or their third-party actions) and publishes the GitHub
   Release with `SHA256SUMS`. The released version MUST equal the Cargo.toml
   version (the version job enforces it for tags AND dispatches). After the
   release is published, copy the asset digests into the platform repo's
   static trusted manifest and deploy it. Ordinary installs do not trust the
   checksum served beside the GitHub binary.
5. After the trusted manifest deployment is live, manually dispatch
   `smoke.yml` with the concrete version. It installs from the release on
   macOS + Linux (install.sh) and Windows (install.ps1), then runs
   `sevra version` + the not-logged-in contract. It intentionally does not
   auto-run at release publication: the independently controlled manifest is
   not approved yet, and the correct installer behavior at that point is to
   fail closed. Green post-manifest smoke = the release is live; installed
   CLIs pick it up on their next daily check (or `sevra update`).
6. If `install.sh` or `install.ps1` changed: copy them to the platform repo's
   `install/sevra.sh` / `install/sevra.ps1` (the hub serves those snapshots
   at https://www.sevrahq.com/install/sevra.sh and .../install/sevra.ps1)
   and deploy. Each pair must stay byte-identical.

## Key custody

The Ed25519 signing key is available to the release job only through this
repo's Actions secret. A separately controlled recovery copy must exist
offline; the platform runtime does not sign releases and must not hold this
key. The secret's
value is the **base64 of the PKCS#8 PEM** (release.yml decodes with
`Buffer.from(..., "base64")` and hands the PEM to `createPrivateKey`; a raw
PEM or base64-of-DER fails the sign step with ERR_OSSL_UNSUPPORTED). Set it
by piping to stdin:

```sh
base64 < sevra-signing-key.pem | tr -d '\n' \
  | gh secret set SEVRA_CLI_SIGNING_KEY -R sevrahq/sevra
```

Never `--body -`, which stores a literal dash. Rotation is
additive and order-sensitive: pin the NEW public key in `src/signing.rs` +
`install.sh` + `sevra.pub`, release while still signing with the old key, let
installed binaries update onto the dual-pin build, then swap the Actions
secret and drop the old pin a release later. Full notes: the platform repo's
`infra/README.md`.

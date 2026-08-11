# Releasing sevra

The deploy model: release-versioned static binaries; installed CLIs
signed-self-update from GitHub Releases, discovering the latest version via
the hub's `/api/hub/versions`.

## Cut a release

1. Bump `version` in `Cargo.toml` (SemVer) + add a `CHANGELOG.md` entry.
2. `make check` (fmt + clippy -D warnings + tests) and `cargo deny check`.
3. Commit and push `main`. Wait for the exact commit's `ci.yml` run to pass.
   Do not create or push the tag by hand.
4. Run the guarded release wrapper from a clean `main` worktree:

   ```sh
   scripts/release.sh \
     --signing-key-ref 'op://RECOVERY_VAULT/SIGNING_ITEM/FIELD' \
     vX.Y.Z
   ```

   The wrapper refuses a dirty/non-main worktree, a non-canonical origin, a
   commit other than the exact `origin/main`, or a commit without a successful
   main-push `ci.yml` run. It also proves repository-level immutable Releases
   are enabled before creating the tag. It then waits for Actions to produce
   exactly five unsigned, tag/SHA-attested binaries. Before reading the
   successor key, the wrapper verifies every attestation and rebuilds all five
   with the same Rust 1.96.0 compiler and locked dependencies: both Darwin
   targets locally, both Linux targets through digest-pinned Cross images,
   and Windows through a SHA-256-pinned cargo-xwin binary with fixed SDK/CRT
   versions. The rebuild source is a private, read-only archive materialized
   from the exact authorized Git object, never the operator checkout after the
   workflow wait. Every downloaded byte must match its independent rebuild.
   Canonical path remapping and `SOURCE_DATE_EPOCH` remove host-path/time
   variance. The Windows link also uses `/Brepro` and omits the otherwise
   random CodeView/PDB identifier.

   Only after those five byte comparisons pass does the wrapper read the
   successor key from 1Password Recovery over memory, pass it to one local
   Node process over stdin, check its pinned SPKI, sign, create checksums,
   upload the complete draft, and publish it immutable. The successor private
   key is never a GitHub secret or exposed to a hosted runner. The wrapper then
   verifies the exact 11-asset set, checksums, every Ed25519 signature,
   immutability, tag target, and binary provenance, then byte-compares the
   published set to the locally signed set. It refuses while the transitional
   repository signer or legacy `SEVRA_CLI_SIGNING_KEY_NEXT` environment secret
   still exists.

   GitHub-hosted runner labels identify maintained images, not immutable image
   digests. They therefore remain an availability/input source, not the
   successor signing boundary: a malicious or nondeterministic build causes a
   byte mismatch and leaves the tag unsigned and unpublished. Platform
   toolchain nondeterminism is also fail-closed and must be investigated; the
   release controller never substitutes a merely similar local binary.

   v0.2.8 is the one compatibility exception: run
   `scripts/release.sh v0.2.8`. It consumes the already-present original
   repository signer. The protected job signs and persists an immutable
   11-file Actions checkpoint with the maximum 90-day recovery retention,
   then attests every byte to the exact tag and
   SHA. The controller verifies that checkpoint's shape, checksums, Ed25519
   signatures, and provenance before deleting the signer. It still injects
   and checks the one-run authorization.

   If the controller stops after the tag is pushed, rerun the same command
   with `--resume`. Resume proceeds only when the remote tag still names the
   exact authorized SHA and one unique release workflow run names that tag and
   SHA. A completed immutable release is mutation-free but still performs the
   complete exact-source five-target reproduction, signature/checksum checks,
   and final byte comparisons. An interrupted v0.2.8 draft is discarded and
   rebuilt from its verified signed checkpoint; an interrupted successor draft
   is discarded and rebuilt from the complete locally reproduced, signed asset
   set.
5. `release.yml` independently rejects a tag whose commit is not already on
   `main`, runs preflight, and builds the 5 unsigned targets (darwin
   x86_64/aarch64, linux x86_64/aarch64 musl, windows x86_64 msvc; the
   Windows asset is `sevra-windows-x86_64.exe`). Successor builds receive
   keyless GitHub/Sigstore provenance and an exact run artifact, but no signing
   material or release-write permission. The local controller publishes only
   after independent reproduction. The released version must equal the
   Cargo.toml version.
6. Copy the verified asset digests into the platform repo's static trusted
   manifest. If `install.sh` or `install.ps1` changed, copy them to the
   platform repo's `install/sevra.sh` / `install/sevra.ps1` at the same time
   (the hub serves those snapshots at
   https://www.sevrahq.com/install/sevra.sh and .../install/sevra.ps1).
   Deploy the reviewed manifest and installer snapshots. Ordinary installs do
   not trust the checksum served beside the GitHub binary.
7. After that deployment is live, manually dispatch `smoke.yml` with the
   concrete version. It first proves production still routes `sevra/0.2.7`
   and older through the old-signed v0.2.8 bridge while v0.2.8 and newer see
   the true latest. It then installs from the release on macOS + Linux
   (install.sh) and Windows (install.ps1), proving both production installer
   scripts are byte-identical to this repository before it runs
   `sevra version` + the not-logged-in contract under
   `SEVRA_REQUIRE_SIGNATURE=1`. It intentionally does not
   auto-run at release publication: the independently controlled manifest is
   not approved yet, and the correct installer behavior at that point is to
   fail closed. Green post-manifest smoke = the release is live; installed
   CLIs pick it up on their next daily check (or `sevra update`).

## Key custody

The successor Ed25519 private key lives only in the separately controlled
1Password Recovery vault and local release-process memory. It is not a
repository, Actions environment, platform-runtime, filesystem, argv, or
shell-profile secret. The referenced 1Password field contains the **base64 of
the PKCS#8 PEM**. A raw PEM, base64-of-DER, or key with the wrong SPKI fails
before any signature is written.

The environment authorization exists only for the one-time v0.2.8 transition.
Its exact shape is `tag:sha:run_id.run_attempt:nonce`, where the SHA is 40
lowercase hex and the nonce is 64 lowercase hex. A different tag, commit, run,
or rerun cannot consume it. If that compatibility wrapper is interrupted
after injection, its exit trap deletes the environment authorization. If the
process was forcibly killed, first inspect that no v0.2.8 job is
waiting/running, then run the cleanup command before `--resume`:

```sh
scripts/release.sh --cleanup-ephemeral-secrets
```

Rotation is additive and order-sensitive:

1. Pin the new public key alongside the old one in `src/signing.rs`,
   `install.sh`, `install.ps1`, and `sevra.pub`.
2. Confirm the successor private key is recoverable from 1Password Recovery.
   Release v0.2.8 with `scripts/release.sh v0.2.8` while the original
   repository secret still exists. The wrapper deletes that original secret
   only after the durable signed checkpoint and all exact-tag/SHA attestations
   verify locally.
3. Deploy the v0.2.8 digest manifest and byte-identical installers. Run the
   protected smoke workflow, then prove an installed v0.2.7 CLI can
   self-update to v0.2.8. These are the authoritative checks that the original
   key still crosses every installer/updater path.
4. Delete the legacy `SEVRA_CLI_SIGNING_KEY_NEXT` environment secret:

   ```sh
   gh secret delete SEVRA_CLI_SIGNING_KEY_NEXT \
     --repo sevrahq/sevra --env release-signing
   ```

   Release v0.2.9 through the wrapper's local `op://` path, still pinning both
   public keys. The controller requires the successor SPKI for every release
   after v0.2.8; no GitHub runner receives the key. Deploy its reviewed digest
   manifest and byte-identical installers, then run the protected smoke. Prove
   both a fresh install and a v0.2.8 self-update to v0.2.9.
5. Only after v0.2.9 proves the successor signing path, remove the original
   public-key pin from the updater, both installers, and `sevra.pub`; release
   that successor-only trust set as v0.2.10 through the same local controller.
   Deploy and smoke it in the same order. Keep v0.2.8's manifest entries and
   the production User-Agent bridge: clients at v0.2.7 or older must still be
   offered old-signed v0.2.8 first, then they can safely advance to the true
   successor-signed latest on their next run.

Full notes: the platform repo's `infra/README.md`.

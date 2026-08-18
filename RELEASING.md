# Releasing sevra

The deploy model: release-versioned static binaries; installed CLIs
signed-self-update from GitHub Releases, discovering the latest version via
the hub's user-agent-aware `/api/hub/versions` endpoint. Installers use the
parallel `/api/hub/releases/sevra/latest` endpoint; post-manifest smoke requires
both routes to agree for every compatibility generation.

## Cut a release

1. Bump `version` in `Cargo.toml` (SemVer) + add a `CHANGELOG.md` entry.
2. `make check` (fmt + clippy -D warnings + tests) and `cargo deny check`.
3. Commit and push `main`. Wait for the exact commit's `ci.yml` run to pass.
   Do not create or push the tag by hand.
4. Run the guarded release wrapper from a clean `main` worktree:

   ```sh
   scripts/release.sh vX.Y.Z
   ```

   The wrapper refuses a dirty/non-main worktree, a non-canonical origin, a
   commit other than the exact `origin/main`, or a commit without a successful
   main-push `ci.yml` run. It also proves repository-level immutable Releases
   are enabled before creating the tag. It then waits for Actions to produce
   exactly five unsigned, tag/SHA-attested binaries. Before reading the
   successor key, the wrapper verifies every attestation and rebuilds all five
   with the same Rust 1.96.0 compiler and locked dependencies: arm64 Darwin
   natively, Intel Darwin with the Intel-host toolchain under Rosetta, both
   Linux targets through digest-pinned Cross images,
   and Windows through SHA-256-pinned cargo-xwin and LLVM tool archives with
   fixed SDK/CRT versions. The rebuild source is a private, read-only archive materialized
   from the exact authorized Git object, never the operator checkout after the
   workflow wait. Its scratch tree lives under the repository's private `.git`
   directory so Colima can mount it into the Linux builders without exposing
   it to the worktree. Every downloaded byte must match its independent rebuild.
   Canonical path remapping and `SOURCE_DATE_EPOCH` remove host-path/time
   variance. The x86_64 Linux Rust sysroot is also normalized to `/rust`; Rust
   source locations from `core` and `std` otherwise embed the controller's
   toolchain path and shift the static read-only data layout. Matching the
   Intel execution architecture matters because the arm64 and x86_64 slices
   of Apple's `ld64` can produce different valid Intel layouts despite
   reporting the same release version. Darwin binaries replace the linker's
   nondeterministic `LC_UUID`
   with a content-derived RFC 4122 UUID, then receive a stable ad-hoc signature
   under the fixed `com.sevra.cli` identifier; both the hosted build and local
   controller apply the same reviewed normalizer. The Windows link also uses
   `/Brepro` and omits the otherwise random CodeView/PDB identifier.

   The reviewed arm64 controller therefore needs Rosetta 2 plus the non-host
   toolchain installed with:

   ```sh
   rustup toolchain install 1.96.0-x86_64-apple-darwin \
     --profile minimal --force-non-host
   ```

   The wrapper verifies both the exact Intel compiler revision and successful
   x86_64 execution before it creates the version tag.

   For releases after v0.2.10, only after those five byte comparisons pass does
   the wrapper read offline signer B from its dedicated local macOS Keychain
   cache, pass it to one local Node process over stdin, check its pinned SPKI, sign, create
   checksums, upload the complete draft, and publish it immutable. Signer B is
   never a GitHub secret or exposed to a hosted runner. The wrapper then
   verifies the exact 11-asset set, checksums, every Ed25519 signature,
   immutability, tag target, and binary provenance, then byte-compares the
   published set to the locally signed set. It refuses while either retired
   compatibility signer remains in GitHub.

   GitHub-hosted runner labels identify maintained images, not immutable image
   digests. They therefore remain an availability/input source, not the
   successor signing boundary: a malicious or nondeterministic build causes a
   byte mismatch and leaves the tag unsigned and unpublished. Platform
   toolchain nondeterminism is also fail-closed and must be investigated; the
   release controller never substitutes a merely similar local binary.

   v0.2.9 and v0.2.10 were the two completed compatibility exceptions. v0.2.9
   consumed the original repository signer and introduced compatibility signer
   A. v0.2.10 consumed A from the protected environment and introduced offline
   signer B. In both cases the protected job persisted an immutable 11-file
   Actions checkpoint with the maximum 90-day recovery retention and attested
   every byte to the exact tag and SHA. The controller verified the
   checkpoint's shape, checksums, Ed25519 signatures, and provenance before
   deleting the signer. Both compatibility signers are now absent from GitHub.

   If the controller stops after the tag is pushed, rerun the same command
   with `--resume`. Resume proceeds only when the remote tag still names the
   exact authorized SHA and one unique release workflow run names that tag and
   SHA. A completed immutable release is mutation-free but still performs the
   complete exact-source five-target reproduction, signature/checksum checks,
   and final byte comparisons. An interrupted v0.2.9 draft is discarded and
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
   concrete version. It first proves both production release endpoints route
   `sevra/0.2.7` and older through the old-signed v0.2.9 bridge while v0.2.9
   and newer see the true latest, and that the two endpoints agree. It then
   installs from the release on macOS + Linux
   (install.sh) and Windows (install.ps1), proving both production installer
   scripts are byte-identical to this repository before it runs
   `sevra version` + the not-logged-in contract under
   `SEVRA_REQUIRE_SIGNATURE=1`. It intentionally does not
   auto-run at release publication: the independently controlled manifest is
   not approved yet, and the correct installer behavior at that point is to
   fail closed. Green post-manifest smoke = the release is live; installed
   CLIs pick it up on their next daily check (or `sevra update`).

## Key custody

Offline signer B's working copy lives only in a non-synchronizing,
this-device-only macOS Keychain item and local release-process memory. An
independent recovery copy may exist outside the workstation, but the release
controller never contacts a password manager. It is not a repository, Actions
environment, platform-runtime, filesystem, argv, or shell-profile secret. The
signing helper accepts a direct PKCS#8 PEM or its
canonical base64 form, canonical base64 PKCS#8 DER, or a canonical base64 raw
32-byte Ed25519 seed. Any malformed, non-canonical, or wrong-SPKI key fails
before any signature is written.

Seed or rotate the working cache only through stdin, then verify presence
without reading the value:

```sh
<independent-secret-read-command> | node scripts/release-keychain.mjs put
node scripts/release-keychain.mjs has
```

The cache helper never prints on `put` or `has`. `get` exists only for the
release controller's final stdin pipe. No release command attempts to populate
the cache or falls back to another provider.

The environment authorization existed only for the v0.2.9 and v0.2.10
compatibility transitions.
Its exact shape is `tag:sha:run_id.run_attempt:nonce`, where the SHA is 40
lowercase hex and the nonce is 64 lowercase hex. A different tag, commit, run,
or rerun cannot consume it. If that compatibility wrapper is interrupted
after injection, its exit trap deletes the environment authorization. If the
process was forcibly killed, first inspect that no v0.2.9 job is
waiting/running, then run the cleanup command before `--resume`:

```sh
scripts/release.sh --cleanup-ephemeral-secrets
```

The completed rotation was additive and order-sensitive:

1. Pin the new public key alongside the old one in `src/signing.rs`,
   `install.sh`, `install.ps1`, and `sevra.pub`.
2. Confirm signer A is recoverable before exposing its public key. Release
   v0.2.9 with `scripts/release.sh v0.2.9` while the original
   repository secret still exists. The wrapper deletes that original secret
   only after the durable signed checkpoint and all exact-tag/SHA attestations
   verify locally.
3. Deploy the v0.2.9 digest manifest and byte-identical installers. Run the
   protected smoke workflow, then prove an installed v0.2.7 CLI can
   self-update to v0.2.9. These are the authoritative checks that the original
   key still crosses every installer/updater path.
4. Release v0.2.10 through the protected compatibility path with signer A,
   while pinning offline signer B alongside both earlier public keys. After the
   immutable checkpoint, tag/SHA provenance, release, fresh install, and
   historical update chain verify, delete A from GitHub.
5. Every release after v0.2.10 uses signer B through the dedicated local
   Keychain cache. The controller fails if the cache is missing and never
   invokes `op` or opens a password-manager prompt.
   Keep all three public pins: retired private keys are gone, and their public
   pins preserve explicit installs and historical update verification. Keep
   v0.2.9's manifest entry and the production User-Agent bridge: clients at
   v0.2.7 or older must be offered old-signed v0.2.9 first, then they can
   advance to v0.2.10 and later releases.

Full notes: the platform repo's `infra/README.md`.

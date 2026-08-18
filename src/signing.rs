//! Ed25519 verification for the self-update path. The pinned publisher key(s)
//! live here (an array, so a rotation ships additively: a build pins both the
//! new and old key, the private key swaps a deploy later). The same key signs
//! release assets in CI; the public key is also served at
//! www.sevrahq.com/install/sevra.pub for out-of-band checks.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

/// SPKI PEMs of the accepted publisher keys.
///
/// v0.2.9 introduced compatibility signer A. v0.2.10 is the final protected
/// bridge: signer A signs a build that additionally pins offline signer B.
/// Keeping all three public keys is harmless and preserves direct upgrades
/// from every prior signed release while private-key custody moves offline.
const PUBKEYS_PEM: &[&str] = &[
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA+v5mafEPcIwKAU/DO/z8MM/cT9ndgE1saSUfvcrzLKA=\n-----END PUBLIC KEY-----",
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAasunxAjcJp8W30eF0ndPlLXqwSjZ/u5raivn3QmaKcc=\n-----END PUBLIC KEY-----",
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAzOIUB6eaOlwx1PqHCUBDF2+F3FLa5VK1u6QoFOVyXME=\n-----END PUBLIC KEY-----",
];

/// Extract the raw 32-byte Ed25519 key from an SPKI PEM. Ed25519 SPKI is a
/// fixed 12-byte prefix + the 32-byte key, so the last 32 bytes of the decoded
/// body are the key.
fn spki_to_raw(pem: &str) -> Option<[u8; 32]> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>();
    let der = STANDARD.decode(b64.trim()).ok()?;
    if der.len() < 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&der[der.len() - 32..]);
    Some(key)
}

/// True if `sig_b64` (standard base64 of 64 raw bytes) is a valid signature of
/// `message` under ANY pinned key.
pub fn verify(message: &[u8], sig_b64: &str) -> bool {
    let sig_bytes = match STANDARD.decode(sig_b64.trim()) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    for pem in PUBKEYS_PEM {
        if let Some(raw) = spki_to_raw(pem) {
            if let Ok(vk) = VerifyingKey::from_bytes(&raw) {
                if vk.verify_strict(message, &signature).is_ok() {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(!verify(b"hello", "not-base64!!"));
        assert!(!verify(b"hello", &STANDARD.encode([0u8; 64])));
    }

    #[test]
    fn all_pinned_keys_parse_and_are_distinct() {
        assert_eq!(PUBKEYS_PEM.len(), 3, "bridge release must trust three keys");
        let keys: Vec<_> = PUBKEYS_PEM
            .iter()
            .map(|pem| {
                let raw = spki_to_raw(pem).expect("pinned key parses");
                VerifyingKey::from_bytes(&raw).expect("pinned Ed25519 key is valid")
            })
            .collect();
        for left in 0..keys.len() {
            for right in (left + 1)..keys.len() {
                assert_ne!(keys[left].as_bytes(), keys[right].as_bytes());
            }
        }
    }

    #[test]
    fn release_workflow_isolates_successor_signing_from_actions() {
        // Git checkouts on Windows may materialize CRLF. Security assertions
        // inspect the workflow's tokens, not its platform line endings.
        let workflow = include_str!("../.github/workflows/release.yml").replace("\r\n", "\n");
        assert!(workflow.contains(
            "if: needs.version.outputs.version == '0.2.9' || needs.version.outputs.version == '0.2.10'"
        ));
        assert!(workflow.contains(
            "if: needs.version.outputs.version != '0.2.9' && needs.version.outputs.version != '0.2.10'"
        ));
        assert!(workflow
            .contains("SEVRA_CLI_SIGNING_KEY_BRIDGE: ${{ secrets.SEVRA_CLI_SIGNING_KEY_NEXT }}"));
        assert!(workflow.contains(
            "SEVRA_EXPECTED_SIGNER_SPKI='MCowBQYDK2VwAyEAasunxAjcJp8W30eF0ndPlLXqwSjZ/u5raivn3QmaKcc='"
        ));
        assert!(workflow.contains("node tests/release-sign.mjs"));
        assert!(workflow.contains("node tests/normalize-macho.mjs"));
        assert!(workflow.contains("node scripts/normalize-macho.mjs \"$binary\""));
        assert!(workflow.contains("/usr/bin/codesign --force --sign - \\"));
        assert!(workflow.contains("--identifier com.sevra.cli --timestamp=none \"$binary\""));
        assert!(workflow.contains("/usr/bin/codesign --verify --strict \"$binary\""));
        assert!(workflow.contains("actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd"));
        assert!(workflow.contains("node ../scripts/release-sign.mjs"));
        assert!(workflow.contains("unset SEVRA_CLI_SIGNING_KEY SEVRA_EXPECTED_SIGNER_SPKI"));
        assert!(workflow.contains("scripts/install-pinned-llvm.sh"));
        assert!(workflow.contains("$RUNNER_TEMP/llvm-mingw/bin"));
        assert!(workflow.contains("name: successor-unsigned"));
        assert!(!workflow.contains("SEVRA_SUCCESSOR_SIGNER_SPKI"));
        assert!(workflow
            .contains("SEVRA_RELEASE_AUTHORIZATION: ${{ secrets.SEVRA_RELEASE_AUTHORIZATION }}"));
        assert!(workflow.contains(
            "fields[2] !== expectedRequest ||\n              !/^[0-9a-f]{64}$/.test(fields[3])"
        ));
        assert!(workflow.contains("fields[1] !== process.env.GITHUB_SHA"));
        assert!(workflow.contains("fields[0] !== process.env.GITHUB_REF_NAME"));
        assert!(workflow.contains("release artifact set does not contain exactly five files"));
        assert!(workflow.contains("retention-days: 90"));
        assert!(!workflow.contains("retention-days: 7"));
        assert!(workflow.contains("cargo-xwin-v0.23.0.universal2-apple-darwin.tar.gz"));
        assert!(
            workflow.contains("d78a88f43247a6298d8888dc4c44a8af92801fdf4e5374cc5a359a1e53770993")
        );
        assert!(workflow
            .contains("RUSTFLAGS=\"$RUSTFLAGS -C link-arg=/Brepro -C link-arg=/debug:none\""));
        assert!(
            workflow.matches("subject-path: 'dist/*'").count() == 6,
            "both compatibility and successor provenance retries must cover their exact sets"
        );
    }

    #[test]
    fn windows_smoke_compares_production_to_the_canonical_git_blob() {
        let workflow = include_str!("../.github/workflows/smoke.yml").replace("\r\n", "\n");
        assert!(workflow.contains("git rev-parse 'HEAD:install.ps1'"));
        assert!(workflow.contains("git hash-object --no-filters $prodInstaller"));
        assert!(workflow.contains("api/hub/releases/sevra/latest?smoke="));
        assert!(workflow.contains("api/hub/versions?smoke="));
        assert!(workflow.contains("endpoints disagree"));
        assert!(!workflow
            .contains("(Get-FileHash install.ps1).Hash -ne (Get-FileHash $prodInstaller).Hash"));
    }

    #[test]
    fn release_wrapper_keeps_successor_signer_local_and_reproduces_every_binary() {
        let wrapper = include_str!("../scripts/release.sh");
        for required in [
            "git status --porcelain=v1",
            "HEAD is not the exact commit currently at origin/main",
            "--workflow ci.yml --commit \"$release_sha\"",
            "release_git_dir=\"$(git rev-parse --absolute-git-dir)\"",
            "mktemp -d \"$release_git_dir/$scratch_name.XXXXXX\"",
            "repos/$repo/immutable-releases",
            "immutable GitHub Releases must be enabled before tagging",
            "openssl rand -hex 32",
            "$tag:$release_sha:$release_run_id.$attempt:$auth_nonce",
            "node \"$source_dir/scripts/release-keychain.mjs\" get",
            "scripts/release-sign.mjs",
            "cleanup_ephemeral_secrets",
            "gh secret delete SEVRA_CLI_SIGNING_KEY --repo \"$repo\"",
            "--name successor-unsigned",
            "RUSTUP_TOOLCHAIN=1.96.0 cross build",
            "cargo +1.96.0 build --release --locked --target aarch64-apple-darwin",
            "rustup which --toolchain 1.96.0-x86_64-apple-darwin rustc",
            "rustup which --toolchain 1.96.0-x86_64-apple-darwin cargo",
            "rustup which --toolchain 1.96.0-x86_64-unknown-linux-gnu rustc",
            "arch -x86_64 /usr/bin/env",
            "\"$x86_cargo\" build --release --locked --target x86_64-apple-darwin",
            "node \"$source_dir/scripts/normalize-macho.mjs\" \"$darwin_binary\"",
            "--identifier com.sevra.cli --timestamp=none \"$darwin_binary\"",
            "--verify --strict \"$darwin_binary\"",
            "\"$xwin_dir/cargo-xwin\" xwin build",
            "\"$source_dir/scripts/install-pinned-llvm.sh\" \"$llvm_dir\"",
            "PATH=\"$llvm_dir/bin:$PATH\"",
            "git archive --format=tar --output=\"$source_archive\" \"$release_sha\"",
            "chmod -R a-w \"$source_dir\"",
            "source_canonical=\"$(CDPATH='' cd -- \"$source_dir\" && pwd -P)\"",
            "cd \"$source_dir\"",
            "cmp \"$windows_dir/x86_64-pc-windows-msvc/release/sevra.exe\"",
            "RUSTFLAGS=\"--remap-path-prefix=$source_canonical=/workspace",
            "--remap-path-prefix=$linux_sysroot=/rust",
            "export RUSTFLAGS SOURCE_DATE_EPOCH",
            "RUSTFLAGS=\"$RUSTFLAGS -C link-arg=/Brepro -C link-arg=/debug:none\"",
            "\"MCowBQYDK2VwAyEAzOIUB6eaOlwx1PqHCUBDF2+F3FLa5VK1u6QoFOVyXME=\"",
            "no byte is written to disk or argv",
            "(.immutable == true)",
            "gh attestation verify \"$asset\"",
            "--source-digest \"$release_sha\"",
            "verify_signed_release_set \"$verify_dir\" \"$final_signer_spki\"",
            "cmp \"$checkpoint_dir/$asset\" \"$verify_dir/$asset\"",
            "cmp \"$release_dir/$asset\" \"$verify_dir/$asset\"",
            "cmp \"$unsigned_dir/$asset\" \"$verify_dir/$asset\"",
        ] {
            assert!(
                wrapper.contains(required),
                "release wrapper lost security gate: {required}"
            );
        }
        assert!(
            !wrapper.contains("gh secret set SEVRA_CLI_SIGNING_KEY"),
            "the successor private key must never be uploaded to Actions"
        );
        assert!(
            !wrapper.contains("op read") && !wrapper.contains("signing-key-ref"),
            "the release controller must never invoke a password manager"
        );
        assert!(
            !wrapper.contains("${TMPDIR:-/tmp}/sevra-release"),
            "Cross-visible release scratch space must stay beneath the repository"
        );
        assert_eq!(
            wrapper.matches("\n  cmp \"$").count(),
            5,
            "all five attested binaries must reproduce before local signing"
        );
    }

    #[test]
    fn release_signer_uses_a_private_local_keychain_cache() {
        let bridge = include_str!("../scripts/release-keychain.mjs");
        let helper = include_str!("../scripts/macos-keychain-signing-key.swift");
        assert!(bridge.contains("com.sevra.release-signing"));
        assert!(bridge.contains("Library"));
        assert!(bridge.contains("Caches"));
        assert!(bridge.contains("chmodSync(cacheDirectory, 0o700)"));
        assert!(bridge.contains("statSync(binaryPath).mode & 0o077"));
        assert!(helper.contains("com.sevra.release-signing"));
        assert!(helper.contains("SEVRA_CLI_SIGNING_KEY"));
        assert!(helper.contains("kSecAttrSynchronizable as String: kCFBooleanFalse"));
        assert!(helper.contains("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"));
        assert!(!bridge.contains("1Password"));
        assert!(!helper.contains("1Password"));
    }

    #[test]
    fn windows_llvm_archiver_is_digest_pinned_and_https_only() {
        let installer = include_str!("../scripts/install-pinned-llvm.sh");
        assert!(installer.contains(
            "https://github.com/mstorsjo/llvm-mingw/releases/download/20260616/llvm-mingw-20260616-ucrt-macos-universal.tar.xz"
        ));
        assert!(
            installer.contains("2cab02a2e964bd4aae981150a45985d07c657cfa8d244959eb9e2dcc5eedd7b1")
        );
        assert!(installer.contains("--proto '=https'"));
        assert!(installer.contains("--proto-redir '=https'"));
        assert!(installer.contains("LLVM version 22.1.8"));
    }

    #[test]
    fn linux_release_toolchain_images_are_digest_pinned() {
        let cross = include_str!("../Cross.toml");
        for target in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"] {
            assert!(
                cross.contains(&format!("ghcr.io/cross-rs/{target}:0.2.5@sha256:")),
                "{target} must use the reviewed cross image by immutable digest"
            );
        }
        assert_eq!(
            cross.matches("@sha256:").count(),
            2,
            "the file should contain only the two reviewed release images"
        );
    }

    #[test]
    fn successor_key_signature_is_accepted() {
        const MESSAGE: &[u8] = b"sevra release signing trust-set regression v0.2.8";
        // Fixed vector generated once with the successor private key. Only the
        // public signature is committed; private key material never enters the
        // source tree.
        const SUCCESSOR_SIGNATURE: &str =
            "FCNsagdkJcD/ZDs5k0BhL8t23AKGLwO5Zrq0sv1BZr4HN8vHXIXWgrfm6GkV+mnUswY3utnyiCNeCavngLbBDg==";
        assert!(verify(MESSAGE, SUCCESSOR_SIGNATURE));
    }

    #[test]
    fn unrelated_key_signature_is_rejected() {
        const MESSAGE: &[u8] = b"sevra release signing trust-set regression v0.2.8";
        const UNRELATED_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEACNrKmNMKPCc4hjFMc7ezA9Xel4l3fx0/YzMF3N9vsW8=\n-----END PUBLIC KEY-----";
        const UNRELATED_SIGNATURE: &str =
            "OS0fG3e4xQd6KTgUQallkV2RgzZQrB+b/rKAetJi9NWFe6se2U9LMu6GQfbDClgR3KwI36e6X8nWJATMoL2zCg==";

        let raw = spki_to_raw(UNRELATED_PEM).expect("unrelated test key parses");
        let key = VerifyingKey::from_bytes(&raw).expect("unrelated test key is valid");
        let sig_bytes = STANDARD
            .decode(UNRELATED_SIGNATURE)
            .expect("unrelated signature is base64");
        let signature = Signature::from_slice(&sig_bytes).expect("unrelated signature is valid");
        assert!(key.verify_strict(MESSAGE, &signature).is_ok());
        assert!(!verify(MESSAGE, UNRELATED_SIGNATURE));
    }
}

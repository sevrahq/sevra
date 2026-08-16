#!/usr/bin/env node

import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";

const RAW_ED25519_PKCS8_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);
const EXPECTED_ASSETS = [
  "sevra-darwin-aarch64",
  "sevra-darwin-x86_64",
  "sevra-linux-aarch64-musl",
  "sevra-linux-x86_64-musl",
  "sevra-windows-x86_64.exe",
].sort();

export function parseReleasePrivateKey(raw) {
  const value = raw.trim().replace(/\r\n/g, "\n");
  if (
    value.startsWith("-----BEGIN PRIVATE KEY-----\n") &&
    value.endsWith("\n-----END PRIVATE KEY-----")
  ) {
    return createPrivateKey(value);
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error("release signing key has an unsupported encoding");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    decoded.fill(0);
    throw new Error("release signing key is not canonical base64");
  }
  if (decoded.length === 32) {
    // RFC 8410 PKCS#8 wrapper for a raw 32-byte Ed25519 seed.
    const wrapped = Buffer.concat([RAW_ED25519_PKCS8_PREFIX, decoded]);
    decoded.fill(0);
    try {
      return createPrivateKey({ key: wrapped, format: "der", type: "pkcs8" });
    } finally {
      wrapped.fill(0);
    }
  }
  try {
    if (decoded.subarray(0, 27).toString("ascii") === "-----BEGIN PRIVATE KEY-----") {
      return createPrivateKey(decoded);
    }
    return createPrivateKey({ key: decoded, format: "der", type: "pkcs8" });
  } finally {
    decoded.fill(0);
  }
}

export function releaseSignerSpki(key) {
  return createPublicKey(key)
    .export({ type: "spki", format: "der" })
    .toString("base64");
}

export function signReleaseAssets({ keyText, expectedSpki, assets }) {
  const names = assets.map((asset) => basename(asset)).sort();
  if (JSON.stringify(names) !== JSON.stringify(EXPECTED_ASSETS)) {
    throw new Error("release signer received an unexpected asset set");
  }
  for (const asset of assets) {
    const metadata = lstatSync(asset);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`release asset is not a regular file: ${basename(asset)}`);
    }
  }

  const key = parseReleasePrivateKey(keyText);
  const publicKey = createPublicKey(key);
  if (releaseSignerSpki(key) !== expectedSpki) {
    throw new Error("compatibility release is configured with the wrong release signer");
  }
  for (const asset of assets) {
    const bytes = readFileSync(asset);
    const signature = sign(null, bytes, key);
    if (!verify(null, bytes, publicKey, signature)) {
      throw new Error("release signature self-check failed");
    }
    writeFileSync(`${asset}.sig`, `${signature.toString("base64")}\n`, {
      mode: 0o600,
      flag: "wx",
    });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [expectedSpki, ...assets] = process.argv.slice(2);
  if (!expectedSpki) throw new Error("expected signer SPKI is required");
  const keyBytes = readFileSync(0);
  if (keyBytes.length === 0 || keyBytes.length > 64 * 1024) {
    keyBytes.fill(0);
    throw new Error("release signing key input has an invalid size");
  }
  const keyText = keyBytes.toString("utf8");
  keyBytes.fill(0);
  try {
    signReleaseAssets({ keyText, expectedSpki, assets });
  } finally {
    // Strings cannot be zeroed in JavaScript; keep the value in this one
    // short-lived process and never print, export, or persist it.
  }
}

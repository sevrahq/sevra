#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { generateKeyPairSync, verify } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  parseReleasePrivateKey,
  releaseSignerSpki,
  signReleaseAssets,
} from "../scripts/release-sign.mjs";

function check(condition, message) {
  if (!condition) throw new Error(message);
}

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
const pem = privateKey.export({ type: "pkcs8", format: "pem" });
const expectedSpki = publicKey
  .export({ type: "spki", format: "der" })
  .toString("base64");
const rawSeed = pkcs8.subarray(pkcs8.length - 32).toString("base64");
const encodedPem = Buffer.from(pem).toString("base64");
for (const encoded of [pkcs8.toString("base64"), pem, encodedPem, rawSeed]) {
  const parsed = parseReleasePrivateKey(encoded);
  check(releaseSignerSpki(parsed) === expectedSpki, "accepted key encoding changed identity");
}

const root = mkdtempSync(join(tmpdir(), "sevra-release-sign-"));
const names = [
  "sevra-darwin-aarch64",
  "sevra-darwin-x86_64",
  "sevra-linux-aarch64-musl",
  "sevra-linux-x86_64-musl",
  "sevra-windows-x86_64.exe",
];
const assets = names.map((name) => join(root, name));
try {
  for (const [index, asset] of assets.entries()) {
    writeFileSync(asset, `release fixture ${index}\n`, { mode: 0o600 });
  }
  const unrelated = generateKeyPairSync("ed25519").publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");
  let refused = false;
  try {
    signReleaseAssets({ keyText: rawSeed, expectedSpki: unrelated, assets });
  } catch {
    refused = true;
  }
  check(refused, "signer accepted the wrong public-key identity");
  check(assets.every((asset) => !existsSync(`${asset}.sig`)), "identity refusal wrote a signature");

  signReleaseAssets({
    keyText: rawSeed,
    expectedSpki,
    assets: [...assets].reverse(),
  });
  for (const asset of assets) {
    const encoded = readFileSync(`${asset}.sig`, "utf8").trim();
    const signature = Buffer.from(encoded, "base64");
    check(signature.length === 64 && signature.toString("base64") === encoded, "signature is not canonical base64");
    check(verify(null, readFileSync(asset), publicKey, signature), "signature did not verify");
    if (process.platform !== "win32") {
      check((statSync(`${asset}.sig`).mode & 0o777) === 0o600, "signature mode is not 0600");
    }
    unlinkSync(`${asset}.sig`);
  }

  const cli = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("../scripts/release-sign.mjs", import.meta.url)), expectedSpki, ...assets],
    { input: rawSeed, encoding: "utf8" },
  );
  check(cli.status === 0, `signer CLI failed: ${cli.stderr}`);
  check(assets.every((asset) => existsSync(`${asset}.sig`)), "signer CLI did not write every signature");

  refused = false;
  try {
    signReleaseAssets({ keyText: rawSeed, expectedSpki, assets: assets.slice(1) });
  } catch {
    refused = true;
  }
  check(refused, "signer accepted a partial asset set");
} finally {
  pkcs8.fill(0);
  rmSync(root, { recursive: true, force: true });
}

console.log("release signer encodings, identity, exact-set, CLI, and signature tests passed");

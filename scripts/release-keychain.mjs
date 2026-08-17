#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const command = process.argv[2];
if (!new Set(["put", "get", "has", "delete"]).has(command)) {
  throw new Error("usage: release-keychain.mjs (put|get|has|delete)");
}
if (process.platform !== "darwin") {
  throw new Error("the release signing cache requires macOS Keychain");
}

const sourcePath = join(
  import.meta.dirname,
  "macos-keychain-signing-key.swift"
);
const source = readFileSync(sourcePath);
const digest = createHash("sha256").update(source).digest("hex").slice(0, 16);
const cacheDirectory = join(
  homedir(),
  "Library",
  "Caches",
  "com.sevra.release-signing"
);
const binaryPath = join(cacheDirectory, `release-keychain-${digest}`);
mkdirSync(cacheDirectory, { recursive: true, mode: 0o700 });
chmodSync(cacheDirectory, 0o700);

if (!existsSync(binaryPath)) {
  const build = spawnSync(
    "/usr/bin/xcrun",
    ["swiftc", "-O", "-framework", "Security", sourcePath, "-o", binaryPath],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
  );
  if (build.status !== 0) {
    throw new Error(
      `could not compile release Keychain helper: ${build.stderr.trim() || "unknown compiler error"}`
    );
  }
  chmodSync(binaryPath, 0o700);
}
if ((statSync(binaryPath).mode & 0o077) !== 0) {
  throw new Error("release Keychain helper is accessible outside the local user");
}

const result = spawnSync(binaryPath, [command], {
  encoding: "buffer",
  maxBuffer: 1024 * 1024,
  stdio: ["inherit", "inherit", "inherit"],
});
if (result.error) throw result.error;
process.exit(result.status ?? 1);

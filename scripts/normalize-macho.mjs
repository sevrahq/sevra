#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MH_MAGIC_64 = 0xfeedfacf;
const MH_EXECUTE = 0x2;
const LC_UUID = 0x1b;
const LC_CODE_SIGNATURE = 0x1d;
const MACH_HEADER_64_SIZE = 32;

function fail(message) {
  throw new Error(`normalize-macho: ${message}`);
}

function locateMutableMetadata(bytes) {
  if (!Buffer.isBuffer(bytes)) fail("input must be a Buffer");
  if (bytes.length < MACH_HEADER_64_SIZE) fail("file is shorter than a Mach-O 64 header");
  if (bytes.readUInt32LE(0) !== MH_MAGIC_64) fail("file is not a little-endian Mach-O 64 binary");
  if (bytes.readUInt32LE(12) !== MH_EXECUTE) fail("Mach-O file is not an executable");

  const commandCount = bytes.readUInt32LE(16);
  const commandBytes = bytes.readUInt32LE(20);
  const commandEnd = MACH_HEADER_64_SIZE + commandBytes;
  if (commandEnd > bytes.length) fail("load-command table exceeds the file");

  let cursor = MACH_HEADER_64_SIZE;
  let uuidOffset = null;
  let signatureRange = null;
  for (let index = 0; index < commandCount; index += 1) {
    if (cursor + 8 > commandEnd) fail("truncated load command");
    const command = bytes.readUInt32LE(cursor);
    const commandSize = bytes.readUInt32LE(cursor + 4);
    if (commandSize < 8 || commandSize % 8 !== 0 || cursor + commandSize > commandEnd) {
      fail("invalid load-command size");
    }
    if (command === LC_UUID) {
      if (commandSize !== 24) fail("LC_UUID has an unexpected size");
      if (uuidOffset !== null) fail("multiple LC_UUID commands are not supported");
      uuidOffset = cursor + 8;
    } else if (command === LC_CODE_SIGNATURE) {
      if (commandSize !== 16) fail("LC_CODE_SIGNATURE has an unexpected size");
      if (signatureRange !== null) fail("multiple LC_CODE_SIGNATURE commands are not supported");
      const dataOffset = bytes.readUInt32LE(cursor + 8);
      const dataSize = bytes.readUInt32LE(cursor + 12);
      const dataEnd = dataOffset + dataSize;
      if (dataOffset < commandEnd || dataEnd < dataOffset || dataEnd > bytes.length) {
        fail("code-signature range exceeds the file");
      }
      signatureRange = [dataOffset, dataEnd];
    }
    cursor += commandSize;
  }
  if (cursor !== commandEnd) fail("load-command table size does not match its commands");
  if (uuidOffset === null) fail("Mach-O executable has no LC_UUID command");
  return { uuidOffset, signatureRange };
}

export function normalizeMachOUuid(bytes) {
  const { uuidOffset, signatureRange } = locateMutableMetadata(bytes);
  const canonical = Buffer.from(bytes);
  canonical.fill(0, uuidOffset, uuidOffset + 16);
  if (signatureRange !== null) canonical.fill(0, signatureRange[0], signatureRange[1]);

  const uuid = createHash("sha256")
    .update("sevra-macho-uuid-v1\0", "utf8")
    .update(canonical)
    .digest()
    .subarray(0, 16);
  // Keep the identifier a conventional RFC 4122 UUID while deriving every
  // payload bit deterministically from the executable outside the linker's
  // random UUID and consequent ad-hoc signature.
  uuid[6] = (uuid[6] & 0x0f) | 0x40;
  uuid[8] = (uuid[8] & 0x3f) | 0x80;

  const normalized = Buffer.from(bytes);
  uuid.copy(normalized, uuidOffset);
  return { bytes: normalized, uuid: Buffer.from(uuid), uuidOffset, signatureRange };
}

export function formatUuid(uuid) {
  if (!Buffer.isBuffer(uuid) || uuid.length !== 16) fail("UUID must contain exactly 16 bytes");
  const hex = uuid.toString("hex").toUpperCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function main() {
  if (process.argv.length !== 3) fail("usage: normalize-macho.mjs <Mach-O executable>");
  const path = process.argv[2];
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) fail("path must name a regular non-symlink file");
  const result = normalizeMachOUuid(readFileSync(path));
  writeFileSync(path, result.bytes);
  process.stdout.write(`normalize-macho: uuid=${formatUuid(result.uuid)} file=${path}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

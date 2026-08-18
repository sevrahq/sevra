#!/usr/bin/env node

import { strict as assert } from "node:assert";
import { normalizeMachOUuid } from "../scripts/normalize-macho.mjs";

const MH_MAGIC_64 = 0xfeedfacf;
const MH_EXECUTE = 0x2;
const LC_UUID = 0x1b;
const LC_CODE_SIGNATURE = 0x1d;

function fixture({ uuidFill = 0x11, signatureFill = 0x22, includeUuid = true } = {}) {
  const commandBytes = (includeUuid ? 24 : 0) + 16;
  const bytes = Buffer.alloc(256, 0);
  bytes.writeUInt32LE(MH_MAGIC_64, 0);
  bytes.writeUInt32LE(0x0100000c, 4);
  bytes.writeUInt32LE(0, 8);
  bytes.writeUInt32LE(MH_EXECUTE, 12);
  bytes.writeUInt32LE(includeUuid ? 2 : 1, 16);
  bytes.writeUInt32LE(commandBytes, 20);
  bytes.fill(0x5a, 32 + commandBytes, 128);

  let cursor = 32;
  if (includeUuid) {
    bytes.writeUInt32LE(LC_UUID, cursor);
    bytes.writeUInt32LE(24, cursor + 4);
    bytes.fill(uuidFill, cursor + 8, cursor + 24);
    cursor += 24;
  }
  bytes.writeUInt32LE(LC_CODE_SIGNATURE, cursor);
  bytes.writeUInt32LE(16, cursor + 4);
  bytes.writeUInt32LE(128, cursor + 8);
  bytes.writeUInt32LE(64, cursor + 12);
  bytes.fill(signatureFill, 128, 192);
  return bytes;
}

const first = fixture({ uuidFill: 0x11, signatureFill: 0x22 });
const second = fixture({ uuidFill: 0xaa, signatureFill: 0xbb });
const firstResult = normalizeMachOUuid(first);
const secondResult = normalizeMachOUuid(second);
assert.deepEqual(firstResult.uuid, secondResult.uuid, "UUID depends on linker-random metadata");
assert.equal(firstResult.uuid[6] >> 4, 4, "UUID is not RFC 4122 version 4");
assert.equal(firstResult.uuid[8] >> 6, 2, "UUID does not use the RFC 4122 variant");
assert.deepEqual(
  firstResult.bytes.subarray(128, 192),
  first.subarray(128, 192),
  "normalizer rewrote the existing code signature before codesign",
);
assert.deepEqual(
  firstResult.bytes.subarray(0, firstResult.uuidOffset),
  first.subarray(0, firstResult.uuidOffset),
  "normalizer changed bytes before LC_UUID",
);

const changedPayload = fixture({ uuidFill: 0x11, signatureFill: 0x22 });
changedPayload[100] ^= 0xff;
assert.notDeepEqual(
  normalizeMachOUuid(changedPayload).uuid,
  firstResult.uuid,
  "UUID did not bind executable content",
);

assert.throws(() => normalizeMachOUuid(Buffer.alloc(8)), /shorter than a Mach-O 64 header/);
assert.throws(() => normalizeMachOUuid(fixture({ includeUuid: false })), /no LC_UUID/);
const invalidSignature = fixture();
invalidSignature.writeUInt32LE(250, 32 + 24 + 8);
assert.throws(() => normalizeMachOUuid(invalidSignature), /code-signature range exceeds/);

console.log("Mach-O deterministic UUID normalization tests passed");

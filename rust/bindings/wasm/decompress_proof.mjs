// Prove the wasm SDK (ruzstd decoder, compression feature OFF) reconstructs a
// COMPRESSED transfer produced by the native/desktop side.
//
// Run: node rust/bindings/wasm/decompress_proof.mjs
// Prereq: spit_frames wrote /private/tmp/desktop_transfer.json, and the
// pkg/ was built with `wasm-pack build --target nodejs`.

import assert from "node:assert";
import { readFileSync } from "node:fs";
import { Receiver } from "./pkg/cypher_wasm.js";

const t = JSON.parse(readFileSync("/private/tmp/desktop_transfer.json", "utf8"));
const original = Buffer.from(t.original_b64, "base64");
const frames = t.frames_b64.map((f) => new Uint8Array(Buffer.from(f, "base64")));

// The wasm SDK keys from the phrase (same phrase the emitter used).
const r = new Receiver(t.phrase, false);
for (const f of frames) r.push_frame(f);

assert(r.is_complete(), "wasm receiver did not complete the transfer");

const out = Buffer.from(r.data());
assert.strictEqual(
  Buffer.compare(out, original),
  0,
  `decompressed output mismatch: got ${out.length} B, expected ${original.length} B`,
);

console.log(`PASS: wasm decompressed a desktop-compressed transfer (${out.length} bytes)`);

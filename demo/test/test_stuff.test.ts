// Proof of concept check: making sure our binary bytes survive conversion to QR,
// rasterizing, and decoding back without losing any details.
// If this fails, the whole transmission scheme is busted.
//
// jsQR runs fine in node via an ESM wrapper, so no browser/canvas is needed here.

import { test, expect } from "vitest";
import jsQR from "jsqr";
import { bytesToQR, drawQRToBytes } from "../src/qr_stuff";

function testRoundtrip(inputBytes: Uint8Array): number[] {
  const myQR = bytesToQR(inputBytes);
  const { data: pixelData, width: w, height: h } = drawQRToBytes(myQR, 8, 4);
  const decodedResult = jsQR(pixelData, w, h);
  expect(decodedResult, `jsQR couldn't read the QR for ${inputBytes.length} bytes`).not.toBeNull();
  return decodedResult!.binaryData;
}

async function getRealSampleFrames(): Promise<Uint8Array[]> {
  // Grab real frames emitted by our WASM sender module to make sure we are testing real stuff
  const { Sender, generate_phrase } = await import(
    "../../rust/bindings/wasm/pkg/cypher_wasm.js"
  );
  const senderGuy = new Sender(generate_phrase(), false);
  const dummyPayload = new Uint8Array(1500).map((_, idx) => (idx * 37 + 11) % 256);
  return senderGuy.frames(dummyPayload, "proof.bin").map((f) => new Uint8Array(f));
}

const testCases: [string, Uint8Array][] = [];

// Generate random-ish bytes to cover the full 0 to 255 spectrum
const smallRandomData = new Uint8Array(200).map((_, idx) => (idx * 91 + 7) % 256);
const mediumRandomData = new Uint8Array(900).map((_, idx) => (idx * 53 + 3) % 256);
testCases.push(["random 200 bytes", smallRandomData]);
testCases.push(["random 900 bytes", mediumRandomData]);
testCases.push(["all zeros 300 bytes", new Uint8Array(300)]);
testCases.push(["all 0xFFs 300 bytes", new Uint8Array(300).fill(0xff)]);

for (const [idx, frame] of (await getRealSampleFrames()).entries()) {
  testCases.push([`real frame #${idx} (${frame.length}B)`, frame]);
}

test.each(testCases)("verify QR encode and decode: %s", (_name, input) => {
  const output = testRoundtrip(input);
  expect(Array.from(output)).toEqual(Array.from(input));
});

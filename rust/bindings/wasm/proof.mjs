import assert from "node:assert";
import { Sender, Receiver, generate_phrase } from "./pkg/cypher_wasm.js";

const phrase = generate_phrase();
const original = "hello from the cypher wasm sdk";
const filename = "greeting.txt";

// --- Happy path: real random keys, real clock, byte-exact round-trip ---
const s = new Sender(phrase, false);
const frames = s.frames(new TextEncoder().encode(original), filename);
assert(frames.length > 0, "sender produced no frames");

const r = new Receiver(phrase, false);
for (const f of frames) r.push_frame(f);
assert(r.is_complete(), "receiver did not complete");

const out = r.data();
const decoded = new TextDecoder().decode(out);
assert.strictEqual(decoded, original, "payload mismatch");
assert.strictEqual(r.name(), filename, "name mismatch");

// --- Negative: wrong phrase must not decode ---
const wrong = new Receiver(generate_phrase(), false);
for (const f of frames) {
  try {
    wrong.push_frame(f);
  } catch (_) {
    /* auth/decode errors are expected and fine */
  }
}
assert(!wrong.is_complete(), "wrong-phrase receiver completed - PSK not enforced");

console.log(`PASS: decoded=${JSON.stringify(decoded)} name=${JSON.stringify(r.name())} frames=${frames.length}`);
console.log("PASS: wrong-phrase receiver did NOT complete");

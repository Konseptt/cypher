// Native macOS round-trip proof for the generated Swift binding.
// Imports the UniFFI-generated `cypher_ffi` module and drives a real
// broadcast send -> receive over the wire frames, byte-exact.

import Foundation

let phrase = generatePhrase()
let message = "hello from the cypher swift binding"
let expected = Data(Array(message.utf8))

let s = try Sender(phrase: phrase, isPublic: false)
let frames = try s.frames(file: expected, name: "greeting.txt")

let r = try Receiver(phrase: phrase, isPublic: false)
for f in frames {
    _ = try r.pushFrame(wire: f)
}

assert(r.isComplete(), "receiver did not reach completion")
let got = try r.data()
assert(Data(got) == expected, "decoded bytes did not match")
assert(r.name() == "greeting.txt", "transfer name mismatch")

let decoded = String(decoding: got, as: UTF8.self)
print("PASS: decoded=\"\(decoded)\" name=\"\(r.name())\" frames=\(frames.count)")

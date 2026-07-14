import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "generated", "python"))
from cypher_ffi import Sender, Receiver, generate_phrase

phrase = generate_phrase()
original = b"hello from the cypher python binding"
frames = Sender(phrase, False).frames(original, "greeting.txt")
r = Receiver(phrase, False)
for f in frames:
    r.push_frame(f)
assert r.is_complete(), "receiver did not complete"
out = r.data()
ok = out == original and r.name() == "greeting.txt"
print(f'frames={len(frames)} decoded="{out.decode()}" name="{r.name()}"')
print("PASS: Python binding round-trip byte-exact (thin UniFFI over the Rust core)" if ok else "FAIL")

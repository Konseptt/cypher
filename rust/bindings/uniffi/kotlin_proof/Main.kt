import uniffi.cypher_ffi.Sender
import uniffi.cypher_ffi.Receiver
import uniffi.cypher_ffi.generatePhrase

fun main() {
    val phrase = generatePhrase()
    val original = "hello from the cypher kotlin binding".toByteArray()
    val frames = Sender(phrase, false).frames(original, "greeting.txt")
    val r = Receiver(phrase, false)
    for (f in frames) r.pushFrame(f)
    check(r.isComplete()) { "receiver did not complete" }
    val out = r.data()
    val ok = out.contentEquals(original) && r.name() == "greeting.txt"
    println("frames=${frames.size} decoded=\"${String(out)}\" name=\"${r.name()}\"")
    println(if (ok) "PASS: Kotlin/JVM binding round-trip byte-exact (Android runs this same code)" else "FAIL")
}

using System;
using System.Linq;
using System.Text;
using uniffi.cypher_ffi;

string phrase = CypherFfiMethods.GeneratePhrase();
byte[] original = Encoding.UTF8.GetBytes("hello from the cypher csharp binding");

var sender = new Sender(phrase, false);
var frames = sender.Frames(original, "greeting.txt");

var receiver = new Receiver(phrase, false);
foreach (var f in frames)
    receiver.PushFrame(f);

if (!receiver.IsComplete())
    throw new Exception("receiver did not complete after all frames");

byte[] outBytes = receiver.Data();
if (!outBytes.SequenceEqual(original))
    throw new Exception("decoded bytes do not match original");

string name = receiver.Name();
if (name != "greeting.txt")
    throw new Exception($"name mismatch: got '{name}'");

Console.WriteLine($"PASS: decoded={Encoding.UTF8.GetString(outBytes)} name={name} frames={frames.Count}");

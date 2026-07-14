//! Cypher protocol core: wire format, crypto, fountain, and session
//! primitives shared by the CLI and any wasm host. Wire behaviour is pinned by
//! the conformance vectors in the CLI crate's `tests/vectors/`.
//!
//! The `compression` COMPRESS path (zstd, a C library) is gated behind the
//! `compression` feature; DECOMPRESS is always available (pure-Rust `ruzstd`
//! without the feature). `tofu`'s file-backed persistence is gated behind `fs`.
//! The wasm32 build (`--no-default-features`) excludes the C encoder and the
//! filesystem, keeping only in-memory paths - `compression::decompress`,
//! `tofu`, `session`, and `transport` build and run on wasm32-unknown-unknown.

pub mod alignment;
pub mod beacon;
pub mod crypto;
pub mod flow;
pub mod fountain;
pub mod frame;
pub mod messages;
pub mod phrase;
pub mod replay;

pub mod compression;
pub mod tofu;

// session + transport traffic in wire bytes. tofu is always available (its
// in-memory store is wasm-fine; only file persistence is `fs`-gated), and
// session gates its compression usage behind `compression`, so both build with
// or without default features - including on wasm32-unknown-unknown.
pub mod session;
pub mod transport;

/// A wasm/FFI-facing smoke entry point that runs a full DETERMINISTIC broadcast
/// PSK round-trip - session + transport + fountain - and returns the number of
/// reconstructed bytes. It uses fixed keys, a fixed SESSION_ID, and a fixed
/// clock so it calls no `OsRng` and runs in a bare wasm VM (no crypto imports
/// needed beyond what the module already stubs). Compression is off in the wasm
/// build, so `send_data` emits RAW frames; the receiver reassembles them.
#[no_mangle]
pub extern "C" fn cypher_core_selftest() -> u32 {
    use ed25519_dalek::SigningKey;
    use session::{BroadcastReceiver, BroadcastSender, BROADCAST_SYMBOL_SIZE};
    use transport::{LoopbackTransport, DEFAULT_CAPS};

    let identity = SigningKey::from_bytes(&[7u8; 32]);
    let psk = [9u8; 32];
    let session_id = 0xDEAD_BEEF_CAFE_1234_u64;
    let payload = b"cypher over wasm";

    let mut t = LoopbackTransport::new(DEFAULT_CAPS);
    let screen = t.screen_arc();
    {
        let mut sender = BroadcastSender::with_session_id(
            &mut t,
            identity,
            psk,
            BROADCAST_SYMBOL_SIZE,
            fountain::DEFAULT_OVERHEAD,
            Box::new(|| 0.0), // fixed clock - no wall clock, no randomness
            session_id,
        );
        if sender.send_data(payload, "", 0).is_err() {
            return 0;
        }
    }

    // Drain the rendered wire frames (BEACON + DATA packets) off the screen.
    let frames: Vec<Vec<u8>> = {
        let mut q = screen.lock().expect("loopback lock");
        q.drain(..).collect()
    };

    let mut receiver = BroadcastReceiver::new(
        psk,
        None, // no TrustStore needed for a PSK round-trip
        "wasm-peer",
        true, // auto-accept identity
        None,
        Box::new(|| 0.0),
    );
    for wire in frames {
        if receiver.on_codes(vec![wire]).is_err() {
            return 0;
        }
    }
    receiver.data().map(|d| d.len()).unwrap_or(0) as u32
}

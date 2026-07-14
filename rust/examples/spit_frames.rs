//! This script just spits out a compressed broadcast transfer and dumps all the wire frames to JSON.
//! That way, the WASM/Node side can test if it can actually decompress them correctly.
//!
//! Run it with: `cargo run --example spit_frames`
//!
//! We're making sure both sides derive the same key from a random phrase we generate on the fly
//! (which we save in the JSON). We're using real wall-clock time for the beacon timestamp
//! so the WASM receiver doesn't reject it for being outside the 5-minute window!

use std::time::{SystemTime, UNIX_EPOCH};

use cypher::compression::{compress, LEVEL_SPEED};
use cypher::crypto::{generate_identity, key_from_phrase};
use cypher::fountain::DEFAULT_OVERHEAD;
use cypher::session::{BroadcastSender, BROADCAST_SYMBOL_SIZE};
use cypher::transport::{LoopbackTransport, DEFAULT_CAPS};

const OUT_PATH: &str = "/private/tmp/desktop_transfer.json";

// This is a super tiny inline base64 encoder. I really didn't want to pull in
// a whole base64 dependency just for this one function. It works exactly like Node's Buffer.
fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(A[(n >> 18 & 63) as usize] as char);
        out.push(A[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    // Let's make a super compressible blob by repeating the classic pangram over and over.
    let big_data: Vec<u8> = b"the quick brown fox jumps over the lazy dog "
        .iter()
        .cycle()
        .take(44 * 300)
        .copied()
        .collect();

    // We have to prove that send_data actually compresses this. The compressed output 
    // has to be smaller, which makes send_data turn on the COMPRESSED flag so WASM can decompress it.
    let zipped_data = compress(&big_data, LEVEL_SPEED).unwrap();
    assert!(
        zipped_data.len() < big_data.len(),
        "big_data did not compress ({} >= {}) - test would not exercise decompress",
        zipped_data.len(),
        big_data.len()
    );
    println!(
        "compressed {} B < original {} B - send_data will set COMPRESSED",
        zipped_data.len(),
        big_data.len()
    );

    let secret_key = cypher::phrase::generate(cypher::phrase::DEFAULT_WORDS);
    let psk = *key_from_phrase(&secret_key).unwrap().as_bytes();

    let mut loopback_wire = LoopbackTransport::new(DEFAULT_CAPS);
    let display = loopback_wire.screen_arc();

    // Gotta use real time here so the beacon timestamp is fresh when the receiver sees it.
    let get_time = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    };

    {
        let mut sender_guy = BroadcastSender::with_session_id(
            &mut loopback_wire,
            generate_identity(),
            psk,
            BROADCAST_SYMBOL_SIZE,
            DEFAULT_OVERHEAD,
            Box::new(get_time),
            0xD0D0_D0D0_D0D0_D0D0, // hardcoded session ID so our key generation is deterministic
        );
        sender_guy
            .send_data(&big_data, "quote.txt", LEVEL_SPEED)
            .unwrap();
    }

    let frames: Vec<Vec<u8>> = display.lock().unwrap().drain(..).collect();
    assert!(!frames.is_empty(), "no wire frames produced");

    let frames_b64: Vec<String> = frames.iter().map(|f| b64(f)).collect();
    let json = serde_json::json!({
        "phrase": secret_key,
        "psk_hex": hex(&psk),
        "original_b64": b64(&big_data),
        "frames_b64": frames_b64,
    });
    std::fs::write(OUT_PATH, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    println!("wrote {} frames to {}", frames.len(), OUT_PATH);
}

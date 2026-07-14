use cypher::beacon::{
    build_payload, build_receiver_beacon_with_token, parse_payload, parse_receiver_beacon, Beacon,
    FRAME_CELLS,
};
use cypher::compression::{compress, decompress, LEVEL_RATIO, LEVEL_SPEED};
use cypher::crypto::{
    decrypt_payload, encrypt_payload, fingerprint, gcm_nonce, identity_public_bytes,
    key_from_phrase, pairing_token_hash, phrase_tokens, psk_session_key, session_key,
};
use cypher::fountain::{encode, Decoder, DEFAULT_OVERHEAD};
use cypher::frame::{header_prefix, Frame};
use cypher::messages::{
    pack_alignment, pack_degraded, pack_handshake_ack, pack_nak, pack_pause, pack_resume,
    pack_resumed, pack_session_complete, pack_session_timeout, parse_alignment, parse_degraded,
    parse_handshake_ack, parse_nak, parse_pause, parse_resume, parse_resumed,
    parse_session_complete, parse_session_timeout,
};
/// Conformance tests against the test vectors.
///
/// Frame vectors:   tests/vectors/frame.json
/// Compression vectors: tests/vectors/compression.json
///
/// NEVER compare compressed bytes - zstd output is not guaranteed identical
/// across libzstd builds/languages. Instead, assert decompress(oracle_frame) ==
/// plaintext and that a Rust round-trip passes.
use serde::Deserialize;

// ─── Frame conformance ────────────────────────────────────────────────────────

/// A single frame vector. Optional `error: true` marks cases that must be
/// rejected. Other fields may be absent for error cases.
#[derive(Debug, Deserialize)]
struct FrameVector {
    name: String,
    #[serde(default)]
    error: bool,
    /// Hex-encoded full wire bytes (header + payload)
    encoded: Option<String>,
    #[serde(default)]
    frame_number: u32,
    #[serde(default)]
    flags: u8,
    /// Hex-encoded payload bytes
    payload: Option<String>,
    /// Hex-encoded 6-byte header prefix (bytes 0-5, i.e. before CRC-16)
    header_prefix: Option<String>,
}

fn load_frame_vectors() -> Vec<FrameVector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/frame.json");
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read frame.json at {path}: {e}"));
    serde_json::from_str(&raw).expect("frame.json parse failed")
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex decode failed"))
        .collect()
}

/// Valid vectors: Rust must encode to the same bytes AND decode back to the
/// same fields. Error vectors must be rejected by Frame::decode.
#[test]
fn frame_conformance_vectors() {
    let vectors = load_frame_vectors();
    let mut n_valid = 0usize;
    let mut n_error = 0usize;

    for v in &vectors {
        if v.error {
            // Error case: decode must fail
            let encoded = hex_decode(v.encoded.as_deref().unwrap_or(""));
            let result = Frame::decode(&encoded);
            assert!(
                result.is_err(),
                "vector {:?}: expected decode error, got Ok({:?})",
                v.name,
                result.unwrap()
            );
            n_error += 1;
        } else {
            // Valid case
            let encoded_bytes = hex_decode(v.encoded.as_ref().unwrap());
            let payload_bytes = hex_decode(v.payload.as_ref().unwrap());
            let prefix_bytes = hex_decode(v.header_prefix.as_ref().unwrap());

            // 1. Decode the oracle-provided bytes; fields must match the vector.
            let decoded = Frame::decode(&encoded_bytes)
                .unwrap_or_else(|e| panic!("vector {:?}: decode failed: {e}", v.name));
            assert_eq!(
                decoded.frame_number, v.frame_number,
                "vector {:?}: frame_number mismatch",
                v.name
            );
            assert_eq!(
                decoded.flags, v.flags,
                "vector {:?}: flags mismatch",
                v.name
            );
            assert_eq!(
                decoded.payload, payload_bytes,
                "vector {:?}: payload mismatch",
                v.name
            );

            // 2. Rust encode must produce the same bytes as the vector.
            let re_encoded = decoded.encode();
            assert_eq!(
                re_encoded, encoded_bytes,
                "vector {:?}: encode → bytes mismatch",
                v.name
            );

            // 3. The header prefix (bytes 0-5) must match the vector exactly.
            assert_eq!(
                &re_encoded[..6],
                prefix_bytes.as_slice(),
                "vector {:?}: header prefix mismatch",
                v.name
            );

            n_valid += 1;
        }
    }

    assert!(n_valid > 0, "no valid frame vectors were checked");
    assert!(n_error > 0, "no error frame vectors were checked");
}

// ─── Compression conformance ─────────────────────────────────────────────────

/// One compression vector (with an optional metadata _note entry at [0]).
#[derive(Debug, Deserialize)]
struct CompressionVector {
    /// Present only on the _note entry - skip it.
    #[serde(rename = "_note")]
    note: Option<String>,
    name: Option<String>,
    /// Hex-encoded plaintext bytes
    plaintext: Option<String>,
    /// Hex-encoded oracle-compressed bytes at level 3 (LEVEL_SPEED)
    speed_frame: Option<String>,
    /// Hex-encoded oracle-compressed bytes at level 9 (LEVEL_RATIO)
    ratio_frame: Option<String>,
}

fn load_compression_vectors() -> Vec<CompressionVector> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/compression.json"
    );
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read compression.json at {path}: {e}"));
    serde_json::from_str(&raw).expect("compression.json parse failed")
}

/// For every compression vector:
///   - decompress(oracle_frame) == plaintext  (for both speed and ratio frames)
///   - Rust compress → decompress == plaintext  (round-trip, both levels)
///
/// Compressed bytes are NOT compared - output is implementation-defined as long as
/// the standard is obeyed.
#[test]
fn compression_conformance_vectors() {
    let vectors = load_compression_vectors();
    let mut n_checked = 0usize;

    for v in &vectors {
        // Skip the metadata _note entry.
        if v.note.is_some() {
            continue;
        }
        let name = v.name.as_deref().unwrap_or("<unnamed>");
        let plaintext = hex_decode(v.plaintext.as_ref().unwrap());
        let speed_frame = hex_decode(v.speed_frame.as_ref().unwrap());
        let ratio_frame = hex_decode(v.ratio_frame.as_ref().unwrap());

        // 1. Decompress oracle speed frame → plaintext
        let got = decompress(&speed_frame, 0)
            .unwrap_or_else(|e| panic!("vector {name}: decompress(speed_frame) failed: {e}"));
        assert_eq!(
            got, plaintext,
            "vector {name}: decompress(speed_frame) != plaintext"
        );

        // 2. Decompress oracle ratio frame → plaintext
        let got = decompress(&ratio_frame, 0)
            .unwrap_or_else(|e| panic!("vector {name}: decompress(ratio_frame) failed: {e}"));
        assert_eq!(
            got, plaintext,
            "vector {name}: decompress(ratio_frame) != plaintext"
        );

        // 3. Rust round-trip at LEVEL_SPEED
        let rs_compressed = compress(&plaintext, LEVEL_SPEED)
            .unwrap_or_else(|e| panic!("vector {name}: compress(LEVEL_SPEED) failed: {e}"));
        let rs_decompressed = decompress(&rs_compressed, 0)
            .unwrap_or_else(|e| panic!("vector {name}: decompress(Rust/speed) failed: {e}"));
        assert_eq!(
            rs_decompressed, plaintext,
            "vector {name}: Rust LEVEL_SPEED round-trip failed"
        );

        // 4. Rust round-trip at LEVEL_RATIO
        let rs_compressed = compress(&plaintext, LEVEL_RATIO)
            .unwrap_or_else(|e| panic!("vector {name}: compress(LEVEL_RATIO) failed: {e}"));
        let rs_decompressed = decompress(&rs_compressed, 0)
            .unwrap_or_else(|e| panic!("vector {name}: decompress(Rust/ratio) failed: {e}"));
        assert_eq!(
            rs_decompressed, plaintext,
            "vector {name}: Rust LEVEL_RATIO round-trip failed"
        );

        n_checked += 1;
    }

    assert!(n_checked > 0, "no compression vectors were checked");
}

// ─── Crypto conformance ───────────────────────────────────────────────────────

/// Deserialise the crypto.json vector file - only the fields relevant to each
/// `kind` are present in the actual JSON.
#[derive(Debug, serde::Deserialize)]
struct CryptoVector {
    kind: String,
    // scrypt_phrase
    phrase: Option<String>,
    key: Option<String>,
    // hkdf_session
    my_ephemeral_seed: Option<String>,
    their_ephemeral_pub: Option<String>,
    session_id: Option<u64>,
    session_key: Option<String>,
    // hkdf_psk
    psk: Option<String>,
    // hkdf_pin
    pin: Option<String>,
    // gcm_nonce
    nonce: Option<String>,
    frame_number: Option<u64>,
    // aes_gcm_unicast / aes_gcm_broadcast
    aad: Option<String>,
    plaintext: Option<String>,
    ciphertext_and_tag: Option<String>,
    frame_payload: Option<String>,
    sid_prefix: Option<String>,
    flags: Option<u8>,
    // ed25519
    identity_seed: Option<String>,
    identity_pub: Option<String>,
    message: Option<String>,
    signature: Option<String>,
    // pairing_token_hash
    pairing_token: Option<String>,
    hash: Option<String>,
    // fingerprint
    fingerprint: Option<String>,
    // phrase_normalize
    tokens: Option<Vec<String>>,
    // info label (present on hkdf_ entries, not used as a test input)
    #[allow(dead_code)]
    info: Option<String>,
}

fn load_crypto_vectors() -> Vec<CryptoVector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/crypto.json");
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read crypto.json at {path}: {e}"));
    serde_json::from_str(&raw).expect("crypto.json parse failed")
}

/// Crypto conformance vectors - pins every scrypt/HKDF/nonce/AES-GCM/Ed25519/
/// HMAC/fingerprint/normalize case in tests/vectors/crypto.json.
#[test]
fn crypto_conformance_vectors() {
    use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
    use x25519_dalek::StaticSecret as XStaticSecret;

    let vectors = load_crypto_vectors();
    let mut n_checked = 0usize;

    for v in &vectors {
        match v.kind.as_str() {
            // ── scrypt phrase KDF ─────────────────────────────────────────────
            "scrypt_phrase" => {
                let phrase = v.phrase.as_deref().unwrap();
                let expected = hex_decode(v.key.as_deref().unwrap());
                let got = key_from_phrase(phrase).unwrap();
                assert_eq!(
                    got.as_bytes(),
                    expected.as_slice(),
                    "scrypt_phrase {:?}: key mismatch",
                    phrase
                );
                n_checked += 1;
            }

            // ── HKDF session (X25519 ECDH + HKDF-SHA256) ─────────────────────
            "hkdf_session" => {
                // Reconstruct X25519 StaticSecret from the 32-byte seed.
                let seed_bytes: [u8; 32] = hex_decode(v.my_ephemeral_seed.as_deref().unwrap())
                    .try_into()
                    .unwrap();
                let their_pub: [u8; 32] = hex_decode(v.their_ephemeral_pub.as_deref().unwrap())
                    .try_into()
                    .unwrap();
                let sid = v.session_id.unwrap();
                let expected = hex_decode(v.session_key.as_deref().unwrap());
                // XStaticSecret can be constructed from a fixed 32-byte scalar.
                let my_secret = XStaticSecret::from(seed_bytes);
                let got = session_key(&my_secret, their_pub, sid);
                assert_eq!(
                    got.as_bytes(),
                    expected.as_slice(),
                    "hkdf_session: session_key mismatch"
                );
                n_checked += 1;
            }

            // ── HKDF PSK ─────────────────────────────────────────────────────
            "hkdf_psk" => {
                let psk: [u8; 32] = hex_decode(v.psk.as_deref().unwrap()).try_into().unwrap();
                let sid = v.session_id.unwrap();
                let expected = hex_decode(v.session_key.as_deref().unwrap());
                let got = psk_session_key(&psk, sid);
                assert_eq!(
                    got.as_bytes(),
                    expected.as_slice(),
                    "hkdf_psk: session_key mismatch"
                );
                n_checked += 1;
            }

            // ── HKDF PIN ─────────────────────────────────────────────────────
            "hkdf_pin" => {
                let key: [u8; 32] = hex_decode(v.key.as_deref().unwrap()).try_into().unwrap();
                let expected_pin = v.pin.as_deref().unwrap();
                let got = cypher::crypto::derive_pin(&key);
                assert_eq!(got, expected_pin, "hkdf_pin: PIN mismatch");
                n_checked += 1;
            }

            // ── GCM nonce ─────────────────────────────────────────────────────
            "gcm_nonce" => {
                let sid = v.session_id.unwrap();
                let frame_num = v.frame_number.unwrap();
                let expected = hex_decode(v.nonce.as_deref().unwrap());
                let got = gcm_nonce(sid, frame_num);
                assert_eq!(
                    got.as_ref(),
                    expected.as_slice(),
                    "gcm_nonce sid={sid} frame={frame_num}: mismatch"
                );
                n_checked += 1;
            }

            // ── AES-256-GCM unicast ───────────────────────────────────────────
            "aes_gcm_unicast" => {
                let key: [u8; 32] = hex_decode(v.key.as_deref().unwrap()).try_into().unwrap();
                let aad = hex_decode(v.aad.as_deref().unwrap());
                let plaintext = hex_decode(v.plaintext.as_deref().unwrap());
                let expected_ct = hex_decode(v.ciphertext_and_tag.as_deref().unwrap());
                let sid = v.session_id.unwrap();
                let frame_num = v.frame_number.unwrap();

                // Encrypt and compare to oracle ciphertext
                let got_ct = encrypt_payload(&key, sid, frame_num, &plaintext, &aad);
                assert_eq!(
                    got_ct, expected_ct,
                    "aes_gcm_unicast frame={frame_num}: ciphertext mismatch"
                );

                // Decrypt oracle ciphertext and verify plaintext
                let got_pt = decrypt_payload(&key, sid, frame_num, &expected_ct, &aad).unwrap();
                assert_eq!(
                    got_pt, plaintext,
                    "aes_gcm_unicast frame={frame_num}: decrypt mismatch"
                );

                // frame_payload == ciphertext_and_tag for unicast
                let fp = hex_decode(v.frame_payload.as_deref().unwrap());
                assert_eq!(
                    fp, expected_ct,
                    "unicast: frame_payload must equal ciphertext_and_tag"
                );

                n_checked += 1;
            }

            // ── AES-256-GCM broadcast ─────────────────────────────────────────
            //
            // Broadcast DATA payload =
            //   SESSION_ID (8B, plaintext) ‖ AES-256-GCM(chunk) + tag(16B)
            //
            // The AAD is the 6-byte header prefix whose PAYLOAD_LENGTH covers
            // the FULL frame_payload (sid_prefix + ciphertext + tag), so the
            // sid_prefix is length-bound and cannot be altered without GCM failure.
            "aes_gcm_broadcast" => {
                let key: [u8; 32] = hex_decode(v.key.as_deref().unwrap()).try_into().unwrap();
                let aad = hex_decode(v.aad.as_deref().unwrap());
                let plaintext = hex_decode(v.plaintext.as_deref().unwrap());
                let sid_prefix = hex_decode(v.sid_prefix.as_deref().unwrap());
                let expected_ct = hex_decode(v.ciphertext_and_tag.as_deref().unwrap());
                let expected_fp = hex_decode(v.frame_payload.as_deref().unwrap());
                let sid = v.session_id.unwrap();
                let frame_num = v.frame_number.unwrap();

                // Encrypt the plaintext chunk.
                let got_ct = encrypt_payload(&key, sid, frame_num, &plaintext, &aad);
                assert_eq!(
                    got_ct, expected_ct,
                    "aes_gcm_broadcast frame={frame_num}: ciphertext mismatch"
                );

                // Broadcast frame_payload = sid_prefix ‖ ciphertext_and_tag.
                let mut fp = sid_prefix.clone();
                fp.extend_from_slice(&got_ct);
                assert_eq!(
                    fp, expected_fp,
                    "aes_gcm_broadcast frame={frame_num}: frame_payload mismatch"
                );

                // Verify AAD encodes payload_len = len(frame_payload).
                let flags = v.flags.unwrap_or(1);
                let payload_len = expected_fp.len() as u16;
                let expected_aad = header_prefix(frame_num as u32, flags, payload_len).unwrap();
                assert_eq!(
                    expected_aad.as_ref(),
                    aad.as_slice(),
                    "aes_gcm_broadcast: AAD does not match header_prefix"
                );

                // Decrypt oracle ciphertext and verify plaintext.
                let got_pt = decrypt_payload(&key, sid, frame_num, &expected_ct, &aad).unwrap();
                assert_eq!(
                    got_pt, plaintext,
                    "aes_gcm_broadcast frame={frame_num}: decrypt mismatch"
                );

                n_checked += 1;
            }

            // ── Ed25519 ───────────────────────────────────────────────────────
            "ed25519" => {
                let seed: [u8; 32] = hex_decode(v.identity_seed.as_deref().unwrap())
                    .try_into()
                    .unwrap();
                let expected_pub = hex_decode(v.identity_pub.as_deref().unwrap());
                let message = hex_decode(v.message.as_deref().unwrap());
                let expected_sig = hex_decode(v.signature.as_deref().unwrap());

                // Reconstruct signing key from seed (32-byte scalar).
                let sk = SigningKey::from_bytes(&seed);
                // Public key must match the vector.
                assert_eq!(
                    sk.verifying_key().to_bytes().as_ref(),
                    expected_pub.as_slice(),
                    "ed25519: public key mismatch"
                );

                // Verify signature using the public verify() helper (never panics).
                let pub_arr: [u8; 32] = expected_pub.try_into().unwrap();
                let sig_arr: [u8; 64] = expected_sig.try_into().unwrap();
                assert!(
                    cypher::crypto::verify(pub_arr, &sig_arr, &message),
                    "ed25519: oracle signature must verify"
                );

                // Verify via dalek directly too.
                let vk = VerifyingKey::from_bytes(&pub_arr).unwrap();
                let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
                assert!(
                    vk.verify(&message, &sig).is_ok(),
                    "ed25519: dalek verify failed"
                );

                n_checked += 1;
            }

            // ── HMAC-SHA256 pairing token hash ────────────────────────────────
            "pairing_token_hash" => {
                let token: [u8; 16] = hex_decode(v.pairing_token.as_deref().unwrap())
                    .try_into()
                    .unwrap();
                let sid = v.session_id.unwrap();
                let expected = hex_decode(v.hash.as_deref().unwrap());
                let got = pairing_token_hash(&token, sid);
                assert_eq!(
                    got.as_ref(),
                    expected.as_slice(),
                    "pairing_token_hash: mismatch"
                );
                n_checked += 1;
            }

            // ── SHA-256 fingerprint ───────────────────────────────────────────
            "fingerprint" => {
                let pub_bytes: [u8; 32] = hex_decode(v.identity_pub.as_deref().unwrap())
                    .try_into()
                    .unwrap();
                let expected = hex_decode(v.fingerprint.as_deref().unwrap());
                let got = fingerprint(&pub_bytes);
                assert_eq!(got.as_ref(), expected.as_slice(), "fingerprint: mismatch");
                n_checked += 1;
            }

            // ── phrase_normalize ─────────────────────────────────────────────
            "phrase_normalize" => {
                let phrase = v.phrase.as_deref().unwrap();
                let expected: Vec<String> = v.tokens.clone().unwrap();
                let got = phrase_tokens(phrase);
                assert_eq!(
                    got, expected,
                    "phrase_normalize {:?}: token mismatch",
                    phrase
                );
                n_checked += 1;
            }

            other => panic!("unknown crypto vector kind: {other:?}"),
        }
    }

    assert!(n_checked > 0, "no crypto vectors were checked");
}

// ─── Phrase conformance ───────────────────────────────────────────────────────

/// Pins the bundled wordlist's SHA-256, word count, and spot-check entries
/// against the values in tests/vectors/phrase.json.
///
/// SHA-256 is computed as SHA-256(words.join("\n")) - no trailing newline.
#[test]
fn phrase_conformance_vectors() {
    use cypher::phrase::WORDLIST;
    use sha2::{Digest, Sha256};

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/phrase.json");
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read phrase.json at {path}: {e}"));
    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(&raw).expect("phrase.json parse failed");

    let v = &vectors[0];
    let expected_sha = v["wordlist_sha256"].as_str().unwrap();
    let expected_count = v["word_count"].as_u64().unwrap() as usize;
    let spot_checks = v["spot_checks"].as_object().unwrap();

    let words = &*WORDLIST;

    // Word count
    assert_eq!(words.len(), expected_count, "wordlist word count mismatch");

    // SHA-256 of words joined with "\n" (no trailing newline)
    let joined = words.join("\n");
    let sha: [u8; 32] = Sha256::digest(joined.as_bytes()).into();
    let sha_hex = hex::encode(sha);
    assert_eq!(sha_hex, expected_sha, "wordlist SHA-256 mismatch");

    // Spot checks: index → expected word
    for (idx_str, expected_word) in spot_checks {
        let idx: usize = idx_str.parse().unwrap();
        let expected = expected_word.as_str().unwrap();
        assert_eq!(
            words[idx], expected,
            "spot check at index {idx}: expected {:?}, got {:?}",
            expected, words[idx]
        );
    }
}

// ─── Beacon conformance ───────────────────────────────────────────────────────
//
// Vectors: tests/vectors/beacon.json (3 entries: "full", "minimal", "receiver_beacon").
//
// "full" and "minimal": build_payload must produce the committed hex bytes
// (byte-exact), and parse_payload must recover the committed field values.
// "receiver_beacon": build_receiver_beacon_with_token must produce the committed
// hex bytes; parse_receiver_beacon must accept them; field offsets must match the
// layout table verified in the vector.

#[derive(Debug, serde::Deserialize)]
struct BeaconVector {
    name: String,
    // "full" / "minimal" fields
    #[serde(default)]
    session_id: u64,
    #[serde(default)]
    timestamp_ms: u64,
    #[serde(default)]
    session_level: u8,
    intended_receiver: Option<String>,
    pairing_token_hash: Option<String>,
    ephemeral_pub: Option<String>,
    identity_pub: Option<String>,
    identity_seed: Option<String>,
    #[serde(default)]
    width: u16,
    #[serde(default)]
    height: u16,
    #[serde(default)]
    max_fps: u8,
    #[serde(default)]
    cell_size: u8,
    #[serde(default)]
    transfer_size: u64,
    transfer_name: Option<String>,
    receiver_session_token: Option<String>,
    #[serde(default)]
    frame_cells: u8,
    #[serde(default)]
    symbol_size: u16,
    #[serde(default)]
    fountain_length: u32,
    payload: Option<String>,
    // "receiver_beacon" fields
    capabilities: Option<String>,
    token: Option<String>,
    wire: Option<String>,
    offsets: Option<serde_json::Value>,
}

fn load_beacon_vectors() -> Vec<BeaconVector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/beacon.json");
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read beacon.json at {path}: {e}"));
    serde_json::from_str(&raw).expect("beacon.json parse failed")
}

fn signing_key_from_seed(seed_hex: &str) -> ed25519_dalek::SigningKey {
    let seed: [u8; 32] = hex_decode(seed_hex).try_into().unwrap();
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn arr32(hex: &str) -> [u8; 32] {
    hex_decode(hex).try_into().unwrap()
}

fn arr16(hex: &str) -> [u8; 16] {
    hex_decode(hex).try_into().unwrap()
}

fn arr8(hex: &str) -> [u8; 8] {
    hex_decode(hex).try_into().unwrap()
}

/// Beacon conformance: each BEACON vector (full, minimal) must produce byte-identical
/// hex from build_payload and recover the committed fields from parse_payload.
/// receiver_beacon: build_receiver_beacon_with_token produces byte-identical hex;
/// parse_receiver_beacon accepts it; field offsets are verified.
#[test]
fn beacon_conformance_vectors() {
    let vectors = load_beacon_vectors();
    let mut n_checked = 0usize;

    for v in &vectors {
        match v.name.as_str() {
            "full" | "minimal" => {
                let sk = signing_key_from_seed(v.identity_seed.as_deref().unwrap());
                // Use cell_size=1 for "minimal" (it's 1 in the vector); the
                // vector has cell_size=0 which would fail the check - actually
                // let's read the value from the vector; "minimal" has cell_size=1.
                // FRAME_CELLS in the vector - use the vector value directly.
                let fc = if v.frame_cells == 0 {
                    FRAME_CELLS
                } else {
                    v.frame_cells
                };

                // Build the Beacon struct from vector inputs.
                let beacon = Beacon::new(
                    v.session_id,
                    v.timestamp_ms,
                    v.session_level,
                    arr32(v.intended_receiver.as_deref().unwrap()),
                    arr32(v.pairing_token_hash.as_deref().unwrap()),
                    arr32(v.ephemeral_pub.as_deref().unwrap()),
                    arr32(v.identity_pub.as_deref().unwrap()),
                    v.width,
                    v.height,
                    v.max_fps,
                    if v.cell_size == 0 { 1 } else { v.cell_size },
                    v.transfer_size,
                    v.transfer_name.clone().unwrap_or_default(),
                    arr16(v.receiver_session_token.as_deref().unwrap()),
                    fc,
                    v.symbol_size,
                    v.fountain_length,
                )
                .unwrap_or_else(|e| panic!("vector {:?}: Beacon::new failed: {e:?}", v.name));

                // 1. build_payload → byte-identical to committed hex.
                let got = build_payload(&beacon, &sk, 1);
                let expected = hex_decode(v.payload.as_ref().unwrap());
                assert_eq!(
                    got, expected,
                    "vector {:?}: build_payload bytes mismatch",
                    v.name
                );

                // 2. parse_payload on committed hex → recovers the committed fields.
                let parsed = parse_payload(&expected)
                    .unwrap_or_else(|e| panic!("vector {:?}: parse_payload failed: {e:?}", v.name));
                assert_eq!(
                    parsed.session_id, v.session_id,
                    "vector {:?}: session_id mismatch",
                    v.name
                );
                assert_eq!(
                    parsed.timestamp_ms, v.timestamp_ms,
                    "vector {:?}: timestamp_ms mismatch",
                    v.name
                );
                assert_eq!(
                    parsed.session_level, v.session_level,
                    "vector {:?}: session_level mismatch",
                    v.name
                );
                assert_eq!(
                    parsed.intended_receiver,
                    arr32(v.intended_receiver.as_deref().unwrap()),
                    "vector {:?}: intended_receiver mismatch",
                    v.name
                );
                assert_eq!(
                    parsed.pairing_token_hash,
                    arr32(v.pairing_token_hash.as_deref().unwrap()),
                    "vector {:?}: pairing_token_hash mismatch",
                    v.name
                );
                assert_eq!(
                    parsed.ephemeral_pub,
                    arr32(v.ephemeral_pub.as_deref().unwrap()),
                    "vector {:?}: ephemeral_pub mismatch",
                    v.name
                );
                assert_eq!(
                    parsed.identity_pub,
                    arr32(v.identity_pub.as_deref().unwrap()),
                    "vector {:?}: identity_pub mismatch",
                    v.name
                );
                assert_eq!(parsed.width, v.width, "vector {:?}: width mismatch", v.name);
                assert_eq!(
                    parsed.height, v.height,
                    "vector {:?}: height mismatch",
                    v.name
                );
                assert_eq!(
                    parsed.max_fps, v.max_fps,
                    "vector {:?}: max_fps mismatch",
                    v.name
                );
                assert_eq!(
                    parsed.transfer_size, v.transfer_size,
                    "vector {:?}: transfer_size mismatch",
                    v.name
                );
                assert_eq!(
                    parsed.transfer_name,
                    v.transfer_name.as_deref().unwrap_or(""),
                    "vector {:?}: transfer_name mismatch",
                    v.name
                );
                assert_eq!(
                    parsed.symbol_size, v.symbol_size,
                    "vector {:?}: symbol_size mismatch",
                    v.name
                );
                assert_eq!(
                    parsed.fountain_length, v.fountain_length,
                    "vector {:?}: fountain_length mismatch",
                    v.name
                );

                n_checked += 1;
            }

            "receiver_beacon" => {
                let sk = signing_key_from_seed(v.identity_seed.as_deref().unwrap());
                let caps: [u8; 8] = arr8(v.capabilities.as_deref().unwrap());
                let token: [u8; 16] = arr16(v.token.as_deref().unwrap());
                let expected_wire = hex_decode(v.wire.as_ref().unwrap());

                // The vector was committed at timestamp_ms 1750000000000.
                // build_receiver_beacon_with_token takes a clock returning seconds.
                let ts_s = v.timestamp_ms as f64 / 1000.0;

                // 1. build → byte-identical to committed hex.
                let got_wire = build_receiver_beacon_with_token(&sk, &caps, &token, move || ts_s);
                assert_eq!(
                    got_wire, expected_wire,
                    "receiver_beacon: build bytes mismatch"
                );

                // 2. parse the committed hex at the same timestamp (no staleness).
                let parsed = parse_receiver_beacon(&expected_wire, move || ts_s)
                    .expect("receiver_beacon: parse_receiver_beacon failed");

                // Fields from the vector.
                assert_eq!(
                    parsed.identity_pub,
                    identity_public_bytes(&sk),
                    "receiver_beacon: identity_pub mismatch"
                );
                assert_eq!(
                    parsed.session_token, token,
                    "receiver_beacon: token mismatch"
                );
                assert_eq!(parsed.capabilities, caps, "receiver_beacon: caps mismatch");
                assert_eq!(
                    parsed.timestamp_ms, v.timestamp_ms,
                    "receiver_beacon: timestamp_ms mismatch"
                );

                // 3. Verify field offsets (pinned by vector).
                let offsets = v.offsets.as_ref().unwrap();
                let off_identity = offsets["IDENTITY"].as_u64().unwrap() as usize;
                let off_token_o = offsets["TOKEN"].as_u64().unwrap() as usize;
                let off_caps_o = offsets["CAPS"].as_u64().unwrap() as usize;
                let off_ts_o = offsets["TIMESTAMP"].as_u64().unwrap() as usize;
                let off_sig = offsets["SIG"].as_u64().unwrap() as usize;
                let off_crc = offsets["CRC"].as_u64().unwrap() as usize;
                let total = offsets["total"].as_u64().unwrap() as usize;

                assert_eq!(
                    total,
                    expected_wire.len(),
                    "receiver_beacon: total length mismatch"
                );
                assert_eq!(
                    &expected_wire[off_identity..off_identity + 32],
                    parsed.identity_pub.as_ref(),
                    "receiver_beacon: IDENTITY offset mismatch"
                );
                assert_eq!(
                    &expected_wire[off_token_o..off_token_o + 16],
                    token.as_ref(),
                    "receiver_beacon: TOKEN offset mismatch"
                );
                assert_eq!(
                    &expected_wire[off_caps_o..off_caps_o + 8],
                    caps.as_ref(),
                    "receiver_beacon: CAPS offset mismatch"
                );
                assert_eq!(
                    u64::from_be_bytes(expected_wire[off_ts_o..off_ts_o + 8].try_into().unwrap()),
                    v.timestamp_ms,
                    "receiver_beacon: TIMESTAMP offset mismatch"
                );
                // SIG is 64 bytes at OFF_SIG; CRC is 2 bytes at OFF_CRC.
                assert_eq!(
                    off_crc,
                    off_sig + 64,
                    "receiver_beacon: SIG+CRC layout mismatch"
                );

                n_checked += 1;
            }

            other => panic!("unknown beacon vector name: {other:?}"),
        }
    }

    assert!(
        n_checked >= 3,
        "expected at least 3 beacon vectors, got {n_checked}"
    );
}

// ─── Messages conformance ─────────────────────────────────────────────────────
//
// Vectors: tests/vectors/messages.json (11 entries, one per message type).
// For each: pack_* must produce the committed payload hex; envelopes use
// IDENTITY_SIG over a random key, so only the structure is verified
// (type byte, payload, 64-byte tail), not the exact envelope bytes.

#[derive(Debug, serde::Deserialize)]
struct MessageVector {
    name: String,
    message_type: u8,
    payload: String,
    envelope: String,
    inputs: serde_json::Value,
}

fn load_message_vectors() -> Vec<MessageVector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/messages.json");
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read messages.json at {path}: {e}"));
    serde_json::from_str(&raw).expect("messages.json parse failed")
}

/// Messages conformance: for each vector entry, pack_* must produce the committed
/// payload bytes; parse_* on those bytes must succeed; the envelope must have the
/// right structure (type byte = committed message_type, 64-byte Ed25519 tail).
#[test]
fn messages_conformance_vectors() {
    use cypher::crypto::SIG_LEN;

    let vectors = load_message_vectors();
    let mut n_checked = 0usize;

    for v in &vectors {
        let expected_payload = hex_decode(&v.payload);
        let expected_envelope = hex_decode(&v.envelope);

        // 1. Envelope structure: first byte = message_type, last 64B = Ed25519 sig.
        assert_eq!(
            expected_envelope[0], v.message_type,
            "vector {:?}: envelope first byte mismatch",
            v.name
        );
        assert_eq!(
            expected_envelope.len(),
            1 + expected_payload.len() + SIG_LEN,
            "vector {:?}: envelope length mismatch",
            v.name
        );
        // Envelope's [1..len-64] must equal the payload.
        let env_payload = &expected_envelope[1..expected_envelope.len() - SIG_LEN];
        assert_eq!(
            env_payload,
            expected_payload.as_slice(),
            "vector {:?}: envelope payload slice mismatch",
            v.name
        );

        // 2. pack_* → byte-identical to committed payload.
        match v.name.as_str() {
            "handshake_ack" => {
                let i = &v.inputs;
                let got = pack_handshake_ack(
                    &arr32(i["ephemeral_pub"].as_str().unwrap()),
                    &arr32(i["identity_pub"].as_str().unwrap()),
                    i["fps"].as_u64().unwrap() as u8,
                    i["width"].as_u64().unwrap() as u16,
                    i["height"].as_u64().unwrap() as u16,
                    i["cell_size"].as_u64().unwrap() as u8,
                );
                assert_eq!(
                    got, expected_payload,
                    "vector {:?}: payload mismatch",
                    v.name
                );
                // parse_handshake_ack must succeed on the committed bytes.
                let parsed = parse_handshake_ack(&expected_payload)
                    .unwrap_or_else(|e| panic!("{:?}: parse failed: {e:?}", v.name));
                assert_eq!(parsed.fps, i["fps"].as_u64().unwrap() as u8);
                assert_eq!(parsed.width, i["width"].as_u64().unwrap() as u16);
            }
            "nak" => {
                let i = &v.inputs;
                let cqs = i["cqs"].as_f64().unwrap() as f32;
                let missing: Vec<u64> = i["missing"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_u64().unwrap())
                    .collect();
                let got = pack_nak(cqs, &missing);
                assert_eq!(
                    got, expected_payload,
                    "vector {:?}: payload mismatch",
                    v.name
                );
                let (gcqs, gmiss) = parse_nak(&expected_payload)
                    .unwrap_or_else(|e| panic!("{:?}: parse failed: {e:?}", v.name));
                assert!((gcqs - cqs).abs() < 1e-5, "nak: cqs mismatch");
                assert_eq!(gmiss, missing);
            }
            "slow_down" | "speed_up" => {
                // Empty payload.
                assert!(
                    expected_payload.is_empty(),
                    "vector {:?}: expected empty payload",
                    v.name
                );
            }
            "session_complete" => {
                let sid = v.inputs["session_id"].as_u64().unwrap();
                let got = pack_session_complete(sid);
                assert_eq!(
                    got, expected_payload,
                    "vector {:?}: payload mismatch",
                    v.name
                );
                assert_eq!(
                    parse_session_complete(&expected_payload).unwrap(),
                    sid,
                    "vector {:?}: parse mismatch",
                    v.name
                );
            }
            "alignment" => {
                let i = &v.inputs;
                let aqs = i["aqs"].as_f64().unwrap() as f32;
                let frame_num = i["frame_num"].as_u64().unwrap();
                let got = pack_alignment(aqs, frame_num);
                assert_eq!(
                    got, expected_payload,
                    "vector {:?}: payload mismatch",
                    v.name
                );
                let (gaqs, gfn) = parse_alignment(&expected_payload)
                    .unwrap_or_else(|e| panic!("{:?}: parse failed: {e:?}", v.name));
                assert!((gaqs - aqs).abs() < 1e-5, "alignment: aqs mismatch");
                assert_eq!(gfn, frame_num);
            }
            "degraded" => {
                let aqs = v.inputs["aqs"].as_f64().unwrap() as f32;
                let got = pack_degraded(aqs);
                assert_eq!(
                    got, expected_payload,
                    "vector {:?}: payload mismatch",
                    v.name
                );
                let gaqs = parse_degraded(&expected_payload)
                    .unwrap_or_else(|e| panic!("{:?}: parse failed: {e:?}", v.name));
                assert!((gaqs - aqs).abs() < 1e-5, "degraded: aqs mismatch");
            }
            "pause" => {
                let ld = v.inputs["last_decoded"].as_u64().unwrap();
                let got = pack_pause(ld);
                assert_eq!(
                    got, expected_payload,
                    "vector {:?}: payload mismatch",
                    v.name
                );
                assert_eq!(parse_pause(&expected_payload).unwrap(), ld);
            }
            "resume" => {
                let i = &v.inputs;
                let resume_from = i["resume_from"].as_u64().unwrap();
                let aqs = i["aqs"].as_f64().unwrap() as f32;
                let got = pack_resume(resume_from, aqs);
                assert_eq!(
                    got, expected_payload,
                    "vector {:?}: payload mismatch",
                    v.name
                );
                let (grf, gaqs) = parse_resume(&expected_payload)
                    .unwrap_or_else(|e| panic!("{:?}: parse failed: {e:?}", v.name));
                assert_eq!(grf, resume_from);
                assert!((gaqs - aqs).abs() < 1e-5, "resume: aqs mismatch");
            }
            "resumed" => {
                let fn_ = v.inputs["frame_num"].as_u64().unwrap();
                let got = pack_resumed(fn_);
                assert_eq!(
                    got, expected_payload,
                    "vector {:?}: payload mismatch",
                    v.name
                );
                assert_eq!(parse_resumed(&expected_payload).unwrap(), fn_);
            }
            "session_timeout" => {
                let sid = v.inputs["session_id"].as_u64().unwrap();
                let got = pack_session_timeout(sid);
                assert_eq!(
                    got, expected_payload,
                    "vector {:?}: payload mismatch",
                    v.name
                );
                assert_eq!(parse_session_timeout(&expected_payload).unwrap(), sid);
            }
            other => panic!("unknown message vector name: {other:?}"),
        }

        n_checked += 1;
    }

    assert_eq!(
        n_checked, 11,
        "expected 11 message vectors, got {n_checked}"
    );
}

// ─── Fountain conformance (tests/vectors/fountain.json) ───────────────────────

#[derive(Debug, serde::Deserialize)]
struct FountainVector {
    name: String,
    symbol_size: u16,
    transfer_length: u64,
    /// Hex-encoded original source bytes.
    source: String,
    /// Hex-encoded serialized RaptorQ EncodingPackets. The list is exactly k+repair long.
    packets: Vec<String>,
    /// Indices into `packets` that form a sufficient decoding subset (the K
    /// source symbols for these vectors).
    decoding_subset: Vec<usize>,
}

fn load_fountain_vectors() -> Vec<FountainVector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/fountain.json");
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read fountain.json at {path}: {e}"));
    serde_json::from_str(&raw).expect("fountain.json parse failed")
}

/// For each vector: (a) Rust encode produces the same byte-identical packet list
/// as the committed vector, (b) decoding the full packet list recovers the source,
/// (c) decoding using only the sufficient-subset indices recovers the source.
#[test]
fn fountain_conformance_vectors() {
    let vectors = load_fountain_vectors();
    assert!(
        !vectors.is_empty(),
        "fountain.json must have at least one vector"
    );

    for v in &vectors {
        let source = hex_decode(&v.source);
        assert_eq!(
            source.len() as u64,
            v.transfer_length,
            "vector {:?}: source length != transfer_length",
            v.name
        );

        let oracle_packets: Vec<Vec<u8>> = v.packets.iter().map(|h| hex_decode(h)).collect();

        // (a) Re-encode with the same symbol_size and DEFAULT_OVERHEAD; the
        // resulting byte list must be identical to the oracle's.
        let rust_packets = encode(&source, v.symbol_size, DEFAULT_OVERHEAD)
            .unwrap_or_else(|e| panic!("vector {:?}: encode failed: {e}", v.name));

        assert_eq!(
            rust_packets.len(),
            oracle_packets.len(),
            "vector {:?}: packet count mismatch (Rust {} vs oracle {})",
            v.name,
            rust_packets.len(),
            oracle_packets.len()
        );
        for (i, (got, want)) in rust_packets.iter().zip(oracle_packets.iter()).enumerate() {
            assert_eq!(got, want, "vector {:?}: packet[{i}] byte mismatch", v.name);
        }

        // (b) Decode the full oracle packet list → exact source.
        {
            let mut dec = Decoder::new(v.transfer_length, v.symbol_size)
                .unwrap_or_else(|e| panic!("vector {:?}: Decoder::new failed: {e}", v.name));
            let mut result: Option<Vec<u8>> = None;
            for pkt in &oracle_packets {
                result = dec.add(pkt);
                if result.is_some() {
                    break;
                }
            }
            assert_eq!(
                result.as_deref(),
                Some(source.as_slice()),
                "vector {:?}: full-packet-list decode failed",
                v.name
            );
        }

        // (c) Decode using only the sufficient-subset indices → exact source.
        {
            let mut dec = Decoder::new(v.transfer_length, v.symbol_size)
                .unwrap_or_else(|e| panic!("vector {:?}: Decoder::new failed: {e}", v.name));
            let mut result: Option<Vec<u8>> = None;
            for &idx in &v.decoding_subset {
                result = dec.add(&oracle_packets[idx]);
                if result.is_some() {
                    break;
                }
            }
            assert_eq!(
                result.as_deref(),
                Some(source.as_slice()),
                "vector {:?}: subset decode failed (subset={:?})",
                v.name,
                v.decoding_subset
            );
        }
    }
}

// ─── QR carrier conformance (tests/vectors/qr.json + tests/vectors/qr/*.png) ─
//
// Vector layout: qr.json contains one object with key "files". Each value is
// either a hex string (single QR code → expected bytes) or an array of hex
// strings (tiled image → set of expected wires, order-independent).
//
// Contract:
//   1. Each committed PNG decodes to the expected bytes (tiled: order-independent).
//   2. A Rust re-encode of each case's bytes decodes back.
//   DO NOT assert pixel equality - encoder versions may differ; the contract is
//   decodability.

#[derive(Debug, serde::Deserialize)]
struct QrVectorFiles {
    #[serde(rename = "max_wire.png")]
    max_wire: String,
    #[serde(rename = "small.png")]
    small: String,
    #[serde(rename = "tiled.png")]
    tiled: Vec<String>,
    #[serde(rename = "zero_run.png")]
    zero_run: String,
}

#[derive(Debug, serde::Deserialize)]
struct QrVectorOuter {
    files: QrVectorFiles,
}

fn load_qr_vectors() -> QrVectorFiles {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/qr.json");
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read qr.json at {path}: {e}"));
    let outer: Vec<QrVectorOuter> = serde_json::from_str(&raw).expect("qr.json parse failed");
    outer.into_iter().next().expect("qr.json is empty").files
}

fn load_png(name: &str) -> image::RgbImage {
    let path = format!("{}/tests/vectors/qr/{name}", env!("CARGO_MANIFEST_DIR"));
    let img = image::open(&path)
        .unwrap_or_else(|e| panic!("cannot open {path}: {e}"))
        .to_rgb8();
    img
}

/// Encode `data` at the default params (scale=8, border=4, ec="m") so
/// re-encoded images are decodable.
fn qr_encode_oracle(data: &[u8]) -> image::RgbImage {
    cypher::qr::encode(data, 8, 4, "m").unwrap_or_else(|e| panic!("qr::encode failed: {e}"))
}

/// QR conformance: every committed PNG decodes to its expected bytes; a
/// Rust re-encode of the expected bytes also decodes back.
#[test]
fn qr_conformance_vectors() {
    let files = load_qr_vectors();

    // ── small.png: single QR code ─────────────────────────────────────────────
    {
        let expected = hex_decode(&files.small);
        let img = load_png("small.png");
        let got =
            cypher::qr::decode(&img).expect("small.png: decode returned None (expected bytes)");
        assert_eq!(got, expected, "small.png: decoded bytes mismatch");

        // Re-encode and decode back (decodability contract, not pixel equality).
        let re_img = qr_encode_oracle(&expected);
        let re_got =
            cypher::qr::decode(&re_img).expect("small.png re-encode: decode returned None");
        assert_eq!(re_got, expected, "small.png re-encode: round-trip mismatch");
    }

    // ── zero_run.png: long zero run regression ────────────────────────────────
    {
        let expected = hex_decode(&files.zero_run);
        let img = load_png("zero_run.png");
        let got = cypher::qr::decode(&img).expect("zero_run.png: decode returned None");
        assert_eq!(got, expected, "zero_run.png: decoded bytes mismatch");

        let re_img = qr_encode_oracle(&expected);
        let re_got =
            cypher::qr::decode(&re_img).expect("zero_run.png re-encode: decode returned None");
        assert_eq!(
            re_got, expected,
            "zero_run.png re-encode: round-trip mismatch"
        );
    }

    // ── max_wire.png: MAX_WIRE bytes (per-frame budget) ───────────────────────
    {
        let expected = hex_decode(&files.max_wire);
        assert_eq!(
            expected.len(),
            cypher::qr::MAX_WIRE,
            "max_wire vector must be exactly MAX_WIRE bytes"
        );
        let img = load_png("max_wire.png");
        let got = cypher::qr::decode(&img).expect("max_wire.png: decode returned None");
        assert_eq!(got, expected, "max_wire.png: decoded bytes mismatch");

        let re_img = qr_encode_oracle(&expected);
        let re_got =
            cypher::qr::decode(&re_img).expect("max_wire.png re-encode: decode returned None");
        assert_eq!(
            re_got, expected,
            "max_wire.png re-encode: round-trip mismatch"
        );
    }

    // ── tiled.png: 2×2 grid of independent QR codes (tiling) ────────────────
    // The vector stores an array of hex strings - order-independent (fountain
    // packets are unordered; receiver decodes every code found).
    {
        let expected_wires: Vec<Vec<u8>> = files.tiled.iter().map(|h| hex_decode(h)).collect();
        let expected_set: std::collections::HashSet<&[u8]> =
            expected_wires.iter().map(|w| w.as_slice()).collect();

        let img = load_png("tiled.png");
        let decoded = cypher::qr::decode_all(&img);
        assert_eq!(
            decoded.len(),
            expected_wires.len(),
            "tiled.png: expected {} codes, got {}",
            expected_wires.len(),
            decoded.len()
        );
        let decoded_set: std::collections::HashSet<&[u8]> =
            decoded.iter().map(|w| w.as_slice()).collect();
        assert_eq!(
            decoded_set, expected_set,
            "tiled.png: decoded wire set mismatch (order-independent)"
        );

        // Re-encode each wire and verify it decodes back.
        for (i, wire) in expected_wires.iter().enumerate() {
            let re_img = qr_encode_oracle(wire);
            let re_got = cypher::qr::decode(&re_img)
                .unwrap_or_else(|| panic!("tiled.png wire[{i}] re-encode: decode returned None"));
            assert_eq!(
                re_got, *wire,
                "tiled.png wire[{i}] re-encode: round-trip mismatch"
            );
        }
    }
}

// ─── Broadcast frames conformance (tests/vectors/broadcast_frames.json) ──────
//
// Each vector: an array of wire-hex DATA frames (first hex is the BEACON,
// rest are fountain DATA frames), the PSK as hex, session_id, symbol_size,
// timestamp_ms, packet_count, and the expected reconstructed payload as hex.
//
// Contract:
//   1. Feed every wire hex (in order) through BroadcastReceiver::on_codes.
//   2. After all frames: receiver.complete == true.
//   3. receiver.data() == expected payload.
//   4. receiver.session_id == vector session_id (from the BEACON).
//   5. receiver.symbol_size() == vector symbol_size.

#[derive(Debug, serde::Deserialize)]
struct BroadcastFrameVector {
    /// Wire-hex frames: frames[0] is the BEACON, frames[1..] are DATA.
    frames: Vec<String>,
    #[allow(dead_code)]
    // JSON field present; not asserted - frame count is implicit in frames.len()
    packet_count: usize,
    /// Hex-encoded reconstructed payload.
    payload: String,
    /// Hex-encoded 32-byte PSK.
    psk: String,
    session_id: u64,
    symbol_size: usize,
    timestamp_ms: u64,
}

fn load_broadcast_frame_vectors() -> Vec<BroadcastFrameVector> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/broadcast_frames.json"
    );
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read broadcast_frames.json at {path}: {e}"));
    serde_json::from_str(&raw).expect("broadcast_frames.json parse failed")
}

/// Broadcast conformance: for each vector, feed all wire frames through
/// BroadcastReceiver::on_codes and assert completion, correct payload, correct
/// session params.
#[test]
fn broadcast_frames_conformance_vectors() {
    let vectors = load_broadcast_frame_vectors();
    assert!(
        !vectors.is_empty(),
        "broadcast_frames.json must have at least one vector"
    );

    for v in &vectors {
        let psk: [u8; 32] = hex_decode(&v.psk).try_into().unwrap_or_else(|_| {
            panic!(
                "broadcast vector: psk must be 32 bytes, got {}",
                v.psk.len() / 2
            )
        });
        let expected_payload = hex_decode(&v.payload);
        let ts_s = v.timestamp_ms as f64 / 1000.0;

        // The receiver uses an injected clock equal to the vector timestamp so
        // the ±5-minute staleness window is satisfied.
        let mut receiver = cypher::session::BroadcastReceiver::new(
            psk,
            None,
            "oracle",
            true,
            None,
            Box::new(move || ts_s),
        );

        // Decode each frame wire hex → raw bytes → feed as a single-element
        // on_codes call (per-frame delivery model).
        for (i, frame_hex) in v.frames.iter().enumerate() {
            let wire = hex_decode(frame_hex);
            let status = receiver.on_codes(vec![wire]).unwrap_or_else(|e| {
                panic!("broadcast vector: frame[{i}] on_codes returned err: {e:?}")
            });
            // Status must be a known value (not an unexpected error variant).
            assert!(
                matches!(
                    status.as_str(),
                    "beacon-accepted"
                        | "stored"
                        | "complete"
                        | "buffered"
                        | "duplicate"
                        | "ignored-duplicate"
                        | "ignored-stale"
                        | "ignored-replay"
                ),
                "broadcast vector: frame[{i}] unexpected status {status:?}"
            );
        }

        // After all frames: must be complete.
        assert!(
            receiver.complete,
            "broadcast vector: receiver must complete after all {} frames",
            v.frames.len()
        );

        // Payload must match the vector exactly.
        let got = receiver
            .data()
            .unwrap_or_else(|e| panic!("broadcast vector: data() failed: {e:?}"));
        assert_eq!(
            got, expected_payload,
            "broadcast vector: data() != expected payload"
        );

        // Session params from the BEACON must match.
        assert_eq!(
            receiver.session_id,
            Some(v.session_id),
            "broadcast vector: session_id mismatch"
        );
        assert_eq!(
            receiver.symbol_size(),
            Some(v.symbol_size),
            "broadcast vector: symbol_size mismatch"
        );
    }
}

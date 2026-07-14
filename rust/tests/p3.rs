// Phase 3 integration tests - beacon, messages, TOFU.
// RECEIVER_BEACON codec and codec-level reverse-beacon cases are included;
// session/QR-dependent cases are deferred (see SKIPPED section at the bottom).

// ─── Beacon ───────────────────────────────────────────────────────────────────

mod beacon {
    use ed25519_dalek::SigningKey;
    use cypher::beacon::{
        build_payload, parse_payload, Beacon, BeaconError, FRAME_CELLS, LEVEL_OPEN, LEVEL_PAIRED,
        LEVEL_PSK, LEVEL_TOFU, LEVEL_WHITELIST, ZERO16, ZERO32,
    };
    use cypher::crypto::{
        ephemeral_public_bytes, generate_ephemeral, generate_identity, identity_public_bytes,
    };

    // Fixed timestamp from the vector (ms).
    const TS: u64 = 1_750_000_000_000;

    fn make_signing_key() -> SigningKey {
        let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
        SigningKey::from_bytes(&seed)
    }

    fn make_beacon_default() -> (Beacon, SigningKey) {
        let ident = make_signing_key();
        let eph = generate_ephemeral();
        let b = Beacon::new(
            0xC0FF_EE11_2233_4455_u64,
            TS,
            LEVEL_TOFU,
            std::array::from_fn(|i| i as u8), // intended_receiver (32B)
            ZERO32,
            ephemeral_public_bytes(&eph),
            identity_public_bytes(&ident),
            1920,
            1080,
            30,
            4,
            1_000_000,
            "myfile.bin".into(),
            ZERO16,
            FRAME_CELLS,
            214,
            987_654,
        )
        .unwrap();
        (b, ident)
    }

    /// parse_payload must recover all Beacon fields from build_payload.
    #[test]
    fn beacon_round_trip() {
        let (b, ident) = make_beacon_default();
        let payload = build_payload(&b, &ident, 1);
        let parsed = parse_payload(&payload).unwrap();
        assert_eq!(parsed, b);
    }

    /// Empty name is valid and round-trips.
    #[test]
    fn beacon_round_trip_empty_name() {
        let ident = make_signing_key();
        let eph = generate_ephemeral();
        let b = Beacon::new(
            0,
            TS,
            LEVEL_OPEN,
            ZERO32,
            ZERO32,
            ephemeral_public_bytes(&eph),
            identity_public_bytes(&ident),
            0,
            0,
            0,
            1,
            0,
            "".into(),
            ZERO16,
            FRAME_CELLS,
            0,
            0,
        )
        .unwrap();
        let payload = build_payload(&b, &ident, 1);
        assert_eq!(parse_payload(&payload).unwrap(), b);
    }

    /// Max-length name (255 bytes) is valid and round-trips.
    #[test]
    fn beacon_round_trip_max_name() {
        let ident = make_signing_key();
        let eph = generate_ephemeral();
        let name = "x".repeat(255);
        let b = Beacon::new(
            0,
            TS,
            LEVEL_OPEN,
            ZERO32,
            ZERO32,
            ephemeral_public_bytes(&eph),
            identity_public_bytes(&ident),
            0,
            0,
            0,
            1,
            0,
            name,
            ZERO16,
            FRAME_CELLS,
            0,
            0,
        )
        .unwrap();
        let payload = build_payload(&b, &ident, 1);
        assert_eq!(parse_payload(&payload).unwrap(), b);
    }

    /// UTF-8 multibyte name round-trips.
    #[test]
    fn beacon_round_trip_utf8_name() {
        let ident = make_signing_key();
        let eph = generate_ephemeral();
        let name = "sp\u{00e9}c.md \u{4e16}\u{754c}"; // "spéc.md 世界"
        let b = Beacon::new(
            0,
            TS,
            LEVEL_OPEN,
            ZERO32,
            ZERO32,
            ephemeral_public_bytes(&eph),
            identity_public_bytes(&ident),
            0,
            0,
            0,
            1,
            0,
            name.into(),
            ZERO16,
            FRAME_CELLS,
            0,
            0,
        )
        .unwrap();
        let payload = build_payload(&b, &ident, 1);
        assert_eq!(parse_payload(&payload).unwrap(), b);
    }

    /// VERSION is the first transmitted byte of the payload.
    #[test]
    fn p16_version_is_first_byte_and_equals_one() {
        let (b, ident) = make_beacon_default();
        let payload = build_payload(&b, &ident, 1);
        assert_eq!(payload[0], 1);
    }

    /// Unknown major version must be rejected even when correctly signed.
    #[test]
    fn p16_unknown_major_rejected_even_when_correctly_signed() {
        let (b, ident) = make_beacon_default();
        let payload = build_payload(&b, &ident, 2);
        assert!(parse_payload(&payload).is_err());
    }

    /// Tampering byte 0 (VERSION) must be rejected.
    #[test]
    fn p16_tampered_version_byte_rejected() {
        let (b, ident) = make_beacon_default();
        let mut payload = build_payload(&b, &ident, 1);
        payload[0] ^= 0xFF;
        assert!(parse_payload(&payload).is_err());
    }

    /// Tampering SESSION_ID (byte 1, first byte after VERSION) must break IDENTITY_SIG.
    /// IDENTITY_SIG covers all fields preceding it.
    #[test]
    fn beacon_sig_binds_session_id() {
        let (b, ident) = make_beacon_default();
        let mut payload = build_payload(&b, &ident, 1);
        payload[1] ^= 0x01; // inside SESSION_ID at offset 1 (after leading VERSION)
        assert_eq!(
            parse_payload(&payload).unwrap_err(),
            BeaconError::InvalidSignature
        );
    }

    /// Tampering offset 146 (MAX_RESOLUTION / WIDTH) must break IDENTITY_SIG -
    /// confirms capability fields are covered.
    #[test]
    fn beacon_sig_covers_capabilities_offset_146() {
        let (b, ident) = make_beacon_default();
        let mut payload = build_payload(&b, &ident, 1);
        payload[146] ^= 0x01; // inside MAX_RESOLUTION (WIDTH first byte at 146)
        assert_eq!(
            parse_payload(&payload).unwrap_err(),
            BeaconError::InvalidSignature
        );
    }

    /// The echoed RECEIVER_SESSION_TOKEN is inside IDENTITY_SIG coverage.
    /// Its last byte is at offset -66 from the end (FIXED_LEN layout: sig 64B + FRAME_CELLS 1B + last-token-byte 1B = 66).
    #[test]
    fn beacon_sig_covers_receiver_session_token_tail() {
        let ident = make_signing_key();
        let eph = generate_ephemeral();
        let token: [u8; 16] = std::array::from_fn(|i| i as u8);
        let b = Beacon::new(
            0xC0FF_EE11_2233_4455_u64,
            TS,
            LEVEL_TOFU,
            std::array::from_fn(|i| i as u8),
            ZERO32,
            ephemeral_public_bytes(&eph),
            identity_public_bytes(&ident),
            1920,
            1080,
            30,
            4,
            1_000_000,
            "myfile.bin".into(),
            token,
            FRAME_CELLS,
            214,
            987_654,
        )
        .unwrap();
        let mut payload = build_payload(&b, &ident, 1);
        let len = payload.len();
        payload[len - 66] ^= 0x01; // last byte of RECEIVER_SESSION_TOKEN
        assert_eq!(
            parse_payload(&payload).unwrap_err(),
            BeaconError::InvalidSignature
        );
    }

    /// Signing with the wrong identity key must fail signature verification.
    #[test]
    fn beacon_wrong_identity_key_fails() {
        let (b, _correct_ident) = make_beacon_default();
        let wrong_ident = generate_identity();
        // signed by wrong key, but IDENTITY_PUB inside payload is the original
        let payload = build_payload(&b, &wrong_ident, 1);
        assert_eq!(
            parse_payload(&payload).unwrap_err(),
            BeaconError::InvalidSignature
        );
    }

    /// SESSION_LEVEL 5 is out of range (0–4 defined).
    #[test]
    fn beacon_bad_session_level_rejected() {
        let ident = make_signing_key();
        let eph = generate_ephemeral();
        let result = Beacon::new(
            0,
            TS,
            5,
            ZERO32,
            ZERO32,
            ephemeral_public_bytes(&eph),
            identity_public_bytes(&ident),
            0,
            0,
            0,
            1,
            0,
            "".into(),
            ZERO16,
            FRAME_CELLS,
            0,
            0,
        );
        assert!(matches!(result, Err(BeaconError::BadSessionLevel(5))));
    }

    /// CELL_SIZE of 0 is invalid.
    #[test]
    fn beacon_cell_size_zero_rejected() {
        let ident = make_signing_key();
        let eph = generate_ephemeral();
        let result = Beacon::new(
            0,
            TS,
            LEVEL_OPEN,
            ZERO32,
            ZERO32,
            ephemeral_public_bytes(&eph),
            identity_public_bytes(&ident),
            0,
            0,
            0,
            0,
            0,
            "".into(),
            ZERO16,
            FRAME_CELLS,
            0,
            0,
        );
        assert!(matches!(result, Err(BeaconError::BadCellSize(0))));
    }

    /// TRANSFER_NAME > 255 bytes is rejected.
    #[test]
    fn beacon_name_too_long_rejected() {
        let ident = make_signing_key();
        let eph = generate_ephemeral();
        let result = Beacon::new(
            0,
            TS,
            LEVEL_OPEN,
            ZERO32,
            ZERO32,
            ephemeral_public_bytes(&eph),
            identity_public_bytes(&ident),
            0,
            0,
            0,
            1,
            0,
            "x".repeat(256),
            ZERO16,
            FRAME_CELLS,
            0,
            0,
        );
        assert!(matches!(result, Err(BeaconError::NameTooLong)));
    }

    /// Payload truncated by 1 byte must be rejected.
    #[test]
    fn beacon_truncated_by_one_rejected() {
        let (b, ident) = make_beacon_default();
        let payload = build_payload(&b, &ident, 1);
        let truncated = &payload[..payload.len() - 1];
        assert!(parse_payload(truncated).is_err());
    }

    /// Severely truncated payload (first 100 bytes) must be rejected.
    #[test]
    fn beacon_truncated_to_100_rejected() {
        let (b, ident) = make_beacon_default();
        let payload = build_payload(&b, &ident, 1);
        assert!(parse_payload(&payload[..100]).is_err());
    }

    /// TRANSFER_NAME with invalid UTF-8 bytes must be rejected.
    #[test]
    fn beacon_bad_utf8_name_rejected() {
        let (b, ident) = make_beacon_default();
        let mut payload = build_payload(&b, &ident, 1);
        // Overwrite the first byte of TRANSFER_NAME (offset 167, the name's
        // start) with 0xFF (not valid UTF-8). The name_len byte is at offset 166.
        // Note: this also breaks the signature, but the UTF-8 check fires first
        // in parse_payload's order (after length/version checks but before sig
        // verification). Either error is acceptable - the contract says rejected.
        let name_len_offset = 166;
        let name_start = name_len_offset + 1;
        payload[name_start] = 0xFF;
        // May raise NameNotUtf8 or InvalidSignature - both are correct rejections.
        assert!(parse_payload(&payload).is_err());
    }

    /// Level constants must have the specified values.
    #[test]
    fn beacon_level_constants() {
        assert_eq!(LEVEL_OPEN, 0);
        assert_eq!(LEVEL_TOFU, 1);
        assert_eq!(LEVEL_PAIRED, 2);
        assert_eq!(LEVEL_WHITELIST, 3);
        assert_eq!(LEVEL_PSK, 4);
    }

    /// All five level constants are distinct.
    #[test]
    fn beacon_level_constants_distinct() {
        let levels = [
            LEVEL_OPEN,
            LEVEL_TOFU,
            LEVEL_PAIRED,
            LEVEL_WHITELIST,
            LEVEL_PSK,
        ];
        let unique: std::collections::HashSet<u8> = levels.iter().copied().collect();
        assert_eq!(unique.len(), levels.len());
    }

    /// Open session has INTENDED_RECEIVER = ZERO32; must round-trip.
    #[test]
    fn beacon_open_session_zero_intended_receiver() {
        let ident = make_signing_key();
        let eph = generate_ephemeral();
        let b = Beacon::new(
            0,
            TS,
            LEVEL_OPEN,
            ZERO32,
            ZERO32,
            ephemeral_public_bytes(&eph),
            identity_public_bytes(&ident),
            0,
            0,
            0,
            1,
            0,
            "".into(),
            ZERO16,
            FRAME_CELLS,
            0,
            0,
        )
        .unwrap();
        let payload = build_payload(&b, &ident, 1);
        let parsed = parse_payload(&payload).unwrap();
        assert_eq!(parsed.intended_receiver, ZERO32);
    }
}

// ─── RECEIVER_BEACON ─────────────────────────────────────────────────────────

mod receiver_beacon {
    use crc::{Crc, CRC_16_IBM_3740};
    use cypher::beacon::{
        build_receiver_beacon_with_token, parse_receiver_beacon, BeaconError, RECEIVER_BEACON_LEN,
    };
    use cypher::crypto::{generate_identity, identity_public_bytes};

    // Byte offsets for the RECEIVER_BEACON wire layout.
    const OFF_IDENTITY: usize = 5;
    const OFF_CAPS: usize = 53;
    const OFF_CRC: usize = 133;
    const BEACON_TOTAL: usize = 135;

    // Fixed clock: returns the same second every call.
    fn clock_at(t: f64) -> impl Fn() -> f64 {
        move || t
    }

    const T0: f64 = 1_750_000_000.0; // arbitrary fixed Unix seconds

    /// RECEIVER_BEACON is exactly 135 bytes.
    #[test]
    fn receiver_beacon_wire_length_is_135() {
        assert_eq!(RECEIVER_BEACON_LEN, BEACON_TOTAL);
        let ident = generate_identity();
        let caps = [0u8; 8];
        let token = [0u8; 16];
        let wire = build_receiver_beacon_with_token(&ident, &caps, &token, clock_at(T0));
        assert_eq!(wire.len(), BEACON_TOTAL);
    }

    /// Magic bytes are "RBEA" (0x52424541) at offsets 0–3.
    #[test]
    fn receiver_beacon_magic_bytes() {
        let ident = generate_identity();
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &[0u8; 16], clock_at(T0));
        assert_eq!(&wire[0..4], b"RBEA");
        assert_eq!(
            u32::from_be_bytes(wire[0..4].try_into().unwrap()),
            0x5242_4541u32
        );
    }

    /// VERSION byte at offset 4 must be 1.
    #[test]
    fn receiver_beacon_version_field_is_one() {
        let ident = generate_identity();
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &[0u8; 16], clock_at(T0));
        assert_eq!(wire[4], 1);
    }

    /// Round-trip - identity_pub, session_token, capabilities, timestamp must survive build → parse.
    #[test]
    fn receiver_beacon_round_trip_all_fields() {
        let ident = generate_identity();
        let caps: [u8; 8] = std::array::from_fn(|i| i as u8);
        let token: [u8; 16] = std::array::from_fn(|i| i as u8);
        let wire = build_receiver_beacon_with_token(&ident, &caps, &token, clock_at(T0));
        let parsed = parse_receiver_beacon(&wire, clock_at(T0)).unwrap();
        assert_eq!(parsed.identity_pub, identity_public_bytes(&ident));
        assert_eq!(parsed.session_token, token);
        assert_eq!(parsed.capabilities, caps);
        assert_eq!(parsed.timestamp_ms, (T0 * 1000.0) as u64);
    }

    /// Tampering RECEIVER_CAPABILITIES (offset 53) must fail -
    /// the CRC-16 or Ed25519 sig catches it.
    #[test]
    fn receiver_beacon_tamper_capabilities_fails() {
        let ident = generate_identity();
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &[0u8; 16], clock_at(T0));
        let mut bad = wire.clone();
        bad[OFF_CAPS] ^= 0x01;
        assert!(parse_receiver_beacon(&bad, clock_at(T0)).is_err());
    }

    /// Tampering the CRC-16 field (offsets 133–134) must fail with ReceiverCrcMismatch.
    #[test]
    fn receiver_beacon_tamper_crc_fails() {
        let ident = generate_identity();
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &[0u8; 16], clock_at(T0));
        let mut bad = wire.clone();
        bad[OFF_CRC] ^= 0xFF;
        assert_eq!(
            parse_receiver_beacon(&bad, clock_at(T0)).unwrap_err(),
            BeaconError::ReceiverCrcMismatch
        );
    }

    /// Truncated by one byte must be rejected (ReceiverWrongLength).
    #[test]
    fn receiver_beacon_truncated_fails() {
        let ident = generate_identity();
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &[0u8; 16], clock_at(T0));
        let truncated = &wire[..wire.len() - 1];
        assert_eq!(
            parse_receiver_beacon(truncated, clock_at(T0)).unwrap_err(),
            BeaconError::ReceiverWrongLength
        );
    }

    /// Wrong MAGIC bytes must be rejected (ReceiverBadMagic).
    #[test]
    fn receiver_beacon_wrong_magic_fails() {
        let ident = generate_identity();
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &[0u8; 16], clock_at(T0));
        let mut bad = wire.clone();
        bad[0..4].copy_from_slice(b"XXXX");
        assert_eq!(
            parse_receiver_beacon(&bad, clock_at(T0)).unwrap_err(),
            BeaconError::ReceiverBadMagic
        );
    }

    /// Stale timestamp (>300 s outside the ±300 000 ms window) must be rejected (ReceiverStale).
    /// Build at T0, parse at T0+301.
    #[test]
    fn receiver_beacon_stale_timestamp_fails() {
        let ident = generate_identity();
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &[0u8; 16], clock_at(T0));
        // 301 seconds later: outside the ±300 s window.
        assert_eq!(
            parse_receiver_beacon(&wire, clock_at(T0 + 301.0)).unwrap_err(),
            BeaconError::ReceiverStale
        );
    }

    /// Timestamp exactly at the boundary (300 s) is still rejected
    /// (abs_diff >= RECEIVER_WINDOW_MS triggers the error).
    #[test]
    fn receiver_beacon_exactly_at_boundary_fails() {
        let ident = generate_identity();
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &[0u8; 16], clock_at(T0));
        assert_eq!(
            parse_receiver_beacon(&wire, clock_at(T0 + 300.0)).unwrap_err(),
            BeaconError::ReceiverStale
        );
    }

    /// Timestamp one millisecond inside the window must be accepted.
    #[test]
    fn receiver_beacon_just_inside_window_accepted() {
        let ident = generate_identity();
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &[0u8; 16], clock_at(T0));
        // 299.999 s: abs_diff < 300_000 ms.
        assert!(parse_receiver_beacon(&wire, clock_at(T0 + 299.999)).is_ok());
    }

    /// Replacing the RECEIVER_IDENTITY_KEY field and recomputing the CRC-16
    /// must still fail on Ed25519 signature verification (ReceiverInvalidSignature).
    #[test]
    fn receiver_beacon_tamper_identity_key_with_recrc_fails_sig() {
        let ident = generate_identity();
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &[0u8; 16], clock_at(T0));
        let other = generate_identity();
        let mut bad = wire.clone();
        bad[OFF_IDENTITY..OFF_IDENTITY + 32].copy_from_slice(&identity_public_bytes(&other));
        // Recompute CRC so the CRC check passes.
        let crc: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_3740);
        let new_crc = crc.checksum(&bad[..OFF_CRC]);
        bad[OFF_CRC..OFF_CRC + 2].copy_from_slice(&new_crc.to_be_bytes());
        // Only the Ed25519 sig check can catch this.
        assert_eq!(
            parse_receiver_beacon(&bad, clock_at(T0)).unwrap_err(),
            BeaconError::ReceiverInvalidSignature
        );
    }
}

// ─── Messages ────────────────────────────────────────────────────────────────

mod messages {
    use cypher::messages::{
        pack_alignment, pack_degraded, pack_handshake_ack, pack_nak, pack_pause, pack_resume,
        pack_resumed, pack_session_complete, pack_session_timeout, parse_alignment, parse_degraded,
        parse_handshake_ack, parse_nak, parse_pause, parse_resume, parse_resumed,
        parse_session_complete, parse_session_timeout, MessageError, ALIGNMENT, DEGRADED,
        HANDSHAKE_ACK, NAK, PAUSE, RESUME, RESUMED, SESSION_COMPLETE, SESSION_TIMEOUT, SLOW_DOWN,
        SPEED_UP,
    };

    /// All 11 message type IDs must be distinct.
    #[test]
    fn message_type_ids_are_distinct() {
        let ids = [
            HANDSHAKE_ACK,
            NAK,
            SLOW_DOWN,
            SPEED_UP,
            SESSION_COMPLETE,
            ALIGNMENT,
            DEGRADED,
            PAUSE,
            RESUME,
            RESUMED,
            SESSION_TIMEOUT,
        ];
        let unique: std::collections::HashSet<u8> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len());
    }

    /// HANDSHAKE_ACK round-trip - all fields survive pack → parse.
    #[test]
    fn handshake_ack_round_trip() {
        let eph: [u8; 32] = std::array::from_fn(|i| i as u8);
        let id: [u8; 32] = std::array::from_fn(|i| (i + 32) as u8);
        let payload = pack_handshake_ack(&eph, &id, 30, 1920, 1080, 4);
        let parsed = parse_handshake_ack(&payload).unwrap();
        assert_eq!(parsed.ephemeral_pub, eph);
        assert_eq!(parsed.identity_pub, id);
        assert_eq!(parsed.fps, 30);
        assert_eq!(parsed.width, 1920);
        assert_eq!(parsed.height, 1080);
        assert_eq!(parsed.cell_size, 4);
    }

    /// HANDSHAKE_ACK truncated by 1 byte must be rejected (WrongSize).
    #[test]
    fn handshake_ack_truncated_rejected() {
        let eph = [0u8; 32];
        let id = [0u8; 32];
        let payload = pack_handshake_ack(&eph, &id, 30, 1920, 1080, 4);
        let truncated = &payload[..payload.len() - 1];
        assert!(parse_handshake_ack(truncated).is_err());
    }

    /// HANDSHAKE_ACK one byte too long must be rejected (WrongSize).
    #[test]
    fn handshake_ack_too_long_rejected() {
        let eph = [0u8; 32];
        let id = [0u8; 32];
        let mut payload = pack_handshake_ack(&eph, &id, 30, 1920, 1080, 4);
        payload.push(0);
        assert!(parse_handshake_ack(&payload).is_err());
    }

    /// NAK round-trip - CQS and missing frame numbers survive.
    #[test]
    fn nak_round_trip() {
        let missing: Vec<u64> = vec![3, 7, 1 << 63];
        let payload = pack_nak(0.875, &missing);
        let (cqs, got) = parse_nak(&payload).unwrap();
        assert!((cqs - 0.875f32).abs() < 1e-6);
        assert_eq!(got, missing);
    }

    /// NAK with empty missing list is valid.
    #[test]
    fn nak_empty_missing_list() {
        let (cqs, missing) = parse_nak(&pack_nak(1.0, &[])).unwrap();
        assert!((cqs - 1.0f32).abs() < 1e-6);
        assert!(missing.is_empty());
    }

    /// NAK payload of 7 bytes (not f32 + n*u64) must be rejected.
    #[test]
    fn nak_bad_length_rejected() {
        assert!(parse_nak(&[0u8; 7]).is_err());
    }

    /// NAK payload of 3 bytes (< 4) must be rejected.
    #[test]
    fn nak_too_short_rejected() {
        assert!(matches!(parse_nak(&[0u8; 3]), Err(MessageError::BadNak)));
    }

    /// SESSION_COMPLETE round-trip - session_id survives.
    #[test]
    fn session_complete_round_trip() {
        let sid = 0xDEAD_BEEF_0011_2233u64;
        assert_eq!(
            parse_session_complete(&pack_session_complete(sid)).unwrap(),
            sid
        );
    }

    /// SESSION_COMPLETE with 7 bytes (not 8) must be rejected.
    #[test]
    fn session_complete_wrong_size_rejected() {
        assert!(parse_session_complete(&[0u8; 7]).is_err());
    }

    /// ALIGNMENT: aqs (f32) + frame_num (u64), 12 bytes, round-trips.
    #[test]
    fn alignment_round_trip() {
        let (aqs, frame) = parse_alignment(&pack_alignment(0.75, 42)).unwrap();
        assert!((aqs - 0.75f32).abs() < 1e-6);
        assert_eq!(frame, 42);
    }

    /// DEGRADED: aqs (f32), 4 bytes, round-trips.
    #[test]
    fn degraded_round_trip() {
        let aqs = parse_degraded(&pack_degraded(0.5)).unwrap();
        assert!((aqs - 0.5f32).abs() < 1e-6);
    }

    /// PAUSE: last_decoded (u64), 8 bytes, round-trips.
    #[test]
    fn pause_round_trip() {
        assert_eq!(parse_pause(&pack_pause(99)).unwrap(), 99);
    }

    /// RESUME: resume_from (u64) + aqs (f32), 12 bytes, round-trips.
    #[test]
    fn resume_round_trip() {
        let (resume_from, aqs) = parse_resume(&pack_resume(100, 0.9)).unwrap();
        assert_eq!(resume_from, 100);
        assert!((aqs - 0.9f32).abs() < 1e-6);
    }

    /// RESUMED: frame_num (u64), 8 bytes, round-trips.
    #[test]
    fn resumed_round_trip() {
        assert_eq!(parse_resumed(&pack_resumed(101)).unwrap(), 101);
    }

    /// SESSION_TIMEOUT: session_id (u64), 8 bytes, round-trips.
    #[test]
    fn session_timeout_round_trip() {
        let sid = 0xDEAD_BEEF_0011_2233u64;
        assert_eq!(
            parse_session_timeout(&pack_session_timeout(sid)).unwrap(),
            sid
        );
    }

    /// ALIGNMENT must reject payloads of wrong size (exactly 12 required).
    #[test]
    fn alignment_size_enforcement() {
        assert!(parse_alignment(&[0u8; 13]).is_err());
        assert!(parse_alignment(&[0u8; 11]).is_err());
    }

    /// DEGRADED must reject payloads of wrong size (exactly 4 required).
    #[test]
    fn degraded_size_enforcement() {
        assert!(parse_degraded(&[0u8; 5]).is_err());
        assert!(parse_degraded(&[0u8; 3]).is_err());
    }

    /// PAUSE must reject payloads of wrong size (exactly 8 required).
    #[test]
    fn pause_size_enforcement() {
        assert!(parse_pause(&[0u8; 9]).is_err());
    }

    /// RESUME must reject payloads of wrong size (exactly 12 required).
    #[test]
    fn resume_size_enforcement() {
        assert!(parse_resume(&[0u8; 13]).is_err());
    }

    /// RESUMED must reject payloads of wrong size (exactly 8 required).
    #[test]
    fn resumed_size_enforcement() {
        assert!(parse_resumed(&[0u8; 9]).is_err());
    }

    /// SESSION_TIMEOUT must reject payloads of wrong size (exactly 8 required).
    #[test]
    fn session_timeout_size_enforcement() {
        assert!(parse_session_timeout(&[0u8; 9]).is_err());
    }

    /// sign_message → open_message round-trip must recover type and payload.
    #[test]
    fn signed_envelope_round_trip() {
        use cypher::crypto::{
            generate_identity, identity_public_bytes, open_message, sign_message,
        };
        let ident = generate_identity();
        let pub_bytes = identity_public_bytes(&ident);
        let nak_payload = pack_nak(0.9, &[5]);
        let wire = sign_message(&ident, NAK, &nak_payload);
        let (msg_type, payload) = open_message(pub_bytes, &wire).unwrap();
        assert_eq!(msg_type, NAK);
        let (cqs, missing) = parse_nak(&payload).unwrap();
        assert!((cqs - 0.9f32).abs() < 1e-6);
        assert_eq!(missing, vec![5u64]);
    }

    /// open_message with wrong public key must return None (silent reject).
    #[test]
    fn signed_envelope_wrong_key_rejected() {
        use cypher::crypto::{
            generate_identity, identity_public_bytes, open_message, sign_message,
        };
        let ident = generate_identity();
        let wrong = generate_identity();
        let wire = sign_message(&ident, NAK, &pack_nak(0.9, &[5]));
        assert!(open_message(identity_public_bytes(&wrong), &wire).is_none());
    }
}

// ─── TOFU ────────────────────────────────────────────────────────────────────

mod tofu {
    use cypher::tofu::{TrustStatus, TrustStore};
    use std::path::PathBuf;

    // Each test gets its own subdirectory keyed on the thread name so parallel
    // runs don't collide. Cleaned up automatically by the OS on next boot.
    fn tmp() -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("unnamed");
        // Sanitize the thread name for use in a path component.
        let safe: String = name
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect();
        let dir = std::env::temp_dir()
            .join("cypher_tofu_tests")
            .join(format!("{safe}_{nanos}"));
        std::fs::create_dir_all(&dir).expect("create tmp dir");
        dir
    }

    const KEY_A: [u8; 32] = {
        let mut k = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            k[i] = i as u8;
            i += 1;
        }
        k
    };
    const KEY_B: [u8; 32] = {
        let mut k = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            k[i] = (i + 32) as u8;
            i += 1;
        }
        k
    };

    /// TOFU first-use flow: new peer → status "New", verify returns false, trust makes it Trusted.
    #[test]
    fn tofu_first_use_flow() {
        let dir = tmp();
        let mut store = TrustStore::new(dir.join("trust.json")).unwrap();
        assert_eq!(store.status("laptop", &KEY_A), TrustStatus::New);
        assert!(!store.verify("laptop", &KEY_A).unwrap());
        store.trust("laptop", &KEY_A).unwrap();
        assert_eq!(store.status("laptop", &KEY_A), TrustStatus::Trusted);
        assert!(store.verify("laptop", &KEY_A).unwrap());
    }

    /// Changed key → status "Changed", verify raises KeyChangedError (hard fail).
    #[test]
    fn tofu_changed_key_hard_fails() {
        let dir = tmp();
        let mut store = TrustStore::new(dir.join("trust.json")).unwrap();
        store.trust("laptop", &KEY_A).unwrap();
        assert_eq!(store.status("laptop", &KEY_B), TrustStatus::Changed);
        let result = store.verify("laptop", &KEY_B);
        assert!(result.is_err());
        // Must be KeyChangedError with the correct peer name.
        let err = result.unwrap_err();
        assert_eq!(err.peer, "laptop");
    }

    /// Explicit re-approval (trust with new key) allows verify to succeed.
    #[test]
    fn tofu_explicit_reapproval_after_change() {
        let dir = tmp();
        let mut store = TrustStore::new(dir.join("trust.json")).unwrap();
        store.trust("laptop", &KEY_A).unwrap();
        store.trust("laptop", &KEY_B).unwrap(); // explicit re-approval
        assert!(store.verify("laptop", &KEY_B).unwrap());
    }

    /// Trust store persists across TrustStore instances (file-backed).
    #[test]
    fn tofu_persists_across_instances() {
        let dir = tmp();
        let path = dir.join("trust.json");
        TrustStore::new(&path)
            .unwrap()
            .trust("laptop", &KEY_A)
            .unwrap();
        assert!(TrustStore::new(&path)
            .unwrap()
            .verify("laptop", &KEY_A)
            .unwrap());
    }

    /// A fresh store (no file) treats every peer as New.
    #[test]
    fn tofu_missing_file_starts_empty() {
        let dir = tmp();
        let store = TrustStore::new(dir.join("nonexistent.json")).unwrap();
        assert_eq!(store.status("laptop", &KEY_A), TrustStatus::New);
    }

    /// Reads a JSON file in the format {"peer": "hex64chars"}.
    #[test]
    fn tofu_reads_python_format_json() {
        let dir = tmp();
        let path = dir.join("trust.json");
        let hex_key: String = KEY_A.iter().map(|b| format!("{b:02x}")).collect();
        let json = format!("{{\"laptop\": \"{hex_key}\"}}");
        std::fs::write(&path, json).unwrap();
        let store = TrustStore::new(&path).unwrap();
        assert!(store.verify("laptop", &KEY_A).unwrap());
    }

    /// Multiple peers are stored and retrieved independently.
    #[test]
    fn tofu_multiple_peers_independent() {
        let dir = tmp();
        let path = dir.join("trust.json");
        let mut store = TrustStore::new(&path).unwrap();
        store.trust("peer_a", &KEY_A).unwrap();
        store.trust("peer_b", &KEY_B).unwrap();
        assert!(store.verify("peer_a", &KEY_A).unwrap());
        assert!(store.verify("peer_b", &KEY_B).unwrap());
        // KEY_A is not the key for peer_b → Changed.
        assert!(store.verify("peer_b", &KEY_A).is_err());
    }

    /// TrustStatus Display matches the Oracle's string returns.
    #[test]
    fn tofu_status_display() {
        assert_eq!(TrustStatus::New.to_string(), "new");
        assert_eq!(TrustStatus::Trusted.to_string(), "trusted");
        assert_eq!(TrustStatus::Changed.to_string(), "changed");
    }
}

// Phase 1 integration tests - frame, compression, replay, flow.

// ─── Frame ────────────────────────────────────────────────────────────────────

mod frame {
    use cypher::frame::{Frame, FrameError, COMPRESSED, ENCRYPTED, HEADER_LEN, TAG};

    fn make_frame() -> Frame {
        Frame::new(42, ENCRYPTED | COMPRESSED, b"hello, optical world".to_vec()).unwrap()
    }

    /// Header is exactly 8 bytes.
    #[test]
    fn frame_header_len_is_eight() {
        assert_eq!(HEADER_LEN, 8);
        assert_eq!(make_frame().header().len(), 8);
    }

    /// Encode → decode round-trip must be lossless.
    #[test]
    fn frame_round_trip() {
        let f = make_frame();
        assert_eq!(Frame::decode(&f.encode()).unwrap(), f);
    }

    /// Empty payload is a valid frame; encoded form is header-only (8 bytes).
    #[test]
    fn frame_round_trip_empty_payload() {
        let f = Frame::new(42, ENCRYPTED | COMPRESSED, vec![]).unwrap();
        let encoded = f.encode();
        assert_eq!(encoded.len(), HEADER_LEN);
        assert_eq!(Frame::decode(&encoded).unwrap(), f);
    }

    /// Exact header layout, pinned against the frame.json "pinned_frame_42" vector.
    ///
    /// frame_number=42, flags=0x03, payload_len=20
    ///   bytes 0-2: (TAG<<20)|42 = (5<<20)|42 = 0x50_002a
    ///   byte  3:   FLAGS = 0x03
    ///   bytes 4-5: PAYLOAD_LENGTH = 20 = 0x00_14
    ///   bytes 6-7: CRC-16 over bytes 0-5 + payload
    #[test]
    fn frame_header_layout_exact_bytes() {
        let payload = (0u8..20).collect::<Vec<u8>>();
        let f = Frame::new(42, ENCRYPTED | COMPRESSED, payload.clone()).unwrap();
        let header = f.header();

        // TAG nibble: value 0x5
        assert_eq!((header[0] >> 4), TAG, "TAG nibble must be 0x5");

        // TAG (4b) + FRAME_NUMBER (20b) packed into first 3 bytes, big-endian
        assert_eq!(&header[0..3], &[0x50, 0x00, 0x2a]);
        // FLAGS byte
        assert_eq!(header[3], 0x03);
        // PAYLOAD_LENGTH big-endian
        assert_eq!(&header[4..6], &[0x00, 0x14]);
        // CRC-16 coverage: bytes 0-5 + payload
        // Verify CRC-16/IBM-3740 matches - we reuse the crc crate directly
        {
            use crc::{Crc, CRC_16_IBM_3740};
            let crc16 = Crc::<u16>::new(&CRC_16_IBM_3740);
            let mut digest = crc16.digest();
            digest.update(&header[0..6]);
            digest.update(&payload);
            let expected = digest.finalize().to_be_bytes();
            assert_eq!(
                &header[6..8],
                &expected,
                "CRC-16 must cover prefix + payload"
            );
        }
    }

    /// Decode extracts all fields faithfully.
    #[test]
    fn frame_decode_extracts_fields() {
        let f = make_frame();
        let d = Frame::decode(&f.encode()).unwrap();
        assert_eq!(d.frame_number, 42);
        assert_eq!(d.flags, ENCRYPTED | COMPRESSED);
        assert_eq!(d.payload, b"hello, optical world");
    }

    /// Bad TAG must be rejected.
    #[test]
    fn frame_bad_tag_rejected() {
        let mut encoded = make_frame().encode();
        encoded[0] ^= 0xF0; // corrupt the TAG nibble
        let err = Frame::decode(&encoded).unwrap_err();
        assert!(
            matches!(err, FrameError::BadTag(_)),
            "expected BadTag, got {err:?}"
        );
    }

    /// CRC-16 mismatch must be detected.
    #[test]
    fn frame_corruption_detected_by_crc() {
        let mut encoded = make_frame().encode();
        encoded[HEADER_LEN] ^= 0x01; // flip a payload bit
        let err = Frame::decode(&encoded).unwrap_err();
        assert!(
            matches!(err, FrameError::CrcMismatch),
            "expected CrcMismatch, got {err:?}"
        );
    }

    /// Fewer than 8 bytes must be rejected.
    #[test]
    fn frame_truncated_header_rejected() {
        let encoded = make_frame().encode();
        assert!(
            matches!(
                Frame::decode(&encoded[..4]).unwrap_err(),
                FrameError::ShorterThanHeader(_)
            ),
            "4-byte input must fail ShorterThanHeader"
        );
    }

    /// PAYLOAD_LENGTH claiming more bytes than the frame contains must be rejected.
    #[test]
    fn frame_payload_length_exceeds_frame_rejected() {
        let encoded = make_frame().encode();
        // Drop all but 2 payload bytes - header says 20 bytes of payload
        let err = Frame::decode(&encoded[..HEADER_LEN + 2]).unwrap_err();
        assert!(
            matches!(err, FrameError::PayloadLengthOverrun),
            "expected PayloadLengthOverrun, got {err:?}"
        );
    }

    /// Flags bit 7 is RESERVED and must be zero; non-zero must be rejected.
    #[test]
    fn frame_reserved_flag_bit7_rejected() {
        let err = Frame::new(1, 1 << 7, vec![]).unwrap_err();
        assert!(
            matches!(err, FrameError::ReservedFlags(_)),
            "bit 7 must be rejected as reserved"
        );
    }

    /// Any bit above bit 6 that is not a defined flag must be rejected.
    #[test]
    fn frame_reserved_flag_high_bits_rejected() {
        // Flags field is u8; bit 7 is the only reserved bit that fits in 8 bits.
        // Confirm that value 0xFF (all bits set, including reserved bit 7) fails.
        let err = Frame::new(1, 0xFF, vec![]).unwrap_err();
        assert!(matches!(err, FrameError::ReservedFlags(_)));
    }

    /// All seven defined FLAGS bits together must be accepted.
    #[test]
    fn frame_all_defined_flags_accepted() {
        // bits 0-6: ENCRYPTED|COMPRESSED|KEYFRAME|LAST_FRAME|PRIORITY|BEACON|RECEIVER_BEACON = 0x7F
        let f = Frame::new(1, 0x7F, b"payload".to_vec()).unwrap();
        assert_eq!(Frame::decode(&f.encode()).unwrap().flags, 0x7F);
    }

    /// FRAME_NUMBER is 20 bits; values ≥ 2^20 must fail.
    #[test]
    fn frame_number_out_of_range_rejected() {
        let over = (1u32 << 20) + 5;
        assert!(matches!(
            Frame::new(over, 0, vec![]).unwrap_err(),
            FrameError::FrameNumberRange(_)
        ));
        let boundary = 1u32 << 20;
        assert!(matches!(
            Frame::new(boundary, 0, vec![]).unwrap_err(),
            FrameError::FrameNumberRange(_)
        ));
    }

    /// Maximum legal FRAME_NUMBER is 2^20 - 1 = 1,048,575.
    #[test]
    fn frame_max_frame_number_accepted() {
        let max = (1u32 << 20) - 1;
        let f = Frame::new(max, 0, vec![1, 2, 3]).unwrap();
        assert_eq!(Frame::decode(&f.encode()).unwrap().frame_number, max);
    }

    /// PAYLOAD_LENGTH field is 16 bits; payload ≥ 65536 bytes must fail.
    #[test]
    fn frame_payload_too_long_rejected() {
        let huge = vec![0u8; 1 << 16]; // 65536 bytes - one over the 16-bit limit
        assert!(matches!(
            Frame::new(0, 0, huge).unwrap_err(),
            FrameError::PayloadTooLarge
        ));
    }

    /// Maximum legal payload is 65535 bytes (u16::MAX).
    #[test]
    fn frame_max_payload_length_accepted() {
        let payload = vec![0xABu8; (1 << 16) - 1];
        let f = Frame::new(0, 0, payload.clone()).unwrap();
        assert_eq!(Frame::decode(&f.encode()).unwrap().payload, payload);
    }

    /// Retransmitted frame must be byte-identical to the original.
    #[test]
    fn frame_retransmit_is_byte_identical() {
        let f = make_frame();
        assert_eq!(f.encode(), f.encode());
    }

    // ── Proptest: decode(encode(f)) == f over arbitrary valid frames ──────────

    use proptest::prelude::*;

    // Valid flags: any subset of bits 0-6 (bit 7 reserved/must-be-zero).
    fn arb_flags() -> impl Strategy<Value = u8> {
        (0u8..=0x7F).boxed()
    }

    proptest! {
        #[test]
        fn frame_proptest_round_trip(
            frame_number in 0u32..=(1u32 << 20) - 1,
            flags in arb_flags(),
            payload in proptest::collection::vec(any::<u8>(), 0..=2048),
        ) {
            let f = Frame::new(frame_number, flags, payload).unwrap();
            let decoded = Frame::decode(&f.encode()).unwrap();
            prop_assert_eq!(decoded, f);
        }
    }
}

// ─── Compression ──────────────────────────────────────────────────────────────

mod compression {
    use cypher::compression::{
        compress, decompress, CompressionError, LEVEL_RATIO, LEVEL_SPEED,
    };

    /// Round-trip of a seeded pattern must be lossless at both compression levels.
    #[test]
    fn compression_round_trip_empty_speed() {
        let data = b"";
        assert_eq!(
            decompress(&compress(data, LEVEL_SPEED).unwrap(), 0).unwrap(),
            data
        );
    }

    #[test]
    fn compression_round_trip_empty_ratio() {
        let data = b"";
        assert_eq!(
            decompress(&compress(data, LEVEL_RATIO).unwrap(), 0).unwrap(),
            data
        );
    }

    #[test]
    fn compression_round_trip_short_speed() {
        let data = b"hello";
        assert_eq!(
            decompress(&compress(data, LEVEL_SPEED).unwrap(), 0).unwrap(),
            data
        );
    }

    #[test]
    fn compression_round_trip_short_ratio() {
        let data = b"hello";
        assert_eq!(
            decompress(&compress(data, LEVEL_RATIO).unwrap(), 0).unwrap(),
            data
        );
    }

    /// Large repetitive data - the repeated "fox" pangram case.
    #[test]
    fn compression_round_trip_repetitive_speed() {
        let data: Vec<u8> = b"the quick brown fox "
            .iter()
            .cycle()
            .take(10000)
            .cloned()
            .collect();
        assert_eq!(
            decompress(&compress(&data, LEVEL_SPEED).unwrap(), 0).unwrap(),
            data
        );
    }

    #[test]
    fn compression_round_trip_repetitive_ratio() {
        let data: Vec<u8> = b"the quick brown fox "
            .iter()
            .cycle()
            .take(10000)
            .cloned()
            .collect();
        assert_eq!(
            decompress(&compress(&data, LEVEL_RATIO).unwrap(), 0).unwrap(),
            data
        );
    }

    /// Seeded 4096-byte pseudo-random bytes.
    #[test]
    fn compression_round_trip_seeded_random_speed() {
        let data = seeded_bytes(1, 4096);
        assert_eq!(
            decompress(&compress(&data, LEVEL_SPEED).unwrap(), 0).unwrap(),
            data
        );
    }

    #[test]
    fn compression_round_trip_seeded_random_ratio() {
        let data = seeded_bytes(1, 4096);
        assert_eq!(
            decompress(&compress(&data, LEVEL_RATIO).unwrap(), 0).unwrap(),
            data
        );
    }

    /// Highly compressible data must shrink to < 10% of original.
    /// (mirrors test_compressible_data_shrinks)
    #[test]
    fn compression_compressible_data_shrinks() {
        let data: Vec<u8> = b"cypher ".iter().cycle().take(10000).cloned().collect();
        let compressed = compress(&data, LEVEL_SPEED).unwrap();
        assert!(
            compressed.len() < data.len() / 10,
            "compressed {} bytes, expected < {}",
            compressed.len(),
            data.len() / 10
        );
    }

    /// RATIO level must produce output no larger than SPEED level for compressible data.
    #[test]
    fn compression_ratio_level_no_worse_than_speed_level() {
        let mut data: Vec<u8> = b"the quick brown fox jumps over the lazy dog "
            .iter()
            .cycle()
            .take(17600)
            .cloned()
            .collect();
        let extra: Vec<u8> = (0u8..=255).cycle().take(10240).collect();
        data.extend_from_slice(&extra);
        let speed = compress(&data, LEVEL_SPEED).unwrap();
        let ratio = compress(&data, LEVEL_RATIO).unwrap();
        assert!(
            ratio.len() <= speed.len(),
            "ratio compressed to {} bytes, speed to {} - ratio must be ≤ speed",
            ratio.len(),
            speed.len()
        );
    }

    /// Garbage bytes must be rejected.
    #[test]
    fn compression_garbage_rejected() {
        let result = decompress(b"\x00not a zstd frame\xff", 0);
        assert!(result.is_err(), "garbage input must fail but got Ok");
        assert!(matches!(result.unwrap_err(), CompressionError::Zstd(_)));
    }

    /// Decompression output size bound is enforced; payload under the limit passes.
    #[test]
    fn compression_output_size_bound_enforced() {
        let bomb = compress(&vec![0u8; 100_000], LEVEL_SPEED).unwrap();
        assert!(bomb.len() < 1000, "zero-filled data must compress tightly");

        // Too small a limit must be rejected
        let err = decompress(&bomb, 1024).unwrap_err();
        assert!(
            matches!(
                err,
                CompressionError::DeclaredTooLarge { .. } | CompressionError::OutputTooLarge { .. }
            ),
            "expected size-limit error, got {err:?}"
        );

        // Exact limit passes
        assert_eq!(decompress(&bomb, 100_000).unwrap(), vec![0u8; 100_000]);
    }

    /// Output size bound is also enforced for streamed frames that omit content size.
    #[test]
    fn compression_output_size_bound_on_unknown_size_frame() {
        // Build a zstd frame without content size via zstd's streaming encoder.
        // The zstd crate's stream::Encoder omits the content size when not pledged.
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let mut enc = zstd::stream::Encoder::new(&mut buf, LEVEL_SPEED).unwrap();
            enc.set_pledged_src_size(None).unwrap(); // omit content size
            enc.write_all(&vec![0u8; 100_000]).unwrap();
            enc.finish().unwrap();
        }
        // Must reject with limit too small
        let err = decompress(&buf, 1024).unwrap_err();
        assert!(
            matches!(err, CompressionError::OutputTooLarge { .. }),
            "unknown-size frame must still respect output bound; got {err:?}"
        );
        // Must pass with sufficient limit
        assert_eq!(decompress(&buf, 200_000).unwrap(), vec![0u8; 100_000]);
    }

    // Helper: deterministic "random" bytes via a simple LCG seeded with `seed`.
    fn seeded_bytes(seed: u64, n: usize) -> Vec<u8> {
        let mut state = seed;
        (0..n)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 33) as u8
            })
            .collect()
    }
}

// ─── Replay ───────────────────────────────────────────────────────────────────

mod replay {
    use cypher::replay::ReplayCache;

    fn clock_at(t: f64) -> Box<dyn FnMut() -> f64 + Send> {
        Box::new(move || t)
    }

    /// Basic replay flow: unseen → proceed; add after SESSION_COMPLETE → cached.
    #[test]
    fn replay_section_9_3_flow() {
        let mut cache = ReplayCache::new(
            cypher::replay::DEFAULT_TTL,
            cypher::replay::MAX_ENTRIES,
            Box::new(|| 0.0),
        );
        let sid: u64 = 0xAABBCCDD_11223344;
        assert!(!cache.contains(sid)); // unseen: proceed
        cache.add(sid); // after SESSION_COMPLETE
        assert!(cache.contains(sid)); // replay: discard
    }

    /// TTL expiry removes entries.
    #[test]
    fn replay_ttl_expiry() {
        use std::sync::{Arc, Mutex};
        let t = Arc::new(Mutex::new(0.0f64));
        let t2 = Arc::clone(&t);
        let mut cache = ReplayCache::new(100.0, 10, Box::new(move || *t2.lock().unwrap()));

        cache.add(1);
        *t.lock().unwrap() = 99.0;
        assert!(cache.contains(1), "entry must survive before TTL");
        *t.lock().unwrap() = 100.0; // exactly at expiry boundary - expired (expiry = 0.0 + 100.0; clock = 100.0 → expiry <= clock)
        assert!(!cache.contains(1), "entry must be gone at TTL boundary");
        assert_eq!(cache.len(), 0, "expired entry must be lazily removed");
    }

    /// LRU eviction when max_entries is reached.
    #[test]
    fn replay_lru_eviction_when_full() {
        use std::sync::{Arc, Mutex};
        let t = Arc::new(Mutex::new(0.0f64));
        let t2 = Arc::clone(&t);
        let mut cache = ReplayCache::new(1000.0, 3, Box::new(move || *t2.lock().unwrap()));

        cache.add(1);
        cache.add(2);
        cache.add(3);
        // Touch 1 to make it most-recent; 2 is now LRU
        cache.add(1);
        // Adding 4 must evict 2 (LRU)
        cache.add(4);
        assert!(!cache.contains(2), "LRU entry 2 must be evicted");
        assert!(cache.contains(1), "touched entry 1 must survive");
        assert!(cache.contains(3), "entry 3 must survive");
        assert!(cache.contains(4), "new entry 4 must be present");
        assert_eq!(cache.len(), 3);
    }

    /// Expired entries are reclaimed before evicting live ones.
    #[test]
    fn replay_expired_entries_evicted_before_live_ones() {
        use std::sync::{Arc, Mutex};
        let t = Arc::new(Mutex::new(0.0f64));
        let t2 = Arc::clone(&t);
        let mut cache = ReplayCache::new(10.0, 2, Box::new(move || *t2.lock().unwrap()));

        cache.add(1);
        *t.lock().unwrap() = 11.0; // entry 1 expired
        cache.add(2);
        cache.add(3); // room freed by expiry; neither 2 nor 3 should be evicted
        assert!(!cache.contains(1));
        assert!(cache.contains(2));
        assert!(cache.contains(3));
    }

    /// An ID not yet added must not appear as contained.
    #[test]
    fn replay_unseen_not_contained() {
        let mut cache = ReplayCache::new(3600.0, 100, clock_at(0.0));
        assert!(!cache.contains(0xDEADBEEF_CAFEBABE));
    }

    /// An empty cache reports len == 0.
    #[test]
    fn replay_empty_len_is_zero() {
        let cache = ReplayCache::new(3600.0, 100, clock_at(0.0));
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());
    }

    /// Adding the same ID twice does not grow the cache.
    #[test]
    fn replay_duplicate_add_no_growth() {
        use std::sync::{Arc, Mutex};
        let t = Arc::new(Mutex::new(0.0f64));
        let t2 = Arc::clone(&t);
        let mut cache = ReplayCache::new(1000.0, 100, Box::new(move || *t2.lock().unwrap()));
        cache.add(42);
        cache.add(42);
        assert_eq!(cache.len(), 1);
    }
}

// ─── Flow ─────────────────────────────────────────────────────────────────────

mod flow {
    use cypher::flow::{adjust_fps, FlowControl, Signal, FLOW_SIGNAL_INTERVAL};

    /// Fill fc with `ok` decoded-ok and `bad` failed records.
    fn fill(fc: &mut FlowControl, ok: usize, bad: usize) {
        for _ in 0..ok {
            fc.record(true);
        }
        for _ in 0..bad {
            fc.record(false);
        }
    }

    /// CQS thresholds trigger the right signals.
    /// Fill 100 records (≥ FLOW_SIGNAL_INTERVAL=30) so the rate limiter does not suppress.
    #[test]
    fn flow_cqs_thresholds() {
        // 84/100 = 0.84 < 0.85 → SLOW_DOWN
        let mut fc = FlowControl::default();
        fill(&mut fc, 84, 16);
        assert_eq!(fc.signal(), Some(Signal::SlowDown));

        // 96/100 = 0.96 > 0.95 → SPEED_UP
        let mut fc = FlowControl::default();
        fill(&mut fc, 96, 4);
        assert_eq!(fc.signal(), Some(Signal::SpeedUp));

        // 90/100 = 0.90 in dead zone → None
        let mut fc = FlowControl::default();
        fill(&mut fc, 90, 10);
        assert_eq!(fc.signal(), None);
    }

    /// CQS thresholds are strict (< 0.85, not ≤).
    #[test]
    fn flow_cqs_thresholds_are_strict() {
        // Exactly 0.85: not < 0.85 → no SLOW_DOWN
        let mut fc = FlowControl::default();
        fill(&mut fc, 85, 15);
        assert_eq!(fc.signal(), None);

        // Exactly 0.95: not > 0.95 → no SPEED_UP
        let mut fc = FlowControl::default();
        fill(&mut fc, 95, 5);
        assert_eq!(fc.signal(), None);
    }

    /// The window rolls - old results age out.
    #[test]
    fn flow_cqs_window_rolls() {
        let mut fc = FlowControl::new(10);
        fill(&mut fc, 0, 10);
        assert_eq!(fc.cqs(), 0.0);
        fill(&mut fc, 10, 0); // bad results roll out of the 10-entry window
        assert_eq!(fc.cqs(), 1.0);
    }

    /// CQS on an empty window is 1.0 (no signal).
    #[test]
    fn flow_cqs_empty_window_is_one() {
        let fc = FlowControl::default();
        assert_eq!(fc.cqs(), 1.0);
    }

    /// Empty FlowControl emits no signal.
    #[test]
    fn flow_signal_empty_window_is_none() {
        let mut fc = FlowControl::default();
        assert_eq!(fc.signal(), None);
    }

    /// adjust_fps steps by ±5, clamped at negotiated bounds.
    #[test]
    fn flow_adjust_fps_steps_and_clamps() {
        assert_eq!(adjust_fps(30, Some(Signal::SlowDown), 10, 60), 25);
        assert_eq!(adjust_fps(30, Some(Signal::SpeedUp), 10, 60), 35);
        assert_eq!(adjust_fps(12, Some(Signal::SlowDown), 10, 60), 10); // clamped at min
        assert_eq!(adjust_fps(58, Some(Signal::SpeedUp), 10, 60), 60); // clamped at max
        assert_eq!(adjust_fps(30, None, 10, 60), 30); // no signal → unchanged
    }

    /// A second signal() call without enough records since the first must be suppressed.
    #[test]
    fn flow_signal_rate_limited() {
        let mut fc = FlowControl::default();
        // Fill 100 records: all failures - this should fire SLOW_DOWN and reset counter.
        fill(&mut fc, 0, 100);
        assert_eq!(
            fc.signal(),
            Some(Signal::SlowDown),
            "first signal must fire after >= {} records",
            FLOW_SIGNAL_INTERVAL
        );
        // Immediately calling again, counter just reset to 0 - must be suppressed.
        assert_eq!(
            fc.signal(),
            None,
            "second signal must be suppressed by rate limiter"
        );
    }

    /// After FLOW_SIGNAL_INTERVAL more records the signal can fire again.
    #[test]
    fn flow_signal_fires_again_after_interval() {
        let mut fc = FlowControl::default();
        fill(&mut fc, 0, 100); // prime the bad state
        fc.signal(); // consume first signal, reset counter to 0
                     // Add FLOW_SIGNAL_INTERVAL more records (all failures, same CQS)
        fill(&mut fc, 0, FLOW_SIGNAL_INTERVAL as usize);
        assert_eq!(
            fc.signal(),
            Some(Signal::SlowDown),
            "signal must re-fire after {} more records",
            FLOW_SIGNAL_INTERVAL
        );
    }
}

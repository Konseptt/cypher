// Phase 4 tests - fountain code layer.
//
// Where a dynamically-typed caller could pass negative or out-of-u16-range
// values, the case is noted as UNPORTABLE and replaced with the type-level
// boundary (0, u16::MAX+1 can't be expressed as u16).

use cypher::fountain::{encode, Decoder, FountainError, DEFAULT_OVERHEAD};

/// The receiver reconstructs the whole payload from ANY K+ε packets -
/// no ordering, no retransmission.
#[test]
fn round_trip_lossy_reconstructs() {
    // Fixed seed data - deterministic, no randomness.
    let data: Vec<u8> = (0u8..=255).cycle().take(120 * 1024).collect();
    let symbol_size: u16 = 300;
    let packets = encode(&data, symbol_size, DEFAULT_OVERHEAD).unwrap();

    // Three loss scenarios, seeded deterministically by dropping every Nth
    // packet instead of at random, to stay no-std / no-rand.
    for (step, drop_pct) in [(0, 0usize), (10, 10), (5, 20)] {
        let kept: Vec<&[u8]> = packets
            .iter()
            .enumerate()
            .filter(|(i, _)| step == 0 || i % (100 / drop_pct) != 0)
            .map(|(_, p)| p.as_slice())
            .collect();

        // Reverse order to test any-ordering.
        let mut dec = Decoder::new(data.len() as u64, symbol_size).unwrap();
        let mut result: Option<Vec<u8>> = None;
        for pkt in kept.iter().rev() {
            result = dec.add(pkt);
            if result.is_some() {
                break;
            }
        }
        assert_eq!(
            result.as_deref(),
            Some(data.as_slice()),
            "lossy {}% failed",
            drop_pct
        );
    }
}

/// Corrupt/malformed packets are rejected without crashing (treated as lost packets).
#[test]
fn junk_packets_are_skipped_not_crashed() {
    let mut dec = Decoder::new(10_000, 1200).unwrap();
    let junks: &[&[u8]] = &[
        b"",
        b"x",
        // 50-byte garbage - shorter than symbol_size+4 but above 4-byte length guard
        &[0xffu8; 50],
        // symbol_size+4 bytes of zeros - valid length, garbage content
        &[0x00u8; 1204],
        // random-ish garbage at correct size
        &(0u8..=255).cycle().take(1204).collect::<Vec<u8>>(),
        // oversized
        &[0xabu8; 5000],
    ];
    for junk in junks {
        // Must return None (treated as lost), must NOT panic.
        assert_eq!(
            dec.add(junk),
            None,
            "junk packet of len {} caused non-None",
            junk.len()
        );
    }
}

/// A decoder with a larger transfer_length than the real payload can never gather
/// enough symbols and therefore never completes (returns None).
#[test]
fn over_claimed_length_never_returns_wrong_bytes() {
    let data: Vec<u8> = (0u8..=255).cycle().take(40 * 1024).collect();
    let symbol_size: u16 = 300;
    let packets = encode(&data, symbol_size, DEFAULT_OVERHEAD).unwrap();

    // Decoder told twice the real length - can never complete.
    let mut dec = Decoder::new((data.len() * 2) as u64, symbol_size).unwrap();
    let mut result: Option<Vec<u8>> = None;
    for pkt in &packets {
        result = dec.add(pkt);
    }
    assert_eq!(result, None, "over-claimed decoder must never complete");
}

/// Bad Decoder params are rejected without crashing.
///
/// PORTABILITY NOTES:
/// - transfer_length=10_000, symbol_size=70_000: 70_000 > u16::MAX, so the type
///   system prevents constructing that call. UNPORTABLE - the equivalent boundary
///   is symbol_size = u16::MAX which IS valid.
/// - transfer_length=-1 and symbol_size=-4: the u64/u16 types reject negatives at
///   compile time. UNPORTABLE - replaced with the zero boundary (the actual guard
///   in fountain.rs) which is the closest expressible equivalent.
#[test]
fn bad_decoder_params_raise_fountain_error() {
    // (transfer_length=0, symbol_size=1200) - zero transfer_length
    assert!(
        matches!(Decoder::new(0, 1200), Err(FountainError::BadParams { .. })),
        "zero transfer_length must be FountainError"
    );

    // (transfer_length=10_000, symbol_size=0) - zero symbol_size
    assert!(
        matches!(
            Decoder::new(10_000, 0),
            Err(FountainError::BadParams { .. })
        ),
        "zero symbol_size must be FountainError"
    );
}

/// encode with symbol_size=0 is also a bad param.
#[test]
fn encode_zero_symbol_size_is_error() {
    let data = vec![0u8; 100];
    assert!(
        matches!(
            encode(&data, 0, DEFAULT_OVERHEAD),
            Err(FountainError::BadSymbolSize)
        ),
        "encode with symbol_size=0 must be FountainError::BadSymbolSize"
    );
}

/// After completion, add() continues to return Some(payload) on every subsequent
/// call (not None, not a panic) - the in-memory result must not be consumed.
#[test]
fn completed_decoder_is_idempotent() {
    let data: Vec<u8> = (0u8..128).collect();
    let symbol_size: u16 = 32;
    let packets = encode(&data, symbol_size, DEFAULT_OVERHEAD).unwrap();

    let mut dec = Decoder::new(data.len() as u64, symbol_size).unwrap();
    let mut first_completion: Option<Vec<u8>> = None;
    for pkt in &packets {
        let r = dec.add(pkt);
        if first_completion.is_none() && r.is_some() {
            first_completion = r;
        }
    }
    assert_eq!(
        first_completion.as_deref(),
        Some(data.as_slice()),
        "did not complete"
    );
    assert!(dec.done(), "done() must be true after completion");

    // Feeding more (already-seen) packets after completion must keep returning the payload.
    for pkt in &packets {
        assert_eq!(
            dec.add(pkt).as_deref(),
            Some(data.as_slice()),
            "post-completion add() must still return Some(payload)"
        );
    }
}

/// Encode packet-count arithmetic (boundary sizes):
///   k_formula = max(1, len(data) // symbol_size)
///   repair     = max(1, int(k_formula * overhead))   -- floor for non-negative values
///   total      = k_actual + repair
///
/// NOTE: k_actual (raptorq's internal source-symbol count) is NOT necessarily
/// equal to k_formula = floor(data_len / symbol_size).  RFC 6330 may pad to the
/// next block boundary, so k_actual >= k_formula.  We do not assert total here
/// because that would encode raptorq internals that are not part of the protocol
/// contract.  Instead we assert the REPAIR delta:
///     encode(data, ss, overhead).len() - encode(data, ss, 0_tiny).len()
///         == max(1, floor(k_formula * overhead))
///
/// We use overhead=f64::MIN_POSITIVE as a proxy for "zero repair requested"
/// since repair = max(1, floor(k * MIN_POSITIVE)) = 1 for all k, so we
/// subtract 1 from the 0-overhead baseline count.
///
/// Three boundary conditions:
///   a) data shorter than one symbol → k_formula=1, repair=1
///   b) data exact multiple of symbol_size → k_formula=data_len/ss
///   c) data is (k*symbol_size)+1 → k_formula unchanged (floor), repair unchanged
fn source_symbol_count(data: &[u8], symbol_size: u16) -> usize {
    // Encode with repair=1 (minimum, overhead rounds to 1/k_formula < 0.1 for k>10,
    // but repair=max(1,...) so we just use a tiny overhead) and then the baseline
    // total - 1 = k_actual. Instead, compute by comparing overhead=0 vs overhead=tiny.
    // Simpler: use get_encoded_packets(0) equivalent = encode(..., tiny_overhead).len() - 1.
    // But we don't expose that. Use the fact that encode(_, _, 0.0+eps) -> k_actual + 1
    // since repair = max(1, floor(k*eps)) = max(1,0) = 1 for all k.
    // So k_actual = encode(data, ss, f64::MIN_POSITIVE).len() - 1.
    let pkts = encode(data, symbol_size, f64::MIN_POSITIVE)
        .expect("encode for k_actual measurement failed");
    pkts.len() - 1 // subtract the 1 repair symbol
}

#[test]
fn encode_packet_count_data_smaller_than_one_symbol() {
    // a) 50 bytes, symbol_size=300 → k_formula=max(1, 0)=1
    //    repair=max(1, floor(1*0.4))=max(1,0)=1
    let data = vec![0u8; 50];
    let ss: u16 = 300;
    let k_formula = 1usize; // max(1, 50//300) = 1
    let expected_rep = std::cmp::max(1, (k_formula as f64 * DEFAULT_OVERHEAD) as usize);
    let k_actual = source_symbol_count(&data, ss);
    let pkts = encode(&data, ss, DEFAULT_OVERHEAD).unwrap();
    assert_eq!(
        pkts.len(),
        k_actual + expected_rep,
        "data < symbol_size: total packet count wrong (k_actual={k_actual}, repair={expected_rep})"
    );
}

#[test]
fn encode_packet_count_exact_multiple() {
    // b) 3000 bytes, symbol_size=300 → k_formula=10, repair=max(1, floor(10*0.4))=4
    let data = vec![0xabu8; 3000];
    let ss: u16 = 300;
    let k_formula = 3000 / 300usize; // = 10
    let expected_rep = std::cmp::max(1, (k_formula as f64 * DEFAULT_OVERHEAD) as usize); // = 4
    let k_actual = source_symbol_count(&data, ss);
    let pkts = encode(&data, ss, DEFAULT_OVERHEAD).unwrap();
    assert_eq!(
        pkts.len(),
        k_actual + expected_rep,
        "exact multiple: total packet count wrong (k_actual={k_actual}, repair={expected_rep})"
    );
}

#[test]
fn encode_packet_count_one_byte_over_multiple() {
    // c) 3001 bytes → k_formula=max(1, 3001//300)=10 - same as 3000 - floor does not
    //    increment. repair=4 unchanged. Same test, different input, different k_actual.
    let data = vec![0xabu8; 3001];
    let ss: u16 = 300;
    let k_formula = 3001 / 300usize; // = 10 (floor)
    let expected_rep = std::cmp::max(1, (k_formula as f64 * DEFAULT_OVERHEAD) as usize);
    let k_actual = source_symbol_count(&data, ss);
    let pkts = encode(&data, ss, DEFAULT_OVERHEAD).unwrap();
    assert_eq!(
        pkts.len(),
        k_actual + expected_rep,
        "+1 byte: total packet count wrong (k_actual={k_actual}, repair={expected_rep})"
    );
}

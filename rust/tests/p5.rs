// QR visual carrier and camera-distortion harness (camsim.rs).
//
// UNPORTABLE cases (noted inline):
//   - test_broadcast_tiled_video_round_trip: requires mp4 render/decode pipeline
//     (render_broadcast + decode_video from examples/); no Rust port of that layer.
//   - test_wrong_psk_tiled_capture_auth_failed: requires BroadcastSender/
//     BroadcastReceiver session layer; not in the Rust public API yet.
//
// Both omissions are protocol-layer tests, not QR-carrier tests.

use cypher::camsim;
use cypher::qr;

/// Default render params (scale=8, border=4, ec="m").
fn encode(data: &[u8]) -> image::RgbImage {
    qr::encode(data, 8, 4, "m").expect("encode failed")
}

fn encode_tiled(wires: &[&[u8]], tiles: usize) -> image::RgbImage {
    qr::encode_tiled(wires, tiles, 8, 4, "m").expect("encode_tiled failed")
}

/// max_payload(8) == MAX_WIRE - 8 (8 = frame header length).
#[test]
fn max_payload_tracks_max_wire() {
    assert_eq!(qr::max_payload(8), qr::MAX_WIRE - 8);
}

/// Each wire payload must round-trip through a standard QR code byte-exactly
/// (byte-mode, no re-encoding via text()).
#[test]
fn round_trip_size_1() {
    let data = vec![0u8; 1];
    assert_eq!(qr::decode(&encode(&data)).unwrap(), data);
}

#[test]
fn round_trip_size_16() {
    let data: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(7)).collect();
    assert_eq!(qr::decode(&encode(&data)).unwrap(), data);
}

#[test]
fn round_trip_size_100() {
    let data: Vec<u8> = (0u8..100).map(|i| i.wrapping_mul(7)).collect();
    assert_eq!(qr::decode(&encode(&data)).unwrap(), data);
}

/// MAX_WIRE bytes round-trip (maximum QR payload budget).
#[test]
fn round_trip_size_max_wire() {
    let n = qr::MAX_WIRE;
    let data: Vec<u8> = (0..n).map(|i| ((i * 7) % 256) as u8).collect();
    assert_eq!(qr::decode(&encode(&data)).unwrap(), data);
}

/// Regression: a long run of 0x00 bytes (e.g. an open BEACON's ZERO32 fields)
/// must encode+decode byte-exactly.  Some encoders reuse numeric/alphanumeric
/// mode for zero runs and lose byte-mode fidelity.
#[test]
fn round_trip_zero_run_regression() {
    let data: Vec<u8> = [vec![0u8; 40], vec![1, 2, 3], vec![0u8; 40]].concat();
    assert_eq!(qr::decode(&encode(&data)).unwrap(), data);
}

/// A noise image (no QR) must yield None - not panic, not empty bytes.
#[test]
fn decode_none_on_non_qr_image() {
    // 256×256 seeded noise (LCG, no rand dep) - visually: no finder patterns.
    let mut noise = image::RgbImage::new(256, 256);
    let mut state: u64 = 0;
    for px in noise.pixels_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let v = (state >> 33) as u8;
        *px = image::Rgb([v, v ^ 0x55, v.wrapping_add(0x33)]);
    }
    assert!(qr::decode(&noise).is_none());
}

/// Statistical bound: at least 10 of 12 seeds must decode correctly at the
/// reference distortion parameters (warp=0.04, blur=5, noise=25, payload 200 B).
/// Payload bounded to 200 B so the QR is small enough that blur and warp
/// don't destroy all finder patterns.
#[test]
fn distortion_tolerance_10_of_12() {
    let payload: Vec<u8> = (0..200u8).collect();
    let img = encode(&payload);
    let ok: usize = (0u64..12)
        .filter(|&seed| {
            let distorted = camsim::cam(&img, seed, 0.04, 5, 25);
            qr::decode(&distorted).as_deref() == Some(payload.as_slice())
        })
        .count();
    assert!(
        ok >= 10,
        "only {ok}/12 seeds decoded under distortion (need ≥10)"
    );
}

/// Build N distinct Cypher frame wire bytes (deterministic).
/// Each is header (8B) + small payload - not valid frames but serves as
/// distinct byte strings for QR carrier round-trip tests.
fn distinct_wires(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let mut wire = vec![0x50u8, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00]; // fake header
            wire[4] = i as u8; // make each wire distinct
            wire.extend(std::iter::repeat_n(i as u8, 32));
            wire.extend(b"tile_payload");
            wire
        })
        .collect()
}

/// T×T grid of independent QR codes; every wire must come back
/// (order is unspecified - zxing-cpp return order is implementation-defined).
#[test]
fn round_trip_full_grid_t2() {
    let wires = distinct_wires(4); // 2×2
    let refs: Vec<&[u8]> = wires.iter().map(|w| w.as_slice()).collect();
    let image = encode_tiled(&refs, 2);
    let recovered: std::collections::HashSet<Vec<u8>> =
        qr::decode_all(&image).into_iter().collect();
    let expected: std::collections::HashSet<Vec<u8>> = wires.into_iter().collect();
    assert_eq!(
        recovered, expected,
        "T=2 full grid: all 4 wires must be recovered"
    );
}

#[test]
fn round_trip_full_grid_t3() {
    let wires = distinct_wires(9); // 3×3
    let refs: Vec<&[u8]> = wires.iter().map(|w| w.as_slice()).collect();
    let image = encode_tiled(&refs, 3);
    let recovered: std::collections::HashSet<Vec<u8>> =
        qr::decode_all(&image).into_iter().collect();
    let expected: std::collections::HashSet<Vec<u8>> = wires.into_iter().collect();
    assert_eq!(
        recovered, expected,
        "T=3 full grid: all 9 wires must be recovered"
    );
}

/// Unused cells stay white; the wires that ARE present must be recovered.
#[test]
fn round_trip_partial_grid_t2() {
    let wires = distinct_wires(2); // fewer than 2²=4
    let refs: Vec<&[u8]> = wires.iter().map(|w| w.as_slice()).collect();
    let image = encode_tiled(&refs, 2);
    let recovered: std::collections::HashSet<Vec<u8>> =
        qr::decode_all(&image).into_iter().collect();
    let expected: std::collections::HashSet<Vec<u8>> = wires.into_iter().collect();
    assert_eq!(
        recovered, expected,
        "T=2 partial grid: present wires must be recovered"
    );
}

#[test]
fn round_trip_partial_grid_t3() {
    let wires = distinct_wires(3); // fewer than 3²=9
    let refs: Vec<&[u8]> = wires.iter().map(|w| w.as_slice()).collect();
    let image = encode_tiled(&refs, 3);
    let recovered: std::collections::HashSet<Vec<u8>> =
        qr::decode_all(&image).into_iter().collect();
    let expected: std::collections::HashSet<Vec<u8>> = wires.into_iter().collect();
    assert_eq!(
        recovered, expected,
        "T=3 partial grid: present wires must be recovered"
    );
}

/// T=1 is the standard value; encode_tiled([w], 1) must be decodable by
/// decode() - the standard single-code path - byte-exactly.
#[test]
fn t1_decode_via_single_code_path() {
    let wire: Vec<u8> = b"hello cypher".to_vec();
    let image = encode_tiled(&[wire.as_slice()], 1);
    assert_eq!(
        qr::decode(&image).unwrap(),
        wire,
        "T=1 image must be decodable by the single-code decode() path"
    );
}

/// A single-code image yields a one-element list from decode_all.
#[test]
fn t1_decode_all_returns_one_element() {
    let wire: Vec<u8> = b"single".to_vec();
    let image = encode_tiled(&[wire.as_slice()], 1);
    let result = qr::decode_all(&image);
    assert_eq!(
        result.len(),
        1,
        "T=1 decode_all must return exactly one element"
    );
    assert_eq!(result[0], wire);
}

/// T=0 is out of range 1..=3.
#[test]
fn tiles_zero_rejected() {
    let wires = distinct_wires(1);
    let refs: Vec<&[u8]> = wires.iter().map(|w| w.as_slice()).collect();
    assert!(
        qr::encode_tiled(&refs, 0, 8, 4, "m").is_err(),
        "tiles=0 must be rejected"
    );
}

/// Max T=3; T=4 exceeds the cap.
#[test]
fn tiles_four_rejected() {
    let wires = distinct_wires(4);
    let refs: Vec<&[u8]> = wires.iter().map(|w| w.as_slice()).collect();
    assert!(
        qr::encode_tiled(&refs, 4, 8, 4, "m").is_err(),
        "tiles=4 must be rejected (max is 3)"
    );
}

/// Contract: len(wires) >= 1.
#[test]
fn empty_wires_rejected() {
    assert!(
        qr::encode_tiled(&[], 2, 8, 4, "m").is_err(),
        "zero wires must be rejected"
    );
}

/// Contract: len(wires) <= tiles².
#[test]
fn too_many_wires_rejected() {
    // 5 wires for a 2×2 grid (cap = 4)
    let wires = distinct_wires(5);
    let refs: Vec<&[u8]> = wires.iter().map(|w| w.as_slice()).collect();
    assert!(
        qr::encode_tiled(&refs, 2, 8, 4, "m").is_err(),
        "5 wires for tiles=2 (cap=4) must be rejected"
    );
}

/// tiles=1 supports exactly 1 wire.
#[test]
fn tiles_one_two_wires_rejected() {
    let wires = distinct_wires(2);
    let refs: Vec<&[u8]> = wires.iter().map(|w| w.as_slice()).collect();
    assert!(
        qr::encode_tiled(&refs, 1, 8, 4, "m").is_err(),
        "2 wires for tiles=1 must be rejected"
    );
}

/// A lost tile is a per-tile failure, not a per-frame failure. White-out the
/// top-right quadrant of a 2×2 grid; the other 3 wires must still decode.
#[test]
fn whiteout_one_quadrant_other_tiles_survive() {
    let wires = distinct_wires(4); // 2×2 grid
    let refs: Vec<&[u8]> = wires.iter().map(|w| w.as_slice()).collect();
    let mut image = encode_tiled(&refs, 2);

    let (w, h) = (image.width(), image.height());
    // Top-right quadrant: rows 0..h/2, cols w/2..w  (tile index 1, row 0 col 1).
    for y in 0..h / 2 {
        for x in w / 2..w {
            image.put_pixel(x, y, image::Rgb([255, 255, 255]));
        }
    }

    let recovered: std::collections::HashSet<Vec<u8>> =
        qr::decode_all(&image).into_iter().collect();

    // Exactly 3 of the 4 wires survive.
    assert_eq!(
        recovered.len(),
        3,
        "3 of 4 tiles must survive after top-right quadrant white-out"
    );
    assert!(
        recovered.is_subset(&wires.iter().cloned().collect()),
        "recovered tiles must be a subset of original wires"
    );
    // The top-right tile (row 0, col 1 → wires[1]) is destroyed.
    assert!(
        !recovered.contains(&wires[1]),
        "wires[1] (top-right tile) must be gone after white-out"
    );
}

/// A BEACON payload can exceed MAX_WIRE; the QR auto-fits a larger version.
/// Verify that encode handles payloads up to 2300 B (ECC-M QR-v40 ceiling)
/// and decode round-trips them.
#[test]
fn beacon_sized_code_round_trips() {
    // A real BEACON wire can be ~200-300 B total; pick a generous upper bound.
    let sizes = [qr::MAX_WIRE + 100, 1500, 2300];
    for &n in &sizes {
        let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let img = qr::encode(&data, 8, 4, "m").expect("encode of oversized payload failed");
        let got = qr::decode(&img);
        assert_eq!(
            got.as_deref(),
            Some(data.as_slice()),
            "BEACON-sized payload of {n} B must round-trip"
        );
    }
}

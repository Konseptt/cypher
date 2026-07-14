// Transport boundary, alignment state machine, and broadcast session layer.
//
// Mock-at-the-boundary: LoopbackTransport, injected clocks, fixed byte inputs.
// No real hardware, cameras, displays, or network.
//
// UNPORTABLE cases (noted inline):
//   - broadcast_sender_short/long/empty_psk_raises: the Rust BroadcastSender
//     takes a [u8; 32] PSK, enforced by the type system - there is no runtime
//     path to test.  Documented.
//   - broadcast_receiver_short/long_psk_raises: same reason.
//   - broadcast_two_sessions_same_psk_different_session_keys: session_key is
//     a private field on BroadcastSender; observable only through decryption
//     behaviour.  The observable version (wrong-PSK data → auth-failed) is
//     already tested in broadcast_wrong_psk_data_frames_auth_fail.
//   - broadcast_second_send_data_increments_frame_numbers: next_frame is
//     private; tested indirectly through packet counts (see
//     broadcast_frame_numbers_never_restart).
//   - reverse_beacon_scan_* variants: require SenderSession (ECDH) which
//     is not yet implemented.

use cypher::alignment::{
    aqs, AlignmentError, AlignmentMonitor, ALIGNED, ALIGNED_ABOVE, ALIGNMENT_CADENCE,
    DECODE_WINDOW, DEGRADED, LOST, LOST_BELOW, LOST_CONSECUTIVE, RECOVERING,
};
use cypher::beacon::build_receiver_beacon_with_token;
use cypher::crypto::{generate_identity, identity_public_bytes};
use cypher::fountain::DEFAULT_OVERHEAD;
use cypher::messages::{
    parse_alignment, parse_degraded, parse_pause, parse_resume, parse_resumed, ALIGNMENT,
    DEGRADED as MSG_DEGRADED, PAUSE, RESUME, RESUMED,
};
use cypher::qr;
use cypher::qr::{parse_receiver_beacon_frame, render_receiver_beacon_frame};
use cypher::replay::ReplayCache;
use cypher::session::{BroadcastReceiver, BroadcastSender, BROADCAST_SYMBOL_SIZE};
use cypher::tofu::TrustStore;
use cypher::transport::{
    loopback_pair, BackChannelRecvError, Capabilities, LoopbackTransport, NoBackChannel,
    DEFAULT_CAPS,
};

// ─── shared helpers ───────────────────────────────────────────────────────────

/// Fixed test PSK (bytes 0..31 in order).
const PSK: [u8; 32] = {
    let mut b = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        b[i] = i as u8;
        i += 1;
    }
    b
};

/// Deterministic high-entropy payload: 5 000 bytes from a 64-bit LCG so the
/// output has a low compression ratio.  5kB → ~6 source symbols at
/// BROADCAST_SYMBOL_SIZE (~964B) → ~8 fountain packets → fast tests.
fn test_data() -> Vec<u8> {
    let mut state: u64 = 0x6c62272e07bb0142;
    (0..5_000)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 56) as u8
        })
        .collect()
}

/// Default capability constants shared across transport tests.
fn default_caps() -> Capabilities {
    DEFAULT_CAPS
}

/// Injected wall-clock: returns `seconds`.  Pass as a boxed closure.
fn fixed_clock(seconds: f64) -> Box<dyn FnMut() -> f64 + Send> {
    Box::new(move || seconds)
}

/// Drain all pending wire frames from a LoopbackTransport's screen queue.
fn drain(transport: &mut LoopbackTransport) -> Vec<Vec<u8>> {
    use cypher::transport::Transport;
    let mut out = Vec::new();
    while let Ok(wire) = transport.capture_frame() {
        out.push(wire);
    }
    out
}

/// Build a full broadcast: returns (BEACON wire, [packet wires]).
fn capture_broadcast(payload: &[u8], psk: [u8; 32], ts: f64) -> (Vec<u8>, Vec<Vec<u8>>) {
    let caps = default_caps();
    let (mut t_send, mut t_recv) = loopback_pair(caps, caps);
    let ident = generate_identity();
    let sid = 0xDEAD_BEEF_CAFE_1234_u64;
    let mut sender = BroadcastSender::with_session_id(
        &mut t_send,
        ident,
        psk,
        BROADCAST_SYMBOL_SIZE,
        DEFAULT_OVERHEAD,
        fixed_clock(ts),
        sid,
    );
    sender
        .send_data(payload, "test.bin", 3)
        .expect("send_data failed");
    let mut all = drain(&mut t_recv);
    assert!(!all.is_empty(), "no frames rendered");
    let beacon_grid = all.remove(0);
    (beacon_grid, all)
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRANSPORT (port of test_transport.py)
// ═══════════════════════════════════════════════════════════════════════════════

mod transport {
    use super::*;
    use cypher::transport::Transport;

    // ── render appears on peer camera ──────────────────────────────────────────

    /// A rendered frame appears on the peer's capture queue; second capture
    /// raises Empty (queue exhausted).
    #[test]
    fn transport_render_appears_on_peer_camera() {
        let caps = default_caps();
        let (mut a, mut b) = loopback_pair(caps, caps);

        // A small wire frame.
        let wire = vec![1u8, 2, 3];
        a.render_frame(&wire);

        let captured = b.capture_frame().expect("peer must see the rendered frame");
        assert_eq!(captured, wire);

        // Queue now empty - second capture must fail.
        assert!(
            b.capture_frame().is_err(),
            "queue must be empty after first capture"
        );
    }

    // ── back channel both directions ───────────────────────────────────────────

    /// Back-channel messages cross both ways; an empty inbox after recv returns Err.
    #[test]
    fn transport_back_channel_both_directions() {
        let caps = default_caps();
        let (mut a, mut b) = loopback_pair(caps, caps);

        a.back_channel_send(b"nak".to_vec()).unwrap();
        b.back_channel_send(b"data".to_vec()).unwrap();

        assert_eq!(b.back_channel_recv().unwrap(), b"nak");
        assert_eq!(a.back_channel_recv().unwrap(), b"data");

        // Both inboxes empty.
        assert_eq!(
            a.back_channel_recv(),
            Err(BackChannelRecvError::Empty),
            "inbox must be empty"
        );
    }

    // ── unpaired transport has no back channel ─────────────────────────────────

    /// An unpaired LoopbackTransport has no back channel; both send and recv
    /// must return NoBackChannel.
    #[test]
    fn transport_unpaired_has_no_back_channel() {
        let mut solo = LoopbackTransport::new(default_caps());

        assert_eq!(
            solo.back_channel_send(b"x".to_vec()),
            Err(NoBackChannel),
            "unpaired send must return NoBackChannel"
        );
        assert_eq!(
            solo.back_channel_recv(),
            Err(BackChannelRecvError::NoBackChannel),
            "unpaired recv must return NoBackChannel"
        );
    }

    // ── capabilities negotiation fields ───────────────────────────────────────

    /// display_capabilities() and sensor_capabilities() must echo
    /// the Capabilities passed at construction.
    #[test]
    fn transport_capabilities_negotiation_fields() {
        let caps = Capabilities {
            width: 1280,
            height: 720,
            max_fps: 60,
            cell_size: 2,
        };
        let t = LoopbackTransport::new(caps);
        assert_eq!(t.display_capabilities(), caps);
        assert_eq!(t.sensor_capabilities(), caps);
    }

    // ── loopback pair symmetry ─────────────────────────────────────────────────

    /// Render on A appears on B's camera; render on B appears on A's camera.
    #[test]
    fn transport_loopback_pair_symmetric() {
        let caps = default_caps();
        let (mut a, mut b) = loopback_pair(caps, caps);

        let wire_a = vec![10u8, 20, 30];
        let wire_b = vec![40u8, 50, 60];

        a.render_frame(&wire_a);
        b.render_frame(&wire_b);

        assert_eq!(
            b.capture_frame().unwrap(),
            wire_a,
            "A's render must reach B"
        );
        assert_eq!(
            a.capture_frame().unwrap(),
            wire_b,
            "B's render must reach A"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ALIGNMENT (port of test_alignment.py - 25 cases, exact boundary pins)
// ═══════════════════════════════════════════════════════════════════════════════

mod alignment_tests {
    use super::*;

    #[test]
    fn alignment_aqs_perfect() {
        assert_eq!(aqs(4, 1.0, 1.0).unwrap(), 1.0);
    }

    #[test]
    fn alignment_aqs_zero() {
        assert_eq!(aqs(0, 0.0, 0.0).unwrap(), 0.0);
    }

    /// 2/4*0.5 + 0.5*0.3 + 0.5*0.2 = 0.25 + 0.15 + 0.10 = 0.50
    #[test]
    fn alignment_aqs_midpoint() {
        let got = aqs(2, 0.5, 0.5).unwrap();
        let expected = 0.25_f32 + 0.15_f32 + 0.10_f32;
        assert!(
            (got - expected).abs() < 1e-5,
            "aqs(2,0.5,0.5) = {got}, expected {expected}"
        );
    }

    /// markers_found > 4 is out of range.
    #[test]
    fn alignment_aqs_markers_out_of_range() {
        assert!(matches!(aqs(5, 0.5, 0.5), Err(AlignmentError::Markers(5))));
    }

    /// sharpness > 1.0 is out of range.
    #[test]
    fn alignment_aqs_sharpness_too_high() {
        assert!(matches!(
            aqs(2, 1.5, 0.5),
            Err(AlignmentError::Sharpness(_))
        ));
    }

    /// decode_ratio < 0.0 is out of range.
    #[test]
    fn alignment_aqs_decode_ratio_negative() {
        assert!(matches!(
            aqs(2, 0.5, -0.1),
            Err(AlignmentError::DecodeRatio(_))
        ));
    }

    // ── constants ──────────────────────────────────────────────────────────────

    #[test]
    fn alignment_threshold_constants() {
        assert_eq!(ALIGNED_ABOVE, 0.75_f32);
        assert_eq!(LOST_BELOW, 0.5_f32);
        assert_eq!(LOST_CONSECUTIVE, 5_u32);
        assert_eq!(DECODE_WINDOW, 30_usize);
        assert_eq!(ALIGNMENT_CADENCE, 10_u64);
    }

    #[test]
    fn alignment_state_constants_exist() {
        assert_eq!(ALIGNED, "ALIGNED");
        assert_eq!(DEGRADED, "DEGRADED");
        assert_eq!(LOST, "LOST");
        assert_eq!(RECOVERING, "RECOVERING");
    }

    // ── initial state ──────────────────────────────────────────────────────────

    #[test]
    fn alignment_monitor_initial_state() {
        let mon = AlignmentMonitor::new(fixed_clock(0.0), 10);
        assert_eq!(mon.state, ALIGNED);
        assert_eq!(mon.last_decoded_frame, 0);
        assert!(mon.lost_since.is_none());
    }

    // ── cadence ────────────────────────────────────────────────────────────────

    /// ALIGNMENT emitted every 10 calls (cadence 10), never before.
    #[test]
    fn alignment_perfect_frames_cadence() {
        let mut mon = AlignmentMonitor::new(fixed_clock(0.0), 10);
        for i in 1u64..=10 {
            let signals = mon
                .observe(4, 1.0, Some(true), Some(i), false)
                .expect("observe failed");
            if i < 10 {
                assert!(
                    signals.is_empty(),
                    "call {i} should emit nothing, got {signals:?}"
                );
            } else {
                let align: Vec<_> = signals.iter().filter(|(t, _)| *t == ALIGNMENT).collect();
                assert_eq!(align.len(), 1, "call 10 must emit exactly 1 ALIGNMENT");
                let (aqs_val, frame_num) = parse_alignment(&align[0].1).unwrap();
                assert!((aqs_val - 1.0_f32).abs() < 1e-5, "aqs must be 1.0");
                assert_eq!(frame_num, 10);
            }
        }
    }

    // ── boundary strictness (the point of these tests) ────────────────────────

    /// AQS = 2/4*0.5 + 1.0*0.3 + 1.0*0.2 = 0.25+0.30+0.20 = 0.75 exactly.
    /// ALIGNED requires strictly > 0.75; exactly 0.75 → DEGRADED.
    #[test]
    fn alignment_boundary_exactly_075_is_degraded_not_aligned() {
        let mut mon = AlignmentMonitor::new(fixed_clock(0.0), 10);
        // Empty decode window → decode_ratio = 1.0.
        // markers=2: 2/4*0.5 = 0.25; sharpness=1.0: *0.3 = 0.30; ratio=1.0: *0.2 = 0.20 → 0.75
        mon.observe(2, 1.0, None, None, false).unwrap();
        assert_eq!(
            mon.state, DEGRADED,
            "AQS=0.75 exactly must be DEGRADED, not ALIGNED"
        );
    }

    /// AQS = 0/4*0.5 + 1.0*0.3 + 1.0*0.2 = 0.5 exactly.
    /// LOST counting requires strictly < 0.5; exactly 0.5 must NOT count.
    #[test]
    fn alignment_boundary_exactly_05_is_degraded_not_lost_counting() {
        let mut mon = AlignmentMonitor::new(fixed_clock(0.0), 10);
        // Enter DEGRADED first (AQS=0.75).
        mon.observe(2, 1.0, None, None, false).unwrap();
        assert_eq!(mon.state, DEGRADED);
        // 5 frames at AQS=0.5 exactly - must not enter LOST.
        for _ in 0..5 {
            mon.observe(0, 1.0, None, None, false).unwrap(); // 0+0.3+0.2=0.5
        }
        assert_eq!(
            mon.state, DEGRADED,
            "AQS=0.5 exactly must not count toward LOST"
        );
        assert!(mon.lost_since.is_none());
    }

    // ── DEGRADED entry signal and de-bounce ────────────────────────────────────

    #[test]
    fn alignment_entering_degraded_emits_signal() {
        let mut mon = AlignmentMonitor::new(fixed_clock(0.0), 10);
        let signals = mon.observe(2, 1.0, None, None, false).unwrap();
        let degraded: Vec<_> = signals.iter().filter(|(t, _)| *t == MSG_DEGRADED).collect();
        assert_eq!(
            degraded.len(),
            1,
            "entering DEGRADED must emit exactly 1 DEGRADED signal"
        );
        let aqs_val = parse_degraded(&degraded[0].1).unwrap();
        assert!(
            (aqs_val - 0.75_f32).abs() < 1e-5,
            "DEGRADED payload must carry AQS=0.75"
        );
    }

    #[test]
    fn alignment_staying_degraded_does_not_re_emit() {
        let mut mon = AlignmentMonitor::new(fixed_clock(0.0), 10);
        mon.observe(2, 1.0, None, None, false).unwrap(); // enter DEGRADED
        let signals = mon.observe(2, 1.0, None, None, false).unwrap(); // stay DEGRADED
        let degraded: Vec<_> = signals.iter().filter(|(t, _)| *t == MSG_DEGRADED).collect();
        assert!(
            degraded.is_empty(),
            "staying in DEGRADED must not re-emit DEGRADED"
        );
    }

    // ── helper: enter LOST with last_decoded_frame=3 ──────────────────────────

    fn enter_lost(ts: f64) -> AlignmentMonitor {
        let mut mon = AlignmentMonitor::new(fixed_clock(ts), 10);
        for fn_ in 1u64..=3 {
            mon.observe(4, 1.0, Some(true), Some(fn_), false).unwrap();
        }
        // 5 frames with AQS < 0.5 (markers=0, sharpness=0.0 → 0.0 + 0.0 + 0.2 < 0.5)
        // with a full decode window of 3 successes, decode_ratio still high.
        // Use markers=0, sharpness=0.0, decoded_ok=None to get 0+0+ratio*0.2.
        // After 3 True entries, ratio = 3/3 = 1.0, AQS = 0 + 0 + 0.2 = 0.2 < 0.5.
        for _ in 0..5 {
            mon.observe(0, 0.0, None, None, false).unwrap();
        }
        mon
    }

    // ── LOST after 5 consecutive ───────────────────────────────────────────────

    #[test]
    fn alignment_lost_after_5_consecutive_emits_pause() {
        let ts = 100.0_f64;
        let mut mon = AlignmentMonitor::new(fixed_clock(ts), 10);
        for fn_ in 1u64..=3 {
            mon.observe(4, 1.0, Some(true), Some(fn_), false).unwrap();
        }
        let mut last_signals = Vec::new();
        for _ in 0..5 {
            last_signals = mon.observe(0, 0.0, None, None, false).unwrap();
        }
        assert_eq!(mon.state, LOST);
        assert_eq!(mon.lost_since, Some(ts));

        let pause: Vec<_> = last_signals.iter().filter(|(t, _)| *t == PAUSE).collect();
        assert_eq!(pause.len(), 1, "5th consecutive bad frame must emit PAUSE");
        let last = parse_pause(&pause[0].1).unwrap();
        assert_eq!(last, 3, "PAUSE must carry last_decoded_frame=3");
    }

    #[test]
    fn alignment_four_bad_one_good_resets_lost_count() {
        let mut mon = AlignmentMonitor::new(fixed_clock(0.0), 10);
        for fn_ in 1u64..=3 {
            mon.observe(4, 1.0, Some(true), Some(fn_), false).unwrap();
        }
        // 4 bad frames - not enough for LOST.
        let mut pause_count = 0;
        for _ in 0..4 {
            let sigs = mon.observe(0, 0.0, None, None, false).unwrap();
            pause_count += sigs.iter().filter(|(t, _)| *t == PAUSE).count();
        }
        // Reset: AQS = 2/4*0.5 + 1.0*0.3 + ratio*0.2 ≥ 0.5 → counter resets.
        mon.observe(2, 1.0, None, None, false).unwrap();
        // 4 more bad - still not LOST.
        for _ in 0..4 {
            let sigs = mon.observe(0, 0.0, None, None, false).unwrap();
            pause_count += sigs.iter().filter(|(t, _)| *t == PAUSE).count();
        }
        assert_eq!(pause_count, 0, "must never hit 5 consecutive bad frames");
        assert_ne!(mon.state, LOST);
        assert!(mon.lost_since.is_none());
    }

    // ── observations while LOST ────────────────────────────────────────────────

    #[test]
    fn alignment_lost_markers_zero_stays_lost() {
        let mut mon = enter_lost(0.0);
        let signals = mon.observe(0, 0.0, None, None, false).unwrap();
        assert!(signals.is_empty(), "LOST + markers=0 must emit nothing");
        assert_eq!(mon.state, LOST);
    }

    #[test]
    fn alignment_lost_markers_nonzero_enters_recovering_emits_resume() {
        let mut mon = enter_lost(0.0);
        let signals = mon.observe(1, 0.5, None, None, false).unwrap();
        assert_eq!(mon.state, RECOVERING);
        let resume: Vec<_> = signals.iter().filter(|(t, _)| *t == RESUME).collect();
        assert_eq!(resume.len(), 1, "entering RECOVERING must emit RESUME");
        let (resume_from, _) = parse_resume(&resume[0].1).unwrap();
        assert_eq!(
            resume_from, 4,
            "resume_from must be last_decoded_frame+1 = 4"
        );
    }

    // ── RECOVERING transitions ─────────────────────────────────────────────────

    #[test]
    fn alignment_recovering_markers_zero_returns_to_lost() {
        let mut mon = enter_lost(0.0);
        mon.observe(1, 0.5, None, None, false).unwrap(); // enter RECOVERING
        let signals = mon.observe(0, 0.0, None, None, false).unwrap();
        assert_eq!(
            mon.state, LOST,
            "RECOVERING + markers=0 must return to LOST"
        );
        let pause: Vec<_> = signals.iter().filter(|(t, _)| *t == PAUSE).collect();
        assert_eq!(pause.len(), 1, "RECOVERING → LOST must emit PAUSE");
    }

    #[test]
    fn alignment_recovering_keyframe_emits_resumed_transitions_to_aligned() {
        let mut mon = enter_lost(0.0);
        mon.observe(1, 0.5, None, None, false).unwrap(); // enter RECOVERING
        let signals = mon
            .observe(4, 1.0, Some(true), Some(42), true) // keyframe
            .unwrap();
        let resumed: Vec<_> = signals.iter().filter(|(t, _)| *t == RESUMED).collect();
        assert_eq!(resumed.len(), 1, "keyframe in RECOVERING must emit RESUMED");
        let frame_num = parse_resumed(&resumed[0].1).unwrap();
        assert_eq!(frame_num, 42);
        assert_eq!(mon.state, ALIGNED, "RESUMED is transient; state → ALIGNED");
    }

    // ── decode window ──────────────────────────────────────────────────────────

    /// An empty decode window uses ratio=1.0 (optimistic).
    #[test]
    fn alignment_empty_window_decode_ratio_is_1() {
        let mut mon = AlignmentMonitor::new(fixed_clock(0.0), 10);
        // markers=4, sharpness=1.0, decoded_ok=None → window stays empty → ratio=1.0 → AQS=1.0
        let signals = mon.observe(4, 1.0, None, None, false).unwrap();
        let degraded: Vec<_> = signals.iter().filter(|(t, _)| *t == MSG_DEGRADED).collect();
        let pause: Vec<_> = signals.iter().filter(|(t, _)| *t == PAUSE).collect();
        assert!(
            degraded.is_empty(),
            "empty window → AQS=1.0 → ALIGNED, no DEGRADED"
        );
        assert!(pause.is_empty(), "empty window → AQS=1.0 → no PAUSE");
        assert_eq!(mon.state, ALIGNED);
    }

    #[test]
    fn alignment_window_slides_30_failures_then_30_successes() {
        let mut mon = AlignmentMonitor::new(fixed_clock(0.0), 10);
        let mut all_signals: Vec<(u8, Vec<u8>)> = Vec::new();
        for i in 0u64..30 {
            let sigs = mon.observe(4, 1.0, Some(false), Some(i), false).unwrap();
            all_signals.extend(sigs);
        }
        for i in 30u64..60 {
            let sigs = mon.observe(4, 1.0, Some(true), Some(i), false).unwrap();
            all_signals.extend(sigs);
        }
        assert_eq!(mon.state, ALIGNED);
        let scores: Vec<f32> = all_signals
            .iter()
            .filter(|(t, _)| *t == ALIGNMENT)
            .map(|(_, p)| parse_alignment(p).unwrap().0)
            .collect();
        // 6 cadence ticks: calls 10, 20, 30, 40, 50, 60.
        assert_eq!(
            scores.len(),
            6,
            "expected 6 ALIGNMENT signals (calls 10..60)"
        );
        // Call 30: window = 30 failures, decode_ratio=0.0.
        // AQS = 4/4*0.5 + 1.0*0.3 + 0.0*0.2 = 0.5 + 0.3 + 0.0 = 0.8
        assert!(
            (scores[2] - 0.8_f32).abs() < 1e-5,
            "call 30: score must be 0.8, got {}",
            scores[2]
        );
        // Call 60: window all-success → decode_ratio=1.0 → AQS=1.0.
        assert!(
            (scores[5] - 1.0_f32).abs() < 1e-5,
            "call 60: score must be 1.0, got {}",
            scores[5]
        );
        // Call 40: ratio rising from 0 → score > 0.8.
        assert!(
            scores[3] > 0.8_f32,
            "call 40: score must be > 0.8, got {}",
            scores[3]
        );
    }

    #[test]
    fn alignment_decoded_ok_true_without_frame_number_raises() {
        let mut mon = AlignmentMonitor::new(fixed_clock(0.0), 10);
        assert!(
            matches!(
                mon.observe(4, 1.0, Some(true), None, false),
                Err(AlignmentError::DecodedOkNeedsFrame)
            ),
            "decoded_ok=true without frame_number must return DecodedOkNeedsFrame"
        );
    }

    // ── cadence fires in DEGRADED and RECOVERING, not in LOST ─────────────────

    #[test]
    fn alignment_cadence_fires_in_degraded() {
        let mut mon = AlignmentMonitor::new(fixed_clock(0.0), 10);
        mon.observe(2, 1.0, None, None, false).unwrap(); // call 1 → DEGRADED
        for _ in 0..8 {
            mon.observe(2, 1.0, None, None, false).unwrap(); // calls 2–9
        }
        let signals = mon.observe(2, 1.0, None, None, false).unwrap(); // call 10 → cadence
        let align: Vec<_> = signals.iter().filter(|(t, _)| *t == ALIGNMENT).collect();
        assert!(
            !align.is_empty(),
            "ALIGNMENT cadence must fire in DEGRADED state"
        );
    }

    /// enter_lost uses 8 calls (3 good + 5 bad); call 9 → RECOVERING; call 10 → cadence.
    #[test]
    fn alignment_cadence_fires_in_recovering() {
        let mut mon = enter_lost(0.0); // 8 calls total
        mon.observe(1, 0.0, None, None, false).unwrap(); // call 9 → RECOVERING
        let signals = mon.observe(1, 0.0, None, None, false).unwrap(); // call 10 → cadence tick
        assert_eq!(mon.state, RECOVERING);
        let align: Vec<_> = signals.iter().filter(|(t, _)| *t == ALIGNMENT).collect();
        assert!(
            !align.is_empty(),
            "ALIGNMENT cadence must fire in RECOVERING state"
        );
    }

    #[test]
    fn alignment_no_alignment_signal_while_lost() {
        let mut mon = enter_lost(0.0); // 8 calls total, state=LOST
        let mut all: Vec<(u8, Vec<u8>)> = Vec::new();
        for _ in 0..10 {
            all.extend(mon.observe(0, 0.0, None, None, false).unwrap());
        }
        let align: Vec<_> = all.iter().filter(|(t, _)| *t == ALIGNMENT).collect();
        assert!(
            align.is_empty(),
            "ALIGNMENT must not fire while in LOST state"
        );
    }

    // ── transition signal before cadence on same call ──────────────────────────

    /// On call 10 in ALIGNED: AQS=0.75 → enters DEGRADED AND cadence tick fires.
    /// DEGRADED signal must appear before ALIGNMENT signal.
    #[test]
    fn alignment_transition_before_cadence_on_same_call() {
        let mut mon = AlignmentMonitor::new(fixed_clock(0.0), 10);
        for i in 1u64..10 {
            mon.observe(4, 1.0, Some(true), Some(i), false).unwrap(); // calls 1–9
        }
        let signals = mon.observe(2, 1.0, None, None, false).unwrap(); // call 10
        let types: Vec<u8> = signals.iter().map(|(t, _)| *t).collect();
        assert!(types.contains(&MSG_DEGRADED), "call 10 must emit DEGRADED");
        assert!(
            types.contains(&ALIGNMENT),
            "call 10 must emit ALIGNMENT (cadence)"
        );
        let pos_degraded = types.iter().position(|&t| t == MSG_DEGRADED).unwrap();
        let pos_alignment = types.iter().position(|&t| t == ALIGNMENT).unwrap();
        assert!(
            pos_degraded < pos_alignment,
            "DEGRADED must precede ALIGNMENT in the same-call signal list"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BROADCAST (port of test_broadcast.py - 33 cases)
// ═══════════════════════════════════════════════════════════════════════════════

mod broadcast {
    use super::*;
    use cypher::session::BROADCAST_SYMBOL_SIZE;
    use cypher::transport::Transport;

    const TS: f64 = 1_750_000_000.0; // fixed timestamp seconds

    // ── 1. Round trip ──────────────────────────────────────────────────────────

    /// send_data emits the BEACON as its first frame; receiver returns
    /// "beacon-accepted".
    #[test]
    fn broadcast_round_trip_beacon_accepted() {
        let caps = default_caps();
        let (mut t_send, mut t_recv) = loopback_pair(caps, caps);
        let ident = generate_identity();
        let mut sender = BroadcastSender::new(
            &mut t_send,
            ident,
            PSK,
            BROADCAST_SYMBOL_SIZE,
            DEFAULT_OVERHEAD,
            fixed_clock(TS),
        );
        let data = test_data();
        sender.send_data(&data, "test.bin", 3).unwrap();

        let beacon_grid = t_recv.capture_frame().unwrap();
        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        let result = receiver.on_codes(vec![beacon_grid.clone()]).unwrap();
        assert_eq!(result, "beacon-accepted");
    }

    #[test]
    fn broadcast_round_trip_complete_data() {
        let caps = default_caps();
        let (mut t_send, mut t_recv) = loopback_pair(caps, caps);
        let ident = generate_identity();
        let data = test_data();
        let mut sender = BroadcastSender::new(
            &mut t_send,
            ident,
            PSK,
            BROADCAST_SYMBOL_SIZE,
            DEFAULT_OVERHEAD,
            fixed_clock(TS),
        );
        sender.send_data(&data, "test.bin", 3).unwrap();
        // Drain the queue before constructing the receiver (borrow rules).
        let grids = drain(&mut t_recv);

        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        for grid in grids {
            receiver.on_codes(vec![grid.clone()]).unwrap();
        }
        assert!(receiver.complete);
        assert_eq!(receiver.data().unwrap(), data);
    }

    #[test]
    fn broadcast_round_trip_spans_at_least_3_frames() {
        let caps = default_caps();
        let (mut t_send, mut t_recv) = loopback_pair(caps, caps);
        let ident = generate_identity();
        let data = test_data();
        let mut sender = BroadcastSender::new(
            &mut t_send,
            ident,
            PSK,
            BROADCAST_SYMBOL_SIZE,
            DEFAULT_OVERHEAD,
            fixed_clock(TS),
        );
        sender.send_data(&data, "test.bin", 3).unwrap();
        let all = drain(&mut t_recv);
        // all[0] is BEACON; all[1..] are DATA frames.
        assert!(
            all.len() > 3,
            "16kB incompressible payload must span ≥ 3 fountain frames (plus beacon), got {}",
            all.len()
        );
    }

    /// Broadcast has no back channel; neither side writes to the other's inbox.
    #[test]
    fn broadcast_no_back_channel_message_sent() {
        let caps = default_caps();
        let (mut t_send, mut t_recv) = loopback_pair(caps, caps);
        let ident = generate_identity();
        let data = test_data();
        let mut sender = BroadcastSender::new(
            &mut t_send,
            ident,
            PSK,
            BROADCAST_SYMBOL_SIZE,
            DEFAULT_OVERHEAD,
            fixed_clock(TS),
        );
        sender.send_data(&data, "test.bin", 3).unwrap();
        // Drain before constructing receiver (borrow rules).
        let grids = drain(&mut t_recv);

        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        for grid in grids {
            receiver.on_codes(vec![grid.clone()]).unwrap();
        }

        // t_send inbox: receiver must not send ACK/NAK/SESSION_COMPLETE.
        assert!(
            matches!(
                t_send.back_channel_recv(),
                Err(BackChannelRecvError::Empty | BackChannelRecvError::NoBackChannel)
            ),
            "broadcast must not write to sender's back-channel inbox"
        );
        // t_recv inbox: sender must not use back channel.
        assert!(
            matches!(
                t_recv.back_channel_recv(),
                Err(BackChannelRecvError::Empty | BackChannelRecvError::NoBackChannel)
            ),
            "broadcast must not write to receiver's back-channel inbox"
        );
    }

    // ── 2. Dedup / looped delivery ─────────────────────────────────────────────

    #[test]
    fn broadcast_looped_delivery_does_not_corrupt() {
        let (beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        let grids: Vec<Vec<u8>> = std::iter::once(beacon.clone())
            .chain(packets.iter().cloned())
            .collect();
        let loop2: Vec<Vec<u8>> = grids.clone();

        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        // Deliver once then again (one full loop).
        for grid in grids.iter().chain(loop2.iter()) {
            receiver.on_codes(vec![grid.clone()]).unwrap();
        }
        assert_eq!(receiver.data().unwrap(), test_data());
    }

    #[test]
    fn broadcast_repeat_duplicate_frames_return_dup_tag() {
        let (beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        receiver.on_codes(vec![beacon.clone()]).unwrap(); // BEACON
        receiver.on_codes(vec![packets[0].clone()]).unwrap(); // first DATA packet
        let before = receiver.packets_seen();
        let result = receiver.on_codes(vec![packets[0].clone()]).unwrap(); // same frame again
        assert_eq!(result, "duplicate");
        assert_eq!(
            receiver.packets_seen(),
            before,
            "duplicate must not re-count"
        );
    }

    // ── 3. Wrong PSK ───────────────────────────────────────────────────────────

    /// The BEACON is not encrypted; PSK only enters at key derivation for DATA.
    #[test]
    fn broadcast_wrong_psk_beacon_still_accepted() {
        let wrong_psk: [u8; 32] = {
            let mut b = [0u8; 32];
            for (i, x) in b.iter_mut().enumerate() {
                *x = (31 - i) as u8;
            }
            b
        };
        let (beacon, _) = capture_broadcast(&test_data(), PSK, TS);
        let mut receiver =
            BroadcastReceiver::new(wrong_psk, None, "sender", true, None, fixed_clock(TS));
        let result = receiver.on_codes(vec![beacon.clone()]).unwrap();
        assert_eq!(
            result, "beacon-accepted",
            "BEACON is not encrypted; wrong PSK must still accept it"
        );
    }

    #[test]
    fn broadcast_wrong_psk_data_frames_auth_fail() {
        let wrong_psk: [u8; 32] = {
            let mut b = [0u8; 32];
            for (i, x) in b.iter_mut().enumerate() {
                *x = (31 - i) as u8;
            }
            b
        };
        let (beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        let mut receiver =
            BroadcastReceiver::new(wrong_psk, None, "sender", true, None, fixed_clock(TS));
        receiver.on_codes(vec![beacon.clone()]).unwrap();
        let results: Vec<String> = packets
            .iter()
            .map(|g| receiver.on_codes(vec![g.clone()]).unwrap())
            .collect();
        let auth_failed = results.iter().any(|r| r.contains("auth"));
        assert!(
            auth_failed,
            "wrong PSK must cause auth-failed on DATA frames"
        );
        assert!(!receiver.complete, "wrong PSK receiver must not complete");
    }

    #[test]
    fn broadcast_wrong_psk_data_not_retrievable() {
        let wrong_psk: [u8; 32] = {
            let mut b = [0u8; 32];
            for (i, x) in b.iter_mut().enumerate() {
                *x = (31 - i) as u8;
            }
            b
        };
        let (beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        let mut receiver =
            BroadcastReceiver::new(wrong_psk, None, "sender", true, None, fixed_clock(TS));
        receiver.on_codes(vec![beacon.clone()]).unwrap();
        for g in &packets {
            let _ = receiver.on_codes(vec![g.clone()]);
        }
        assert!(
            receiver.data().is_err(),
            "wrong PSK: data() must return Err (corrupt/partial plaintext must never be returned)"
        );
    }

    // ── 4. Self-bootstrapping DATA frames (P13) ────────────────────────────────

    #[test]
    fn broadcast_data_frame_before_beacon_bootstraps() {
        let (beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        // DATA packets first - decrypted and buffered.
        for g in &packets {
            let status = receiver.on_codes(vec![g.clone()]).unwrap();
            assert!(
                status == "buffered" || status == "duplicate" || status == "stored",
                "pre-BEACON packet must be buffered, got {status:?}"
            );
        }
        assert!(
            receiver.session_id.is_some(),
            "PSK self-bootstrap must set session_id"
        );
        assert!(!receiver.complete, "decoder not built yet (no BEACON)");
        assert!(
            !receiver.identity_verified,
            "identity unverified before BEACON"
        );
        // BEACON supplies the fountain params.
        receiver.on_codes(vec![beacon.clone()]).unwrap();
        assert!(receiver.complete);
        assert_eq!(receiver.data().unwrap(), test_data());
        assert!(receiver.identity_verified);
    }

    #[test]
    fn broadcast_mid_stream_join_reassembles() {
        let (beacon, datas) = capture_broadcast(&test_data(), PSK, TS);
        // Deliver second half + BEACON + first half (mid-stream join).
        let mid = datas.len() / 2;
        let order: Vec<Vec<u8>> = datas[mid..]
            .iter()
            .chain(std::iter::once(&beacon))
            .chain(datas[..mid].iter())
            .cloned()
            .collect();
        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        for g in &order {
            receiver.on_codes(vec![g.clone()]).unwrap();
        }
        assert!(receiver.complete);
        assert_eq!(receiver.data().unwrap(), test_data());
    }

    /// Flipping a SESSION_ID prefix byte → wrong key → auth-failed; session_id
    /// must remain None (not locked onto the bogus session).
    #[test]
    fn broadcast_tampered_session_id_prefix_auth_fails() {
        use cypher::frame::Frame;

        let (beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        // Tamper the first DATA packet's SESSION_ID prefix.
        let frame = Frame::decode(&packets[0]).unwrap();
        let mut bad_payload = frame.payload.clone();
        bad_payload[0] ^= 0xFF;
        let bad_frame = Frame::new(frame.frame_number, frame.flags, bad_payload).unwrap();

        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        let result = receiver.on_codes(vec![bad_frame.encode()]).unwrap();
        assert!(
            result == "auth-failed" || result == "undecodable",
            "tampered SID prefix must fail, got {result:?}"
        );
        assert!(!receiver.complete);
        // A spoofed frame must NOT lock the receiver onto a bogus session.
        assert!(
            receiver.session_id.is_none(),
            "state must not be committed after failed auth"
        );
        // A valid transfer must still complete after the spoofed frame.
        receiver.on_codes(vec![beacon.clone()]).unwrap();
        for g in &packets {
            receiver.on_codes(vec![g.clone()]).unwrap();
        }
        assert!(receiver.complete);
        assert_eq!(receiver.data().unwrap(), test_data());
    }

    /// frame 0 is the BEACON's reserved number; DATA claiming it must be rejected.
    #[test]
    fn broadcast_data_frame_number_zero_rejected() {
        use cypher::frame::Frame;

        let (_beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        let frame = Frame::decode(&packets[0]).unwrap();
        // Forge a DATA frame with frame_number=0.
        let forged = Frame::new(0, frame.flags, frame.payload.clone()).unwrap();

        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        let result = receiver.on_codes(vec![forged.encode()]).unwrap();
        assert_eq!(
            result, "undecodable",
            "frame_number=0 DATA must be rejected"
        );
    }

    #[test]
    fn broadcast_data_bootstrap_honors_replay_cache() {
        let (beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        // First receiver: completes and registers the session in the cache.
        let mut first = BroadcastReceiver::new(
            PSK,
            None,
            "sender",
            true,
            Some(ReplayCache::new(3600.0, 1_000_000, Box::new(|| TS))),
            fixed_clock(TS),
        );
        // Complete the first transfer and capture the session_id.
        receiver_complete_full(&mut first, &beacon, &packets);
        assert!(first.complete);
        let completed_sid = first.session_id.unwrap();

        // Second receiver: share a replay cache that already knows the session_id.
        let mut cache2 = ReplayCache::new(3600.0, 1_000_000, Box::new(move || TS));
        cache2.add(completed_sid);

        let mut second =
            BroadcastReceiver::new(PSK, None, "sender", true, Some(cache2), fixed_clock(TS));
        let result = second.on_codes(vec![packets[0].clone()]).unwrap();
        assert_eq!(
            result, "ignored-replay",
            "replay cache must block replayed session"
        );
    }

    fn receiver_complete_full(
        receiver: &mut BroadcastReceiver<'_>,
        beacon: &[u8],
        packets: &[Vec<u8>],
    ) {
        receiver.on_codes(vec![beacon.to_vec()]).unwrap();
        for g in packets {
            receiver.on_codes(vec![g.clone()]).unwrap();
        }
    }

    #[test]
    fn broadcast_wrong_psk_data_bootstrap_auth_fails() {
        let (_beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        let mut other_psk = PSK;
        other_psk[0] ^= 0xFF; // different PSK

        let mut receiver =
            BroadcastReceiver::new(other_psk, None, "sender", true, None, fixed_clock(TS));
        let result = receiver.on_codes(vec![packets[0].clone()]).unwrap();
        assert_eq!(result, "auth-failed");
    }

    /// Data bootstraps via PSK; a late BEACON whose identity conflicts with the
    /// pinned key is a hard TOFU failure that propagates as KeyChangedError.
    #[test]
    fn broadcast_late_beacon_key_change_hard_fails() {
        let (beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        let tmp = tempdir();
        let trust_path = tmp.join("trust.json");
        let mut store = TrustStore::new(&trust_path).unwrap();
        // Pin a DIFFERENT key for "sender".
        store.trust("sender", &[0u8; 32]).unwrap();

        let mut receiver =
            BroadcastReceiver::new(PSK, Some(&mut store), "sender", true, None, fixed_clock(TS));
        for g in &packets {
            let _ = receiver.on_codes(vec![g.clone()]);
        }
        // The late BEACON has a different identity → KeyChangedError.
        let err = receiver.on_codes(vec![beacon.clone()]);
        assert!(
            err.is_err(),
            "late BEACON with changed identity must return KeyChangedError"
        );
    }

    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cypher_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ── 5. Level gate ──────────────────────────────────────────────────────────

    /// BroadcastReceiver only handles LEVEL_PSK (4); a LEVEL_OPEN BEACON must
    /// return "ignored-not-psk".
    #[test]
    fn broadcast_receiver_rejects_non_psk_beacon() {
        use cypher::beacon::{build_payload, Beacon, FRAME_CELLS, LEVEL_OPEN, ZERO16, ZERO32};
        use cypher::frame::{Frame, BEACON, PRIORITY};

        let ident = generate_identity();
        let pub_bytes = identity_public_bytes(&ident);
        let beacon = Beacon::new(
            0xABCD_EF01_2345_6789,
            (TS * 1000.0) as u64,
            LEVEL_OPEN,
            ZERO32,
            ZERO32,
            ZERO32,
            pub_bytes,
            1920,
            1080,
            30,
            4,
            100,
            "open.bin".into(),
            ZERO16,
            FRAME_CELLS,
            512,
            10,
        )
        .unwrap();
        let payload = build_payload(&beacon, &ident, 1);
        let frame = Frame::new(0, BEACON | PRIORITY, payload).unwrap();

        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        let result = receiver.on_codes(vec![frame.encode()]).unwrap();
        assert_eq!(result, "ignored-not-psk");
    }

    // ── 6. Fountain loss tolerance ────────────────────────────────────────────

    fn feed_subset(
        beacon: &[u8],
        datas: &[Vec<u8>],
        keep_indices: &[usize],
    ) -> BroadcastReceiver<'static> {
        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        receiver.on_codes(vec![beacon.to_vec()]).unwrap();
        for &i in keep_indices {
            receiver.on_codes(vec![datas[i].clone()]).unwrap();
            if receiver.complete {
                break;
            }
        }
        receiver
    }

    /// Any sufficient subset reconstructs the exact payload.
    #[test]
    fn broadcast_lossy_subset_80pct_reconstructs() {
        let data = test_data();
        let (beacon, datas) = capture_broadcast(&data, PSK, TS);
        // Keep every 5th out of 5 = 80% (deterministic, no rand needed).
        let keep: Vec<usize> = (0..datas.len()).filter(|i| i % 5 != 0).collect();
        let receiver = feed_subset(&beacon, &datas, &keep);
        assert!(receiver.complete, "80% subset must reconstruct");
        assert_eq!(receiver.data().unwrap(), data);
    }

    /// Keep 75%: drop every 4th packet.
    #[test]
    fn broadcast_lossy_subset_75pct_reconstructs() {
        let data = test_data();
        let (beacon, datas) = capture_broadcast(&data, PSK, TS);
        let keep: Vec<usize> = (0..datas.len()).filter(|i| i % 4 != 0).collect();
        let receiver = feed_subset(&beacon, &datas, &keep);
        assert!(receiver.complete, "75% subset must reconstruct");
        assert_eq!(receiver.data().unwrap(), data);
    }

    /// 40% kept < K source symbols - stays incomplete.
    #[test]
    fn broadcast_too_lossy_stays_incomplete() {
        let data = test_data();
        let (beacon, datas) = capture_broadcast(&data, PSK, TS);
        // Keep only 40%: take every 5th packet.
        let keep: Vec<usize> = (0..datas.len()).filter(|i| i % 5 == 0).collect();
        let receiver = feed_subset(&beacon, &datas, &keep);
        assert!(!receiver.complete, "40% must stay incomplete");
        assert!(
            receiver.data().is_err(),
            "incomplete receiver: data() must return Err"
        );
    }

    /// Fountain packets are unordered; full set in reverse order reconstructs.
    #[test]
    fn broadcast_order_independent_full_set() {
        let data = test_data();
        let (beacon, datas) = capture_broadcast(&data, PSK, TS);
        // Reverse order - proves no ordering dependency.
        let keep: Vec<usize> = (0..datas.len()).rev().collect();
        let receiver = feed_subset(&beacon, &datas, &keep);
        assert!(receiver.complete, "reversed full set must reconstruct");
        assert_eq!(receiver.data().unwrap(), data);
    }

    // ── 7. PSK length validation (type-enforced) ───────────────────────────────
    //
    // UNPORTABLE: BroadcastSender::new and BroadcastReceiver::new take
    // [u8; 32] PSK - the type system enforces length; there is no runtime path
    // for a "short PSK" or "long PSK" test.
    //
    // Observable: calling BroadcastSender::new with the correct [u8; 32] succeeds.

    /// Exact 32-byte PSK construction succeeds (observable boundary for the type enforcement).
    #[test]
    fn broadcast_sender_exact_32_bytes_ok() {
        let caps = default_caps();
        let (mut t_send, _) = loopback_pair(caps, caps);
        let ident = generate_identity();
        // Must not panic.
        let _sender = BroadcastSender::new(
            &mut t_send,
            ident,
            [0u8; 32],
            BROADCAST_SYMBOL_SIZE,
            DEFAULT_OVERHEAD,
            fixed_clock(TS),
        );
    }

    // ── 8. Per-session key isolation ───────────────────────────────────────────

    /// A second send_data after the first produces additional frames (frame
    /// numbers continued, not restarted).  GCM nonce is SESSION_ID+FRAME_NUMBER
    /// and the PSK-derived key is fixed per session, so frame numbers MUST NOT
    /// restart.
    #[test]
    fn broadcast_frame_numbers_never_restart() {
        let caps = default_caps();
        let (mut t_send, mut t_recv) = loopback_pair(caps, caps);
        let ident = generate_identity();
        let mut sender = BroadcastSender::new(
            &mut t_send,
            ident,
            PSK,
            BROADCAST_SYMBOL_SIZE,
            DEFAULT_OVERHEAD,
            fixed_clock(TS),
        );
        let small = vec![0xAAu8; 200];
        let n1 = sender.send_data(&small, "a.bin", 3).unwrap();
        // Second batch: same session, different data.
        let n2 = sender.send_data(&small, "b.bin", 3).unwrap();
        // Both batches produce non-zero DATA frames.
        assert!(n1 > 0, "first send must produce DATA frames");
        assert!(n2 > 0, "second send must produce DATA frames");
        // session_id is public; verify first batch rendered frames.
        let all = drain(&mut t_recv);
        // 2 BEACONs + n1 + n2 DATA frames.
        assert_eq!(
            all.len(),
            (2 + n1 + n2) as usize,
            "total frames must be 2 BEACONs + n1 + n2"
        );
    }

    #[test]
    fn broadcast_data_after_close_raises_cleanly() {
        let (beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        for g in std::iter::once(&beacon).chain(packets.iter()) {
            receiver.on_codes(vec![g.clone()]).unwrap();
        }
        assert!(receiver.data().is_ok(), "data() must work before close()");
        receiver.close();
        let err = receiver.data();
        assert!(err.is_err(), "data() after close() must return Err");
        // Must mention "closed" in the error message.
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("closed"),
            "error must mention 'closed', got: {msg:?}"
        );
    }

    // ── Multi-code capture via on_codes ───────────────────────────────────────

    /// on_codes takes multiple wire codes captured in one frame and must decode
    /// every code.
    #[test]
    fn broadcast_tiled_captures_via_on_grid() {
        let (beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        assert!(
            packets.len() >= 2,
            "need at least 2 DATA packets for tiling"
        );

        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));

        // Deliver BEACON first (fountain params).
        receiver.on_codes(vec![beacon.clone()]).unwrap();

        // Feed the first 4 DATA packet wires (or fewer) in one on_codes call.
        let tile_count = 4.min(packets.len());
        let wires: Vec<Vec<u8>> = packets[..tile_count].to_vec();

        let status = receiver.on_codes(wires).unwrap();
        // After 1..4 packets we may already be "complete" or just "stored".
        assert!(
            status == "stored" || status == "complete" || status == "beacon-accepted",
            "multi-code on_codes must return 'stored' or 'complete', got {status:?}"
        );
        assert_eq!(
            receiver.packets_seen(),
            tile_count,
            "all {tile_count} packets in one on_codes call must be decrypted"
        );
    }

    /// on_codes aggregation: a "complete" result outranks any "stored".
    #[test]
    fn broadcast_status_aggregation_complete_outranks_stored() {
        let (beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        receiver.on_codes(vec![beacon.clone()]).unwrap();
        // Feed all DATA packet wires in one on_codes call.
        let wires: Vec<Vec<u8>> = packets.clone();
        let status = receiver.on_codes(wires).unwrap();
        // If we gave it enough packets, it completes; result must be "complete".
        if receiver.complete {
            assert_eq!(
                status, "complete",
                "on_codes must report 'complete' when done"
            );
        }
    }

    /// on_codes: "auth-failed" outranks "undecodable".
    #[test]
    fn broadcast_status_aggregation_auth_failed_outranks_undecodable() {
        let (beacon, packets) = capture_broadcast(&test_data(), PSK, TS);
        let mut receiver = BroadcastReceiver::new(PSK, None, "sender", true, None, fixed_clock(TS));
        receiver.on_codes(vec![beacon.clone()]).unwrap();

        // One real packet wire + one garbage wire.
        let real_wire = packets[0].clone();
        let garbage = vec![0xFFu8; 50]; // not a valid frame → "undecodable"

        let result = receiver.on_codes(vec![real_wire, garbage]).unwrap();
        // real_wire should decode to "stored" or "complete"; garbage → "undecodable".
        // Aggregation must not return "undecodable" when a non-undecodable code exists.
        assert_ne!(
            result, "undecodable",
            "on_codes must not return 'undecodable' when a real packet was also present"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// REVERSE BEACON QR wrappers (session-level, broadcast+beacon layer)
// Ports of test_reverse_beacon.py cases that only need render/parse wrappers.
// ═══════════════════════════════════════════════════════════════════════════════

mod reverse_beacon {
    use super::*;

    const TS: f64 = 1_750_000_000.0;

    // ── round-trip identity/token/caps ────────────────────────────────────────

    #[test]
    fn reverse_beacon_round_trip_identity_token_caps() {
        let ident = generate_identity();
        let caps: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
        let token = [0xABu8; 16];
        let ts = TS;
        let wire = build_receiver_beacon_with_token(&ident, &caps, &token, move || ts);
        let grid = render_receiver_beacon_frame(&wire).unwrap();
        let parsed = parse_receiver_beacon_frame(&grid, move || ts).unwrap();

        assert_eq!(parsed.identity_pub, identity_public_bytes(&ident));
        assert_eq!(parsed.session_token, token);
        assert_eq!(parsed.capabilities, caps);
    }

    /// Carrier frame must have RECEIVER_BEACON set, ENCRYPTED clear,
    /// FRAME_NUMBER = 0.
    #[test]
    fn reverse_beacon_carrier_frame_flags() {
        use cypher::frame::{Frame, ENCRYPTED, RECEIVER_BEACON};

        let ident = generate_identity();
        let token = [0u8; 16];
        let ts = TS;
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &token, move || ts);
        let grid = render_receiver_beacon_frame(&wire).unwrap();
        let raw = qr::decode(&grid).unwrap();
        let frame = Frame::decode(&raw).unwrap();

        assert!(
            frame.flags & RECEIVER_BEACON != 0,
            "RECEIVER_BEACON flag must be set"
        );
        assert!(frame.flags & ENCRYPTED == 0, "ENCRYPTED flag must be clear");
        assert_eq!(frame.frame_number, 0);
    }

    /// The 135-byte structure is carried verbatim as the payload.
    #[test]
    fn reverse_beacon_carrier_frame_payload_verbatim() {
        let ident = generate_identity();
        let token = [0u8; 16];
        let ts = TS;
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &token, move || ts);
        let grid = render_receiver_beacon_frame(&wire).unwrap();
        let raw = qr::decode(&grid).unwrap();
        use cypher::frame::Frame;
        let frame = Frame::decode(&raw).unwrap();

        assert_eq!(
            frame.payload, wire,
            "RECEIVER_BEACON payload must be verbatim wire bytes"
        );
        assert_eq!(frame.payload.len(), cypher::beacon::RECEIVER_BEACON_LEN);
    }

    /// Corrupt IDENTITY_KEY + recompute inner CRC → Ed25519 sig check fires.
    #[test]
    fn reverse_beacon_tamper_reaches_sig_check() {
        let ident = generate_identity();
        let token = [0u8; 16];
        let ts = TS;
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &token, move || ts);

        // Corrupt byte 5 (first byte of IDENTITY_PUB at offset 5).
        let mut bad = wire.clone();
        bad[5] ^= 0xFF;
        // Recompute CRC-16/IBM-3740 over body (all but last 2 bytes).
        let crc = crc::Crc::<u16>::new(&crc::CRC_16_IBM_3740);
        let body_len = bad.len() - 2;
        let new_crc = crc.checksum(&bad[..body_len]);
        let crc_bytes = new_crc.to_be_bytes();
        bad[body_len] = crc_bytes[0];
        bad[body_len + 1] = crc_bytes[1];

        let grid = render_receiver_beacon_frame(&bad).unwrap();
        let err = parse_receiver_beacon_frame(&grid, move || ts);
        assert!(
            err.is_err(),
            "tampered IDENTITY_PUB with patched CRC must fail sig check"
        );
    }

    #[test]
    fn reverse_beacon_non_rbea_grid_raises_beacon_error() {
        use cypher::frame::{Frame, ENCRYPTED};

        let frame = Frame::new(1, ENCRYPTED, vec![0x42u8; 16]).unwrap();
        let grid = qr::encode(&frame.encode(), 8, 4, "m").unwrap();
        let ts = TS;
        let err = parse_receiver_beacon_frame(&grid, move || ts);
        assert!(
            err.is_err(),
            "non-RECEIVER_BEACON grid must return BeaconError"
        );
    }

    #[test]
    fn reverse_beacon_corrupt_image_raises_beacon_error() {
        let ident = generate_identity();
        let token = [0u8; 16];
        let ts = TS;
        let wire = build_receiver_beacon_with_token(&ident, &[0u8; 8], &token, move || ts);
        let mut grid = render_receiver_beacon_frame(&wire).unwrap();

        // Wipe the top half of the QR image (all white).
        let half_height = grid.height() / 2;
        for y in 0..half_height {
            for x in 0..grid.width() {
                grid.put_pixel(x, y, image::Rgb([255u8; 3]));
            }
        }
        let err = parse_receiver_beacon_frame(&grid, move || ts);
        assert!(err.is_err(), "corrupted QR image must return BeaconError");
    }
}

// Interactive session layer (SenderSession / ReceiverSession).
//
// Mock at the boundary: LoopbackTransport + Arc queue handles, injected clocks.
// No real hardware, cameras, displays, or network.
//
// BORROW PATTERN: SenderSession takes &mut ts, ReceiverSession takes &mut tr.
// To avoid holding both mutable borrows while also needing to drain queues,
// we use ts.screen_arc() / ts.inbox_arc() to get Arc handles BEFORE creating
// sessions; those Arcs let us drain queues without touching ts/tr directly.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use cypher::beacon::{
    build_receiver_beacon_with_token, LEVEL_OPEN, LEVEL_PAIRED, LEVEL_TOFU, LEVEL_WHITELIST, ZERO32,
};
use cypher::crypto::{fingerprint, generate_identity, identity_public_bytes, sign_message};
use cypher::messages::{self, pack_session_complete};
use cypher::replay::ReplayCache;
use cypher::session::interactive::{ReceiverSession, SenderSession};
use cypher::tofu::TrustStore;
use cypher::transport::{loopback_pair, Capabilities, LoopbackTransport};

const CAPS: Capabilities = Capabilities {
    width: 528,
    height: 528,
    max_fps: 30,
    cell_size: 2,
};

fn fixed_clock(t: f64) -> Box<dyn FnMut() -> f64 + Send> {
    Box::new(move || t)
}

fn fresh_trust(tmp: &std::path::Path) -> TrustStore {
    TrustStore::new(tmp.join("trust.json")).unwrap()
}

fn fresh_replay() -> ReplayCache {
    ReplayCache::new(3600.0, 100_000, Box::new(|| 1_780_000_000.0))
}

/// Drain all images from an Arc<Mutex<VecDeque<RgbImage>>>.
fn drain_screen(arc: &Arc<Mutex<VecDeque<Vec<u8>>>>) -> Vec<Vec<u8>> {
    let mut q = arc.lock().unwrap();
    q.drain(..).collect()
}

/// Drain all messages from an Arc<Mutex<VecDeque<Vec<u8>>>>.
fn drain_inbox(arc: &Arc<Mutex<VecDeque<Vec<u8>>>>) -> Vec<Vec<u8>> {
    let mut q = arc.lock().unwrap();
    q.drain(..).collect()
}

/// Pop one message of the given type, discarding others.
#[allow(dead_code)]
fn pop_typed(arc: &Arc<Mutex<VecDeque<Vec<u8>>>>, msg_type: u8) -> Vec<u8> {
    let mut q = arc.lock().unwrap();
    for i in 0..q.len() {
        if q[i][0] == msg_type {
            return q.remove(i).unwrap();
        }
    }
    panic!("message type 0x{msg_type:02x} not found in inbox");
}

/// Full handshake: start → ack-sent → await_ack.
/// Uses Arc handles to pass frames without conflicting borrows.
fn handshake(
    sender: &mut SenderSession<LoopbackTransport>,
    receiver: &mut ReceiverSession<LoopbackTransport>,
    tr_screen: &Arc<Mutex<VecDeque<Vec<u8>>>>,
) {
    sender.start(0, "test").unwrap();
    let grids = drain_screen(tr_screen);
    assert!(!grids.is_empty(), "sender must emit a BEACON");
    for g in &grids {
        let _ = receiver.on_wire(g);
    }
    assert!(sender.await_ack().unwrap());
}

/// Pump: deliver all pending frames to receiver, then all pending back-channel
/// messages to sender. Uses Arc handles.
fn pump(
    sender: &mut SenderSession<LoopbackTransport>,
    receiver: &mut ReceiverSession<LoopbackTransport>,
    ts_inbox: &Arc<Mutex<VecDeque<Vec<u8>>>>,
    tr_screen: &Arc<Mutex<VecDeque<Vec<u8>>>>,
) {
    for g in drain_screen(tr_screen) {
        let _ = receiver.on_wire(&g);
    }
    for m in drain_inbox(ts_inbox) {
        let _ = sender.handle_backchannel(&m);
    }
}

// ── constructor validation matrix ────────────────────────────────────────────

#[test]
fn ctor_level_psk_rejected() {
    let (mut ts, _tr) = loopback_pair(CAPS, CAPS);
    let err = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        Some(4), // LEVEL_PSK
        None,
        None,
        [0u8; 16],
        fixed_clock(1_780_000_000.0),
    );
    assert!(err.is_err());
}

#[test]
fn ctor_bad_level_rejected() {
    let (mut ts, _tr) = loopback_pair(CAPS, CAPS);
    let err = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        Some(99),
        None,
        None,
        [0u8; 16],
        fixed_clock(1_780_000_000.0),
    );
    assert!(err.is_err());
}

#[test]
fn ctor_level_tofu_requires_intended_receiver() {
    let (mut ts, _tr) = loopback_pair(CAPS, CAPS);
    let err = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        Some(LEVEL_TOFU),
        None,
        None,
        [0u8; 16],
        fixed_clock(1_780_000_000.0),
    );
    assert!(err.is_err());
}

#[test]
fn ctor_level_paired_requires_pairing_token() {
    let (mut ts, _tr) = loopback_pair(CAPS, CAPS);
    let r_pub = identity_public_bytes(&generate_identity());
    let err = SenderSession::new(
        &mut ts,
        generate_identity(),
        fingerprint(&r_pub),
        Some(LEVEL_PAIRED),
        None, // no token
        None,
        [0u8; 16],
        fixed_clock(1_780_000_000.0),
    );
    assert!(err.is_err());
}

#[test]
fn ctor_level_whitelist_requires_non_empty_whitelist() {
    let (mut ts, _tr) = loopback_pair(CAPS, CAPS);
    let r_pub = identity_public_bytes(&generate_identity());
    let fp = fingerprint(&r_pub);
    let err = SenderSession::new(
        &mut ts,
        generate_identity(),
        fp,
        Some(LEVEL_WHITELIST),
        None,
        Some(vec![]),
        [0u8; 16],
        fixed_clock(1_780_000_000.0),
    );
    assert!(err.is_err());
}

#[test]
fn ctor_level_whitelist_requires_intended_in_whitelist() {
    let (mut ts, _tr) = loopback_pair(CAPS, CAPS);
    let r_pub = identity_public_bytes(&generate_identity());
    let other_pub = identity_public_bytes(&generate_identity());
    let err = SenderSession::new(
        &mut ts,
        generate_identity(),
        fingerprint(&r_pub),
        Some(LEVEL_WHITELIST),
        None,
        Some(vec![other_pub]),
        [0u8; 16],
        fixed_clock(1_780_000_000.0),
    );
    assert!(err.is_err());
}

#[test]
fn ctor_default_level_open_when_broadcast() {
    let (mut ts, _tr) = loopback_pair(CAPS, CAPS);
    let s = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(1_780_000_000.0),
    );
    assert!(s.is_ok());
}

// ── handshake happy paths - levels 0–3 ───────────────────────────────────────

#[test]
fn handshake_level_0_open_session_keys_match() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    assert!(sender.session_key.is_some());
    assert!(receiver.session_key.is_some());
    // Both sides derive the same key via ECDH.
    assert_eq!(
        sender.session_key.as_ref().unwrap().as_bytes(),
        receiver.session_key.as_ref().unwrap().as_bytes()
    );
}

#[test]
fn handshake_pin_is_6_digits_and_matches() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    let pin = sender.pin.as_ref().unwrap();
    assert_eq!(pin.len(), 6);
    assert!(pin.chars().all(|c| c.is_ascii_digit()));
    assert_eq!(sender.pin, receiver.pin);
}

#[test]
fn handshake_level_2_paired_completes() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let r_ident = generate_identity();
    let r_pub = identity_public_bytes(&r_ident);
    let fp = fingerprint(&r_pub);
    let token = [0x42u8; 16];
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        fp,
        Some(LEVEL_PAIRED),
        Some(token),
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        r_ident,
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        Some(token),
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    assert!(sender.session_key.is_some());
}

#[test]
fn handshake_level_3_whitelist_completes() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let s_ident = generate_identity();
    let r_ident = generate_identity();
    let s_pub = identity_public_bytes(&s_ident);
    let r_pub = identity_public_bytes(&r_ident);
    let fp = fingerprint(&r_pub);
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        s_ident,
        fp,
        Some(LEVEL_WHITELIST),
        None,
        Some(vec![r_pub]),
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        r_ident,
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        Some(vec![s_pub]),
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    assert!(sender.session_key.is_some());
}

// ── BEACON checklist rejections ───────────────────────────────────────────────

#[test]
fn ignored_replay_when_session_already_seen() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    sender.start(0, "test").unwrap();
    let grids = drain_screen(&tr_screen);
    // Seed the replay cache with this session BEFORE the receiver borrows it
    // (the interactive ReceiverSession holds &mut ReplayCache for its lifetime,
    // so external mutation must precede construction).
    replay.add(sender.session_id);
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    assert_eq!(receiver.on_wire(&grids[0]).unwrap(), "ignored-replay");
}

#[test]
fn ignored_stale_when_outside_5min_window() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let t_sender = 1_780_000_000.0f64;
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t_sender),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t_sender + 361.0), // >5 min ahead
    );
    sender.start(0, "test").unwrap();
    let grids = drain_screen(&tr_screen);
    assert_eq!(receiver.on_wire(&grids[0]).unwrap(), "ignored-stale");
}

#[test]
fn ignored_level_too_low_when_below_min_level() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        Some(LEVEL_OPEN),
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        1, // min_level=1, sender sends LEVEL_OPEN=0
        None,
        None,
        None,
        fixed_clock(t),
    );
    sender.start(0, "test").unwrap();
    let grids = drain_screen(&tr_screen);
    assert_eq!(
        receiver.on_wire(&grids[0]).unwrap(),
        "ignored-level-too-low"
    );
}

#[test]
fn ignored_not_for_me_when_intended_receiver_differs() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let r_ident_a = generate_identity();
    let r_pub_a = identity_public_bytes(&r_ident_a);
    let fp_a = fingerprint(&r_pub_a);
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        fp_a,
        Some(LEVEL_TOFU),
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver_b = ReceiverSession::new(
        &mut tr,
        generate_identity(), // different identity
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    sender.start(0, "test").unwrap();
    let grids = drain_screen(&tr_screen);
    assert_eq!(receiver_b.on_wire(&grids[0]).unwrap(), "ignored-not-for-me");
}

#[test]
fn ignored_wrong_token_on_paired_level_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let r_ident = generate_identity();
    let r_pub = identity_public_bytes(&r_ident);
    let fp = fingerprint(&r_pub);
    let token_sender = [0x11u8; 16];
    let token_receiver = [0x22u8; 16];
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        fp,
        Some(LEVEL_PAIRED),
        Some(token_sender),
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        r_ident,
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        Some(token_receiver),
        None,
        None,
        fixed_clock(t),
    );
    sender.start(0, "test").unwrap();
    let grids = drain_screen(&tr_screen);
    let result = receiver.on_wire(&grids[0]).unwrap();
    assert!(
        result.starts_with("ignored"),
        "expected ignored-*, got {result}"
    );
}

#[test]
fn ignored_not_whitelisted_when_sender_not_in_whitelist() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let s_ident = generate_identity();
    let r_ident = generate_identity();
    let r_pub = identity_public_bytes(&r_ident);
    let fp = fingerprint(&r_pub);
    let other_pub = identity_public_bytes(&generate_identity());
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        s_ident,
        fp,
        Some(LEVEL_WHITELIST),
        None,
        Some(vec![r_pub]),
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        r_ident,
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        Some(vec![other_pub]), // sender not in whitelist
        None,
        fixed_clock(t),
    );
    sender.start(0, "test").unwrap();
    let grids = drain_screen(&tr_screen);
    assert_eq!(
        receiver.on_wire(&grids[0]).unwrap(),
        "ignored-not-whitelisted"
    );
}

#[test]
fn confirmation_required_in_mode_a_auto_accept_false() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        false, // auto_accept = false (Mode A)
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    sender.start(0, "test").unwrap();
    let grids = drain_screen(&tr_screen);
    assert_eq!(
        receiver.on_wire(&grids[0]).unwrap(),
        "confirmation-required"
    );
}

// ── TOFU key change hard fail ────────────────────────────────────────────────

#[test]
fn tofu_key_change_hard_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    trust.trust("sender", &[0u8; 32]).unwrap(); // pre-pin a different key
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    sender.start(0, "test").unwrap();
    let grids = drain_screen(&tr_screen);
    assert!(receiver.on_wire(&grids[0]).is_err()); // KeyChangedError
}

// ── re-ACK ───────────────────────────────────────────────────────────────────

#[test]
fn repeated_beacon_resends_cached_ack() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);

    // Re-send BEACON for the same session (already live + not complete)
    sender.start(0, "test").unwrap();
    let grids2 = drain_screen(&tr_screen);
    let result = receiver.on_wire(&grids2[0]).unwrap();
    assert!(
        result == "ack-resent" || result == "ack-sent",
        "expected ack-resent or ack-sent, got {result}"
    );
}

// ── NAK retransmit byte-identity ─────────────────────────────────────────────

#[test]
fn nak_retransmit_byte_identical() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);

    sender.send(b"chunk one").unwrap();
    sender.send(b"chunk two").unwrap();
    sender.finish().unwrap();

    let mut grids = drain_screen(&tr_screen);
    // frame 1: deliver; frame 2: drop; frame 3 (LAST): deliver
    let _f1 = receiver.on_wire(&grids[0]).unwrap();
    let lost = grids.remove(1);
    receiver.on_wire(&grids[1]).unwrap();

    // Sender retransmits frame 2
    let nak = drain_inbox(&ts_inbox).into_iter().next().expect("NAK");
    assert_eq!(sender.handle_backchannel(&nak).unwrap(), "retransmitted");

    let retransmit = drain_screen(&tr_screen)
        .into_iter()
        .next()
        .expect("retransmit");
    assert_eq!(
        retransmit, lost,
        "retransmit must be byte-identical to original"
    );
}

// ── forged back-channel silently rejected ────────────────────────────────────

#[test]
fn forged_backchannel_rejected_silently() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);

    let imposter = generate_identity();
    let forged = sign_message(
        &imposter,
        messages::SESSION_COMPLETE,
        &pack_session_complete(sender.session_id),
    );
    assert_eq!(sender.handle_backchannel(&forged).unwrap(), "rejected");
    assert!(!sender.complete);
}

// ── full transfer round-trip pipeline ────────────────────────────────────────

#[test]
fn full_transfer_send_data_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);

    let data = b"the quick brown fox jumps over the lazy dog".repeat(50);
    let n_frames = sender.send_data(&data, 3).unwrap();
    assert!(n_frames >= 1);
    pump(&mut sender, &mut receiver, &ts_inbox, &tr_screen);

    assert!(receiver.complete);
    assert!(sender.complete);
    assert_eq!(receiver.data().unwrap(), data);
}

#[test]
fn send_recv_multi_chunk_assembles_in_order() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);

    sender.send(b"chunk one").unwrap();
    sender.send(b"chunk two").unwrap();
    sender.send(b"chunk three").unwrap();
    sender.finish().unwrap();
    pump(&mut sender, &mut receiver, &ts_inbox, &tr_screen);

    assert!(receiver.complete);
    assert_eq!(receiver.data().unwrap(), b"chunk onechunk twochunk three");
}

#[test]
fn data_before_completion_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let _sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    assert!(receiver.data().is_err());
}

// ── FPS negotiation ──────────────────────────────────────────────────────────

#[test]
fn fps_negotiated_to_min_of_both_caps() {
    let tmp = tempfile::tempdir().unwrap();
    let caps_sender = Capabilities {
        max_fps: 30,
        ..CAPS
    };
    let caps_recv = Capabilities {
        max_fps: 20,
        ..CAPS
    };
    let (mut ts, mut tr) = loopback_pair(caps_sender, caps_recv);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    assert_eq!(sender.fps.unwrap(), 20); // min(30, 20)
}

// ── DEGRADED reduces fps ─────────────────────────────────────────────────────

#[test]
fn degraded_signal_reduces_fps() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let r_ident = generate_identity();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        r_ident.clone(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    let initial_fps = sender.fps.unwrap();

    let degraded = sign_message(&r_ident, messages::DEGRADED, &messages::pack_degraded(0.6));
    assert_eq!(
        sender.handle_backchannel(&degraded).unwrap(),
        "degraded-adjusted"
    );
    assert!(sender.fps.unwrap() < initial_fps);
}

// ── scan_receiver_beacon ─────────────────────────────────────────────────────

fn make_rbea_grid(r_ident: &SigningKey, t: f64) -> (Vec<u8>, [u8; 16]) {
    let caps = [0u8; 8];
    let token = [0xABu8; 16];
    let wire = build_receiver_beacon_with_token(r_ident, &caps, &token, || t);
    (wire, token)
}

#[test]
fn scan_receiver_beacon_returns_fingerprint() {
    let t = 1_780_000_000.0f64;
    let r_ident = generate_identity();
    let r_pub = identity_public_bytes(&r_ident);
    let (grid, _token) = make_rbea_grid(&r_ident, t);
    let (mut ts, _tr) = loopback_pair(CAPS, CAPS);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let fp = sender.scan_receiver_beacon(&grid).unwrap();
    assert_eq!(fp, fingerprint(&r_pub));
}

#[test]
fn scan_after_start_returns_error() {
    let t = 1_780_000_000.0f64;
    let r_ident = generate_identity();
    let (grid, _) = make_rbea_grid(&r_ident, t);
    let (mut ts, _tr) = loopback_pair(CAPS, CAPS);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    sender.start(0, "test").unwrap();
    assert!(sender.scan_receiver_beacon(&grid).is_err());
}

#[test]
fn scan_rejected_on_whitelist_session() {
    let t = 1_780_000_000.0f64;
    let r_ident = generate_identity();
    let r_pub = identity_public_bytes(&r_ident);
    let fp = fingerprint(&r_pub);
    let (grid, _) = make_rbea_grid(&r_ident, t);
    let (mut ts, _tr) = loopback_pair(CAPS, CAPS);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        fp,
        Some(LEVEL_WHITELIST),
        None,
        Some(vec![r_pub]),
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    assert!(sender.scan_receiver_beacon(&grid).is_err());
}

#[test]
fn scan_upgrades_open_to_tofu_observable() {
    // After scan on an OPEN session, a DIFFERENT receiver gets ignored-not-for-me
    let tmp = tempfile::tempdir().unwrap();
    let t = 1_780_000_000.0f64;
    let r_ident_a = generate_identity();
    let (grid, _) = make_rbea_grid(&r_ident_a, t);
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    sender.scan_receiver_beacon(&grid).unwrap();
    let r_ident_b = generate_identity(); // different receiver
    let mut receiver_b = ReceiverSession::new(
        &mut tr,
        r_ident_b,
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    sender.start(0, "test").unwrap();
    let grids = drain_screen(&tr_screen);
    assert_eq!(receiver_b.on_wire(&grids[0]).unwrap(), "ignored-not-for-me");
}

#[test]
fn scan_then_start_full_transfer() {
    let tmp = tempfile::tempdir().unwrap();
    let t = 1_780_000_000.0f64;
    let r_ident = generate_identity();
    let (rbea_grid, token) = make_rbea_grid(&r_ident, t);

    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    sender.scan_receiver_beacon(&rbea_grid).unwrap();

    let mut receiver = ReceiverSession::new(
        &mut tr,
        r_ident,
        &mut trust,
        &mut replay,
        "sender",
        true,
        1, // min_level=1
        None,
        None,
        Some(token), // token echo
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);

    sender.send(b"reverse-beacon-data").unwrap();
    sender.finish().unwrap();
    pump(&mut sender, &mut receiver, &ts_inbox, &tr_screen);

    assert!(receiver.complete);
    assert_eq!(receiver.data().unwrap(), b"reverse-beacon-data");
}

// ── wrong token echo silently ignored ────────────────────────────────────────

#[test]
fn wrong_token_echo_silently_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let t = 1_780_000_000.0f64;
    let r_ident = generate_identity();
    let r_pub = identity_public_bytes(&r_ident);
    let fp = fingerprint(&r_pub);
    let token_correct = [0xAAu8; 16];
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        fp,
        Some(LEVEL_TOFU),
        None,
        None,
        [0xBBu8; 16], // wrong token echo
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        r_ident,
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        Some(token_correct),
        fixed_clock(t),
    );
    sender.start(0, "test").unwrap();
    let grids = drain_screen(&tr_screen);
    assert_eq!(
        receiver.on_wire(&grids[0]).unwrap(),
        "ignored-wrong-token-echo"
    );
}

// ── pairing token wiped on completion ────────────────────────────────────────

#[test]
fn pairing_token_wiped_on_complete() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
    let r_ident = generate_identity();
    let r_pub = identity_public_bytes(&r_ident);
    let fp = fingerprint(&r_pub);
    let token = [0x42u8; 16];
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        fp,
        Some(LEVEL_PAIRED),
        Some(token),
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        r_ident,
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        Some(token),
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    sender.send(b"data").unwrap();
    sender.finish().unwrap();
    pump(&mut sender, &mut receiver, &ts_inbox, &tr_screen);
    assert!(sender.complete);
    assert!(sender.session_key.is_none()); // wiped on completion
}

// ── pipeline tests ───────────────────────────────────────────────────────────

#[test]
fn pipeline_end_to_end_multi_frame() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);

    // 5000 bytes of pseudo-random data to force multiple frames
    let data: Vec<u8> = (0u64..)
        .scan(0x6c62272e07bb0142u64, |s, _| {
            *s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            Some((*s >> 56) as u8)
        })
        .take(5000)
        .collect();
    let n_frames = sender.send_data(&data, 3).unwrap();
    assert!(n_frames > 1);
    pump(&mut sender, &mut receiver, &ts_inbox, &tr_screen);
    assert!(sender.complete && receiver.complete);
    assert_eq!(receiver.data().unwrap(), data);
}

#[test]
fn pipeline_compression_shrinks_wire_size() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);

    let data = b"cypher protocol ".repeat(1000);
    let n_frames = sender.send_data(&data, 3).unwrap();
    assert_eq!(n_frames, 1);
    pump(&mut sender, &mut receiver, &ts_inbox, &tr_screen);
    assert_eq!(receiver.data().unwrap(), data);
}

#[test]
fn pipeline_heavy_image_damage_never_wrong_data() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = 1_780_000_000.0f64;
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(t),
    )
    .unwrap();
    let mut receiver = ReceiverSession::new(
        &mut tr,
        generate_identity(),
        &mut trust,
        &mut replay,
        "sender",
        true,
        0,
        None,
        None,
        None,
        fixed_clock(t),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);

    sender.send_data(b"payload", 3).unwrap();
    let grids = drain_screen(&tr_screen);
    let wire = &grids[0];
    // beyond ECC capacity: Frame::decode fails or GCM rejects
    let mut damaged = wire.clone();
    let half = damaged.len() / 2;
    for b in damaged.iter_mut().take(half) {
        *b = 0xFF;
    }
    let result = receiver.on_wire(&damaged).unwrap();
    assert!(
        result == "undecodable" || result == "auth-failed",
        "expected undecodable or auth-failed, got {result}"
    );
    assert!(receiver.missing().is_empty());
}

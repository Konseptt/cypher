// Two-stage zeroize policy.
// Primary trigger: SESSION_COMPLETE wipes keys on both sides.
// Fallback trigger: SESSION_TTL seconds after LAST_FRAME.
//
// All tests use injectable clocks; no real time, no hardware.
//
// BORROW PATTERN: same Arc queue approach as p6b_session.rs.
// Extract screen_arc()/inbox_arc() BEFORE creating sessions to avoid
// conflicting &mut borrows when draining queues mid-test.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use cypher::beacon::ZERO32;
use cypher::crypto::generate_identity;
use cypher::replay::ReplayCache;
use cypher::session::interactive::{ReceiverSession, SenderSession};
use cypher::session::SESSION_TTL;
use cypher::tofu::TrustStore;
use cypher::transport::{loopback_pair, Capabilities, LoopbackTransport};

const CAPS: Capabilities = Capabilities {
    width: 528,
    height: 528,
    max_fps: 30,
    cell_size: 2,
};

fn fresh_trust(tmp: &std::path::Path) -> TrustStore {
    TrustStore::new(tmp.join("trust.json")).unwrap()
}

fn fresh_replay() -> ReplayCache {
    ReplayCache::new(3600.0, 100_000, Box::new(|| 1_780_000_000.0))
}

fn fixed_clock(t: f64) -> Box<dyn FnMut() -> f64 + Send> {
    Box::new(move || t)
}

fn drain_screen(arc: &Arc<Mutex<VecDeque<Vec<u8>>>>) -> Vec<Vec<u8>> {
    arc.lock().unwrap().drain(..).collect()
}

fn drain_inbox(arc: &Arc<Mutex<VecDeque<Vec<u8>>>>) -> Vec<Vec<u8>> {
    arc.lock().unwrap().drain(..).collect()
}

fn handshake(
    sender: &mut SenderSession<LoopbackTransport>,
    receiver: &mut ReceiverSession<LoopbackTransport>,
    tr_screen: &Arc<Mutex<VecDeque<Vec<u8>>>>,
) {
    sender.start(0, "test").unwrap();
    for g in drain_screen(tr_screen) {
        let _ = receiver.on_wire(&g);
    }
    assert!(sender.await_ack().unwrap());
}

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

// ── 1. SESSION_TTL constant ───────────────────────────────────────────────────

#[test]
fn session_ttl_is_300() {
    // fallback default is 5 minutes = 300 s from LAST_FRAME
    assert_eq!(SESSION_TTL, 300.0);
}

// ── 2. Primary trigger: SESSION_COMPLETE wipes both sides ────────────────────

#[test]
fn primary_trigger_wipes_sender_keys() {
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
    sender.send(b"payload").unwrap();
    sender.finish().unwrap();
    pump(&mut sender, &mut receiver, &ts_inbox, &tr_screen);

    assert!(sender.complete);
    assert!(sender.session_key.is_none()); // wiped on completion
}

#[test]
fn primary_trigger_wipes_receiver_keys() {
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
    sender.send(b"payload").unwrap();
    sender.finish().unwrap();
    pump(&mut sender, &mut receiver, &ts_inbox, &tr_screen);

    assert!(receiver.complete);
    assert!(receiver.session_key.is_none()); // wiped on completion
}

#[test]
fn primary_trigger_preserves_receiver_data() {
    // plaintext chunks NOT wiped - data() must survive completion
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
    sender.send(b"first").unwrap();
    sender.send(b"second").unwrap();
    sender.finish().unwrap();
    pump(&mut sender, &mut receiver, &ts_inbox, &tr_screen);

    assert!(receiver.complete);
    assert_eq!(receiver.data().unwrap(), b"firstsecond");
}

// ── 3. Fallback trigger: sender side ─────────────────────────────────────────

#[test]
fn sender_ttl_expires_at_deadline() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = Arc::new(Mutex::new(1_780_000_000.0f64));
    let t_clone = Arc::clone(&t);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        Box::new(move || *t_clone.lock().unwrap()),
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
        fixed_clock(*t.lock().unwrap()),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    sender.send(b"data").unwrap();
    sender.finish().unwrap();
    drain_screen(&tr_screen); // do NOT deliver to receiver

    // inclusive boundary: expiry fires at exactly SESSION_TTL
    *t.lock().unwrap() += SESSION_TTL;
    assert_eq!(sender.handle_backchannel(b"x").unwrap(), "expired");
    assert!(sender.session_key.is_none());
}

#[test]
fn sender_ttl_second_call_still_expired() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = Arc::new(Mutex::new(1_780_000_000.0f64));
    let t_clone = Arc::clone(&t);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        Box::new(move || *t_clone.lock().unwrap()),
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
        fixed_clock(*t.lock().unwrap()),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    sender.send(b"data").unwrap();
    sender.finish().unwrap();
    drain_screen(&tr_screen);

    *t.lock().unwrap() += SESSION_TTL;
    sender.handle_backchannel(b"x").unwrap();
    // second call must still return expired
    assert_eq!(sender.handle_backchannel(b"x").unwrap(), "expired");
}

#[test]
fn sender_not_expired_before_deadline() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = Arc::new(Mutex::new(1_780_000_000.0f64));
    let t_clone = Arc::clone(&t);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        Box::new(move || *t_clone.lock().unwrap()),
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
        fixed_clock(*t.lock().unwrap()),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    sender.send(b"data").unwrap();
    sender.finish().unwrap();
    drain_screen(&tr_screen);

    // strictly less than TTL - must NOT expire
    *t.lock().unwrap() += SESSION_TTL - 1.0;
    let result = sender.handle_backchannel(b"x").unwrap();
    assert_ne!(result, "expired");
    assert!(sender.session_key.is_some());
}

// ── 4. Fallback trigger: receiver side ───────────────────────────────────────

#[test]
fn receiver_ttl_expires_at_deadline() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = Arc::new(Mutex::new(1_780_000_000.0f64));
    let t_clone = Arc::clone(&t);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(*t.lock().unwrap()),
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
        Box::new(move || *t_clone.lock().unwrap()),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);

    sender.send(b"chunk one").unwrap();
    // capture frame 1 without delivering it (TTL target)
    let data_grid_1 = drain_screen(&tr_screen).into_iter().next().unwrap();
    sender.send(b"chunk two").unwrap();
    drain_screen(&tr_screen); // discard frame 2
    sender.finish().unwrap();
    let last_frame_grid = drain_screen(&tr_screen).into_iter().next().unwrap();

    // Deliver only LAST_FRAME - receiver is missing frames 1 & 2, sends NAK
    assert_eq!(receiver.on_wire(&last_frame_grid).unwrap(), "nak-sent");

    // expiry fires at inclusive boundary
    *t.lock().unwrap() += SESSION_TTL;
    let result = receiver.on_wire(&data_grid_1).unwrap();
    assert_eq!(result, "expired");
    assert!(receiver.session_key.is_none());
}

#[test]
fn receiver_not_expired_before_deadline() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = Arc::new(Mutex::new(1_780_000_000.0f64));
    let t_clone = Arc::clone(&t);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(*t.lock().unwrap()),
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
        Box::new(move || *t_clone.lock().unwrap()),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);

    sender.send(b"chunk one").unwrap();
    let data_grid_1 = drain_screen(&tr_screen).into_iter().next().unwrap();
    sender.send(b"chunk two").unwrap();
    drain_screen(&tr_screen);
    sender.finish().unwrap();
    let last_frame_grid = drain_screen(&tr_screen).into_iter().next().unwrap();
    assert_eq!(receiver.on_wire(&last_frame_grid).unwrap(), "nak-sent");

    // strictly before deadline - must NOT expire
    *t.lock().unwrap() += SESSION_TTL - 1.0;
    let result = receiver.on_wire(&data_grid_1).unwrap();
    assert_ne!(result, "expired");
    assert!(receiver.session_key.is_some());
}

// ── 5. No expiry without LAST_FRAME ──────────────────────────────────────────

#[test]
fn no_expiry_without_last_frame_sender() {
    // TTL timer starts from LAST_FRAME; handshake only → deadline never set
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = Arc::new(Mutex::new(1_780_000_000.0f64));
    let t_clone = Arc::clone(&t);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        Box::new(move || *t_clone.lock().unwrap()),
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
        fixed_clock(*t.lock().unwrap()),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    // NO finish() called

    *t.lock().unwrap() += 10_000.0;
    let result = sender.handle_backchannel(b"x").unwrap();
    assert_ne!(result, "expired");
    assert!(sender.session_key.is_some());
}

#[test]
fn no_expiry_without_last_frame_receiver() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = Arc::new(Mutex::new(1_780_000_000.0f64));
    let t_clone = Arc::clone(&t);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(*t.lock().unwrap()),
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
        Box::new(move || *t_clone.lock().unwrap()),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    sender.send(b"pending").unwrap();
    let data_grid = drain_screen(&tr_screen).into_iter().next().unwrap();
    // NO finish() - receiver never sees LAST_FRAME

    *t.lock().unwrap() += 10_000.0;
    let result = receiver.on_wire(&data_grid).unwrap();
    assert_ne!(result, "expired");
    assert!(receiver.session_key.is_some());
}

// ── 6. Completion beats expiry ────────────────────────────────────────────────

#[test]
fn completion_beats_expiry_sender() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = Arc::new(Mutex::new(1_780_000_000.0f64));
    let t_clone = Arc::clone(&t);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        Box::new(move || *t_clone.lock().unwrap()),
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
        fixed_clock(*t.lock().unwrap()),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    sender.send(b"data").unwrap();
    sender.finish().unwrap();
    pump(&mut sender, &mut receiver, &ts_inbox, &tr_screen);
    assert!(sender.complete);

    *t.lock().unwrap() += SESSION_TTL + 1.0;
    // completed: no expiry
    let result = sender.handle_backchannel(b"x").unwrap();
    assert_ne!(result, "expired");
}

#[test]
fn completion_beats_expiry_receiver() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = Arc::new(Mutex::new(1_780_000_000.0f64));
    let t_clone = Arc::clone(&t);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(*t.lock().unwrap()),
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
        Box::new(move || *t_clone.lock().unwrap()),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    sender.send(b"data").unwrap();
    sender.finish().unwrap();
    pump(&mut sender, &mut receiver, &ts_inbox, &tr_screen);
    assert!(receiver.complete);

    *t.lock().unwrap() += SESSION_TTL + 1.0;
    // Pass garbage wire bytes - undecodable, not expired
    let noise = vec![0u8; 64];
    let result = receiver.on_wire(&noise).unwrap();
    assert_ne!(result, "expired");
}

// ── 7. Receiver idempotency, retransmit must not re-arm ──────────────────────

#[test]
fn receiver_ttl_second_call_still_expired() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = Arc::new(Mutex::new(1_780_000_000.0f64));
    let t_clone = Arc::clone(&t);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(*t.lock().unwrap()),
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
        Box::new(move || *t_clone.lock().unwrap()),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    sender.send(b"chunk one").unwrap();
    let data_grid_1 = drain_screen(&tr_screen).into_iter().next().unwrap();
    sender.send(b"chunk two").unwrap();
    drain_screen(&tr_screen);
    sender.finish().unwrap();
    let last_frame_grid = drain_screen(&tr_screen).into_iter().next().unwrap();
    assert_eq!(receiver.on_wire(&last_frame_grid).unwrap(), "nak-sent");

    *t.lock().unwrap() += SESSION_TTL;
    assert_eq!(receiver.on_wire(&data_grid_1).unwrap(), "expired");
    // second call still expired
    assert_eq!(receiver.on_wire(&data_grid_1).unwrap(), "expired");
}

#[test]
fn retransmitted_last_frame_does_not_postpone_expiry() {
    // A retransmitted LAST_FRAME must NOT push the deadline out.
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let mut trust = fresh_trust(tmp.path());
    let mut replay = fresh_replay();
    let t = Arc::new(Mutex::new(1_780_000_000.0f64));
    let t_clone = Arc::clone(&t);
    let mut sender = SenderSession::new(
        &mut ts,
        generate_identity(),
        ZERO32,
        None,
        None,
        None,
        [0u8; 16],
        fixed_clock(*t.lock().unwrap()),
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
        Box::new(move || *t_clone.lock().unwrap()),
    );
    handshake(&mut sender, &mut receiver, &tr_screen);
    sender.send(b"chunk one").unwrap();
    drain_screen(&tr_screen); // frame 1 lost
    sender.finish().unwrap();
    let last_frame_grid = drain_screen(&tr_screen).into_iter().next().unwrap();
    assert_eq!(receiver.on_wire(&last_frame_grid).unwrap(), "nak-sent");

    // Before deadline: re-deliver LAST_FRAME (byte-identical retransmit)
    *t.lock().unwrap() += SESSION_TTL - 1.0;
    assert_eq!(receiver.on_wire(&last_frame_grid).unwrap(), "nak-sent");

    // At original deadline: must still expire (not postponed)
    *t.lock().unwrap() += 1.0;
    assert_eq!(receiver.on_wire(&last_frame_grid).unwrap(), "expired");
}

// Pause/resume state machine.
//
// BORROW PATTERN: SenderSession takes &mut ts, ReceiverSession takes &mut tr.
// We extract Arc handles via screen_arc()/inbox_arc() before creating sessions.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use cypher::beacon::ZERO32;
use cypher::crypto::{generate_identity, sign_message};
use cypher::messages;
use cypher::replay::ReplayCache;
use cypher::session::interactive::{ReceiverSession, SenderSession, ALIGNMENT_TIMEOUT};
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

fn drain_screen(arc: &Arc<Mutex<VecDeque<Vec<u8>>>>) -> Vec<Vec<u8>> {
    arc.lock().unwrap().drain(..).collect()
}

fn drain_inbox(arc: &Arc<Mutex<VecDeque<Vec<u8>>>>) -> Vec<Vec<u8>> {
    arc.lock().unwrap().drain(..).collect()
}

fn pop_typed(arc: &Arc<Mutex<VecDeque<Vec<u8>>>>, msg_type: u8) -> Vec<u8> {
    let mut q = arc.lock().unwrap();
    for i in 0..q.len() {
        if q[i][0] == msg_type {
            return q.remove(i).unwrap();
        }
    }
    panic!("message type 0x{msg_type:02x} not in inbox");
}

// Incompressible test payload: an LCG stream that zstd cannot shrink, so an
// n-byte transfer spans MANY chunks. A compressible ramp (i*k+c as u8) shrinks
// to ~276 B = one chunk, which would make step 1 the LAST_FRAME and
// complete+zeroize the session before the KEYFRAME path is exercised.
fn incompressible(seed: u64, n: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    (0..n)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 56) as u8
        })
        .collect()
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

#[allow(dead_code)]
fn drain_back(
    sender: &mut SenderSession<LoopbackTransport>,
    ts_inbox: &Arc<Mutex<VecDeque<Vec<u8>>>>,
) {
    for m in drain_inbox(ts_inbox) {
        let _ = sender.handle_backchannel(&m);
    }
}

#[allow(dead_code)]
fn drain_front(
    receiver: &mut ReceiverSession<LoopbackTransport>,
    tr_screen: &Arc<Mutex<VecDeque<Vec<u8>>>>,
) {
    for g in drain_screen(tr_screen) {
        let _ = receiver.on_wire(&g);
    }
}

/// Drive the receiver's alignment monitor to LOST state (5 consecutive AQS < 0.5).
fn drive_to_lost(receiver: &mut ReceiverSession<LoopbackTransport>) {
    for _ in 0..5 {
        receiver
            .observe_alignment(0, 0.0, None, None, false)
            .unwrap();
    }
}

// ── ALIGNMENT_TIMEOUT constant ───────────────────────────────────────────────

#[test]
fn alignment_timeout_constant_is_600() {
    assert_eq!(ALIGNMENT_TIMEOUT, 600.0);
}

// ── step API basics ───────────────────────────────────────────────────────────

#[test]
fn step_before_begin_transfer_returns_idle() {
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
    assert_eq!(sender.step().unwrap(), "idle");
}

#[test]
fn begin_transfer_sets_done_false() {
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
    let data: Vec<u8> = incompressible(7, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    assert!(!sender.done());
}

#[test]
fn step_after_done_returns_idle() {
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
    sender.begin_transfer(b"tiny payload", 3).unwrap();
    while !sender.done() {
        sender.step().unwrap();
        drain_screen(&tr_screen); // discard rendered frames
    }
    assert_eq!(sender.step().unwrap(), "idle");
}

// ── happy path: step full transfer round-trip ─────────────────────────────────

#[test]
fn step_full_transfer_roundtrip() {
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

    let data: Vec<u8> = (0u64..)
        .scan(0x6c62272e07bb0142u64, |s, _| {
            *s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            Some((*s >> 56) as u8)
        })
        .take(20_000)
        .collect();
    sender.begin_transfer(&data, 3).unwrap();
    let mut tags = Vec::new();
    while !sender.done() {
        let tag = sender.step().unwrap();
        tags.push(tag.clone());
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
    }
    for m in drain_inbox(&ts_inbox) {
        let _ = sender.handle_backchannel(&m);
    }
    assert!(receiver.complete);
    assert_eq!(receiver.data().unwrap(), data);
    assert!(tags.contains(&"last".to_string()));
    assert!(tags.iter().filter(|t| t.as_str() == "data").count() >= 2);
}

// ── PAUSE → WAITING ───────────────────────────────────────────────────────────

#[test]
fn handle_backchannel_pause_returns_paused() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
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

    let data: Vec<u8> = incompressible(11, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    for fn_num in 0..2u64 {
        sender.step().unwrap();
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
        receiver
            .observe_alignment(4, 1.0, Some(true), Some(fn_num), false)
            .unwrap();
    }
    drive_to_lost(&mut receiver);

    let raw = pop_typed(&ts_inbox, messages::PAUSE);
    assert_eq!(sender.handle_backchannel(&raw).unwrap(), "paused");
    assert!(sender.paused);
}

#[test]
fn step_while_paused_returns_waiting() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
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
        r_ident,
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

    let data: Vec<u8> = incompressible(13, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    for fn_num in 0..2u64 {
        sender.step().unwrap();
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
        receiver
            .observe_alignment(4, 1.0, Some(true), Some(fn_num), false)
            .unwrap();
    }
    drive_to_lost(&mut receiver);
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::PAUSE))
        .unwrap();
    assert_eq!(sender.step().unwrap(), "waiting");
}

#[test]
fn waiting_frame_on_grid_returns_waiting_seen() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
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
        r_ident,
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

    let data: Vec<u8> = incompressible(17, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    for fn_num in 0..2u64 {
        sender.step().unwrap();
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
        receiver
            .observe_alignment(4, 1.0, Some(true), Some(fn_num), false)
            .unwrap();
    }
    drive_to_lost(&mut receiver);
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::PAUSE))
        .unwrap();
    sender.step().unwrap(); // emit WAITING
    let grids = drain_screen(&tr_screen);
    assert!(!grids.is_empty());
    assert_eq!(receiver.on_wire(&grids[0]).unwrap(), "waiting-seen");
}

#[test]
fn waiting_frame_does_not_complete_transfer() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
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
        r_ident,
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

    let data: Vec<u8> = incompressible(19, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    for fn_num in 0..2u64 {
        sender.step().unwrap();
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
        receiver
            .observe_alignment(4, 1.0, Some(true), Some(fn_num), false)
            .unwrap();
    }
    drive_to_lost(&mut receiver);
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::PAUSE))
        .unwrap();
    sender.step().unwrap();
    for g in drain_screen(&tr_screen) {
        let _ = receiver.on_wire(&g);
    }
    assert!(!receiver.complete);
}

// ── WAITING vs KEYFRAME discriminator ────────────────────────────────────────

#[test]
fn discriminator_waiting_vs_keyframe_by_payload_length() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
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
        r_ident,
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

    let data: Vec<u8> = incompressible(23, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    for fn_num in 0..2u64 {
        sender.step().unwrap();
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
        receiver
            .observe_alignment(4, 1.0, Some(true), Some(fn_num), false)
            .unwrap();
    }
    drive_to_lost(&mut receiver);
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::PAUSE))
        .unwrap();

    // WAITING: KEYFRAME flag + empty payload
    sender.step().unwrap();
    let waiting_result = drain_screen(&tr_screen)
        .into_iter()
        .map(|g| receiver.on_wire(&g).unwrap())
        .next()
        .unwrap();
    assert_eq!(waiting_result, "waiting-seen");

    // RECOVERING → RESUME → KEYFRAME
    receiver
        .observe_alignment(1, 0.5, None, None, false)
        .unwrap();
    let resume = pop_typed(&ts_inbox, messages::RESUME);
    sender.handle_backchannel(&resume).unwrap();
    sender.step().unwrap();
    let kf_result = drain_screen(&tr_screen)
        .into_iter()
        .map(|g| receiver.on_wire(&g).unwrap())
        .next()
        .unwrap();
    assert_eq!(kf_result, "keyframe-ok");
    assert_ne!(waiting_result, kf_result);
}

// ── RESUME → KEYFRAME ────────────────────────────────────────────────────────

#[test]
fn handle_backchannel_resume_returns_resuming() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
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
        r_ident,
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

    let data: Vec<u8> = incompressible(29, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    for fn_num in 0..2u64 {
        sender.step().unwrap();
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
        receiver
            .observe_alignment(4, 1.0, Some(true), Some(fn_num), false)
            .unwrap();
    }
    drive_to_lost(&mut receiver);
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::PAUSE))
        .unwrap();
    sender.step().unwrap();
    drain_screen(&tr_screen);
    receiver
        .observe_alignment(1, 0.5, None, None, false)
        .unwrap();
    let resume = pop_typed(&ts_inbox, messages::RESUME);
    assert_eq!(sender.handle_backchannel(&resume).unwrap(), "resuming");
}

#[test]
fn step_after_resume_returns_keyframe() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
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
        r_ident,
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

    let data: Vec<u8> = incompressible(31, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    for fn_num in 0..2u64 {
        sender.step().unwrap();
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
        receiver
            .observe_alignment(4, 1.0, Some(true), Some(fn_num), false)
            .unwrap();
    }
    drive_to_lost(&mut receiver);
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::PAUSE))
        .unwrap();
    sender.step().unwrap();
    drain_screen(&tr_screen);
    receiver
        .observe_alignment(1, 0.5, None, None, false)
        .unwrap();
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::RESUME))
        .unwrap();
    assert_eq!(sender.step().unwrap(), "keyframe");
}

#[test]
fn keyframe_on_grid_returns_keyframe_ok() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
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
        r_ident,
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

    let data: Vec<u8> = incompressible(37, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    for fn_num in 0..2u64 {
        sender.step().unwrap();
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
        receiver
            .observe_alignment(4, 1.0, Some(true), Some(fn_num), false)
            .unwrap();
    }
    drive_to_lost(&mut receiver);
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::PAUSE))
        .unwrap();
    sender.step().unwrap();
    drain_screen(&tr_screen);
    receiver
        .observe_alignment(1, 0.5, None, None, false)
        .unwrap();
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::RESUME))
        .unwrap();
    sender.step().unwrap(); // emit KEYFRAME
    let kf_grids = drain_screen(&tr_screen);
    assert!(!kf_grids.is_empty());
    assert_eq!(receiver.on_wire(&kf_grids[0]).unwrap(), "keyframe-ok");
}

// ── full roundtrip after pause/resume ────────────────────────────────────────

#[test]
fn full_transfer_after_pause_resume_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
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
        r_ident,
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

    let data: Vec<u8> = incompressible(41, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    for fn_num in 0..2u64 {
        sender.step().unwrap();
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
        receiver
            .observe_alignment(4, 1.0, Some(true), Some(fn_num), false)
            .unwrap();
    }
    drive_to_lost(&mut receiver);
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::PAUSE))
        .unwrap();

    sender.step().unwrap(); // WAITING
    drain_screen(&tr_screen);
    receiver
        .observe_alignment(1, 0.5, None, None, false)
        .unwrap();
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::RESUME))
        .unwrap();

    let mut remaining_tags = Vec::new();
    while !sender.done() {
        let tag = sender.step().unwrap();
        remaining_tags.push(tag.clone());
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
    }
    // drain residual back-channel
    for _ in 0..10 {
        for m in drain_inbox(&ts_inbox) {
            let _ = sender.handle_backchannel(&m);
        }
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
    }

    assert!(remaining_tags.contains(&"keyframe".to_string()));
    assert!(receiver.complete);
    assert_eq!(receiver.data().unwrap(), data);
}

// ── DEGRADED ──────────────────────────────────────────────────────────────────

#[test]
fn degraded_returns_degraded_adjusted_and_reduces_fps() {
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

    let data: Vec<u8> = incompressible(43, 5_000);
    sender.begin_transfer(&data, 3).unwrap();
    sender.step().unwrap();
    drain_screen(&tr_screen);
    let initial_fps = sender.fps.unwrap();

    let deg = sign_message(&r_ident, messages::DEGRADED, &messages::pack_degraded(0.6));
    assert_eq!(
        sender.handle_backchannel(&deg).unwrap(),
        "degraded-adjusted"
    );
    assert!(sender.fps.unwrap() < initial_fps);
}

// ── alignment_timeout ────────────────────────────────────────────────────────

#[test]
fn no_timeout_before_600s() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
    let r_ident = generate_identity();
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
        r_ident,
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

    let data: Vec<u8> = incompressible(47, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    for fn_num in 0..2u64 {
        sender.step().unwrap();
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
        receiver
            .observe_alignment(4, 1.0, Some(true), Some(fn_num), false)
            .unwrap();
    }
    drive_to_lost(&mut receiver);
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::PAUSE))
        .unwrap();

    *t.lock().unwrap() += 599.9; // just under the limit
    assert_eq!(sender.step().unwrap(), "waiting");
    assert!(!sender.timed_out);
}

#[test]
fn timeout_fires_after_600s() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let ts_inbox = ts.inbox_arc();
    let r_ident = generate_identity();
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
        r_ident,
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

    let data: Vec<u8> = incompressible(53, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    for fn_num in 0..2u64 {
        sender.step().unwrap();
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
        receiver
            .observe_alignment(4, 1.0, Some(true), Some(fn_num), false)
            .unwrap();
    }
    drive_to_lost(&mut receiver);
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::PAUSE))
        .unwrap();

    *t.lock().unwrap() += 600.1;
    assert_eq!(sender.step().unwrap(), "timed-out");
    assert!(sender.timed_out);
}

#[test]
fn session_timeout_message_sent_on_expiry() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut ts, mut tr) = loopback_pair(CAPS, CAPS);
    let tr_screen = tr.screen_arc();
    let tr_inbox = tr.inbox_arc(); // SESSION_TIMEOUT goes sender→receiver (receiver's inbox)
    let ts_inbox = ts.inbox_arc();
    let r_ident = generate_identity();
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
        r_ident,
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

    let data: Vec<u8> = incompressible(59, 20_000);
    sender.begin_transfer(&data, 3).unwrap();
    for fn_num in 0..2u64 {
        sender.step().unwrap();
        for g in drain_screen(&tr_screen) {
            let _ = receiver.on_wire(&g);
        }
        receiver
            .observe_alignment(4, 1.0, Some(true), Some(fn_num), false)
            .unwrap();
    }
    drive_to_lost(&mut receiver);
    sender
        .handle_backchannel(&pop_typed(&ts_inbox, messages::PAUSE))
        .unwrap();

    *t.lock().unwrap() += 600.1;
    sender.step().unwrap(); // triggers timeout

    // SESSION_TIMEOUT is sent via back_channel → receiver's inbox
    let raw = tr_inbox
        .lock()
        .unwrap()
        .pop_front()
        .expect("SESSION_TIMEOUT");
    assert_eq!(raw[0], messages::SESSION_TIMEOUT);
}

// ── KEYFRAME integrity ────────────────────────────────────────────────────────

#[test]
fn keyframe_integrity_ok_after_clean_transfer() {
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

    sender.send(b"a small payload").unwrap();
    sender.finish().unwrap();
    for g in drain_screen(&tr_screen) {
        let _ = receiver.on_wire(&g);
    }
    for m in drain_inbox(&ts_inbox) {
        let _ = sender.handle_backchannel(&m);
    }
    assert!(receiver.complete);
    assert!(receiver.integrity_ok());
    assert_eq!(receiver.data().unwrap(), b"a small payload");
}

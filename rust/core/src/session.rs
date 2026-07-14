//! session lifecycle over a [`Transport`]. The BROADCAST half -
//! [`BroadcastSender`] and [`BroadcastReceiver`] (PSK mode) - and the
//! interactive `SenderSession`/`ReceiverSession` (ECDH) in the `mod interactive`
//! seam below.
//!
//! This layer traffics in wire bytes: the host carrier (QR) does its own error
//! correction on receive, so every frame this module sees has already passed the
//! code's own error correction before [`Frame::decode`] checks the CRC.
//!
//! Zeroization is real here: the dalek and `SessionKey` types wipe on drop.

use thiserror::Error;

use crate::beacon::{build_payload, parse_payload, Beacon, BeaconError, LEVEL_PSK, ZERO16, ZERO32};
use crate::compression::{self, CompressionError};
use crate::crypto::{self, CryptoError, SessionKey, GCM_TAG_LEN};
use crate::fountain;
use crate::frame::{
    header_prefix, Frame, FrameError, BEACON, COMPRESSED, ENCRYPTED, HEADER_LEN, MAX_WIRE, PRIORITY,
};
use crate::replay::{ReplayCache, DEFAULT_TTL, MAX_ENTRIES};
use crate::tofu::{KeyChangedError, TrustStore};
use crate::transport::Transport;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;

pub const TIMESTAMP_WINDOW_MS: u64 = 300_000;
pub const SID_PREFIX_LEN: usize = 8; // 8-byte SESSION_ID prepended to broadcast DATA frames
/// One RaptorQ packet per frame. Size the symbol so the whole DATA frame wire
/// fits MAX_WIRE: HEADER_LEN(8) + SID(8) + GCM tag(16) + the packet (raptorq
/// aligns the symbol size and adds a small PayloadId; the -4 leaves room).
/// Derived from [`crate::frame::MAX_WIRE`] so a capacity lift flows through
/// automatically.
pub const BROADCAST_SYMBOL_SIZE: usize = MAX_WIRE - HEADER_LEN - SID_PREFIX_LEN - GCM_TAG_LEN - 4;

/// Fountain symbol size for a given per-frame wire budget. Shifts the symbol
/// size by the same amount as the wire budget moves off MAX_WIRE, since the
/// per-packet framing overhead is fixed.
///
/// # Errors
/// [`SessionError::Message`] if the resulting symbol size is < 1.
pub fn symbol_size_for_max_wire(max_wire: usize) -> Result<usize, SessionError> {
    let framing = MAX_WIRE - BROADCAST_SYMBOL_SIZE;
    if max_wire <= framing {
        return Err(SessionError::Message(format!(
            "max_wire {max_wire} leaves no room for a fountain symbol"
        )));
    }
    Ok(max_wire - framing)
}

/// Repair-packet overhead fraction for a target frame-loss percentage:
/// tolerating loss fraction f needs f/(1-f) extra repair packets. `loss = 0`
/// yields `0.0`.
///
/// # Errors
/// [`SessionError::Message`] if `loss` is outside 0..=75.
pub fn overhead_for_max_loss(loss: u32) -> Result<f64, SessionError> {
    if loss > 75 {
        return Err(SessionError::Message(
            "max_loss must be 0..75 (percent of frames)".to_string(),
        ));
    }
    let redundancy = (100.0 * loss as f64 / (100 - loss) as f64).round();
    Ok(redundancy / 100.0)
}

pub const MAX_BROADCAST_FRAMES: u32 = (1 << 20) - 1; // frame_number is 20-bit; packets must fit
pub const MAX_BUFFERED_PACKETS: usize = 100_000; // cap pre-BEACON packet buffer (DoS bound; loop re-delivers)
pub const SESSION_TTL: f64 = 300.0; // fallback: 5 minutes from LAST_FRAME
pub const MIN_FPS: u8 = 5; // provisional lower bound for fps adjustments

/// Session-level failure, plus the wrapped errors from the composed modules.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("{0}")]
    Message(String),
    #[error("psk must be 32 bytes")]
    BadPsk,
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error(transparent)]
    Beacon(#[from] BeaconError),
    #[error(transparent)]
    Fountain(#[from] fountain::FountainError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Compression(#[from] CompressionError),
    #[error(transparent)]
    KeyChanged(#[from] KeyChangedError),
}

// The QR carrier brings its own Reed-Solomon ECC, so the frame carries no
// per-frame RS block.
fn build_frame(frame_number: u32, flags: u8, payload: Vec<u8>) -> Result<Frame, FrameError> {
    Frame::new(frame_number, flags, payload)
}

/// Broadcast PSK mode with fountain coding: no back channel, no ECDH, no ACK, no
/// SESSION_COMPLETE. The payload is compressed then RaptorQ fountain-encoded into
/// equal-size, self-identifying packets - one packet per frame. The renderer
/// loops the packet set; a receiver reconstructs from ANY K+ε of them, so there
/// is no LAST_FRAME/gap model.
///
/// NO FORWARD SECRECY: the PSK keys every session derived from it, so a single
/// PSK compromise exposes every past and future session.
pub struct BroadcastSender<'a, T: Transport> {
    transport: &'a mut T,
    identity: SigningKey,
    symbol_size: usize,
    overhead: f64, // repair-packet fraction (redundancy knob)
    clock: Box<dyn FnMut() -> f64 + Send>,
    pub session_id: u64, // CSPRNG
    session_key: Option<SessionKey>,
    next_frame: u32, // BEACON takes frame number 0
}

impl<'a, T: Transport> BroadcastSender<'a, T> {
    /// A fresh CSPRNG SESSION_ID. Use [`BroadcastSender::with_session_id`] to
    /// inject one for determinism (conformance vectors).
    ///
    /// # Errors
    /// [`SessionError::BadPsk`] if `psk` is not 32 bytes (enforced by the type
    /// here; kept for signature symmetry with the receiver).
    pub fn new(
        transport: &'a mut T,
        identity: SigningKey,
        psk: [u8; 32],
        symbol_size: usize,
        overhead: f64,
        clock: Box<dyn FnMut() -> f64 + Send>,
    ) -> Self {
        let session_id = OsRng.next_u64();
        Self::with_session_id(
            transport,
            identity,
            psk,
            symbol_size,
            overhead,
            clock,
            session_id,
        )
    }

    /// Deterministic variant with an injected SESSION_ID (HKDF from the PSK, no
    /// ephemeral ECDH). For the interop vector.
    pub fn with_session_id(
        transport: &'a mut T,
        identity: SigningKey,
        psk: [u8; 32],
        symbol_size: usize,
        overhead: f64,
        clock: Box<dyn FnMut() -> f64 + Send>,
        session_id: u64,
    ) -> Self {
        let session_key = crypto::psk_session_key(&psk, session_id);
        Self {
            transport,
            identity,
            symbol_size,
            overhead,
            clock,
            session_id,
            session_key: Some(session_key),
            next_frame: 1,
        }
    }

    fn emit_beacon(
        &mut self,
        transfer_size: u64,
        transfer_name: &str,
        fountain_length: u32,
    ) -> Result<(), SessionError> {
        let caps = self.transport.display_capabilities();
        let beacon = Beacon::new(
            self.session_id,
            ((self.clock)() * 1000.0) as u64,
            LEVEL_PSK,
            ZERO32, // PSK sessions are broadcast
            ZERO32,
            ZERO32, // no ECDH in PSK mode - field unused
            crypto::identity_public_bytes(&self.identity),
            caps.width,
            caps.height,
            caps.max_fps,
            caps.cell_size,
            transfer_size,
            transfer_name.to_string(),
            ZERO16,
            crate::beacon::FRAME_CELLS,
            self.symbol_size as u16, // fountain params the Decoder needs
            fountain_length,
        )?;
        let payload = build_payload(&beacon, &self.identity, 1);
        let frame = build_frame(0, BEACON | PRIORITY, payload)?;
        self.transport.render_frame(&frame.encode());
        Ok(())
    }

    fn send_packet(&mut self, plaintext: &[u8], flags: u8) -> Result<u32, SessionError> {
        let number = self.next_frame;
        self.next_frame += 1;
        // Broadcast DATA frames self-bootstrap - prepend SESSION_ID (8B,
        // plaintext) so a receiver can derive the key and join at ANY frame.
        // payload_len (hence the AAD) covers the prefix, and the CRC-16 covers it
        // too, so a tampered SESSION_ID fails before or at decryption.
        let sid = self.session_id.to_be_bytes();
        let payload_len = SID_PREFIX_LEN + plaintext.len() + GCM_TAG_LEN;
        let aad = header_prefix(number, flags, payload_len as u16)?;
        let key = self.session_key.as_ref().expect("open session");
        let ct = crypto::encrypt_payload(
            key.as_bytes(),
            self.session_id,
            number as u64,
            plaintext,
            &aad,
        );
        let mut payload = sid.to_vec();
        payload.extend_from_slice(&ct);
        let frame = build_frame(number, flags, payload)?;
        self.transport.render_frame(&frame.encode());
        Ok(number)
    }

    /// The whole broadcast (no back channel): compress -> fountain -> one packet
    /// per frame -> encrypt -> QR, preceded by the BEACON carrying the fountain
    /// params. Returns the number of DATA (packet) frames rendered.
    ///
    /// # Errors
    /// [`SessionError::Message`] if the payload needs more than
    /// [`MAX_BROADCAST_FRAMES`] packets; propagates the composed modules' errors.
    pub fn send_data(&mut self, data: &[u8], name: &str, level: i32) -> Result<u32, SessionError> {
        #[cfg(feature = "compression")]
        let (payload, flags) = {
            let compressed = compression::compress(data, level)?;
            if compressed.len() >= data.len() {
                // already-compressed media: zstd did not help - send raw, no
                // COMPRESSED flag (the receiver must not attempt to decompress it).
                (data.to_vec(), ENCRYPTED)
            } else {
                (compressed, ENCRYPTED | COMPRESSED)
            }
        };
        // No compressor in this build: send raw, never set COMPRESSED.
        #[cfg(not(feature = "compression"))]
        let (payload, flags) = {
            let _ = level;
            (data.to_vec(), ENCRYPTED)
        };
        let packets = fountain::encode(&payload, self.symbol_size as u16, self.overhead)?;
        if packets.len() as u64 > MAX_BROADCAST_FRAMES as u64 {
            return Err(SessionError::Message(format!(
                "payload too large for one broadcast: {} packets > {} \
                 (raise symbol_size / MAX_WIRE, or split)",
                packets.len(),
                MAX_BROADCAST_FRAMES
            )));
        }
        // BEACON first: it carries fountain_length + symbol_size (the Decoder's
        // params) and transfer_size (the decompression bound / bomb guard).
        self.emit_beacon(data.len() as u64, name, payload.len() as u32)?;
        for packet in &packets {
            self.send_packet(packet, flags)?; // frame_number 1..N; a packet is the plaintext
        }
        Ok(packets.len() as u32)
    }

    /// Best-effort key drop; the `SessionKey` wipes on drop.
    pub fn close(&mut self) {
        self.session_key = None;
    }
}

/// Broadcast PSK mode receiver with fountain coding: no back channel, nothing
/// signed outbound. Each decrypted DATA payload is a self-identifying RaptorQ
/// packet; the receiver feeds them to a [`fountain::Decoder`] and completes as
/// soon as the decoder has ANY K+ε packets - there is no LAST_FRAME/gap model.
///
/// The Decoder needs the BEACON's fountain params (fountain_length +
/// symbol_size). A receiver may see DATA before the BEACON (self-bootstrap
/// decrypts fine), so decrypted packets are buffered until those params arrive.
pub struct BroadcastReceiver<'a> {
    psk: [u8; 32],
    trust: Option<&'a mut TrustStore>,
    peer_name: String,
    auto_accept: bool,
    replay: ReplayCache, // a broadcast receiver MUST consult a replay cache at bootstrap
    clock: Box<dyn FnMut() -> f64 + Send>,
    pub session_id: Option<u64>,
    session_key: Option<SessionKey>,
    sender_identity: Option<[u8; 32]>,
    /// True once a signed BEACON has been verified (TOFU). A transfer can
    /// complete from data frames alone via the PSK; this lets a caller with a
    /// trust_store tell PSK-trust from identity-proven.
    pub identity_verified: bool,
    pub transfer_size: u64,
    pub transfer_name: String, // from the BEACON; the original filename
    compressed: bool,
    // Fountain state: buffer decrypted packets until the BEACON's params are
    // known, then build the Decoder and drain the buffer.
    symbol_size: Option<usize>,
    fountain_length: Option<u32>,
    decoder: Option<fountain::Decoder>,
    result: Option<Vec<u8>>,
    buffer: Vec<Vec<u8>>, // decrypted packets awaiting the Decoder (pre-BEACON)
    seen: std::collections::HashSet<u32>, // frame_numbers already decrypted (skip loop duplicates)
    pub complete: bool,
    closed: bool,
}

// Statuses that advance the session; any one of these wins the aggregation.
// Ordered by session progress so completion outranks a plain accept when both
// appear in one capture.
const ADVANCING: [&str; 3] = ["complete", "beacon-accepted", "stored"];

impl<'a> BroadcastReceiver<'a> {
    /// `replay_cache = None` -> a fresh live cache so replay defence is ON by
    /// default (matches `ReceiverSession`); pass a persistent cache for
    /// cross-run protection.
    ///
    /// # Errors
    /// [`SessionError::BadPsk`] if `psk` is not 32 bytes (enforced by the type
    /// here; kept for signature symmetry).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        psk: [u8; 32],
        trust_store: Option<&'a mut TrustStore>,
        peer_name: &str,
        auto_accept: bool,
        replay_cache: Option<ReplayCache>,
        clock: Box<dyn FnMut() -> f64 + Send>,
    ) -> Self {
        let replay = replay_cache
            .unwrap_or_else(|| ReplayCache::new(DEFAULT_TTL, MAX_ENTRIES, Box::new(default_clock)));
        Self {
            psk,
            trust: trust_store,
            peer_name: peer_name.to_string(),
            auto_accept,
            replay,
            clock,
            session_id: None,
            session_key: None,
            sender_identity: None,
            identity_verified: false,
            transfer_size: 0,
            transfer_name: String::new(),
            compressed: false,
            symbol_size: None,
            fountain_length: None,
            decoder: None,
            result: None,
            buffer: Vec::new(),
            seen: std::collections::HashSet::new(),
            complete: false,
            closed: false,
        }
    }

    /// The pre-decoded entry point: route each code through the per-code logic
    /// and aggregate by priority - a status that advances the session >
    /// auth-failed > first non-undecodable > undecodable. A single-code capture
    /// returns exactly what one code returns.
    ///
    /// # Errors
    /// [`KeyChangedError`] - a changed pinned identity key is a hard fail.
    pub fn on_codes(&mut self, codes: Vec<Vec<u8>>) -> Result<String, KeyChangedError> {
        let results: Vec<String> = codes
            .iter()
            .map(|raw| self.on_code(raw))
            .collect::<Result<_, _>>()?;
        if results.is_empty() {
            return Ok("undecodable".to_string());
        }
        for adv in ADVANCING {
            if results.iter().any(|r| r == adv) {
                return Ok(adv.to_string());
            }
        }
        if results.iter().any(|r| r == "auth-failed") {
            return Ok("auth-failed".to_string());
        }
        for r in &results {
            if r != "undecodable" {
                return Ok(r.clone());
            }
        }
        Ok("undecodable".to_string())
    }

    fn on_code(&mut self, raw: &[u8]) -> Result<String, KeyChangedError> {
        // The QR carries the whole frame (header + payload + ECC); route on
        // FLAGS.
        let frame = match Frame::decode(raw) {
            Ok(f) => f,
            Err(_) => return Ok("undecodable".to_string()),
        };
        if frame.flags & BEACON != 0 {
            self.on_beacon(&frame)
        } else {
            Ok(self.on_data(&frame))
        }
    }

    fn on_beacon(&mut self, frame: &Frame) -> Result<String, KeyChangedError> {
        let beacon = match parse_payload(&frame.payload) {
            Ok(b) => b,
            Err(_) => return Ok("ignored-invalid".to_string()),
        };
        let session_id = beacon.session_id;
        let now_ms = ((self.clock)() * 1000.0) as u64;
        if now_ms.abs_diff(beacon.timestamp_ms) >= TIMESTAMP_WINDOW_MS {
            return Ok("ignored-stale".to_string()); // ±5 min window
        }
        // BroadcastReceiver is the level-4 handler; require PSK.
        if beacon.session_level != LEVEL_PSK {
            return Ok("ignored-not-psk".to_string());
        }
        if self.replay.contains(session_id) {
            return Ok("ignored-replay".to_string());
        }
        // Data frames may have already bootstrapped this session. A BEACON for a
        // DIFFERENT broadcast than the one we're receiving is not ours; ignore it
        // rather than switch mid-transfer.
        if self.session_id.is_some() && self.session_id != Some(session_id) {
            return Ok("ignored-wrong-session".to_string());
        }
        // Fully established already (session + identity): a repeat is idempotent.
        if self.session_id.is_some() && self.identity_verified {
            return Ok("ignored-duplicate".to_string());
        }
        // The BEACON's unique contribution over a data frame: a signed identity.
        if let Some(trust) = self.trust.as_mut() {
            // verify() returns KeyChangedError on a changed key - a HARD fail
            // that propagates out of on_codes.
            let trusted = trust.verify(&self.peer_name, &beacon.identity_pub)?;
            if !trusted {
                if !self.auto_accept {
                    return Ok("confirmation-required".to_string());
                }
                if trust.trust(&self.peer_name, &beacon.identity_pub).is_err() {
                    return Ok("ignored-invalid".to_string());
                }
            }
        }
        if self.session_id.is_none() {
            // not yet bootstrapped by a data frame
            self.session_id = Some(session_id);
            self.session_key = Some(crypto::psk_session_key(&self.psk, session_id));
        }
        self.sender_identity = Some(beacon.identity_pub);
        self.identity_verified = true;
        self.transfer_size = beacon.transfer_size;
        self.transfer_name = beacon.transfer_name.clone();
        // The fountain params the Decoder needs; build it and drain any packets
        // buffered from DATA frames seen before this BEACON.
        if self.decoder.is_none() {
            let decoder =
                match fountain::Decoder::new(beacon.fountain_length as u64, beacon.symbol_size) {
                    Ok(d) => d,
                    Err(_) => return Ok("ignored-invalid".to_string()), // corrupt/lying fountain params
                };
            self.decoder = Some(decoder);
            self.symbol_size = Some(beacon.symbol_size as usize);
            self.fountain_length = Some(beacon.fountain_length);
            let buffered = std::mem::take(&mut self.buffer);
            for packet in buffered {
                self.feed(&packet);
            }
        }
        Ok("beacon-accepted".to_string())
    }

    fn on_data(&mut self, frame: &Frame) -> String {
        // Broadcast DATA frames self-bootstrap - the first 8 bytes are the
        // plaintext SESSION_ID, so a receiver can join at ANY frame.
        if frame.payload.len() < SID_PREFIX_LEN + GCM_TAG_LEN {
            return "undecodable".to_string();
        }
        if frame.frame_number == 0 {
            return "undecodable".to_string(); // frame 0 is the BEACON's reserved number, never DATA
        }
        let mut sid_bytes = [0u8; 8];
        sid_bytes.copy_from_slice(&frame.payload[..SID_PREFIX_LEN]);
        let sid = u64::from_be_bytes(sid_bytes);
        let ciphertext = &frame.payload[SID_PREFIX_LEN..];
        if self.session_id.is_some() && self.session_id != Some(sid) {
            return "ignored-wrong-session".to_string(); // a different broadcast's frame
        }
        if self.seen.contains(&frame.frame_number) {
            return "duplicate".to_string(); // a looped re-send of an already-decrypted packet
        }
        let bootstrapping = self.session_id.is_none();
        let key = if bootstrapping {
            // Replay defence must not be bypassed just because we skipped the
            // BEACON: refuse a session already completed.
            if self.replay.contains(sid) {
                return "ignored-replay".to_string();
            }
            crypto::psk_session_key(&self.psk, sid) // derive into a LOCAL
        } else {
            self.session_key
                .as_ref()
                .expect("bootstrapped session")
                .clone()
        };
        // Decrypt BEFORE committing any session state: a spoofed frame (arbitrary
        // sid + garbage) must fail without locking the receiver onto a bogus
        // session, or one frame could permanently deny the transfer.
        let aad = match header_prefix(frame.frame_number, frame.flags, frame.payload.len() as u16) {
            Ok(a) => a,
            Err(_) => return "undecodable".to_string(),
        };
        let plaintext = match crypto::decrypt_payload(
            key.as_bytes(),
            sid,
            frame.frame_number as u64,
            ciphertext,
            &aad,
        ) {
            Ok(p) => p,
            Err(_) => return "auth-failed".to_string(),
        };
        if bootstrapping {
            // commit only now that a real frame authenticated
            self.session_id = Some(sid);
            self.session_key = Some(key);
        }
        self.seen.insert(frame.frame_number);
        if frame.flags & COMPRESSED != 0 {
            self.compressed = true;
        }
        // The plaintext IS a fountain packet. Feed the Decoder if its params
        // (from the BEACON) are known; else buffer until the BEACON builds it.
        if self.decoder.is_none() {
            if self.buffer.len() < MAX_BUFFERED_PACKETS {
                // DoS bound; loop re-delivers
                self.buffer.push(plaintext);
            }
            return "buffered".to_string();
        }
        self.feed(&plaintext)
    }

    /// Feed one fountain packet to the Decoder; complete when it has enough. A
    /// corrupt/malformed packet is skipped inside `Decoder::add` (never a crash).
    fn feed(&mut self, packet: &[u8]) -> String {
        let decoder = self
            .decoder
            .as_mut()
            .expect("feed only after Decoder built");
        if let Some(payload) = decoder.add(packet) {
            if !self.complete {
                self.complete = true;
                self.result = Some(payload);
                if let Some(sid) = self.session_id {
                    self.replay.add(sid);
                }
            }
        }
        if self.complete {
            "complete".to_string()
        } else {
            "stored".to_string()
        }
    }

    /// How many distinct packets have been decrypted (progress indicator).
    pub fn packets_seen(&self) -> usize {
        self.seen.len()
    }

    /// RaptorQ symbol size from the BEACON; `None` until a BEACON is seen.
    pub fn symbol_size(&self) -> Option<usize> {
        self.symbol_size
    }

    /// The reconstructed payload. Confidentiality+integrity come from the PSK;
    /// this does NOT imply the sender's IDENTITY was verified - check
    /// [`Self::identity_verified`] if that matters.
    ///
    /// # Errors
    /// [`SessionError::Message`] if the session is closed or not yet complete;
    /// [`SessionError::Compression`] if a bounded decompress fails.
    pub fn data(&self) -> Result<Vec<u8>, SessionError> {
        if self.closed {
            return Err(SessionError::Message(
                "broadcast session closed - call data() before close()".to_string(),
            ));
        }
        if !self.complete {
            return Err(SessionError::Message(
                "broadcast transfer not complete: fountain decoder needs more packets".to_string(),
            ));
        }
        let raw = self.result.clone().expect("complete implies a result");
        if !self.compressed {
            return Ok(raw);
        }
        // bomb guard: BEACON TRANSFER_SIZE bounds the decompressed size.
        // decompress is always available (zstd native, ruzstd on wasm).
        Ok(compression::decompress(&raw, self.transfer_size as usize)?)
    }

    /// Best-effort drop of plaintext + key. PSK mode has no forward secrecy, but
    /// retaining plaintext past use is needless; call after data().
    pub fn close(&mut self) {
        self.buffer = Vec::new();
        self.decoder = None;
        self.result = None;
        self.session_key = None;
        self.closed = true;
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn default_clock() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after 1970")
        .as_secs_f64()
}

// wasm32 has no wall clock (SystemTime::now panics). A wasm host MUST inject an
// explicit clock into any session/replay cache it constructs; this stub only
// keeps the default-clock fallback from aborting the module.
#[cfg(target_arch = "wasm32")]
fn default_clock() -> f64 {
    0.0
}

// The interactive ECDH sessions (SenderSession/ReceiverSession).
pub mod interactive {
    use crc::{Crc, CRC_16_IBM_3740};

    use super::{build_frame, MIN_FPS, SESSION_TTL, TIMESTAMP_WINDOW_MS};
    use crate::alignment::{AlignmentMonitor, ALIGNMENT_CADENCE};
    use crate::beacon::{
        build_payload, parse_payload, parse_receiver_beacon, Beacon, BeaconError, FRAME_CELLS,
        LEVEL_OPEN, LEVEL_PAIRED, LEVEL_PSK, LEVEL_TOFU, LEVEL_WHITELIST, ZERO32,
    };
    use crate::compression;
    use crate::crypto::{self, CryptoError, SessionKey, GCM_TAG_LEN, SIG_LEN};
    use crate::flow::{FlowControl, Signal};
    use crate::frame::{
        header_prefix, max_payload, Frame, FrameError, BEACON, COMPRESSED, ENCRYPTED, HEADER_LEN,
        KEYFRAME, LAST_FRAME, PRIORITY, RECEIVER_BEACON,
    };
    use crate::messages;
    use crate::replay::ReplayCache;
    use crate::tofu::{KeyChangedError, TrustStore};
    use crate::transport::Transport;

    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use std::collections::HashMap;
    use x25519_dalek::StaticSecret as XStaticSecret;

    /// Default: 10 minutes of paused gap time.
    pub const ALIGNMENT_TIMEOUT: f64 = 600.0;

    /// Negotiated session parameters. On the sender these come from the parsed
    /// ACK; on the receiver from [`ReceiverSession::negotiate`].
    #[derive(Debug, Clone, Copy)]
    struct Agreed {
        fps: u8,
        width: u16,
        height: u16,
        cell_size: u8,
    }

    // binascii.crc_hqx(data, 0xFFFF) == CRC-16/IBM-3740.
    const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_3740);

    fn crc_hqx(data: &[u8]) -> u16 {
        CRC16.checksum(data)
    }

    /// Session-level failure for the interactive classes. String-based like the
    /// broadcast half's [`super::SessionError::Message`] variant.
    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum SessionError {
        #[error("{0}")]
        Message(String),
    }

    fn msg(text: &str) -> SessionError {
        SessionError::Message(text.to_string())
    }

    /// The COMPRESSED flag bit this build emits on data frames: set with the
    /// `compression` feature, `0` without it (a build that cannot decompress
    /// must never claim it did).
    #[cfg(feature = "compression")]
    const COMP_FLAG: u8 = COMPRESSED;
    #[cfg(not(feature = "compression"))]
    const COMP_FLAG: u8 = 0;

    /// The outbound transfer stream and the flag bit that records whether the
    /// compression stage ran. With the `compression` feature it compresses and
    /// returns [`COMPRESSED`]; without it, it returns the raw bytes and `0` so
    /// no COMPRESSED frame is ever emitted by a build that cannot decompress.
    fn stage_stream(data: &[u8], level: i32) -> Result<(Vec<u8>, u8), SessionError> {
        #[cfg(feature = "compression")]
        {
            let compressed = compression::compress(data, level).map_err(|e| msg(&e.to_string()))?;
            Ok((compressed, COMP_FLAG))
        }
        #[cfg(not(feature = "compression"))]
        {
            let _ = level;
            Ok((data.to_vec(), COMP_FLAG))
        }
    }

    /// Sender state machine over a [`Transport`].
    pub struct SenderSession<'a, T: Transport> {
        transport: &'a mut T,
        identity: SigningKey,
        intended: [u8; 32],
        level: u8,
        pairing_token: Option<[u8; 16]>,
        whitelist: Option<Vec<[u8; 32]>>,
        receiver_session_token: [u8; 16], // echo
        clock: Box<dyn FnMut() -> f64 + Send>,
        pub session_id: u64, // CSPRNG
        ephemeral: Option<XStaticSecret>,
        pub session_key: Option<SessionKey>,
        pub pin: Option<String>,
        receiver_identity: Option<[u8; 32]>,
        agreed: Option<Agreed>,
        pub fps: Option<u8>,
        next_frame: u32,                   // BEACON takes frame number 0
        sent_grids: HashMap<u32, Vec<u8>>, // retransmits (cached wire bytes)
        pub complete: bool,
        ttl_deadline: Option<f64>,
        pub reject_reason: Option<String>,
        started: bool, // gates scan_receiver_beacon
        // interruptible-transfer state (begin_transfer/step)
        tx_chunks: Vec<(usize, Vec<u8>)>, // (stream_offset, chunk_bytes)
        tx_cursor: usize,
        compressed_stream: Vec<u8>,
        chunk_size: usize,
        total_frames: u64,
        frame_offsets: HashMap<u32, usize>, // data frame_number -> stream offset
        transfer_active: bool,
        last_sent: bool,
        pub paused: bool,
        pub timed_out: bool,
        paused_at: Option<u64>, // last_decoded + 1
        alignment_deadline: Option<f64>,
        resume_offset: Option<usize>, // pending resume-KEYFRAME RESUME_OFFSET; None = none
        waiting_grid: Option<Vec<u8>>, // cached WAITING wire bytes
    }

    impl<'a, T: Transport> SenderSession<'a, T> {
        /// Constructor validation matrix. `session_level = None` defaults to
        /// LEVEL_OPEN for a broadcast target else LEVEL_TOFU.
        ///
        /// # Errors
        /// [`SessionError::Message`] on any invalid level/token/whitelist
        /// combination.
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            transport: &'a mut T,
            identity: SigningKey,
            intended_receiver: [u8; 32],
            session_level: Option<u8>,
            pairing_token: Option<[u8; 16]>,
            receiver_whitelist: Option<Vec<[u8; 32]>>,
            receiver_session_token: [u8; 16],
            clock: Box<dyn FnMut() -> f64 + Send>,
        ) -> Result<Self, SessionError> {
            // default preserves prior behaviour: open if broadcast, else TOFU
            let level = session_level.unwrap_or({
                if intended_receiver == ZERO32 {
                    LEVEL_OPEN
                } else {
                    LEVEL_TOFU
                }
            });
            if level == LEVEL_PSK {
                return Err(msg("PSK sessions not yet implemented"));
            }
            if !matches!(
                level,
                LEVEL_OPEN | LEVEL_TOFU | LEVEL_PAIRED | LEVEL_WHITELIST
            ) {
                return Err(msg(&format!("bad session_level: {}", level)));
            }
            if level >= LEVEL_TOFU && intended_receiver == ZERO32 {
                return Err(msg("levels 1-3 require an intended_receiver"));
            }
            if level == LEVEL_PAIRED && pairing_token.is_none() {
                return Err(msg("level 2 requires a 16-byte pairing_token"));
            }
            if level == LEVEL_WHITELIST
                && receiver_whitelist
                    .as_ref()
                    .map(|w| w.is_empty())
                    .unwrap_or(true)
            {
                return Err(msg("level 3 requires a non-empty receiver_whitelist"));
            }
            if level == LEVEL_WHITELIST {
                // sender specifies INTENDED_RECEIVER from whitelist
                let wl = receiver_whitelist
                    .as_ref()
                    .expect("checked non-empty above");
                if !wl
                    .iter()
                    .any(|k| crypto::fingerprint(k) == intended_receiver)
                {
                    return Err(msg("intended_receiver is not in receiver_whitelist"));
                }
            }
            let session_id = OsRng.next_u64();
            Ok(Self {
                transport,
                identity,
                intended: intended_receiver,
                level,
                pairing_token,
                whitelist: receiver_whitelist,
                receiver_session_token, // echo
                clock,
                session_id,
                ephemeral: Some(crypto::generate_ephemeral()),
                session_key: None,
                pin: None,
                receiver_identity: None,
                agreed: None,
                fps: None,
                next_frame: 1,
                sent_grids: HashMap::new(),
                complete: false,
                ttl_deadline: None,
                reject_reason: None,
                started: false,
                tx_chunks: Vec::new(),
                tx_cursor: 0,
                compressed_stream: Vec::new(),
                chunk_size: 0,
                total_frames: 0,
                frame_offsets: HashMap::new(),
                transfer_active: false,
                last_sent: false,
                paused: false,
                timed_out: false,
                paused_at: None,
                alignment_deadline: None,
                resume_offset: None,
                waiting_grid: None,
            })
        }

        /// Scan a receiver's reverse beacon (already-parsed RECEIVER_BEACON wire
        /// bytes; the host QR layer decoded the frame) to target a level-1
        /// session - adopt its fingerprint, upgrade to LEVEL_TOFU, and echo the
        /// scanned session token. Must be called before [`Self::start`]; returns
        /// the receiver fingerprint.
        ///
        /// # Errors
        /// [`SessionError::Message`] if called after start, on a whitelist
        /// session, on a beacon-parse failure, or on an intended-receiver clash.
        pub fn scan_receiver_beacon(&mut self, rbea_wire: &[u8]) -> Result<[u8; 32], SessionError> {
            if self.started {
                return Err(msg(
                    "cannot scan a reverse beacon after the session has started",
                ));
            }
            if self.level == LEVEL_WHITELIST {
                return Err(msg(
                    "reverse-beacon scan does not apply to a whitelist (level 3) session",
                ));
            }
            let now = (self.clock)();
            let rb = parse_receiver_beacon(rbea_wire, || now).map_err(|e| msg(&e.to_string()))?;
            let fingerprint = crypto::fingerprint(&rb.identity_pub);
            if self.intended != ZERO32 && self.intended != fingerprint {
                return Err(msg(
                    "scanned receiver conflicts with configured intended_receiver",
                ));
            }
            self.intended = fingerprint;
            if self.level == LEVEL_OPEN {
                self.level = LEVEL_TOFU;
            }
            self.receiver_session_token = rb.session_token;
            Ok(fingerprint)
        }

        /// Emit the BEACON (frame 0, `BEACON | PRIORITY`).
        ///
        /// # Errors
        /// [`SessionError::Message`] on a beacon/frame/QR encode failure.
        pub fn start(
            &mut self,
            transfer_size: u64,
            transfer_name: &str,
        ) -> Result<(), SessionError> {
            self.started = true; // gate scan_receiver_beacon: scan is pre-start only
            let caps = self.transport.display_capabilities();
            let token_hash = if self.level == LEVEL_PAIRED {
                crypto::pairing_token_hash(
                    self.pairing_token.as_ref().expect("level 2 has a token"),
                    self.session_id,
                )
            } else {
                ZERO32
            };
            let ephemeral_pub =
                crypto::ephemeral_public_bytes(self.ephemeral.as_ref().expect("open session"));
            let beacon = Beacon::new(
                self.session_id,
                ((self.clock)() * 1000.0) as u64,
                self.level,
                self.intended,
                token_hash,
                ephemeral_pub,
                crypto::identity_public_bytes(&self.identity),
                caps.width,
                caps.height,
                caps.max_fps,
                caps.cell_size,
                transfer_size,
                transfer_name.to_string(),
                self.receiver_session_token,
                FRAME_CELLS,
                0,
                0,
            )
            .map_err(|e: BeaconError| msg(&e.to_string()))?;
            let payload = build_payload(&beacon, &self.identity, 1);
            let frame =
                build_frame(0, BEACON | PRIORITY, payload).map_err(|e| msg(&e.to_string()))?;
            self.transport.render_frame(&frame.encode());
            Ok(())
        }

        /// Await and validate the signed HANDSHAKE_ACK. `false` rejections record
        /// their cause in [`Self::reject_reason`] (silent rejection).
        ///
        /// # Errors
        /// [`SessionError::Message`] only if the back channel is unavailable
        /// (broadcast mode); a validation failure is a returned `Ok(false)`.
        pub fn await_ack(&mut self) -> Result<bool, SessionError> {
            let raw = self
                .transport
                .back_channel_recv()
                .map_err(|e| msg(&e.to_string()))?;
            self.reject_reason = None;
            if raw.len() < 1 + SIG_LEN || raw[0] != messages::HANDSHAKE_ACK {
                self.reject_reason = Some("malformed".to_string());
                return Ok(false);
            }
            let (body, sig) = raw.split_at(raw.len() - SIG_LEN);
            let ack = match messages::parse_handshake_ack(&body[1..]) {
                Ok(a) => a,
                Err(_) => {
                    self.reject_reason = Some("malformed".to_string());
                    return Ok(false);
                }
            };
            if !crypto::verify(ack.identity_pub, sig, body) {
                self.reject_reason = Some("bad-signature".to_string());
                return Ok(false);
            }
            if self.intended != ZERO32 && crypto::fingerprint(&ack.identity_pub) != self.intended {
                self.reject_reason = Some("not-intended-receiver".to_string());
                return Ok(false);
            }
            if self.level == LEVEL_WHITELIST {
                // belt-and-braces: unreachable when intended_receiver comes from
                // the whitelist (ctor-enforced), kept as a second layer.
                let ok = self
                    .whitelist
                    .as_ref()
                    .map(|w| w.contains(&ack.identity_pub))
                    .unwrap_or(false);
                if !ok {
                    self.reject_reason = Some("not-whitelisted".to_string());
                    return Ok(false);
                }
            }
            self.receiver_identity = Some(ack.identity_pub);
            self.fps = Some(ack.fps);
            self.session_key = Some(crypto::session_key(
                self.ephemeral.as_ref().expect("open session"),
                ack.ephemeral_pub,
                self.session_id,
            ));
            self.pin = Some(crypto::derive_pin(
                self.session_key.as_ref().expect("just set").as_bytes(),
            ));
            self.agreed = Some(Agreed {
                fps: ack.fps,
                width: ack.width,
                height: ack.height,
                cell_size: ack.cell_size,
            });
            Ok(true)
        }

        fn send_frame(&mut self, plaintext: &[u8], flags: u8) -> Result<u32, SessionError> {
            let key = self
                .session_key
                .as_ref()
                .ok_or_else(|| {
                    msg("no session key: handshake incomplete or session closed/expired")
                })?
                .clone();
            let number = self.next_frame;
            self.next_frame += 1;
            let payload_len = plaintext.len() + GCM_TAG_LEN;
            let aad = header_prefix(number, flags, payload_len as u16)
                .map_err(|e: FrameError| msg(&e.to_string()))?;
            let payload = crypto::encrypt_payload(
                key.as_bytes(),
                self.session_id,
                number as u64,
                plaintext,
                &aad,
            );
            let frame = build_frame(number, flags, payload).map_err(|e| msg(&e.to_string()))?;
            let wire = frame.encode();
            self.sent_grids.insert(number, wire.clone());
            self.transport.render_frame(&wire);
            Ok(number)
        }

        /// Encrypt+send one arbitrary plaintext frame (`ENCRYPTED`).
        ///
        /// # Errors
        /// [`SessionError::Message`] if there is no session key or on encode.
        pub fn send(&mut self, plaintext: &[u8]) -> Result<u32, SessionError> {
            self.send_frame(plaintext, ENCRYPTED)
        }

        /// Whole-transfer send: zstd -> chunk -> encrypt per frame -> LAST_FRAME.
        /// Returns the number of DATA frames sent.
        ///
        /// # Errors
        /// [`SessionError::Message`] if there is no session key, on compression,
        /// or on encode.
        pub fn send_data(&mut self, data: &[u8], level: i32) -> Result<u32, SessionError> {
            if self.session_key.is_none() {
                return Err(msg(
                    "no session key: handshake incomplete or session closed/expired",
                ));
            }
            let (compressed, comp_flag) = stage_stream(data, level)?;
            let chunk = max_payload(HEADER_LEN) - GCM_TAG_LEN;
            let mut off = 0;
            while off < compressed.len() {
                let end = (off + chunk).min(compressed.len());
                self.send_frame(&compressed[off..end], ENCRYPTED | comp_flag)?;
                off = end;
            }
            let n_frames = self.next_frame - 1;
            self.finish()?;
            Ok(n_frames)
        }

        /// LAST_FRAME + TTL deadline. Returns its frame number.
        ///
        /// # Errors
        /// [`SessionError::Message`] if there is no session key or on encode.
        pub fn finish(&mut self) -> Result<u32, SessionError> {
            let number = self.send_frame(b"", ENCRYPTED | LAST_FRAME)?;
            self.ttl_deadline = Some((self.clock)() + SESSION_TTL); // fallback
            Ok(number)
        }

        /// Interruptible transfer: compress + chunk now, emit nothing. Drive one
        /// frame per [`Self::step`].
        ///
        /// # Errors
        /// [`SessionError::Message`] if there is no session key or on compression.
        pub fn begin_transfer(&mut self, data: &[u8], level: i32) -> Result<(), SessionError> {
            if self.session_key.is_none() {
                return Err(msg(
                    "no session key: handshake incomplete or session closed/expired",
                ));
            }
            let (compressed, _comp_flag) = stage_stream(data, level)?;
            let chunk = max_payload(HEADER_LEN) - GCM_TAG_LEN;
            let mut chunks = Vec::new();
            let mut off = 0;
            while off < compressed.len() {
                let end = (off + chunk).min(compressed.len());
                chunks.push((off, compressed[off..end].to_vec()));
                off = end;
            }
            self.total_frames = chunks.len() as u64 + 1; // data chunks + LAST_FRAME
            self.compressed_stream = compressed;
            self.chunk_size = chunk;
            self.tx_chunks = chunks;
            self.tx_cursor = 0;
            self.frame_offsets = HashMap::new();
            self.transfer_active = true;
            self.last_sent = false;
            self.paused = false;
            self.timed_out = false;
            self.paused_at = None;
            self.alignment_deadline = None;
            self.resume_offset = None;
            Ok(())
        }

        pub fn done(&self) -> bool {
            self.tx_cursor >= self.tx_chunks.len() && self.last_sent
        }

        /// Emit exactly one frame; return a tag: `idle`, `timed-out`, `waiting`,
        /// `keyframe`, `data`, `last`.
        ///
        /// # Errors
        /// [`SessionError::Message`] on any encode/back-channel failure.
        pub fn step(&mut self) -> Result<String, SessionError> {
            if !self.transfer_active {
                return Ok("idle".to_string()); // nothing loaded -> nothing to emit
            }
            if self.check_alignment_timeout()? {
                return Ok("timed-out".to_string());
            }
            if self.paused {
                self.render_waiting()?;
                return Ok("waiting".to_string());
            }
            if let Some(resume_offset) = self.resume_offset {
                // 0 is a valid offset; None = none pending
                self.emit_keyframe(resume_offset)?;
                self.resume_offset = None;
                return Ok("keyframe".to_string());
            }
            if self.tx_cursor < self.tx_chunks.len() {
                let (off, chunk) = self.tx_chunks[self.tx_cursor].clone();
                let number = self.send_frame(&chunk, ENCRYPTED | COMP_FLAG)?;
                self.frame_offsets.insert(number, off);
                self.tx_cursor += 1;
                return Ok("data".to_string());
            }
            if !self.last_sent {
                self.finish()?; // ENCRYPTED | LAST_FRAME + ttl deadline
                self.last_sent = true;
                return Ok("last".to_string());
            }
            Ok("idle".to_string())
        }

        fn emit_keyframe(&mut self, resume_offset: usize) -> Result<(), SessionError> {
            // SESSION_ID + TOTAL_FRAMES + RESUME_OFFSET + CHECKSUM, big-endian
            // ">QQQH", encrypted like any DATA frame. 26 B plaintext.
            let checksum = crc_hqx(&self.compressed_stream[..resume_offset]);
            let mut payload = Vec::with_capacity(26);
            payload.extend_from_slice(&self.session_id.to_be_bytes());
            payload.extend_from_slice(&self.total_frames.to_be_bytes());
            payload.extend_from_slice(&(resume_offset as u64).to_be_bytes());
            payload.extend_from_slice(&checksum.to_be_bytes());
            self.send_frame(&payload, ENCRYPTED | KEYFRAME)?;
            Ok(())
        }

        fn render_waiting(&mut self) -> Result<(), SessionError> {
            // PRIORITY|KEYFRAME, empty payload (payload_len 0 is the
            // discriminator from a real KEYFRAME), not encrypted, consumes no
            // frame number.
            if self.waiting_grid.is_none() {
                let frame = build_frame(0, PRIORITY | KEYFRAME, Vec::new())
                    .map_err(|e| msg(&e.to_string()))?;
                self.waiting_grid = Some(frame.encode());
            }
            let wire = self.waiting_grid.as_ref().expect("just set");
            self.transport.render_frame(wire);
            Ok(())
        }

        fn check_alignment_timeout(&mut self) -> Result<bool, SessionError> {
            // On paused-gap timeout, tell the receiver and fail. Sends
            // SESSION_TIMEOUT once; the deadline is reset only by a RESUME.
            if self.timed_out {
                return Ok(true);
            }
            if self.paused {
                if let Some(deadline) = self.alignment_deadline {
                    if (self.clock)() >= deadline {
                        let signed = crypto::sign_message(
                            &self.identity,
                            messages::SESSION_TIMEOUT,
                            &messages::pack_session_timeout(self.session_id),
                        );
                        self.transport
                            .back_channel_send(signed)
                            .map_err(|e| msg(&e.to_string()))?;
                        self.timed_out = true;
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }

        fn rewind_to(&mut self, resume_from: u32) -> usize {
            // Resume at the chunk whose frame_number == resume_from, or the
            // earliest sent chunk with frame_number >= resume_from; if resume_from
            // is past everything sent, resume at the current cursor. Returns the
            // stream offset that chunk starts at (the KEYFRAME's RESUME_OFFSET).
            let mut ahead: Vec<u32> = self
                .frame_offsets
                .keys()
                .copied()
                .filter(|&n| n >= resume_from)
                .collect();
            ahead.sort_unstable();
            if let Some(&first) = ahead.first() {
                let off = self.frame_offsets[&first];
                // offsets are exact multiples of chunk_size (range step), so the
                // chunk index is off // chunk_size.
                self.tx_cursor = off / self.chunk_size;
                return off;
            }
            if self.tx_cursor < self.tx_chunks.len() {
                return self.tx_chunks[self.tx_cursor].0;
            }
            self.compressed_stream.len()
        }

        /// Route a signed back-channel message. Returns a status string.
        ///
        /// # Errors
        /// [`SessionError::Message`] on a back-channel-send failure or encode.
        pub fn handle_backchannel(&mut self, raw: &[u8]) -> Result<String, SessionError> {
            if let Some(deadline) = self.ttl_deadline {
                if !self.complete && (self.clock)() >= deadline {
                    self.close(); // fallback zeroize
                    return Ok("expired".to_string());
                }
            }
            if self.check_alignment_timeout()? {
                return Ok("timed-out".to_string());
            }
            let recv_id = match self.receiver_identity {
                Some(id) => id,
                None => return Ok("rejected".to_string()), // no receiver yet -> reject silently
            };
            let opened = crypto::open_message(recv_id, raw);
            let (msg_type, payload) = match opened {
                Some(pair) => pair,
                None => return Ok("rejected".to_string()), // silent
            };
            if msg_type == messages::NAK {
                if let Ok((_, missing)) = messages::parse_nak(&payload) {
                    for number in missing {
                        // retransmit must be byte-identical
                        if let Some(grid) = self.sent_grids.get(&(number as u32)) {
                            let grid = grid.clone();
                            self.transport.render_frame(&grid);
                        }
                    }
                }
                return Ok("retransmitted".to_string());
            }
            if msg_type == messages::SESSION_COMPLETE {
                if let Ok(sid) = messages::parse_session_complete(&payload) {
                    if sid == self.session_id {
                        self.complete = true;
                        self.close();
                        return Ok("complete".to_string());
                    }
                }
                return Ok("rejected".to_string());
            }
            if msg_type == messages::SLOW_DOWN || msg_type == messages::SPEED_UP {
                let (signal, name) = if msg_type == messages::SLOW_DOWN {
                    (Signal::SlowDown, "slow_down")
                } else {
                    (Signal::SpeedUp, "speed_up")
                };
                self.adjust_fps(signal);
                return Ok(name.to_string());
            }
            // alignment-event handlers
            if msg_type == messages::DEGRADED {
                // ECC_LEVEL is fixed for the session, so DEGRADED reduces fps
                // only (adaptive ECC deferred to v0.2).
                self.adjust_fps(Signal::SlowDown);
                return Ok("degraded-adjusted".to_string());
            }
            if msg_type == messages::PAUSE {
                if let Ok(last_decoded) = messages::parse_pause(&payload) {
                    self.paused = true;
                    self.paused_at = Some(last_decoded + 1);
                    self.alignment_deadline = Some((self.clock)() + ALIGNMENT_TIMEOUT);
                }
                return Ok("paused".to_string());
            }
            if msg_type == messages::RESUME {
                if let Ok((resume_from, _aqs)) = messages::parse_resume(&payload) {
                    self.paused = false;
                    self.resume_offset = Some(self.rewind_to(resume_from as u32));
                    // RESUME restores the negotiated fps.
                    self.fps = self.agreed.as_ref().map(|a| a.fps);
                    self.alignment_deadline = None; // gap timer clears on RESUME
                }
                return Ok("resuming".to_string());
            }
            if msg_type == messages::RESUMED {
                self.resume_offset = None;
                return Ok("resumed".to_string());
            }
            if msg_type == messages::ALIGNMENT {
                return Ok("alignment".to_string()); // informational
            }
            Ok("rejected".to_string())
        }

        // +/-5 fps per signal, floored at MIN_FPS and capped at the negotiated
        // fps.
        fn adjust_fps(&mut self, signal: Signal) {
            let current = self.fps.unwrap_or(0) as i32;
            let max_fps = self.agreed.as_ref().map(|a| a.fps).unwrap_or(0) as i32;
            let adjusted = crate::flow::adjust_fps(current, Some(signal), MIN_FPS as i32, max_fps);
            self.fps = Some(adjusted as u8);
        }

        /// Best-effort zeroize: drop the ephemeral, key, grid cache, and
        /// single-use pairing token.
        pub fn close(&mut self) {
            self.ephemeral = None;
            self.session_key = None;
            self.sent_grids.clear();
            self.pairing_token = None; // single-use: drop after complete
        }
    }

    /// Receiver state machine over a [`Transport`].
    pub struct ReceiverSession<'a, T: Transport> {
        transport: &'a mut T,
        identity: SigningKey,
        trust: &'a mut TrustStore,
        replay: &'a mut ReplayCache,
        peer_name: String,
        auto_accept: bool, // Mode B
        min_level: u8,     // reject below configured minimum
        pairing_token: Option<[u8; 16]>,
        sender_whitelist: Vec<[u8; 32]>,
        session_token: Option<[u8; 16]>, // token-echo binding
        clock: Box<dyn FnMut() -> f64 + Send>,
        cached_ack: Option<Vec<u8>>, // signed HANDSHAKE_ACK bytes, re-ACK
        ephemeral: Option<XStaticSecret>,
        pub session_id: Option<u64>,
        pub session_key: Option<SessionKey>,
        pub pin: Option<String>,
        sender_identity: Option<[u8; 32]>,
        agreed: Option<Agreed>,
        pub flow: FlowControl,
        chunks: HashMap<u32, Vec<u8>>, // frame_number -> plaintext
        keyframe_offsets: HashMap<u32, usize>, // keyframe frame_number -> RESUME_OFFSET
        keyframe_checks: HashMap<u32, (usize, u16)>, // keyframe frame_number -> (offset, checksum)
        keyframe_bad: bool,            // a KEYFRAME whose plaintext didn't parse
        compressed: bool,
        pub transfer_size: u64, // from BEACON; decompression bound
        last_frame: Option<u32>,
        pub complete: bool,
        ttl_deadline: Option<f64>,
        pub alignment: Option<AlignmentMonitor>, // monitor; built once keys derived
    }

    impl<'a, T: Transport> ReceiverSession<'a, T> {
        #[allow(clippy::too_many_arguments)]
        pub fn new(
            transport: &'a mut T,
            identity: SigningKey,
            trust_store: &'a mut TrustStore,
            replay_cache: &'a mut ReplayCache,
            peer_name: &str,
            auto_accept: bool,
            min_level: u8,
            pairing_token: Option<[u8; 16]>,
            sender_whitelist: Option<Vec<[u8; 32]>>,
            session_token: Option<[u8; 16]>,
            clock: Box<dyn FnMut() -> f64 + Send>,
        ) -> Self {
            Self {
                transport,
                identity,
                trust: trust_store,
                replay: replay_cache,
                peer_name: peer_name.to_string(),
                auto_accept,
                min_level,
                pairing_token,
                sender_whitelist: sender_whitelist.unwrap_or_default(),
                session_token,
                clock,
                cached_ack: None,
                ephemeral: None,
                session_id: None,
                session_key: None,
                pin: None,
                sender_identity: None,
                agreed: None,
                flow: FlowControl::default(),
                chunks: HashMap::new(),
                keyframe_offsets: HashMap::new(),
                keyframe_checks: HashMap::new(),
                keyframe_bad: false,
                compressed: false,
                transfer_size: 0,
                last_frame: None,
                complete: false,
                ttl_deadline: None,
                alignment: None,
            }
        }

        /// Route one frame's wire bytes (the host carrier already decoded the
        /// QR). Returns a status string.
        ///
        /// # Errors
        /// [`KeyChangedError`] - a changed pinned identity key is a hard TOFU
        /// failure that propagates.
        pub fn on_wire(&mut self, wire: &[u8]) -> Result<String, KeyChangedError> {
            if let Some(deadline) = self.ttl_deadline {
                if !self.complete && (self.clock)() >= deadline {
                    self.ephemeral = None; // fallback zeroize
                    self.session_key = None;
                    self.chunks.clear(); // partial plaintext of a dead session
                    return Ok("expired".to_string());
                }
            }
            // The wire carries the whole frame; route on FLAGS.
            let frame = match Frame::decode(wire) {
                Ok(f) => f,
                Err(_) => {
                    self.flow.record(false);
                    return Ok("undecodable".to_string());
                }
            };
            let flags = frame.flags;
            if flags & RECEIVER_BEACON != 0 {
                // a receiver's own reverse beacon; not sender->receiver data
                return Ok("ignored-receiver-beacon".to_string());
            }
            if flags & BEACON != 0 {
                return self.on_beacon(&frame);
            }
            if self.agreed.is_none() {
                return Ok("ignored-wrong-session".to_string()); // no session yet
            }
            if flags & KEYFRAME != 0 {
                return Ok(self.on_keyframe(&frame));
            }
            Ok(self.on_data(&frame))
        }

        /// Capture-layer seam: feed one camera observation to the monitor,
        /// sign+send every back-channel signal it emits, return the new state.
        ///
        /// # Errors
        /// [`SessionError::Message`] on an alignment-input error or a
        /// back-channel-send failure.
        pub fn observe_alignment(
            &mut self,
            markers_found: u8,
            sharpness: f32,
            decoded_ok: Option<bool>,
            frame_number: Option<u64>,
            is_keyframe: bool,
        ) -> Result<&'static str, SessionError> {
            let monitor = self
                .alignment
                .as_mut()
                .ok_or_else(|| msg("alignment monitor not built: no session yet"))?;
            let signals = monitor
                .observe(
                    markers_found,
                    sharpness,
                    decoded_ok,
                    frame_number,
                    is_keyframe,
                )
                .map_err(|e| msg(&e.to_string()))?;
            let state = self.alignment.as_ref().expect("just used").state;
            for (msg_type, payload) in signals {
                self.send(msg_type, &payload)?;
            }
            Ok(state)
        }

        fn on_keyframe(&mut self, frame: &Frame) -> String {
            // Discriminator: KEYFRAME with an empty payload is a WAITING frame
            // (sender paused), not data - never NAK it.
            if frame.payload.is_empty() {
                return "waiting-seen".to_string();
            }
            if self.session_id.is_none() || self.session_key.is_none() {
                return "ignored-wrong-session".to_string();
            }
            let aad =
                match header_prefix(frame.frame_number, frame.flags, frame.payload.len() as u16) {
                    Ok(a) => a,
                    Err(_) => return "ignored-wrong-session".to_string(),
                };
            let key = self.session_key.as_ref().expect("checked above").clone();
            let plaintext = match crypto::decrypt_payload(
                key.as_bytes(),
                self.session_id.expect("checked above"),
                frame.frame_number as u64,
                &frame.payload,
                &aad,
            ) {
                Ok(p) => p,
                Err(CryptoError::Decrypt) => {
                    self.flow.record(false);
                    return "auth-failed".to_string();
                }
                Err(_) => {
                    self.flow.record(false);
                    return "auth-failed".to_string();
                }
            };
            // 26-byte plaintext, big-endian ">QQQH".
            if plaintext.len() != 26 {
                self.keyframe_bad = true;
                // a malformed KEYFRAME still occupies a frame number, not a data
                // slot; record it (offset 0) so missing() never treats it as lost.
                self.keyframe_offsets.insert(frame.frame_number, 0);
                return "keyframe-checksum-mismatch".to_string();
            }
            let resume_offset =
                u64::from_be_bytes(plaintext[16..24].try_into().expect("26-byte plaintext"))
                    as usize;
            let checksum =
                u16::from_be_bytes(plaintext[24..26].try_into().expect("26-byte plaintext"));
            // A KEYFRAME occupies a frame number but carries no stream bytes; record
            // its RESUME_OFFSET so re-sent DATA overwrites at that offset and
            // missing() never treats the number as a lost DATA frame.
            self.keyframe_offsets
                .insert(frame.frame_number, resume_offset);
            // Do NOT latch a failure here: a still-NAK-pending gap makes the
            // checksum transiently mismatch; the `integrity_ok` property re-checks.
            self.keyframe_checks
                .insert(frame.frame_number, (resume_offset, checksum));
            let assembled = self.assemble();
            let take = resume_offset.min(assembled.len());
            let provisional = crc_hqx(&assembled[..take]) != checksum;
            if provisional {
                "keyframe-checksum-mismatch".to_string()
            } else {
                "keyframe-ok".to_string()
            }
        }

        /// True iff every KEYFRAME's prefix checksum matches the assembled
        /// stream. Computed (not latched).
        pub fn integrity_ok(&self) -> bool {
            if self.keyframe_bad {
                return false;
            }
            let asm = self.assemble();
            self.keyframe_checks.values().all(|&(off, cs)| {
                let take = off.min(asm.len());
                crc_hqx(&asm[..take]) == cs
            })
        }

        fn on_beacon(&mut self, frame: &Frame) -> Result<String, KeyChangedError> {
            // Verify the beacon signature first (parse_payload does): nothing
            // downstream acts on an unauthenticated frame.
            let beacon = match parse_payload(&frame.payload) {
                Ok(b) => b,
                Err(_) => return Ok("ignored-invalid".to_string()),
            };
            let session_id = beacon.session_id;
            // A repeat (signature-valid) BEACON for the active, incomplete
            // session re-sends the cached ACK unchanged. Ordered before the replay
            // check, which handles COMPLETED sessions.
            if self.session_id == Some(session_id) && !self.complete {
                if let Some(cached) = self.cached_ack.clone() {
                    let _ = self.transport.back_channel_send(cached);
                    return Ok("ack-resent".to_string());
                }
            }
            if self.replay.contains(session_id) {
                return Ok("ignored-replay".to_string()); // silent
            }
            let now_ms = ((self.clock)() * 1000.0) as u64;
            if now_ms.abs_diff(beacon.timestamp_ms) >= TIMESTAMP_WINDOW_MS {
                return Ok("ignored-stale".to_string());
            }
            // LEVEL_PSK is excluded from the level ordering.
            if beacon.session_level == LEVEL_PSK {
                return Ok("ignored-psk-unsupported".to_string());
            }
            // Mandatory checklist, in order (a-e); all silent ignores.
            // a-b: SESSION_LEVEL vs configured minimum
            if beacon.session_level < self.min_level {
                return Ok("ignored-level-too-low".to_string());
            }
            // c: levels 1-3 must target this receiver's fingerprint.
            let mine = crypto::fingerprint(&crypto::identity_public_bytes(&self.identity));
            if (LEVEL_TOFU..=LEVEL_WHITELIST).contains(&beacon.session_level)
                && beacon.intended_receiver == ZERO32
            {
                return Ok("ignored-invalid".to_string());
            }
            if beacon.intended_receiver != ZERO32 && beacon.intended_receiver != mine {
                return Ok("ignored-not-for-me".to_string()); // silent
            }
            // Token-echo binding: a receiver that issued a session token silently
            // ignores a targeted BEACON echoing a stale token. Broadcast
            // (untargeted) beacons are exempt.
            if let Some(token) = self.session_token {
                if beacon.intended_receiver == mine
                    && !constant_time_eq(&token, &beacon.receiver_session_token)
                {
                    return Ok("ignored-wrong-token-echo".to_string());
                }
            }
            // d: level 2 must verify PAIRING_TOKEN_HASH
            if beacon.session_level == LEVEL_PAIRED {
                let token = match self.pairing_token {
                    Some(t) => t,
                    None => return Ok("ignored-no-token".to_string()),
                };
                let expected = crypto::pairing_token_hash(&token, session_id);
                if !constant_time_eq(&expected, &beacon.pairing_token_hash) {
                    return Ok("ignored-wrong-token".to_string());
                }
            }
            // e: level 3 checks the whitelist and skips TOFU entirely.
            if beacon.session_level == LEVEL_WHITELIST {
                if !self.sender_whitelist.contains(&beacon.identity_pub) {
                    return Ok("ignored-not-whitelisted".to_string());
                }
            } else {
                let status = self.trust.verify(&self.peer_name, &beacon.identity_pub)?;
                if !status {
                    // unknown key: first use
                    if !self.auto_accept {
                        return Ok("confirmation-required".to_string());
                    }
                    if self
                        .trust
                        .trust(&self.peer_name, &beacon.identity_pub)
                        .is_err()
                    {
                        return Ok("ignored-invalid".to_string());
                    }
                }
            }

            self.session_id = Some(session_id);
            self.sender_identity = Some(beacon.identity_pub);
            self.transfer_size = beacon.transfer_size;
            let ephemeral = crypto::generate_ephemeral();
            self.session_key = Some(crypto::session_key(
                &ephemeral,
                beacon.ephemeral_pub,
                session_id,
            ));
            self.pin = Some(crypto::derive_pin(
                self.session_key.as_ref().expect("just set").as_bytes(),
            ));
            let ephemeral_pub = crypto::ephemeral_public_bytes(&ephemeral);
            self.ephemeral = Some(ephemeral);
            let agreed = self.negotiate(&beacon);
            // session established -> stand up the alignment monitor.
            // ponytail: the monitor owns its own FnMut clock; the injected
            // session clock cannot be cloned, so the monitor gets a system clock.
            // Its clock is used only for the alignment_timeout reset, which the
            // loopback path (on_wire never calls observe) never exercises.
            self.alignment = Some(AlignmentMonitor::new(
                Box::new(super::default_clock),
                ALIGNMENT_CADENCE,
            ));
            let ack = messages::pack_handshake_ack(
                &ephemeral_pub,
                &crypto::identity_public_bytes(&self.identity),
                agreed.fps,
                agreed.width,
                agreed.height,
                agreed.cell_size,
            );
            let signed_ack = crypto::sign_message(&self.identity, messages::HANDSHAKE_ACK, &ack);
            self.agreed = Some(agreed);
            self.cached_ack = Some(signed_ack.clone()); // exact bytes for idempotent re-ACK
            let _ = self.transport.back_channel_send(signed_ack);
            Ok("ack-sent".to_string())
        }

        fn negotiate(&self, beacon: &Beacon) -> Agreed {
            // provisional policy: min/max rules.
            let caps = self.transport.sensor_capabilities();
            Agreed {
                fps: beacon.max_fps.min(caps.max_fps),
                width: beacon.width.min(caps.width),
                height: beacon.height.min(caps.height),
                cell_size: beacon.cell_size.max(caps.cell_size),
            }
        }

        fn on_data(&mut self, frame: &Frame) -> String {
            if self.session_id.is_none() || self.session_key.is_none() {
                return "ignored-wrong-session".to_string(); // no live session key
            }
            let aad =
                match header_prefix(frame.frame_number, frame.flags, frame.payload.len() as u16) {
                    Ok(a) => a,
                    Err(_) => return "ignored-wrong-session".to_string(),
                };
            let key = self.session_key.as_ref().expect("checked above").clone();
            let plaintext = match crypto::decrypt_payload(
                key.as_bytes(),
                self.session_id.expect("checked above"),
                frame.frame_number as u64,
                &frame.payload,
                &aad,
            ) {
                Ok(p) => p,
                Err(_) => {
                    self.flow.record(false);
                    return "auth-failed".to_string();
                }
            };
            self.flow.record(true);
            self.chunks.insert(frame.frame_number, plaintext); // placed by offset in assemble()
            if frame.flags & COMPRESSED != 0 {
                self.compressed = true;
            }
            if frame.flags & LAST_FRAME != 0 {
                self.last_frame = Some(frame.frame_number);
                if self.ttl_deadline.is_none() {
                    // arm once - a retransmitted LAST_FRAME must not postpone the
                    // fallback wipe
                    self.ttl_deadline = Some((self.clock)() + SESSION_TTL);
                }
            }
            if self.last_frame.is_some() {
                let missing = self.missing();
                if !missing.is_empty() {
                    let cqs = self.flow.cqs() as f32;
                    let _ = self.send(messages::NAK, &messages::pack_nak(cqs, &missing));
                    return "nak-sent".to_string();
                }
                let sid = self.session_id.expect("session active");
                let _ = self.send(
                    messages::SESSION_COMPLETE,
                    &messages::pack_session_complete(sid),
                );
                self.replay.add(sid);
                self.complete = true;
                self.ephemeral = None; // best-effort zeroize
                self.session_key = None;
                self.pairing_token = None; // single-use
                return "complete-sent".to_string();
            }
            "stored".to_string()
        }

        /// NAK computation: DATA frame numbers 1..=last that were neither stored
        /// nor claimed by a KEYFRAME.
        pub fn missing(&self) -> Vec<u64> {
            let last = match self.last_frame {
                Some(l) => l,
                None => return Vec::new(),
            };
            (1..=last)
                .filter(|n| !self.chunks.contains_key(n) && !self.keyframe_offsets.contains_key(n))
                .map(|n| n as u64)
                .collect()
        }

        fn assemble(&self) -> Vec<u8> {
            // Replay all frames in FRAME-NUMBER order with a running write offset
            // that each KEYFRAME resets to its RESUME_OFFSET.
            let mut keys: Vec<u32> = self
                .chunks
                .keys()
                .chain(self.keyframe_offsets.keys())
                .copied()
                .collect();
            keys.sort_unstable();
            keys.dedup();
            let mut buf: Vec<u8> = Vec::new();
            let mut offset = 0usize;
            for n in keys {
                if let Some(&kf_off) = self.keyframe_offsets.get(&n) {
                    offset = kf_off;
                    continue;
                }
                let chunk = &self.chunks[&n];
                let end = offset + chunk.len();
                if end > buf.len() {
                    buf.resize(end, 0);
                }
                buf[offset..end].copy_from_slice(chunk);
                offset = end;
            }
            buf
        }

        /// The reassembled (and, if flagged, decompressed) transfer.
        ///
        /// # Errors
        /// [`SessionError::Message`] if the session is not complete, a KEYFRAME
        /// checksum mismatches, or a bounded decompress fails.
        pub fn data(&self) -> Result<Vec<u8>, SessionError> {
            if !self.complete {
                return Err(msg("session not complete"));
            }
            if !self.integrity_ok() {
                return Err(msg("KEYFRAME checksum mismatch - data integrity lost"));
            }
            let raw = self.assemble();
            if !self.compressed {
                return Ok(raw);
            }
            // bomb guard: BEACON TRANSFER_SIZE is the exact decompressed size;
            // 0 = unknown = unbounded. decompress is always available
            // (zstd native, ruzstd on wasm).
            compression::decompress(&raw, self.transfer_size as usize)
                .map_err(|e| msg(&e.to_string()))
        }

        fn send(&mut self, msg_type: u8, payload: &[u8]) -> Result<(), SessionError> {
            let signed = crypto::sign_message(&self.identity, msg_type, payload);
            self.transport
                .back_channel_send(signed)
                .map_err(|e| msg(&e.to_string()))
        }

        /// Best-effort zeroize.
        pub fn close(&mut self) {
            self.ephemeral = None;
            self.session_key = None;
            self.chunks.clear();
        }
    }

    // constant-time compare.
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::{overhead_for_max_loss, symbol_size_for_max_wire, BROADCAST_SYMBOL_SIZE};

    #[test]
    fn symbol_size_presets() {
        assert_eq!(symbol_size_for_max_wire(250).unwrap(), 214); // phone
        assert_eq!(
            symbol_size_for_max_wire(1000).unwrap(),
            BROADCAST_SYMBOL_SIZE
        ); // laptop
        assert_eq!(symbol_size_for_max_wire(2000).unwrap(), 1964); // monitor
    }

    #[test]
    fn symbol_size_too_small_errors() {
        assert!(symbol_size_for_max_wire(36).is_err());
        assert!(symbol_size_for_max_wire(0).is_err());
        assert_eq!(symbol_size_for_max_wire(37).unwrap(), 1);
    }

    #[test]
    fn overhead_from_loss() {
        assert_eq!(overhead_for_max_loss(0).unwrap(), 0.0);
        assert_eq!(overhead_for_max_loss(50).unwrap(), 1.0);
        assert_eq!(overhead_for_max_loss(75).unwrap(), 3.0);
    }

    #[test]
    fn overhead_out_of_range_errors() {
        assert!(overhead_for_max_loss(76).is_err());
        assert!(overhead_for_max_loss(100).is_err());
    }
}

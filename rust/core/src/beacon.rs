//! BEACON payload codec. A BEACON travels as a frame (FRAME_NUMBER=0,
//! ENCRYPTED=0, FLAGS bit 5); this module builds and parses the frame payload:
//! VERSION through IDENTITY_SIG.
//!
//! The protocol VERSION byte leads the BEACON body - the only place VERSION
//! rides the wire, so [`parse_payload`] rejects unknown majors. SESSION_ID
//! follows VERSION. IDENTITY_SIG covers MAGIC (big-endian, a virtual prefix that
//! is never transmitted) plus the body.

use crc::{Crc, CRC_16_IBM_3740};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

use crate::crypto::{self, SIG_LEN};
use crate::frame::MAGIC;

pub const LEVEL_OPEN: u8 = 0;
pub const LEVEL_TOFU: u8 = 1;
pub const LEVEL_PAIRED: u8 = 2;
pub const LEVEL_WHITELIST: u8 = 3;
/// Broadcast/PSK, excluded from the level ordering.
pub const LEVEL_PSK: u8 = 4;

/// Open session / no pairing token.
pub const ZERO32: [u8; 32] = [0u8; 32];
/// No reverse-beacon token echoed.
pub const ZERO16: [u8; 16] = [0u8; 16];

/// Cells per side, standard value, no negotiation.
pub const FRAME_CELLS: u8 = 64;
pub const MAX_NAME: usize = 255;

// Fixed-field block, packed `>BQQB32s32s32s32sHHBBQHI`:
// VERSION, SESSION_ID, TIMESTAMP, SESSION_LEVEL, INTENDED_RECEIVER,
// PAIRING_TOKEN_HASH, EPHEMERAL_PUB, IDENTITY_PUB, WIDTH, HEIGHT, MAX_FPS,
// CELL_SIZE, TRANSFER_SIZE, SYMBOL_SIZE, FOUNTAIN_LENGTH.
const FIXED_LEN: usize = 1 + 8 + 8 + 1 + 32 + 32 + 32 + 32 + 2 + 2 + 1 + 1 + 8 + 2 + 4; // = 166

/// RECEIVER_BEACON. MAGIC "RBEA", VERSION 1.
pub const RECEIVER_MAGIC: u32 = 0x5242_4541;
pub const RECEIVER_VERSION: u8 = 1;
// MAGIC 4B + VERSION 1B + IDENTITY 32B + TOKEN 16B + CAPABILITIES 8B + TS 8B.
const RECEIVER_FIXED_LEN: usize = 4 + 1 + 32 + 16 + 8 + 8; // = 69
/// MAGIC..TIMESTAMP (69) + Ed25519 sig (64) + CRC-16 (2) = 135.
pub const RECEIVER_BEACON_LEN: usize = RECEIVER_FIXED_LEN + SIG_LEN + 2;
/// PROVISIONAL: no staleness rule is defined; reuse the BEACON window
/// (±5 minutes).
pub const RECEIVER_WINDOW_MS: u64 = 300_000;

// binascii.crc_hqx(data, 0xFFFF) == CRC-16/IBM-3740.
const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_3740);

/// Malformed BEACON payload or invalid identity signature.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BeaconError {
    #[error("bad SESSION_LEVEL: {0}")]
    BadSessionLevel(u8),
    #[error("bad CELL_SIZE: {0}")]
    BadCellSize(u8),
    #[error("TRANSFER_NAME exceeds 255 bytes")]
    NameTooLong,
    #[error("payload too short")]
    PayloadTooShort,
    #[error("payload length does not match TRANSFER_NAME length")]
    NameLenMismatch,
    #[error("TRANSFER_NAME is not valid UTF-8")]
    NameNotUtf8,
    #[error("unsupported BEACON VERSION: {0}")]
    UnsupportedVersion(u8),
    #[error("invalid IDENTITY_SIG")]
    InvalidSignature,
    #[error("RECEIVER_BEACON wrong length")]
    ReceiverWrongLength,
    #[error("bad RECEIVER_BEACON MAGIC")]
    ReceiverBadMagic,
    #[error("unsupported RECEIVER_BEACON VERSION: {0}")]
    ReceiverUnsupportedVersion(u8),
    #[error("RECEIVER_BEACON CRC-16 mismatch")]
    ReceiverCrcMismatch,
    #[error("invalid RECEIVER_BEACON signature")]
    ReceiverInvalidSignature,
    #[error("RECEIVER_BEACON timestamp outside window")]
    ReceiverStale,
}

/// The BEACON fields.
///
/// The wire body leads with a 1B protocol VERSION, which [`parse_payload`]
/// validates and then discards - it is not a field here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    /// Carried in the BEACON body, not the frame header.
    pub session_id: u64,
    pub timestamp_ms: u64,
    pub session_level: u8,
    /// 32B fingerprint, [`ZERO32`] = open.
    pub intended_receiver: [u8; 32],
    /// 32B, [`ZERO32`] unless level 2.
    pub pairing_token_hash: [u8; 32],
    pub ephemeral_pub: [u8; 32],
    pub identity_pub: [u8; 32],
    pub width: u16,
    pub height: u16,
    pub max_fps: u8,
    pub cell_size: u8,
    pub transfer_size: u64,
    pub transfer_name: String,
    /// 16B echo.
    pub receiver_session_token: [u8; 16],
    /// Standard 64, no negotiation.
    pub frame_cells: u8,
    /// The RaptorQ symbol size (fountain broadcast).
    pub symbol_size: u16,
    /// Length of the COMPRESSED payload fed to the fountain encoder (distinct
    /// from `transfer_size` = original file size).
    pub fountain_length: u32,
}

impl Beacon {
    /// Construct a validated BEACON. The 32/16-byte length checks are enforced
    /// by the field types; the remaining invariants (level whitelist, cell size,
    /// name length) are checked here.
    ///
    /// # Errors
    /// [`BeaconError::BadSessionLevel`], [`BeaconError::BadCellSize`], or
    /// [`BeaconError::NameTooLong`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: u64,
        timestamp_ms: u64,
        session_level: u8,
        intended_receiver: [u8; 32],
        pairing_token_hash: [u8; 32],
        ephemeral_pub: [u8; 32],
        identity_pub: [u8; 32],
        width: u16,
        height: u16,
        max_fps: u8,
        cell_size: u8,
        transfer_size: u64,
        transfer_name: String,
        receiver_session_token: [u8; 16],
        frame_cells: u8,
        symbol_size: u16,
        fountain_length: u32,
    ) -> Result<Self, BeaconError> {
        if !matches!(
            session_level,
            LEVEL_OPEN | LEVEL_TOFU | LEVEL_PAIRED | LEVEL_WHITELIST | LEVEL_PSK
        ) {
            return Err(BeaconError::BadSessionLevel(session_level));
        }
        if cell_size < 1 {
            return Err(BeaconError::BadCellSize(cell_size));
        }
        if transfer_name.len() > MAX_NAME {
            return Err(BeaconError::NameTooLong);
        }
        Ok(Self {
            session_id,
            timestamp_ms,
            session_level,
            intended_receiver,
            pairing_token_hash,
            ephemeral_pub,
            identity_pub,
            width,
            height,
            max_fps,
            cell_size,
            transfer_size,
            transfer_name,
            receiver_session_token,
            frame_cells,
            symbol_size,
            fountain_length,
        })
    }
}

fn body(beacon: &Beacon, version: u8) -> Vec<u8> {
    let name = beacon.transfer_name.as_bytes();
    let mut out = Vec::with_capacity(FIXED_LEN + 1 + name.len() + 16 + 1);
    out.push(version);
    out.extend_from_slice(&beacon.session_id.to_be_bytes());
    out.extend_from_slice(&beacon.timestamp_ms.to_be_bytes());
    out.push(beacon.session_level);
    out.extend_from_slice(&beacon.intended_receiver);
    out.extend_from_slice(&beacon.pairing_token_hash);
    out.extend_from_slice(&beacon.ephemeral_pub);
    out.extend_from_slice(&beacon.identity_pub);
    out.extend_from_slice(&beacon.width.to_be_bytes());
    out.extend_from_slice(&beacon.height.to_be_bytes());
    out.push(beacon.max_fps);
    out.push(beacon.cell_size);
    out.extend_from_slice(&beacon.transfer_size.to_be_bytes());
    out.extend_from_slice(&beacon.symbol_size.to_be_bytes());
    out.extend_from_slice(&beacon.fountain_length.to_be_bytes());
    // Variable tail: name_len, name, RECEIVER_SESSION_TOKEN, FRAME_CELLS.
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    out.extend_from_slice(&beacon.receiver_session_token);
    out.push(beacon.frame_cells);
    out
}

// MAGIC is a virtual signed prefix, never transmitted.
fn signed_prefix(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Build a signed BEACON payload (body ‖ IDENTITY_SIG). Callers pass `version`
/// explicitly.
pub fn build_payload(beacon: &Beacon, identity_priv: &SigningKey, version: u8) -> Vec<u8> {
    let body = body(beacon, version);
    let sig = crypto::sign(identity_priv, &signed_prefix(&body));
    let mut out = body;
    out.extend_from_slice(&sig);
    out
}

/// Parse and verify a BEACON payload against the EMBEDDED IDENTITY_PUB_KEY.
/// VERSION leads the body: its major is checked and then discarded (not a
/// [`Beacon`] field). SESSION_ID follows. IDENTITY_SIG covers MAGIC (a virtual
/// prefix, never transmitted) plus the body.
///
/// # Errors
/// [`BeaconError`] on any malformation, unknown VERSION, or signature failure -
/// callers ignore bad beacons silently.
pub fn parse_payload(payload: &[u8]) -> Result<Beacon, BeaconError> {
    // Minimum: fixed block + name_len(1) + token(16) + frame_cells(1) + sig.
    if payload.len() < FIXED_LEN + 1 + 16 + 1 + SIG_LEN {
        return Err(BeaconError::PayloadTooShort);
    }
    let version = payload[0];
    if version != 1 {
        // only major 1 exists; reject unknown majors.
        return Err(BeaconError::UnsupportedVersion(version));
    }
    let name_len = payload[FIXED_LEN] as usize;
    let name_start = FIXED_LEN + 1;
    let name_end = name_start + name_len;
    let token_end = name_end + 16; // RECEIVER_SESSION_TOKEN between name and FRAME_CELLS.
    let frame_cells_end = token_end + 1; // FRAME_CELLS precedes the signature.
    let sig_start = frame_cells_end;
    if payload.len() != sig_start + SIG_LEN {
        return Err(BeaconError::NameLenMismatch);
    }
    let name = std::str::from_utf8(&payload[name_start..name_end])
        .map_err(|_| BeaconError::NameNotUtf8)?
        .to_string();

    let identity_pub: [u8; 32] = payload[114..146]
        .try_into()
        .expect("32 bytes at IDENTITY_PUB offset");

    let (body_bytes, sig) = payload.split_at(sig_start);
    if !crypto::verify(identity_pub, sig, &signed_prefix(body_bytes)) {
        return Err(BeaconError::InvalidSignature);
    }

    let mut receiver_session_token = [0u8; 16];
    receiver_session_token.copy_from_slice(&payload[name_end..token_end]);

    // Fixed-field offsets (see FIXED_LEN comment); big-endian throughout.
    Beacon::new(
        u64::from_be_bytes(payload[1..9].try_into().unwrap()),
        u64::from_be_bytes(payload[9..17].try_into().unwrap()),
        payload[17], // SESSION_LEVEL
        payload[18..50].try_into().unwrap(),
        payload[50..82].try_into().unwrap(),
        payload[82..114].try_into().unwrap(),
        payload[114..146].try_into().unwrap(),
        u16::from_be_bytes(payload[146..148].try_into().unwrap()),
        u16::from_be_bytes(payload[148..150].try_into().unwrap()),
        payload[150], // MAX_FPS
        payload[151], // CELL_SIZE
        u64::from_be_bytes(payload[152..160].try_into().unwrap()),
        name,
        receiver_session_token,
        payload[token_end], // FRAME_CELLS
        u16::from_be_bytes(payload[160..162].try_into().unwrap()),
        u32::from_be_bytes(payload[162..166].try_into().unwrap()),
    )
}

/// RECEIVER_BEACON fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverBeacon {
    pub identity_pub: [u8; 32],
    pub session_token: [u8; 16],
    /// 8B raw bitmask passthrough - undefined, PROVISIONAL.
    pub capabilities: [u8; 8],
    pub timestamp_ms: u64,
}

fn receiver_signed(
    identity_pub: &[u8; 32],
    token: &[u8; 16],
    capabilities: &[u8; 8],
    timestamp_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECEIVER_FIXED_LEN);
    out.extend_from_slice(&RECEIVER_MAGIC.to_be_bytes());
    out.push(RECEIVER_VERSION);
    out.extend_from_slice(identity_pub);
    out.extend_from_slice(token);
    out.extend_from_slice(capabilities);
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    out
}

/// RECEIVER_BEACON. Returns `(wire_bytes, session_token)` with a fresh 16B
/// CSPRNG token. ED25519_SIG covers MAGIC..TIMESTAMP; CRC-16 covers all
/// preceding fields including the signature. Infallible: the capabilities
/// length is enforced by the `[u8; 8]` type.
pub fn build_receiver_beacon(
    identity_priv: &SigningKey,
    capabilities: &[u8; 8],
    clock: impl Fn() -> f64,
) -> (Vec<u8>, [u8; 16]) {
    let mut token = [0u8; 16];
    OsRng.fill_bytes(&mut token);
    let wire = build_receiver_beacon_with_token(identity_priv, capabilities, &token, clock);
    (wire, token)
}

/// Deterministic variant of [`build_receiver_beacon`] with an injected token,
/// for the conformance vector. Same wire layout.
pub fn build_receiver_beacon_with_token(
    identity_priv: &SigningKey,
    capabilities: &[u8; 8],
    token: &[u8; 16],
    clock: impl Fn() -> f64,
) -> Vec<u8> {
    let identity_pub = crypto::identity_public_bytes(identity_priv);
    let timestamp_ms = (clock() * 1000.0) as u64;
    let signed = receiver_signed(&identity_pub, token, capabilities, timestamp_ms);
    let sig = crypto::sign(identity_priv, &signed);
    let mut body = signed;
    body.extend_from_slice(&sig);
    let crc = CRC16.checksum(&body);
    body.extend_from_slice(&crc.to_be_bytes());
    body
}

/// Parse and verify a RECEIVER_BEACON. Validation order: length, MAGIC,
/// VERSION, CRC-16, signature, timestamp window.
///
/// # Errors
/// [`BeaconError`] on any failure - callers ignore silently.
pub fn parse_receiver_beacon(
    data: &[u8],
    clock: impl Fn() -> f64,
) -> Result<ReceiverBeacon, BeaconError> {
    if data.len() != RECEIVER_BEACON_LEN {
        return Err(BeaconError::ReceiverWrongLength);
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
    if magic != RECEIVER_MAGIC {
        return Err(BeaconError::ReceiverBadMagic);
    }
    let version = data[4];
    if version != RECEIVER_VERSION {
        return Err(BeaconError::ReceiverUnsupportedVersion(version));
    }
    let (body, crc_bytes) = data.split_at(data.len() - 2);
    let stored_crc = u16::from_be_bytes(crc_bytes.try_into().unwrap());
    if stored_crc != CRC16.checksum(body) {
        return Err(BeaconError::ReceiverCrcMismatch);
    }
    let identity_pub: [u8; 32] = data[5..37].try_into().unwrap();
    let signed = &data[..RECEIVER_FIXED_LEN];
    let sig = &data[RECEIVER_FIXED_LEN..RECEIVER_FIXED_LEN + SIG_LEN];
    if !crypto::verify(identity_pub, sig, signed) {
        return Err(BeaconError::ReceiverInvalidSignature);
    }
    let mut session_token = [0u8; 16];
    session_token.copy_from_slice(&data[37..53]);
    let capabilities: [u8; 8] = data[53..61].try_into().unwrap();
    let timestamp_ms = u64::from_be_bytes(data[61..69].try_into().unwrap());
    let now = (clock() * 1000.0) as u64;
    if now.abs_diff(timestamp_ms) >= RECEIVER_WINDOW_MS {
        return Err(BeaconError::ReceiverStale);
    }
    Ok(ReceiverBeacon {
        identity_pub,
        session_token,
        capabilities,
        timestamp_ms,
    })
}

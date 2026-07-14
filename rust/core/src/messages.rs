//! back-channel message payloads.
//!
//! The wire envelope is [`crate::crypto::sign_message`] /
//! [`crate::crypto::open_message`] (`[MESSAGE_TYPE 1B][PAYLOAD][SIG 64B]`).
//! The type IDs and the HANDSHAKE_ACK/NAK encodings are PROVISIONAL.

use thiserror::Error;

pub const HANDSHAKE_ACK: u8 = 0x01;
pub const NAK: u8 = 0x02;
/// Empty payload.
pub const SLOW_DOWN: u8 = 0x03;
/// Empty payload.
pub const SPEED_UP: u8 = 0x04;
pub const SESSION_COMPLETE: u8 = 0x05;
pub const ALIGNMENT: u8 = 0x06;
pub const DEGRADED: u8 = 0x07;
pub const PAUSE: u8 = 0x08;
pub const RESUME: u8 = 0x09;
pub const RESUMED: u8 = 0x0A;
pub const SESSION_TIMEOUT: u8 = 0x0B;

/// HANDSHAKE_ACK payload size: `">32s32sBHHB"` = 32 + 32 + 1 + 2 + 2 + 1.
const ACK_LEN: usize = 32 + 32 + 1 + 2 + 2 + 1;

/// Payload does not match its message type's layout.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MessageError {
    #[error("{name} must be {expected} bytes")]
    WrongSize { name: &'static str, expected: usize },
    #[error("NAK must be f32 CQS + n*u64 frame numbers")]
    BadNak,
}

fn check(payload: &[u8], size: usize, name: &'static str) -> Result<(), MessageError> {
    if payload.len() != size {
        return Err(MessageError::WrongSize {
            name,
            expected: size,
        });
    }
    Ok(())
}

/// Receiver ephemeral + identity keys and agreed parameters.
/// Layout `">32s32sBHHB"`: EPHEMERAL, IDENTITY, FPS, WIDTH, HEIGHT, CELL_SIZE.
pub fn pack_handshake_ack(
    ephemeral_pub: &[u8; 32],
    identity_pub: &[u8; 32],
    fps: u8,
    width: u16,
    height: u16,
    cell_size: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ACK_LEN);
    out.extend_from_slice(ephemeral_pub);
    out.extend_from_slice(identity_pub);
    out.push(fps);
    out.extend_from_slice(&width.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.push(cell_size);
    out
}

pub struct HandshakeAck {
    pub ephemeral_pub: [u8; 32],
    pub identity_pub: [u8; 32],
    pub fps: u8,
    pub width: u16,
    pub height: u16,
    pub cell_size: u8,
}

/// # Errors
/// [`MessageError::WrongSize`] if `payload` is not [`ACK_LEN`] bytes.
pub fn parse_handshake_ack(payload: &[u8]) -> Result<HandshakeAck, MessageError> {
    check(payload, ACK_LEN, "HANDSHAKE_ACK")?;
    let mut ephemeral_pub = [0u8; 32];
    let mut identity_pub = [0u8; 32];
    ephemeral_pub.copy_from_slice(&payload[0..32]);
    identity_pub.copy_from_slice(&payload[32..64]);
    Ok(HandshakeAck {
        ephemeral_pub,
        identity_pub,
        fps: payload[64],
        width: u16::from_be_bytes([payload[65], payload[66]]),
        height: u16::from_be_bytes([payload[67], payload[68]]),
        cell_size: payload[69],
    })
}

/// Missing frame numbers; CQS rides in every NAK. Layout: f32 CQS (BE) followed
/// by `n` × u64 frame numbers (BE).
pub fn pack_nak(cqs: f32, missing: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + missing.len() * 8);
    out.extend_from_slice(&cqs.to_be_bytes());
    for n in missing {
        out.extend_from_slice(&n.to_be_bytes());
    }
    out
}

/// # Errors
/// [`MessageError::BadNak`] unless `payload` is 4 + a multiple of 8 bytes.
pub fn parse_nak(payload: &[u8]) -> Result<(f32, Vec<u64>), MessageError> {
    if payload.len() < 4 || !(payload.len() - 4).is_multiple_of(8) {
        return Err(MessageError::BadNak);
    }
    let cqs = f32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let missing = payload[4..]
        .chunks_exact(8)
        .map(|c| u64::from_be_bytes(c.try_into().expect("chunks_exact(8) yields 8 bytes")))
        .collect();
    Ok((cqs, missing))
}

pub fn pack_session_complete(session_id: u64) -> Vec<u8> {
    session_id.to_be_bytes().to_vec()
}

/// # Errors
/// [`MessageError::WrongSize`] if `payload` is not 8 bytes.
pub fn parse_session_complete(payload: &[u8]) -> Result<u64, MessageError> {
    check(payload, 8, "SESSION_COMPLETE")?;
    Ok(u64::from_be_bytes(payload.try_into().expect("checked 8")))
}

/// Layout `">fQ"`: AQS (f32 BE), FRAME_NUMBER (u64 BE).
pub fn pack_alignment(aqs: f32, frame_num: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&aqs.to_be_bytes());
    out.extend_from_slice(&frame_num.to_be_bytes());
    out
}

/// # Errors
/// [`MessageError::WrongSize`] if `payload` is not 12 bytes.
pub fn parse_alignment(payload: &[u8]) -> Result<(f32, u64), MessageError> {
    check(payload, 12, "ALIGNMENT")?;
    let aqs = f32::from_be_bytes(payload[0..4].try_into().expect("checked 12"));
    let frame_num = u64::from_be_bytes(payload[4..12].try_into().expect("checked 12"));
    Ok((aqs, frame_num))
}

pub fn pack_degraded(aqs: f32) -> Vec<u8> {
    aqs.to_be_bytes().to_vec()
}

/// # Errors
/// [`MessageError::WrongSize`] if `payload` is not 4 bytes.
pub fn parse_degraded(payload: &[u8]) -> Result<f32, MessageError> {
    check(payload, 4, "DEGRADED")?;
    Ok(f32::from_be_bytes(payload.try_into().expect("checked 4")))
}

pub fn pack_pause(last_decoded: u64) -> Vec<u8> {
    last_decoded.to_be_bytes().to_vec()
}

/// # Errors
/// [`MessageError::WrongSize`] if `payload` is not 8 bytes.
pub fn parse_pause(payload: &[u8]) -> Result<u64, MessageError> {
    check(payload, 8, "PAUSE")?;
    Ok(u64::from_be_bytes(payload.try_into().expect("checked 8")))
}

/// Layout `">Qf"`: RESUME_FROM (u64 BE), AQS (f32 BE).
pub fn pack_resume(resume_from: u64, aqs: f32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&resume_from.to_be_bytes());
    out.extend_from_slice(&aqs.to_be_bytes());
    out
}

/// # Errors
/// [`MessageError::WrongSize`] if `payload` is not 12 bytes.
pub fn parse_resume(payload: &[u8]) -> Result<(u64, f32), MessageError> {
    check(payload, 12, "RESUME")?;
    let resume_from = u64::from_be_bytes(payload[0..8].try_into().expect("checked 12"));
    let aqs = f32::from_be_bytes(payload[8..12].try_into().expect("checked 12"));
    Ok((resume_from, aqs))
}

pub fn pack_resumed(frame_num: u64) -> Vec<u8> {
    frame_num.to_be_bytes().to_vec()
}

/// # Errors
/// [`MessageError::WrongSize`] if `payload` is not 8 bytes.
pub fn parse_resumed(payload: &[u8]) -> Result<u64, MessageError> {
    check(payload, 8, "RESUMED")?;
    Ok(u64::from_be_bytes(payload.try_into().expect("checked 8")))
}

pub fn pack_session_timeout(session_id: u64) -> Vec<u8> {
    session_id.to_be_bytes().to_vec()
}

/// # Errors
/// [`MessageError::WrongSize`] if `payload` is not 8 bytes.
pub fn parse_session_timeout(payload: &[u8]) -> Result<u64, MessageError> {
    check(payload, 8, "SESSION_TIMEOUT")?;
    Ok(u64::from_be_bytes(payload.try_into().expect("checked 8")))
}

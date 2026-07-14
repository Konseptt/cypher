//! frame format: compact 8-byte header, FLAGS, build/parse.

use crc::{Crc, CRC_16_IBM_3740};
use thiserror::Error;

/// "SEMP" - not in the compact header; kept for other importers only.
pub const MAGIC: u32 = 0x5345_4D50;
/// Not in the compact header; session state.
pub const VERSION: u8 = 1;

/// Header bits 0–3, constant sanity value.
pub const TAG: u8 = 0x5;

pub const ENCRYPTED: u8 = 1 << 0;
pub const COMPRESSED: u8 = 1 << 1;
pub const KEYFRAME: u8 = 1 << 2;
pub const LAST_FRAME: u8 = 1 << 3;
pub const PRIORITY: u8 = 1 << 4;
/// Payload is a BEACON.
pub const BEACON: u8 = 1 << 5;
/// Payload is a RECEIVER_BEACON.
pub const RECEIVER_BEACON: u8 = 1 << 6;
// bit 7 reserved.

const VALID_FLAGS: u8 =
    ENCRYPTED | COMPRESSED | KEYFRAME | LAST_FRAME | PRIORITY | BEACON | RECEIVER_BEACON;

pub const HEADER_LEN: usize = 8;
pub const MAX_FRAME_NUMBER: u32 = (1 << 20) - 1;
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

// Per-frame wire budget = bytes carried per frame (one QR code, host side).
// Bigger = fewer frames (higher throughput) but a denser QR = fewer camera
// pixels per module. This is the throughput/robustness KNOB.
// ECC-M QR-v40 tops out ~2300 B. Raise toward ~2000 for a good camera, lower
// for a weak webcam. BROADCAST_SYMBOL_SIZE derives from this.
pub const MAX_WIRE: usize = 1000;

/// Bytes of frame payload that fit one frame, given the frame header overhead.
pub fn max_payload(header_len: usize) -> usize {
    MAX_WIRE - header_len
}

/// binascii.crc_hqx(data, 0xFFFF) == CRC-16/IBM-3740.
const CRC16: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_3740);

/// Frame violates the wire format.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("FRAME_NUMBER out of 20-bit range: {0}")]
    FrameNumberRange(u32),
    #[error("reserved FLAGS bits set: {0:#04x}")]
    ReservedFlags(u8),
    #[error("payload exceeds PAYLOAD_LENGTH field range")]
    PayloadTooLarge,
    #[error("frame shorter than header: {0} bytes")]
    ShorterThanHeader(usize),
    #[error("bad TAG: {0:#x}")]
    BadTag(u8),
    #[error("PAYLOAD_LENGTH exceeds frame size")]
    PayloadLengthOverrun,
    #[error("CRC-16 mismatch")]
    CrcMismatch,
}

/// First 6 header bytes: TAG+FRAME_NUMBER (3B), FLAGS (1B), PAYLOAD_LENGTH (2B)
/// - the header WITHOUT the trailing CRC-16. This 6-byte prefix is the
/// AES-256-GCM AAD: the CRC cannot be part of the AAD because it depends on the
/// ciphertext, which is not known when the AAD is fixed.
///
/// # Errors
/// [`FrameError::FrameNumberRange`] if `frame_number` exceeds 20 bits.
///
/// ```
/// use cypher_core::frame::header_prefix;
/// assert_eq!(header_prefix(42, 3, 20).unwrap(), [0x50, 0x00, 0x2a, 0x03, 0x00, 0x14]);
/// ```
pub fn header_prefix(
    frame_number: u32,
    flags: u8,
    payload_len: u16,
) -> Result<[u8; 6], FrameError> {
    if frame_number > MAX_FRAME_NUMBER {
        return Err(FrameError::FrameNumberRange(frame_number));
    }
    let tag_num = ((TAG as u32) << 20) | frame_number;
    let tag_bytes = tag_num.to_be_bytes(); // [0, hi, mid, lo]
    let len_bytes = payload_len.to_be_bytes();
    Ok([
        tag_bytes[1],
        tag_bytes[2],
        tag_bytes[3],
        flags,
        len_bytes[0],
        len_bytes[1],
    ])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub frame_number: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Construct a validated frame.
    ///
    /// # Errors
    /// [`FrameError::FrameNumberRange`], [`FrameError::ReservedFlags`], or
    /// [`FrameError::PayloadTooLarge`] on out-of-range fields.
    pub fn new(frame_number: u32, flags: u8, payload: Vec<u8>) -> Result<Self, FrameError> {
        if frame_number > MAX_FRAME_NUMBER {
            return Err(FrameError::FrameNumberRange(frame_number));
        }
        if flags & !VALID_FLAGS != 0 {
            return Err(FrameError::ReservedFlags(flags));
        }
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(FrameError::PayloadTooLarge);
        }
        Ok(Self {
            frame_number,
            flags,
            payload,
        })
    }

    /// The full 8-byte header: 6-byte prefix + CRC-16 over prefix+payload.
    pub fn header(&self) -> [u8; HEADER_LEN] {
        let prefix = header_prefix(self.frame_number, self.flags, self.payload.len() as u16)
            .expect("frame fields validated at construction");
        let mut digest = CRC16.digest();
        digest.update(&prefix);
        digest.update(&self.payload);
        let crc = digest.finalize().to_be_bytes();
        let mut header = [0u8; HEADER_LEN];
        header[..6].copy_from_slice(&prefix);
        header[6..].copy_from_slice(&crc);
        header
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.header().to_vec();
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a frame, validating TAG, PAYLOAD_LENGTH vs frame size, and CRC.
    ///
    /// # Errors
    /// See [`FrameError`] variants for the individual validation failures.
    pub fn decode(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() < HEADER_LEN {
            return Err(FrameError::ShorterThanHeader(data.len()));
        }
        let tag_num = u32::from_be_bytes([0, data[0], data[1], data[2]]);
        let tag = (tag_num >> 20) as u8;
        if tag != TAG {
            return Err(FrameError::BadTag(tag));
        }
        let frame_number = tag_num & MAX_FRAME_NUMBER;
        let flags = data[3];
        let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        if data.len() < HEADER_LEN + payload_len {
            return Err(FrameError::PayloadLengthOverrun);
        }
        let payload = &data[HEADER_LEN..HEADER_LEN + payload_len];
        let stored_crc = u16::from_be_bytes([data[6], data[7]]);
        let mut digest = CRC16.digest();
        digest.update(&data[0..6]);
        digest.update(payload);
        if stored_crc != digest.finalize() {
            return Err(FrameError::CrcMismatch);
        }
        Self::new(frame_number, flags, payload.to_vec())
    }
}

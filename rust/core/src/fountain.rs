//! Rateless erasure (fountain) coding for reliable one-way broadcast. Thin
//! wrapper over the `raptorq` crate (RFC 6330): `Encoder::with_defaults` +
//! `get_encoded_packets`, each `EncodingPacket` serialized on the wire.
//!
//! Pipeline order: compress -> fountain-encode -> (per-symbol) encrypt -> QR.

use raptorq::{Decoder as RaptorDecoder, Encoder, EncodingPacket, ObjectTransmissionInformation};
use thiserror::Error;

/// Default extra packets beyond the source, as a fraction of source symbols.
/// ~40% repair lets a receiver finish within roughly one video loop at up to
/// ~28% frame loss.
pub const DEFAULT_OVERHEAD: f64 = 0.4;

#[derive(Debug, Error)]
pub enum FountainError {
    /// Bad encoder params: a zero symbol size.
    #[error("symbol_size must be positive")]
    BadSymbolSize,
    /// Bad decoder params: values that would make raptorq panic (0 / out of range).
    #[error("bad fountain params: transfer_length={transfer_length} symbol_size={symbol_size}")]
    BadParams {
        transfer_length: u64,
        symbol_size: u16,
    },
}

/// Payload bytes -> a list of fountain packets (each ~`symbol_size`+4 bytes,
/// self-identifying). Loop this list on the wire; the receiver reconstructs from
/// any K+ε of them.
///
/// Repair count: `k = max(1, len//symbol_size)`,
/// `repair = max(1, int(k*overhead))` (`int()` truncates toward zero, i.e.
/// floor for the non-negative values here), then `get_encoded_packets(repair)`.
pub fn encode(data: &[u8], symbol_size: u16, overhead: f64) -> Result<Vec<Vec<u8>>, FountainError> {
    if symbol_size == 0 {
        return Err(FountainError::BadSymbolSize);
    }
    let k = std::cmp::max(1, data.len() / symbol_size as usize);
    let repair = std::cmp::max(1, (k as f64 * overhead) as u32);
    let packets = Encoder::with_defaults(data, symbol_size)
        .get_encoded_packets(repair)
        .iter()
        .map(EncodingPacket::serialize)
        .collect();
    Ok(packets)
}

/// Collect fountain packets (in any order, with duplicates) until the payload
/// reconstructs. `transfer_length` and `symbol_size` come from the BEACON.
pub struct Decoder {
    inner: RaptorDecoder,
    result: Option<Vec<u8>>,
}

impl Decoder {
    /// Params come from the BEACON. Reject the values that would make raptorq
    /// panic (0 / out of range) so a corrupt-but-accepted or buggy-sender beacon
    /// degrades to a clean error, never a crash. Guards
    /// `0 < symbol_size <= 65535` and `transfer_length > 0`.
    pub fn new(transfer_length: u64, symbol_size: u16) -> Result<Self, FountainError> {
        if symbol_size == 0 || transfer_length == 0 {
            return Err(FountainError::BadParams {
                transfer_length,
                symbol_size,
            });
        }
        let config = ObjectTransmissionInformation::with_defaults(transfer_length, symbol_size);
        Ok(Self {
            inner: RaptorDecoder::new(config),
            result: None,
        })
    }

    /// Feed one packet. Returns the full payload once enough have arrived (and on
    /// every call thereafter), else `None`.
    ///
    /// A malformed packet is treated as a lost packet (skipped), never a crash.
    /// `EncodingPacket::deserialize` indexes `data[0..4]` and slices `data[4..]`,
    /// so it panics on inputs shorter than 4 bytes - guard the length here.
    /// Duplicates and late packets are safe.
    ///
    /// Caller MUST authenticate packets first: raptorq trusts its input. The
    /// protocol feeds only AES-GCM-verified packets here.
    pub fn add(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        if self.result.is_none() {
            if packet.len() < 4 {
                return None; // fountain tolerates losses
            }
            // raptorq panics on malformed packets at BOTH boundaries: deserialize
            // (guarded above) and decode - the latter indexes an ESI-sized array,
            // so an out-of-range ESI is an "index out of bounds" panic. Catch the
            // panic, treat the packet as lost, keep the same decoder.
            //
            // AssertUnwindSafe: `&mut self.inner` is not UnwindSafe, but this is all
            // safe Rust (no unsafe invariants to break). A caught panic drops one
            // packet before it mutates shared state; at worst the decoder holds an
            // extra recorded ESI, which is tolerated - a later valid packet still
            // completes. The same decoder is reused.
            let inner = &mut self.inner;
            let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                inner.decode(EncodingPacket::deserialize(packet))
            }));
            // NOTE: the panic runtime prints a Rust panic line to stderr before we
            // catch it (cosmetic - a junk-frame flood spams stderr). Do NOT install
            // a global panic hook from a library to silence it.
            self.result = decoded.unwrap_or(None); // Err(panic) => lost packet
        }
        self.result.clone()
    }

    pub fn done(&self) -> bool {
        self.result.is_some()
    }
}

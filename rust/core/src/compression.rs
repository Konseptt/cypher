//! zstd compression stage.
//! Always compress BEFORE encrypt; the COMPRESSED flag records whether this
//! stage ran.
//!
//! `compress` (the encoder) needs the C `zstd` library and is only built with
//! the `compression` feature. `decompress` is ALWAYS available: with the
//! feature it uses `zstd`, without it (the wasm build) it uses the pure-Rust
//! `ruzstd` decoder. Both decode paths enforce the same three guards.

#[cfg(feature = "compression")]
use std::io::Read;

use thiserror::Error;

pub const LEVEL_SPEED: i32 = 3;
pub const LEVEL_RATIO: i32 = 9;

#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("declared content size {declared} exceeds limit {limit}")]
    DeclaredTooLarge { declared: u64, limit: usize },
    #[error("output {actual} B exceeds limit {limit}")]
    OutputTooLarge { actual: usize, limit: usize },
    #[error("trailing bytes after first zstd frame")]
    TrailingBytes,
    #[error("zstd error: {0}")]
    Zstd(String),
}

/// Compress `data` into a single zstd frame at the given level.
///
/// # Errors
/// [`CompressionError::Zstd`] if the underlying zstd encoder fails.
#[cfg(feature = "compression")]
pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>, CompressionError> {
    // Bulk (one-shot) compression pledges the source size, embedding the content
    // size in the frame header - which `decompress` relies on for the
    // declared-size guard.
    zstd::bulk::compress(data, level).map_err(|e| CompressionError::Zstd(e.to_string()))
}

/// Decompress a single-frame zstd transfer.
///
/// `max_output_size = 0` means unbounded. The pipeline must bound it (e.g. from
/// BEACON TRANSFER_SIZE) when decompressing peer data as a decompression-bomb
/// guard. When a bound is set, the frame's declared content size (when present)
/// is checked first, then the actual output length.
///
/// A compressed transfer is exactly ONE zstd frame; trailing bytes after the
/// first frame are rejected loudly - zstd libraries otherwise silently ignore
/// them, truncating data.
///
/// # Errors
/// [`CompressionError::DeclaredTooLarge`], [`CompressionError::OutputTooLarge`],
/// [`CompressionError::TrailingBytes`], or [`CompressionError::Zstd`].
#[cfg(feature = "compression")]
pub fn decompress(data: &[u8], max_output_size: usize) -> Result<Vec<u8>, CompressionError> {
    if max_output_size != 0 {
        // `Ok(None)` is CONTENTSIZE_UNKNOWN, `Err` is a malformed frame prefix.
        let declared = zstd::zstd_safe::get_frame_content_size(data)
            .map_err(|e| CompressionError::Zstd(e.to_string()))?;
        if let Some(declared) = declared {
            if declared > max_output_size as u64 {
                return Err(CompressionError::DeclaredTooLarge {
                    declared,
                    limit: max_output_size,
                });
            }
        }
    }
    // The first frame's exact compressed byte length; anything after it means
    // trailing frames/bytes, which are rejected.
    let frame_len = zstd::zstd_safe::find_frame_compressed_size(data).map_err(|code| {
        CompressionError::Zstd(zstd::zstd_safe::get_error_name(code).to_string())
    })?;
    if frame_len < data.len() {
        return Err(CompressionError::TrailingBytes);
    }
    let mut out = Vec::new();
    zstd::stream::read::Decoder::new(&data[..frame_len])
        .map_err(|e| CompressionError::Zstd(e.to_string()))?
        .read_to_end(&mut out)
        .map_err(|e| CompressionError::Zstd(e.to_string()))?;
    if max_output_size != 0 && out.len() > max_output_size {
        return Err(CompressionError::OutputTooLarge {
            actual: out.len(),
            limit: max_output_size,
        });
    }
    Ok(out)
}

/// Decompress a single-frame zstd transfer using the pure-Rust `ruzstd`
/// decoder (the wasm build, `compression` feature off). Enforces the same three
/// guards as the `zstd` path.
///
/// # Errors
/// [`CompressionError::DeclaredTooLarge`], [`CompressionError::OutputTooLarge`],
/// [`CompressionError::TrailingBytes`], or [`CompressionError::Zstd`].
#[cfg(not(feature = "compression"))]
pub fn decompress(data: &[u8], max_output_size: usize) -> Result<Vec<u8>, CompressionError> {
    use std::io::{Cursor, Read};

    use ruzstd::decoding::StreamingDecoder;

    // `new` reads (and parses) the frame header but decodes no blocks yet, so the
    // declared content size is available before any data is produced.
    let mut cursor = Cursor::new(data);
    let mut decoder = StreamingDecoder::new(&mut cursor)
        .map_err(|e| CompressionError::Zstd(format!("decoder init: {e}")))?;

    // Guard (a): declared content size from the frame header. `content_size` is 0
    // when the size flag is absent (CONTENTSIZE_UNKNOWN); `zstd::bulk` always
    // sets it, so a real transfer is checked here.
    if max_output_size != 0 {
        let declared = decoder.decoder.content_size();
        if declared != 0 && declared > max_output_size as u64 {
            return Err(CompressionError::DeclaredTooLarge {
                declared,
                limit: max_output_size,
            });
        }
    }

    // Decode exactly ONE frame. The FrameDecoder reads only the one frame's bytes
    // (header, blocks, optional content checksum) and stops, so the cursor
    // position after read == the frame's length.
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| CompressionError::Zstd(e.to_string()))?;
    drop(decoder); // release the &mut borrow of `cursor`

    // Guard (b): trailing bytes. If the cursor did not reach the end of `data`,
    // bytes remain after the first frame - reject rather than silently drop.
    if (cursor.position() as usize) < data.len() {
        return Err(CompressionError::TrailingBytes);
    }

    // Guard (c): actual output size.
    if max_output_size != 0 && out.len() > max_output_size {
        return Err(CompressionError::OutputTooLarge {
            actual: out.len(),
            limit: max_output_size,
        });
    }
    Ok(out)
}

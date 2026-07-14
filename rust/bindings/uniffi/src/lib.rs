//! UniFFI binding over cypher-core broadcast mode. Same shape as the wasm
//! SDK (bindings/wasm/src/lib.rs): a `Sender` that renders wire frames and a
//! `Receiver` that accumulates them into the original file. Mobile hosts loop
//! the frames as QR codes and feed captured frames back in.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use cypher_core::crypto::{generate_identity, key_from_phrase};
use cypher_core::fountain::DEFAULT_OVERHEAD;
use cypher_core::session::{
    overhead_for_max_loss, symbol_size_for_max_wire, BroadcastReceiver, BroadcastSender,
    BROADCAST_SYMBOL_SIZE,
};
use cypher_core::transport::{LoopbackTransport, DEFAULT_CAPS};

uniffi::setup_scaffolding!();

/// The well-known phrase for unauthenticated public broadcast.
const PUBLIC_PHRASE: &str = "cypher-public-broadcast";

/// A fresh random code phrase drawn from the protocol wordlist. Mirrors the
/// wasm SDK's `generate_phrase()` so mobile/desktop hosts can offer the same
/// "generate a phrase for me" affordance as the browser.
#[uniffi::export]
pub fn generate_phrase() -> String {
    cypher_core::phrase::generate(cypher_core::phrase::DEFAULT_WORDS)
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("crypto error: {msg}")]
    Crypto { msg: String },
    #[error("session error: {msg}")]
    Session { msg: String },
    #[error("pinned key changed: {msg}")]
    KeyChanged { msg: String },
    #[error("internal error: {msg}")]
    Internal { msg: String },
}

/// Real wall-clock in seconds - mobile has a live clock, so BEACON
/// timestamp-window validation passes with live keys.
fn clock() -> Box<dyn FnMut() -> f64 + Send> {
    Box::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after 1970")
            .as_secs_f64()
    })
}

fn derive_psk(phrase: &str, is_public: bool) -> Result<[u8; 32], FfiError> {
    let source = if is_public { PUBLIC_PHRASE } else { phrase };
    let key = key_from_phrase(source).map_err(|e| FfiError::Crypto { msg: e.to_string() })?;
    Ok(*key.as_bytes())
}

#[derive(uniffi::Object)]
pub struct Sender {
    psk: [u8; 32],
}

#[uniffi::export]
impl Sender {
    #[uniffi::constructor]
    pub fn new(phrase: String, is_public: bool) -> Result<Arc<Self>, FfiError> {
        Ok(Arc::new(Sender {
            psk: derive_psk(&phrase, is_public)?,
        }))
    }

    /// Render `file` (named `name`) to the wire frames the host loops as QR
    /// codes. Random session_id (OsRng).
    ///
    /// `max_wire` = QR density (per-frame wire budget); `max_loss` = tolerable
    /// frame-loss percent; `level` = zstd compression level. `None` for any of
    /// them keeps today's broadcast defaults.
    #[uniffi::method(default(max_wire = None, max_loss = None, level = None))]
    pub fn frames(
        &self,
        file: Vec<u8>,
        name: String,
        max_wire: Option<u32>,
        max_loss: Option<u32>,
        level: Option<i32>,
    ) -> Result<Vec<Vec<u8>>, FfiError> {
        let symbol_size = match max_wire {
            None => BROADCAST_SYMBOL_SIZE,
            Some(mw) => symbol_size_for_max_wire(mw as usize)
                .map_err(|e| FfiError::Session { msg: e.to_string() })?,
        };
        let overhead = match max_loss {
            None => DEFAULT_OVERHEAD,
            Some(loss) => {
                overhead_for_max_loss(loss).map_err(|e| FfiError::Session { msg: e.to_string() })?
            }
        };
        let mut t = LoopbackTransport::new(DEFAULT_CAPS);
        let screen = t.screen_arc();
        {
            let mut sender = BroadcastSender::new(
                &mut t,
                generate_identity(),
                self.psk,
                symbol_size,
                overhead,
                clock(),
            );
            sender
                .send_data(&file, &name, level.unwrap_or(0))
                .map_err(|e| FfiError::Session { msg: e.to_string() })?;
        }
        let frames = screen
            .lock()
            .map_err(|_| FfiError::Internal {
                msg: "loopback lock poisoned".to_string(),
            })?
            .drain(..)
            .collect();
        Ok(frames)
    }
}

// The `Send` clock makes BroadcastReceiver Send; the Mutex makes it Sync for
// UniFFI.
#[derive(uniffi::Object)]
pub struct Receiver {
    inner: Mutex<BroadcastReceiver<'static>>,
}

#[uniffi::export]
impl Receiver {
    #[uniffi::constructor]
    pub fn new(phrase: String, is_public: bool) -> Result<Arc<Self>, FfiError> {
        let psk = derive_psk(&phrase, is_public)?;
        let inner = BroadcastReceiver::new(psk, None, "ffi-peer", true, None, clock());
        Ok(Arc::new(Receiver {
            inner: Mutex::new(inner),
        }))
    }

    pub fn push_frame(&self, wire: Vec<u8>) -> Result<String, FfiError> {
        self.inner
            .lock()
            .map_err(|_| FfiError::Internal {
                msg: "receiver lock poisoned".to_string(),
            })?
            .on_codes(vec![wire])
            .map_err(|e| FfiError::KeyChanged { msg: e.to_string() })
    }

    pub fn is_complete(&self) -> bool {
        self.inner.lock().map(|r| r.complete).unwrap_or(false)
    }

    pub fn data(&self) -> Result<Vec<u8>, FfiError> {
        self.inner
            .lock()
            .map_err(|_| FfiError::Internal {
                msg: "receiver lock poisoned".to_string(),
            })?
            .data()
            .map_err(|e| FfiError::Session { msg: e.to_string() })
    }

    pub fn name(&self) -> String {
        self.inner
            .lock()
            .map(|r| r.transfer_name.clone())
            .unwrap_or_default()
    }
}

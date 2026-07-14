//! wasm-bindgen SDK over cypher-core broadcast mode. The host loops the
//! returned wire frames as QR codes and feeds captured frames back in.

use js_sys::Uint8Array;
use cypher_core::crypto::{generate_identity, key_from_phrase};
use cypher_core::fountain::DEFAULT_OVERHEAD;
use cypher_core::session::{
    overhead_for_max_loss, symbol_size_for_max_wire, BroadcastReceiver, BroadcastSender,
    BROADCAST_SYMBOL_SIZE,
};
use cypher_core::transport::{LoopbackTransport, DEFAULT_CAPS};
use wasm_bindgen::prelude::*;

/// The well-known phrase for unauthenticated public broadcast.
const PUBLIC_PHRASE: &str = "cypher-public-broadcast";

/// Real wall-clock in seconds - works in node and the browser, so BEACON
/// timestamp-window validation passes with live keys.
fn clock() -> Box<dyn FnMut() -> f64 + Send> {
    Box::new(|| js_sys::Date::now() / 1000.0)
}

fn derive_psk(phrase: &str, is_public: bool) -> Result<[u8; 32], JsError> {
    let source = if is_public { PUBLIC_PHRASE } else { phrase };
    let key = key_from_phrase(source).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(*key.as_bytes())
}

/// A fresh random code phrase drawn from the protocol wordlist.
#[wasm_bindgen]
pub fn generate_phrase() -> String {
    cypher_core::phrase::generate(cypher_core::phrase::DEFAULT_WORDS)
}

#[wasm_bindgen]
pub struct Sender {
    psk: [u8; 32],
}

#[wasm_bindgen]
impl Sender {
    #[wasm_bindgen(constructor)]
    pub fn new(phrase: String, is_public: bool) -> Result<Sender, JsError> {
        Ok(Sender {
            psk: derive_psk(&phrase, is_public)?,
        })
    }

    /// Render `file` (named `name`) to the wire frames the host loops as QR
    /// codes. Random session_id (OsRng via getrandom's js backend).
    ///
    /// `max_wire` = QR density (per-frame wire budget); `max_loss` = tolerable
    /// frame-loss percent. `None` for either keeps today's broadcast defaults.
    pub fn frames(
        &self,
        file: &[u8],
        name: String,
        max_wire: Option<u32>,
        max_loss: Option<u32>,
    ) -> Result<Vec<Uint8Array>, JsError> {
        let symbol_size = match max_wire {
            None => BROADCAST_SYMBOL_SIZE,
            Some(mw) => {
                symbol_size_for_max_wire(mw as usize).map_err(|e| JsError::new(&e.to_string()))?
            }
        };
        let overhead = match max_loss {
            None => DEFAULT_OVERHEAD,
            Some(loss) => overhead_for_max_loss(loss).map_err(|e| JsError::new(&e.to_string()))?,
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
                .send_data(file, &name, 0)
                .map_err(|e| JsError::new(&e.to_string()))?;
        }
        let frames: Vec<Vec<u8>> = screen
            .lock()
            .map_err(|_| JsError::new("loopback lock poisoned"))?
            .drain(..)
            .collect();
        Ok(frames.iter().map(|f| Uint8Array::from(&f[..])).collect())
    }
}

#[wasm_bindgen]
pub struct Receiver {
    inner: BroadcastReceiver<'static>,
}

#[wasm_bindgen]
impl Receiver {
    #[wasm_bindgen(constructor)]
    pub fn new(phrase: String, is_public: bool) -> Result<Receiver, JsError> {
        let psk = derive_psk(&phrase, is_public)?;
        let inner = BroadcastReceiver::new(psk, None, "wasm-peer", true, None, clock());
        Ok(Receiver { inner })
    }

    pub fn push_frame(&mut self, wire: &[u8]) -> Result<String, JsError> {
        self.inner
            .on_codes(vec![wire.to_vec()])
            .map_err(|e| JsError::new(&e.to_string()))
    }

    pub fn is_complete(&self) -> bool {
        self.inner.complete
    }

    pub fn data(&self) -> Result<Vec<u8>, JsError> {
        self.inner.data().map_err(|e| JsError::new(&e.to_string()))
    }

    pub fn name(&self) -> String {
        self.inner.transfer_name.clone()
    }
}

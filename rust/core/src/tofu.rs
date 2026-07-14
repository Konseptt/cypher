//! TOFU trust store. File-backed JSON `{peer: hex32}`; platform keychain /
//! secure-enclave storage is a deployment concern - tests mock at the file
//! boundary.

use std::collections::BTreeMap;
use std::fmt;
#[cfg(feature = "fs")]
use std::fs;
#[cfg(feature = "fs")]
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Stored identity key does not match - hard fail, require explicit
/// re-approval (the SSH host-key-changed model).
#[derive(Debug, Error)]
#[error("identity key for {peer:?} has changed")]
pub struct KeyChangedError {
    pub peer: String,
}

/// Result of comparing a presented identity key against the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    /// Never seen this peer.
    New,
    /// Stored key matches the presented one.
    Trusted,
    /// Stored key differs - a changed key.
    Changed,
}

impl fmt::Display for TrustStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TrustStatus::New => "new",
            TrustStatus::Trusted => "trusted",
            TrustStatus::Changed => "changed",
        })
    }
}

/// I/O or JSON failure loading/persisting the store.
#[derive(Debug, Error)]
pub enum TrustStoreError {
    #[error("trust store I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("trust store is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("stored key for {0:?} is not 32-byte hex")]
    BadKey(String),
}

pub struct TrustStore {
    #[cfg(feature = "fs")]
    path: PathBuf,
    keys: BTreeMap<String, [u8; 32]>,
}

impl TrustStore {
    /// Load the JSON store at `path`, or start empty if it does not exist.
    ///
    /// # Errors
    /// [`TrustStoreError`] on read failure, malformed JSON, or a value that is
    /// not 32-byte hex.
    #[cfg(feature = "fs")]
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, TrustStoreError> {
        let path = path.as_ref().to_path_buf();
        let mut keys = BTreeMap::new();
        if path.exists() {
            let raw: BTreeMap<String, String> = serde_json::from_str(&fs::read_to_string(&path)?)?;
            for (peer, hex_key) in raw {
                let bytes =
                    hex_decode32(&hex_key).ok_or_else(|| TrustStoreError::BadKey(peer.clone()))?;
                keys.insert(peer, bytes);
            }
        }
        Ok(Self { path, keys })
    }

    /// An empty, non-persistent trust store. Always available (no filesystem);
    /// `trust()` updates the in-memory map but writes nothing to disk. This is
    /// the only constructor on wasm, where there is no filesystem.
    pub fn in_memory() -> Self {
        Self {
            #[cfg(feature = "fs")]
            path: PathBuf::new(),
            keys: BTreeMap::new(),
        }
    }

    /// `New` (never seen), `Trusted` (matches), or `Changed` (mismatch).
    pub fn status(&self, peer: &str, identity_pub: &[u8; 32]) -> TrustStatus {
        match self.keys.get(peer) {
            None => TrustStatus::New,
            Some(stored) if stored == identity_pub => TrustStatus::Trusted,
            Some(_) => TrustStatus::Changed,
        }
    }

    /// `true` if trusted, `false` if unknown. Never silently accept a changed
    /// key.
    ///
    /// # Errors
    /// [`KeyChangedError`] on a stored/presented key mismatch.
    pub fn verify(&self, peer: &str, identity_pub: &[u8; 32]) -> Result<bool, KeyChangedError> {
        match self.status(peer, identity_pub) {
            TrustStatus::New => Ok(false),
            TrustStatus::Trusted => Ok(true),
            TrustStatus::Changed => Err(KeyChangedError {
                peer: peer.to_string(),
            }),
        }
    }

    /// Store (or explicitly re-approve) a peer's identity key. Persists with an
    /// atomic tmp-file + rename in the same directory.
    ///
    /// # Errors
    /// [`TrustStoreError::Io`] / [`TrustStoreError::Json`] on write failure.
    pub fn trust(&mut self, peer: &str, identity_pub: &[u8; 32]) -> Result<(), TrustStoreError> {
        self.keys.insert(peer.to_string(), *identity_pub);
        #[cfg(feature = "fs")]
        {
            let dump: BTreeMap<&str, String> = self
                .keys
                .iter()
                .map(|(k, v)| (k.as_str(), hex_encode(v)))
                .collect();
            let json = serde_json::to_string(&dump)?;
            let tmp = self.path.with_extension("tmp");
            fs::write(&tmp, json)?;
            fs::rename(&tmp, &self.path)?;
        }
        Ok(())
    }
}

#[cfg(feature = "fs")]
fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(feature = "fs")]
fn hex_decode32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

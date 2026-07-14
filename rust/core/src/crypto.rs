//! Crypto primitives: X25519 + HKDF session keys, AES-256-GCM frame encryption,
//! Ed25519 signatures and the signed back-channel message format, PIN
//! derivation, PSK session keys for broadcast mode, and the code-phrase KDF.
//!
//! Zeroization is real: the dalek key types already wipe on drop, and
//! [`SessionKey`] wipes the derived 32-byte keys (see the type docs).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use scrypt::{scrypt, Params as ScryptParams};
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF `info` for the ECDH session key.
pub const INFO_SESSION: &[u8] = b"cypher-v1-session";
/// HKDF `info` for the PSK-broadcast session key.
pub const INFO_PSK: &[u8] = b"cypher-v1-psk";
/// HKDF `info` for the interactive PIN.
pub const INFO_PIN: &[u8] = b"cypher-v1-pin";
/// scrypt salt for the code-phrase KDF.
pub const SALT_PHRASE: &[u8] = b"cypher-v1-phrase";
/// Ed25519 signature length.
pub const SIG_LEN: usize = 64;
/// AES-256-GCM authentication tag length.
pub const GCM_TAG_LEN: usize = 16;

/// A derived 32-byte symmetric key, wiped on drop. The dalek private-key types
/// already zeroize themselves, so only these HKDF/scrypt outputs need the
/// wrapper here.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKey(pub [u8; 32]);

impl SessionKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Crypto failure. GCM tag verification is the only fallible operation
/// surfaced here; the signed-message and phrase paths use `Option` / their own
/// errors to honour the silent-rejection contract.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("AES-256-GCM authentication failed")]
    Decrypt,
    #[error("empty code phrase")]
    EmptyPhrase,
}

/// Fresh per-session X25519 secret (ephemeral, never reused).
pub fn generate_ephemeral() -> XStaticSecret {
    XStaticSecret::random_from_rng(OsRng)
}

/// Long-term Ed25519 identity key.
pub fn generate_identity() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Raw 32-byte X25519 public key.
pub fn ephemeral_public_bytes(secret: &XStaticSecret) -> [u8; 32] {
    XPublicKey::from(secret).to_bytes()
}

/// Raw 32-byte Ed25519 public key.
pub fn identity_public_bytes(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

fn hkdf_derive(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out: &mut [u8]) {
    // `salt = None` selects HKDF's RFC 5869 all-zero salt.
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, out)
        .expect("HKDF output length within 255*HashLen");
}

/// `shared = X25519(mine, theirs)`; `session_key = HKDF-SHA256(ikm = shared,
/// salt = SESSION_ID (8B BE), info = INFO_SESSION, 32B)`.
pub fn session_key(
    my_ephemeral: &XStaticSecret,
    their_pub: [u8; 32],
    session_id: u64,
) -> SessionKey {
    let shared = my_ephemeral.diffie_hellman(&XPublicKey::from(their_pub));
    let mut key = [0u8; 32];
    hkdf_derive(
        shared.as_bytes(),
        Some(&session_id.to_be_bytes()),
        INFO_SESSION,
        &mut key,
    );
    SessionKey(key)
}

/// Broadcast PSK mode. No forward secrecy.
pub fn psk_session_key(psk: &[u8; 32], session_id: u64) -> SessionKey {
    let mut key = [0u8; 32];
    hkdf_derive(psk, Some(&session_id.to_be_bytes()), INFO_PSK, &mut key);
    SessionKey(key)
}

/// Canonicalise a code phrase: NFKD-fold, drop non-ASCII-alphanumeric
/// characters, lowercase, split on runs of the dropped characters. Accents fold
/// to their base letter (`é` → `e`), while characters with no ASCII
/// decomposition (CJK, emoji) are dropped entirely.
pub fn phrase_tokens(phrase: &str) -> Vec<String> {
    // NFKD, then keep only ASCII bytes, lowercase, and split into `[a-z0-9]+`
    // runs.
    let folded: String = phrase
        .nfkd()
        .filter(|c| c.is_ascii())
        .collect::<String>()
        .to_ascii_lowercase();
    folded
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Derive the 32-byte broadcast PSK from a human code phrase with scrypt
/// (n = 2^14, r = 8, p = 1), keyed on the normalised phrase (tokens joined with
/// `-`) and the fixed [`SALT_PHRASE`].
///
/// # Errors
/// [`CryptoError::EmptyPhrase`] if the phrase normalises to no tokens.
pub fn key_from_phrase(phrase: &str) -> Result<SessionKey, CryptoError> {
    let tokens = phrase_tokens(phrase);
    if tokens.is_empty() {
        return Err(CryptoError::EmptyPhrase);
    }
    let normalised = tokens.join("-");
    let mut key = [0u8; 32];
    // log_n = 14 == n = 2^14; r = 8, p = 1, 32-byte output.
    let params = ScryptParams::new(14, 8, 1, 32).expect("valid scrypt params");
    scrypt(normalised.as_bytes(), SALT_PHRASE, &params, &mut key)
        .expect("32-byte scrypt output length is valid");
    Ok(SessionKey(key))
}

/// `uint24` of 3 HKDF bytes (no salt) mod 1,000,000, zero-padded.
pub fn derive_pin(key: &[u8; 32]) -> String {
    let mut pin_bytes = [0u8; 3];
    hkdf_derive(key, None, INFO_PIN, &mut pin_bytes);
    // uint24, big-endian (top byte zero), mod 1e6.
    let value = u32::from_be_bytes([0, pin_bytes[0], pin_bytes[1], pin_bytes[2]]);
    format!("{:06}", value % 1_000_000)
}

/// 12-byte GCM nonce = SESSION_ID[0:4] (of the 8-byte BE SESSION_ID) ‖
/// FRAME_NUMBER (8B BE).
pub fn gcm_nonce(session_id: u64, frame_number: u64) -> [u8; 12] {
    let sid = session_id.to_be_bytes();
    let frame = frame_number.to_be_bytes();
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&sid[..4]);
    nonce[4..].copy_from_slice(&frame);
    nonce
}

/// AES-256-GCM encrypt with the 6-byte header prefix as AAD. Returns
/// `ciphertext ‖ 16-byte tag` - the frame PAYLOAD. Deterministic in its inputs,
/// as the byte-identical retransmission rule requires.
///
/// ```
/// use cypher_core::crypto::encrypt_payload;
/// use cypher_core::frame::{header_prefix, ENCRYPTED};
/// let key = [0u8; 32];
/// let aad = header_prefix(42, ENCRYPTED, 4 + 16).unwrap();
/// let payload = encrypt_payload(&key, 1, 42, b"data", &aad);
/// assert_eq!(payload.len(), 4 + 16);
/// ```
pub fn encrypt_payload(
    key: &[u8; 32],
    session_id: u64,
    frame_number: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = gcm_nonce(session_id, frame_number);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-256-GCM encryption is infallible for valid key/nonce")
}

/// AES-256-GCM decrypt-and-verify.
///
/// # Errors
/// [`CryptoError::Decrypt`] on any tampering (tag mismatch or truncation).
pub fn decrypt_payload(
    key: &[u8; 32],
    session_id: u64,
    frame_number: u64,
    payload: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = gcm_nonce(session_id, frame_number);
    cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: payload, aad })
        .map_err(|_| CryptoError::Decrypt)
}

/// Ed25519 signature over `message`.
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> [u8; SIG_LEN] {
    signing_key.sign(message).to_bytes()
}

/// Verify an Ed25519 signature. Returns `false` on ANY malformed input - never
/// panics - so callers reject silently (no oracle for attackers).
pub fn verify(pub_key: [u8; 32], signature: &[u8], message: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&pub_key) else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; SIG_LEN], _> = signature.try_into() else {
        return false;
    };
    vk.verify(message, &Signature::from_bytes(&sig_bytes))
        .is_ok()
}

/// Back-channel format: `[MESSAGE_TYPE 1B][PAYLOAD][SIG 64B]`, the signature
/// covering `type ‖ payload`.
pub fn sign_message(signing_key: &SigningKey, msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + payload.len());
    body.push(msg_type);
    body.extend_from_slice(payload);
    let sig = sign(signing_key, &body);
    body.extend_from_slice(&sig);
    body
}

/// `(msg_type, payload)` if the signature verifies, else `None` (silent
/// rejection).
pub fn open_message(pub_key: [u8; 32], data: &[u8]) -> Option<(u8, Vec<u8>)> {
    if data.len() < 1 + SIG_LEN {
        return None;
    }
    let (body, sig) = data.split_at(data.len() - SIG_LEN);
    if verify(pub_key, sig, body) {
        Some((body[0], body[1..].to_vec()))
    } else {
        None
    }
}

/// INTENDED_RECEIVER = SHA-256(identity public key).
pub fn fingerprint(identity_pub: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(identity_pub).into()
}

/// HMAC-SHA256(key = pairing_token, msg = SESSION_ID 8B BE).
pub fn pairing_token_hash(token: &[u8; 16], session_id: u64) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(token).expect("HMAC accepts any key length");
    mac.update(&session_id.to_be_bytes());
    mac.finalize().into_bytes().into()
}

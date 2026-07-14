//! human code-phrase carrier for broadcast transfers.
//!
//! Broadcast is one-way: there is no handshake and the ciphertext is public,
//! so the phrase's entropy is the ONLY protection. Word count is the security
//! knob - each word adds `log2(len(WORDLIST))` bits (≈47.7 bits at the default
//! four words over this 3859-word list). [`crate::crypto::key_from_phrase`]
//! runs the words through the slow scrypt KDF; this module only picks them.

use std::sync::LazyLock;

use rand::rngs::OsRng;
use rand::seq::SliceRandom;

/// Curated 3-6 letter common English words. The conformance vector pins its
/// length and SHA-256.
static WORDLIST_TEXT: &str = include_str!("wordlist.txt");

/// The parsed word list, one word per line.
pub static WORDLIST: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| WORDLIST_TEXT.lines().collect());

/// Default phrase length (≈47.7 bits over the 3859-word reference list).
pub const DEFAULT_WORDS: usize = 4;

/// Assert the word-list invariant: at least 1024 distinct lowercase-alphabetic
/// words of 3–6 characters.
///
/// # Panics
/// If the bundled word list is ever edited into a bad state.
pub fn validate() {
    let words = &*WORDLIST;
    assert!(words.len() >= 1024, "word list too small");
    let unique: std::collections::HashSet<_> = words.iter().collect();
    assert_eq!(unique.len(), words.len(), "duplicate words");
    assert!(
        words
            .iter()
            .all(|w| { (3..=6).contains(&w.len()) && w.chars().all(|c| c.is_ascii_lowercase()) }),
        "word out of 3-6 lowercase-alpha range"
    );
}

/// A random `-`-joined code phrase drawn uniformly from [`WORDLIST`]. Entropy
/// is `words * log2(len(WORDLIST))` bits.
pub fn generate(words: usize) -> String {
    validate();
    let list = &*WORDLIST;
    let mut rng = OsRng;
    (0..words)
        .map(|_| *list.choose(&mut rng).expect("non-empty word list"))
        .collect::<Vec<_>>()
        .join("-")
}

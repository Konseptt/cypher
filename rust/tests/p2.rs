// Phase 2 integration tests - crypto and phrase.

// ─── Crypto ───────────────────────────────────────────────────────────────────

mod crypto {
    use cypher::crypto::{
        decrypt_payload, derive_pin, encrypt_payload, fingerprint, gcm_nonce, generate_ephemeral,
        generate_identity, identity_public_bytes, key_from_phrase, open_message,
        pairing_token_hash, phrase_tokens, psk_session_key, session_key, sign, sign_message,
        verify, CryptoError, GCM_TAG_LEN, SIG_LEN,
    };

    const SID: u64 = 0x1122334455667788;

    /// X25519 ECDH - both sides derive the same session key.
    #[test]
    fn crypto_ecdh_both_sides_agree() {
        let a = generate_ephemeral();
        let b = generate_ephemeral();
        let pub_a = cypher::crypto::ephemeral_public_bytes(&a);
        let pub_b = cypher::crypto::ephemeral_public_bytes(&b);
        let key_a = session_key(&a, pub_b, SID);
        let key_b = session_key(&b, pub_a, SID);
        assert_eq!(key_a.as_bytes(), key_b.as_bytes());
        assert_eq!(key_a.as_bytes().len(), 32);
    }

    /// SESSION_ID is a domain separator - different IDs → different keys.
    #[test]
    fn crypto_session_id_domain_separates_keys() {
        let a = generate_ephemeral();
        let b = generate_ephemeral();
        let pub_b = cypher::crypto::ephemeral_public_bytes(&b);
        let k1 = session_key(&a, pub_b, SID);
        let k2 = session_key(&a, pub_b, SID + 1);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    /// psk_session_key is 32 bytes, deterministic, and changes with SID.
    #[test]
    fn crypto_psk_session_key_deterministic() {
        let psk: [u8; 32] = std::array::from_fn(|i| i as u8);
        let k = psk_session_key(&psk, SID);
        assert_eq!(k.as_bytes().len(), 32);
        assert_eq!(k.as_bytes(), psk_session_key(&psk, SID).as_bytes());
        assert_ne!(
            k.as_bytes(),
            psk_session_key(&psk, SID + 1).as_bytes(),
            "different SID must produce different PSK key"
        );
    }

    /// Phrase normalization: accent-fold + lowercase + separator unification.
    #[test]
    fn crypto_phrase_tokens_accent_fold_and_separator() {
        assert_eq!(
            phrase_tokens("caf\u{e9}  PIANO-river"),
            ["cafe", "piano", "river"]
        );
    }

    /// NFKD accent fold - "café" and "cafe" produce the same tokens.
    #[test]
    fn crypto_phrase_tokens_cafe_nfkd() {
        assert_eq!(
            phrase_tokens("caf\u{e9}-piano"),
            phrase_tokens("cafe-piano")
        );
    }

    /// CJK characters (no ASCII decomposition) are dropped entirely.
    #[test]
    fn crypto_phrase_tokens_cjk_dropped() {
        assert_eq!(
            phrase_tokens("Hello \u{4e16}\u{754c} World"),
            ["hello", "world"]
        );
    }

    /// All-CJK input normalises to empty token list.
    #[test]
    fn crypto_phrase_tokens_all_cjk_is_empty() {
        assert!(phrase_tokens("\u{65e5}\u{672c}\u{8a9e}").is_empty());
    }

    /// Punctuation-only and empty input normalise to empty.
    #[test]
    fn crypto_phrase_tokens_punctuation_only_is_empty() {
        assert!(phrase_tokens("---!!!...").is_empty());
        assert!(phrase_tokens("").is_empty());
    }

    /// key_from_phrase is 32 bytes and deterministic.
    #[test]
    fn crypto_key_from_phrase_deterministic_and_32_bytes() {
        let k = key_from_phrase("alpha-bravo-charlie-delta").unwrap();
        assert_eq!(k.as_bytes().len(), 32);
        assert_eq!(
            k.as_bytes(),
            key_from_phrase("alpha-bravo-charlie-delta")
                .unwrap()
                .as_bytes()
        );
    }

    /// KAT: pins scrypt(n=2^14, r=8, p=1, dklen=32) + SALT_PHRASE.
    /// Any weakening (n, r, p, salt, dklen) changes this value and fails the test.
    #[test]
    fn crypto_key_from_phrase_known_answer() {
        let hex = hex::decode("caad492c1880d390251f5661c8c30ea1816648885279472e32ed767a73a402a9")
            .unwrap();
        assert_eq!(
            key_from_phrase("alpha-bravo-charlie-delta")
                .unwrap()
                .as_bytes(),
            hex.as_slice()
        );
    }

    /// Space and hyphen separators are unified - same key.
    #[test]
    fn crypto_key_from_phrase_normalization_equivalence() {
        let k1 = key_from_phrase("Donkey Piano").unwrap();
        let k2 = key_from_phrase("donkey-piano").unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    /// Different phrases derive different keys.
    #[test]
    fn crypto_key_from_phrase_differs_by_phrase() {
        let k1 = key_from_phrase("donkey-piano").unwrap();
        let k2 = key_from_phrase("donkey-river").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    /// Accented and unaccented spellings derive the same key.
    #[test]
    fn crypto_key_from_phrase_accent_folds_to_ascii() {
        let k1 = key_from_phrase("caf\u{e9}-piano").unwrap();
        let k2 = key_from_phrase("cafe-piano").unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    /// Phrase that reduces to no tokens must be rejected.
    #[test]
    fn crypto_key_from_phrase_rejects_all_cjk() {
        assert!(matches!(
            key_from_phrase("\u{65e5}\u{672c}\u{8a9e}"),
            Err(CryptoError::EmptyPhrase)
        ));
    }

    /// Empty phrase must be rejected.
    #[test]
    fn crypto_key_from_phrase_rejects_empty() {
        assert!(matches!(key_from_phrase(""), Err(CryptoError::EmptyPhrase)));
    }

    /// Punctuation-only phrase must be rejected.
    #[test]
    fn crypto_key_from_phrase_rejects_punctuation_only() {
        assert!(matches!(
            key_from_phrase("---!!!..."),
            Err(CryptoError::EmptyPhrase)
        ));
    }

    /// Nonce layout: SESSION_ID[0:4] (4B BE) ‖ FRAME_NUMBER (8B BE).
    #[test]
    fn crypto_gcm_nonce_layout() {
        let nonce = gcm_nonce(SID, 1);
        assert_eq!(nonce.len(), 12);
        // SESSION_ID = 0x1122334455667788 → first 4 bytes big-endian = 11 22 33 44
        assert_eq!(&nonce[..4], &[0x11, 0x22, 0x33, 0x44]);
        // FRAME_NUMBER = 1 as 8-byte BE
        assert_eq!(&nonce[4..], &(1u64).to_be_bytes());
    }

    /// AES-256-GCM encrypt → decrypt round-trip.
    #[test]
    fn crypto_encrypt_decrypt_round_trip() {
        let key = [0u8; 32];
        let aad: Vec<u8> = (0u8..29).collect();
        let ct = encrypt_payload(&key, SID, 7, b"secret data", &aad);
        assert_eq!(ct.len(), b"secret data".len() + GCM_TAG_LEN);
        assert_eq!(
            decrypt_payload(&key, SID, 7, &ct, &aad).unwrap(),
            b"secret data"
        );
    }

    /// Retransmission rule: same inputs → byte-identical ciphertext.
    #[test]
    fn crypto_encryption_is_deterministic_for_retransmits() {
        let key = [0u8; 32];
        let aad = vec![0u8; 29];
        let ct1 = encrypt_payload(&key, SID, 7, b"x", &aad);
        let ct2 = encrypt_payload(&key, SID, 7, b"x", &aad);
        assert_eq!(ct1, ct2, "retransmit must be byte-identical");
        // different frame_number → different ciphertext
        let ct3 = encrypt_payload(&key, SID, 8, b"x", &aad);
        assert_ne!(ct1, ct3);
    }

    /// Tampered key must cause decryption to fail.
    #[test]
    fn crypto_gcm_rejects_tampered_key() {
        let key = [0u8; 32];
        let aad: Vec<u8> = (0u8..29).collect();
        let ct = encrypt_payload(&key, SID, 7, b"secret", &aad);
        let mut bad_key = [0u8; 32];
        bad_key[31] = 0x01;
        assert_eq!(
            decrypt_payload(&bad_key, SID, 7, &ct, &aad).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    /// Tampered AAD must cause decryption to fail.
    #[test]
    fn crypto_gcm_rejects_tampered_aad() {
        let key = [0u8; 32];
        let aad: Vec<u8> = (0u8..29).collect();
        let ct = encrypt_payload(&key, SID, 7, b"secret", &aad);
        let mut bad_aad = aad.clone();
        *bad_aad.last_mut().unwrap() = 0xff;
        assert_eq!(
            decrypt_payload(&key, SID, 7, &ct, &bad_aad).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    /// Bit flip in ciphertext must cause decryption to fail.
    #[test]
    fn crypto_gcm_rejects_tampered_ciphertext() {
        let key = [0u8; 32];
        let aad: Vec<u8> = (0u8..29).collect();
        let mut ct = encrypt_payload(&key, SID, 7, b"secret", &aad);
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert_eq!(
            decrypt_payload(&key, SID, 7, &ct, &aad).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    /// Wrong frame_number (hence wrong nonce) must cause decryption to fail.
    #[test]
    fn crypto_gcm_rejects_wrong_frame_number() {
        let key = [0u8; 32];
        let aad: Vec<u8> = (0u8..29).collect();
        let ct = encrypt_payload(&key, SID, 7, b"secret", &aad);
        assert_eq!(
            decrypt_payload(&key, SID, 8, &ct, &aad).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    /// derive_pin is 6 decimal digits, deterministic, and key-dependent.
    #[test]
    fn crypto_pin_format_and_agreement() {
        use sha2::{Digest, Sha256};
        let key: [u8; 32] = Sha256::digest(b"session").into();
        let pin = derive_pin(&key);
        assert_eq!(pin.len(), 6, "PIN must be 6 characters");
        assert!(
            pin.chars().all(|c| c.is_ascii_digit()),
            "PIN must be digits"
        );
        assert_eq!(pin, derive_pin(&key), "PIN must be deterministic");
        let other_key: [u8; 32] = Sha256::digest(b"other").into();
        assert_ne!(
            pin,
            derive_pin(&other_key),
            "different key must give different PIN"
        );
    }

    /// Ed25519 sign/verify round-trip; tampered message and wrong pubkey rejected.
    #[test]
    fn crypto_sign_verify() {
        let ident = generate_identity();
        let pub_bytes = identity_public_bytes(&ident);
        let sig = sign(&ident, b"beacon fields");
        assert_eq!(sig.len(), SIG_LEN);
        assert!(
            verify(pub_bytes, &sig, b"beacon fields"),
            "valid sig must verify"
        );
        assert!(
            !verify(pub_bytes, &sig, b"tampered fields"),
            "wrong message must not verify"
        );
        assert!(
            !verify([0u8; 32], &sig, b"beacon fields"),
            "wrong pubkey must not verify"
        );
    }

    /// verify on malformed input returns false - never panics.
    #[test]
    fn crypto_verify_malformed_input_returns_false() {
        assert!(!verify([0xffu8; 32], &[0xffu8; 64], b"whatever"));
        assert!(!verify([0u8; 32], &[0u8; 1], b"too short sig"));
        assert!(!verify([0u8; 32], &[], b"empty sig"));
    }

    /// sign_message → open_message round-trip.
    #[test]
    fn crypto_back_channel_message_round_trip() {
        let ident = generate_identity();
        let pub_bytes = identity_public_bytes(&ident);
        let wire = sign_message(&ident, 0x03, &[0u8; 8]);
        assert_eq!(open_message(pub_bytes, &wire), Some((0x03, vec![0u8; 8])));
    }

    /// Truncated sig is silently rejected (None, no panic).
    #[test]
    fn crypto_back_channel_rejects_truncated_sig() {
        let ident = generate_identity();
        let pub_bytes = identity_public_bytes(&ident);
        let wire = sign_message(&ident, 0x03, b"payload");
        assert_eq!(open_message(pub_bytes, &wire[..wire.len() - 1]), None);
    }

    /// Too-short input (< 1 + SIG_LEN) is silently rejected.
    #[test]
    fn crypto_back_channel_rejects_too_short() {
        let ident = generate_identity();
        let pub_bytes = identity_public_bytes(&ident);
        assert_eq!(open_message(pub_bytes, &[0x03]), None);
    }

    /// Tampered body is silently rejected.
    #[test]
    fn crypto_back_channel_rejects_tampered_body() {
        let ident = generate_identity();
        let pub_bytes = identity_public_bytes(&ident);
        let wire = sign_message(&ident, 0x03, b"payload");
        let mut tampered = wire.clone();
        tampered[0] ^= 1;
        assert_eq!(open_message(pub_bytes, &tampered), None);
    }

    /// Message signed by a different key is silently rejected.
    #[test]
    fn crypto_back_channel_rejects_wrong_signer() {
        let ident = generate_identity();
        let other = generate_identity();
        let other_pub = identity_public_bytes(&other);
        let wire = sign_message(&ident, 0x03, b"payload");
        assert_eq!(open_message(other_pub, &wire), None);
    }

    /// fingerprint is SHA-256(identity public key).
    #[test]
    fn crypto_fingerprint_is_sha256() {
        use sha2::{Digest, Sha256};
        let ident = generate_identity();
        let pub_bytes = identity_public_bytes(&ident);
        let expected: [u8; 32] = Sha256::digest(pub_bytes).into();
        assert_eq!(fingerprint(&pub_bytes), expected);
        assert_eq!(fingerprint(&pub_bytes).len(), 32);
    }

    // pairing_token_hash KAT - vector uses a 16-byte token.
    // See tests/vectors/crypto.json kind="pairing_token_hash".
    #[test]
    fn crypto_pairing_token_hash_known_answer() {
        let token: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap()
            .try_into()
            .unwrap();
        // vector session_id = 81985529216486895 = 0x0112233445566778
        let sid_val: u64 = 81985529216486895;
        let expected =
            hex::decode("83a0f83e14bf1a66d4d05b68cf6b249de8833f5c044113b197d61ef878f0fd11")
                .unwrap();
        let got = pairing_token_hash(&token, sid_val);
        assert_eq!(got.as_ref(), expected.as_slice());
    }
}

// ─── Phrase ───────────────────────────────────────────────────────────────────

mod phrase {
    use cypher::phrase::{generate, validate, DEFAULT_WORDS, WORDLIST};

    /// Wordlist must have ≥1024 distinct entries, all 3-6 lowercase alpha.
    #[test]
    fn phrase_wordlist_large_unique_and_well_formed() {
        let words = &*WORDLIST;
        assert!(words.len() >= 1024, "word list too small: {}", words.len());
        let unique: std::collections::HashSet<_> = words.iter().collect();
        assert_eq!(unique.len(), words.len(), "duplicate words in list");
        for w in words.iter() {
            let len = w.len();
            assert!(
                (3..=6).contains(&len),
                "word {:?} length {} out of 3-6 range",
                w,
                len
            );
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "word {:?} contains non-lowercase-ascii",
                w
            );
        }
    }

    /// validate() does not panic on the bundled wordlist.
    #[test]
    fn phrase_validate_does_not_panic() {
        validate(); // panics on bad wordlist state
    }

    /// Default generate() produces 4 words, each from the wordlist.
    #[test]
    fn phrase_generate_default_is_four_words_from_wordlist() {
        let phrase = generate(DEFAULT_WORDS);
        let parts: Vec<&str> = phrase.split('-').collect();
        assert_eq!(parts.len(), 4, "default phrase must have 4 words");
        let words = &*WORDLIST;
        for p in &parts {
            assert!(words.contains(p), "word {:?} not in wordlist", p);
        }
    }

    /// Word count is configurable.
    #[test]
    fn phrase_generate_word_count_is_configurable() {
        assert_eq!(generate(6).split('-').count(), 6);
        assert_eq!(generate(1).split('-').count(), 1);
    }

    /// Two consecutive calls must differ (collision astronomically unlikely with ~47.7 bits of entropy per 4-word phrase).
    #[test]
    fn phrase_generate_two_calls_differ() {
        assert_ne!(generate(DEFAULT_WORDS), generate(DEFAULT_WORDS));
    }

    /// Entropy smoke - 500 single-word draws must produce >100 distinct words
    /// (a regression that samples from a tiny slice would yield ≤8 distinct words).
    #[test]
    fn phrase_generate_draws_from_the_whole_wordlist() {
        let distinct: std::collections::HashSet<String> = (0..500).map(|_| generate(1)).collect();
        assert!(
            distinct.len() > 100,
            "only {} distinct words in 500 draws - entropy regression?",
            distinct.len()
        );
    }
}

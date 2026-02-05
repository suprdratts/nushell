//! Cryptographic utilities for secret encryption

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Random generation failed")]
    RandomFailed,
}

/// Handles encryption/decryption of secrets
pub struct Crypto {
    key: LessSafeKey,
    rng: SystemRandom,
}

impl Crypto {
    /// Create a new Crypto instance with the given master key
    pub fn new(master_key: [u8; 32]) -> Self {
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &master_key)
            .expect("Invalid key length");
        let key = LessSafeKey::new(unbound_key);
        let rng = SystemRandom::new();
        
        Self { key, rng }
    }

    /// Generate a random 32-byte key
    pub fn generate_key() -> [u8; 32] {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key).expect("Failed to generate random key");
        key
    }

    /// Encrypt plaintext, returning nonce || ciphertext
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        self.rng.fill(&mut nonce_bytes).map_err(|_| CryptoError::RandomFailed)?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // Encrypt (in-place, with space for tag)
        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(in_out);
        
        Ok(result)
    }

    /// Decrypt nonce || ciphertext, returning plaintext
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < 12 {
            return Err(CryptoError::DecryptionFailed);
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_arr);

        // Decrypt
        let mut in_out = ciphertext.to_vec();
        let plaintext = self.key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        Ok(plaintext.to_vec())
    }

    /// Encrypt and base64 encode (for storage)
    pub fn encrypt_to_base64(&self, plaintext: &str) -> Result<String, CryptoError> {
        use base64::Engine;
        let encrypted = self.encrypt(plaintext.as_bytes())?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted))
    }

    /// Base64 decode and decrypt (from storage)
    pub fn decrypt_from_base64(&self, encoded: &str) -> Result<String, CryptoError> {
        use base64::Engine;
        let encrypted = base64::engine::general_purpose::STANDARD.decode(encoded)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let decrypted = self.decrypt(&encrypted)?;
        String::from_utf8(decrypted).map_err(|_| CryptoError::DecryptionFailed)
    }
}

/// Generate a secure random token (for API keys, etc.)
pub fn generate_token(prefix: &str) -> String {
    use base64::Engine;
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 24];
    rng.fill(&mut bytes).expect("Failed to generate random bytes");
    format!("{}_{}", prefix, base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = Crypto::generate_key();
        let crypto = Crypto::new(key);
        
        let plaintext = "Hello, SEKS!";
        let encrypted = crypto.encrypt(plaintext.as_bytes()).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
    }

    #[test]
    fn test_base64_roundtrip() {
        let key = Crypto::generate_key();
        let crypto = Crypto::new(key);
        
        let plaintext = "sk-ant-api03-secret-key";
        let encrypted = crypto.encrypt_to_base64(plaintext).unwrap();
        let decrypted = crypto.decrypt_from_base64(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }
}

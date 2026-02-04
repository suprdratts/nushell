//! Secret Registry - Thread-safe storage for sensitive values
//!
//! The registry holds secrets and their encoded variants (base64, hex) for efficient
//! matching during output scrubbing.

use crate::MIN_SECRET_LENGTH;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::HashSet;

/// Global secret registry instance.
///
/// This is used by the convenience functions `register_secret`, `scrub_output`, etc.
/// For isolated use cases (e.g., testing), create a local `SecretRegistry` instead.
pub static GLOBAL_REGISTRY: Lazy<SecretRegistry> = Lazy::new(SecretRegistry::new);

/// A thread-safe registry for storing secrets and their encoded variants.
///
/// The registry automatically generates common encoded forms of each secret:
/// - Base64 (standard)
/// - Hex (lowercase and uppercase)
///
/// All variants are stored and matched during scrubbing.
#[derive(Debug, Default)]
pub struct SecretRegistry {
    /// Set of all secret patterns to match (original + encoded variants)
    patterns: RwLock<HashSet<String>>,
    /// Count of original secrets (not including variants)
    original_count: RwLock<usize>,
}

impl SecretRegistry {
    /// Create a new empty secret registry.
    pub fn new() -> Self {
        Self {
            patterns: RwLock::new(HashSet::new()),
            original_count: RwLock::new(0),
        }
    }

    /// Register a secret value.
    ///
    /// The secret and its common encoded variants (base64, hex) will be stored.
    /// Secrets shorter than `MIN_SECRET_LENGTH` are ignored to prevent false positives.
    ///
    /// # Arguments
    /// * `secret` - The sensitive value to register
    ///
    /// # Returns
    /// `true` if the secret was registered, `false` if it was too short or already exists
    pub fn register(&self, secret: &str) -> bool {
        // Ignore secrets that are too short - would cause too many false positives
        if secret.len() < MIN_SECRET_LENGTH {
            return false;
        }

        let mut patterns = self.patterns.write();
        let mut count = self.original_count.write();

        // Check if already registered (check the original)
        if patterns.contains(secret) {
            return false;
        }

        // Add the original secret
        patterns.insert(secret.to_string());
        *count += 1;

        // Generate and add encoded variants
        let variants = generate_encoded_variants(secret);
        for variant in variants {
            patterns.insert(variant);
        }

        true
    }

    /// Check if a string contains any registered secrets.
    ///
    /// # Arguments
    /// * `text` - The text to check
    ///
    /// # Returns
    /// `true` if any registered secret pattern is found
    pub fn contains_secret(&self, text: &str) -> bool {
        let patterns = self.patterns.read();
        patterns.iter().any(|pattern| text.contains(pattern))
    }

    /// Get all registered patterns (secrets + variants).
    ///
    /// Returns a sorted vector for consistent ordering.
    pub fn patterns(&self) -> Vec<String> {
        let patterns = self.patterns.read();
        let mut result: Vec<_> = patterns.iter().cloned().collect();
        // Sort by length descending to match longer secrets first
        result.sort_by(|a, b| b.len().cmp(&a.len()));
        result
    }

    /// Get the count of original secrets (not including encoded variants).
    pub fn count(&self) -> usize {
        *self.original_count.read()
    }

    /// Clear all registered secrets.
    pub fn clear(&self) {
        let mut patterns = self.patterns.write();
        let mut count = self.original_count.write();
        patterns.clear();
        *count = 0;
    }
}

/// Generate common encoded variants of a secret.
///
/// Currently generates:
/// - Base64 (standard encoding)
/// - Hex (lowercase)
/// - Hex (uppercase)
fn generate_encoded_variants(secret: &str) -> Vec<String> {
    let mut variants = Vec::new();

    // Base64 encoding
    let base64_encoded = BASE64_STANDARD.encode(secret.as_bytes());
    variants.push(base64_encoded);

    // Hex encoding (lowercase)
    let hex_lower: String = secret.bytes().map(|b| format!("{:02x}", b)).collect();
    variants.push(hex_lower);

    // Hex encoding (uppercase)
    let hex_upper: String = secret.bytes().map(|b| format!("{:02X}", b)).collect();
    variants.push(hex_upper);

    variants
}

// Convenience functions for the global registry

/// Register a secret in the global registry.
///
/// # Arguments
/// * `secret` - The sensitive value to register
///
/// # Returns
/// `true` if the secret was registered, `false` if it was too short or already exists
pub fn register_secret(secret: &str) -> bool {
    GLOBAL_REGISTRY.register(secret)
}

/// Get the count of secrets in the global registry.
pub fn secret_count() -> usize {
    GLOBAL_REGISTRY.count()
}

/// Clear all secrets from the global registry.
pub fn clear_secrets() {
    GLOBAL_REGISTRY.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_variants() {
        let variants = generate_encoded_variants("test");
        assert_eq!(variants.len(), 3);

        // Base64 of "test" is "dGVzdA=="
        assert!(variants.contains(&"dGVzdA==".to_string()));

        // Hex of "test" is "74657374"
        assert!(variants.contains(&"74657374".to_string()));
        assert!(variants.contains(&"74657374".to_uppercase()));
    }

    #[test]
    fn test_registry_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let registry = Arc::new(SecretRegistry::new());
        let mut handles = vec![];

        // Spawn multiple threads registering secrets
        for i in 0..10 {
            let reg = Arc::clone(&registry);
            handles.push(thread::spawn(move || {
                reg.register(&format!("secret-{:04}", i));
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(registry.count(), 10);
    }

    #[test]
    fn test_patterns_sorted_by_length() {
        let registry = SecretRegistry::new();
        registry.register("short");
        registry.register("longer-secret");

        let patterns = registry.patterns();
        // Longer patterns should come first
        assert!(patterns[0].len() >= patterns.last().unwrap().len());
    }
}

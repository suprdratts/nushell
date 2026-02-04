//! Secret Registry - Thread-safe storage for sensitive values
//!
//! The registry holds secrets and their encoded variants (base64, hex) for efficient
//! matching during output scrubbing.

use crate::MIN_SECRET_LENGTH;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::HashMap;

/// Global secret registry instance.
///
/// This is used by the convenience functions `register_secret`, `scrub_output`, etc.
/// For isolated use cases (e.g., testing), create a local `SecretRegistry` instead.
pub static GLOBAL_REGISTRY: Lazy<SecretRegistry> = Lazy::new(SecretRegistry::new);

/// A registered secret with its name and all pattern variants
#[derive(Debug, Clone)]
struct RegisteredSecret {
    /// The human-readable name for this secret
    name: String,
    /// All patterns to match (original + encoded variants)
    patterns: Vec<String>,
}

/// A thread-safe registry for storing secrets and their encoded variants.
///
/// The registry automatically generates common encoded forms of each secret:
/// - Base64 (standard)
/// - Hex (lowercase and uppercase)
///
/// All variants are stored and matched during scrubbing.
#[derive(Debug, Default)]
pub struct SecretRegistry {
    /// Map of secret name -> RegisteredSecret
    secrets: RwLock<HashMap<String, RegisteredSecret>>,
}

impl SecretRegistry {
    /// Create a new empty secret registry.
    pub fn new() -> Self {
        Self {
            secrets: RwLock::new(HashMap::new()),
        }
    }

    /// Register a secret value with a name.
    ///
    /// The secret and its common encoded variants (base64, hex) will be stored.
    /// Secrets shorter than `MIN_SECRET_LENGTH` are ignored to prevent false positives.
    ///
    /// # Arguments
    /// * `name` - The name to use in redaction markers (e.g., "github_token")
    /// * `secret` - The sensitive value to register
    ///
    /// # Returns
    /// `true` if the secret was registered, `false` if it was too short or already exists
    pub fn register_named(&self, name: &str, secret: &str) -> bool {
        // Ignore secrets that are too short - would cause too many false positives
        if secret.len() < MIN_SECRET_LENGTH {
            return false;
        }

        let mut secrets = self.secrets.write();

        // Check if already registered
        if secrets.contains_key(name) {
            return false;
        }

        // Generate all patterns (original + encoded variants)
        let mut patterns = vec![secret.to_string()];
        patterns.extend(generate_encoded_variants(secret));

        secrets.insert(
            name.to_string(),
            RegisteredSecret {
                name: name.to_string(),
                patterns,
            },
        );

        true
    }

    /// Register a secret value (anonymous, uses [REDACTED]).
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

        let mut secrets = self.secrets.write();

        // Use the secret itself as the key for anonymous secrets
        let key = format!("__anon_{}", secrets.len());
        
        // Check if this exact secret value is already registered
        for registered in secrets.values() {
            if registered.patterns.first() == Some(&secret.to_string()) {
                return false;
            }
        }

        // Generate all patterns (original + encoded variants)
        let mut patterns = vec![secret.to_string()];
        patterns.extend(generate_encoded_variants(secret));

        secrets.insert(
            key,
            RegisteredSecret {
                name: String::new(), // Empty name means use [REDACTED]
                patterns,
            },
        );

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
        let secrets = self.secrets.read();
        secrets
            .values()
            .any(|s| s.patterns.iter().any(|p| text.contains(p)))
    }

    /// Get all registered patterns with their redaction markers, sorted by length (longest first).
    ///
    /// Returns a vector of (pattern, redaction_marker) pairs.
    pub fn patterns_with_markers(&self) -> Vec<(String, String)> {
        let secrets = self.secrets.read();
        let mut result: Vec<(String, String)> = Vec::new();

        for registered in secrets.values() {
            let marker = if registered.name.is_empty() {
                "[REDACTED]".to_string()
            } else {
                format!("<secret:{}>", registered.name)
            };

            for pattern in &registered.patterns {
                result.push((pattern.clone(), marker.clone()));
            }
        }

        // Sort by pattern length descending to match longer secrets first
        result.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        result
    }

    /// Get all registered patterns (secrets + variants).
    ///
    /// Returns a sorted vector for consistent ordering (longest first).
    pub fn patterns(&self) -> Vec<String> {
        self.patterns_with_markers()
            .into_iter()
            .map(|(p, _)| p)
            .collect()
    }

    /// Get the count of original secrets (not including encoded variants).
    pub fn count(&self) -> usize {
        self.secrets.read().len()
    }

    /// Clear all registered secrets.
    pub fn clear(&self) {
        self.secrets.write().clear();
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

/// Register a named secret in the global registry.
///
/// # Arguments
/// * `name` - The name to use in redaction markers
/// * `secret` - The sensitive value to register
///
/// # Returns
/// `true` if the secret was registered, `false` if it was too short or already exists
pub fn register_named_secret(name: &str, secret: &str) -> bool {
    GLOBAL_REGISTRY.register_named(name, secret)
}

/// Register a secret in the global registry (anonymous, uses [REDACTED]).
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

    #[test]
    fn test_named_secrets() {
        let registry = SecretRegistry::new();
        registry.register_named("github_token", "ghp_abc123xyz");

        let patterns = registry.patterns_with_markers();
        // Should have the original + 3 encoded variants
        assert!(patterns.len() >= 4);

        // All should have the same marker
        for (_, marker) in &patterns {
            assert_eq!(marker, "<secret:github_token>");
        }
    }

    #[test]
    fn test_anonymous_secrets() {
        let registry = SecretRegistry::new();
        registry.register("mysecretvalue");

        let patterns = registry.patterns_with_markers();
        for (_, marker) in &patterns {
            assert_eq!(marker, "[REDACTED]");
        }
    }
}

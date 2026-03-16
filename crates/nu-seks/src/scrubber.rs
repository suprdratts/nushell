//! Output Scrubber - Replace secrets with redaction markers
//!
//! The scrubber performs string replacement of all registered secrets and their
//! encoded variants with redaction markers like `[REDACTED]` or `<secret:name>`.

use crate::registry::{GLOBAL_REGISTRY, SecretRegistry};

/// Scrub output using the global secret registry.
///
/// Replaces all occurrences of registered secrets (and their encoded variants)
/// with their appropriate redaction markers.
///
/// # Arguments
/// * `output` - The output string to scrub
///
/// # Returns
/// A new string with secrets replaced, or the original if no secrets were found
///
/// # Example
/// ```
/// use nu_seks::{register_secret, scrub_output, clear_secrets};
///
/// clear_secrets();
/// register_secret("my-api-key-12345");
///
/// let output = scrub_output("Your key is: my-api-key-12345");
/// assert_eq!(output, "Your key is: [REDACTED]");
///
/// clear_secrets();
/// ```
pub fn scrub_output(output: &str) -> String {
    scrub_output_with_registry(output, &GLOBAL_REGISTRY)
}

/// Scrub output using a specific secret registry.
///
/// This is useful for testing or when you need isolated secret registries.
///
/// # Arguments
/// * `output` - The output string to scrub
/// * `registry` - The secret registry to use
///
/// # Returns
/// A new string with secrets replaced, or a copy of the original if no secrets were found
pub fn scrub_output_with_registry(output: &str, registry: &SecretRegistry) -> String {
    // Fast path: if no secrets registered, return early
    if registry.count() == 0 {
        return output.to_string();
    }

    // Fast path: if no secrets found, return early
    if !registry.contains_secret(output) {
        return output.to_string();
    }

    // Get patterns with their markers, sorted by length (longest first)
    // This ensures we replace "my-long-secret" before "secret" if both are registered
    let patterns = registry.patterns_with_markers();

    let mut result = output.to_string();
    for (pattern, marker) in patterns {
        // Only replace if pattern is non-empty (safety check)
        if !pattern.is_empty() {
            result = result.replace(&pattern, &marker);
        }
    }

    result
}

/// Scrub bytes output, treating it as UTF-8.
///
/// Non-UTF-8 bytes are passed through unchanged.
///
/// # Arguments
/// * `bytes` - The byte slice to scrub
///
/// # Returns
/// Scrubbed bytes as a Vec<u8>
pub fn scrub_bytes(bytes: &[u8]) -> Vec<u8> {
    scrub_bytes_with_registry(bytes, &GLOBAL_REGISTRY)
}

/// Scrub bytes output using a specific registry.
///
/// # Arguments
/// * `bytes` - The byte slice to scrub
/// * `registry` - The secret registry to use
///
/// # Returns
/// Scrubbed bytes as a Vec<u8>
pub fn scrub_bytes_with_registry(bytes: &[u8], registry: &SecretRegistry) -> Vec<u8> {
    match std::str::from_utf8(bytes) {
        Ok(text) => scrub_output_with_registry(text, registry).into_bytes(),
        Err(_) => bytes.to_vec(), // Non-UTF-8, pass through unchanged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_registry() {
        let registry = SecretRegistry::new();
        let input = "Some text with no secrets";
        let output = scrub_output_with_registry(input, &registry);
        assert_eq!(output, input);
    }

    #[test]
    fn test_multiple_occurrences() {
        let registry = SecretRegistry::new();
        registry.register("token123");

        let input = "Start token123 middle token123 end";
        let output = scrub_output_with_registry(input, &registry);
        assert_eq!(output, "Start [REDACTED] middle [REDACTED] end");
    }

    #[test]
    fn test_overlapping_secrets() {
        let registry = SecretRegistry::new();
        registry.register("mysecret");
        registry.register("secret");

        // "mysecret" should be replaced first (longer)
        let input = "This contains mysecret and also just secret";
        let output = scrub_output_with_registry(input, &registry);
        assert_eq!(output, "This contains [REDACTED] and also just [REDACTED]");
    }

    #[test]
    fn test_scrub_bytes_utf8() {
        let registry = SecretRegistry::new();
        registry.register("password");

        let input = b"Your password is password";
        let output = scrub_bytes_with_registry(input, &registry);
        assert_eq!(output, b"Your [REDACTED] is [REDACTED]");
    }

    #[test]
    fn test_scrub_bytes_non_utf8() {
        let registry = SecretRegistry::new();
        registry.register("password");

        // Invalid UTF-8 sequence
        let input: &[u8] = &[0xff, 0xfe, 0x00, 0x01];
        let output = scrub_bytes_with_registry(input, &registry);
        assert_eq!(output, input); // Should pass through unchanged
    }

    #[test]
    fn test_json_output_scrubbing() {
        let registry = SecretRegistry::new();
        registry.register("api-key-xyz123");

        let input = r#"{"token": "api-key-xyz123", "user": "test"}"#;
        let output = scrub_output_with_registry(input, &registry);
        assert_eq!(output, r#"{"token": "[REDACTED]", "user": "test"}"#);
    }

    #[test]
    fn test_multiline_scrubbing() {
        let registry = SecretRegistry::new();
        registry.register("secret-value");

        let input = "Line 1: secret-value\nLine 2: also secret-value here\nLine 3: clean";
        let output = scrub_output_with_registry(input, &registry);
        assert_eq!(
            output,
            "Line 1: [REDACTED]\nLine 2: also [REDACTED] here\nLine 3: clean"
        );
    }

    #[test]
    fn test_url_scrubbing() {
        let registry = SecretRegistry::new();
        registry.register("my-token-abc");

        let input = "https://api.example.com?token=my-token-abc&other=param";
        let output = scrub_output_with_registry(input, &registry);
        assert_eq!(
            output,
            "https://api.example.com?token=[REDACTED]&other=param"
        );
    }

    #[test]
    fn test_environment_variable_format() {
        let registry = SecretRegistry::new();
        registry.register("supersecret123");

        let input = "export API_KEY=supersecret123";
        let output = scrub_output_with_registry(input, &registry);
        assert_eq!(output, "export API_KEY=[REDACTED]");
    }

    #[test]
    fn test_named_secret_scrubbing() {
        let registry = SecretRegistry::new();
        registry.register_named("github_token", "ghp_abc123xyz");

        let input = "Token: ghp_abc123xyz";
        let output = scrub_output_with_registry(input, &registry);
        assert_eq!(output, "Token: <secret:github_token>");
    }

    #[test]
    fn test_mixed_named_and_anonymous() {
        let registry = SecretRegistry::new();
        registry.register_named("api_key", "sk-1234567890");
        registry.register("anonymous-secret");

        let input = "API: sk-1234567890, Other: anonymous-secret";
        let output = scrub_output_with_registry(input, &registry);
        assert_eq!(output, "API: <secret:api_key>, Other: [REDACTED]");
    }
}

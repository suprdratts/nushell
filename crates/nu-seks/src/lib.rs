//! # nu-seks - SEKS Security Module for Nushell
//!
//! This crate provides security features for the SEKS (Secure Execution Kernel for Shells) project,
//! a security-focused fork of nushell.
//!
//! ## Features
//!
//! - **Secret Registry**: Register sensitive values that should never appear in output
//! - **Output Scrubbing**: Automatically replace registered secrets with `<secret:name>` or `[REDACTED]`
//! - **Encoding-Aware**: Detects secrets in common encodings (base64, hex)
//! - **Broker Client**: Connect to the SEKS broker to fetch secrets
//!
//! ## Design Philosophy
//!
//! Token scrubbing is **defense-in-depth**. It's not bulletproof - a determined attacker
//! could potentially circumvent it. However, it significantly raises the bar for attacks
//! by preventing accidental token exposure in:
//!
//! - Command output accidentally logged or shared
//! - Shell history that might be synced or backed up
//! - Error messages that include sensitive context
//! - Debug output during development
//!
//! ## Usage
//!
//! ```rust
//! use nu_seks::{register_named_secret, scrub_output, clear_secrets};
//!
//! // Register a named secret token
//! register_named_secret("api_token", "my-api-token-12345");
//!
//! // Any output containing the secret will be scrubbed
//! let output = "Response: my-api-token-12345";
//! let scrubbed = scrub_output(output);
//! assert_eq!(scrubbed, "Response: <secret:api_token>");
//!
//! // Also works with base64-encoded version
//! let encoded = "bXktYXBpLXRva2VuLTEyMzQ1"; // base64 of the token
//! let output_with_encoded = format!("Token: {}", encoded);
//! let scrubbed = scrub_output(&output_with_encoded);
//! // The encoded version is also redacted
//! ```

mod broker;
mod registry;
mod scrubber;
mod writer;

pub use broker::{BrokerClient, BrokerError};
pub use registry::{
    clear_secrets, register_named_secret, register_secret, secret_count, SecretRegistry,
    GLOBAL_REGISTRY,
};
pub use scrubber::{scrub_bytes, scrub_bytes_with_registry, scrub_output, scrub_output_with_registry};
pub use writer::ScrubWriter;

/// The default redaction marker used to replace anonymous secrets in output
pub const REDACTION_MARKER: &str = "[REDACTED]";

/// Minimum length for a secret to be registered.
/// Shorter strings would cause too many false positives.
pub const MIN_SECRET_LENGTH: usize = 4;

/// Default path for the broker socket
pub const DEFAULT_BROKER_SOCKET: &str = "~/.seksh/broker.sock";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_scrubbing() {
        let registry = SecretRegistry::new();
        registry.register("secret123");

        let input = "The password is secret123 and here it is again: secret123";
        let output = scrub_output_with_registry(input, &registry);

        assert_eq!(
            output,
            "The password is [REDACTED] and here it is again: [REDACTED]"
        );
    }

    #[test]
    fn test_no_secrets() {
        let registry = SecretRegistry::new();
        let input = "This has no secrets";
        let output = scrub_output_with_registry(input, &registry);
        assert_eq!(output, input);
    }

    #[test]
    fn test_base64_encoding() {
        let registry = SecretRegistry::new();
        registry.register("my-secret-token");

        // "my-secret-token" in base64
        let input = "Encoded: bXktc2VjcmV0LXRva2Vu";
        let output = scrub_output_with_registry(input, &registry);

        assert_eq!(output, "Encoded: [REDACTED]");
    }

    #[test]
    fn test_hex_encoding() {
        let registry = SecretRegistry::new();
        registry.register("secret");

        // "secret" in hex (lowercase)
        let input = "Hex value: 736563726574";
        let output = scrub_output_with_registry(input, &registry);

        assert_eq!(output, "Hex value: [REDACTED]");
    }

    #[test]
    fn test_min_length_enforcement() {
        let registry = SecretRegistry::new();
        // Too short, should not be registered
        registry.register("abc");
        assert_eq!(registry.count(), 0);

        // Long enough, should be registered
        registry.register("abcd");
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_clear_secrets() {
        let registry = SecretRegistry::new();
        registry.register("secret1");
        registry.register("secret2");
        assert_eq!(registry.count(), 2);

        registry.clear();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_global_registry() {
        clear_secrets();
        register_secret("global-test-secret");

        let input = "Contains global-test-secret here";
        let output = scrub_output(input);

        assert_eq!(output, "Contains [REDACTED] here");
        clear_secrets();
    }

    #[test]
    fn test_named_secret() {
        clear_secrets();
        register_named_secret("test_token", "my-secret-value");

        let input = "Token: my-secret-value";
        let output = scrub_output(input);

        assert_eq!(output, "Token: <secret:test_token>");
        clear_secrets();
    }
}

//! Scrubbing Writer - A Write implementation that scrubs secrets
//!
//! This provides a wrapper around any `Write` implementation that automatically
//! scrubs registered secrets from the output.
//!
//! # Implementation Notes
//!
//! For streaming output, we face a challenge: secrets might be split across
//! write boundaries. The current implementation uses line-based buffering
//! for text output, which handles most common cases while keeping memory
//! usage bounded.
//!
//! For binary output, data is passed through unchanged.

use crate::registry::{GLOBAL_REGISTRY, SecretRegistry};
use crate::scrubber::scrub_output_with_registry;
use std::io::{self, Write};

/// A writer that scrubs secrets from output before writing to the inner writer.
///
/// This wraps any `Write` implementation and ensures registered secrets are
/// replaced with `[REDACTED]` before being written.
///
/// # Line Buffering
///
/// To handle secrets that might span write boundaries, this writer buffers
/// output until a newline is encountered, then scrubs and flushes the line.
/// This works well for most shell output which is line-oriented.
///
/// # Example
///
/// ```rust,ignore
/// use nu_seks::{ScrubWriter, register_secret};
/// use std::io::Write;
///
/// register_secret("my-token");
///
/// let mut output = Vec::new();
/// {
///     let mut writer = ScrubWriter::new(&mut output);
///     write!(writer, "Token: my-token\n").unwrap();
/// }
///
/// assert_eq!(String::from_utf8(output).unwrap(), "Token: [REDACTED]\n");
/// ```
pub struct ScrubWriter<'a, W: Write> {
    inner: W,
    registry: &'a SecretRegistry,
    buffer: Vec<u8>,
}

impl<'a, W: Write> ScrubWriter<'a, W> {
    /// Create a new scrubbing writer using the global secret registry.
    pub fn new(inner: W) -> ScrubWriter<'static, W> {
        ScrubWriter {
            inner,
            registry: &GLOBAL_REGISTRY,
            buffer: Vec::with_capacity(1024),
        }
    }

    /// Create a new scrubbing writer using a specific registry.
    pub fn with_registry(inner: W, registry: &'a SecretRegistry) -> Self {
        ScrubWriter {
            inner,
            registry,
            buffer: Vec::with_capacity(1024),
        }
    }

    /// Flush the internal buffer, scrubbing any secrets.
    fn flush_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        // Try to interpret as UTF-8 for scrubbing
        let scrubbed = match std::str::from_utf8(&self.buffer) {
            Ok(text) => scrub_output_with_registry(text, self.registry).into_bytes(),
            Err(_) => {
                // Binary data, pass through unchanged
                std::mem::take(&mut self.buffer)
            }
        };

        self.inner.write_all(&scrubbed)?;
        self.buffer.clear();
        Ok(())
    }

    /// Get a reference to the inner writer.
    pub fn inner(&self) -> &W {
        &self.inner
    }

    /// Get a mutable reference to the inner writer.
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Consume this writer and return the inner writer.
    ///
    /// Note: Any buffered data will be flushed (and scrubbed) first.
    pub fn into_inner(mut self) -> io::Result<W> {
        self.flush_buffer()?;
        self.inner.flush()?;

        // Use ManuallyDrop to prevent the Drop impl from running,
        // since we're consuming self and returning inner
        let this = std::mem::ManuallyDrop::new(self);

        // SAFETY: We're not running Drop, so it's safe to move inner out.
        // We use ptr::read because this is inside ManuallyDrop.
        Ok(unsafe { std::ptr::read(&this.inner) })
    }
}

impl<'a, W: Write> Write for ScrubWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Fast path: if no secrets registered, write directly
        if self.registry.count() == 0 {
            return self.inner.write(buf);
        }

        // Line-based buffering: accumulate until we see a newline
        for &byte in buf {
            self.buffer.push(byte);

            // Flush on newline to keep memory bounded and handle line-oriented output
            if byte == b'\n' {
                self.flush_buffer()?;
            }
        }

        // If buffer gets too large (e.g., no newlines), flush anyway
        // This prevents unbounded memory growth for binary/non-line output
        const MAX_BUFFER_SIZE: usize = 64 * 1024; // 64KB
        if self.buffer.len() >= MAX_BUFFER_SIZE {
            self.flush_buffer()?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer()?;
        self.inner.flush()
    }
}

impl<'a, W: Write> Drop for ScrubWriter<'a, W> {
    fn drop(&mut self) {
        // Best-effort flush on drop
        let _ = self.flush_buffer();
        let _ = self.inner.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clear_secrets;

    #[test]
    fn test_scrub_writer_basic() {
        let registry = SecretRegistry::new();
        registry.register("secret123");

        let mut output = Vec::new();
        {
            let mut writer = ScrubWriter::with_registry(&mut output, &registry);
            writer.write_all(b"Password: secret123\n").unwrap();
        }

        assert_eq!(String::from_utf8(output).unwrap(), "Password: [REDACTED]\n");
    }

    #[test]
    fn test_scrub_writer_split_across_writes() {
        let registry = SecretRegistry::new();
        registry.register("secret");

        let mut output = Vec::new();
        {
            let mut writer = ScrubWriter::with_registry(&mut output, &registry);
            // Write "secret" split across two writes, but on same line
            writer.write_all(b"The sec").unwrap();
            writer.write_all(b"ret is here\n").unwrap();
        }

        // Should be scrubbed because it's buffered until newline
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "The [REDACTED] is here\n"
        );
    }

    #[test]
    fn test_scrub_writer_no_secrets() {
        let registry = SecretRegistry::new();

        let mut output = Vec::new();
        {
            let mut writer = ScrubWriter::with_registry(&mut output, &registry);
            writer.write_all(b"Normal output\n").unwrap();
        }

        assert_eq!(String::from_utf8(output).unwrap(), "Normal output\n");
    }

    #[test]
    fn test_scrub_writer_multiple_lines() {
        let registry = SecretRegistry::new();
        registry.register("token");

        let mut output = Vec::new();
        {
            let mut writer = ScrubWriter::with_registry(&mut output, &registry);
            writer.write_all(b"Line 1: token\n").unwrap();
            writer.write_all(b"Line 2: no secrets\n").unwrap();
            writer.write_all(b"Line 3: another token\n").unwrap();
        }

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("[REDACTED]"));
        assert!(!result.contains("token"));
        assert_eq!(result.matches("[REDACTED]").count(), 2);
    }

    #[test]
    fn test_scrub_writer_global_registry() {
        clear_secrets();
        crate::register_secret("global-secret");

        let mut output = Vec::new();
        {
            let mut writer = ScrubWriter::new(&mut output);
            writer.write_all(b"Has global-secret\n").unwrap();
        }

        assert_eq!(String::from_utf8(output).unwrap(), "Has [REDACTED]\n");
        clear_secrets();
    }
}

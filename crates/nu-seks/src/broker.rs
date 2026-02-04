//! SEKS Broker Client
//!
//! Client for communicating with the SEKS broker over a Unix socket.
//! The broker holds secrets and provides them on request.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// Error types for broker operations
#[derive(Debug)]
pub enum BrokerError {
    /// Failed to connect to the broker socket
    ConnectionFailed(String),
    /// Failed to send request to broker
    SendFailed(String),
    /// Failed to receive response from broker
    ReceiveFailed(String),
    /// Broker returned an error
    BrokerError(String),
    /// Secret not found
    SecretNotFound(String),
    /// Invalid response from broker
    InvalidResponse(String),
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerError::ConnectionFailed(msg) => write!(f, "Failed to connect to broker: {}", msg),
            BrokerError::SendFailed(msg) => write!(f, "Failed to send to broker: {}", msg),
            BrokerError::ReceiveFailed(msg) => write!(f, "Failed to receive from broker: {}", msg),
            BrokerError::BrokerError(msg) => write!(f, "Broker error: {}", msg),
            BrokerError::SecretNotFound(name) => write!(f, "Secret not found: {}", name),
            BrokerError::InvalidResponse(msg) => write!(f, "Invalid broker response: {}", msg),
        }
    }
}

impl std::error::Error for BrokerError {}

/// Client for communicating with the SEKS broker
pub struct BrokerClient {
    socket_path: PathBuf,
}

impl BrokerClient {
    /// Create a new broker client with the default socket path
    pub fn new() -> Self {
        Self::with_socket_path(Self::default_socket_path())
    }

    /// Create a new broker client with a custom socket path
    pub fn with_socket_path(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Get the default socket path (~/.seksh/broker.sock)
    pub fn default_socket_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".seksh").join("broker.sock")
    }

    /// Check if the broker is running
    pub fn is_running(&self) -> bool {
        self.socket_path.exists()
            && UnixStream::connect(&self.socket_path).is_ok()
    }

    /// Get a secret from the broker
    pub fn get_secret(&self, name: &str) -> Result<String, BrokerError> {
        // Connect to the broker
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| BrokerError::ConnectionFailed(e.to_string()))?;

        // Set a timeout
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .ok();

        // Send the request as JSON
        let request = format!(r#"{{"cmd":"get","name":"{}"}}"#, name);
        stream
            .write_all(request.as_bytes())
            .map_err(|e| BrokerError::SendFailed(e.to_string()))?;
        stream
            .write_all(b"\n")
            .map_err(|e| BrokerError::SendFailed(e.to_string()))?;
        stream
            .flush()
            .map_err(|e| BrokerError::SendFailed(e.to_string()))?;

        // Read the response
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader
            .read_line(&mut response)
            .map_err(|e| BrokerError::ReceiveFailed(e.to_string()))?;

        // Parse the response
        self.parse_response(&response, name)
    }

    /// List available secrets (names only, not values)
    pub fn list_secrets(&self) -> Result<Vec<String>, BrokerError> {
        // Connect to the broker
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| BrokerError::ConnectionFailed(e.to_string()))?;

        // Set a timeout
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .ok();

        // Send the request
        let request = r#"{"cmd":"list"}"#;
        stream
            .write_all(request.as_bytes())
            .map_err(|e| BrokerError::SendFailed(e.to_string()))?;
        stream
            .write_all(b"\n")
            .map_err(|e| BrokerError::SendFailed(e.to_string()))?;
        stream
            .flush()
            .map_err(|e| BrokerError::SendFailed(e.to_string()))?;

        // Read the response
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader
            .read_line(&mut response)
            .map_err(|e| BrokerError::ReceiveFailed(e.to_string()))?;

        // Parse the response - expect {"names": ["foo", "bar"]}
        self.parse_list_response(&response)
    }

    fn parse_response(&self, response: &str, name: &str) -> Result<String, BrokerError> {
        let response = response.trim();

        // Simple JSON parsing without external dependencies
        // Expected format: {"value": "secret"} or {"error": "message"}

        if response.contains("\"error\"") {
            // Extract error message
            if let Some(start) = response.find("\"error\":") {
                let rest = &response[start + 8..];
                if let Some(value) = extract_json_string(rest) {
                    if value.contains("not found") {
                        return Err(BrokerError::SecretNotFound(name.to_string()));
                    }
                    return Err(BrokerError::BrokerError(value));
                }
            }
            return Err(BrokerError::InvalidResponse(response.to_string()));
        }

        if response.contains("\"value\"") {
            if let Some(start) = response.find("\"value\":") {
                let rest = &response[start + 8..];
                if let Some(value) = extract_json_string(rest) {
                    return Ok(value);
                }
            }
        }

        Err(BrokerError::InvalidResponse(response.to_string()))
    }

    fn parse_list_response(&self, response: &str) -> Result<Vec<String>, BrokerError> {
        let response = response.trim();

        if response.contains("\"error\"") {
            if let Some(start) = response.find("\"error\":") {
                let rest = &response[start + 8..];
                if let Some(value) = extract_json_string(rest) {
                    return Err(BrokerError::BrokerError(value));
                }
            }
            return Err(BrokerError::InvalidResponse(response.to_string()));
        }

        // Extract names array - simple parsing
        // Expected: {"names":["foo","bar"]}
        if let Some(start) = response.find("\"names\":") {
            let rest = &response[start + 8..];
            if let Some(array_start) = rest.find('[') {
                let array_rest = &rest[array_start + 1..];
                if let Some(array_end) = array_rest.find(']') {
                    let array_content = &array_rest[..array_end];
                    let names: Vec<String> = array_content
                        .split(',')
                        .filter_map(|s| {
                            let s = s.trim();
                            if s.starts_with('"') && s.ends_with('"') && s.len() > 2 {
                                Some(s[1..s.len() - 1].to_string())
                            } else if s.is_empty() {
                                None
                            } else {
                                None
                            }
                        })
                        .collect();
                    return Ok(names);
                }
            }
        }

        Err(BrokerError::InvalidResponse(response.to_string()))
    }
}

impl Default for BrokerClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a JSON string value (handles basic escaping)
fn extract_json_string(s: &str) -> Option<String> {
    let s = s.trim();
    if !s.starts_with('"') {
        return None;
    }

    let mut result = String::new();
    let mut chars = s[1..].chars();
    let mut escaped = false;

    while let Some(c) = chars.next() {
        if escaped {
            match c {
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                '"' => result.push('"'),
                '\\' => result.push('\\'),
                _ => {
                    result.push('\\');
                    result.push(c);
                }
            }
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Some(result);
        } else {
            result.push(c);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_string() {
        assert_eq!(extract_json_string(r#""hello""#), Some("hello".to_string()));
        assert_eq!(
            extract_json_string(r#""hello world""#),
            Some("hello world".to_string())
        );
        assert_eq!(
            extract_json_string(r#""with \"quotes\"""#),
            Some("with \"quotes\"".to_string())
        );
        assert_eq!(
            extract_json_string(r#""line\nbreak""#),
            Some("line\nbreak".to_string())
        );
        assert_eq!(extract_json_string("not a string"), None);
    }

    #[test]
    fn test_default_socket_path() {
        let path = BrokerClient::default_socket_path();
        assert!(path.to_string_lossy().contains(".seksh"));
        assert!(path.to_string_lossy().contains("broker.sock"));
    }
}

//! SEKS Broker Client
//!
//! Client for communicating with the SEKS broker over HTTP REST API.
//! The broker holds secrets and provides them on request.
//!
//! Configuration via environment variables:
//! - SEKS_BROKER_URL: Base URL of the broker (default: http://localhost:8787)
//! - SEKS_AGENT_TOKEN: Bearer token for authentication (required)

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Default broker URL for local development
const DEFAULT_BROKER_URL: &str = "http://localhost:8787";

/// Error types for broker operations
#[derive(Debug)]
pub enum BrokerError {
    /// No agent token configured
    NoToken,
    /// Failed to connect to the broker
    ConnectionFailed(String),
    /// Failed to send request to broker
    RequestFailed(String),
    /// Broker returned an error
    BrokerError(String),
    /// Secret not found
    SecretNotFound(String),
    /// Invalid response from broker
    InvalidResponse(String),
    /// HTTP error status
    HttpError(u16, String),
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerError::NoToken => write!(f, "SEKS_AGENT_TOKEN not set"),
            BrokerError::ConnectionFailed(msg) => write!(f, "Failed to connect to broker: {}", msg),
            BrokerError::RequestFailed(msg) => write!(f, "Request failed: {}", msg),
            BrokerError::BrokerError(msg) => write!(f, "Broker error: {}", msg),
            BrokerError::SecretNotFound(name) => write!(f, "Secret not found: {}", name),
            BrokerError::InvalidResponse(msg) => write!(f, "Invalid broker response: {}", msg),
            BrokerError::HttpError(code, msg) => write!(f, "HTTP {}: {}", code, msg),
        }
    }
}

impl std::error::Error for BrokerError {}

// ─── Request/Response Types ────────────────────────────────────────────────────

#[derive(Serialize)]
struct GetSecretRequest<'a> {
    name: &'a str,
}

#[derive(Deserialize)]
struct GetSecretResponse {
    ok: bool,
    value: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct ListSecretsResponse {
    ok: bool,
    secrets: Option<Vec<SecretInfo>>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct SecretInfo {
    name: String,
    #[allow(dead_code)]
    provider: Option<String>,
}

// ─── Broker Client ─────────────────────────────────────────────────────────────

/// Client for communicating with the SEKS broker via HTTP
pub struct BrokerClient {
    broker_url: String,
    agent_token: Option<String>,
    agent: ureq::Agent,
}

impl BrokerClient {
    /// Create a new broker client using environment variables
    pub fn new() -> Self {
        let broker_url =
            std::env::var("SEKS_BROKER_URL").unwrap_or_else(|_| DEFAULT_BROKER_URL.to_string());
        let agent_token = std::env::var("SEKS_AGENT_TOKEN").ok();

        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build();

        Self {
            broker_url,
            agent_token,
            agent,
        }
    }

    /// Create a new broker client with explicit configuration
    pub fn with_config(broker_url: String, agent_token: String) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build();
        
        Self {
            broker_url,
            agent_token: Some(agent_token),
            agent,
        }
    }

    /// Check if the broker is reachable
    pub fn is_running(&self) -> bool {
        let url = format!("{}/v1/health", self.broker_url);
        self.agent.get(&url).call().is_ok()
    }

    /// Get a secret from the broker
    pub fn get_secret(&self, name: &str) -> Result<String, BrokerError> {
        let token = self.agent_token.as_ref().ok_or(BrokerError::NoToken)?;

        let url = format!("{}/v1/secrets/get", self.broker_url);
        let request = GetSecretRequest { name };

        let response = self
            .agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("Content-Type", "application/json")
            .send_json(&request)
            .map_err(|e| match e {
                ureq::Error::Status(code, resp) => {
                    let body = resp.into_string().unwrap_or_default();
                    BrokerError::HttpError(code, body)
                }
                ureq::Error::Transport(t) => BrokerError::ConnectionFailed(t.to_string()),
            })?;

        let resp: GetSecretResponse = response
            .into_json()
            .map_err(|e| BrokerError::InvalidResponse(e.to_string()))?;
        
        if resp.ok {
            resp.value
                .ok_or_else(|| BrokerError::InvalidResponse("Missing value".to_string()))
        } else {
            let error = resp.error.unwrap_or_else(|| "Unknown error".to_string());
            if error.contains("not found") {
                Err(BrokerError::SecretNotFound(name.to_string()))
            } else {
                Err(BrokerError::BrokerError(error))
            }
        }
    }

    /// List available secrets (names only, not values)
    pub fn list_secrets(&self) -> Result<Vec<String>, BrokerError> {
        let token = self.agent_token.as_ref().ok_or(BrokerError::NoToken)?;

        let url = format!("{}/v1/secrets/list", self.broker_url);
        
        let response = self
            .agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", token))
            .set("Content-Type", "application/json")
            .send_string("{}")
            .map_err(|e| match e {
                ureq::Error::Status(code, resp) => {
                    let body = resp.into_string().unwrap_or_default();
                    BrokerError::HttpError(code, body)
                }
                ureq::Error::Transport(t) => BrokerError::ConnectionFailed(t.to_string()),
            })?;

        let resp: ListSecretsResponse = response
            .into_json()
            .map_err(|e| BrokerError::InvalidResponse(e.to_string()))?;

        if resp.ok {
            let secrets = resp.secrets.unwrap_or_default();
            Ok(secrets.into_iter().map(|s| s.name).collect())
        } else {
            let error = resp.error.unwrap_or_else(|| "Unknown error".to_string());
            Err(BrokerError::BrokerError(error))
        }
    }

    /// Get the configured broker URL
    pub fn broker_url(&self) -> &str {
        &self.broker_url
    }

    /// Check if a token is configured
    pub fn has_token(&self) -> bool {
        self.agent_token.is_some()
    }
}

impl Default for BrokerClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_broker_url() {
        // Clear env vars for test
        std::env::remove_var("SEKS_BROKER_URL");
        std::env::remove_var("SEKS_AGENT_TOKEN");

        let client = BrokerClient::new();
        assert_eq!(client.broker_url(), DEFAULT_BROKER_URL);
        assert!(!client.has_token());
    }

    #[test]
    fn test_with_config() {
        let client = BrokerClient::with_config(
            "https://broker.example.com".to_string(),
            "test_token".to_string(),
        );
        assert_eq!(client.broker_url(), "https://broker.example.com");
        assert!(client.has_token());
    }

    #[test]
    fn test_no_token_error() {
        std::env::remove_var("SEKS_AGENT_TOKEN");
        let client = BrokerClient::new();
        let result = client.get_secret("TEST");
        assert!(matches!(result, Err(BrokerError::NoToken)));
    }
}

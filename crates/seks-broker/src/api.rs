//! REST API handlers for agents

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{auth, AppState};

// ─── Types ─────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

#[derive(Deserialize)]
pub struct SecretGetRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct SecretGetResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct SecretInfo {
    pub name: String,
    pub provider: String,
}

#[derive(Serialize)]
pub struct SecretListResponse {
    pub ok: bool,
    pub secrets: Vec<SecretInfo>,
}

#[derive(Deserialize)]
pub struct ProxyRequest {
    pub service: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub body: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct ProxyResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ─── Handlers ──────────────────────────────────────────────────────────────────

/// Health check endpoint
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Get a secret value
pub async fn secrets_get(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SecretGetRequest>,
) -> impl IntoResponse {
    // Authenticate
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    
    let agent = match auth::authenticate_agent(&state, auth_header).await {
        Some(a) => a,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SecretGetResponse {
                    ok: false,
                    value: None,
                    error: Some("Unauthorized".to_string()),
                }),
            );
        }
    };

    // Get secret
    let secret = match state.db.get_secret(&agent.client_id, &req.name).await {
        Ok(s) => s,
        Err(_) => {
            // Log failed access
            let _ = state.db.log_audit(
                &agent.client_id,
                Some(&agent.id),
                "secret.get",
                Some(&req.name),
                "not_found",
                None,
                None,
            ).await;

            return (
                StatusCode::NOT_FOUND,
                Json(SecretGetResponse {
                    ok: false,
                    value: None,
                    error: Some(format!("Secret '{}' not found", req.name)),
                }),
            );
        }
    };

    // Decrypt
    let value = match state.crypto.decrypt_from_base64(&secret.encrypted_value) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SecretGetResponse {
                    ok: false,
                    value: None,
                    error: Some("Failed to decrypt secret".to_string()),
                }),
            );
        }
    };

    // Log access
    let _ = state.db.log_audit(
        &agent.client_id,
        Some(&agent.id),
        "secret.get",
        Some(&req.name),
        "success",
        None,
        None,
    ).await;

    (
        StatusCode::OK,
        Json(SecretGetResponse {
            ok: true,
            value: Some(value),
            error: None,
        }),
    )
}

/// List available secrets
pub async fn secrets_list(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    // Authenticate
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    
    let agent = match auth::authenticate_agent(&state, auth_header).await {
        Some(a) => a,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SecretListResponse {
                    ok: false,
                    secrets: vec![],
                }),
            );
        }
    };

    // List secrets
    let secrets = state.db.list_secrets(&agent.client_id).await.unwrap_or_default();
    
    let secret_infos: Vec<SecretInfo> = secrets
        .into_iter()
        .map(|s| SecretInfo {
            name: s.name,
            provider: s.provider,
        })
        .collect();

    // Log access
    let _ = state.db.log_audit(
        &agent.client_id,
        Some(&agent.id),
        "secret.list",
        None,
        "success",
        None,
        None,
    ).await;

    (
        StatusCode::OK,
        Json(SecretListResponse {
            ok: true,
            secrets: secret_infos,
        }),
    )
}

/// Proxy a request with credential injection
pub async fn proxy_request(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ProxyRequest>,
) -> impl IntoResponse {
    // Authenticate
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    
    let agent = match auth::authenticate_agent(&state, auth_header).await {
        Some(a) => a,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ProxyResponse {
                    ok: false,
                    status: None,
                    body: None,
                    error: Some("Unauthorized".to_string()),
                }),
            );
        }
    };

    // Get the appropriate secret for this service
    let secret_name = match req.service.as_str() {
        "openai" => "OPENAI_API_KEY",
        "anthropic" => "ANTHROPIC_API_KEY",
        "claude" => "ANTHROPIC_API_KEY",
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ProxyResponse {
                    ok: false,
                    status: None,
                    body: None,
                    error: Some(format!("Unknown service: {}", req.service)),
                }),
            );
        }
    };

    let secret = match state.db.get_secret(&agent.client_id, secret_name).await {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ProxyResponse {
                    ok: false,
                    status: None,
                    body: None,
                    error: Some(format!("No {} configured", secret_name)),
                }),
            );
        }
    };

    let api_key = match state.crypto.decrypt_from_base64(&secret.encrypted_value) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ProxyResponse {
                    ok: false,
                    status: None,
                    body: None,
                    error: Some("Failed to decrypt secret".to_string()),
                }),
            );
        }
    };

    // Build the upstream URL
    let base_url = match req.service.as_str() {
        "openai" => "https://api.openai.com",
        "anthropic" | "claude" => "https://api.anthropic.com",
        _ => unreachable!(),
    };
    let url = format!("{}{}", base_url, req.path);

    // Build the request
    let client = reqwest::Client::new();
    let mut request_builder = match req.method.to_uppercase().as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "PATCH" => client.patch(&url),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ProxyResponse {
                    ok: false,
                    status: None,
                    body: None,
                    error: Some(format!("Unsupported method: {}", req.method)),
                }),
            );
        }
    };

    // Add auth header based on service
    request_builder = match req.service.as_str() {
        "openai" => request_builder.header("Authorization", format!("Bearer {}", api_key)),
        "anthropic" | "claude" => request_builder
            .header("x-api-key", &api_key)
            .header("anthropic-version", "2023-06-01"),
        _ => request_builder,
    };

    // Add content-type for POST/PUT/PATCH
    if req.body.is_some() {
        request_builder = request_builder.header("Content-Type", "application/json");
    }

    // Add custom headers
    for (key, value) in &req.headers {
        // Don't allow overriding auth headers
        if key.to_lowercase() != "authorization" && key.to_lowercase() != "x-api-key" {
            request_builder = request_builder.header(key, value);
        }
    }

    // Add body
    if let Some(body) = req.body {
        request_builder = request_builder.json(&body);
    }

    // Execute request
    let response = match request_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            // Log error
            let _ = state.db.log_audit(
                &agent.client_id,
                Some(&agent.id),
                "proxy.request",
                Some(&req.service),
                "error",
                None,
                Some(&format!("Request failed: {}", e)),
            ).await;

            return (
                StatusCode::BAD_GATEWAY,
                Json(ProxyResponse {
                    ok: false,
                    status: None,
                    body: None,
                    error: Some(format!("Request failed: {}", e)),
                }),
            );
        }
    };

    let status = response.status().as_u16();
    let body: Option<serde_json::Value> = response.json().await.ok();

    // Log success
    let _ = state.db.log_audit(
        &agent.client_id,
        Some(&agent.id),
        "proxy.request",
        Some(&req.service),
        "success",
        None,
        Some(&format!("status={}", status)),
    ).await;

    (
        StatusCode::OK,
        Json(ProxyResponse {
            ok: status >= 200 && status < 300,
            status: Some(status),
            body,
            error: None,
        }),
    )
}

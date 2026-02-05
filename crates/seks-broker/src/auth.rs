//! Authentication utilities

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use axum_extra::extract::CookieJar;

use crate::{db::Agent, AppState};

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Extract bearer token from Authorization header
pub fn extract_bearer_token(auth_header: Option<&str>) -> Option<&str> {
    auth_header?
        .strip_prefix("Bearer ")
        .or_else(|| auth_header?.strip_prefix("bearer "))
}

/// Authenticate an agent from request headers
pub async fn authenticate_agent(state: &AppState, auth_header: Option<&str>) -> Option<Agent> {
    let token = extract_bearer_token(auth_header)?;
    
    match state.db.get_agent_by_token(token).await {
        Ok(agent) => {
            // Update last seen (fire and forget)
            let _ = state.db.update_agent_last_seen(&agent.id).await;
            Some(agent)
        }
        Err(_) => None,
    }
}

/// Get client ID from session cookie (for web UI)
pub async fn get_session_client(state: &AppState, cookies: &CookieJar) -> Option<String> {
    let session_id = cookies.get("session")?.value();
    let session = state.db.get_session(session_id).await.ok()?;
    Some(session.client_id)
}

/// Middleware to require agent authentication
pub async fn require_agent_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    if authenticate_agent(&state, auth_header).await.is_some() {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_verify() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();
        
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(
            extract_bearer_token(Some("Bearer abc123")),
            Some("abc123")
        );
        assert_eq!(
            extract_bearer_token(Some("bearer xyz")),
            Some("xyz")
        );
        assert_eq!(extract_bearer_token(Some("Basic abc")), None);
        assert_eq!(extract_bearer_token(None), None);
    }
}

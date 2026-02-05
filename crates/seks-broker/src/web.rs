//! Web UI handlers for human administration

use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::CookieJar;
use cookie::Cookie;
use serde::Deserialize;

use crate::{auth, crypto, db::AuditEntry, AppState};

// ─── Templates ─────────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    client_name: String,
    secret_count: usize,
    agent_count: usize,
    recent_activity: Vec<AuditEntry>,
}

#[derive(Template)]
#[template(path = "secrets.html")]
struct SecretsTemplate {
    secrets: Vec<SecretView>,
}

#[derive(Template)]
#[template(path = "secrets_add.html")]
struct SecretsAddTemplate {
    error: Option<String>,
    providers: Vec<ProviderOption>,
}

#[derive(Template)]
#[template(path = "agents.html")]
struct AgentsTemplate {
    agents: Vec<AgentView>,
}

#[derive(Template)]
#[template(path = "activity.html")]
struct ActivityTemplate {
    entries: Vec<AuditEntry>,
}

// ─── View Models ───────────────────────────────────────────────────────────────

struct SecretView {
    id: String,
    name: String,
    provider: String,
    created_at: String,
}

struct AgentView {
    id: String,
    name: String,
    token_preview: String,
    created_at: String,
    last_seen: String,
}

struct ProviderOption {
    value: &'static str,
    label: &'static str,
}

const PROVIDERS: &[ProviderOption] = &[
    ProviderOption { value: "anthropic", label: "Anthropic (Claude)" },
    ProviderOption { value: "openai", label: "OpenAI" },
    ProviderOption { value: "google", label: "Google AI" },
    ProviderOption { value: "smtp", label: "SMTP (Email)" },
    ProviderOption { value: "twilio", label: "Twilio" },
    ProviderOption { value: "other", label: "Other" },
];

// ─── Form Data ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginForm {
    email: String,
    password: String,
}

#[derive(Deserialize)]
pub struct SecretAddForm {
    name: String,
    provider: String,
    value: String,
}

#[derive(Deserialize)]
pub struct AgentAddForm {
    name: String,
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

fn render_template<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Template error: {}", e),
        )
            .into_response(),
    }
}

async fn require_login(state: &AppState, cookies: &CookieJar) -> Result<String, Redirect> {
    match auth::get_session_client(state, cookies).await {
        Some(client_id) => Ok(client_id),
        None => Err(Redirect::to("/login")),
    }
}

// ─── Handlers ──────────────────────────────────────────────────────────────────

/// Landing page
pub async fn index() -> impl IntoResponse {
    render_template(IndexTemplate)
}

/// Login page
pub async fn login_page() -> impl IntoResponse {
    render_template(LoginTemplate { error: None })
}

/// Login form submission
pub async fn login_submit(
    State(state): State<AppState>,
    cookies: CookieJar,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    // Try to get client by email
    let client = match state.db.get_client_by_email(&form.email).await {
        Ok(c) => c,
        Err(_) => {
            // Create new client if doesn't exist (for MVP, auto-register)
            let password_hash = match auth::hash_password(&form.password) {
                Ok(h) => h,
                Err(_) => {
                    return (
                        cookies,
                        render_template(LoginTemplate {
                            error: Some("Failed to process password".to_string()),
                        }),
                    );
                }
            };
            
            match state.db.create_client(&form.email, &password_hash, None).await {
                Ok(c) => c,
                Err(_) => {
                    return (
                        cookies,
                        render_template(LoginTemplate {
                            error: Some("Failed to create account".to_string()),
                        }),
                    );
                }
            }
        }
    };

    // Verify password
    match auth::verify_password(&form.password, &client.password_hash) {
        Ok(true) => {}
        _ => {
            return (
                cookies,
                render_template(LoginTemplate {
                    error: Some("Invalid email or password".to_string()),
                }),
            );
        }
    }

    // Create session
    let session = match state.db.create_session(&client.id).await {
        Ok(s) => s,
        Err(_) => {
            return (
                cookies,
                render_template(LoginTemplate {
                    error: Some("Failed to create session".to_string()),
                }),
            );
        }
    };

    // Set session cookie
    let cookie = Cookie::build(("session", session.id))
        .path("/")
        .http_only(true)
        .same_site(cookie::SameSite::Lax);

    let cookies = cookies.add(cookie);

    (cookies, Redirect::to("/dashboard").into_response())
}

/// Logout
pub async fn logout(State(state): State<AppState>, cookies: CookieJar) -> impl IntoResponse {
    if let Some(session_cookie) = cookies.get("session") {
        let _ = state.db.delete_session(session_cookie.value()).await;
    }

    let cookies = cookies.remove(Cookie::from("session"));
    (cookies, Redirect::to("/login"))
}

/// Dashboard
pub async fn dashboard(State(state): State<AppState>, cookies: CookieJar) -> impl IntoResponse {
    let client_id = match require_login(&state, &cookies).await {
        Ok(id) => id,
        Err(redirect) => return redirect.into_response(),
    };

    let client = state.db.get_client_by_id(&client_id).await.ok();
    let secrets = state.db.list_secrets(&client_id).await.unwrap_or_default();
    let agents = state.db.list_agents(&client_id).await.unwrap_or_default();
    let activity = state.db.list_audit(&client_id, 5).await.unwrap_or_default();

    render_template(DashboardTemplate {
        client_name: client
            .and_then(|c| c.name)
            .unwrap_or_else(|| "User".to_string()),
        secret_count: secrets.len(),
        agent_count: agents.len(),
        recent_activity: activity,
    })
}

/// List secrets
pub async fn secrets_list(State(state): State<AppState>, cookies: CookieJar) -> impl IntoResponse {
    let client_id = match require_login(&state, &cookies).await {
        Ok(id) => id,
        Err(redirect) => return redirect.into_response(),
    };

    let secrets = state.db.list_secrets(&client_id).await.unwrap_or_default();
    
    let secret_views: Vec<SecretView> = secrets
        .into_iter()
        .map(|s| SecretView {
            id: s.id,
            name: s.name,
            provider: s.provider,
            created_at: s.created_at.format("%Y-%m-%d %H:%M").to_string(),
        })
        .collect();

    render_template(SecretsTemplate { secrets: secret_views })
}

/// Add secret page
pub async fn secrets_add_page(
    State(state): State<AppState>,
    cookies: CookieJar,
) -> impl IntoResponse {
    if require_login(&state, &cookies).await.is_err() {
        return Redirect::to("/login").into_response();
    }

    render_template(SecretsAddTemplate {
        error: None,
        providers: PROVIDERS.to_vec(),
    })
}

/// Add secret form submission
pub async fn secrets_add_submit(
    State(state): State<AppState>,
    cookies: CookieJar,
    Form(form): Form<SecretAddForm>,
) -> impl IntoResponse {
    let client_id = match require_login(&state, &cookies).await {
        Ok(id) => id,
        Err(redirect) => return redirect.into_response(),
    };

    // Validate
    if form.name.is_empty() || form.value.is_empty() {
        return render_template(SecretsAddTemplate {
            error: Some("Name and value are required".to_string()),
            providers: PROVIDERS.to_vec(),
        });
    }

    // Encrypt the value
    let encrypted = match state.crypto.encrypt_to_base64(&form.value) {
        Ok(e) => e,
        Err(_) => {
            return render_template(SecretsAddTemplate {
                error: Some("Failed to encrypt secret".to_string()),
                providers: PROVIDERS.to_vec(),
            });
        }
    };

    // Store
    match state.db.create_secret(&client_id, &form.name, &form.provider, &encrypted).await {
        Ok(_) => Redirect::to("/secrets").into_response(),
        Err(_) => render_template(SecretsAddTemplate {
            error: Some("Failed to save secret (may already exist)".to_string()),
            providers: PROVIDERS.to_vec(),
        }),
    }
}

/// Delete secret
pub async fn secrets_delete(
    State(state): State<AppState>,
    cookies: CookieJar,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let client_id = match require_login(&state, &cookies).await {
        Ok(id) => id,
        Err(redirect) => return redirect.into_response(),
    };

    let _ = state.db.delete_secret(&id, &client_id).await;
    Redirect::to("/secrets").into_response()
}

/// List agents
pub async fn agents_list(State(state): State<AppState>, cookies: CookieJar) -> impl IntoResponse {
    let client_id = match require_login(&state, &cookies).await {
        Ok(id) => id,
        Err(redirect) => return redirect.into_response(),
    };

    let agents = state.db.list_agents(&client_id).await.unwrap_or_default();
    
    let agent_views: Vec<AgentView> = agents
        .into_iter()
        .map(|a| AgentView {
            id: a.id,
            name: a.name,
            token_preview: format!("{}...{}", &a.token[..12], &a.token[a.token.len()-4..]),
            created_at: a.created_at.format("%Y-%m-%d %H:%M").to_string(),
            last_seen: a
                .last_seen_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Never".to_string()),
        })
        .collect();

    render_template(AgentsTemplate { agents: agent_views })
}

/// Add agent
pub async fn agents_add(
    State(state): State<AppState>,
    cookies: CookieJar,
    Form(form): Form<AgentAddForm>,
) -> impl IntoResponse {
    let client_id = match require_login(&state, &cookies).await {
        Ok(id) => id,
        Err(redirect) => return redirect.into_response(),
    };

    let token = crypto::generate_token("seks_agent");
    let _ = state.db.create_agent(&client_id, &form.name, &token).await;

    Redirect::to("/agents").into_response()
}

/// Delete agent
pub async fn agents_delete(
    State(state): State<AppState>,
    cookies: CookieJar,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let client_id = match require_login(&state, &cookies).await {
        Ok(id) => id,
        Err(redirect) => return redirect.into_response(),
    };

    let _ = state.db.delete_agent(&id, &client_id).await;
    Redirect::to("/agents").into_response()
}

/// Activity log
pub async fn activity_log(State(state): State<AppState>, cookies: CookieJar) -> impl IntoResponse {
    let client_id = match require_login(&state, &cookies).await {
        Ok(id) => id,
        Err(redirect) => return redirect.into_response(),
    };

    let entries = state.db.list_audit(&client_id, 100).await.unwrap_or_default();
    render_template(ActivityTemplate { entries })
}

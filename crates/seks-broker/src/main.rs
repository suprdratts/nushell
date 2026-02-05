//! SEKS Broker - Cloud-native secret management for AI agents
//!
//! A REST service that:
//! - Stores client API keys (encrypted at rest)
//! - Provides secrets to authenticated agents
//! - Proxies requests with credential injection
//! - Offers a web UI for key management

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use clap::Parser;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod auth;
mod crypto;
mod db;
mod web;

pub use db::Database;

/// SEKS Broker - Secret management for AI agents
#[derive(Parser, Debug)]
#[command(name = "seks-broker")]
#[command(about = "Cloud-native secret management for AI agents")]
struct Args {
    /// Address to bind to
    #[arg(short, long, default_value = "127.0.0.1:9443")]
    addr: String,

    /// Database path
    #[arg(short, long, default_value = "~/.seks/broker.db")]
    database: String,

    /// Master encryption key (hex-encoded, 32 bytes)
    /// In production, this should come from KMS/HSM
    #[arg(long, env = "SEKS_MASTER_KEY")]
    master_key: Option<String>,
}

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub crypto: Arc<crypto::Crypto>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "seks_broker=info,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load .env if present
    let _ = dotenvy::dotenv();

    // Parse CLI args
    let args = Args::parse();

    // Expand ~ in database path
    let db_path = shellexpand::tilde(&args.database).to_string();
    
    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(&db_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Initialize or generate master key
    let master_key = match args.master_key {
        Some(key) => {
            let bytes = hex::decode(&key)?;
            if bytes.len() != 32 {
                anyhow::bail!("Master key must be 32 bytes (64 hex characters)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => {
            tracing::warn!("No master key provided, generating ephemeral key");
            tracing::warn!("Data will not persist across restarts!");
            crypto::Crypto::generate_key()
        }
    };

    // Initialize crypto
    let crypto = Arc::new(crypto::Crypto::new(master_key));

    // Initialize database
    tracing::info!("Opening database at {}", db_path);
    let db = Arc::new(Database::new(&db_path).await?);
    db.migrate().await?;

    // Create app state
    let state = AppState { db, crypto };

    // Build router
    let app = Router::new()
        // API routes
        .route("/v1/health", get(api::health))
        .route("/v1/secrets/get", post(api::secrets_get))
        .route("/v1/secrets/list", post(api::secrets_list))
        .route("/v1/proxy/request", post(api::proxy_request))
        // Web UI routes
        .route("/", get(web::index))
        .route("/login", get(web::login_page).post(web::login_submit))
        .route("/logout", post(web::logout))
        .route("/dashboard", get(web::dashboard))
        .route("/secrets", get(web::secrets_list))
        .route("/secrets/add", get(web::secrets_add_page).post(web::secrets_add_submit))
        .route("/secrets/:id/delete", post(web::secrets_delete))
        .route("/agents", get(web::agents_list))
        .route("/agents/add", post(web::agents_add))
        .route("/agents/:id/delete", post(web::agents_delete))
        .route("/activity", get(web::activity_log))
        // Static files
        .nest_service("/static", tower_http::services::ServeDir::new("static"))
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Start server
    let addr: SocketAddr = args.addr.parse()?;
    tracing::info!("SEKS Broker listening on http://{}", addr);
    
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

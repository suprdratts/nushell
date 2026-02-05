//! Database layer for SEKS Broker

use chrono::{DateTime, Utc};
use sqlx::{sqlite::SqlitePoolOptions, FromRow, SqlitePool};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("Not found")]
    NotFound,
}

/// Client (human user who owns API keys)
#[derive(Debug, Clone, FromRow)]
pub struct Client {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Agent (AI agent that accesses secrets)
#[derive(Debug, Clone, FromRow)]
pub struct Agent {
    pub id: String,
    pub client_id: String,
    pub name: String,
    pub token: String,          // Bearer token for API auth
    pub scopes: String,         // JSON array of allowed scopes
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Secret (encrypted API key or credential)
#[derive(Debug, Clone, FromRow)]
pub struct Secret {
    pub id: String,
    pub client_id: String,
    pub name: String,           // e.g., "OPENAI_API_KEY"
    pub provider: String,       // e.g., "openai", "anthropic"
    pub encrypted_value: String, // Base64-encoded encrypted value
    pub metadata: Option<String>, // JSON metadata (labels, etc.)
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Audit log entry
#[derive(Debug, Clone, FromRow)]
pub struct AuditEntry {
    pub id: String,
    pub client_id: String,
    pub agent_id: Option<String>,
    pub action: String,         // e.g., "secret.get", "proxy.request"
    pub resource: Option<String>, // e.g., secret name
    pub status: String,         // "success" or "error"
    pub ip_address: Option<String>,
    pub details: Option<String>, // JSON details
    pub created_at: DateTime<Utc>,
}

/// Session for web UI auth
#[derive(Debug, Clone, FromRow)]
pub struct Session {
    pub id: String,
    pub client_id: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(path: &str) -> Result<Self, DbError> {
        let url = format!("sqlite:{}?mode=rwc", path);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await?;
        
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<(), DbError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES clients(id),
                name TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                scopes TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen_at TEXT
            );

            CREATE TABLE IF NOT EXISTS secrets (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES clients(id),
                name TEXT NOT NULL,
                provider TEXT NOT NULL,
                encrypted_value TEXT NOT NULL,
                metadata TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                UNIQUE(client_id, name)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                agent_id TEXT,
                action TEXT NOT NULL,
                resource TEXT,
                status TEXT NOT NULL,
                ip_address TEXT,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES clients(id),
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_agents_client ON agents(client_id);
            CREATE INDEX IF NOT EXISTS idx_agents_token ON agents(token);
            CREATE INDEX IF NOT EXISTS idx_secrets_client ON secrets(client_id);
            CREATE INDEX IF NOT EXISTS idx_audit_client ON audit_log(client_id);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
            CREATE INDEX IF NOT EXISTS idx_sessions_client ON sessions(client_id);
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ─── Clients ───────────────────────────────────────────────────────────────

    pub async fn create_client(&self, email: &str, password_hash: &str, name: Option<&str>) -> Result<Client, DbError> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        sqlx::query(
            "INSERT INTO clients (id, email, password_hash, name, created_at) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(email)
        .bind(password_hash)
        .bind(name)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(Client {
            id,
            email: email.to_string(),
            password_hash: password_hash.to_string(),
            name: name.map(|s| s.to_string()),
            created_at: now,
        })
    }

    pub async fn get_client_by_email(&self, email: &str) -> Result<Client, DbError> {
        sqlx::query_as("SELECT * FROM clients WHERE email = ?")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DbError::NotFound)
    }

    pub async fn get_client_by_id(&self, id: &str) -> Result<Client, DbError> {
        sqlx::query_as("SELECT * FROM clients WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DbError::NotFound)
    }

    // ─── Agents ────────────────────────────────────────────────────────────────

    pub async fn create_agent(&self, client_id: &str, name: &str, token: &str) -> Result<Agent, DbError> {
        let id = format!("agent_{}", Uuid::new_v4().to_string().split('-').next().unwrap());
        let now = Utc::now();
        let scopes = "[]".to_string();
        
        sqlx::query(
            "INSERT INTO agents (id, client_id, name, token, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(client_id)
        .bind(name)
        .bind(token)
        .bind(&scopes)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(Agent {
            id,
            client_id: client_id.to_string(),
            name: name.to_string(),
            token: token.to_string(),
            scopes,
            created_at: now,
            last_seen_at: None,
        })
    }

    pub async fn get_agent_by_token(&self, token: &str) -> Result<Agent, DbError> {
        sqlx::query_as("SELECT * FROM agents WHERE token = ?")
            .bind(token)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DbError::NotFound)
    }

    pub async fn list_agents(&self, client_id: &str) -> Result<Vec<Agent>, DbError> {
        Ok(sqlx::query_as("SELECT * FROM agents WHERE client_id = ? ORDER BY created_at DESC")
            .bind(client_id)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn delete_agent(&self, id: &str, client_id: &str) -> Result<(), DbError> {
        sqlx::query("DELETE FROM agents WHERE id = ? AND client_id = ?")
            .bind(id)
            .bind(client_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_agent_last_seen(&self, id: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE agents SET last_seen_at = ? WHERE id = ?")
            .bind(Utc::now())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ─── Secrets ───────────────────────────────────────────────────────────────

    pub async fn create_secret(
        &self,
        client_id: &str,
        name: &str,
        provider: &str,
        encrypted_value: &str,
    ) -> Result<Secret, DbError> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        sqlx::query(
            "INSERT INTO secrets (id, client_id, name, provider, encrypted_value, created_at, updated_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(client_id)
        .bind(name)
        .bind(provider)
        .bind(encrypted_value)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(Secret {
            id,
            client_id: client_id.to_string(),
            name: name.to_string(),
            provider: provider.to_string(),
            encrypted_value: encrypted_value.to_string(),
            metadata: None,
            created_at: now,
            updated_at: now,
        })
    }

    pub async fn get_secret(&self, client_id: &str, name: &str) -> Result<Secret, DbError> {
        sqlx::query_as("SELECT * FROM secrets WHERE client_id = ? AND name = ?")
            .bind(client_id)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DbError::NotFound)
    }

    pub async fn list_secrets(&self, client_id: &str) -> Result<Vec<Secret>, DbError> {
        Ok(sqlx::query_as("SELECT * FROM secrets WHERE client_id = ? ORDER BY name")
            .bind(client_id)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn delete_secret(&self, id: &str, client_id: &str) -> Result<(), DbError> {
        sqlx::query("DELETE FROM secrets WHERE id = ? AND client_id = ?")
            .bind(id)
            .bind(client_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ─── Audit Log ─────────────────────────────────────────────────────────────

    pub async fn log_audit(
        &self,
        client_id: &str,
        agent_id: Option<&str>,
        action: &str,
        resource: Option<&str>,
        status: &str,
        ip_address: Option<&str>,
        details: Option<&str>,
    ) -> Result<(), DbError> {
        let id = Uuid::new_v4().to_string();
        
        sqlx::query(
            "INSERT INTO audit_log (id, client_id, agent_id, action, resource, status, ip_address, details, created_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(client_id)
        .bind(agent_id)
        .bind(action)
        .bind(resource)
        .bind(status)
        .bind(ip_address)
        .bind(details)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn list_audit(&self, client_id: &str, limit: i64) -> Result<Vec<AuditEntry>, DbError> {
        Ok(sqlx::query_as(
            "SELECT * FROM audit_log WHERE client_id = ? ORDER BY created_at DESC LIMIT ?"
        )
        .bind(client_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    // ─── Sessions ──────────────────────────────────────────────────────────────

    pub async fn create_session(&self, client_id: &str) -> Result<Session, DbError> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(24);
        
        sqlx::query(
            "INSERT INTO sessions (id, client_id, expires_at, created_at) VALUES (?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(client_id)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(Session {
            id,
            client_id: client_id.to_string(),
            expires_at,
            created_at: now,
        })
    }

    pub async fn get_session(&self, id: &str) -> Result<Session, DbError> {
        let session: Session = sqlx::query_as("SELECT * FROM sessions WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DbError::NotFound)?;
        
        // Check expiration
        if session.expires_at < Utc::now() {
            self.delete_session(id).await?;
            return Err(DbError::NotFound);
        }
        
        Ok(session)
    }

    pub async fn delete_session(&self, id: &str) -> Result<(), DbError> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

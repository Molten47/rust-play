use anyhow::Result;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    Json,
    response::IntoResponse,
    extract::State,
};
use std::future::Future;
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use crate::AppState;
use argon2::{Argon2, PasswordHasher, PasswordVerifier, password_hash::{SaltString, PasswordHash, rand_core::OsRng}};

// ── Domain model ──────────────────────────────────────────────────────────────
#[derive(Debug)]
struct ApiKeyRecord {
    id:          Uuid,
    user_id:     Option<Uuid>,
    secret_hash: String,
    scopes:      Vec<String>,
    expires_at:  Option<DateTime<Utc>>,
    revoked:     bool,
}

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow, Debug)]
pub struct ApiKey {
    pub id:           Uuid,
    pub user_id:      Option<Uuid>,
    pub prefix:       String,
    pub scopes:       Vec<String>,
    pub expires_at:   Option<DateTime<Utc>>,
    pub created_at:   DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked:      bool,
    pub name:         Option<String>,
}

// ── Verified identity injected into handlers ──────────────────────────────────

#[derive(Clone, Debug)]
pub struct ApiKeyIdentity {
    pub user_id: Uuid,
    pub scopes:  Vec<String>,
}

// ── Request shapes ────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct CreateApiKeyRequest {
    pub name:       Option<String>,
    pub scopes:     Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Debug)]
pub struct CreateApiKeyResponse {
    pub key:    String,   // raw key shown ONCE — never stored
    pub prefix: String,
    pub scopes: Vec<String>,
    pub name:   Option<String>,
}

// ── Key generation ────────────────────────────────────────────────────────────

/// Generates a key in format: ak_{8char_prefix}_{32char_secret}
fn generate_api_key() -> (String, String, String) {

let prefix: String = rand::thread_rng()
    .sample_iter(&rand::distributions::Alphanumeric)
    .take(8)
    .map(char::from)
    .collect();

let secret: String = rand::thread_rng()
    .sample_iter(&rand::distributions::Alphanumeric)
    .take(32)
    .map(char::from)
    .collect();

    let full_key = format!("ak_{}_{}", prefix, secret);
    (full_key, prefix, secret)
}

fn hash_secret(secret: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .to_string();
    Ok(hash)
}

fn verify_secret(secret: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(secret.as_bytes(), &parsed)
        .is_ok()
}

// ── Database layer ────────────────────────────────────────────────────────────

pub async fn create_api_key(
    pool:    &PgPool,
    user_id: Uuid,
    payload: &CreateApiKeyRequest,
) -> Result<CreateApiKeyResponse> {
    let (full_key, prefix, secret) = generate_api_key();
    let secret_hash = hash_secret(&secret)?;

    sqlx::query!(
        r#"
        INSERT INTO api_keys (user_id, prefix, secret_hash, scopes, expires_at, name)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        user_id,
        prefix,
        secret_hash,
        &payload.scopes,
        payload.expires_at,
        payload.name,
    )
    .execute(pool)
    .await?;

    Ok(CreateApiKeyResponse {
        key:    full_key,   // shown once, never retrievable again
        prefix: prefix,
        scopes: payload.scopes.clone(),
        name:   payload.name.clone(),
    })
}

pub async fn list_api_keys(pool: &PgPool, user_id: Uuid) -> Result<Vec<ApiKey>> {
    let keys = sqlx::query_as!(
        ApiKey,
        r#"
        SELECT id, user_id, prefix, scopes, expires_at, created_at, last_used_at, revoked, name
        FROM api_keys
        WHERE user_id = $1 AND revoked = FALSE
        ORDER BY created_at DESC
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(keys)
}

pub async fn revoke_api_key(pool: &PgPool, user_id: Uuid, key_id: Uuid) -> Result<()> {
    sqlx::query!(
        "UPDATE api_keys SET revoked = TRUE WHERE id = $1 AND user_id = $2",
        key_id,
        user_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Core verification — O(1) prefix lookup then Argon2 verify
pub async fn verify_api_key(pool: &PgPool, raw_key: &str) -> Result<ApiKeyIdentity> {
    // Parse format: ak_{prefix}_{secret}
    let parts: Vec<&str> = raw_key.splitn(3, '_').collect();
    if parts.len() != 3 || parts[0] != "ak" {
        anyhow::bail!("Invalid key format");
    }

    let prefix = parts[1];
    let secret = parts[2];

    // O(1) indexed lookup by prefix
   let record = sqlx::query_as!(
    ApiKeyRecord,
        r#"
        SELECT id, user_id, secret_hash, scopes, expires_at, revoked
        FROM api_keys
        WHERE prefix = $1
        "#,
        prefix,
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("Key not found"))?;

    // Check revocation
    if record.revoked {
        anyhow::bail!("API key has been revoked");
    }

    // Check expiry
    if let Some(exp) = record.expires_at {
        if Utc::now() > exp {
            anyhow::bail!("API key has expired");
        }
    }

    // Verify secret via Argon2
    if !verify_secret(secret, &record.secret_hash) {
        anyhow::bail!("Invalid API key secret");
    }

    // Update last_used_at
    sqlx::query!(
        "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
        record.id,
    )
    .execute(pool)
    .await?;

    Ok(ApiKeyIdentity {
        user_id: record.user_id.unwrap_or_default(),
        scopes:  record.scopes,
    })
}

// ── Axum extractor ────────────────────────────────────────────────────────────

impl FromRequestParts<Arc<AppState>> for ApiKeyIdentity {
    type Rejection = StatusCode;

    fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> impl Future<Output = Result<Self, StatusCode>> + Send {
        let auth = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|s| s.to_string());

        let db    = state.db.clone();
        let secret = state.jwt_secret.clone();

        async move {
            let auth = auth.ok_or(StatusCode::UNAUTHORIZED)?;

            if auth.starts_with("ak_") {
                verify_api_key(&db, &auth)
                    .await
                    .map_err(|_| StatusCode::UNAUTHORIZED)
            } else {
                crate::auth::verify_jwt(&auth, &secret)
                    .map(|claims| ApiKeyIdentity {
                        user_id: claims.sub.parse().unwrap_or_default(),
                        scopes:  vec!["*".to_string()],
                    })
                    .map_err(|_| StatusCode::UNAUTHORIZED)
            }
        }
    }
}

// ── Axum handlers ─────────────────────────────────────────────────────────────

/// POST /api-keys — create a new scoped API key
pub async fn create_api_key_handler(
    State(state): State<Arc<AppState>>,
    identity: ApiKeyIdentity,
    Json(payload): Json<CreateApiKeyRequest>,
) -> impl IntoResponse {
    match create_api_key(&state.db, identity.user_id, &payload).await {
        Ok(res) => Json(res).into_response(),
        Err(e) => {
            eprintln!("Failed to create API key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// GET /api-keys — list all active keys for the current user
pub async fn list_api_keys_handler(
    State(state): State<Arc<AppState>>,
    identity: ApiKeyIdentity,
) -> impl IntoResponse {
    match list_api_keys(&state.db, identity.user_id).await {
        Ok(keys) => Json(keys).into_response(),
        Err(e) => {
            eprintln!("Failed to list API keys: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// DELETE /api-keys/:id — revoke a key
pub async fn revoke_api_key_handler(
    State(state): State<Arc<AppState>>,
    identity: ApiKeyIdentity,
    axum::extract::Path(key_id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    match revoke_api_key(&state.db, identity.user_id, key_id).await {
        Ok(_)  => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            eprintln!("Failed to revoke API key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
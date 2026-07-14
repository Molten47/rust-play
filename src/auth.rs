use axum::{
    extract::{Query, State},
    http::{StatusCode, HeaderMap},
    Json,
    response::{IntoResponse}
};
use serde::{Deserialize, Serialize};
use sqlx::{types::{ipnetwork::IpNetwork},PgPool};
use std::sync::Arc;
use uuid::Uuid;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use rand::Rng;
use crate::AppState;
use crate::users::find_or_create_user;
use reqwest::Client;
use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration as CookieDuration;

// ── JWT ───────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub struct JwtClaims {
    pub sub: String,       // user UUID
    pub exp: usize,        // expiry timestamp
    pub iat: usize,        // issued at
}

pub fn issue_jwt(user_id: Uuid, secret: &str) -> anyhow::Result<String> {
    let now = Utc::now();
    let claims = JwtClaims {
        sub: user_id.to_string(),
        iat: now.timestamp() as usize,
        exp: (now + Duration::minutes(15)).timestamp() as usize, // 15 min lifetime
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

pub fn verify_jwt(token: &str, secret: &str) -> anyhow::Result<JwtClaims> {
    let data = decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(data.claims)
}


// _________ Rate Limiter ____________________________
fn get_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .split(',')
        .next()
        .unwrap_or("unknown")
        .trim()
        .to_string()
}

// ── Refresh tokens ────────────────────────────────────────────────────────────

/// Generate a secure random refresh token and store its hash in the DB
pub async fn issue_refresh_token(
    pool: &PgPool,
    user_id: Uuid,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> anyhow::Result<String> {
    // Generate 64 random bytes, encode as hex string
    let raw_token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    // Hash before storing — never store raw refresh tokens
    let token_hash = argon2_hash(&raw_token)?;

    let expires_at = Utc::now() + Duration::days(7);

let parsed_ip: Option<IpNetwork> = ip_address
    .and_then(|ip| ip.parse().ok());

sqlx::query!(
    r#"
    INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_address, user_agent)
    VALUES ($1, $2, $3, $4, $5)
    "#,
    user_id,
    token_hash,
    expires_at,
    parsed_ip as Option<IpNetwork>,
    user_agent,
)
.execute(pool)
.await?;
   
    Ok(raw_token) // return raw — sent to client once, never stored raw
}

/// Validate a refresh token and issue a new JWT + rotated refresh token
pub async fn rotate_refresh_token(
    pool: &PgPool,
    raw_token: &str,
    ip_address: Option<&str>,
    jwt_secret: &str,
) -> anyhow::Result<(String, String)> {
    // Find all non-revoked, non-expired tokens and check hash
    let candidates = sqlx::query!(
        r#"
        SELECT id, user_id, token_hash, use_count, ip_address
        FROM refresh_tokens
        WHERE revoked = FALSE AND expires_at > NOW()
        "#
    )
    .fetch_all(pool)
    .await?;

    let matched = candidates.iter().find(|row| {
        argon2_verify(raw_token, &row.token_hash).unwrap_or(false)
    });

    let record = matched.ok_or_else(|| anyhow::anyhow!("Invalid or expired refresh token"))?;

    // Revoke if use_count is suspiciously high (possible token theft)
    if record.use_count > 10 {
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1",
            record.id
        )
        .execute(pool)
        .await?;
        anyhow::bail!("Refresh token revoked due to overuse");
    }

    // Revoke if IP changed significantly (optional strictness)
if let (Some(stored_ip), Some(current_ip)) = (&record.ip_address, ip_address) {
    let stored_str = stored_ip.ip().to_string();
    if stored_str != current_ip {
        eprintln!("⚠️  IP mismatch on refresh: stored={}, current={}", stored_str, current_ip);
    }
}

    // Increment use count
    sqlx::query!(
        "UPDATE refresh_tokens SET use_count = use_count + 1 WHERE id = $1",
        record.id
    )
    .execute(pool)
    .await?;

    let user_id = record.user_id;

    // Issue new JWT
    let new_jwt = issue_jwt(user_id, jwt_secret)?;

    // Rotate: revoke old token, issue new one
    sqlx::query!(
        "UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1",
        record.id
    )
    .execute(pool)
    .await?;

    let new_refresh = issue_refresh_token(pool, user_id, ip_address, None).await?;

    Ok((new_jwt, new_refresh))
}

// ── Argon2 helpers ────────────────────────────────────────────────────────────

fn argon2_hash(raw: &str) -> anyhow::Result<String> {
    use argon2::{Argon2, PasswordHasher, password_hash::{SaltString, rand_core::OsRng}};
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(raw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .to_string();
    Ok(hash)
}

fn argon2_verify(raw: &str, hash: &str) -> anyhow::Result<bool> {
    use argon2::{Argon2, PasswordVerifier, password_hash::PasswordHash};
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(Argon2::default().verify_password(raw.as_bytes(), &parsed).is_ok())
}

// ── OAuth callback shape ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct OAuthCallback {
    pub code:  String,
    #[allow(dead_code)]
    pub state: Option<String>,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub access_token:  String,
    pub refresh_token: String,
    pub user_id:       String,
}

// ── Google OAuth2 API shapes ──────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct GoogleTokenResponse {
    access_token:  String,
    refresh_token: Option<String>,   // only sent on first consent, or with prompt=consent
    #[allow(dead_code)]
    expires_in:    Option<i64>,
}

#[derive(Deserialize, Debug)]
struct GoogleUserInfo {
    id:             String,
    email:          String,
    name:           Option<String>,
    picture:        Option<String>,
}

// ── Axum handlers ─────────────────────────────────────────────────────────────

/// GET /auth/google/callback
pub async fn google_callback_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<OAuthCallback>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let ip = get_client_ip(&headers);

// Rate limit auth endpoint
    if !state.rate_limiter.check(&ip) {
        eprintln!("🚫 Rate limit exceeded for IP: {}", ip);
        return StatusCode::TOO_MANY_REQUESTS.into_response();
}

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let http = Client::new();

    // ── Step 1: Exchange authorization code for Google access token ───────────
   let token_res: Result<reqwest::Response, reqwest::Error> = http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code",          params.code.as_str()),
            ("client_id",     state.google_client_id.as_str()),
            ("client_secret", state.google_client_secret.as_str()),
            ("redirect_uri",  state.google_redirect_uri.as_str()),
            ("grant_type",    "authorization_code"),
        ])
        .send()
        .await;

    let google_token = match token_res {
        Ok(res) => match res.json::<GoogleTokenResponse>().await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Failed to parse Google token response: {}", e);
                return StatusCode::BAD_GATEWAY.into_response();
            }
        },
        Err(e) => {
            eprintln!("Failed to reach Google token endpoint: {}", e);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // ── Step 2: Use access token to fetch user profile ────────────────────────
    let userinfo_res = http
        .get("https://www.googleapis.com/oauth2/v1/userinfo")
        .bearer_auth(&google_token.access_token)
        .send()
        .await;

    let google_user = match userinfo_res {
        Ok(res) => match res.json::<GoogleUserInfo>().await {
            Ok(u) => u,
            Err(e) => {
                eprintln!("Failed to parse Google userinfo: {}", e);
                return StatusCode::BAD_GATEWAY.into_response();
            }
        },
        Err(e) => {
            eprintln!("Failed to reach Google userinfo endpoint: {}", e);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    // ── Step 3: Find or create user in your DB ────────────────────────────────
   let user = match find_or_create_user(
    &state.db,
    "google",
    &google_user.id,
    &google_user.email,
    google_user.name.as_deref(),
    google_user.picture.as_deref(),
    &google_token.access_token,
    google_token.refresh_token.as_deref(),   // new arg
).await {
        Ok(u) => u,
        Err(e) => {
            eprintln!("DB error on find_or_create_user: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // ── Step 4: Issue your own JWT + refresh token ────────────────────────────
    let jwt = match issue_jwt(user.id, &state.jwt_secret) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("JWT issue error: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let refresh = match issue_refresh_token(
        &state.db,
        user.id,
        Some(ip.as_str()),
        user_agent.as_deref(),
    ).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Refresh token error: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // ── Step 5: Build cookies and redirect back to the frontend ───────────────
  let frontend_url = std::env::var("FRONTEND_URL")
    .unwrap_or_else(|_| "http://localhost:3000".to_string());

    let redirect_target = format!("{}/dashboard", frontend_url);

    let mut response = axum::response::Redirect::temporary(&redirect_target)
        .into_response();

    let is_prod = std::env::var("APP_ENV").unwrap_or_default() == "production";

    let access_cookie = Cookie::build(("access_token", jwt))
        .http_only(true)
        .secure(is_prod)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(CookieDuration::minutes(15))
        .build();

    let refresh_cookie = Cookie::build(("refresh_token", refresh))
        .http_only(true)
        .secure(is_prod)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(CookieDuration::days(7))
        .build();

    let user_id_cookie = Cookie::build(("user_id", user.id.to_string()))
        .http_only(false)
        .secure(is_prod)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(CookieDuration::days(7))
        .build();

    let headers = response.headers_mut();
    headers.append(
        axum::http::header::SET_COOKIE,
        access_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        refresh_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        user_id_cookie.to_string().parse().unwrap(),
    );

    response
}

/// GET /auth/google/login  — redirects user to Google consent screen
pub async fn google_login_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth\
         ?client_id={}\
         &redirect_uri={}\
         &response_type=code\
         &scope=openid%20email%20profile%20https://www.googleapis.com/auth/gmail.readonly\
         &access_type=offline\
         &prompt=consent",
        state.google_client_id,
        state.google_redirect_uri,
    );
    axum::response::Redirect::temporary(&url)
}

/// POST /auth/refresh
#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

use axum_extra::extract::CookieJar;

pub async fn refresh_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> impl IntoResponse {
    let ip = get_client_ip(&headers);

    if !state.rate_limiter.check(&ip) {
        eprintln!("🚫 Rate limit exceeded for IP: {}", ip);
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let raw_refresh = match jar.get("refresh_token") {
        Some(c) => c.value().to_string(),
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    match rotate_refresh_token(&state.db, &raw_refresh, Some(ip.as_str()), &state.jwt_secret).await {
        Ok((new_jwt, new_refresh)) => {
            let is_prod = std::env::var("APP_ENV").unwrap_or_default() == "production";

            let access_cookie = Cookie::build(("access_token", new_jwt))
                .http_only(true).secure(is_prod).same_site(SameSite::Lax)
                .path("/").max_age(CookieDuration::minutes(15)).build();

            let refresh_cookie = Cookie::build(("refresh_token", new_refresh))
                .http_only(true).secure(is_prod).same_site(SameSite::Lax)
                .path("/").max_age(CookieDuration::days(7)).build();

            let mut response = StatusCode::OK.into_response();
            let headers = response.headers_mut();
            headers.append(axum::http::header::SET_COOKIE, access_cookie.to_string().parse().unwrap());
            headers.append(axum::http::header::SET_COOKIE, refresh_cookie.to_string().parse().unwrap());
            response
        }
        Err(e) => {
            eprintln!("Refresh error: {}", e);
            StatusCode::UNAUTHORIZED.into_response()
        }
    }
}

pub async fn logout_handler() -> impl IntoResponse {
    let is_prod = std::env::var("APP_ENV").unwrap_or_default() == "production";

    let clear_access = Cookie::build(("access_token", ""))
        .http_only(true)
        .secure(is_prod)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(CookieDuration::seconds(0))
        .build();

    let clear_refresh = Cookie::build(("refresh_token", ""))
        .http_only(true)
        .secure(is_prod)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(CookieDuration::seconds(0))
        .build();

    let clear_user = Cookie::build(("user_id", ""))
        .secure(is_prod)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(CookieDuration::seconds(0))
        .build();

    let mut response = axum::http::StatusCode::OK.into_response();
    let headers = response.headers_mut();
    headers.append(axum::http::header::SET_COOKIE, clear_access.to_string().parse().unwrap());
    headers.append(axum::http::header::SET_COOKIE, clear_refresh.to_string().parse().unwrap());
    headers.append(axum::http::header::SET_COOKIE, clear_user.to_string().parse().unwrap());
    response
}
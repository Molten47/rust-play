use serde::{Serialize, Deserialize};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow, Debug)]
pub struct User {
    pub id:           Uuid,
    pub display_name: Option<String>,
    pub avatar_url:   Option<String>,
    pub created_at:   DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow, Debug)]
#[allow(dead_code)]

pub struct OAuthAccount {
    pub id:           Uuid,
    pub user_id:      Uuid,
    pub provider:     String,
    pub provider_uid: String,
    pub email:        String,
    pub created_at:   DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow, Debug)]
#[allow(dead_code)]
pub struct WatchedEmail {
    pub id:        Uuid,
    pub user_id:   Uuid,
    pub email:     String,
    pub provider:  String,
    pub created_at: DateTime<Utc>,
}

/// Find existing user by provider + provider UID, or create a new one
pub async fn find_or_create_user(
    pool: &PgPool,
    provider: &str,
    provider_uid: &str,
    email: &str,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
    access_token: &str,
    refresh_token: Option<&str>,   // new param
) -> anyhow::Result<User> {
    let existing = sqlx::query_as!(
        User,
        r#"
        SELECT u.id, u.display_name, u.avatar_url, u.created_at
        FROM users u
        JOIN oauth_accounts oa ON oa.user_id = u.id
        WHERE oa.provider = $1 AND oa.provider_uid = $2
        "#,
        provider,
        provider_uid,
    )
    .fetch_optional(pool)
    .await?;

    if let Some(user) = existing {
        // Update access token always; only overwrite refresh_token if Google sent a new one
        sqlx::query!(
            r#"
            UPDATE oauth_accounts
            SET access_token = $1,
                refresh_token = COALESCE($2, refresh_token)
            WHERE provider = $3 AND provider_uid = $4
            "#,
            access_token,
            refresh_token,
            provider,
            provider_uid,
        )
        .execute(pool)
        .await?;

        return Ok(user);
    }

    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (display_name, avatar_url)
        VALUES ($1, $2)
        RETURNING id, display_name, avatar_url, created_at
        "#,
        display_name,
        avatar_url,
    )
    .fetch_one(pool)
    .await?;

    sqlx::query!(
        r#"
        INSERT INTO oauth_accounts (user_id, provider, provider_uid, email, access_token, refresh_token)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
        user.id,
        provider,
        provider_uid,
        email,
        access_token,
        refresh_token,
    )
    .execute(pool)
    .await?;

    Ok(user)
}


/// Add an email address to watch for a user
#[allow(dead_code)]
pub async fn add_watched_email(
    pool: &PgPool,
    user_id: Uuid,
    email: &str,
    provider: &str,
) -> anyhow::Result<WatchedEmail> {
    let record = sqlx::query_as!(
        WatchedEmail,
        r#"
        INSERT INTO watched_emails (user_id, email, provider)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, email) DO NOTHING
        RETURNING id, user_id, email, provider, created_at
        "#,
        user_id,
        email,
        provider,
    )
    .fetch_one(pool)
    .await?;

    Ok(record)
}
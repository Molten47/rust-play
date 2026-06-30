use serde::{Serialize, Deserialize};
use axum::{extract::State, Json, http::StatusCode};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::AppState;

// ── Domain model (maps directly to the priority_mail table) ──────────────────

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow, Debug)]
pub struct PriorityMail {
    pub id:           Uuid,
    pub sender_name:  Option<String>,
    pub sender_email: String,
    pub summary:      String,
    pub url_link:     String,
    pub category:     Option<String>,
    pub created_at:   DateTime<Utc>,
}

// ── Input shape for inserting a new priority mail ────────────────────────────

#[derive(Deserialize, Debug)]
pub struct CreatePriorityMail {
    pub sender_name:  Option<String>,
    pub sender_email: String,
    pub summary:      String,
    pub url_link:     String,
    pub category:     Option<String>,
}

// ── Database layer ───────────────────────────────────────────────────────────

pub async fn insert_priority_mail(
    pool: &PgPool,
    payload: &CreatePriorityMail,
) -> anyhow::Result<PriorityMail> {
    let record = sqlx::query_as!(
        PriorityMail,
        r#"
        INSERT INTO priority_mail (sender_name, sender_email, summary, url_link, category)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, sender_name, sender_email, summary, url_link, category, created_at
        "#,
        payload.sender_name,
        payload.sender_email,
        payload.summary,
        payload.url_link,
        payload.category,
    )
    .fetch_one(pool)
    .await?;

    Ok(record)
}

pub async fn fetch_all_priority_mail(pool: &PgPool) -> anyhow::Result<Vec<PriorityMail>> {
    let records = sqlx::query_as!(
        PriorityMail,
        r#"
        SELECT id, sender_name, sender_email, summary, url_link, category, created_at
        FROM priority_mail
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(records)
}

// ── Axum handlers ────────────────────────────────────────────────────────────

/// GET /priority-mail  — returns all priority emails, newest first
pub async fn list_priority_mail_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<PriorityMail>>, StatusCode> {
    fetch_all_priority_mail(&state.db)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// POST /priority-mail  — insert a new priority email record
pub async fn create_priority_mail_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreatePriorityMail>,
) -> Result<Json<PriorityMail>, StatusCode> {
    insert_priority_mail(&state.db, &payload)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
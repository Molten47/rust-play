use serde::{Serialize, Deserialize};
use axum::{extract::{State, Query}, Json, http::StatusCode};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use base64::{Engine as _, engine::general_purpose::STANDARD as base64};
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
    pub message_id:   Option<String>,
    pub created_at:   DateTime<Utc>,
}

// ── Input shape for inserting a new priority mail ────────────────────────────

#[derive(Deserialize, Debug)]
pub struct CreatePriorityMail {
    pub sender_name:  Option<String>,
    pub sender_email: String,
    pub summary:      String,
    pub url_link:     String,
    pub message_id:   Option<String>,
    pub category:     Option<String>,
}

// ── Cursor pagination ─────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct CursorParams {
    pub cursor: Option<String>,   // opaque, base64-encoded
    pub limit:  Option<i64>,
}

#[derive(Serialize, Debug)]
pub struct CursorPage {
    pub items:       Vec<PriorityMail>,
    pub next_cursor: Option<String>,
    pub has_more:    bool,
}

/// Encode (created_at, id) into an opaque cursor string
fn encode_cursor(created_at: DateTime<Utc>, id: Uuid) -> String {
    let raw = format!("{}|{}", created_at.to_rfc3339(), id);
    base64.encode(raw)
}

/// Decode an opaque cursor back into (created_at, id)
fn decode_cursor(cursor: &str) -> anyhow::Result<(DateTime<Utc>, Uuid)> {
    let raw = String::from_utf8(base64.decode(cursor)?)?;
    let (ts_str, id_str) = raw
        .split_once('|')
        .ok_or_else(|| anyhow::anyhow!("Malformed cursor"))?;
    let ts = DateTime::parse_from_rfc3339(ts_str)?.with_timezone(&Utc);
    let id = Uuid::parse_str(id_str)?;
    Ok((ts, id))
}

// ── Database layer ───────────────────────────────────────────────────────────

pub async fn insert_priority_mail(
    pool: &PgPool,
    payload: &CreatePriorityMail,
) -> anyhow::Result<Option<PriorityMail>> {
    let record = sqlx::query_as!(
        PriorityMail,
        r#"
        INSERT INTO priority_mail (sender_name, sender_email, summary, url_link, category, message_id)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (message_id) DO NOTHING
        RETURNING id, sender_name, sender_email, summary, url_link, category, message_id, created_at
        "#,
        payload.sender_name,
        payload.sender_email,
        payload.summary,
        payload.url_link,
        payload.category,
        payload.message_id,
    )
    .fetch_optional(pool)
    .await?;

    Ok(record)
}

pub async fn fetch_priority_mail_page(
    pool: &PgPool,
    cursor: Option<(DateTime<Utc>, Uuid)>,
    limit: i64,
) -> anyhow::Result<CursorPage> {
    // Fetch one extra row so we can tell if there's a next page without a second query
    let fetch_limit = limit + 1;

    let mut items = match cursor {
        Some((cursor_ts, cursor_id)) => {
            sqlx::query_as!(
                PriorityMail,
                r#"
                SELECT id, sender_name, sender_email, summary, url_link, category, created_at, message_id
                FROM priority_mail
                WHERE (created_at, id) < ($1, $2)
                ORDER BY created_at DESC, id DESC
                LIMIT $3
                "#,
                cursor_ts,
                cursor_id,
                fetch_limit,
            )
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as!(
                PriorityMail,
                r#"
                SELECT id, sender_name, sender_email, summary, url_link, category, created_at, message_id
                FROM priority_mail
                ORDER BY created_at DESC, id DESC
                LIMIT $1
                "#,
                fetch_limit,
            )
            .fetch_all(pool)
            .await?
        }
    };

    let has_more = items.len() as i64 > limit;
    if has_more {
        items.truncate(limit as usize);
    }

    let next_cursor = if has_more {
        items.last().map(|m| encode_cursor(m.created_at, m.id))
    } else {
        None
    };

    Ok(CursorPage { items, next_cursor, has_more })
}

// ── Axum handlers ────────────────────────────────────────────────────────────

/// GET /priority-mail?cursor=<opaque>&limit=20  — returns a page of priority emails, newest first
pub async fn list_priority_mail_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CursorParams>,
) -> Result<Json<CursorPage>, StatusCode> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);

    let cursor = match params.cursor {
        Some(c) => match decode_cursor(&c) {
            Ok(parsed) => Some(parsed),
            Err(_) => return Err(StatusCode::BAD_REQUEST), // malformed cursor
        },
        None => None,
    };

    fetch_priority_mail_page(&state.db, cursor, limit)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn create_priority_mail_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreatePriorityMail>,
) -> Result<Json<Option<PriorityMail>>, StatusCode> {
    insert_priority_mail(&state.db, &payload)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
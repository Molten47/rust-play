use serde::{Serialize, Deserialize};
use axum::{
    extract::{
        State,
        ws::{WebSocket, WebSocketUpgrade, Message},
    },
    Json,
    http::StatusCode,
    response::IntoResponse,
};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::AppState;

// ── Domain model ─────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow, Debug)]
pub struct Notification {
    pub id:          Uuid,
    pub sender_name: Option<String>,
    pub summary:     String,
    pub created_at:  DateTime<Utc>,
}

// ── Input shape (id and created_at are DB-generated, never sent by client) ───

#[derive(Deserialize, Debug)]
pub struct CreateNotification {
    pub sender_name: Option<String>,
    pub summary:     String,
}

// ── Database layer ────────────────────────────────────────────────────────────

pub async fn insert_notification(
    pool: &PgPool,
    payload: &CreateNotification,
) -> anyhow::Result<Notification> {
    let record = sqlx::query_as!(
        Notification,
        r#"
        INSERT INTO notifications (sender_name, summary)
        VALUES ($1, $2)
        RETURNING id, sender_name, summary, created_at
        "#,
        payload.sender_name,
        payload.summary,
    )
    .fetch_one(pool)
    .await?;

    Ok(record)
}

pub async fn fetch_all_notifications(pool: &PgPool) -> anyhow::Result<Vec<Notification>> {
    let records = sqlx::query_as!(
        Notification,
        r#"
        SELECT id, sender_name, summary, created_at
        FROM notifications
        ORDER BY created_at DESC
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(records)
}

// ── REST handlers ─────────────────────────────────────────────────────────────

/// GET /notifications — fetch all notifications, newest first
pub async fn list_notifications_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Notification>>, StatusCode> {
    fetch_all_notifications(&state.db)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// POST /notifications — inserts a new notification
pub async fn create_notification_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateNotification>,
) -> Result<Json<Notification>, StatusCode> {
    insert_notification(&state.db, &payload)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

// ── WebSocket handler ─────────────────────────────────────────────────────────

/// GET /notifications/ws — upgrades to WebSocket, pushes latest notification
/// The Next.js frontend connects here to receive real-time push events
pub async fn notifications_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    // Fetch latest notifications and push them down the socket on connect
    match fetch_all_notifications(&state.db).await {
        Ok(notifications) => {
            for notif in notifications {
                let msg = match serde_json::to_string(&notif) {
                    Ok(json) => json,
                    Err(_) => continue,
                };
                if socket.send(Message::Text(msg.into())).await.is_err() {
                    // Client disconnected
                    return;
                }
            }
        }
        Err(e) => {
            eprintln!("WebSocket DB error: {}", e);
        }
    }
}
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use anyhow::Result;
use axum::{extract::State, Json, http::StatusCode};
use std::sync::Arc;
use crate::AppState;

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow, Debug)]
pub struct Keyword {
    pub id: Uuid,
    pub category: Option<String>,
    pub content: String,
}

// Keep your database fetching function here
pub async fn fetch_all_keywords(pool: &PgPool) -> Result<Vec<Keyword>> {
    let keywords = sqlx::query_as!(
        Keyword,
        "SELECT id, category, content FROM keywords"
    )
    .fetch_all(pool)
    .await?;

    Ok(keywords)
}

#[allow(dead_code)]
// Keep your matching engine logic here
pub async fn evaluate_email_body(email_body: &str, pool: &PgPool) -> Result<()> {
    let system_keywords = fetch_all_keywords(pool).await?;
    let lower_email_body = email_body.to_lowercase();

    for keyword in system_keywords {
        let lower_keyword = keyword.content.to_lowercase();
        if lower_email_body.contains(&lower_keyword) {
            println!("🎯 Match Found! Keyword: {}", keyword.content);
            // Save to matched_emails table here...
        }
    }
    Ok(())
}

pub async fn list_keywords_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Keyword>>, StatusCode> {
    fetch_all_keywords(&state.db)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
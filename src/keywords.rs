use uuid::Uuid;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use anyhow::Result;
use axum::{extract::State, Json, http::StatusCode};
use std::sync::Arc;
use crate::AppState;

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow, Debug)]
pub struct Keyword {
    pub id:             Uuid,
    pub category:       Option<String>,
    pub content:        Option<String>,
    pub sender_pattern: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateKeyword {
    pub category:       Option<String>,
    pub content:        Option<String>,
    pub sender_pattern: Option<String>,
}

// ── Database layer ───────────────────────────────────────────────────────────

pub async fn fetch_all_keywords(pool: &PgPool) -> Result<Vec<Keyword>> {
    let keywords = sqlx::query_as!(
        Keyword,
        "SELECT id, category, content, sender_pattern FROM keywords"
    )
    .fetch_all(pool)
    .await?;

    Ok(keywords)
}

/// Checks whether a sender matches a rule's sender_pattern.
/// - Pattern containing '@' → exact email match (case-insensitive)
/// - Pattern without '@'    → domain match, e.g. "company.com" matches "anyone@company.com"
fn sender_matches(sender_email: &str, pattern: &str) -> bool {
    let sender_lower  = sender_email.to_lowercase();
    let pattern_lower = pattern.trim().to_lowercase();

    if pattern_lower.contains('@') {
        sender_lower == pattern_lower
    } else {
        sender_lower.ends_with(&format!("@{}", pattern_lower))
    }
}

/// Returns the first matching rule's category, if any, for a given email.
/// A rule matches when:
///   - it has sender_pattern only  → sender must match
///   - it has content only         → body must contain content
///   - it has both                 → both must match
pub async fn classify_email(
    pool: &PgPool,
    sender_email: &str,
    email_body: &str,
) -> Result<Option<String>> {
    let rules = fetch_all_keywords(pool).await?;
    let lower_body = email_body.to_lowercase();

    for rule in rules {
        let sender_ok = match &rule.sender_pattern {
            Some(pattern) if !pattern.trim().is_empty() => sender_matches(sender_email, pattern),
            _ => true, // no sender pattern → doesn't constrain
        };

        let content_ok = match &rule.content {
            Some(content) if !content.trim().is_empty() => lower_body.contains(&content.to_lowercase()),
            _ => true, // no content → doesn't constrain
        };

        // At least one of the two must actually be a real constraint,
        // otherwise an empty rule (no content, no sender) would match everything.
        let has_constraint = rule.sender_pattern.as_deref().is_some_and(|s| !s.trim().is_empty())
            || rule.content.as_deref().is_some_and(|c| !c.trim().is_empty());

        if has_constraint && sender_ok && content_ok {
            if rule.category.is_some() {
                println!("🎯 Rule matched — category: {:?}", rule.category);
                return Ok(rule.category);
            }
        }
    }

    Ok(None)
}

// ── Axum handlers ────────────────────────────────────────────────────────────

pub async fn list_keywords_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Keyword>>, StatusCode> {
    fetch_all_keywords(&state.db)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn create_keyword_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateKeyword>,
) -> Result<Json<Keyword>, StatusCode> {
    // Require at least one of content / sender_pattern so rules can't be created empty
    let has_content = payload.content.as_deref().is_some_and(|c| !c.trim().is_empty());
    let has_sender  = payload.sender_pattern.as_deref().is_some_and(|s| !s.trim().is_empty());

    if !has_content && !has_sender {
        return Err(StatusCode::BAD_REQUEST);
    }

    let keyword = sqlx::query_as!(
        Keyword,
        r#"
        INSERT INTO keywords (category, content, sender_pattern)
        VALUES ($1, $2, $3)
        RETURNING id, category, content, sender_pattern
        "#,
        payload.category,
        payload.content,
        payload.sender_pattern,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(keyword))
}

/// Finds the first keyword rule that matches a given sender + email body.
/// Returns the matched Keyword so callers can access its category, content, etc.
pub fn find_matching_keyword<'a>(
    keywords: &'a [Keyword],
    sender_email: &str,
    email_body: &str,
) -> Option<&'a Keyword> {
    let lower_body = email_body.to_lowercase();

    keywords.iter().find(|rule| {
        let sender_ok = match &rule.sender_pattern {
            Some(pattern) if !pattern.trim().is_empty() => sender_matches(sender_email, pattern),
            _ => true,
        };

        let content_ok = match &rule.content {
            Some(content) if !content.trim().is_empty() => lower_body.contains(&content.to_lowercase()),
            _ => true,
        };

        let has_constraint = rule.sender_pattern.as_deref().is_some_and(|s| !s.trim().is_empty())
            || rule.content.as_deref().is_some_and(|c| !c.trim().is_empty());

        has_constraint && sender_ok && content_ok
    })
}
use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;
use crate::keywords::{fetch_all_keywords, find_matching_keyword};
use crate::priority_mail::{insert_priority_mail, CreatePriorityMail};
use crate::notifications::{insert_notification, CreateNotification};

// ── Gmail API response shapes ─────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct GoogleRefreshResponse {
    access_token: String,
    #[allow(dead_code)]
    expires_in:   i64,
}


#[derive(Deserialize, Debug)]
struct GmailListResponse {
    messages: Option<Vec<GmailMessageRef>>,
}

#[derive(Deserialize, Debug)]
struct GmailMessageRef {
    id: String,
}

#[derive(Deserialize, Debug)]
struct GmailMessage {
    id:      String,
    payload: GmailPayload,
    snippet: Option<String>,
}

#[derive(Deserialize, Debug)]
struct GmailPayload {
    headers: Vec<GmailHeader>,
}

#[derive(Deserialize, Debug)]
struct GmailHeader {
    name:  String,
    value: String,
}

// ── Parsed email ──────────────────────────────────────────────────────────────

#[derive(Debug)]
struct ParsedEmail {
    message_id:   String,
    sender_name:  Option<String>,
    sender_email: String,
    subject:      String,
    snippet:      String,
}

// ── Header extractor ──────────────────────────────────────────────────────────

fn extract_header(headers: &[GmailHeader], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.clone())
}

/// Parse "Display Name <email@example.com>" into (name, email)
fn parse_from_header(from: &str) -> (Option<String>, String) {
    if let Some(start) = from.find('<') {
        if let Some(end) = from.find('>') {
            let name  = from[..start].trim().trim_matches('"').to_string();
            let email = from[start + 1..end].trim().to_string();
            return (Some(name).filter(|n| !n.is_empty()), email);
        }
    }
    (None, from.trim().to_string())
}

// ── Core crawler function ─────────────────────────────────────────────────────


/// Exchange a stored refresh_token for a new short-lived access_token
async fn refresh_google_access_token(
    pool:          &PgPool,
    user_id:       Uuid,
    refresh_token: &str,
    client_id:     &str,
    client_secret: &str,
) -> Result<String> {
    let http = Client::new();

    let res: GoogleRefreshResponse = http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("refresh_token", refresh_token),
            ("client_id",     client_id),
            ("client_secret", client_secret),
            ("grant_type",    "refresh_token"),
        ])
        .send()
        .await?
        .json::<GoogleRefreshResponse>()
        .await?;

    // Persist the new access token
    sqlx::query!(
        "UPDATE oauth_accounts SET access_token = $1 WHERE user_id = $2 AND provider = 'google'",
        res.access_token,
        user_id,
    )
    .execute(pool)
    .await?;

    Ok(res.access_token)
}

/// Crawl inbox for a single user using their stored Google access token
pub async fn crawl_user_inbox(
    pool:         &PgPool,
    user_id:      Uuid,
    access_token: &str,
) -> Result<usize> {
    let http     = Client::new();
    let keywords = fetch_all_keywords(pool).await?;

    if keywords.is_empty() {
        return Ok(0);
    }

    // ── Step 1: List recent inbox messages (max 20) ───────────────────────────
    let list_res: GmailListResponse = http
        .get("https://gmail.googleapis.com/gmail/v1/users/me/messages")
        .bearer_auth(access_token)
        .query(&[
            ("maxResults", "20"),
            ("labelIds",   "INBOX"),
            ("q",          "is:unread"),
        ])
        .send()
        .await?
        .json::<GmailListResponse>()
        .await?;

    let message_refs: Vec<GmailMessageRef> = match list_res.messages {
        Some(msgs) if !msgs.is_empty() => msgs,
        _ => {
            println!("📭 No unread messages found for user {}", user_id);
            return Ok(0);
        }
    };

    println!("📬 Found {} unread messages for user {}", message_refs.len(), user_id);

    let mut match_count = 0usize;

    // ── Step 2: Fetch + evaluate each message ─────────────────────────────────
    for msg_ref in message_refs {
        let msg_res: GmailMessage = http
            .get(format!(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/{}",
                msg_ref.id
            ))
            .bearer_auth(access_token)
            .query(&[("format", "metadata"), ("metadataHeaders", "From"), ("metadataHeaders", "Subject")])
            .send()
            .await?
            .json::<GmailMessage>()
            .await?;

        let from    = extract_header(&msg_res.payload.headers, "From").unwrap_or_default();
        let subject = extract_header(&msg_res.payload.headers, "Subject").unwrap_or_default();
        let snippet = msg_res.snippet.unwrap_or_default();

        let (sender_name, sender_email) = parse_from_header(&from);

        let email = ParsedEmail {
            message_id:   msg_res.id,
            sender_name:  sender_name.clone(),
            sender_email: sender_email.clone(),
            subject:      subject.clone(),
            snippet:      snippet.clone(),
        };

        // ── Step 3: Run keyword + sender matching ─────────────────────────────
        let body_to_scan = format!("{} {}", email.subject, email.snippet);

        let matched_keyword = find_matching_keyword(&keywords, &email.sender_email, &body_to_scan);

        if let Some(keyword) = matched_keyword {
            println!(
                "🎯 Match [{}] in email from {} — rule content: {:?}, sender_pattern: {:?}",
                email.message_id,
                email.sender_email,
                keyword.content,
                keyword.sender_pattern,
            );

            // Build Gmail deep link
            let url_link = format!(
            "https://mail.google.com/mail/u/0/#all/{}",
            email.message_id
            );

            let summary = format!(
                "[{}] {} — {}",
                keyword.category.as_deref().unwrap_or("General"),
                email.subject,
                &email.snippet.chars().take(100).collect::<String>()
            );

            // ── Step 4: Insert into priority_mail (only notify on new matches) ─
            let result = insert_priority_mail(pool, &CreatePriorityMail {
                sender_name:  email.sender_name.clone(),
                sender_email: email.sender_email.clone(),
                summary:      summary.clone(),
                url_link:     url_link.clone(),
                category:     keyword.category.clone(),
                message_id:   Some(email.message_id.clone()),
            }).await?;

            if result.is_some() {
                insert_notification(pool, &CreateNotification {
                    sender_name: email.sender_name.clone(),
                    summary: format!(
                        "Priority email from {}: {}",
                        email.sender_email,
                        &email.subject
                    ),
                }).await?;
                match_count += 1;
            }
        }
    }

    // ── Step 5: Update last crawled timestamp ─────────────────────────────────
    sqlx::query!(
        "UPDATE oauth_accounts SET last_crawled_at = NOW() WHERE user_id = $1 AND provider = 'google'",
        user_id,
    )
    .execute(pool)
    .await?;

    println!("✅ Crawl complete for user {} — {} matches", user_id, match_count);
    Ok(match_count)
}

// ── Crawl all users ───────────────────────────────────────────────────────────

pub async fn crawl_all_users(
    pool:                 &PgPool,
    google_client_id:     &str,
    google_client_secret: &str,
) -> Result<()> {
    let accounts = sqlx::query!(
        r#"
        SELECT user_id, access_token, refresh_token
        FROM oauth_accounts
        WHERE provider = 'google'
        "#
    )
    .fetch_all(pool)
    .await?;

    println!("🔄 Starting crawl for {} accounts", accounts.len());

    for account in accounts {
        let access_token = match &account.refresh_token {
            Some(rt) => {
                match refresh_google_access_token(
                    pool,
                    account.user_id,
                    rt,
                    google_client_id,
                    google_client_secret,
                ).await {
                    Ok(new_token) => new_token,
                    Err(e) => {
                        eprintln!("❌ Token refresh failed for user {}: {}", account.user_id, e);
                        continue;
                    }
                }
            }
            None => {
                eprintln!("⚠️  No refresh_token for user {} — re-login required", account.user_id);
                continue;
            }
        };

        if let Err(e) = crawl_user_inbox(pool, account.user_id, &access_token).await {
            eprintln!("❌ Crawl error for user {}: {}", account.user_id, e);
        }
    }

    Ok(())
}
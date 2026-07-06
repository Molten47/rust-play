use axum::{routing::{get, post, delete}, Router, extract::State};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use dotenvy::dotenv;
use std::env;
use axum::middleware as axum_middleware;
use tokio::time::{interval, Duration as TokioDuration};
use security::RateLimiter;
use tower_http::set_header::SetResponseHeaderLayer;
use axum::http::header::{
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS, HeaderValue
};
use tower_http::limit::RequestBodyLimitLayer;


mod keywords;
mod priority_mail;
mod notifications;
mod users;
mod auth;
mod middleware;
mod crawler;
mod security;
mod api_keys;

// Shared application state passed into every handler

#[derive(Clone)]
pub struct AppState {
    pub db:                   sqlx::PgPool,
    pub jwt_secret:           String,
    pub google_client_id:     String,
    pub google_client_secret: String,
    pub google_redirect_uri:  String,
    pub rate_limiter:         Arc<RateLimiter>,
}

// In main(), build state as:


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    
dotenv().ok();

let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    println!("🚀 Database connected successfully.");

let _jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
let state = Arc::new(AppState {
    db:                   pool,
    jwt_secret:           env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
    google_client_id:     env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set"),
    google_client_secret: env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET must be set"),
    google_redirect_uri:  env::var("GOOGLE_REDIRECT_URI").expect("GOOGLE_REDIRECT_URI must be set"),
    rate_limiter:         Arc::new(RateLimiter::new(10, 60)), // 10 requests per 60 seconds per IP
});

let protected = Router::new()
    .route("/keywords",      get(keywords::list_keywords_handler))
    .route("/priority-mail", get(priority_mail::list_priority_mail_handler).post(priority_mail::create_priority_mail_handler))
    .route("/notifications", get(notifications::list_notifications_handler).post(notifications::create_notification_handler))
    .route("/notifications/ws", get(notifications::notifications_ws_handler))
    .route("/crawl", post(crawl_trigger_handler))
    .route("/api-keys",      get(api_keys::list_api_keys_handler).post(api_keys::create_api_key_handler))
    .route("/api-keys/{id}",  delete(api_keys::revoke_api_key_handler))
    .layer(axum_middleware::from_fn_with_state(
        state.clone(),
        middleware::require_auth,
    ));

let public = Router::new()
    .route("/auth/google/login",    get(auth::google_login_handler))
    .route("/auth/google/callback", get(auth::google_callback_handler))
    .route("/auth/refresh",         post(auth::refresh_handler));

let app = Router::new()
    .merge(protected)
    .merge(public)
    .layer(CorsLayer::permissive())
    .layer(RequestBodyLimitLayer::new(1024 * 16)) // 16kb max request body
    .layer(SetResponseHeaderLayer::overriding(
        X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    ))
    .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await?;

    // ── Background crawler loop ────────────────────────────────────────────────
{
    let bg_state = state.clone();
    tokio::spawn(async move {
    let mut ticker = interval(TokioDuration::from_secs(300));
    loop {
        ticker.tick().await;
        println!("⏰ Scheduled crawl starting...");
        if let Err(e) = crawler::crawl_all_users(
            &bg_state.db,
            &bg_state.google_client_id,
            &bg_state.google_client_secret,
        ).await {
            eprintln!("❌ Scheduled crawl failed: {}", e);
        }
    }
});

// Cleanup stale rate limiter entries every 5 minutes
{
    let rl = state.rate_limiter.clone();
    tokio::spawn(async move {
        let mut ticker = interval(TokioDuration::from_secs(300));
        loop {
            ticker.tick().await;
            rl.cleanup();
        }
    });
}

}
    println!("🌐 API listening on http://localhost:3001");
    axum::serve(listener, app).await?;

    Ok(())
}
async fn crawl_trigger_handler(
    State(state): State<Arc<AppState>>,
) -> impl axum::response::IntoResponse {
    match crawler::crawl_all_users(
        &state.db,
        &state.google_client_id,
        &state.google_client_secret,
    ).await {
        Ok(_)  => (axum::http::StatusCode::OK, "Crawl complete"),
        Err(e) => {
            eprintln!("Crawl error: {}", e);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Crawl failed")
        }
    }
}

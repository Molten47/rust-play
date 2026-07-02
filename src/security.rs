use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Simple in-memory IP rate limiter
/// Tracks request counts per IP within a sliding window
pub struct RateLimiter {
    requests: Mutex<HashMap<String, Vec<Instant>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Returns true if the IP is allowed, false if rate limited
    pub fn check(&self, ip: &str) -> bool {
        let mut map = self.requests.lock().unwrap();
        let now = Instant::now();
        let window = self.window;

        let entries = map.entry(ip.to_string()).or_default();

        // Remove entries outside the window
        entries.retain(|t| now.duration_since(*t) < window);

        if entries.len() >= self.max_requests {
            return false;
        }

        entries.push(now);
        true
    }

    /// Periodically clean up stale IPs to prevent memory growth
    pub fn cleanup(&self) {
        let mut map = self.requests.lock().unwrap();
        let now = Instant::now();
        let window = self.window;
        map.retain(|_, entries| {
            entries.retain(|t| now.duration_since(*t) < window);
            !entries.is_empty()
        });
    }
}
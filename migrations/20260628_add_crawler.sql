-- Track last crawl time per user so we don't re-process old emails
ALTER TABLE oauth_accounts
    ADD COLUMN IF NOT EXISTS last_crawled_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;
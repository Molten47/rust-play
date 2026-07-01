ALTER TABLE oauth_accounts
    ADD COLUMN IF NOT EXISTS refresh_token TEXT;
CREATE TABLE users (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    display_name VARCHAR(100),
    avatar_url   TEXT
);

-- Each OAuth provider account linked to a user
-- One user can link Google + Yahoo + Outlook
CREATE TABLE oauth_accounts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider      VARCHAR(50)  NOT NULL,   -- 'google' | 'yahoo' | 'outlook'
    provider_uid  TEXT         NOT NULL,   -- provider's own user ID
    email         TEXT         NOT NULL,
    access_token  TEXT         NOT NULL,   -- the provider token (encrypted at rest)
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (provider, provider_uid)        -- to prevent duplicate links
);

-- Email addresses the user wants crawled for priority notifications
CREATE TABLE watched_emails (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    provider   VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, email)
);

--Built-in refresh tokens (not the provider's)
CREATE TABLE refresh_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   TEXT        NOT NULL UNIQUE,  -- Argon2 hash, never store raw
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked      BOOLEAN     NOT NULL DEFAULT FALSE,
    ip_address   INET,
    user_agent   TEXT,
    use_count    INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);
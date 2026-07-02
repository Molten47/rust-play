CREATE TABLE IF NOT EXISTS api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    prefix       VARCHAR(8)  NOT NULL UNIQUE,
    secret_hash  TEXT        NOT NULL,
    scopes       TEXT[]      NOT NULL DEFAULT '{}',
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked      BOOLEAN     NOT NULL DEFAULT FALSE,
    name         TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_keys_prefix  ON api_keys(prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
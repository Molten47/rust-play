ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked      BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS name         TEXT;

-- Fix expires_at to be nullable
ALTER TABLE api_keys
    ALTER COLUMN expires_at DROP NOT NULL;

-- Fix secret_hash to be TEXT not VARCHAR(255)
ALTER TABLE api_keys
    ALTER COLUMN secret_hash TYPE TEXT;

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
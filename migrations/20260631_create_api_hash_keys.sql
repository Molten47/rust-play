CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    prefix VARCHAR(8) NOT NULL UNIQUE,          -- Used to look up the row
    secret_hash VARCHAR(255) NOT NULL,          -- Argon2id hash of the secret part
    scopes TEXT[] NOT NULL DEFAULT '{}',         -- Array of allowed permissions
    expires_at TIMESTAMPTZ NOT NULL,            -- Expiry timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index the prefix for lightning-fast database lookups
CREATE INDEX idx_api_keys_prefix ON api_keys(prefix);
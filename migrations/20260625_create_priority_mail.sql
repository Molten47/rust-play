CREATE TABLE priority_mail (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_name VARCHAR(100),
    sender_email VARCHAR(255) NOT NULL,
    summary     TEXT NOT NULL,
    url_link    TEXT NOT NULL,
    category    VARCHAR(100),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE priority_mail
    ADD COLUMN IF NOT EXISTS message_id TEXT UNIQUE;
    
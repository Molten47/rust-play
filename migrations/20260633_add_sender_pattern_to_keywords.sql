-- Add migration script here
ALTER TABLE keywords ADD COLUMN sender_pattern TEXT;
ALTER TABLE keywords ALTER COLUMN content DROP NOT NULL;
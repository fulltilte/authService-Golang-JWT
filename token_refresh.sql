CREATE TABLE refresh_tokens (
    user_id UUID UNIQUE NOT NULL,
    token_hash TEXT NOT NULL,
    ip_address VARCHAR(45) NOT NULL
);
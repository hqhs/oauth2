-- Add up migration script here

CREATE TABLE IF NOT EXISTS users (
    user_id BLOB PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id blob primary key,
    user_id blob NOT NULL UNIQUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Add up migration script here

CREATE TABLE IF NOT EXISTS users (
    user_id BLOB PRIMARY KEY,
    handle text not null unique,
    email text,
    name text,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id blob primary key,
    user_id blob NOT NULL,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

create table if not exists pending_authorizations (
    google_token text not null,
    discord_token text not null,
    twitch_token text not null
);

create table if not exists discord_users (
    user_id blob not null unique,
    discord_id text not null unique,

    -- user info
    username text not null,
    avatar text,
    locale text,
    email text,

    foreign key (user_id) references users(user_id)
);

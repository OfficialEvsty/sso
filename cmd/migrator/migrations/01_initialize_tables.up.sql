CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(254) NOT NULL UNIQUE,
    hash_pass VARCHAR(255) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_email ON users (email);

CREATE TABLE IF NOT EXISTS apps(
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    redirect_uri TEXT NOT NULL,
    secret TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(36) PRIMARY KEY,
    client_id INTEGER NOT NULL,
    ipv4 INET NOT NULL,
    scope TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (client_id) REFERENCES apps(id)  ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    session_id VARCHAR(36) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS redirect_uris (
    id BIGSERIAL PRIMARY KEY,
    uri TEXT NOT NULL,
    state TEXT NOT NULL,
    session_id VARCHAR(36) NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pkces (
    code_challenge TEXT PRIMARY KEY,
    hash_method TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    session_id VARCHAR(36) NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS authorization_codes (
    code VARCHAR(36) PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);
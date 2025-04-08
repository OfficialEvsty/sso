CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(50) PRIMARY KEY,
    client_id INTEGER NOT NULL,
    ipv4 VARCHAR(15) NOT NULL,
    FOREIGN KEY (client_id) REFERENCES apps(id)  ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    session_id VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS redirect_uris (
    id SERIAL PRIMARY KEY,
    uri TEXT NOT NULL,
    state TEXT NOT NULL,
    session_id VARCHAR(50) NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pkces (
    code_challenge TEXT PRIMARY KEY,
    hash_method TEXT NOT NULL,
    session_id VARCHAR(50) NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS authorization_codes (
    code VARCHAR(50) PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS email_verification (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(254) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
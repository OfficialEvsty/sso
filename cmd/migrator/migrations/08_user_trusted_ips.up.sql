CREATE TABLE IF NOT EXISTS user_trusted_ips (
    id BIGSERIAL PRIMARY KEY,
    ipv4 INET NOT NULL,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT unique_ip_per_user UNIQUE (user_id, ipv4)
);
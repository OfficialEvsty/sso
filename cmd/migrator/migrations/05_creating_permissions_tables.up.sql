    CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE IF NOT EXISTS app_roles (
    id SERIAL PRIMARY KEY,
    role_id INTEGER REFERENCES roles(is) ON DELETE CASCADE,
    app_id INTEGER REFERENCES apps(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (app_id) REFERENCES apps(id)
);

INSERT INTO roles (name) VALUES ('admin');
/*INSERT INTO user_roles (user_id, role_id) VALUES (1, 1);*/
CREATE TABLE roles (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(50) UNIQUE NOT NULL,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE TABLE users (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password VARCHAR(100) NOT NULL,
  enabled BOOLEAN DEFAULT TRUE,
  refresh_token VARCHAR,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE TABLE users_roles (
  user_id BIGINT NOT NULL,
  role_id BIGINT NOT NULL,
  PRIMARY KEY(user_id, role_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (role_id) REFERENCES roles(id)
);

INSERT INTO roles (name, created_at, updated_at) VALUES ('USER', now(), now()), ('ADMIN', now(), now());

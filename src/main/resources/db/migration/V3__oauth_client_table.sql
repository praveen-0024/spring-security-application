CREATE TABLE oauth_client (
    id BIGSERIAL PRIMARY KEY,
    registration_id VARCHAR(100) UNIQUE NOT NULL,   -- e.g., "google", "github"
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    redirect_uri VARCHAR(255),
    scope VARCHAR(255),
    provider_uri VARCHAR(255),
    authorization_uri VARCHAR(255),
    token_uri VARCHAR(255),
    user_info_uri VARCHAR(255),
    user_name_attribute VARCHAR(100),
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

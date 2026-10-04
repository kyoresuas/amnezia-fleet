-- NULL означает без лимита
ALTER TABLE users ADD COLUMN device_limit integer CHECK (device_limit > 0);

-- ссылка для самостоятельного подключения устройств
ALTER TABLE users ADD COLUMN link_token_enc bytea;
ALTER TABLE users ADD COLUMN link_token_hash bytea UNIQUE;

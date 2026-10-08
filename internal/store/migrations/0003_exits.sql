-- выход в другую страну для выбранных доменов, например YouTube через РФ
CREATE TABLE exits (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id      uuid NOT NULL UNIQUE REFERENCES clusters (id) ON DELETE CASCADE,
    name            text NOT NULL,
    endpoint        inet NOT NULL,
    listen_port     integer NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    public_key      text NOT NULL,
    private_key_enc bytea NOT NULL,
    params          jsonb NOT NULL,
    subnet_v4       cidr NOT NULL DEFAULT '10.67.0.0/24',
    dns             text NOT NULL DEFAULT '77.88.8.8',
    domains         text[] NOT NULL,
    enabled         boolean NOT NULL DEFAULT true,
    token_hash      bytea NOT NULL UNIQUE,
    last_seen_at    timestamptz,
    last_error      text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- ключ и адрес узла в туннеле до выхода
CREATE TABLE exit_links (
    exit_id         uuid NOT NULL REFERENCES exits (id) ON DELETE CASCADE,
    node_id         uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    public_key      text NOT NULL,
    private_key_enc bytea NOT NULL,
    address         inet NOT NULL,
    PRIMARY KEY (exit_id, node_id),
    UNIQUE (exit_id, address)
);

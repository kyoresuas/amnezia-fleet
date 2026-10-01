CREATE TABLE clusters (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL UNIQUE,
    hostname        text NOT NULL,
    listen_port     integer NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    public_key      text NOT NULL,
    private_key_enc bytea NOT NULL,
    params          jsonb NOT NULL,
    subnet_v4       cidr NOT NULL,
    subnet_v6       cidr,
    dns             text[] NOT NULL DEFAULT '{}',
    mtu             integer NOT NULL DEFAULT 1280,
    dns_mode        text NOT NULL DEFAULT 'failover' CHECK (dns_mode IN ('failover', 'all')),
    dns_ttl         integer NOT NULL DEFAULT 60 CHECK (dns_ttl >= 60),
    -- растёт при каждом изменении для агентов
    revision        bigint NOT NULL DEFAULT 1,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE nodes (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id       uuid NOT NULL REFERENCES clusters (id) ON DELETE CASCADE,
    name             text NOT NULL,
    state            text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'draining', 'disabled')),
    agent_token_hash bytea NOT NULL UNIQUE,
    last_seen_at     timestamptz,
    agent_version    text NOT NULL DEFAULT '',
    applied_revision bigint NOT NULL DEFAULT 0,
    last_error       text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cluster_id, name)
);

-- Публичные адреса узлов, публикуются в DNS
CREATE TABLE node_addresses (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id           uuid NOT NULL REFERENCES nodes (id) ON DELETE CASCADE,
    ip                inet NOT NULL UNIQUE,
    state             text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'spare', 'blocked', 'disabled')),
    priority          integer NOT NULL DEFAULT 100,
    health            text NOT NULL DEFAULT 'unknown' CHECK (health IN ('up', 'down', 'unknown')),
    health_changed_at timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                text NOT NULL UNIQUE,
    note                text NOT NULL DEFAULT '',
    status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    traffic_limit_bytes bigint CHECK (traffic_limit_bytes > 0),
    expires_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE peers (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    cluster_id        uuid NOT NULL REFERENCES clusters (id) ON DELETE CASCADE,
    name              text NOT NULL,
    public_key        text NOT NULL,
    private_key_enc   bytea,
    preshared_key_enc bytea,
    address_v4        inet NOT NULL,
    address_v6        inet,
    enabled           boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cluster_id, public_key),
    UNIQUE (cluster_id, address_v4),
    UNIQUE (cluster_id, address_v6)
);

CREATE INDEX peers_user_id_idx ON peers (user_id);

CREATE TABLE probes (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL UNIQUE,
    region       text NOT NULL DEFAULT '',
    public_key   text NOT NULL UNIQUE,
    token_hash   bytea NOT NULL UNIQUE,
    last_seen_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE probe_results (
    probe_id   uuid NOT NULL REFERENCES probes (id) ON DELETE CASCADE,
    address_id uuid NOT NULL REFERENCES node_addresses (id) ON DELETE CASCADE,
    ok         boolean NOT NULL,
    rtt_ms     integer,
    error      text NOT NULL DEFAULT '',
    -- одинаковых результатов подряд
    streak     integer NOT NULL DEFAULT 1,
    checked_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (probe_id, address_id)
);

CREATE TABLE dns_state (
    cluster_id uuid PRIMARY KEY REFERENCES clusters (id) ON DELETE CASCADE,
    records    inet[] NOT NULL DEFAULT '{}',
    synced_at  timestamptz,
    error      text NOT NULL DEFAULT ''
);

CREATE TABLE events (
    id         bigserial PRIMARY KEY,
    cluster_id uuid REFERENCES clusters (id) ON DELETE CASCADE,
    node_id    uuid REFERENCES nodes (id) ON DELETE CASCADE,
    kind       text NOT NULL,
    message    text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX events_created_at_idx ON events (created_at DESC);

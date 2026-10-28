-- Caminho: internal/seclog/migrations/001_security_events.sql
-- Tabela de eventos de segurança (append-only: o gateway só faz INSERT).
CREATE TABLE IF NOT EXISTS security_events (
    id          BIGSERIAL    PRIMARY KEY,
    occurred_at TIMESTAMPTZ  NOT NULL,
    event_type  TEXT         NOT NULL,
    severity    TEXT         NOT NULL,
    request_id  TEXT         NOT NULL DEFAULT '',
    client_ip   TEXT         NOT NULL DEFAULT '',
    client_id   TEXT         NOT NULL DEFAULT '',
    method      TEXT         NOT NULL DEFAULT '',
    path        TEXT         NOT NULL DEFAULT '',
    status      INTEGER      NOT NULL DEFAULT 0,
    detail      TEXT         NOT NULL DEFAULT ''
);

-- Índices para as consultas típicas de investigação.
CREATE INDEX IF NOT EXISTS idx_security_events_time      ON security_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_ip_time   ON security_events (client_ip, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_type_time ON security_events (event_type, occurred_at DESC);

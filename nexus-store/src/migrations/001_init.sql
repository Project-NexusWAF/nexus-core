CREATE TABLE IF NOT EXISTS rule_sets (
    id         SERIAL PRIMARY KEY,
    version    VARCHAR(50) NOT NULL UNIQUE,
    content    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active     BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_rule_sets_active ON rule_sets(active) WHERE active = TRUE;

CREATE TABLE IF NOT EXISTS attack_logs (
    id          UUID PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL,
    client_ip   INET NOT NULL,
    uri         TEXT NOT NULL,
    method      VARCHAR(10) NOT NULL,
    risk_score  REAL NOT NULL,
    decision    VARCHAR(20) NOT NULL,
    threat_tags TEXT[] NOT NULL DEFAULT '{}',
    blocked_by  VARCHAR(50),
    ml_score    REAL,
    ml_label    VARCHAR(50),
    block_code  VARCHAR(50)
);
CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_attack_logs_client_ip  ON attack_logs(client_ip);

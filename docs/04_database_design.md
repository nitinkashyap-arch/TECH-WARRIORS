# Database Entities & Schema Design

**Project Name:** Campus Cybersecurity Threat Detection System  
**Document Version:** 1.0.0  
**Target RDBMS:** PostgreSQL 16+  
**ORM Layer:** SQLAlchemy 2.0 (Async/Declarative) + Alembic  

---

## 1. Entity-Relationship (ER) Overview

The database stores administrative credentials, security rules, generated threat incidents, aggregated flow telemetry, simulation audit logs, and system metrics.

To prevent disk saturation during high-speed network capture, **individual packet payloads are never stored in the database**. Only aggregated flow summaries, triggered threat incident evidence, and periodic telemetry metrics are persisted.

```mermaid
erDiagram
    USERS ||--o{ THREAT_ALERTS : resolves
    USERS ||--o{ SIMULATION_RUNS : executes
    USERS ||--o{ AUDIT_LOGS : generates
    DETECTION_RULES ||--o{ THREAT_ALERTS : triggers
    SIMULATION_RUNS ||--o{ THREAT_ALERTS : originates
    THREAT_ALERTS ||--|| FLOW_EVIDENCE : contains

    USERS {
        uuid id PK
        varchar username UK
        varchar email UK
        varchar password_hash
        varchar role
        boolean is_active
        timestamp last_login_at
        timestamp created_at
    }

    DETECTION_RULES {
        uuid id PK
        varchar rule_code UK
        varchar name
        varchar category
        varchar severity
        jsonb condition_logic
        float threshold_value
        boolean is_enabled
        timestamp created_at
        timestamp updated_at
    }

    THREAT_ALERTS {
        uuid id PK
        varchar attack_type
        varchar severity
        varchar detection_source
        float confidence_score
        varchar source_ip
        varchar destination_ip
        integer source_port
        integer destination_port
        varchar protocol
        varchar status
        uuid rule_id FK "nullable"
        uuid simulation_run_id FK "nullable"
        uuid resolved_by FK "nullable"
        timestamp resolved_at
        timestamp created_at
    }

    FLOW_EVIDENCE {
        uuid id PK
        uuid alert_id FK UK
        integer packet_count
        bigint byte_count
        float duration_seconds
        integer syn_count
        integer ack_count
        integer fin_count
        integer rst_count
        float packet_rate
        float byte_rate
        jsonb raw_feature_vector
        timestamp captured_at
    }

    SIMULATION_RUNS {
        uuid id PK
        varchar attack_type
        varchar target_ip
        integer target_port
        integer packet_rate
        integer duration_seconds
        integer packets_transmitted
        varchar execution_status
        uuid initiated_by FK
        timestamp started_at
        timestamp completed_at
    }

    AUDIT_LOGS {
        uuid id PK
        uuid user_id FK "nullable"
        varchar action
        varchar client_ip
        jsonb details
        timestamp created_at
    }

    SYSTEM_METRICS {
        bigserial id PK
        timestamp recorded_at
        bigint total_packets
        bigint total_bytes
        integer active_flows
        integer tcp_count
        integer udp_count
        integer icmp_count
        float capture_fps
    }
```

---

## 2. Table Specifications & PostgreSQL DDL

### 2.1 Table: `users`
Stores administrative user accounts with encrypted credentials.

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'analyst', 'auditor')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);
```

### 2.2 Table: `detection_rules`
Defines deterministic signature criteria and configurable thresholds.

```sql
CREATE TABLE detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_code VARCHAR(50) NOT NULL UNIQUE,          -- e.g., 'RULE-DOS-SYNFLOOD-01'
    name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,                  -- 'DOS', 'SCAN', 'ANOMALY', 'BRUTEFORCE'
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    condition_logic JSONB NOT NULL,                 -- e.g., '{"field": "syn_ack_ratio", "op": ">", "val": 5.0}'
    threshold_value DOUBLE PRECISION,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_rules_enabled ON detection_rules(is_enabled);
CREATE INDEX idx_rules_category ON detection_rules(category);
```

### 2.3 Table: `simulation_runs`
Tracks all synthetic traffic and attack executions, including safety parameters and outcomes.

```sql
CREATE TABLE simulation_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_type VARCHAR(50) NOT NULL,               -- 'SYN_FLOOD', 'PORT_SCAN', 'DNS_TUNNEL', 'SSH_BRUTE'
    target_ip VARCHAR(45) NOT NULL,
    target_port INTEGER,
    packet_rate INTEGER NOT NULL,                   -- packets per second
    duration_seconds INTEGER NOT NULL,
    packets_transmitted INTEGER NOT NULL DEFAULT 0,
    execution_status VARCHAR(20) NOT NULL DEFAULT 'PENDING' 
        CHECK (execution_status IN ('PENDING', 'RUNNING', 'COMPLETED', 'ABORTED', 'FAILED')),
    initiated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sim_status ON simulation_runs(execution_status);
CREATE INDEX idx_sim_started ON simulation_runs(started_at DESC);
```

### 2.4 Table: `threat_alerts`
Primary security incident register aggregating detections from both ML and rule engines.

```sql
CREATE TABLE threat_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_type VARCHAR(100) NOT NULL,              -- e.g., 'TCP SYN Flood', 'Horizontal Port Scan'
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    detection_source VARCHAR(30) NOT NULL CHECK (detection_source IN ('RULE_BASED', 'MACHINE_LEARNING', 'HYBRID')),
    confidence_score REAL NOT NULL CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),
    source_ip VARCHAR(45) NOT NULL,                 -- Supports IPv4 or IPv6
    destination_ip VARCHAR(45) NOT NULL,
    source_port INTEGER CHECK (source_port >= 0 AND source_port <= 65535),
    destination_port INTEGER CHECK (destination_port >= 0 AND destination_port <= 65535),
    protocol VARCHAR(10) NOT NULL,                  -- 'TCP', 'UDP', 'ICMP', 'DNS'
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE' 
        CHECK (status IN ('ACTIVE', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')),
    rule_id UUID REFERENCES detection_rules(id) ON DELETE SET NULL,
    simulation_run_id UUID REFERENCES simulation_runs(id) ON DELETE SET NULL,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    notes TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Fast lookup indexes for Dashboard triage
CREATE INDEX idx_alerts_status ON threat_alerts(status);
CREATE INDEX idx_alerts_severity ON threat_alerts(severity);
CREATE INDEX idx_alerts_source_ip ON threat_alerts(source_ip);
CREATE INDEX idx_alerts_created_at ON threat_alerts(created_at DESC);
```

### 2.5 Table: `flow_evidence`
Stores the detailed numerical feature vector and packet statistics associated with an alert for academic inspection and triage verification.

```sql
CREATE TABLE flow_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID NOT NULL UNIQUE REFERENCES threat_alerts(id) ON DELETE CASCADE,
    packet_count INTEGER NOT NULL,
    byte_count BIGINT NOT NULL,
    duration_seconds REAL NOT NULL,
    syn_count INTEGER NOT NULL DEFAULT 0,
    ack_count INTEGER NOT NULL DEFAULT 0,
    fin_count INTEGER NOT NULL DEFAULT 0,
    rst_count INTEGER NOT NULL DEFAULT 0,
    packet_rate REAL NOT NULL,                      -- packets/sec
    byte_rate REAL NOT NULL,                        -- bytes/sec
    raw_feature_vector JSONB NOT NULL,              -- Numerical features passed into Scikit-learn
    captured_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_flow_evidence_alert ON flow_evidence(alert_id);
```

### 2.6 Table: `system_metrics`
Aggregated 1-minute time series data used to power historical trend charts without straining database memory.

```sql
CREATE TABLE system_metrics (
    id BIGSERIAL PRIMARY KEY,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    total_packets BIGINT NOT NULL,
    total_bytes BIGINT NOT NULL,
    active_flows INTEGER NOT NULL,
    tcp_count INTEGER NOT NULL,
    udp_count INTEGER NOT NULL,
    icmp_count INTEGER NOT NULL,
    capture_fps REAL NOT NULL DEFAULT 0.0           -- Frames per second processed
);

CREATE INDEX idx_metrics_recorded ON system_metrics(recorded_at DESC);
```

### 2.7 Table: `audit_logs`
Compliance table logging all administrative operations (rule modifications, simulations, triage actions).

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,                   -- e.g., 'TRIGGER_SIMULATION', 'DISMISS_ALERT'
    client_ip VARCHAR(45) NOT NULL,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);
```

---

## 3. Data Retention & Archival Strategy

In an active campus network, ingestion volume can grow rapidly. To guarantee that PostgreSQL does not exhaust college lab workstation disk storage:

| Entity | Retention Duration | Purge / Maintenance Policy |
| :--- | :--- | :--- |
| `threat_alerts` | 90 Days | Retained for semester report generation and academic evaluation. |
| `flow_evidence` | 90 Days | Cascades automatically when parent `threat_alerts` are purged. |
| `system_metrics` | 14 Days | Aggregated into daily rollups; raw 1-minute entries pruned after 14 days. |
| `simulation_runs` | 30 Days | Audit records preserved for evaluation review. |
| `audit_logs` | 180 Days | Standard compliance window. |

> [!TIP]
> A scheduled FastAPI background task runs a daily SQL cleanup script:
> ```sql
> DELETE FROM system_metrics WHERE recorded_at < NOW() - INTERVAL '14 days';
> ```

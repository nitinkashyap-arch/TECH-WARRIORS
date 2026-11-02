# Campus Cybersecurity Threat Detection System

[![Project Status: Phase 1 In Progress](https://img.shields.io/badge/Project%20Status-Phase%201%20(Specifications%20%26%20Setup)-blue.svg)](#)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-green.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18%20(TypeScript)-61dafb.svg)](https://react.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind%20CSS-3.4%2B-38bdf8.svg)](https://tailwindcss.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%20Alpine-336791.svg)](https://www.postgresql.org/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4%2B-f89939.svg)](https://scikit-learn.org/)
[![Docker](https://img.shields.io/badge/Deployment-Docker%20Compose-2496ed.svg)](https://www.docker.com/)

An enterprise-grade, hybrid network intrusion detection and telemetry platform engineered as an academic major project for college campus network environments. The system pairs **authorized passive real-time packet monitoring** with an **in-memory synthetic attack simulation engine**, detecting malicious activity through a synchronized **rule-based + machine learning** dual pipeline.

---

## 1. Project Overview

University and college campus networks operate under distinct operational challenges: thousands of unmanaged student BYOD (Bring Your Own Device) endpoints, open academic Wi-Fi, research servers, and high bandwidth volumes. Commercial enterprise SIEM/IDS platforms (e.g., Splunk, Cisco Firepower) are cost-prohibitive, closed-source, and poorly suited for student-level experimentation or academic evaluation.

The **Campus Cybersecurity Threat Detection System** bridges this gap:
- It monitors campus or lab traffic passively using **Scapy** with Berkeley Packet Filters (BPF).
- It provides a safe, sandboxed **traffic simulation engine** to generate realistic attack vectors (SYN floods, port scans, DNS tunneling, brute-force bursts) without risking live network downtime.
- It analyzes flows simultaneously with **deterministic signature rules** ($O(1)$ latency for known attacks) and **Scikit-learn ML models** (Random Forest + Isolation Forest for statistical and zero-day anomalies).
- It streams real-time threat alerts and throughput metrics to an **admin-only React dashboard** via WebSockets.

---

## 2. Key Features

- **Hybrid Network Telemetry:**
  - **Authorized Live Monitoring:** Promiscuous passive packet capture on authorized subnets or SPAN mirror ports.
  - **Sandboxed Simulation Generator:** Pre-packaged attack profiles with strict destination IP whitelist constraints and an instantaneous emergency abort button.
  - **Pure Simulation Mode:** Allows complete offline demonstration on a single laptop without elevated network privileges—ideal for college viva examinations.
- **Dual-Engine Detection:**
  - **Deterministic Rule Engine:** Evaluates declarative YAML signatures for abnormal TCP flag combinations, port sweeps, and threshold violations.
  - **Machine Learning Engine:** Extracts an 18-dimensional flow feature vector over 5-second sliding windows, running multi-class classification (Random Forest) and anomaly detection (Isolation Forest).
  - **Correlated Scoring:** Combines outputs into a unified threat index ($S \in [0.0, 1.0]$) to reduce false positives.
- **Admin-Only Real-Time Dashboard:**
  - **Live WebSocket Streaming:** 1-second batch telemetry heartbeats for throughput, packet rates, and active flows.
  - **Interactive Visualizations:** Recharts dual-area traffic volume, protocol breakdown donut, threat category bars, and top offending source IPs.
  - **Incident Triage:** Comprehensive alert inspection table with granular flow evidence, status management (`Active`, `Investigating`, `Resolved`, `False Positive`), and CSV/JSON export.
- **Privacy & Security by Design:**
  - **Zero Layer 7 Payload Storage:** Application-layer payloads (passwords, cookies, messages) are pruned in memory immediately after header dissection to uphold student privacy.
  - **Single-Tier Hardened Auth:** JWT bearer tokens signed with HMAC-SHA256, Argon2id/bcrypt password hashing, and tamper-evident audit logging.

---

## 3. Technology Stack

| Layer | Technology | Role & Function |
| :--- | :--- | :--- |
| **Frontend UI** | React 18, TypeScript, Vite | Single-page administrative dashboard |
| **Styling & UI** | Tailwind CSS, Lucide Icons | Responsive modern cybersecurity theme |
| **Charting Engine** | Recharts | Live timeseries throughput, protocol donut, threat bars |
| **Backend API** | Python 3.11+, FastAPI, Uvicorn | High-performance asynchronous REST & WebSocket backend |
| **Data Validation** | Pydantic v2 | Strict request/response DTO schemas |
| **Database & ORM** | PostgreSQL 16, SQLAlchemy 2.0, Alembic | Relational storage for users, rules, alerts, and metrics |
| **Network Engine** | Scapy, Npcap / libpcap, BPF | Raw packet capture, header dissection, packet crafting |
| **Machine Learning** | Scikit-learn, NumPy, Pandas, Joblib | Random Forest classifier, Isolation Forest, feature scaler |
| **Authentication** | JWT (`python-jose`), Passlib (Argon2id/bcrypt) | Stateless token-based administrative authentication |
| **Containerization** | Docker, Docker Compose | Modular multi-container deployment |

---

## 4. System Architecture Overview

The system operates across four decoupled layers communicating via asynchronous queues, REST APIs, and WebSockets:

```mermaid
graph TB
    subgraph ClientLayer ["1. Presentation Layer (Browser)"]
        UI["React Admin Dashboard (TypeScript + Tailwind)"]
        Charts["Recharts Live Analytics"]
        WSClient["WebSocket Client"]
        UI --- Charts
        UI --- WSClient
    end

    subgraph APILayer ["2. Application Layer (FastAPI)"]
        AuthModule["JWT Security & Auth"]
        RestRouter["REST API Endpoints (/api/v1)"]
        WSHub["WebSocket Telemetry Hub"]
        AlertService["Alert Triage Service"]
        SimService["Simulation Controller"]
        
        RestRouter --> AuthModule
        RestRouter --> AlertService
        RestRouter --> SimService
        AlertService --> WSHub
        SimService --> WSHub
    end

    subgraph DetectionLayer ["3. Detection & Correlation Pipeline"]
        FlowAggregator["Flow Aggregator (5s Sliding Windows)"]
        RuleEngine["Deterministic Rule Engine (YAML Signatures)"]
        MLEngine["Scikit-Learn ML Inference (RF + Isolation Forest)"]
        Correlator["Threat Scorer & Alert Correlator"]
        
        FlowAggregator --> RuleEngine
        FlowAggregator --> MLEngine
        RuleEngine --> Correlator
        MLEngine --> Correlator
        Correlator --> AlertService
    end

    subgraph IngestionLayer ["4. Network Ingestion Daemon"]
        ScapySniffer["Scapy Passive Sniffer (Promiscuous / BPF)"]
        TrafficSim["Synthetic Traffic & Attack Generator"]
        PacketQueue["Thread-Safe Ingestion Queue"]
        
        ScapySniffer --> PacketQueue
        TrafficSim --> PacketQueue
        PacketQueue --> FlowAggregator
    end

    subgraph DataLayer ["Persistence Layer"]
        Postgres[(PostgreSQL 16 Database)]
        ModelStore["Pre-Trained Models (.joblib)"]
        RuleStore["Rule Definitions (.yaml)"]
        
        AlertService --> Postgres
        MLEngine --> ModelStore
        RuleEngine --> RuleStore
    end

    WSClient <==>|WebSockets (Live Alerts & Telemetry)| WSHub
    UI <==>|HTTPS / JSON REST API| RestRouter
```

---

## 5. Detailed Architecture & Design Documentation

Comprehensive technical specifications are available in the [`docs/`](docs/) directory:

| Document | Description |
| :--- | :--- |
| [**01. Project Requirements Document**](docs/01_project_requirements.md) | Functional & non-functional requirements, user personas, privacy & academic boundaries. |
| [**02. System Architecture Document**](docs/02_system_architecture.md) | C4 architectural diagrams, sequence data flow, Docker containerization strategy. |
| [**03. Application Modules Specification**](docs/03_application_modules.md) | Monorepo layout, module responsibilities, and class interface contracts. |
| [**04. Database Entities & Schema Design**](docs/04_database_design.md) | PostgreSQL ER diagram, complete DDL schemas, indexes, and data retention policies. |
| [**05. API Architecture & Contracts**](docs/05_api_architecture.md) | REST API endpoints, JWT auth flow, and real-time WebSocket protocol frames. |
| [**06. Threat Detection Engine Specification**](docs/06_detection_engine.md) | 18-D feature vector, Random Forest & Isolation Forest pipelines, and correlation formula. |
| [**07. Network Monitoring & Simulation**](docs/07_network_monitoring_and_simulation.md) | Scapy packet capture, BPF filters, attack simulation profiles, and safety guardrails. |
| [**08. Development Roadmap & Milestones**](docs/08_development_roadmap.md) | 16-week milestone breakdown, sprint schedules, risk matrix, and viva defense plan. |
| [**Master Documentation Index**](docs/README.md) | Quick overview and navigation across all technical documents. |

---

## 6. Project Roadmap Overview

- [x] **Phase 1: Project Scaffolding & Specifications** *(Weeks 1–2 - In Progress)*
  - Architecture blueprints, ER design, API contracts, Git repo initialization.
- [ ] **Phase 2: Ingestion Pipeline & Synthetic Simulation** *(Weeks 3–4)*
  - Scapy sniffer, BPF filtering, flow aggregator, and attack simulation profiles.
- [ ] **Phase 3: Dual Detection Engine** *(Weeks 5–7)*
  - YAML rule evaluator, Scikit-learn model training, and threat correlation scoring.
- [ ] **Phase 4: Backend API & WebSocket Hub** *(Weeks 8–9)*
  - FastAPI routers, PostgreSQL ORM, JWT security, and 1-second telemetry broadcasting.
- [ ] **Phase 5: React Frontend Dashboard & Visualizations** *(Weeks 10–12)*
  - Recharts integration, live telemetry cards, alert triage table, and simulation controls.
- [ ] **Phase 6: System Integration & Lab Testing** *(Weeks 13–14)*
  - Docker Compose orchestration, campus testbed validation, and false-positive tuning.
- [ ] **Phase 7: Evaluation, Benchmarking & Viva Defense** *(Weeks 15–16)*
  - Confusion matrices, latency benchmarking, major project report, and demonstration presentation.

---

## 7. License & Academic Disclaimer

This project is developed for educational and academic evaluation purposes as a college major project. Live network capture and simulation tools must only be operated on networks with authorized consent from designated institutional administrators.

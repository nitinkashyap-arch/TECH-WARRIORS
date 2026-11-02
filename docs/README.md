# Campus Cybersecurity Threat Detection System
## Architecture & Engineering Specification Index

**Project Classification:** College Major Project  
**System Type:** Hybrid Intrusion Detection & Real-Time Network Threat Telemetry System  
**Stack:** React (TypeScript + Tailwind CSS + Recharts) | FastAPI (Python) | PostgreSQL | Scikit-learn | Scapy | WebSockets | Docker  

---

## Documentation Navigation

This documentation suite provides a complete, production-grade architectural blueprint for the major project. All specifications are organized into modular documents inside the `docs/` directory:

| Document | Purpose & Summary |
| :--- | :--- |
| [**01. Project Requirements Document (PRD)**](file:///c:/Users/nitin/Downloads/campus-cybersecurity-system/docs/01_project_requirements.md) | Problem statement, functional requirements (FR), non-functional requirements (NFR), user personas, academic constraints, privacy and compliance boundaries. |
| [**02. System Architecture Document**](file:///c:/Users/nitin/Downloads/campus-cybersecurity-system/docs/02_system_architecture.md) | High-level system architecture, C4 component diagrams, end-to-end data flow sequence, container topology, and quality attribute rationale. |
| [**03. Application Modules Specification**](file:///c:/Users/nitin/Downloads/campus-cybersecurity-system/docs/03_application_modules.md) | Comprehensive monorepo directory layout, backend modules (ingestion, simulation, detection, websocket, API), frontend modules (charts, triage, simulation panel), and interface contracts. |
| [**04. Database Entities & Schema Design**](file:///c:/Users/nitin/Downloads/campus-cybersecurity-system/docs/04_database_design.md) | PostgreSQL entity-relationship (ER) diagram, complete DDL schemas (users, alerts, flow evidence, rules, simulation runs, metrics), indexes, and storage retention strategies. |
| [**05. API Architecture & Contracts**](file:///c:/Users/nitin/Downloads/campus-cybersecurity-system/docs/05_api_architecture.md) | REST API catalog (`/api/v1`), OAuth2 JWT authentication flow, request/response JSON schemas, and real-time WebSocket protocol frames (telemetry heartbeats, alert broadcasts). |
| [**06. Threat Detection Engine Specification**](file:///c:/Users/nitin/Downloads/campus-cybersecurity-system/docs/06_detection_engine.md) | 18-dimensional flow feature extraction pipeline, Random Forest multi-class classifier, Isolation Forest anomaly detector, YAML deterministic signatures, and the hybrid correlation formula. |
| [**07. Network Monitoring & Simulation**](file:///c:/Users/nitin/Downloads/campus-cybersecurity-system/docs/07_network_monitoring_and_simulation.md) | Scapy passive promiscuous sniffing, BPF kernel filters, legal authorization protocol, payload stripping, pre-configured attack simulation profiles, and strict safety guardrails. |
| [**08. Development Roadmap & Milestones**](file:///c:/Users/nitin/Downloads/campus-cybersecurity-system/docs/08_development_roadmap.md) | 16-week college major project timeline, sprint deliverables, evaluation readiness, risk mitigation matrix, and benchmark methodology for viva defense. |

---

## Architectural Principles Summary

1. **Safety First (Zero Risk to Campus):** Built-in simulation targets only authorized loopback or isolated lab subnets. Public IPs are strictly blocked by guardrail code.
2. **Student & Faculty Privacy:** Layer 7 packet payloads are pruned in memory immediately after transport-layer header dissection. No personal browsing content is ever stored.
3. **Dual-Engine Precision:** Deterministic rules provide instantaneous zero-false-positive catches for known signatures (e.g., SYN floods, port scans), while Scikit-learn (Random Forest + Isolation Forest) catches statistical and zero-day anomalies.
4. **Resilient Decoupling:** Packet sniffing operates asynchronously in background worker threads, preventing heavy capture traffic from blocking the FastAPI web server or WebSocket telemetry.
5. **Demonstration Reliability:** The system can run in **Pure Simulation Mode** on a single laptop without internet, administrative Wi-Fi permissions, or special hardware, ensuring 100% reliability during viva examinations.

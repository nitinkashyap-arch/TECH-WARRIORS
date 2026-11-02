# Threat Detection Engine: Machine Learning & Rule-Based Approach

**Project Name:** Campus Cybersecurity Threat Detection System  
**Document Version:** 1.0.0  
**Core Technologies:** Python, Scikit-learn, NumPy, Pandas, Scapy  

---

## 1. Rationale for a Hybrid Detection Philosophy

Network intrusion detection systems historically fall into two polarized camps:
1. **Signature/Rule-Based (e.g., Snort, Suricata):** Fast ($O(1)$ or $O(N)$ string/regex matching), deterministic, with near-zero false positives for documented exploits, but completely blind to novel, obfuscated, or zero-day attacks.
2. **Anomaly/Machine Learning-Based:** Capable of generalizing and identifying subtle statistical deviations from baseline behavior, but prone to false-positive alarms caused by benign network bursts (e.g., steam updates, lab backups, student class registration rushes).

For a college campus network, where student activity fluctuates dramatically between lectures and dorm hours, an isolated ML model causes alert fatigue, while an isolated rule engine misses student-engineered exploits. Our system deploys a **dual-engine hybrid ensemble** that evaluates network traffic simultaneously through both paradigms.

```mermaid
flowchart LR
    PacketStream["Captured / Simulated Packet Flow"] --> Dissector["Header Dissector & Feature Aggregator"]
    
    subgraph DualEngine ["Dual Detection Engine"]
        Dissector -->|Windowed Statistics| RuleEngine["Rule-Based Engine<br/>(Deterministic Signatures)"]
        Dissector -->|18-D Feature Vector| MLEngine["Scikit-learn Pipeline<br/>(Random Forest + Isolation Forest)"]
    end

    RuleEngine -->|Rule Match Score (0.0 or 1.0)| Correlator["Threat Scorer & Correlator"]
    MLEngine -->|Softmax Probability & Anomaly Index| Correlator

    Correlator -->|Weighted Threat Score S in [0.0, 1.0]| SeverityClassifier{"Threat Score Threshold"}
    
    SeverityClassifier -->|< 0.40| Discard["Benign (Aggregate Only)"]
    SeverityClassifier -->|0.40 - 0.64| LowAlert["Low / Logged Anomaly"]
    SeverityClassifier -->|0.65 - 0.84| HighAlert["High Alert (Notify)"]
    SeverityClassifier -->|>= 0.85| CriticalAlert["Critical Alert (WebSocket Instant Push)"]
```

---

## 2. Feature Extraction & Engineering Pipeline

The system transforms raw packet streams into standardized numerical feature vectors over a **5.0-second sliding time window**.

### 2.1 The 18-Dimensional Feature Vector Specification

| # | Feature Name | Data Type | Formula / Description | Attack Sensitivity |
| :-: | :--- | :--- | :--- | :--- |
| **1** | `flow_duration` | Float (s) | $t_{\text{last}} - t_{\text{first}}$ within current window | Slowloris, Port Scans |
| **2** | `fwd_packets` | Integer | Total packets originating from source | Floods, Brute-Force |
| **3** | `bwd_packets` | Integer | Total packets responding from destination | Normal vs Unanswered Floods |
| **4** | `fwd_bytes` | BigInt | Total forward payload and header bytes | Exfiltration, Volume Floods |
| **5** | `bwd_bytes` | BigInt | Total backward payload and header bytes | Large Downloads, Echoes |
| **6** | `packet_rate` | Float | $(\text{fwd\_pkts} + \text{bwd\_pkts}) / \text{duration}$ | Volumetric DoS / DDoS |
| **7** | `byte_rate` | Float | $(\text{fwd\_bytes} + \text{bwd\_bytes}) / \text{duration}$ | Bandwidth Exhaustion |
| **8** | `pkt_len_mean` | Float | $\mu(\text{packet lengths})$ | Buffer overflows, Ping floods |
| **9** | `pkt_len_std` | Float | $\sigma(\text{packet lengths})$ | Uniform attacks vs irregular normal traffic |
| **10** | `syn_count` | Integer | Total packets with TCP SYN flag set | SYN Flood, Stealth Scans |
| **11** | `ack_count` | Integer | Total packets with TCP ACK flag set | Normal TCP session health |
| **12** | `fin_count` | Integer | Total packets with TCP FIN flag set | Session teardown, FIN scans |
| **13** | `rst_count` | Integer | Total packets with TCP RST flag set | Port rejection, Abort floods |
| **14** | `psh_count` | Integer | Total packets with TCP PSH flag set | Interactive traffic, Shell bursts |
| **15** | `syn_ack_ratio` | Float | $(\text{syn\_count} + 1) / (\text{ack\_count} + 1)$ | SYN Flood indicator |
| **16** | `dest_port_entropy` | Float | Count of unique destination ports targeted | Port sweeps & horizontal scans |
| **17** | `iat_mean` | Float | Mean Inter-Arrival Time between packets | Fast automated bots vs human traffic |
| **18** | `protocol_code` | Integer | Encoded protocol (TCP = 6, UDP = 17, ICMP = 1) | Protocol anomaly detection |

---

## 3. Machine Learning Architecture (Scikit-learn)

### 3.1 Model 1: Supervised Multi-Class Classifier (Random Forest)
- **Why Random Forest?**
  1. Superior performance on tabular network metadata compared to Deep Neural Networks.
  2. Highly resistant to overfitting on high-variance network features.
  3. Ultra-low CPU inference latency ($\approx 5 - 12\text{ ms}$ per flow window), allowing high-throughput inspection on standard college PCs without requiring a dedicated GPU.
  4. Provides explicit feature importances for academic explainability during viva presentations.
- **Classification Targets:**
  - `0`: Benign / Legitimate Traffic
  - `1`: DoS / DDoS (SYN flood, UDP flood)
  - `2`: Port Scan / Network Reconnaissance
  - `3`: Brute Force (SSH / HTTP login bursts)

### 3.2 Model 2: Unsupervised Zero-Day Anomaly Detector (Isolation Forest)
- **Purpose:** Identifies novel anomalous traffic patterns that do not match known attack signatures or supervised training classes.
- **Mechanism:** Isolates observations by randomly selecting a feature and splitting value. Anomalies require fewer splits to isolate than normal cluster points.
- **Output:** Anomaly score $A_{\text{if}} \in [-1.0, 1.0]$. Values $< -0.2$ indicate significant statistical deviation.

### 3.3 Training Strategy & Dataset Ground Truth
1. **Public IDS Dataset Baseline:**
   - Pre-processed subsets of **CIC-IDS2017** and **NSL-KDD**.
   - Redundant or socket-specific features (e.g., static IP addresses, exact timestamps) are excluded to prevent models from memorizing IP addresses instead of learning behavioral characteristics.
2. **Campus Synthetic Augmentation:**
   - Synthetic attack flows generated by our Scapy simulation engine are injected into benign baseline lab traffic to adapt the model to the local network topology.
3. **Pipeline Serialization:**
   - Models are bundled with fitted `StandardScaler` transformations using `joblib`:
     - `models/rf_classifier_v1.joblib`
     - `models/iso_forest_v1.joblib`
     - `models/scaler_v1.joblib`

---

## 4. Rule-Based Engine Specification

The rule engine executes declarative rules written in YAML format (`rules/signatures.yaml`). Each rule specifies matching conditions and an assigned severity.

### 4.1 Sample Rule Definitions

```yaml
rules:
  - id: "RULE-DOS-SYNFLOOD-01"
    name: "TCP SYN Flood Attack Signature"
    category: "DOS"
    severity: "CRITICAL"
    enabled: true
    condition:
      protocol: "TCP"
      syn_count: { gt: 50 }
      syn_ack_ratio: { gt: 4.0 }
      packet_rate: { gt: 80.0 }
    description: "Abnormal surge of SYN packets with negligible ACK replies, indicative of half-open connection exhaustion."

  - id: "RULE-SCAN-HORIZONTAL-01"
    name: "Horizontal Port Sweep"
    category: "SCAN"
    severity: "HIGH"
    enabled: true
    condition:
      protocol: "TCP"
      dest_port_entropy: { gt: 15 }
      duration: { lt: 3.0 }
    description: "Single source querying over 15 unique destination ports within a 3-second window."

  - id: "RULE-FLAG-MALFORMED-01"
    name: "TCP Null / Xmas Scan Flags"
    category: "SCAN"
    severity: "HIGH"
    enabled: true
    condition:
      protocol: "TCP"
      invalid_flags: true # Flags == 0 (NULL) or (SYN+FIN) or (FIN+PSH+URG)
    description: "Illegal TCP flag combinations used to bypass rudimentary stateless firewalls."

  - id: "RULE-PORT-SUSPICIOUS-01"
    name: "Known Backdoor / Trojan Port Access"
    category: "MALWARE"
    severity: "CRITICAL"
    enabled: true
    condition:
      dest_port_in: [4444, 31337, 5555, 6667, 1337]
    description: "Outbound or inbound connection targeting well-known reverse-shell or C2 communication ports."
```

---

## 5. Threat Correlation & Unified Scoring Formula

When a flow window completes, it is evaluated by both engines. The Correlator computes a composite Threat Score $S \in [0.0, 1.0]$:

$$S = \min\left(1.0, \; w_r \cdot S_{\text{rule}} + w_m \cdot P_{\text{rf}} + w_a \cdot A_{\text{norm}}\right)$$

Where:
- $S_{\text{rule}} \in \{0.0, 1.0\}$: Binary match indicator from the rule engine.
- $P_{\text{rf}} \in [0.0, 1.0]$: Random Forest predicted class probability for the highest non-benign class.
- $A_{\text{norm}} \in [0.0, 1.0]$: Normalized Isolation Forest anomaly score ($A_{\text{norm}} = \frac{1 - A_{\text{if}}}{2}$).
- Default Weights:
  - $w_r = 0.50$ (Deterministic rules carry high decisive authority)
  - $w_m = 0.35$ (Supervised Random Forest attack probability)
  - $w_a = 0.15$ (Unsupervised anomaly deviation)

### 5.1 Threat Triage Decision Matrix

| Rule Match ($S_{\text{rule}}$) | ML Prob ($P_{\text{rf}}$) | Anomaly ($A_{\text{norm}}$) | Unified Score ($S$) | Final Classification | Action Taken |
| :-: | :-: | :-: | :-: | :--- | :--- |
| 1.0 | $\ge 0.70$ | $\ge 0.60$ | $\ge 0.85$ | **CRITICAL (Hybrid Confirmed)** | Immediate DB write, WebSocket broadcast, Audio alert on UI |
| 1.0 | $< 0.40$ | $< 0.30$ | $\approx 0.55 - 0.65$ | **MEDIUM (Signature Only)** | DB write, UI table update, Rule hit badge |
| 0.0 | $\ge 0.80$ | $\ge 0.70$ | $\approx 0.70 - 0.80$ | **HIGH (Statistical Attack)** | DB write, ML Anomaly badge, WebSocket notification |
| 0.0 | $< 0.30$ | $\ge 0.85$ | $\approx 0.45 - 0.55$ | **LOW (Novel Deviation)** | Telemetry log, flagged for analyst review |
| 0.0 | $< 0.30$ | $< 0.30$ | $< 0.30$ | **BENIGN** | Discard flow details, increment traffic counter |

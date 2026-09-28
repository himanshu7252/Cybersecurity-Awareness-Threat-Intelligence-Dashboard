# Cybersecurity Awareness & Threat Intelligence Dashboard
*A Defensive Cybersecurity, SOC Telemetry, Threat Intelligence, and Security Awareness Platform*

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.x-green.svg)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/Tests-35%2F35%20Passing%20(100%25)-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Defensive](https://img.shields.io/badge/Mode-100%25%20Defensive%20%26%20Safe-teal.svg)](#ethical-disclaimer)

---

## Overview
The **Cybersecurity Awareness & Threat Intelligence Dashboard** is an enterprise-grade, defensive cybersecurity project that bridges technical **Cyber Threat Intelligence (CTI)** processing with human-layer **Cybersecurity Awareness**. 

Designed for students, SOC analysts, and security engineers, the platform ingests, validates, normalizes, scores, correlates, and visualizes over **2,300 safe synthetic threat intelligence records**. In parallel, it hosts an interactive educational center with **15 defensive modules** and an automated **32-question assessment quiz** that calculates an awareness readiness score and outputs personalized learning paths.

---

## Key Features & Highlights

- **Threat Intelligence Feed:** Over 2,300 threat records spanning 10 threat categories and 6 indicator types.
- **SOC-Style Visual Analytics:** 10 interactive Chart.js visualizations (Threats over time, severity donut, category breakdown, IOC type distribution, MITRE ATT&CK tactics, risk histogram, confidence distribution, vulnerability severity, polar density, threat status).
- **Passive IOC Search & Enrichment:** Instant lookup tool that enriches IPs, domains, hashes, URLs, and CVEs strictly via local database queries with **zero external outbound network connections**.
- **Multi-Format IOC Syntax Validator:** Strict syntax validation engine for IPv4, IPv6, Domain, URL, MD5, SHA-1, SHA-256, and CVE IDs.
- **Mathematical Multi-Factor Risk Scoring:** Composite risk engine weighting severity (30%), confidence (25%), recency (15%), observation frequency (10%), source reliability (10%), and correlation (10%).
- **Risk vs. Confidence Calibration:** Clear operational separation between threat impact (Risk) and intelligence certainty (Confidence).
- **Admiralty-Style Source Reliability:** Evaluates sources across Tiers A through D (Internal SOC, Vendor, Research Report, Public Feed, Community, Unknown).
- **MITRE ATT&CK Behavioral Mapping:** Direct mapping to ATT&CK tactics and techniques with standardized IDs.
- **SOC Alert Engine with De-duplication:** Automatically triggers alerts on risk thresholds and correlates repetitive sightings to eliminate **SOC Analyst Alert Fatigue**.
- **Contextual Vulnerability Prioritization:** Balances base CVSS scores against asset criticality, perimeter exposure, and active exploitation evidence.
- **Tier-1 SOC Investigation View:** Chronological threat lifecycle timeline, correlated cluster graph, defensive SOP action checklist, and interactive analyst case notes.
- **Executive Cybersecurity Summary:** Non-technical posture briefing for C-suite and leadership.
- **15 Cybersecurity Awareness Modules:** Comprehensive guides detailing what each threat is, why it matters, critical warning signs, safe defensive habits, and incident reporting guidance.
- **32-Question Awareness Assessment Quiz:** Multi-category assessment evaluating competency and calculating an educational readiness score (0-100) with tailored recommendations.
- **Automated 35-Scenario Test Suite:** 100% passing tests covering syntax validation, risk engines, alert correlation, and database persistence.

---

## Critical SOC Taxonomy Distinction

The platform enforces strict adherence to defensive taxonomy:

```
┌────────────────────────────────────────────────────────┐
│ 1. OBSERVATION: Raw log entry / packet / sighting       │
│      ▼                                                 │
│ 2. INDICATOR (IOC): Artifact (IP, Hash, Domain, URL)   │
│      ▼                                                 │
│ 3. ALERT: Rule-based or threshold trigger for triage    │
│      ▼                                                 │
│ 4. THREAT: Hostile capability with malicious potential │
│      ▼                                                 │
│ 5. INCIDENT: Confirmed impact on system or CIA triad   │
└────────────────────────────────────────────────────────┘
```
> **Critical Rule:** An IOC match does **NOT** equal a confirmed breach! Indicators must be investigated in context before destructive containment actions are taken.

---

## Safe Synthetic Dataset

To ensure ethical and safe execution:
- **IP Addresses:** RFC 5737 Documentation Ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- **Domains:** RFC 2606 / RFC 6761 Reserved Domains (`example.com`, `example.org`, `*.invalid`).
- **URLs:** Sanitized fictional paths (e.g., `https://login-check.invalid/auth/checkpoint`).
- **File Hashes:** Randomly generated cryptographic SHA-256 strings labeled `SYNTHETIC / DEMO ONLY`.

---

## Technology Stack

- **Backend:** Python 3.11+, Flask 3.x
- **Data Analytics & Storage:** SQLite3 (WAL mode enabled), Pandas
- **Frontend:** Vanilla HTML5, Modern CSS (Glassmorphism, High-Tech SOC Dark Theme), Vanilla JavaScript (ES6 Modules)
- **Visual Analytics:** Chart.js 4.4, Font Awesome 6
- **Testing:** Pytest 8.x, Python `unittest`

---

## System Architecture

```
Synthetic / Public Defensive Data
                ↓
      Data Ingestion Layer
                ↓
    Normalization & Validation (IOC Validator)
                ↓
         Local Threat Enrichment
                ↓
    Multi-Factor Risk + Confidence Engine
                ↓
 ┌──────────────┼─────────────────┐
 ↓              ↓                 ↓
Threat DB   Alert Engine    ATT&CK Mapping
 ↓              ↓                 ↓
 └──────────────┼─────────────────┘
                ↓
      Flask REST API & Engine
                ↓
  ┌─────────────┴─────────────┐
  ↓                           ↓
SOC Dashboard & Triage    Awareness Center & Quiz
```

---

## Project Folder Structure

```
Cybersecurity-Awareness-Threat-Intelligence-Dashboard/
│
├── backend/
│   ├── app.py                      # Flask server & route registrations
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── threats.py              # Threat feed, details, notes APIs
│   │   ├── indicators.py           # Passive search & syntax validation APIs
│   │   ├── dashboard.py            # Stats, trends, and executive summary APIs
│   │   ├── alerts.py               # Alert triage and fatigue reduction APIs
│   │   ├── vulnerabilities.py      # CVE awareness and prioritization APIs
│   │   └── awareness.py            # Modules, quiz, and submission evaluation APIs
│   ├── models/
│   │   ├── __init__.py
│   │   └── database.py             # SQLite schema, tables, WAL mode, seed loader
│   ├── services/
│   │   ├── __init__.py
│   │   ├── threat_service.py       # Core querying, filtering, and stats aggregation
│   │   ├── ioc_validator.py        # Multi-format syntax validation engine
│   │   ├── enrichment_engine.py    # Passive local database enrichment
│   │   ├── risk_engine.py          # Multi-factor threat risk & CVE priority engines
│   │   ├── correlation_engine.py   # Threat clustering and timeline milestones
│   │   ├── alert_engine.py         # Alert generation and de-duplication
│   │   ├── attack_mapper.py        # MITRE ATT&CK tactic/technique taxonomy
│   │   └── awareness_service.py    # Quiz scoring and personalized recommendations
│   └── utils/
│       ├── __init__.py
│       └── helpers.py              # XSS sanitization and API response formatting
│
├── frontend/
│   ├── index.html                  # Executive Cybersecurity Summary & Portal Home
│   ├── threat-dashboard.html       # SOC Dashboard (10 charts, table, search modal)
│   ├── threat-details.html         # Tier-1 SOC Case Investigation View
│   ├── awareness.html              # Cybersecurity Awareness Center (15 modules)
│   ├── quiz.html                   # 32-Question Assessment Quiz & Score Report
│   ├── css/
│   │   └── styles.css              # SOC Dark Theme with Glassmorphic styling
│   └── js/
│       ├── api.js                  # Frontend REST API client
│       ├── dashboard.js            # Chart.js visualizations & feed logic
│       ├── details.js              # Threat dossier, timeline, and analyst notes
│       ├── awareness.js            # Module cards and modal viewer logic
│       └── quiz.js                 # Interactive quiz engine and score evaluator
│
├── awareness/
│   ├── modules.json                # 15 defensive educational modules
│   └── quiz_questions.json         # 32 questions across 10 security categories
│
├── data/
│   ├── generate_threat_data.py     # Synthetic dataset generator script
│   ├── threat_intelligence_dataset.csv # 2,300+ safe threat records
│   └── vulnerabilities.csv         # Curated defensive CVE awareness dataset
│
├── tests/
│   ├── __init__.py
│   └── test_all_35_scenarios.py    # Automated 35-scenario unit & integration test suite
│
├── docs/
│   ├── API_DOCUMENTATION.md        # Comprehensive REST API specifications
│   ├── ARCHITECTURE.md             # System architecture & CTI foundations
│   ├── SOC_ANALYST_PLAYBOOK.md     # Tier-1 triage playbook & safe demonstration
│   └── INTERVIEW_PREPARATION.md    # 10 placement interview Q&As
│
├── reports/
│   └── PROJECT_REPORT.md           # 31-section academic/industry project report
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Local Installation & Execution Guide

### Prerequisites
- Python 3.10 or higher
- Git

### Step-by-Step Execution

#### Step 1: Clone the Repository
```bash
git clone https://github.com/your-username/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
```

#### Step 2: Create a Virtual Environment
```bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On Linux/macOS:
source venv/bin/activate
```

#### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

#### Step 4: (Optional) Re-generate Synthetic Threat Data
```bash
python data/generate_threat_data.py
```

#### Step 5: Run Automated Tests
```bash
pytest
# Or:
python -m unittest tests/test_all_35_scenarios.py
```

#### Step 6: Start the Platform Server
```bash
python backend/app.py
```

#### Step 7: Open the Application
Navigate in any web browser to:
- **Executive Summary:** `http://127.0.0.1:5000/`
- **SOC Threat Intelligence Dashboard:** `http://127.0.0.1:5000/threat-dashboard.html`
- **SOC Threat Investigation View:** `http://127.0.0.1:5000/threat-details.html?id=THR-2026-001`
- **Cybersecurity Awareness Center:** `http://127.0.0.1:5000/awareness.html`
- **Security Assessment Quiz:** `http://127.0.0.1:5000/quiz.html`

---

## Safe Demonstration Scenario: Case Study `THR-2026-001`

To safely demonstrate SOC investigation capabilities:
1. Open the **Threat Dashboard** (`/threat-dashboard.html`).
2. In the search box, enter `198.51.100.25` or `login-check.invalid` and click **Enrich IOC**.
3. Observe the passive enriched dossier:
   - **Threat ID:** `THR-2026-001`
   - **Category:** `PHISHING`
   - **Risk Score:** `78/100` (High)
   - **Confidence Score:** `85/100`
   - **Syntactic Validation:** Valid domain name format
   - **Notice:** Confirmed zero external network connection.
4. Click **Open Full SOC Investigation** to inspect the chronological timeline and MITRE ATT&CK mapping (`T1566 Phishing`).
5. In the **Analyst Notes** form, record a triage finding and observe the instant persistent update.

---

## Automated Test Results (35 / 35 Passed)

| Test ID | Scenario | Expected | Result |
| :--- | :--- | :--- | :--- |
| **TC-01** | Valid IPv4 Syntax | `valid=True, type=IPv4` | **PASS** |
| **TC-02** | Invalid IPv4 Syntax | `valid=False` | **PASS** |
| **TC-03** | Valid IPv6 Syntax | `valid=True, type=IPv6` | **PASS** |
| **TC-04** | Valid Domain Syntax | `valid=True, type=DOMAIN` | **PASS** |
| **TC-05** | Invalid Domain Syntax | `valid=False` | **PASS** |
| **TC-06** | Valid URL Syntax | `valid=True, type=URL` | **PASS** |
| **TC-07** | Valid MD5 Hash Syntax | `valid=True, type=MD5` | **PASS** |
| **TC-08** | Valid SHA1 Hash Syntax | `valid=True, type=SHA-1` | **PASS** |
| **TC-09** | Valid SHA256 Hash Syntax | `valid=True, type=SHA-256` | **PASS** |
| **TC-10** | Valid CVE Format | `valid=True, type=CVE ID` | **PASS** |
| **TC-11** | Invalid CVE Format | `valid=False` | **PASS** |
| **TC-12** | Threat Record Creation | `success=True` | **PASS** |
| **TC-13** | Multi-Factor Risk Calculation | `Score in [60, 90]` | **PASS** |
| **TC-14** | Confidence Score Penalty | `Score reflects lower certainty` | **PASS** |
| **TC-15** | Source Reliability Tiers | `Grade A (SOC) > Grade D (Unknown)` | **PASS** |
| **TC-16** | Local IOC Passive Enrichment | `known=True, ID=THR-2026-001` | **PASS** |
| **TC-17** | Indicator Search Lookup | `Found in demo dataset` | **PASS** |
| **TC-18** | Threat Cluster Correlation | `Cluster > 0, Timeline >= 3` | **PASS** |
| **TC-19** | Duplicate Observation De-duplication | `status=CORRELATED, count>=2` | **PASS** |
| **TC-20** | Alert Generation Threshold | `alert_id generated` | **PASS** |
| **TC-21** | Alert Correlation Retrieval | `Returns active alerts list` | **PASS** |
| **TC-22** | Alert Status Transition | `status=INVESTIGATING` | **PASS** |
| **TC-23** | SOC Analyst Note Logging | `success=True, note_id>0` | **PASS** |
| **TC-24** | MITRE ATT&CK Mapping | `Maps to Impact (T1486)` | **PASS** |
| **TC-25** | Contextual Vulnerability Scoring | `Exposed Crit > Internal Low` | **PASS** |
| **TC-26** | Dashboard Aggregated Statistics | `Total Threats >= 2,000` | **PASS** |
| **TC-27** | Threat Feed Severity Filtering | `All returned are CRITICAL` | **PASS** |
| **TC-28** | Threat Feed Category Filtering | `All returned are PHISHING` | **PASS** |
| **TC-29** | Threat Feed Risk Sorting | `Sorted descending` | **PASS** |
| **TC-30** | Awareness Module Retrieval | `15 modules loaded` | **PASS** |
| **TC-31** | Awareness Quiz Scoring Engine | `100% answers = Strong Awareness` | **PASS** |
| **TC-32** | Personalized Learning Recommendations | `Recommends weak category` | **PASS** |
| **TC-33** | Empty Dataset Search Handling | `total_records=0` | **PASS** |
| **TC-34** | REST API Input Validation | `status=400 on missing parameter` | **PASS** |
| **TC-35** | Database Persistence Verification | `Threats >= 2000, Vulns > 0` | **PASS** |

---

## Security, Privacy & Ethical Compliance

- **No Active Probing:** Indicators are analyzed purely as passive data records. The application will never establish TCP/HTTP connections to searched hosts.
- **Sanitized Documentation Ranges:** Strictly uses RFC 5737 and RFC 2606 reserved namespaces.
- **Input Sanitization:** All text inputs are HTML-escaped to prevent Stored Cross-Site Scripting (XSS).
- **Access Control Notice:** Threat intelligence data often includes sensitive internal sighting telemetry requiring role-based access control (RBAC) in production environments.

---

## GitHub Repository & Proof of Work Strategy

### Recommended GitHub Topics
`cybersecurity` `threat-intelligence` `cti` `soc` `ioc` `mitre-attack` `security-awareness` `python` `flask` `vulnerability-management` `incident-response` `security-analytics` `defensive-security`

### Recommended Commit History
```bash
git init
git add .
git commit -m "Initialize cybersecurity threat intelligence dashboard"
git commit -m "Add synthetic threat intelligence dataset"
git commit -m "Implement IOC validation engine"
git commit -m "Add threat enrichment engine"
git commit -m "Implement multi-factor risk and confidence scoring"
git commit -m "Add threat correlation and timeline milestones"
git commit -m "Implement security alert engine with fatigue reduction"
git commit -m "Add MITRE ATT&CK mapping module"
git commit -m "Build vulnerability awareness and contextual prioritization"
git commit -m "Create SOC threat dashboard with 10 Chart.js analytics"
git commit -m "Add IOC search and passive lookup modal"
git commit -m "Build threat investigation case view and analyst notes"
git commit -m "Create cybersecurity awareness center with 15 modules"
git commit -m "Add 32-question security awareness quiz"
git commit -m "Implement awareness scoring and personalized recommendations"
git commit -m "Add executive cybersecurity summary"
git commit -m "Implement automated 35-scenario test suite"
git commit -m "Complete README, playbooks, and architectural documentation"
```

---

## Ethical Disclaimer

> **IMPORTANT DEFENSIVE NOTICE:**  
> This project is designed exclusively for defensive cybersecurity education, threat intelligence analysis, and security awareness training. It does **not** execute, deploy, or interact with malicious payloads or unauthorized external systems. All indicators used are synthetic and conform to documentation standards.

---

## Author & Acknowledgements
- **Developer:** Defensive Cybersecurity Engineering Student & SOC Analyst
- **Mentor:** Antigravity AI Cybersecurity Pair Programmer
- **Course:** Defensive Cybersecurity & Threat Intelligence Capstone

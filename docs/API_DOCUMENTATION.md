# REST API Documentation
**Cybersecurity Awareness & Threat Intelligence Dashboard**
*Defensive Security Engineering & SOC Training Platform*

---

## Architecture & Base URL
- **Base URL:** `http://127.0.0.1:5000/api`
- **Content-Type:** `application/json`
- **Data Protection:** All indicator lookups operate passively on local synthetic datasets. No external connections are established.

---

## 1. Indicator Validation & Search

### `POST /api/indicators/validate`
Validates the syntactic format of a threat indicator without evaluating reputation.
- **Request Body:**
  ```json
  {
    "indicator": "198.51.100.25"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "data": {
      "valid": true,
      "indicator_type": "IP ADDRESS (IPv4)",
      "normalized_value": "198.51.100.25",
      "validation_notes": "Valid IPv4 address notation (4 octets, 0-255) (Matches safe RFC 5737 documentation test range)."
    }
  }
  ```

### `GET /api/indicators/search?q={indicator}`
Passively enriches an indicator against local synthetic threat intelligence.
- **Query Parameters:**
  - `q` (required): The indicator string (IP, Domain, URL, Hash, CVE).
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "data": {
      "searched_indicator": "login-check.invalid",
      "normalized_value": "login-check.invalid",
      "syntactic_validation": { "valid": true, "indicator_type": "DOMAIN" },
      "known_in_demo_dataset": true,
      "threat_id": "THR-2026-001",
      "threat_name": "Synthetic Credential Phishing Campaign",
      "indicator_type": "DOMAIN",
      "sightings_count": 1,
      "first_seen": "2026-09-01T08:00:00Z",
      "last_seen": "2026-09-28T10:00:00Z",
      "severity": "HIGH",
      "risk_score": 78,
      "confidence_score": 85,
      "status": "MONITORING",
      "associated_categories": ["PHISHING"],
      "sources": [{ "name": "Internal SOC", "reliability": "A – Highly Reliable" }],
      "mitre_mapping": [{ "tactic": "Initial Access", "technique": "Phishing (T1566)" }],
      "related_alerts": [],
      "related_indicators": [],
      "defensive_recommendations": [
        "Review historical firewall, proxy, and DNS query logs for internal resolution.",
        "Check endpoint detection & response (EDR) telemetry for matching hashes.",
        "Add to defensive perimeter sinkhole blocklist if verified malicious."
      ],
      "defensive_notice": "Passive database lookup only. No automated external connection was established."
    }
  }
  ```

---

## 2. Threat Intelligence Feed

### `GET /api/threats`
Retrieves paginated, filtered, and sorted threat intelligence records.
- **Query Parameters:**
  - `category` (optional): Filter by threat category (`PHISHING`, `MALWARE`, `RANSOMWARE`, etc.)
  - `severity` (optional): Filter by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`)
  - `indicator_type` (optional): Filter by indicator type (`IP ADDRESS`, `DOMAIN`, `URL`, `FILE HASH`, `CVE ID`)
  - `status` (optional): Filter by status (`NEW`, `UNDER_REVIEW`, `MONITORING`, `CLOSED`, `FALSE_POSITIVE`)
  - `min_risk` / `max_risk` (optional): Numeric range (0-100)
  - `min_confidence` (optional): Numeric threshold (0-100)
  - `search` (optional): Free-text substring match
  - `sort_by` (optional): `last_seen`, `first_seen`, `risk_score`, `confidence_score`
  - `order` (optional): `desc` or `asc`
  - `page` (optional, default 1)
  - `page_size` (optional, default 25)
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "data": {
      "total_records": 2301,
      "page": 1,
      "page_size": 25,
      "total_pages": 93,
      "threats": [ ... ]
    }
  }
  ```

### `GET /api/threats/{threat_id}`
Retrieves complete details for a single threat record including indicators, ATT&CK mappings, alerts, and notes.

### `POST /api/threats`
Ingests a new threat record with automatic risk calculation.
- **Request Body:**
  ```json
  {
    "threat_name": "Synthetic Endpoint Dropper",
    "category": "MALWARE",
    "severity": "HIGH",
    "confidence_score": 80,
    "indicator_type": "FILE HASH",
    "indicator_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
  ```

### `POST /api/threats/{threat_id}/notes`
Appends a SOC analyst triage note to an existing case.

---

## 3. SOC Dashboard & Metrics

### `GET /api/dashboard/stats`
Returns aggregated high-level SOC key performance indicators (KPIs):
- `total_threats`
- `critical_threats`
- `high_threats`
- `active_indicators`
- `open_investigations`
- `average_confidence`
- `vulnerabilities_tracked`
- `active_alerts`

### `GET /api/dashboard/trends`
Provides compiled datasets for the 10 Chart.js dashboard visualizations:
1. `threats_over_time`
2. `threats_by_severity`
3. `threats_by_category`
4. `ioc_distribution`
5. `attack_tactics`
6. `risk_distribution`
7. `confidence_distribution`
8. `vulns_by_severity`
9. `top_categories`
10. `threat_status_distribution`

### `GET /api/executive/summary`
Generates non-technical strategic posture report for C-suite and leadership.

---

## 4. Alert Management & Fatigue Reduction

### `GET /api/alerts`
Returns correlated alerts with optional `?status=` filter.

### `PUT /api/alerts/{alert_id}/status`
Transitions alert triage status (`NEW`, `INVESTIGATING`, `MONITORING`, `RESOLVED`, `FALSE_POSITIVE`).

---

## 5. Vulnerability Awareness

### `GET /api/vulnerabilities`
Returns tracked CVE records sorted by priority score.

### `POST /api/vulnerabilities/prioritize`
Calculates contextual patching priority given asset criticality and internet exposure factors.

---

## 6. Cybersecurity Awareness & Quiz

### `GET /api/awareness/modules`
Returns the 15 defensive educational modules with warning signs and safe practices.

### `GET /api/quiz`
Retrieves 32 assessment questions across 10 security domains.

### `POST /api/quiz/submit`
Evaluates user answers, computes 0-100 awareness score, assigns grade, and outputs personalized learning recommendations.

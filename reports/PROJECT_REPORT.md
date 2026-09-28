# Comprehensive Project Report
## Cybersecurity Awareness & Threat Intelligence Dashboard
**Academic & Industry Defensive Security Engineering Portfolio Project**

---

## 1. Abstract
The modern cybersecurity landscape is characterized by a widening attack surface that targets both technological infrastructure and human vulnerabilities. Traditional defenses frequently isolate technical Cyber Threat Intelligence (CTI) within Security Operations Centers (SOC) while treating employee security awareness as a disconnected compliance obligation. This project presents the **Cybersecurity Awareness & Threat Intelligence Dashboard**, an end-to-end defensive platform that unifies real-time threat intelligence processing with targeted security education. The platform ingests, normalizes, validates, and mathematically scores over 2,300 safe synthetic threat artifacts across RFC-compliant ranges. Featuring 10 interactive visual analytics, a passive indicator enrichment engine, alert fatigue reduction, MITRE ATT&CK mapping, and 15 structured educational modules paired with a 32-question assessment engine, the platform demonstrates how technical telemetry and human awareness operate as complementary defensive tiers.

---

## 2. Introduction
Cyber Threat Intelligence (CTI) involves the systematic collection, evaluation, and analysis of threat data to produce actionable insights for defenders. Simultaneously, human error remains implicated in over 80% of corporate breaches. Bridging technical telemetry and human behavioral training provides defense-in-depth across the entire organizational attack surface.

---

## 3. Problem Statement
Contemporary cybersecurity operations suffer from three acute challenges:
1. **Analyst Alert Fatigue:** High volumes of duplicate or unverified indicators overwhelm SOC queues.
2. **Disconnected Awareness Programs:** Security awareness training is typically static, generic, and unlinked to real-world threats targeting the organization.
3. **Improper Intelligence Interpretation:** Junior analysts frequently conflate indicators of compromise (IOCs) with confirmed breaches, lacking standardized taxonomy to distinguish observations, alerts, threats, and incidents.

---

## 4. Objectives
- Ingest and normalize over 2,000 safe, sanitized threat records adhering to RFC documentation ranges (RFC 5737, RFC 2606).
- Implement an automated multi-format IOC syntax validator (IPv4, IPv6, Domain, URL, MD5, SHA-1, SHA-256, CVE ID).
- Design a mathematical risk scoring engine (0-100) weighting severity, confidence, recency, observation frequency, source reliability, and correlation.
- Build an alert engine with automatic de-duplication to reduce SOC alert fatigue.
- Map threat categories to the MITRE ATT&CK framework using accurate tactic and technique identifiers.
- Develop an educational Awareness Center with 15 modules and an automated 32-question quiz generating personalized learning recommendations.
- Verify platform correctness with an automated 35-scenario test suite achieving 100% test coverage.

---

## 5. Cybersecurity Awareness vs Threat Intelligence
- **Cybersecurity Awareness:** Focuses on human behavioral conditioning, teaching users to recognize social engineering, phishing lures, credential theft, and operational hygiene.
- **Threat Intelligence:** Focuses on evidence-based data regarding adversary capabilities, infrastructure, and tactics to inform technical controls.
- **Unified Synergy:** When technical CTI detects an uptick in phishing or MFA prompt bombing, the Awareness module dynamically prioritizes relevant educational modules, hardening human defenders before compromise occurs.

---

## 6. Threat Intelligence Tiers
1. **Strategic:** Broad trends and business risk for executive leadership.
2. **Tactical:** TTPs and attack mechanics aligned with MITRE ATT&CK for incident responders.
3. **Operational:** Campaign-specific details and adversary infrastructure for threat hunters.
4. **Technical:** Atomic indicators (IPs, hashes, domains) for firewall and EDR blocklists.
*This project focuses primarily on Technical, Tactical, and Awareness-Oriented intelligence.*

---

## 7. IOC and IOA Concepts
- **Indicator of Compromise (IOC):** Forensic artifact indicating past activity (e.g., file hash, IP address). Vulnerable to trivial adversary modification.
- **Indicator of Attack (IOA):** Behavioral pattern demonstrating active adversary intent and technique execution (e.g., process injection, credential dumping).

---

## 8. Threat Intelligence Lifecycle
The platform operationalizes the classic CTI cycle:
1. **Planning & Direction:** Establish collection priorities across 10 threat categories.
2. **Collection:** Ingest synthetic records into local SQLite storage.
3. **Processing & Normalization:** Validate syntactic structure and normalize indicator strings.
4. **Analysis & Enrichment:** Compute multi-factor risk, assess confidence, and correlate clusters.
5. **Dissemination:** Present actionable data through SOC and Executive views.
6. **Feedback:** Triage alerts and update analyst notes.

---

## 9. Proposed System Architecture
The system employs a modular layered architecture:
- **Data Ingestion:** Synthetic feed generation and CSV loading.
- **Engine Layer:** IOC Validator, Enrichment Engine, Risk & Confidence Engine, Correlation Engine, Alert Engine, Attack Mapper.
- **Persistence Layer:** SQLite relational schema with indexing on high-cardinality query fields.
- **API Layer:** Flask REST API with JSON response formatting and XSS sanitization.
- **Frontend Presentation:** Vanilla CSS SOC theme, Chart.js visualizations, and asynchronous DOM manipulation.

---

## 10. Synthetic Dataset Generation
To ensure strict ethical and defensive compliance:
- **IP Addresses:** RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- **Domains:** RFC 2606 / 6761 reserved domains (`example.com`, `example.org`, `*.invalid`).
- **File Hashes:** Cryptographically generated SHA-256 digests explicitly labeled synthetic.
- **Total Records:** 2,301 threat records and 39 curated defensive vulnerability profiles.

---

## 11. Multi-Format IOC Validation Engine
The `validate_indicator()` service evaluates whether an artifact is syntactically valid without checking reputation:
- Evaluates IPv4 octet bounds, IPv6 hexadecimal groups, FQDN label lengths, URL protocols, hexadecimal hash lengths, and standard CVE formatting.
- Explicitly establishes that format validity is independent of malicious intent.

---

## 12. Threat Risk & Confidence Scoring Engine
$$\text{Risk Score} = 0.30(\text{Severity}) + 0.25(\text{Confidence}) + 0.15(\text{Recency}) + 0.10(\text{Frequency}) + 0.10(\text{Source Reliability}) + 0.10(\text{Context})$$
- Scores are classified into five operational tiers: Informational (0-20), Low (21-40), Medium (41-60), High (61-80), and Critical (81-100).
- Source reliability follows Admiralty Code principles (A: Internal SOC, B: Research Report, C: Community, D: Unknown).

---

## 13. Threat Correlation & Clustering
Threat records sharing category attributes, temporal proximity, and co-occurring infrastructure are grouped into **Related Threat Clusters**. An analyst timeline reconstructs the lifecycle milestones from First Seen through Active Monitoring and Case Resolution.

---

## 14. MITRE ATT&CK Alignment
Threat telemetry is mapped to ATT&CK tactics (Initial Access, Execution, Persistence, Impact, etc.) and explicit techniques (e.g., T1566 Phishing, T1486 Data Encrypted for Impact). The dashboard visualizes tactic distributions to highlight adversary behavioral trends.

---

## 15. Vulnerability Prioritization
Demonstrates why CVSS alone fails to determine remediation urgency. The prioritization formula incorporates asset criticality, internet perimeter exposure, and active in-the-wild exploitation evidence to calculate a contextual priority score (0-100).

---

## 16. Alert Management & SOC Fatigue Reduction
When repetitive sightings of the same indicator occur in rapid succession, the alert engine correlates subsequent occurrences into a single existing alert, incrementing the observation count while keeping the analyst queue uncluttered.

---

## 17. Security Awareness Center & Quiz Engine
- **15 Modules:** Comprehensive guides detailing what the threat is, why it matters, critical warning signs, safe defensive practices, and incident guidance.
- **32 Assessment Questions:** Spans 10 security domains.
- **Scoring & Recommendations:** Generates an overall 0-100 awareness score, evaluates category competencies, and generates prioritized remedial learning recommendations.

---

## 18. Testing & Validation Results
An automated test suite comprising 35 unit and integration tests was implemented using `unittest` and `pytest`:
- **Syntax Validation Tests (11 tests):** 100% Passed.
- **Scoring & Reliability Tests (4 tests):** 100% Passed.
- **Enrichment, Alert & Correlation Tests (9 tests):** 100% Passed.
- **Threat Query, Sorting & Database Tests (7 tests):** 100% Passed.
- **Awareness & Quiz Evaluation Tests (4 tests):** 100% Passed.
- **Overall Result:** 35/35 Passed in 0.44 seconds.

---

## 19. Security, Privacy & Ethical Compliance
- Zero automated external network connections are established.
- Input sanitization escapes HTML entities to prevent stored XSS attacks.
- No malware samples, exploit payloads, or active phishing kits are utilized.
- All testing data adheres to international RFC standards for documentation and testing.

---

## 20. Conclusion & Future Scope
The Cybersecurity Awareness & Threat Intelligence Dashboard successfully bridges technical SOC telemetry with human-layer defenses. Future enhancements include live STIX/TAXII feed parsing, SIEM integrations (Splunk/Elastic), CISA Known Exploited Vulnerabilities (KEV) synchronization, and containerized Docker orchestration.

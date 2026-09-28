# System Architecture & Defensive Engineering Principles
**Cybersecurity Awareness & Threat Intelligence Dashboard**

---

## 1. System Architecture Overview

The platform bridges **Technical Threat Intelligence** and **Human-Layer Cybersecurity Awareness**, ensuring defensive telemetry informs security education while human risk signals inform technical monitoring.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   DEFENSIVE INGESTION LAYER                            │
│  • Synthetic Threat Feed (RFC 5737 IPs, RFC 2606 Domains, Safe Hashes) │
│  • Curated Vulnerability Disclosures (CVEs, CVSS 3.1)                  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   NORMALIZATION & VALIDATION LAYER                     │
│  • Syntax Validation Engine (IPv4, IPv6, Domain, URL, MD5, SHA, CVE)   │
│  • Indicator Normalization (Lowercase, Stripping, Typo-Squat Checking) │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   ENRICHMENT & SCORING PIPELINE                        │
│  • Local Passive Enrichment (Zero Outbound Connections)                │
│  • Multi-Factor Risk Engine (Severity 30%, Conf 25%, Recency 15%...)   │
│  • Source Reliability Evaluation (Admiralty System Tiers A-D)          │
│  • MITRE ATT&CK Behavioral Mapping (Tactics & Techniques)              │
└───────────────────┬───────────────────────────────┬────────────────────┘
                    │                               │
                    ▼                               ▼
┌──────────────────────────────────┐ ┌──────────────────────────────────┐
│       CORRELATION ENGINE         │ │       ALERT ENGINE               │
│ • Threat Clustering (Category/Time)│ │ • Risk Threshold Triggering    │
│ • Investigation Milestones       │ │ • Alert De-duplication           │
│ • Timeline Generation            │ │ • SOC Alert Fatigue Reduction    │
└───────────────────┬──────────────┘ └──────────────┬───────────────────┘
                    │                               │
                    └───────────────┬───────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      PERSISTENCE & STORAGE (SQLite)                    │
│  • threats, indicators, attack_mappings, sources, alerts               │
│  • vulnerabilities, analyst_notes, awareness_modules, quiz_results     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 REST API & ORCHESTRATION LAYER (Flask)                 │
│  • Threat Query & Filter APIs    • Passive IOC Search & Enrich         │
│  • Dashboard Stats & Trends      • Case Notes & Alert Triage           │
│  • Awareness Modules Service     • Interactive Quiz Evaluation Engine  │
└───────────────────┬───────────────────────────────┬────────────────────┘
                    │                               │
                    ▼                               ▼
┌──────────────────────────────────┐ ┌──────────────────────────────────┐
│     SOC DASHBOARD & ANALYTICS    │ │   CYBERSECURITY AWARENESS CENTER │
│ • 10 Chart.js Visualizations     │ │ • 15 Interactive Defense Modules │
│ • Live Indicator Search Modal    │ │ • 32-Question Multi-Domain Quiz  │
│ • SOC Investigation Case View    │ │ • Personalized Learning Paths    │
│ • Executive Posture Summary      │ │ • Educational Awareness Score    │
└──────────────────────────────────┘ └──────────────────────────────────┘
```

---

## 2. Core Defensive Cybersecurity Concepts

### A. Cybersecurity Awareness
- **Simple Explanation:** Helping people recognize everyday digital traps—like fake emails or rogue links—so they don't accidentally let criminals into the system.
- **Technical Explanation:** The systematic conditioning and educational measurement of the human security perimeter to mitigate social engineering, credential harvesting, and policy violations.

### B. Cyber Threat Intelligence (CTI)
- **Simple Explanation:** Gathering information about what hackers are doing so our digital guards know what to look out for.
- **Technical Explanation:** Evidence-based knowledge (including context, mechanisms, indicators, implications, and actionable advice) about existing or emerging hazards to assets that can be used to inform decisions.

### C. Indicator of Compromise (IOC)
- **Simple Explanation:** Digital fingerprints or clues left behind by an attacker, such as a known bad IP address or file name.
- **Technical Explanation:** Forensic artifacts identified on a network or operating system that indicate, with high likelihood, an unauthorized intrusion or malicious payload presence.

### D. Indicator of Attack (IOA)
- **Simple Explanation:** Clues showing what an attacker is trying to do right now, rather than what files they used in the past.
- **Technical Explanation:** Proactive behavioral patterns focusing on adversary intent, technique execution (e.g., persistence establishment, credential dumping), and ongoing attack activity regardless of file hash variation.

### E. Vulnerability
- **Simple Explanation:** A flaw, bug, or weak spot in computer code that allows unauthorized actions.
- **Technical Explanation:** A weakness in computational logic or design found in software/hardware components that can be exploited by a threat actor to gain unauthorized access or cause disruption.

### F. Common Vulnerabilities and Exposures (CVE)
- **Simple Explanation:** A standardized reference dictionary giving every known software flaw a unique serial number (like CVE-2024-3400).
- **Technical Explanation:** A system of unique identifiers cataloged by MITRE and CVE Numbering Authorities (CNAs) to facilitate cross-system tracking and vulnerability management.

### G. Common Vulnerability Scoring System (CVSS)
- **Simple Explanation:** A standardized 0 to 10 severity grade indicating how dangerous a software flaw is.
- **Technical Explanation:** An open industry standard (CVSS v3.1 / v4.0) that measures vulnerability severity across base metrics (attack vector, complexity, privileges required, user interaction, impact to confidentiality/integrity/availability).

### H. Threat Feed
- **Simple Explanation:** An ongoing stream of security intelligence data continuously sent to defensive firewalls and monitoring tools.
- **Technical Explanation:** Real-time or batch dissemination of machine-readable threat data (STIX/TAXII, CSV, JSON) containing atomic indicators and associated contextual attribution.

### I. Threat Actor Concept
- **Simple Explanation:** An individual or group responsible for planning and carrying out malicious cyber operations.
- **Technical Explanation:** An entity possessing capability, intent, and opportunity to target computing assets (e.g., nation-state APTs, cybercrime syndicates, hacktivists, insider threats).

### J. Tactics, Techniques, and Procedures (TTP)
- **Simple Explanation:** The patterns, habits, and methods hackers use to conduct their operations.
- **Technical Explanation:** The operational behavior of adversaries. Tactics describe intermediate goals (*why*); Techniques describe methods (*how*); Procedures describe specific implementations.

### K. MITRE ATT&CK
- **Simple Explanation:** A periodic table of hacker tricks categorizing adversary behaviors across every stage of an attack.
- **Technical Explanation:** A globally accessible knowledge base of adversary tactics and techniques based on real-world observations, used to model threat behavior and measure defensive posture.

### L. Threat Enrichment
- **Simple Explanation:** Taking a single clue (like an IP address) and researching who owns it, what it is linked to, and how dangerous it is.
- **Technical Explanation:** Augmenting raw telemetry with external or localized contextual metadata (domain registration, passive DNS, threat category, risk scoring, geolocation) to enable rapid analyst decision-making.

### M. Threat Correlation
- **Simple Explanation:** Connecting the dots between separate clues to realize they are all part of the same crime scene.
- **Technical Explanation:** Aggregating disparate network and host artifacts across time and infrastructure to identify common campaign clusters or shared infrastructure.

### N. Threat Hunting
- **Simple Explanation:** Proactively searching through network logs to find sneaky intruders that slipped past automated alarms.
- **Technical Explanation:** A proactive, hypothesis-driven analytical process that interrogates network telemetry and endpoint activity to detect adversaries evading signature-based defenses.

### O. Security Operations Center (SOC)
- **Simple Explanation:** The digital control room where security analysts monitor computer screens 24/7 to defend against hackers.
- **Technical Explanation:** A centralized organizational unit employing people, processes, and technology (SIEM, SOAR, EDR) to continuously monitor, detect, analyze, and respond to cybersecurity events.

---

## 3. Four Types of Threat Intelligence

| Intelligence Tier | Target Audience | Primary Focus | Practical Example |
| :--- | :--- | :--- | :--- |
| **Strategic** | Board of Directors, CISO, CIO | High-level risk trends, geopolitical developments, financial impacts | Executive briefing on ransomware trends targeting healthcare systems. |
| **Tactical** | SOC Leads, Incident Handlers | Adversary tactics, techniques, and procedures (TTPs) | MITRE ATT&CK mapping of phishing and token theft mechanisms. |
| **Operational** | Threat Hunters, Intelligence Analysts | Specific adversary campaigns, timing, targeting intent | Active monitoring of a credential harvesting infrastructure campaign. |
| **Technical** | SOC Tier 1/2, Firewall Admins | Immediate atomic indicators (IPs, hashes, domains, CVEs) | Blocking synthetic domain `login-check.invalid` at DNS sinkholes. |

*This course project focuses on Technical + Tactical + Awareness-Oriented Intelligence.*

---

## 4. IOC Lifecycle Management

```
Observed ──► Validated ──► Enriched ──► Scored ──► Investigated ──► Monitored ──► Expired/Closed
   ▲                                                                                     │
   └─────────────────────────── Re-Sighting Loop ────────────────────────────────────────┘
```

1. **Observed:** Artifact ingested from synthetic feed or internal log sensor.
2. **Validated:** Format validated syntactically (format verification != malicious confirmation).
3. **Enriched:** Contextual lookups performed passively against internal database.
4. **Scored:** Mathematical risk (0-100) and confidence (0-100) calculated.
5. **Investigated:** SOC analyst triages the item, reviews ATT&CK alignment, and records notes.
6. **Monitored:** Boundary sensors monitor for sightings over a 30-day window.
7. **Expired/Closed:** Threat mitigated or marked false positive after verified remediation.

# SOC Analyst Triage Playbook & Investigation Guide
**Tier-1 & Tier-2 SOC Procedures**

---

## 1. The Critical SOC Taxonomy Distinction

Do **NOT** label every suspicious indicator as a confirmed attack!

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

---

## 2. Tier-1 SOC Investigation Workflow

```
Threat Feed Ingestion
       ↓
IOC Detected
       ↓
Syntactic Validation (validate_indicator)
       ↓
Local Passive Enrichment (enrich_indicator)
       ↓
Risk & Confidence Scoring (calculate_threat_risk)
       ↓
Alert Generation & De-duplication (prevent alert fatigue)
       ↓
SOC Queue Triage
       ↓
Cluster Correlation (correlate_threats)
       ↓
Investigative Decision:
┌──────┴───────────────┬─────────────────┬────────────────────┐
↓                      ↓                 ↓                    ↓
Escalate (Tier-2)      Active Monitoring  Resolve (Benign)     Mark False Positive
       ↓
Incident Documentation (Analyst Notes)
```

---

## 3. Safe Demonstration Scenario: Case Study `THR-2026-001`

### Case Overview
- **Threat ID:** `THR-2026-001`
- **Threat Name:** Synthetic Credential Phishing Campaign
- **Category:** `PHISHING`
- **Indicator Type:** `DOMAIN`
- **Indicator Value:** `login-check.invalid` *(RFC 2606 safe reserved domain)*
- **Severity:** `HIGH`
- **Risk Score:** `78/100`
- **Confidence Score:** `85/100`
- **Status:** `MONITORING`
- **Correlated Ingress IP:** `198.51.100.25` *(RFC 5737 TEST-NET-2)*
- **Correlated Hash:** `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- **ATT&CK Alignment:**
  - Tactic: `Initial Access` (TA0001)
  - Technique: `Phishing (T1566)` / `Spearphishing Link (T1566.002)`

### Analyst Step-by-Step Triage
1. **Passive Lookup:** Search `login-check.invalid` in the dashboard search bar. Observe that risk score is 78 and confidence is 85%.
2. **Review Correlated Cluster:** Open the SOC investigation view. Review correlated IP `198.51.100.25` and hash artifacts.
3. **DO NOT VISIT OR PROBE:** Confirm strictly passive analysis. Never paste the domain into an unisolated browser or initiate automated ping/curl requests.
4. **Historical Log Check:** Query proxy and DNS query logs for historical sightings of `login-check.invalid`.
5. **Containment Recommendation:**
   - Place `login-check.invalid` on the perimeter DNS sinkhole blocklist.
   - Enforce mail filter blocks on messages referencing `login-check.invalid`.
   - Issue awareness advisory regarding fake single sign-on credential prompts.
6. **Case Documentation:** Append note in the SOC Case Notes:
   `"Verified multi-observation cluster. Correlated with staging IP 198.51.100.25. Added to monitoring queue."`

---

## 4. Incident Response Lifecycle Checklist

| Phase | Operational Focus | Action Items |
| :--- | :--- | :--- |
| **1. Preparation** | Tools, policies, training | Maintain offline backups, run awareness quizzes, ensure logging telemetry is active. |
| **2. Detection & Identification** | Spotting anomalies | Detect alert in SOC queue, validate syntax, correlate indicators, assess blast radius. |
| **3. Containment** | Stopping propagation | Isolate affected host from network (disable Wi-Fi / disconnect ethernet), block C2 IP on firewall, revoke active session tokens. |
| **4. Eradication** | Removing attacker presence | Clean infected binaries, patch exploited vulnerabilities (CVEs), re-image compromised machines. |
| **5. Recovery** | Returning to service safely | Restore systems from known clean offline backups, verify integrity, monitor for re-infection for 30 days. |
| **6. Lessons Learned** | Improving defense | Conduct post-incident debrief, update detection rules, reinforce employee training in weak categories. |

---

## 5. False Positives & Intelligence Limitations

- **Shared Cloud IPs:** An IP on AWS, Azure, or Cloudflare may host both benign services and malicious actors.
- **Dynamic Infrastructure:** Domains expire, change ownership, or use domain parking.
- **Stale Indicators:** A threat indicator observed 6 months ago may no longer be active today.
- **Conclusion:** Threat intelligence is decision support, not absolute ground truth. Analysts must verify contextual evidence before destructive action.

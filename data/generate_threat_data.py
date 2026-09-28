#!/usr/bin/env python3
"""
Synthetic Threat Intelligence Dataset Generator
Author: Defensive Cybersecurity Engineering Team
Purpose: Generates safe, sanitized, defensive threat intelligence datasets
         strictly utilizing RFC documentation IP ranges, reserved domains,
         and synthetic file hashes for education and SOC training.
"""

import os
import csv
import random
import hashlib
from datetime import datetime, timedelta

# Ensure reproducibility
random.seed(42)

# Directory setup
DATA_DIR = os.path.dirname(os.path.abspath(__file__))
THREAT_DATASET_PATH = os.path.join(DATA_DIR, "threat_intelligence_dataset.csv")
VULN_DATASET_PATH = os.path.join(DATA_DIR, "vulnerabilities.csv")

# Safe Reserved Indicators (RFC 5737 & RFC 2606 / 6761)
SAFE_IPV4_PREFIXES = ["192.0.2.", "198.51.100.", "203.0.113."]
SAFE_DOMAINS = [
    "example.com", "example.org", "example.net",
    "auth-portal.invalid", "update-service.invalid", "cloud-storage.invalid",
    "secure-verify.invalid", "mail-gateway.invalid", "telemetry-sync.invalid",
    "internal-api.invalid", "cdn-assets.invalid", "payment-notice.invalid",
    "login-check.invalid", "doc-share.invalid", "identity-sso.invalid"
]

SAFE_URL_PATHS = [
    "/login/session-verify",
    "/auth/checkpoint",
    "/downloads/critical_update.bin",
    "/invoices/Q3_invoice_document.pdf",
    "/account/security-challenge",
    "/telemetry/beacon",
    "/api/v1/heartbeat",
    "/sync/payload_loader.txt"
]

THREAT_CATEGORIES = [
    "PHISHING",
    "MALWARE",
    "RANSOMWARE",
    "CREDENTIAL THREATS",
    "WEB THREATS",
    "NETWORK THREATS",
    "VULNERABILITY EXPOSURE",
    "SOCIAL ENGINEERING",
    "DATA EXPOSURE",
    "ACCOUNT SECURITY"
]

INDICATOR_TYPES = [
    "IP ADDRESS",
    "DOMAIN",
    "URL",
    "FILE HASH",
    "EMAIL/SENDER DOMAIN",
    "CVE ID"
]

SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]

SOURCE_NAMES = [
    "Internal SOC",
    "Security Vendor",
    "Public Threat Feed",
    "Research Report",
    "Community Submission",
    "Unknown Source"
]

REGIONS = ["North America", "Europe", "Asia-Pacific", "Latin America", "Middle East", "Global / Multi-region"]

MITRE_TACTICS_AND_TECHNIQUES = {
    "PHISHING": [
        ("Initial Access", "Phishing (T1566)"),
        ("Initial Access", "Spearphishing Link (T1566.002)"),
        ("Initial Access", "Spearphishing Attachment (T1566.001)")
    ],
    "MALWARE": [
        ("Execution", "User Execution (T1204)"),
        ("Defense Evasion", "Obfuscated Files or Information (T1027)"),
        ("Command and Control", "Application Layer Protocol (T1071)")
    ],
    "RANSOMWARE": [
        ("Impact", "Data Encrypted for Impact (T1486)"),
        ("Impact", "Inhibit System Recovery (T1490)"),
        ("Exfiltration", "Exfiltration Over C2 Channel (T1041)")
    ],
    "CREDENTIAL THREATS": [
        ("Credential Access", "Brute Force (T1110)"),
        ("Credential Access", "OS Credential Dumping (T1003)"),
        ("Credential Access", "Credentials in Files (T1552)")
    ],
    "WEB THREATS": [
        ("Initial Access", "Exploit Public-Facing Application (T1190)"),
        ("Defense Evasion", "Web Service (T1102)"),
        ("Command and Control", "Web Protocols (T1071.001)")
    ],
    "NETWORK THREATS": [
        ("Discovery", "Network Service Scanning (T1046)"),
        ("Discovery", "Network Sniffing (T1040)"),
        ("Command and Control", "Non-Standard Port (T1571)")
    ],
    "VULNERABILITY EXPOSURE": [
        ("Initial Access", "Exploit Public-Facing Application (T1190)"),
        ("Privilege Escalation", "Exploitation for Privilege Escalation (T1068)")
    ],
    "SOCIAL ENGINEERING": [
        ("Initial Access", "Phishing (T1566)"),
        ("Defense Evasion", "Impersonation (T1656)")
    ],
    "DATA EXPOSURE": [
        ("Exfiltration", "Exfiltration Over Web Service (T1567)"),
        ("Collection", "Data from Information Repositories (T1213)")
    ],
    "ACCOUNT SECURITY": [
        ("Persistence", "Valid Accounts (T1078)"),
        ("Persistence", "Account Manipulation (T1098)")
    ]
}

SAMPLE_CVES = [
    "CVE-2024-21413", "CVE-2024-38063", "CVE-2023-44487", "CVE-2023-38606",
    "CVE-2023-34362", "CVE-2024-21762", "CVE-2024-3400", "CVE-2024-4577",
    "CVE-2023-22518", "CVE-2024-23897", "CVE-2023-46805", "CVE-2024-27198",
    "CVE-2024-20353", "CVE-2023-4966", "CVE-2024-1709", "CVE-2024-6387"
]

def generate_safe_indicator(ind_type):
    """Generate safe, non-operational indicator values strictly for defensive analysis."""
    if ind_type == "IP ADDRESS":
        prefix = random.choice(SAFE_IPV4_PREFIXES)
        suffix = random.randint(1, 254)
        return f"{prefix}{suffix}"
    elif ind_type == "DOMAIN":
        domain = random.choice(SAFE_DOMAINS)
        sub = random.choice(["portal", "cdn", "gateway", "sync", "mail", "api", "auth", "static"])
        return f"{sub}.{domain}"
    elif ind_type == "URL":
        domain = random.choice(SAFE_DOMAINS)
        path = random.choice(SAFE_URL_PATHS)
        protocol = "https" if random.random() > 0.3 else "http"
        return f"{protocol}://{domain}{path}"
    elif ind_type == "FILE HASH":
        seed = f"synthetic-file-{random.random()}-{datetime.now().isoformat()}"
        return hashlib.sha256(seed.encode()).hexdigest()
    elif ind_type == "EMAIL/SENDER DOMAIN":
        user = random.choice(["service-notice", "billing-alert", "security-desk", "admin-verify", "hr-update"])
        domain = random.choice(SAFE_DOMAINS)
        return f"{user}@{domain}"
    elif ind_type == "CVE ID":
        return random.choice(SAMPLE_CVES)
    return "203.0.113.10"

def generate_synthetic_threat_dataset(record_count=2300):
    """Generate 2,000+ safe synthetic threat records adhering to schema."""
    records = []
    base_time = datetime(2026, 9, 28, 12, 0, 0)

    # 1. First record: Required Safe Demonstration Scenario (THR-2026-001)
    scenario_1 = {
        "threat_id": "THR-2026-001",
        "timestamp": (base_time - timedelta(days=27)).isoformat() + "Z",
        "threat_name": "Synthetic Credential Phishing Campaign",
        "threat_category": "PHISHING",
        "indicator_type": "DOMAIN",
        "indicator_value": "login-check.invalid",
        "source_name": "Internal SOC",
        "confidence_score": 85,
        "severity": "HIGH",
        "risk_score": 78,
        "status": "MONITORING",
        "first_seen": (base_time - timedelta(days=27, hours=4)).isoformat() + "Z",
        "last_seen": (base_time - timedelta(hours=2)).isoformat() + "Z",
        "country_or_region_optional": "North America",
        "description": "Synthetic credential harvest portal mimicking single sign-on authentication prompt. Related to staging infrastructure 198.51.100.25.",
        "mitre_tactic_optional": "Initial Access",
        "mitre_technique_optional": "Phishing (T1566)",
        "cve_id_optional": ""
    }
    records.append(scenario_1)

    # 2. Second record: Correlated staging IP for scenario 1
    scenario_2 = {
        "threat_id": "THR-2026-002",
        "timestamp": (base_time - timedelta(days=26)).isoformat() + "Z",
        "threat_name": "Synthetic Phishing Ingress Infrastructure",
        "threat_category": "PHISHING",
        "indicator_type": "IP ADDRESS",
        "indicator_value": "198.51.100.25",
        "source_name": "Security Vendor",
        "confidence_score": 88,
        "severity": "HIGH",
        "risk_score": 76,
        "status": "MONITORING",
        "first_seen": (base_time - timedelta(days=26, hours=2)).isoformat() + "Z",
        "last_seen": (base_time - timedelta(hours=5)).isoformat() + "Z",
        "country_or_region_optional": "North America",
        "description": "Synthetic hosting IP resolving login-check.invalid host. Multiple telemetry sightings.",
        "mitre_tactic_optional": "Command and Control",
        "mitre_technique_optional": "Application Layer Protocol (T1071)",
        "cve_id_optional": ""
    }
    records.append(scenario_2)

    # 3. Third record: Correlated synthetic hash
    scenario_3 = {
        "threat_id": "THR-2026-003",
        "timestamp": (base_time - timedelta(days=25)).isoformat() + "Z",
        "threat_name": "Synthetic Phishing Form Payload Loader",
        "threat_category": "PHISHING",
        "indicator_type": "FILE HASH",
        "indicator_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "source_name": "Research Report",
        "confidence_score": 90,
        "severity": "HIGH",
        "risk_score": 80,
        "status": "MONITORING",
        "first_seen": (base_time - timedelta(days=25)).isoformat() + "Z",
        "last_seen": (base_time - timedelta(days=1)).isoformat() + "Z",
        "country_or_region_optional": "North America",
        "description": "Synthetic SHA-256 hash representing dummy HTML login scraper attachment.",
        "mitre_tactic_optional": "Initial Access",
        "mitre_technique_optional": "Spearphishing Attachment (T1566.001)",
        "cve_id_optional": ""
    }
    records.append(scenario_3)

    # 4. Generate remaining records up to record_count
    for i in range(4, record_count + 1):
        threat_id = f"THR-2026-{i:04d}"
        category = random.choice(THREAT_CATEGORIES)
        ind_type = random.choice(INDICATOR_TYPES)
        ind_value = generate_safe_indicator(ind_type)
        source = random.choice(SOURCE_NAMES)
        severity = random.choices(
            SEVERITIES,
            weights=[15, 25, 30, 20, 10],
            k=1
        )[0]

        # Calculate realistic synthetic risk & confidence
        if severity == "CRITICAL":
            risk = random.randint(81, 98)
            conf = random.randint(60, 95)
        elif severity == "HIGH":
            risk = random.randint(61, 80)
            conf = random.randint(50, 92)
        elif severity == "MEDIUM":
            risk = random.randint(41, 60)
            conf = random.randint(40, 85)
        elif severity == "LOW":
            risk = random.randint(21, 40)
            conf = random.randint(30, 80)
        else:
            risk = random.randint(5, 20)
            conf = random.randint(25, 75)

        status = random.choices(
            STATUSES,
            weights=[35, 20, 25, 15, 5],
            k=1
        )[0]

        days_ago = random.randint(0, 90)
        hours_ago = random.randint(0, 23)
        seen_base = base_time - timedelta(days=days_ago, hours=hours_ago)
        first_seen = (seen_base - timedelta(days=random.randint(1, 15), hours=random.randint(1, 12))).isoformat() + "Z"
        last_seen = seen_base.isoformat() + "Z"

        region = random.choice(REGIONS)

        # MITRE Mapping when justified
        tactic, technique = "", ""
        if category in MITRE_TACTICS_AND_TECHNIQUES and random.random() > 0.2:
            t_choice = random.choice(MITRE_TACTICS_AND_TECHNIQUES[category])
            tactic = t_choice[0]
            technique = t_choice[1]

        # CVE if vulnerability exposure or web threat
        cve = ""
        if category in ["VULNERABILITY EXPOSURE", "WEB THREATS"] or ind_type == "CVE ID":
            cve = random.choice(SAMPLE_CVES)
            if ind_type == "CVE ID":
                ind_value = cve

        # Defensive threat name generator
        name_templates = {
            "PHISHING": [
                f"Synthetic {ind_type.title()} Phishing Probe",
                f"Deceptive Brand Spoof Infrastructure ({ind_value[:18]})",
                f"Suspicious Credential Redirection Activity"
            ],
            "MALWARE": [
                f"Synthetic Ransom Loader Ingress Artifact",
                f"Simulated Endpoint Dropper Telemetry",
                f"Defensive Malware Test Signature ({ind_type.title()})"
            ],
            "RANSOMWARE": [
                f"Simulated DarkLocker Staging Beacon",
                f"Synthetic Extortion Ingress Vector",
                f"Defensive ShadowCopy Tamper Probe"
            ],
            "CREDENTIAL THREATS": [
                f"Synthetic Credential Spray Source ({ind_value[:15]})",
                f"Simulated Kerberoast Telemetry Marker",
                f"Defensive Brute-Force Testing Node"
            ],
            "WEB THREATS": [
                f"Public Application Probe Observation",
                f"Simulated SQLi/XSS Test Pattern",
                f"API Endpoint Scanner Indicator"
            ],
            "NETWORK THREATS": [
                f"Unusual Inbound Port Sweep Observation",
                f"Defensive Lateral Movement Sensor Flag",
                f"Simulated DNS Tunneling Query Indicator"
            ],
            "VULNERABILITY EXPOSURE": [
                f"Targeted Exposure Indicator for {cve or 'CVE-2024-3400'}",
                f"Unpatched Perimeter Appliance Beacon",
                f"Known Flaw Exposure Telemetry"
            ],
            "SOCIAL ENGINEERING": [
                f"Executive Impersonation Telemetry",
                f"Simulated Pretexting Contact Point",
                f"Unsolicited Gift Card Lure Activity"
            ],
            "DATA EXPOSURE": [
                f"Public Cloud Bucket Misconfiguration Flag",
                f"Simulated Token Exposure Observation",
                f"Data Leakage Canary Trigger"
            ],
            "ACCOUNT SECURITY": [
                f"Impossible Travel Telemetry Anomaly",
                f"Suspicious MFA Prompt Bombing Sequence",
                f"Dormant Account Awakening Flag"
            ]
        }
        threat_name = random.choice(name_templates[category])
        description = (
            f"Defensive observation: Synthetic {ind_type} artifact observed in connection with {category.lower()} "
            f"telemetry. Source classified as {source}. Safe sanitized indicator for SOC triage and awareness training."
        )

        record = {
            "threat_id": threat_id,
            "timestamp": last_seen,
            "threat_name": threat_name,
            "threat_category": category,
            "indicator_type": ind_type,
            "indicator_value": ind_value,
            "source_name": source,
            "confidence_score": conf,
            "severity": severity,
            "risk_score": risk,
            "status": status,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "country_or_region_optional": region,
            "description": description,
            "mitre_tactic_optional": tactic,
            "mitre_technique_optional": technique,
            "cve_id_optional": cve
        }
        records.append(record)

    # Write out to CSV
    fields = [
        "threat_id", "timestamp", "threat_name", "threat_category",
        "indicator_type", "indicator_value", "source_name", "confidence_score",
        "severity", "risk_score", "status", "first_seen", "last_seen",
        "country_or_region_optional", "description", "mitre_tactic_optional",
        "mitre_technique_optional", "cve_id_optional"
    ]

    with open(THREAT_DATASET_PATH, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)

    print(f"[+] Successfully generated {len(records)} safe synthetic threat records in {THREAT_DATASET_PATH}")
    return len(records)

def generate_vulnerability_dataset():
    """Generate safe defensive vulnerability records for CVE & Vulnerability Awareness."""
    vuln_data = [
        {
            "cve_id": "CVE-2024-3400",
            "product_category": "VPN Gateway / Firewall",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "published_date": "2024-04-12",
            "patch_available": "YES",
            "exploitation_status_demo": "Active In-The-Wild Exploitation Known",
            "description": "Command injection vulnerability in PAN-OS GlobalProtect feature enabling unauthenticated remote code execution with root privileges.",
            "priority_score": 98
        },
        {
            "cve_id": "CVE-2024-21413",
            "product_category": "Email Client / Productivity",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "published_date": "2024-02-13",
            "patch_available": "YES",
            "exploitation_status_demo": "Public PoC Available / Actively Monitored",
            "description": "Microsoft Outlook Remote Code Execution Vulnerability (MonikerLink bug) allowing NTLM credential leaking and code execution via crafted hyperlinks.",
            "priority_score": 95
        },
        {
            "cve_id": "CVE-2024-38063",
            "product_category": "Operating System / Network Stack",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "published_date": "2024-08-13",
            "patch_available": "YES",
            "exploitation_status_demo": "Proof-of-Concept Disclosed",
            "description": "Windows TCP/IP Remote Code Execution Vulnerability triggered by sending crafted IPv6 packets to an affected system.",
            "priority_score": 94
        },
        {
            "cve_id": "CVE-2023-44487",
            "product_category": "Web Server / HTTP Protocol",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "published_date": "2023-10-10",
            "patch_available": "YES",
            "exploitation_status_demo": "High-Volume DDoS Campaigns Documented",
            "description": "HTTP/2 Rapid Reset protocol flaw allowing coordinated stream cancellations resulting in massive Denial of Service against web infrastructure.",
            "priority_score": 85
        },
        {
            "cve_id": "CVE-2024-4577",
            "product_category": "Web Server Runtime / CGI",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "published_date": "2024-06-06",
            "patch_available": "YES",
            "exploitation_status_demo": "Automated Ransomware Ingress Scanning",
            "description": "PHP CGI Argument Injection vulnerability on Windows allowing remote code execution via best-fit character encoding bypass.",
            "priority_score": 96
        },
        {
            "cve_id": "CVE-2024-6387",
            "product_category": "Remote Access / SSH",
            "severity": "HIGH",
            "cvss_score": 8.1,
            "published_date": "2024-07-01",
            "patch_available": "YES",
            "exploitation_status_demo": "RegreSSHion Race Condition Demonstrated",
            "description": "OpenSSH signal handler race condition in sshd on glibc-based Linux systems allowing potential unauthenticated root execution.",
            "priority_score": 82
        },
        {
            "cve_id": "CVE-2023-34362",
            "product_category": "Managed File Transfer (MFT)",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "published_date": "2023-06-02",
            "patch_available": "YES",
            "exploitation_status_demo": "Mass Data Extortion Campaigns Known",
            "description": "MOVEit Transfer SQL injection flaw allowing unauthenticated attackers to obtain unauthorized database access and execute arbitrary payloads.",
            "priority_score": 99
        },
        {
            "cve_id": "CVE-2024-21762",
            "product_category": "SSL VPN Gateway",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "published_date": "2024-02-09",
            "patch_available": "YES",
            "exploitation_status_demo": "Targeted Perimeter Intrusions",
            "description": "FortiOS out-of-bounds write vulnerability in SSL VPN web portal permitting unauthenticated remote execution via crafted HTTP requests.",
            "priority_score": 97
        },
        {
            "cve_id": "CVE-2024-23897",
            "product_category": "CI/CD & DevOps Automation",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "published_date": "2024-01-24",
            "patch_available": "YES",
            "exploitation_status_demo": "Public Exploit Available",
            "description": "Jenkins CLI arbitrary file read vulnerability via args4j parser feature enabling remote attackers to read server files and forge session tokens.",
            "priority_score": 90
        },
        {
            "cve_id": "CVE-2024-1709",
            "product_category": "Remote Desktop Management",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "published_date": "2024-02-21",
            "patch_available": "YES",
            "exploitation_status_demo": "Widespread Automated Exploitation",
            "description": "ConnectWise ScreenConnect authentication bypass via path traversal permitting attackers to create unauthorized administrative accounts.",
            "priority_score": 100
        },
        {
            "cve_id": "CVE-2023-4966",
            "product_category": "Application Delivery Controller",
            "severity": "CRITICAL",
            "cvss_score": 9.4,
            "published_date": "2023-10-10",
            "patch_available": "YES",
            "exploitation_status_demo": "Citrix Bleed Session Token Hijacking",
            "description": "Citrix ADC / Gateway buffer overflow vulnerability allowing sensitive memory leakage and unauthenticated session token hijacking.",
            "priority_score": 93
        },
        {
            "cve_id": "CVE-2024-27198",
            "product_category": "CI/CD Build Server",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "published_date": "2024-03-04",
            "patch_available": "YES",
            "exploitation_status_demo": "Ransomware Ingress Documented",
            "description": "JetBrains TeamCity authentication bypass allowing remote administrative takeovers through alternative path manipulation in web interface.",
            "priority_score": 92
        }
    ]

    # Add synthetic defensive baseline vulnerabilities
    product_types = ["Web Framework", "Database Server", "Container Engine", "Identity Provider", "API Gateway", "DNS Resolver"]
    for i in range(13, 40):
        cve_id = f"CVE-2026-{1000 + i}"
        prod = random.choice(product_types)
        cvss = round(random.uniform(4.0, 9.5), 1)
        sev = "CRITICAL" if cvss >= 9.0 else ("HIGH" if cvss >= 7.0 else ("MEDIUM" if cvss >= 4.0 else "LOW"))
        patch = "YES" if random.random() > 0.15 else "WORKAROUND ONLY"
        exploited = "Simulated / Synthetic Defense Scenario" if random.random() > 0.4 else "Theoretical / Research Only"
        priority = int(cvss * 8 + (15 if patch == "YES" else 5))
        if priority > 100:
            priority = 99

        vuln_data.append({
            "cve_id": cve_id,
            "product_category": prod,
            "severity": sev,
            "cvss_score": cvss,
            "published_date": f"2026-0{random.randint(1, 9)}-{random.randint(10, 28)}",
            "patch_available": patch,
            "exploitation_status_demo": exploited,
            "description": f"Defensive vulnerability model: Synthetic {sev.lower()} exposure affecting enterprise {prod.lower()} infrastructure. Documented for prioritization practice.",
            "priority_score": priority
        })

    fields = ["cve_id", "product_category", "severity", "cvss_score", "published_date", "patch_available", "exploitation_status_demo", "description", "priority_score"]
    with open(VULN_DATASET_PATH, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(vuln_data)

    print(f"[+] Successfully generated {len(vuln_data)} defensive vulnerability records in {VULN_DATASET_PATH}")
    return len(vuln_data)

if __name__ == "__main__":
    generate_synthetic_threat_dataset(2300)
    generate_vulnerability_dataset()

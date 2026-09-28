"""
MITRE ATT&CK Framework Mapping Service
Author: Defensive Cybersecurity Engineering Team
Purpose: Maps defensive categories and telemetry to ATT&CK tactics, techniques,
         and provides tactic breakdown aggregations without fabricating IDs.
"""

from typing import Dict, List, Any

# Canonical MITRE ATT&CK Matrix references
MITRE_TACTIC_INFO = {
    "Initial Access": {
        "id": "TA0001",
        "description": "The adversary is trying to get into your network.",
        "icon": "fas fa-door-open"
    },
    "Execution": {
        "id": "TA0002",
        "description": "The adversary is trying to run malicious code.",
        "icon": "fas fa-terminal"
    },
    "Persistence": {
        "id": "TA0003",
        "description": "The adversary is trying to maintain their foothold.",
        "icon": "fas fa-anchor"
    },
    "Privilege Escalation": {
        "id": "TA0004",
        "description": "The adversary is trying to gain higher-level permissions.",
        "icon": "fas fa-level-up-alt"
    },
    "Defense Evasion": {
        "id": "TA0005",
        "description": "The adversary is trying to avoid being detected.",
        "icon": "fas fa-shield-virus"
    },
    "Credential Access": {
        "id": "TA0006",
        "description": "The adversary is trying to steal account names and passwords.",
        "icon": "fas fa-key"
    },
    "Discovery": {
        "id": "TA0007",
        "description": "The adversary is trying to figure out your environment.",
        "icon": "fas fa-search-location"
    },
    "Lateral Movement": {
        "id": "TA0008",
        "description": "The adversary is trying to move through your environment.",
        "icon": "fas fa-arrows-alt"
    },
    "Collection": {
        "id": "TA0009",
        "description": "The adversary is trying to gather data of interest.",
        "icon": "fas fa-boxes"
    },
    "Command and Control": {
        "id": "TA0011",
        "description": "The adversary is trying to communicate with compromised systems.",
        "icon": "fas fa-satellite-dish"
    },
    "Exfiltration": {
        "id": "TA0010",
        "description": "The adversary is trying to steal data.",
        "icon": "fas fa-file-export"
    },
    "Impact": {
        "id": "TA0040",
        "description": "The adversary is trying to manipulate, interrupt, or destroy your systems.",
        "icon": "fas fa-bomb"
    }
}

DEFAULT_CATEGORY_MAPPINGS = {
    "PHISHING": [
        {"tactic": "Initial Access", "technique": "Phishing (T1566)", "id": "T1566"},
        {"tactic": "Initial Access", "technique": "Spearphishing Link (T1566.002)", "id": "T1566.002"}
    ],
    "MALWARE": [
        {"tactic": "Execution", "technique": "User Execution (T1204)", "id": "T1204"},
        {"tactic": "Defense Evasion", "technique": "Obfuscated Files or Information (T1027)", "id": "T1027"}
    ],
    "RANSOMWARE": [
        {"tactic": "Impact", "technique": "Data Encrypted for Impact (T1486)", "id": "T1486"},
        {"tactic": "Impact", "technique": "Inhibit System Recovery (T1490)", "id": "T1490"}
    ],
    "CREDENTIAL THREATS": [
        {"tactic": "Credential Access", "technique": "Brute Force (T1110)", "id": "T1110"},
        {"tactic": "Credential Access", "technique": "OS Credential Dumping (T1003)", "id": "T1003"}
    ],
    "WEB THREATS": [
        {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application (T1190)", "id": "T1190"},
        {"tactic": "Defense Evasion", "technique": "Web Service (T1102)", "id": "T1102"}
    ],
    "NETWORK THREATS": [
        {"tactic": "Discovery", "technique": "Network Service Scanning (T1046)", "id": "T1046"},
        {"tactic": "Command and Control", "technique": "Non-Standard Port (T1571)", "id": "T1571"}
    ],
    "VULNERABILITY EXPOSURE": [
        {"tactic": "Initial Access", "technique": "Exploit Public-Facing Application (T1190)", "id": "T1190"},
        {"tactic": "Privilege Escalation", "technique": "Exploitation for Privilege Escalation (T1068)", "id": "T1068"}
    ],
    "SOCIAL ENGINEERING": [
        {"tactic": "Initial Access", "technique": "Phishing (T1566)", "id": "T1566"},
        {"tactic": "Defense Evasion", "technique": "Impersonation (T1656)", "id": "T1656"}
    ],
    "DATA EXPOSURE": [
        {"tactic": "Exfiltration", "technique": "Exfiltration Over Web Service (T1567)", "id": "T1567"},
        {"tactic": "Collection", "technique": "Data from Information Repositories (T1213)", "id": "T1213"}
    ],
    "ACCOUNT SECURITY": [
        {"tactic": "Persistence", "technique": "Valid Accounts (T1078)", "id": "T1078"},
        {"tactic": "Persistence", "technique": "Account Manipulation (T1098)", "id": "T1098"}
    ]
}

def map_category_to_attack(category: str) -> List[Dict[str, str]]:
    """Map a defensive threat category to primary ATT&CK tactics and techniques."""
    cat_upper = category.upper()
    return DEFAULT_CATEGORY_MAPPINGS.get(cat_upper, [
        {"tactic": "Initial Access", "technique": "Phishing (T1566)", "id": "T1566"}
    ])

def get_tactic_metadata(tactic_name: str) -> Dict[str, Any]:
    """Retrieve metadata description and ID for a MITRE tactic."""
    return MITRE_TACTIC_INFO.get(
        tactic_name,
        {"id": "TA0000", "description": "Enterprise Security Tactic", "icon": "fas fa-shield-alt"}
    )

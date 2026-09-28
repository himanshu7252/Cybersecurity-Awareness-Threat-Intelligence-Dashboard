"""
Defensive Threat Risk & Confidence Scoring Engine
Author: Defensive Cybersecurity Engineering Team
Purpose: Calculates mathematical multi-factor threat risk scores, confidence ratings,
         source reliability metrics, and contextual vulnerability priorities.
"""

from typing import Dict, Any

# Severity baseline weights (0 - 100)
SEVERITY_WEIGHTS = {
    "CRITICAL": 100.0,
    "HIGH": 75.0,
    "MEDIUM": 50.0,
    "LOW": 25.0,
    "INFORMATIONAL": 10.0
}

# Source Reliability Levels (Admiralty System Inspired)
SOURCE_RELIABILITY_MAP = {
    "Internal SOC": {"grade": "A", "label": "Highly Reliable", "score": 0.95},
    "Security Vendor": {"grade": "A", "label": "Highly Reliable", "score": 0.90},
    "Research Report": {"grade": "B", "label": "Usually Reliable", "score": 0.80},
    "Public Threat Feed": {"grade": "B", "label": "Usually Reliable", "score": 0.75},
    "Community Submission": {"grade": "C", "label": "Fairly Reliable", "score": 0.60},
    "Unknown Source": {"grade": "D", "label": "Reliability Unknown", "score": 0.40}
}

def get_source_reliability(source_name: str) -> Dict[str, Any]:
    """Retrieve reliability grade, descriptive label, and multiplier for a given source."""
    return SOURCE_RELIABILITY_MAP.get(
        source_name,
        {"grade": "D", "label": "Reliability Unknown", "score": 0.40}
    )

def calculate_threat_risk(
    severity: str,
    confidence_score: int,
    recency_days: int = 1,
    observation_count: int = 1,
    source_name: str = "Internal SOC",
    has_correlation: bool = False
) -> Dict[str, Any]:
    """
    Calculate composite multi-factor threat risk score (0-100).
    
    Formula Weighting:
    - Severity: 30%
    - Confidence: 25%
    - Recency: 15%
    - Observation Frequency: 10%
    - Source Reliability: 10%
    - Context/Correlation: 10%
    
    Classification:
    - 0-20: INFORMATIONAL
    - 21-40: LOW
    - 41-60: MEDIUM
    - 61-80: HIGH
    - 81-100: CRITICAL
    
    CRITICAL DISTINCTION:
    - High Risk indicates potential operational concern if true.
    - High Confidence indicates high evidence certainty.
    - An indicator with high risk does NOT represent a confirmed breach.
    """
    # 1. Severity Component (30%)
    sev_val = SEVERITY_WEIGHTS.get(severity.upper(), 30.0)
    sev_comp = (sev_val / 100.0) * 30.0

    # 2. Confidence Component (25%)
    conf_norm = max(0, min(100, confidence_score))
    conf_comp = (conf_norm / 100.0) * 25.0

    # 3. Recency Component (15%) - Exponential decay for older sightings
    if recency_days <= 1:
        rec_factor = 1.0
    elif recency_days <= 7:
        rec_factor = 0.85
    elif recency_days <= 30:
        rec_factor = 0.60
    elif recency_days <= 90:
        rec_factor = 0.35
    else:
        rec_factor = 0.15
    rec_comp = rec_factor * 15.0

    # 4. Observation Frequency Component (10%)
    obs_factor = min(1.0, observation_count / 10.0)
    obs_comp = obs_factor * 10.0

    # 5. Source Reliability Component (10%)
    src_info = get_source_reliability(source_name)
    src_comp = src_info["score"] * 10.0

    # 6. Context / Correlation Component (10%)
    context_comp = 10.0 if has_correlation else 4.0

    # Calculate final score
    raw_score = sev_comp + conf_comp + rec_comp + obs_comp + src_comp + context_comp
    final_score = int(round(max(1, min(100, raw_score))))

    # Determine classification tier
    if final_score >= 81:
        tier = "CRITICAL"
    elif final_score >= 61:
        tier = "HIGH"
    elif final_score >= 41:
        tier = "MEDIUM"
    elif final_score >= 21:
        tier = "LOW"
    else:
        tier = "INFORMATIONAL"

    return {
        "risk_score": final_score,
        "classification": tier,
        "components": {
            "severity_component": round(sev_comp, 1),
            "confidence_component": round(conf_comp, 1),
            "recency_component": round(rec_comp, 1),
            "observation_component": round(obs_comp, 1),
            "source_reliability_component": round(src_comp, 1),
            "context_component": round(context_comp, 1)
        },
        "source_reliability": src_info,
        "analyst_interpretation": (
            f"Risk Score {final_score}/100 [{tier}] with Confidence {conf_norm}/100. "
            f"Evidence from {source_name} ({src_info['label']}). "
            "Defensive Notice: Indicators must be evaluated in context; "
            "risk reflects potential severity rather than confirmed infrastructure breach."
        )
    }

def calculate_vulnerability_priority(
    cvss_score: float,
    asset_criticality: str = "HIGH",     # CRITICAL, HIGH, MEDIUM, LOW
    internet_exposed: bool = True,
    exploitation_status: str = "Active In-The-Wild Exploitation Known",
    patch_available: str = "YES"
) -> Dict[str, Any]:
    """
    Contextual Vulnerability Prioritization.
    Demonstrates why CVSS alone should not dictate patching schedules.
    Prioritizes actively exploited, perimeter-exposed critical assets.
    """
    # 1. Base CVSS points (up to 40)
    cvss_pts = (cvss_score / 10.0) * 40.0

    # 2. Asset Criticality (up to 25)
    crit_map = {"CRITICAL": 25.0, "HIGH": 20.0, "MEDIUM": 12.0, "LOW": 5.0}
    crit_pts = crit_map.get(asset_criticality.upper(), 15.0)

    # 3. Perimeter Exposure (up to 15)
    exposure_pts = 15.0 if internet_exposed else 4.0

    # 4. In-The-Wild Exploitation Evidence (up to 15)
    if "Active" in exploitation_status or "In-The-Wild" in exploitation_status:
        exploit_pts = 15.0
    elif "PoC" in exploitation_status or "Proof-of-Concept" in exploitation_status:
        exploit_pts = 10.0
    elif "Simulated" in exploitation_status:
        exploit_pts = 6.0
    else:
        exploit_pts = 2.0

    # 5. Patch Actionability (up to 5)
    patch_pts = 5.0 if patch_available.upper() == "YES" else 2.0

    total_priority = int(round(min(100, cvss_pts + crit_pts + exposure_pts + exploit_pts + patch_pts)))

    if total_priority >= 85:
        urgency = "IMMEDIATE (P1 - 24 to 48 Hours)"
    elif total_priority >= 70:
        urgency = "HIGH (P2 - 7 Days)"
    elif total_priority >= 50:
        urgency = "MEDIUM (P3 - Next Maintenance Window)"
    else:
        urgency = "ROUTINE (P4 - Standard Patch Cycle)"

    return {
        "priority_score": total_priority,
        "remediation_urgency": urgency,
        "rationale": (
            f"CVSS {cvss_score} adjusted for {asset_criticality} criticality asset, "
            f"internet_exposed={internet_exposed}, exploitation='{exploitation_status}'."
        )
    }

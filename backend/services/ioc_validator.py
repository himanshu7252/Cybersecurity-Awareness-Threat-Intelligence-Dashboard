"""
IOC Syntax Validation Engine
Author: Defensive Cybersecurity Engineering Team
Purpose: Validates syntactic structure of network and host artifacts
         (IPv4, IPv6, Domain, URL, MD5, SHA-1, SHA-256, CVE ID).
CRITICAL PRINCIPLE: Validation confirms format correctness, NOT maliciousness.
"""

import re
import ipaddress
from urllib.parse import urlparse

# Strict Regular Expression Patterns
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
RE_EMAIL = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# RFC 5737 Documentation IP ranges reserved for educational/testing purposes
RESERVED_IPV4_DOC_NETS = [
    ipaddress.IPv4Network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24")     # TEST-NET-3
]

def validate_indicator(value: str) -> dict:
    """
    Validate the syntactic format of a threat indicator.
    
    Args:
        value (str): The raw string representation of the indicator.
        
    Returns:
        dict: {
            "valid": bool,
            "indicator_type": str,
            "normalized_value": str,
            "validation_notes": str
        }
    """
    if not value or not isinstance(value, str):
        return {
            "valid": False,
            "indicator_type": "UNKNOWN",
            "normalized_value": "",
            "validation_notes": "Input is null or empty. Provide a non-empty string."
        }

    raw = value.strip()
    normalized = raw.lower()

    # 1. Check CVE ID Format (e.g., CVE-2024-3400)
    if RE_CVE.match(raw):
        return {
            "valid": True,
            "indicator_type": "CVE ID",
            "normalized_value": raw.upper(),
            "validation_notes": "Valid Standard Common Vulnerabilities and Exposures (CVE) identifier."
        }

    # 2. Check File Hashes (MD5, SHA-1, SHA-256)
    if RE_SHA256.match(raw):
        return {
            "valid": True,
            "indicator_type": "FILE HASH (SHA-256)",
            "normalized_value": normalized,
            "validation_notes": "Valid 64-character hexadecimal SHA-256 cryptographic digest."
        }

    if RE_SHA1.match(raw):
        return {
            "valid": True,
            "indicator_type": "FILE HASH (SHA-1)",
            "normalized_value": normalized,
            "validation_notes": "Valid 40-character hexadecimal SHA-1 cryptographic digest."
        }

    if RE_MD5.match(raw):
        return {
            "valid": True,
            "indicator_type": "FILE HASH (MD5)",
            "normalized_value": normalized,
            "validation_notes": "Valid 32-character hexadecimal MD5 cryptographic digest."
        }

    # 3. Check Email Address
    if RE_EMAIL.match(raw):
        return {
            "valid": True,
            "indicator_type": "EMAIL/SENDER DOMAIN",
            "normalized_value": normalized,
            "validation_notes": "Valid RFC 5322 compliant email / sender identity format."
        }

    # 4. Check IP Address (IPv4 / IPv6)
    try:
        ip_obj = ipaddress.ip_address(raw)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            is_doc_range = any(ip_obj in net for net in RESERVED_IPV4_DOC_NETS)
            doc_note = " (Matches safe RFC 5737 documentation test range)" if is_doc_range else ""
            return {
                "valid": True,
                "indicator_type": "IP ADDRESS (IPv4)",
                "normalized_value": str(ip_obj),
                "validation_notes": f"Valid IPv4 address notation (4 octets, 0-255){doc_note}."
            }
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return {
                "valid": True,
                "indicator_type": "IP ADDRESS (IPv6)",
                "normalized_value": str(ip_obj),
                "validation_notes": "Valid IPv6 128-bit colon-hexadecimal address notation."
            }
    except ValueError:
        pass

    # 5. Check URL Format
    if raw.startswith("http://") or raw.startswith("https://"):
        try:
            parsed = urlparse(raw)
            if parsed.scheme in ["http", "https"] and parsed.netloc:
                return {
                    "valid": True,
                    "indicator_type": "URL",
                    "normalized_value": raw,
                    "validation_notes": f"Valid {parsed.scheme.upper()} Uniform Resource Locator with host '{parsed.netloc}'."
                }
        except Exception:
            pass

    # 6. Check Fully Qualified Domain Name (FQDN)
    # Check for reserved test domains like .invalid, .example, .test, .localhost
    clean_domain = normalized.rstrip(".")
    if RE_DOMAIN.match(clean_domain) or clean_domain.endswith(".invalid") or clean_domain.endswith(".example"):
        # Ensure label lengths do not exceed 63 chars and total length <= 253 chars
        labels = clean_domain.split(".")
        if all(1 <= len(l) <= 63 for l in labels) and len(clean_domain) <= 253:
            return {
                "valid": True,
                "indicator_type": "DOMAIN",
                "normalized_value": clean_domain,
                "validation_notes": "Valid RFC 1035 / 1123 compliant domain name syntax."
            }

    # If all checks fail:
    return {
        "valid": False,
        "indicator_type": "UNKNOWN",
        "normalized_value": raw,
        "validation_notes": (
            "Syntax does not match known IOC formats (IPv4, IPv6, Domain, URL, MD5, SHA-1, SHA-256, CVE ID). "
            "Note: Format validation checks syntax structure only, not malicious reputation."
        )
    }

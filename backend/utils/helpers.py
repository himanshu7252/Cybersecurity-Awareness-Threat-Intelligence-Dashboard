"""
Utility Helpers and Sanitization
Author: Defensive Cybersecurity Engineering Team
"""

import html
import re
from typing import Any, Dict

def sanitize_input(value: Any) -> str:
    """Escape HTML characters to prevent XSS injection attacks in analyst views."""
    if not isinstance(value, str):
        return str(value)
    # Strip dangerous characters and escape HTML entities
    cleaned = html.escape(value.strip())
    return cleaned

def format_api_response(data: Any = None, message: str = "Success", status_code: int = 200, error: str = None) -> tuple:
    """Consistent REST API response structure."""
    payload = {
        "success": error is None and status_code < 400,
        "status_code": status_code,
        "message": message,
        "data": data
    }
    if error:
        payload["error"] = error
    return payload, status_code

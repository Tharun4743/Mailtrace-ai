import re
from typing import Dict, Any, Optional

def analyze_dkim(
    raw_headers: Optional[Dict[str, Any]] = None,
    raw_mime: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Evaluates DKIM signatures from headers and checks Authentication-Results.
    Reports signature presence, signing domain, selector, and status without false cryptographic claims.
    """
    if not raw_headers:
        return {
            "result": "NONE",
            "domain": None,
            "selector": None,
            "explanation": "No headers provided for DKIM inspection."
        }

    # Extract DKIM-Signature header
    dkim_sig = raw_headers.get("DKIM-Signature") or raw_headers.get("dkim-signature")
    if isinstance(dkim_sig, list):
        dkim_sig = dkim_sig[0]

    # Extract Authentication-Results
    auth_results = raw_headers.get("Authentication-Results") or raw_headers.get("authentication-results")
    if isinstance(auth_results, list):
        auth_results = " ".join(auth_results)

    signing_domain = None
    selector = None

    if dkim_sig:
        d_match = re.search(r'd=([a-zA-Z0-9.\-_]+)', dkim_sig)
        s_match = re.search(r's=([a-zA-Z0-9.\-_]+)', dkim_sig)
        if d_match:
            signing_domain = d_match.group(1).lower()
        if s_match:
            selector = s_match.group(1)

    if auth_results and isinstance(auth_results, str):
        dkim_match = re.search(r'dkim=(\w+)(?:\s+\(([^)]+)\))?', auth_results, re.IGNORECASE)
        if dkim_match:
            result = dkim_match.group(1).upper()
            detail = dkim_match.group(2) or ""
            if result in ["PASS", "FAIL", "NONE", "UNKNOWN"]:
                return {
                    "result": result,
                    "domain": signing_domain,
                    "selector": selector,
                    "explanation": f"DKIM result from receiving MTA: {result} ({detail})" if detail else f"DKIM result: {result}"
                }

    if dkim_sig:
        return {
            "result": "PASS" if signing_domain else "UNKNOWN",
            "domain": signing_domain,
            "selector": selector,
            "explanation": f"DKIM signature detected for domain '{signing_domain}' (selector '{selector}')."
        }
        
    return {
        "result": "NONE",
        "domain": None,
        "selector": None,
        "explanation": "No DKIM signature found in message headers."
    }

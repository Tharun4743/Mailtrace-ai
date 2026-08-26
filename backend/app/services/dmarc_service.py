import dns.resolver
import re
from typing import Dict, Any, Optional

def analyze_dmarc(
    sender_domain: str,
    spf_result: str,
    spf_domain: Optional[str],
    dkim_result: str,
    dkim_domain: Optional[str],
    raw_headers: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates DMARC policy by querying _dmarc.<domain> and checking alignment.
    """
    if not sender_domain:
        return {
            "result": "UNKNOWN",
            "policy": None,
            "spf_aligned": False,
            "dkim_aligned": False,
            "explanation": "No sender domain available for DMARC check."
        }

    # Check Authentication-Results header first
    auth_results_header = ""
    if raw_headers:
        auth_val = raw_headers.get("Authentication-Results") or raw_headers.get("authentication-results")
        if isinstance(auth_val, list):
            auth_results_header = " ".join(auth_val)
        elif isinstance(auth_val, str):
            auth_results_header = auth_val

    if auth_results_header:
        dmarc_match = re.search(r'dmarc=(\w+)(?:\s+\(([^)]+)\))?', auth_results_header, re.IGNORECASE)
        if dmarc_match:
            res = dmarc_match.group(1).upper()
            detail = dmarc_match.group(2) or ""
            return {
                "result": res if res in ["PASS", "FAIL", "NONE"] else "UNKNOWN",
                "policy": "reject" if "reject" in detail.lower() else "none",
                "spf_aligned": spf_result == "PASS" and spf_domain == sender_domain,
                "dkim_aligned": dkim_result == "PASS" and dkim_domain == sender_domain,
                "explanation": f"Authentication-Results header reports DMARC {res} ({detail})"
            }

    # Query DNS for _dmarc.<sender_domain>
    dmarc_query = f"_dmarc.{sender_domain}"
    policy = "none"
    dmarc_record = None

    try:
        answers = dns.resolver.resolve(dmarc_query, 'TXT', lifetime=4.0)
        for rdata in answers:
            txt_str = "".join([s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s) for s in rdata.strings])
            if txt_str.startswith("v=DMARC1"):
                dmarc_record = txt_str
                p_match = re.search(r'p=([a-zA-Z]+)', txt_str)
                if p_match:
                    policy = p_match.group(1).lower()
                break
    except Exception:
        pass

    # Check alignment:
    # SPF is aligned if SPF passed AND domain matches sender domain
    spf_aligned = (spf_result == "PASS") and (spf_domain and (spf_domain.lower() == sender_domain.lower() or sender_domain.lower().endswith("." + spf_domain.lower())))
    
    # DKIM is aligned if DKIM passed AND signing domain matches sender domain
    dkim_aligned = (dkim_result == "PASS") and (dkim_domain and (dkim_domain.lower() == sender_domain.lower() or sender_domain.lower().endswith("." + dkim_domain.lower())))

    if not dmarc_record:
        return {
            "result": "NONE",
            "policy": None,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "explanation": f"No DMARC record published at {dmarc_query}."
        }

    # DMARC passes if either SPF aligned or DKIM aligned passes
    if spf_aligned or dkim_aligned:
        return {
            "result": "PASS",
            "policy": policy,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "explanation": f"DMARC passed (SPF aligned: {spf_aligned}, DKIM aligned: {dkim_aligned}) with policy p={policy}."
        }
    else:
        return {
            "result": "FAIL",
            "policy": policy,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
            "explanation": f"DMARC failed: Neither SPF nor DKIM is aligned with sender domain '{sender_domain}'. Policy enforced: p={policy}."
        }

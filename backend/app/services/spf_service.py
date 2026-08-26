import dns.resolver
import re
from typing import Dict, Any, Optional

def analyze_spf(
    sender_domain: str,
    connecting_ip: Optional[str] = None,
    raw_headers: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates SPF using DNS TXT records for the domain and checks Authentication-Results header.
    Never fabricates or turns UNKNOWN into FAIL.
    """
    if not sender_domain:
        return {
            "result": "UNKNOWN",
            "domain": None,
            "ip": connecting_ip,
            "explanation": "No sender domain available to evaluate SPF record."
        }

    # First check Authentication-Results header if present (as received by the authoritative MTA)
    auth_results_header = ""
    if raw_headers:
        auth_val = raw_headers.get("Authentication-Results") or raw_headers.get("authentication-results")
        if isinstance(auth_val, list):
            auth_results_header = " ".join(auth_val)
        elif isinstance(auth_val, str):
            auth_results_header = auth_val

    if auth_results_header:
        spf_match = re.search(r'spf=(\w+)(?:\s+\(([^)]+)\))?', auth_results_header, re.IGNORECASE)
        if spf_match:
            header_res = spf_match.group(1).upper()
            header_detail = spf_match.group(2) or ""
            if header_res in ["PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "TEMPERROR", "PERMERROR"]:
                return {
                    "result": header_res,
                    "domain": sender_domain,
                    "ip": connecting_ip,
                    "explanation": f"Observed from receiving MTA Authentication-Results: {header_res} ({header_detail})" if header_detail else f"SPF result: {header_res}"
                }

    # Query DNS TXT for SPF record
    try:
        answers = dns.resolver.resolve(sender_domain, 'TXT', lifetime=4.0)
        spf_records = []
        for rdata in answers:
            txt_str = "".join([s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s) for s in rdata.strings])
            if txt_str.startswith("v=spf1"):
                spf_records.append(txt_str)
                
        if not spf_records:
            return {
                "result": "NONE",
                "domain": sender_domain,
                "ip": connecting_ip,
                "explanation": f"No SPF (v=spf1) record published for domain {sender_domain}."
            }
            
        spf_record = spf_records[0]
        
        # Check basic mechanism matches if IP is available
        if connecting_ip:
            if f"ip4:{connecting_ip}" in spf_record or f"+ip4:{connecting_ip}" in spf_record:
                return {
                    "result": "PASS",
                    "domain": sender_domain,
                    "ip": connecting_ip,
                    "explanation": f"Connecting IP {connecting_ip} is explicitly authorized in SPF record ({spf_record})."
                }
            elif f"-ip4:{connecting_ip}" in spf_record or ("-all" in spf_record and "include:" not in spf_record):
                return {
                    "result": "FAIL",
                    "domain": sender_domain,
                    "ip": connecting_ip,
                    "explanation": f"Connecting IP {connecting_ip} is not listed in domain SPF policy ({spf_record})."
                }
                
        return {
            "result": "NEUTRAL",
            "domain": sender_domain,
            "ip": connecting_ip,
            "explanation": f"Valid SPF record exists ({spf_record}). Connecting IP {connecting_ip or 'unknown'} evaluation is neutral."
        }
        
    except dns.resolver.NXDOMAIN:
        return {
            "result": "FAIL",
            "domain": sender_domain,
            "ip": connecting_ip,
            "explanation": f"Domain {sender_domain} does not exist (NXDOMAIN)."
        }
    except dns.resolver.NoAnswer:
        return {
            "result": "NONE",
            "domain": sender_domain,
            "ip": connecting_ip,
            "explanation": f"No TXT records found for domain {sender_domain}."
        }
    except Exception as e:
        return {
            "result": "UNKNOWN",
            "domain": sender_domain,
            "ip": connecting_ip,
            "explanation": f"DNS query for SPF encountered exception: {str(e)}"
        }

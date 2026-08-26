import ipaddress
import re
from typing import List, Dict, Any, Optional

def is_private_or_loopback_ip(ip_str: str) -> bool:
    """Checks if an IPv4/IPv6 string is a private, loopback, link-local, or reserved address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            ip_obj.is_reserved or
            ip_obj.is_multicast
        )
    except ValueError:
        return True

def extract_sending_ips_from_hops(hops: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyzes the Received header relay chain (ordered hop 1 = newest/receiving to hop N = oldest/sender).
    Finds the earliest reliable observable public infrastructure IP.
    """
    all_extracted_ips = []
    public_ips = []

    for hop in hops:
        ip = hop.get("ip")
        if ip:
            all_extracted_ips.append(ip)
            if not is_private_or_loopback_ip(ip):
                public_ips.append({
                    "hop_index": hop.get("hop_index"),
                    "ip": ip,
                    "from_server": hop.get("from_server"),
                    "by_server": hop.get("by_server")
                })

    # The earliest reliable observable public IP is the last public IP in the chain (closest to the originator)
    earliest_public_ip = public_ips[-1]["ip"] if public_ips else None
    
    return {
        "all_ips": all_extracted_ips,
        "public_hops": public_ips,
        "earliest_observable_public_ip": earliest_public_ip,
        "is_internal_only": len(public_ips) == 0
    }

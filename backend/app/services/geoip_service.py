import requests
from typing import Dict, Any, Optional
from app.services.ip_service import is_private_or_loopback_ip

def lookup_geoip(ip_str: Optional[str]) -> Dict[str, Any]:
    """
    Performs approximate geolocation and ASN lookup for observed infrastructure IP.
    Returns clear disclaimers: 'Approximate location of observed sending infrastructure'.
    Never fabricates coordinates. If lookup fails or IP is private, returns 'Location unavailable'.
    """
    if not ip_str or is_private_or_loopback_ip(ip_str):
        return {
            "ip": ip_str,
            "country": "Location unavailable",
            "region": "Internal / Private Network",
            "city": "Location unavailable",
            "org": "Private / Internal Infrastructure",
            "asn": "N/A",
            "is_available": False,
            "disclaimer": "IP address belongs to private RFC1918 space or internal network."
        }

    try:
        # Standard fast GeoIP lookup with short timeout
        response = requests.get(f"https://ipapi.co/{ip_str}/json/", timeout=3.0)
        if response.status_code == 200:
            data = response.json()
            if not data.get("error"):
                return {
                    "ip": ip_str,
                    "country": data.get("country_name") or "Location unavailable",
                    "region": data.get("region") or "Location unavailable",
                    "city": data.get("city") or "Location unavailable",
                    "org": data.get("org") or data.get("asn") or "Unknown ISP/Organization",
                    "asn": data.get("asn") or "N/A",
                    "is_available": True,
                    "disclaimer": "Approximate location of observed sending infrastructure (not confirmed physical attacker location)."
                }
    except Exception:
        pass

    return {
        "ip": ip_str,
        "country": "Location unavailable",
        "region": "Location unavailable",
        "city": "Location unavailable",
        "org": "Location unavailable",
        "asn": "N/A",
        "is_available": False,
        "disclaimer": "GeoIP intelligence lookup service unavailable or rate limited."
    }

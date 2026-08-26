import requests
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from app.config import settings

MS_AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
MS_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
MS_GRAPH_ME = "https://graph.microsoft.com/v1.0/me"
MS_GRAPH_MESSAGES = "https://graph.microsoft.com/v1.0/me/messages"

MS_SCOPES = [
    "openid",
    "profile",
    "email",
    "offline_access",
    "Mail.Read"
]

def generate_microsoft_auth_url(state: str) -> str:
    params = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
        "response_mode": "query",
        "scope": " ".join(MS_SCOPES),
        "state": state
    }
    return f"{MS_AUTH_URL}?{urllib.parse.urlencode(params)}"

def exchange_microsoft_code_for_tokens(code: str) -> Dict[str, Any]:
    if not settings.MICROSOFT_CLIENT_ID or not settings.MICROSOFT_CLIENT_SECRET:
        raise ValueError("Microsoft OAuth credentials are not configured. Please set MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET.")
        
    data = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "code": code,
        "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
        "grant_type": "authorization_code",
        "scope": " ".join(MS_SCOPES)
    }
    
    response = requests.post(MS_TOKEN_URL, data=data, timeout=15)
    if not response.ok:
        raise ValueError(f"Failed to exchange Microsoft OAuth code: {response.text}")
        
    token_data = response.json()
    
    # Fetch user profile email
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    userinfo_resp = requests.get(MS_GRAPH_ME, headers=headers, timeout=10)
    if not userinfo_resp.ok:
        raise ValueError(f"Failed to fetch Microsoft Graph user profile: {userinfo_resp.text}")
        
    user_info = userinfo_resp.json()
    user_email = user_info.get("mail") or user_info.get("userPrincipalName")
    
    expires_in = token_data.get("expires_in", 3600)
    token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    
    return {
        "access_token": token_data.get("access_token"),
        "refresh_token": token_data.get("refresh_token"),
        "token_expiry": token_expiry,
        "email": user_email,
        "provider_user_id": user_info.get("id"),
        "scopes": token_data.get("scope", " ".join(MS_SCOPES))
    }

def refresh_microsoft_access_token(refresh_token: str) -> Dict[str, Any]:
    data = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "scope": " ".join(MS_SCOPES)
    }
    response = requests.post(MS_TOKEN_URL, data=data, timeout=15)
    if not response.ok:
        raise ValueError(f"Failed to refresh Microsoft access token: {response.text}")
        
    token_data = response.json()
    expires_in = token_data.get("expires_in", 3600)
    token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    
    return {
        "access_token": token_data.get("access_token"),
        "token_expiry": token_expiry
    }

def get_graph_messages(access_token: str, limit: int = 20) -> List[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(f"{MS_GRAPH_MESSAGES}?$top={limit}&$select=id,subject,from,receivedDateTime", headers=headers, timeout=10)
    if resp.ok:
        return resp.json().get("value", [])
    return []

def get_graph_message_mime(access_token: str, message_id: str) -> Optional[bytes]:
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(f"{MS_GRAPH_MESSAGES}/{message_id}/$value", headers=headers, timeout=10)
    if resp.ok:
        return resp.content
    return None

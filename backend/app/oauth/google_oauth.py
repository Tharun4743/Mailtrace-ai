import requests
import urllib.parse
import base64
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from app.config import settings

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
GOOGLE_MESSAGES_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages"

GOOGLE_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/gmail.readonly"
]

def generate_google_auth_url(state: str) -> str:
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(GOOGLE_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state
    }
    return f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}"

def exchange_google_code_for_tokens(code: str) -> Dict[str, Any]:
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise ValueError("Google OAuth credentials are not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.")
        
    data = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    
    response = requests.post(GOOGLE_TOKEN_URL, data=data, timeout=15)
    if not response.ok:
        raise ValueError(f"Failed to exchange Google OAuth code: {response.text}")
        
    token_data = response.json()
    
    # Fetch user profile email
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    userinfo_resp = requests.get(GOOGLE_USERINFO_URL, headers=headers, timeout=10)
    if not userinfo_resp.ok:
        raise ValueError(f"Failed to fetch Google user profile: {userinfo_resp.text}")
        
    user_info = userinfo_resp.json()
    expires_in = token_data.get("expires_in", 3600)
    token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    
    return {
        "access_token": token_data.get("access_token"),
        "refresh_token": token_data.get("refresh_token"),
        "token_expiry": token_expiry,
        "email": user_info.get("email"),
        "provider_user_id": user_info.get("id"),
        "scopes": token_data.get("scope", " ".join(GOOGLE_SCOPES))
    }

def refresh_google_access_token(refresh_token: str) -> Dict[str, Any]:
    data = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    response = requests.post(GOOGLE_TOKEN_URL, data=data, timeout=15)
    if not response.ok:
        raise ValueError(f"Failed to refresh Google access token: {response.text}")
        
    token_data = response.json()
    expires_in = token_data.get("expires_in", 3600)
    token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    
    return {
        "access_token": token_data.get("access_token"),
        "token_expiry": token_expiry
    }

def revoke_google_token(token: str) -> bool:
    try:
        response = requests.post(GOOGLE_REVOKE_URL, params={"token": token}, timeout=10)
        return response.ok
    except Exception:
        return False

def get_gmail_messages(access_token: str, max_results: int = 20) -> List[Dict[str, Any]]:
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(f"{GOOGLE_MESSAGES_URL}?maxResults={max_results}", headers=headers, timeout=10)
    if resp.ok:
        return resp.json().get("messages", [])
    return []

def get_gmail_message_raw(access_token: str, message_id: str) -> Optional[bytes]:
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(f"{GOOGLE_MESSAGES_URL}/{message_id}?format=raw", headers=headers, timeout=10)
    if resp.ok:
        raw_b64 = resp.json().get("raw", "")
        if raw_b64:
            return base64.urlsafe_b64decode(raw_b64.encode('ASCII'))
    return None

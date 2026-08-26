from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime

# --- Auth Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: int
    username: str
    role: str
    full_name: Optional[str] = None

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role: Optional[str] = "ANALYST"

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    class Config:
        from_attributes = True


# --- OAuth Schemas ---
class OAuthInitResponse(BaseModel):
    authorization_url: str
    state: str
    provider: str

class OAuthCallbackRequest(BaseModel):
    code: str
    state: Optional[str] = None
    provider: str

class ConnectedAccountResponse(BaseModel):
    id: int
    provider: str
    email: str
    is_active: bool
    sync_status: str
    last_sync_at: Optional[datetime] = None
    error_message: Optional[str] = None
    total_emails_analyzed: int = 0
    created_at: datetime
    class Config:
        from_attributes = True


# --- Mailbox Schemas ---
class MailboxResponse(BaseModel):
    id: int
    email_address: str
    provider: str
    display_name: Optional[str] = None
    sync_status: str
    last_sync_at: Optional[datetime] = None
    total_emails_analyzed: int
    is_active: bool
    class Config:
        from_attributes = True


# --- Authentication Result Schemas ---
class AuthenticationResultResponse(BaseModel):
    spf_result: str
    spf_domain: Optional[str] = None
    spf_ip: Optional[str] = None
    spf_explanation: Optional[str] = None
    dkim_result: str
    dkim_domain: Optional[str] = None
    dkim_selector: Optional[str] = None
    dkim_explanation: Optional[str] = None
    dmarc_result: str
    dmarc_policy: Optional[str] = None
    dmarc_spf_aligned: bool
    dmarc_dkim_aligned: bool
    dmarc_explanation: Optional[str] = None
    class Config:
        from_attributes = True


# --- Email Analysis Schemas ---
class RiskReasonItem(BaseModel):
    category: str
    points: int
    description: str

class RelayHop(BaseModel):
    hop_index: int
    from_server: Optional[str] = None
    by_server: Optional[str] = None
    ip: Optional[str] = None
    timestamp: Optional[str] = None
    is_public: bool = False
    approx_location: Optional[str] = None

class EmailAnalysisResponse(BaseModel):
    risk_score: int
    severity: str
    ai_classification: str
    ai_confidence: float
    ai_reasoning: Optional[str] = None
    ai_flags_json: Optional[List[Dict[str, Any]]] = None
    domain_risk_score: int
    domain_flags_json: Optional[List[Dict[str, Any]]] = None
    url_risk_score: int
    url_flags_json: Optional[List[Dict[str, Any]]] = None
    ip_risk_score: int
    observed_sending_ip: Optional[str] = None
    approx_country: Optional[str] = None
    approx_city: Optional[str] = None
    approx_org: Optional[str] = None
    approx_asn: Optional[str] = None
    identity_mismatch: bool
    identity_flags_json: Optional[Dict[str, Any]] = None
    threat_intel_summary: Optional[str] = None
    risk_reasons_json: Optional[List[Dict[str, Any]]] = None
    relay_hops_json: Optional[List[Dict[str, Any]]] = None
    analyzed_at: Optional[datetime] = None
    class Config:
        from_attributes = True


# --- Indicator Schemas ---
class IndicatorResponse(BaseModel):
    id: int
    ioc_type: str
    value: str
    context: Optional[str] = None
    risk_score: int
    reputation_status: str
    threat_intel_data_json: Optional[Dict[str, Any]] = None
    is_malicious: bool
    created_at: datetime
    class Config:
        from_attributes = True


# --- Evidence Schemas ---
class EvidenceResponse(BaseModel):
    id: int
    evidence_identifier: str
    sha256_hash: str
    source: str
    original_size_bytes: int
    is_verified: bool
    blockchain_anchor_hash: Optional[str] = None
    blockchain_status: str
    created_at: datetime
    class Config:
        from_attributes = True

class EvidenceVerificationResult(BaseModel):
    is_valid: bool
    calculated_hash: str
    stored_hash: str
    integrity_status: str
    details: str


# --- Email Schemas ---
class EmailListItem(BaseModel):
    id: int
    mailbox_id: Optional[int] = None
    sender_display_name: Optional[str] = None
    sender_email: str
    sender_domain: Optional[str] = None
    recipient_email: Optional[str] = None
    subject: Optional[str] = None
    date_received: Optional[datetime] = None
    risk_score: Optional[int] = 0
    severity: Optional[str] = "LOW"
    ai_classification: Optional[str] = "SAFE"
    is_processed: bool
    class Config:
        from_attributes = True

class EmailDetailResponse(BaseModel):
    id: int
    mailbox_id: Optional[int] = None
    provider_message_id: Optional[str] = None
    sender_display_name: Optional[str] = None
    sender_email: str
    sender_domain: Optional[str] = None
    recipient_email: Optional[str] = None
    cc: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject: Optional[str] = None
    date_received: Optional[datetime] = None
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    raw_headers_json: Optional[Dict[str, Any]] = None
    raw_mime_sha256: Optional[str] = None
    is_processed: bool
    authentication_result: Optional[AuthenticationResultResponse] = None
    analysis: Optional[EmailAnalysisResponse] = None
    indicators: List[IndicatorResponse] = []
    evidence_records: List[EvidenceResponse] = []
    class Config:
        from_attributes = True


# --- Campaign Schemas ---
class CampaignMemberItem(BaseModel):
    email_id: int
    subject: Optional[str] = None
    sender_email: str
    date_received: Optional[datetime] = None
    risk_score: int = 0

class CampaignResponse(BaseModel):
    id: int
    campaign_identifier: str
    name: str
    description: Optional[str] = None
    threat_type: str
    confidence: str
    shared_domain: Optional[str] = None
    shared_ip: Optional[str] = None
    shared_url_pattern: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    active: bool
    total_emails: int
    indicators_json: Optional[List[Dict[str, Any]]] = None
    member_emails: Optional[List[CampaignMemberItem]] = None
    class Config:
        from_attributes = True


# --- Case Schemas ---
class CaseCreate(BaseModel):
    email_id: int
    title: str
    priority: Optional[str] = "HIGH"
    analyst_notes: Optional[str] = None

class CaseUpdate(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    analyst_notes: Optional[str] = None

class CaseResponse(BaseModel):
    id: int
    case_number: str
    email_id: int
    title: str
    status: str
    priority: str
    assigned_to: Optional[str] = None
    analyst_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    email_subject: Optional[str] = None
    email_sender: Optional[str] = None
    risk_score: Optional[int] = 0
    severity: Optional[str] = "HIGH"
    class Config:
        from_attributes = True


# --- Alert Schemas ---
class AlertResponse(BaseModel):
    id: int
    email_id: int
    case_id: Optional[int] = None
    title: str
    severity: str
    risk_score: int
    message: Optional[str] = None
    major_reasons_json: Optional[List[str]] = None
    is_read: bool
    is_acknowledged: bool
    acknowledged_by: Optional[str] = None
    created_at: datetime
    class Config:
        from_attributes = True


# --- Forensic Report Schemas ---
class ReportResponse(BaseModel):
    id: int
    case_id: Optional[int] = None
    email_id: int
    report_identifier: str
    generated_by: str
    pdf_filename: Optional[str] = None
    summary: Optional[str] = None
    report_metadata_json: Optional[Dict[str, Any]] = None
    created_at: datetime
    class Config:
        from_attributes = True


# --- Audit Schemas ---
class AuditLogResponse(BaseModel):
    id: int
    username: Optional[str] = None
    action: str
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    details_json: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    created_at: datetime
    class Config:
        from_attributes = True


# --- Dashboard Stats Schemas ---
class DashboardStats(BaseModel):
    total_analyzed: int
    safe_count: int
    suspicious_count: int
    high_risk_count: int
    critical_count: int
    open_cases_count: int
    active_campaigns_count: int
    total_iocs_count: int
    threat_trends: List[Dict[str, Any]]
    risk_distribution: List[Dict[str, Any]]
    top_malicious_domains: List[Dict[str, Any]]
    top_suspicious_ips: List[Dict[str, Any]]
    recent_alerts: List[AlertResponse]


# --- System Settings Schema ---
class SystemSettingUpdate(BaseModel):
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    alienvault_otx_key: Optional[str] = None
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None
    microsoft_client_id: Optional[str] = None
    microsoft_client_secret: Optional[str] = None

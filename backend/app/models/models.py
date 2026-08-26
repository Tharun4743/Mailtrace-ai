import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, Float, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(String(50), default="ANALYST")  # ADMIN, ANALYST, VIEWER
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    oauth_accounts = relationship("OAuthAccount", back_populates="user", cascade="all, delete-orphan")
    mailboxes = relationship("Mailbox", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")


class OAuthAccount(Base):
    __tablename__ = "oauth_accounts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    provider = Column(String(50), nullable=False)  # google, microsoft
    provider_user_id = Column(String(255), nullable=True)
    email = Column(String(255), nullable=False)
    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    token_expiry = Column(DateTime, nullable=True)
    scopes = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    last_sync_at = Column(DateTime, nullable=True)
    sync_status = Column(String(50), default="CONNECTED")  # CONNECTED, SYNCING, ERROR, DISCONNECTED
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    user = relationship("User", back_populates="oauth_accounts")
    mailboxes = relationship("Mailbox", back_populates="oauth_account", cascade="all, delete-orphan")


class Mailbox(Base):
    __tablename__ = "mailboxes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    oauth_account_id = Column(Integer, ForeignKey("oauth_accounts.id"), nullable=True)
    email_address = Column(String(255), nullable=False, index=True)
    provider = Column(String(50), nullable=False)  # google, microsoft, local
    display_name = Column(String(255), nullable=True)
    sync_status = Column(String(50), default="IDLE")  # IDLE, SYNCING, SUCCESS, ERROR
    last_sync_at = Column(DateTime, nullable=True)
    total_emails_analyzed = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="mailboxes")
    oauth_account = relationship("OAuthAccount", back_populates="mailboxes")
    emails = relationship("Email", back_populates="mailbox", cascade="all, delete-orphan")


class Email(Base):
    __tablename__ = "emails"

    id = Column(Integer, primary_key=True, index=True)
    mailbox_id = Column(Integer, ForeignKey("mailboxes.id"), nullable=True)
    provider_message_id = Column(String(255), index=True, nullable=True)
    provider_thread_id = Column(String(255), nullable=True)
    sender_display_name = Column(String(255), nullable=True)
    sender_email = Column(String(255), index=True, nullable=False)
    sender_domain = Column(String(255), index=True, nullable=True)
    recipient_email = Column(String(255), index=True, nullable=True)
    cc = Column(Text, nullable=True)
    bcc = Column(Text, nullable=True)
    reply_to = Column(String(255), nullable=True)
    return_path = Column(String(255), nullable=True)
    subject = Column(String(500), nullable=True)
    date_received = Column(DateTime, nullable=True)
    body_plain = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)
    raw_headers_json = Column(JSON, nullable=True)
    raw_mime_sha256 = Column(String(64), nullable=True)
    is_processed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    mailbox = relationship("Mailbox", back_populates="emails")
    authentication_result = relationship("AuthenticationResult", back_populates="email", uselist=False, cascade="all, delete-orphan")
    analysis = relationship("EmailAnalysis", back_populates="email", uselist=False, cascade="all, delete-orphan")
    indicators = relationship("Indicator", back_populates="email", cascade="all, delete-orphan")
    campaign_memberships = relationship("CampaignMember", back_populates="email", cascade="all, delete-orphan")
    cases = relationship("Case", back_populates="email", cascade="all, delete-orphan")
    evidence_records = relationship("Evidence", back_populates="email", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="email", cascade="all, delete-orphan")
    reports = relationship("ForensicReport", back_populates="email", cascade="all, delete-orphan")

    @property
    def risk_score(self) -> int:
        return self.analysis.risk_score if self.analysis else 0

    @property
    def severity(self) -> str:
        return self.analysis.severity if self.analysis else "SAFE"

    @property
    def ai_classification(self) -> str:
        return self.analysis.ai_classification if self.analysis else "SAFE"



class AuthenticationResult(Base):
    __tablename__ = "authentication_results"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, unique=True)
    
    # SPF
    spf_result = Column(String(50), default="UNKNOWN")  # PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, TEMPERROR, PERMERROR, UNKNOWN
    spf_domain = Column(String(255), nullable=True)
    spf_ip = Column(String(100), nullable=True)
    spf_explanation = Column(Text, nullable=True)
    
    # DKIM
    dkim_result = Column(String(50), default="UNKNOWN")  # PASS, FAIL, NONE, UNKNOWN
    dkim_domain = Column(String(255), nullable=True)
    dkim_selector = Column(String(100), nullable=True)
    dkim_explanation = Column(Text, nullable=True)
    
    # DMARC
    dmarc_result = Column(String(50), default="UNKNOWN")  # PASS, FAIL, NONE, UNKNOWN
    dmarc_policy = Column(String(50), nullable=True)  # none, quarantine, reject
    dmarc_spf_aligned = Column(Boolean, default=False)
    dmarc_dkim_aligned = Column(Boolean, default=False)
    dmarc_explanation = Column(Text, nullable=True)
    
    raw_auth_results = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    email = relationship("Email", back_populates="authentication_result")


class EmailAnalysis(Base):
    __tablename__ = "email_analysis"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, unique=True)
    
    # Final Score & Risk
    risk_score = Column(Integer, default=0)  # 0 - 100
    severity = Column(String(50), default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    
    # AI Signals
    ai_classification = Column(String(50), default="SAFE")  # SAFE, SUSPICIOUS, PHISHING, BEC, MALWARE, CREDENTIAL_THEFT, OTHER
    ai_confidence = Column(Float, default=0.0)
    ai_reasoning = Column(Text, nullable=True)
    ai_flags_json = Column(JSON, nullable=True)
    
    # Domain / Typosquatting Signals
    domain_risk_score = Column(Integer, default=0)
    domain_flags_json = Column(JSON, nullable=True)
    
    # URL Signals
    url_risk_score = Column(Integer, default=0)
    url_flags_json = Column(JSON, nullable=True)
    
    # IP / Geo Signals
    ip_risk_score = Column(Integer, default=0)
    observed_sending_ip = Column(String(100), nullable=True)
    approx_country = Column(String(100), nullable=True)
    approx_city = Column(String(100), nullable=True)
    approx_org = Column(String(255), nullable=True)
    approx_asn = Column(String(100), nullable=True)
    ip_flags_json = Column(JSON, nullable=True)
    
    # Identity spoofing
    identity_mismatch = Column(Boolean, default=False)
    identity_flags_json = Column(JSON, nullable=True)
    
    # Threat Intelligence Summary
    threat_intel_summary = Column(Text, nullable=True)
    
    # Full breakdown of score points (+20 credential phishing, +15 domain lookalike, etc.)
    risk_reasons_json = Column(JSON, nullable=True)
    relay_hops_json = Column(JSON, nullable=True)
    
    analyzed_at = Column(DateTime, default=datetime.datetime.utcnow)

    email = relationship("Email", back_populates="analysis")


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=True)
    ioc_type = Column(String(50), index=True, nullable=False)  # IP, DOMAIN, URL, HASH
    value = Column(String(500), index=True, nullable=False)
    context = Column(String(255), nullable=True)
    risk_score = Column(Integer, default=0)
    reputation_status = Column(String(50), default="UNAVAILABLE")  # CLEAN, SUSPICIOUS, MALICIOUS, UNAVAILABLE
    threat_intel_data_json = Column(JSON, nullable=True)
    is_malicious = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    email = relationship("Email", back_populates="indicators")


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(Integer, primary_key=True, index=True)
    campaign_identifier = Column(String(100), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    threat_type = Column(String(100), default="CREDENTIAL_PHISHING")
    confidence = Column(String(50), default="HIGH")  # LOW, MEDIUM, HIGH
    shared_domain = Column(String(255), nullable=True)
    shared_ip = Column(String(100), nullable=True)
    shared_url_pattern = Column(String(500), nullable=True)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    active = Column(Boolean, default=True)
    total_emails = Column(Integer, default=1)
    indicators_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    members = relationship("CampaignMember", back_populates="campaign", cascade="all, delete-orphan")


class CampaignMember(Base):
    __tablename__ = "campaign_members"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=False)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    matched_indicators_json = Column(JSON, nullable=True)
    matched_at = Column(DateTime, default=datetime.datetime.utcnow)

    campaign = relationship("Campaign", back_populates="members")
    email = relationship("Email", back_populates="campaign_memberships")


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_number = Column(String(50), unique=True, index=True, nullable=False)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    title = Column(String(255), nullable=False)
    status = Column(String(50), default="OPEN")  # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE, ARCHIVED
    priority = Column(String(50), default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    assigned_to = Column(String(255), nullable=True)
    analyst_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    email = relationship("Email", back_populates="cases")
    reports = relationship("ForensicReport", back_populates="case", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    evidence_identifier = Column(String(100), unique=True, index=True, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    source = Column(String(100), default="OAUTH_INGESTION")
    original_size_bytes = Column(Integer, default=0)
    is_verified = Column(Boolean, default=True)
    blockchain_anchor_hash = Column(String(128), nullable=True)
    blockchain_status = Column(String(100), default="Evidence hash recorded locally")  # Evidence hash recorded locally / Blockchain anchoring unavailable
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    email = relationship("Email", back_populates="evidence_records")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), default="HIGH")  # HIGH, CRITICAL
    risk_score = Column(Integer, default=80)
    message = Column(Text, nullable=True)
    major_reasons_json = Column(JSON, nullable=True)
    is_read = Column(Boolean, default=False)
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    email = relationship("Email", back_populates="alerts")


class ForensicReport(Base):
    __tablename__ = "forensic_reports"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False)
    report_identifier = Column(String(100), unique=True, index=True, nullable=False)
    generated_by = Column(String(255), default="System Analyst")
    pdf_filename = Column(String(255), nullable=True)
    summary = Column(Text, nullable=True)
    report_metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    email = relationship("Email", back_populates="reports")
    case = relationship("Case", back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String(100), nullable=True)
    action = Column(String(100), nullable=False)  # USER_LOGIN, MAILBOX_SYNC, CASE_UPDATE, REPORT_GENERATED, etc.
    target_type = Column(String(50), nullable=True)
    target_id = Column(String(100), nullable=True)
    details_json = Column(JSON, nullable=True)
    ip_address = Column(String(100), default="127.0.0.1")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="audit_logs")


class SystemSetting(Base):
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=True)
    description = Column(String(255), nullable=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

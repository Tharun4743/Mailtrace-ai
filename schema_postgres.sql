-- ==============================================================================
-- MAILTRACE AI — POSTGRESQL DATABASE SCHEMA DDL
-- ==============================================================================
-- This SQL script creates all tables, constraints, foreign keys, and indices
-- for the MAILTRACE AI production email threat detection platform.
--
-- Supported PostgreSQL Versions: 12, 13, 14, 15, 16, 17
-- Compatible with: Local PostgreSQL, Docker, AWS RDS, Supabase, Neon, Railway
--
-- NOTE: If using the FastAPI backend, tables are also created automatically
-- on application startup via SQLAlchemy Base.metadata.create_all(bind=engine).
-- ==============================================================================

-- 1. USERS TABLE
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'ANALYST',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_users_id ON users (id);
CREATE INDEX IF NOT EXISTS ix_users_username ON users (username);
CREATE INDEX IF NOT EXISTS ix_users_email ON users (email);


-- 2. OAUTH ACCOUNTS TABLE
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255),
    email VARCHAR(255) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    token_expiry TIMESTAMP WITHOUT TIME ZONE,
    scopes TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    last_sync_at TIMESTAMP WITHOUT TIME ZONE,
    sync_status VARCHAR(50) DEFAULT 'CONNECTED',
    error_message TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_oauth_accounts_id ON oauth_accounts (id);
CREATE INDEX IF NOT EXISTS ix_oauth_accounts_user_id ON oauth_accounts (user_id);


-- 3. MAILBOXES TABLE
CREATE TABLE IF NOT EXISTS mailboxes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    oauth_account_id INTEGER REFERENCES oauth_accounts(id) ON DELETE CASCADE,
    email_address VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    display_name VARCHAR(255),
    sync_status VARCHAR(50) DEFAULT 'IDLE',
    last_sync_at TIMESTAMP WITHOUT TIME ZONE,
    total_emails_analyzed INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_mailboxes_id ON mailboxes (id);
CREATE INDEX IF NOT EXISTS ix_mailboxes_email_address ON mailboxes (email_address);


-- 4. EMAILS TABLE
CREATE TABLE IF NOT EXISTS emails (
    id SERIAL PRIMARY KEY,
    mailbox_id INTEGER REFERENCES mailboxes(id) ON DELETE CASCADE,
    provider_message_id VARCHAR(255),
    provider_thread_id VARCHAR(255),
    sender_display_name VARCHAR(255),
    sender_email VARCHAR(255) NOT NULL,
    sender_domain VARCHAR(255),
    recipient_email VARCHAR(255),
    cc TEXT,
    bcc TEXT,
    reply_to VARCHAR(255),
    return_path VARCHAR(255),
    subject VARCHAR(500),
    date_received TIMESTAMP WITHOUT TIME ZONE,
    body_plain TEXT,
    body_html TEXT,
    raw_headers_json JSONB,
    raw_mime_sha256 VARCHAR(64),
    is_processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_emails_id ON emails (id);
CREATE INDEX IF NOT EXISTS ix_emails_provider_message_id ON emails (provider_message_id);
CREATE INDEX IF NOT EXISTS ix_emails_sender_email ON emails (sender_email);
CREATE INDEX IF NOT EXISTS ix_emails_sender_domain ON emails (sender_domain);
CREATE INDEX IF NOT EXISTS ix_emails_recipient_email ON emails (recipient_email);


-- 5. AUTHENTICATION RESULTS (SPF, DKIM, DMARC)
CREATE TABLE IF NOT EXISTS authentication_results (
    id SERIAL PRIMARY KEY,
    email_id INTEGER NOT NULL UNIQUE REFERENCES emails(id) ON DELETE CASCADE,
    spf_result VARCHAR(50) DEFAULT 'UNKNOWN',
    spf_domain VARCHAR(255),
    spf_ip VARCHAR(100),
    spf_explanation TEXT,
    dkim_result VARCHAR(50) DEFAULT 'UNKNOWN',
    dkim_domain VARCHAR(255),
    dkim_selector VARCHAR(100),
    dkim_explanation TEXT,
    dmarc_result VARCHAR(50) DEFAULT 'UNKNOWN',
    dmarc_policy VARCHAR(50),
    dmarc_spf_aligned BOOLEAN DEFAULT FALSE,
    dmarc_dkim_aligned BOOLEAN DEFAULT FALSE,
    dmarc_explanation TEXT,
    raw_auth_results TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_auth_results_id ON authentication_results (id);
CREATE INDEX IF NOT EXISTS ix_auth_results_email_id ON authentication_results (email_id);


-- 6. EMAIL ANALYSIS & 5-LAYER THREAT SCORES
CREATE TABLE IF NOT EXISTS email_analysis (
    id SERIAL PRIMARY KEY,
    email_id INTEGER NOT NULL UNIQUE REFERENCES emails(id) ON DELETE CASCADE,
    risk_score INTEGER DEFAULT 0,
    severity VARCHAR(50) DEFAULT 'LOW',
    ai_classification VARCHAR(50) DEFAULT 'SAFE',
    ai_confidence FLOAT DEFAULT 0.0,
    ai_reasoning TEXT,
    ai_flags_json JSONB,
    domain_risk_score INTEGER DEFAULT 0,
    domain_flags_json JSONB,
    url_risk_score INTEGER DEFAULT 0,
    url_flags_json JSONB,
    ip_risk_score INTEGER DEFAULT 0,
    observed_sending_ip VARCHAR(100),
    approx_country VARCHAR(100),
    approx_city VARCHAR(100),
    approx_org VARCHAR(255),
    approx_asn VARCHAR(100),
    ip_flags_json JSONB,
    identity_mismatch BOOLEAN DEFAULT FALSE,
    identity_flags_json JSONB,
    threat_intel_summary TEXT,
    risk_reasons_json JSONB,
    relay_hops_json JSONB,
    analyzed_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_email_analysis_id ON email_analysis (id);
CREATE INDEX IF NOT EXISTS ix_email_analysis_email_id ON email_analysis (email_id);
CREATE INDEX IF NOT EXISTS ix_email_analysis_risk_score ON email_analysis (risk_score);
CREATE INDEX IF NOT EXISTS ix_email_analysis_severity ON email_analysis (severity);


-- 7. INDICATORS OF COMPROMISE (IOC)
CREATE TABLE IF NOT EXISTS indicators (
    id SERIAL PRIMARY KEY,
    email_id INTEGER REFERENCES emails(id) ON DELETE CASCADE,
    ioc_type VARCHAR(50) NOT NULL,
    value VARCHAR(500) NOT NULL,
    context VARCHAR(255),
    risk_score INTEGER DEFAULT 0,
    reputation_status VARCHAR(50) DEFAULT 'UNAVAILABLE',
    threat_intel_data_json JSONB,
    is_malicious BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_indicators_id ON indicators (id);
CREATE INDEX IF NOT EXISTS ix_indicators_ioc_type ON indicators (ioc_type);
CREATE INDEX IF NOT EXISTS ix_indicators_value ON indicators (value);


-- 8. THREAT CAMPAIGNS
CREATE TABLE IF NOT EXISTS campaigns (
    id SERIAL PRIMARY KEY,
    campaign_identifier VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    threat_type VARCHAR(100) DEFAULT 'CREDENTIAL_PHISHING',
    confidence VARCHAR(50) DEFAULT 'HIGH',
    shared_domain VARCHAR(255),
    shared_ip VARCHAR(100),
    shared_url_pattern VARCHAR(500),
    first_seen TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    total_emails INTEGER DEFAULT 1,
    indicators_json JSONB,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_campaigns_id ON campaigns (id);
CREATE INDEX IF NOT EXISTS ix_campaigns_identifier ON campaigns (campaign_identifier);


-- 9. CAMPAIGN MEMBERS
CREATE TABLE IF NOT EXISTS campaign_members (
    id SERIAL PRIMARY KEY,
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    matched_indicators_json JSONB,
    matched_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_campaign_members_id ON campaign_members (id);


-- 10. FORENSIC CASES
CREATE TABLE IF NOT EXISTS cases (
    id SERIAL PRIMARY KEY,
    case_number VARCHAR(50) UNIQUE NOT NULL,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'OPEN',
    priority VARCHAR(50) DEFAULT 'HIGH',
    assigned_to VARCHAR(255),
    analyst_notes TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_cases_id ON cases (id);
CREATE INDEX IF NOT EXISTS ix_cases_number ON cases (case_number);


-- 11. EVIDENCE LOCKER (TAMPER-PROOF SHA256 & BLOCKCHAIN)
CREATE TABLE IF NOT EXISTS evidence (
    id SERIAL PRIMARY KEY,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    evidence_identifier VARCHAR(100) UNIQUE NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    source VARCHAR(100) DEFAULT 'OAUTH_INGESTION',
    original_size_bytes INTEGER DEFAULT 0,
    is_verified BOOLEAN DEFAULT TRUE,
    blockchain_anchor_hash VARCHAR(128),
    blockchain_status VARCHAR(100) DEFAULT 'Evidence hash recorded locally',
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_evidence_id ON evidence (id);
CREATE INDEX IF NOT EXISTS ix_evidence_identifier ON evidence (evidence_identifier);


-- 12. REAL-TIME THREAT ALERTS
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(50) DEFAULT 'HIGH',
    risk_score INTEGER DEFAULT 80,
    message TEXT,
    major_reasons_json JSONB,
    is_read BOOLEAN DEFAULT FALSE,
    is_acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(255),
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_alerts_id ON alerts (id);
CREATE INDEX IF NOT EXISTS ix_alerts_email_id ON alerts (email_id);


-- 13. FORENSIC PDF REPORTS
CREATE TABLE IF NOT EXISTS forensic_reports (
    id SERIAL PRIMARY KEY,
    case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    report_identifier VARCHAR(100) UNIQUE NOT NULL,
    generated_by VARCHAR(255) DEFAULT 'System Analyst',
    pdf_filename VARCHAR(255),
    summary TEXT,
    report_metadata_json JSONB,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_forensic_reports_id ON forensic_reports (id);
CREATE INDEX IF NOT EXISTS ix_forensic_reports_identifier ON forensic_reports (report_identifier);


-- 14. AUDIT LOGS
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(100),
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50),
    target_id VARCHAR(100),
    details_json JSONB,
    ip_address VARCHAR(100) DEFAULT '127.0.0.1',
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_audit_logs_id ON audit_logs (id);


-- 15. SYSTEM SETTINGS
CREATE TABLE IF NOT EXISTS system_settings (
    id SERIAL PRIMARY KEY,
    key VARCHAR(100) UNIQUE NOT NULL,
    value TEXT,
    description VARCHAR(255),
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_system_settings_id ON system_settings (id);
CREATE INDEX IF NOT EXISTS ix_system_settings_key ON system_settings (key);


-- ==============================================================================
-- DEFAULT INITIAL USERS SEED (ADMIN & ANALYST)
-- Password for admin: Admin@12345
-- Password for analyst: Analyst@12345
-- ==============================================================================
INSERT INTO users (username, email, hashed_password, full_name, role, is_active)
VALUES 
    ('admin', 'admin@mailtrace.ai', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'SOC Lead Administrator', 'ADMIN', true),
    ('analyst', 'analyst@mailtrace.ai', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'Senior Forensic Analyst', 'ANALYST', true)
ON CONFLICT (username) DO NOTHING;

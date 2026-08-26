# 🛡️ MAILTRACE AI — Production Email Threat Detection & Real-Time Defense Platform

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-12--17-336791.svg?style=for-the-badge&logo=postgresql)](https://postgresql.org)
[![React + Vite](https://img.shields.io/badge/React%2018-Vite%20%2B%20TS-61DAFB.svg?style=for-the-badge&logo=react)](https://vitejs.dev)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-CSS%203.4-38B2AC.svg?style=for-the-badge&logo=tailwind-css)](https://tailwindcss.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

**MAILTRACE AI** is an enterprise-grade AI and deterministic email security platform. It provides automated mailbox synchronization (via Google Workspace and Microsoft 365 OAuth 2.0), deep multi-vector email threat analysis (SPF, DKIM, DMARC, ML Phishing NLP, Lookalike Domain Typosquatting, URL Destination Inspecting, Attachment Sandboxing), real-time alerts across web and mobile, and a SOC-grade threat investigation dashboard with courtroom-admissible PDF forensic reports.

---

## 📑 Table of Contents

1. [System Architecture](#-system-architecture)
2. [Detailed End-to-End Workflow](#-detailed-end-to-end-workflow)
3. [5-Layer Threat Detection & Risk Scoring](#-5-layer-threat-detection--risk-scoring)
4. [🐘 PostgreSQL Database & Automatic Table Creation](#-postgresql-database--automatic-table-creation)
   - [How Automatic Table Creation Works](#1-how-automatic-table-creation-works)
   - [PostgreSQL Connection String Formats](#2-postgresql-connection-string-formats)
   - [One-Command Database Initialization CLI](#3-one-command-database-initialization-cli)
   - [Raw PostgreSQL DDL Schema Script](#4-raw-postgresql-ddl-schema-script)
5. [Step-by-Step Environment Variable Guide](#-step-by-step-environment-variable-guide)
   - [Core Application & JWT Security](#1-core-application--jwt-security)
   - [Google Workspace / Gmail OAuth 2.0](#2-google-workspace--gmail-oauth-20-setup)
   - [Microsoft 365 / Azure AD OAuth 2.0](#3-microsoft-365--azure-ad-oauth-20-setup)
   - [Threat Intelligence Feeds (VirusTotal, AbuseIPDB, AlienVault OTX)](#4-threat-intelligence-feeds-optional)
   - [Real-Time Notifications (Mobile Webhook & SMTP)](#5-real-time-notifications-mobile-webhook--smtp)
   - [GeoIP & ASN Lookup](#6-maxmind-geoip--asn-intelligence)
   - [Blockchain Evidence Anchoring](#7-blockchain-evidence-anchoring-optional)
6. [Installation & Setup Guide](#-installation--setup-guide)
   - [Prerequisites](#prerequisites)
   - [Backend Installation](#backend-installation)
   - [Frontend Installation](#frontend-installation)
   - [Default Accounts & Role-Based Access Control (RBAC)](#default-accounts--role-based-access-control-rbac)
7. [API & WebSocket Specifications](#-api--websocket-specifications)
8. [Troubleshooting & Common Issues](#-troubleshooting--common-issues)

---

## 🏗️ System Architecture

```
                                  MAILTRACE AI PLATFORM
                                            │
                     ┌──────────────────────┴──────────────────────┐
                     │                                             │
            EXTERNAL MAILBOXES                             CLIENT DASHBOARDS
      (Google Workspace / MS 365)                    (React 18 + Tailwind + Lucide)
                     │                                             │
      OAuth 2.0 Token Exchange                              JWT Auth + Role RBAC
                     │                                             │
                     ▼                                             ▼
        ┌─────────────────────────┐                   ┌─────────────────────────┐
        │  FASTAPI BACKEND CORE   │ ◄──WebSocket WebSocket Push Notification   │
        │  (Async Python Engine)  │                   │ (Browser Desktop + App) │
        └────────────┬────────────┘                   └─────────────────────────┘
                     │
        ┌────────────┴────────────────────────┬────────────────────────┐
        ▼                                     ▼                        ▼
┌───────────────────┐               ┌───────────────────┐    ┌───────────────────┐
│ BACKGROUND WORKER │               │ 5-LAYER DETECTOR  │    │  FORENSIC REPORTS │
│ • 25s Poll Cycle  │ ──► MIME ──►  │ • Sender & Brand  │──► │ • Courtroom PDF   │
│ • Deduping Engine │     Parsing   │ • SPF/DKIM/DMARC  │    │ • IOC CSV Export  │
│ • Token Auto-Sync │               │ • NLP Phishing ML │    │ • Evidence SHA256 │
└───────────────────┘               │ • URL Analyzer    │    └───────────────────┘
                                    │ • Attachment Risk │
                                    └───────────────────┘
```

---

## ⚡ Detailed End-to-End Workflow

```
[1. User Registration & Sign In]
               │
               ▼
[2. Connect Mailbox via OAuth 2.0] (Gmail or Outlook 365)
               │ (Passwords are never stored; read-only tokens utilized)
               ▼
[3. Ingestion & Deduplication] (Background worker polls mailboxes & parses MIME)
               │
               ▼
[4. 5-Layer Deterministic & ML Threat Engine]
   ├─► 1. Sender & Domain Analysis (Typosquatting, lookalike unicode, Brand impersonation)
   ├─► 2. Authentication Integrity (Live DNS lookup for SPF, DKIM, DMARC alignment)
   ├─► 3. Content NLP & Intent (Phishing ML classifier, urgency, credential harvesting)
   ├─► 4. Link & URL Engine (Deceptive subdomains, IP hosts, VirusTotal scan)
   └─► 5. Attachment Scanner (Dangerous executables, macro files, double extensions)
               │
               ▼
[5. Risk Calculation & Classification (0–100 Score)]
   ├─ 🟢 Safe (0–29)            -> ✅ Safe to open
   ├─ 🟠 Suspicious (30–69)     -> ⚠️ Warning Banner attached
   ├─ 🔴 High Risk (70–89)      -> 🚫 Flagged Dangerous (Do not open)
   └─ 🚨 Critical (90–100)      -> 🚨 Quarantined & High-Priority Alert
               │
               ▼
[6. Instant Real-Time Alert Dispatch]
   ├─► WebSocket broadcast to active frontend sessions
   ├─► HTML5 Native Browser Push Notification
   ├─► Mobile Push Notification Gateway (Webhook)
   └─► Security Alert Email (SMTP)
               │
               ▼
[7. Analyst Investigation & Response]
   ├─► Deep-dive header inspection & geo-ip mapping
   ├─► AI summary & recommended triage actions
   ├─► One-click Courtroom/SOC Forensic PDF Report Generation
   └─► Export Indicators of Compromise (IOC)
```

### Detailed Workflow Stages:

1. **User Authentication & Session Management**:
   - Users authenticate using secure JWT (JSON Web Tokens) with Argon2/Bcrypt password hashing.
   - Built-in Role-Based Access Control (RBAC): `ADMIN`, `ANALYST`, and `USER`.

2. **Zero-Knowledge OAuth 2.0 Mailbox Linking**:
   - In **Settings -> Connect Mailbox**, the user initiates an OAuth 2.0 consent flow with Google or Microsoft.
   - The user grants strictly `read-only` email access (`gmail.readonly` or `Mail.Read`).
   - Access and refresh tokens are securely stored. Raw mailbox passwords are never requested or stored.

3. **Autonomous Ingestion & Deduplication Engine**:
   - The `MailboxMonitorWorker` executes every 25 seconds in an asynchronous background event loop.
   - Fetches recent incoming emails via Gmail REST API or Microsoft Graph API.
   - Emails are checked against `provider_message_id` and raw message body hashes to prevent duplicate ingestion.

4. **Multi-Vector Risk Analysis Pipeline**:
   - Extracts sender domain, headers, `Authentication-Results`, `Received-SPF`, `DKIM-Signature`, URLs, and attachments.
   - Executes DNS lookups against SPF TXT records, DKIM public keys, and `_dmarc.<domain>` records.
   - Feeds the subject and body to the NLP Phishing Classifier (Scikit-Learn TF-IDF + Logistic Regression).
   - Scans URLs and attachment extensions for high-risk malware patterns.

5. **Real-Time Notification & Alert Broadcast**:
   - If an email scores $\ge 30$, an `Alert` entity is committed.
   - Emits a WebSocket payload to all active client browsers.
   - If `MOBILE_PUSH_WEBHOOK_URL` is set, transmits an encrypted payload to the push gateway.
   - Triggers desktop browser notifications via Web Notifications API.

6. **SOC Deep Dive & Courtroom Forensic Export**:
   - Security analysts inspect exact threat signals, geographical origin, IP ASN, raw headers, and evidence hashes.
   - Generates a PDF Forensic Report adhering to digital forensic chain-of-custody standards with evidence SHA-256 hashes.

---

## 🎯 5-Layer Threat Detection & Risk Scoring

Total Risk Score ranges from **0 to 100 points**:

| Layer | Assessment Focus | Max Points | Threat Indicators Evaluated |
| :--- | :--- | :---: | :--- |
| **1. Sender & Domain** | Lookalike / Spoofing / Impersonation | **20** | Brand impersonation (e.g. PayPal mention from external domain), Typosquatting (`micros0ft.com`, `paypa1.com`), High-risk suspicious TLDs (`.xyz`, `.buzz`, `.top`, `.tk`, etc.), Display name mismatch. |
| **2. Authentication** | SPF / DKIM / DMARC | **15** | `SPF: Fail/Softfail`, `DKIM: Fail/Invalid`, `DMARC: Fail/Reject/Quarantine`, Sender domain alignment failure. |
| **3. Content NLP** | Semantic Phishing & Social Engineering | **25** | ML Phishing Model probability score, Urgency & Coercion triggers ("immediate account suspension"), Credential harvesting lures ("verify password now"), Business Email Compromise (BEC) / Wire transfer patterns. |
| **4. URL & Link Engine** | Malicious Link & Redirection Analysis | **20** | Raw IP addresses used in links (`http://192.168.1.1/login`), deceptive link paths, credential capture query params, VirusTotal & AbuseIPDB threat match. |
| **5. Attachment Safety** | Malware & Payload Inspection | **20** | Dangerous executable extensions (`.exe`, `.scr`, `.bat`, `.vbs`, `.iso`, `.hta`), Macro-enabled office docs (`.docm`, `.xlsm`), Suspicious archives (`.zip`), Double extensions (`invoice.pdf.exe`). |

---

## 🐘 PostgreSQL Database & Automatic Table Creation

### 1. How Automatic Table Creation Works

Whenever you start the backend server (`uvicorn app.main:app`) or configure your PostgreSQL connection string in `.env`, **FastAPI and SQLAlchemy automatically connect to PostgreSQL and create all 15 tables, constraints, foreign keys, and indexes if they do not already exist.**

In addition, it automatically seeds the initial `ADMIN` (`admin` / `Admin@12345`) and `ANALYST` (`analyst` / `Analyst@12345`) accounts.

### 2. PostgreSQL Connection String Formats

Set `DATABASE_URL` in your `.env`:

```ini
# --- Local PostgreSQL ---
DATABASE_URL="postgresql://postgres:your_password@localhost:5432/mailtrace"

# --- Docker PostgreSQL ---
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/mailtrace"

# --- Supabase PostgreSQL ---
DATABASE_URL="postgresql://postgres.yourproject:your_password@aws-0-us-east-1.pooler.supabase.com:5432/postgres"

# --- Neon.tech Serverless PostgreSQL ---
DATABASE_URL="postgresql://your_user:your_password@ep-cool-snowflake-123456.us-east-2.aws.neon.tech/neondb?sslmode=require"

# --- AWS RDS / Azure Database for PostgreSQL ---
DATABASE_URL="postgresql://dbadmin:your_secure_password@mailtrace-db.c7xxxx.rds.amazonaws.com:5432/mailtrace"
```

> [!NOTE]
> If your provider uses `postgres://` (legacy scheme), MailTrace AI automatically normalizes it to `postgresql://` so no syntax errors occur.

---

### 3. One-Command Database Initialization CLI

To test your PostgreSQL connection, create all tables, and seed initial accounts from the terminal:

```bash
cd backend
python init_db.py
```

Output:
```
=================================================================
  MAILTRACE AI — Database Initialization (PostgreSQL)
=================================================================
Target Database URL: localhost:5432/mailtrace

✅ Database connection verified successfully.
Creating all tables if they do not exist...
✅ All 15 database tables created / verified successfully.
Seeding initial security administrator and analyst accounts...
✅ Default accounts ready: 'admin' and 'analyst'.

🎉 Database setup complete! You can now start the FastAPI server.
=================================================================
```

---

### 4. Raw PostgreSQL DDL Schema Script

If you prefer to run raw SQL queries directly in **pgAdmin**, **DBeaver**, **psql**, or the **Supabase SQL Editor**, execute the script located at [`schema_postgres.sql`](file:///c:/Users/tharu/Downloads/MAILSPAM/schema_postgres.sql):

```sql
-- ==============================================================================
-- MAILTRACE AI — POSTGRESQL TABLE CREATION DDL QUERIES
-- ==============================================================================

-- 1. USERS
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
CREATE INDEX IF NOT EXISTS ix_users_username ON users (username);
CREATE INDEX IF NOT EXISTS ix_users_email ON users (email);

-- 2. OAUTH ACCOUNTS
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

-- 3. MAILBOXES
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
CREATE INDEX IF NOT EXISTS ix_mailboxes_email_address ON mailboxes (email_address);

-- 4. EMAILS
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
CREATE INDEX IF NOT EXISTS ix_emails_provider_message_id ON emails (provider_message_id);
CREATE INDEX IF NOT EXISTS ix_emails_sender_email ON emails (sender_email);

-- 5. AUTHENTICATION RESULTS
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

-- 6. EMAIL ANALYSIS & 5-LAYER SCORES
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

-- 7. INDICATORS (IOC)
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

-- 8. THREAT CAMPAIGNS & MEMBERS
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

CREATE TABLE IF NOT EXISTS campaign_members (
    id SERIAL PRIMARY KEY,
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    email_id INTEGER NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    matched_indicators_json JSONB,
    matched_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 9. FORENSIC CASES
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

-- 10. EVIDENCE LOCKER
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

-- 11. REAL-TIME THREAT ALERTS
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

-- 12. FORENSIC PDF REPORTS
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

-- 13. AUDIT LOGS
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

-- 14. SYSTEM SETTINGS
CREATE TABLE IF NOT EXISTS system_settings (
    id SERIAL PRIMARY KEY,
    key VARCHAR(100) UNIQUE NOT NULL,
    value TEXT,
    description VARCHAR(255),
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 15. DEFAULT SEED DATA
INSERT INTO users (username, email, hashed_password, full_name, role, is_active)
VALUES 
    ('admin', 'admin@mailtrace.ai', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'SOC Lead Administrator', 'ADMIN', true),
    ('analyst', 'analyst@mailtrace.ai', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', 'Senior Forensic Analyst', 'ANALYST', true)
ON CONFLICT (username) DO NOTHING;
```

---

## 🔒 Step-by-Step Environment Variable Guide

Create a `.env` file in the root folder (or `backend/.env`) by copying `.env.example`:

```bash
cp .env.example .env
```

---

### 1. Core Application & JWT Security

| Variable | Type | Example | Description |
| :--- | :--- | :--- | :--- |
| `PROJECT_NAME` | String | `"MAILTRACE AI"` | Name displayed across reports and headers. |
| `VERSION` | String | `"2.0.0"` | Current platform release version. |
| `ENVIRONMENT` | String | `"development"` or `"production"` | Runtime environment mode. |
| `JWT_SECRET` | String | *See below* | Cryptographic key used to sign and verify session JWTs. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Integer | `1440` | Token expiration duration (1440 min = 24 hours). |

#### 🔑 How to Generate a Secure `JWT_SECRET`:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

### 2. Google Workspace / Gmail OAuth 2.0 Setup

Allows users to connect their Gmail / Google Workspace inbox with zero-knowledge OAuth.

| Variable | Value / Format | Description |
| :--- | :--- | :--- |
| `GOOGLE_CLIENT_ID` | `xxxx-xxxx.apps.googleusercontent.com` | Google OAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | `GOCSPX-xxxxxxxxxxxx` | Google OAuth Client Secret |
| `GOOGLE_REDIRECT_URI` | `http://localhost:5173/auth/google/callback` | Callback URL handled by frontend router |

#### 📋 How to Obtain Google OAuth Credentials:

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project named **MailTrace AI**.
3. Navigate to **APIs & Services** > **Library**, search for **Gmail API** and click **Enable**.
4. Navigate to **APIs & Services** > **OAuth consent screen**:
   - Select **External** (or **Internal** if using Google Workspace organization).
   - Scopes: `gmail.readonly`, `userinfo.email`, `userinfo.profile`, `openid`.
   - Add your personal/testing email under **Test Users**.
5. Navigate to **APIs & Services** > **Credentials**:
   - Click **Create Credentials** > **OAuth client ID** (Application type: **Web application**).
   - **Authorized JavaScript origins**: `http://localhost:5173`
   - **Authorized redirect URIs**: `http://localhost:5173/auth/google/callback` and `http://localhost:8000/api/v1/oauth/google/callback`.
6. Copy the **Client ID** and **Client Secret** into your `.env`.

---

### 3. Microsoft 365 / Azure AD OAuth 2.0 Setup

Allows users to connect Microsoft 365, Outlook.com, and Hotmail mailboxes.

| Variable | Value / Format | Description |
| :--- | :--- | :--- |
| `MICROSOFT_CLIENT_ID` | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | Azure Application (client) ID |
| `MICROSOFT_CLIENT_SECRET` | `xxxxxxxxxxxxxxxxxxxxxxxx` | Azure Client Secret Value |
| `MICROSOFT_REDIRECT_URI` | `http://localhost:5173/auth/microsoft/callback` | Callback URL handled by frontend |

#### 📋 How to Obtain Microsoft Azure Credentials:

1. Sign in to the [Microsoft Entra Admin Center](https://entra.microsoft.com/) or [Azure Portal](https://portal.azure.com/).
2. Navigate to **Identity** > **Applications** > **App registrations** > **New registration**.
3. Supported account types: **Multitenant and personal Microsoft accounts**.
4. Redirect URI: Platform **Web**, URI: `http://localhost:5173/auth/microsoft/callback`.
5. Under **API Permissions**, add Delegated `Microsoft Graph`: `Mail.Read`, `User.Read`, `offline_access`, `openid`, `profile`, `email`.
6. Under **Certificates & secrets**, create a **New client secret** and copy the **Value** into `.env`.

---

### 4. Threat Intelligence Feeds (Optional)

| Variable | Description | Where to get it |
| :--- | :--- | :--- |
| `VIRUSTOTAL_API_KEY` | Scans links & attachments against 70+ antivirus engines | [VirusTotal API Signup](https://www.virustotal.com/gui/join-us) -> Profile -> API Key |
| `ABUSEIPDB_API_KEY` | Malicious sender IP reputation lookup | [AbuseIPDB Free Key](https://www.abuseipdb.com/account/api) -> Create Key |
| `ALIENVAULT_OTX_KEY` | Real-time threat pulses & IP IOC indicators | [AlienVault OTX Signup](https://otx.alienvault.com/api) -> Direct OTX Key |

---

### 5. Real-Time Notifications (Mobile Webhook & SMTP)

| Variable | Example | Description |
| :--- | :--- | :--- |
| `MOBILE_PUSH_WEBHOOK_URL` | `https://webhook.site/...` or Discord/Slack Webhook URL | Webhook endpoint triggered on High/Critical risk threat detection. |
| `SMTP_HOST` | `smtp.gmail.com` | Outgoing SMTP mail server for security alerts. |
| `SMTP_PORT` | `587` | Outgoing SMTP TLS port. |
| `SMTP_USERNAME` | `alerts@mailtrace.ai` | SMTP authentication user. |
| `SMTP_PASSWORD` | `xxxx xxxx xxxx xxxx` | 16-character Google App Password. |
| `SMTP_FROM_EMAIL` | `no-reply@mailtrace.ai` | From address header for dispatched alerts. |

---

### 6. MaxMind GeoIP & ASN Intelligence

| Variable | Default Path | Description |
| :--- | :--- | :--- |
| `GEOIP_DATABASE_PATH` | `./data/GeoLite2-City.mmdb` | MaxMind GeoLite2 City binary database |
| `GEOIP_ASN_DATABASE_PATH` | `./data/GeoLite2-ASN.mmdb` | MaxMind GeoLite2 ASN binary database |

---

### 7. Blockchain Evidence Anchoring (Optional)

```ini
BLOCKCHAIN_ENABLED=false
BLOCKCHAIN_RPC_URL="https://polygon-mumbai.g.alchemy.com/v2/YOUR_API_KEY"
BLOCKCHAIN_NETWORK="polygon_mumbai"
BLOCKCHAIN_PRIVATE_KEY=""
```

---

## 🚀 Installation & Setup Guide

### ⚡ 1-Click Quickstart (Windows)

Simply double-click **`run.bat`** (or run it from terminal):

```cmd
run.bat
```

What `run.bat` does automatically:
1. Verifies Python 3.10+ and Node.js 18+ installations.
2. Creates `.env` from `.env.example` if not present.
3. Sets up Python virtual environment (`backend\venv`) and installs backend dependencies.
4. Initializes the database (PostgreSQL / SQLite) and auto-creates all 15 tables with default `admin` and `analyst` accounts.
5. Installs frontend packages (`npm install`).
6. Starts FastAPI backend on `http://localhost:8000` and Vite frontend on `http://localhost:5173` in dedicated windows.
7. Automatically opens your default web browser to the dashboard.

To gracefully stop all services at once, run:
```cmd
stop.bat
```

---

### Prerequisites (Manual Setup)
- **Python 3.10+**
- **Node.js 18+** & `npm`
- **PostgreSQL 12+** (or SQLite)

---

### Backend Installation (Manual)

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create and activate a Virtual Environment:
   ```bash
   # Windows (PowerShell):
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS:
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies (including PostgreSQL drivers):
   ```bash
   pip install -r requirements.txt
   ```

4. Initialize the PostgreSQL database & auto-create tables:
   ```bash
   python init_db.py
   ```

5. Start the FastAPI backend server:
   ```bash
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

Backend is live at: `http://localhost:8000`  
Interactive Swagger Docs: `http://localhost:8000/docs`  
Health Check: `http://localhost:8000/health`

---

### Frontend Installation

1. Open a new terminal and navigate to `frontend`:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

Frontend application is running at: `http://localhost:5173`

---

### Default Accounts & Role-Based Access Control (RBAC)

| Role | Username | Email | Default Password | Permissions |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `admin@mailtrace.ai` | `Admin@12345` | Full system access, audit logs, user management, mailbox sync. |
| **Forensic Analyst** | `analyst` | `analyst@mailtrace.ai` | `Analyst@12345` | Threat triage, forensic PDF exports, IOC investigations. |

---

## 📡 API & WebSocket Specifications

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/auth/register` | Register new user account. |
| `POST` | `/api/v1/auth/login` | Authenticate & receive JWT access token. |
| `GET` | `/api/v1/auth/me` | Retrieve authenticated user profile. |
| `GET` | `/api/v1/emails/` | List analyzed emails with pagination and threat filters. |
| `GET` | `/api/v1/emails/{id}` | Deep forensic breakdown of a specific email. |
| `POST` | `/api/v1/emails/scan-raw` | Scan a raw MIME `.eml` or RFC822 email on-demand. |
| `GET` | `/api/v1/oauth/google/init` | Initiate Google Workspace OAuth flow. |
| `POST` | `/api/v1/oauth/google/callback` | Complete Google OAuth & sync initial 20 emails. |
| `GET` | `/api/v1/oauth/microsoft/init` | Initiate Microsoft 365 OAuth flow. |
| `POST` | `/api/v1/oauth/microsoft/callback`| Complete Microsoft OAuth & sync initial 20 emails. |
| `GET` | `/api/v1/reports/forensic-pdf/{id}`| Generate and download official Courtroom/SOC Forensic PDF Report. |
| `GET` | `/api/v1/stats/overview` | Platform metrics (total scanned, threat score distributions, attack vectors). |
| `GET` | `/health` | Real-time system health check (DB, background worker, mailboxes). |
| `WS` | `/api/v1/ws` | Live WebSocket stream broadcasting instant threat alerts. |

---

## 🛠️ Troubleshooting & Common Issues

### 1. `Google OAuth Error: redirect_uri_mismatch`
- **Fix**: In Google Cloud Console -> **Credentials** -> Click your OAuth Client -> Add `http://localhost:5173/auth/google/callback` to **Authorized Redirect URIs**.

### 2. `Google OAuth Error: Access Blocked (App has not completed verification)`
- **Fix**: Add your Gmail address under Google Cloud Console -> **OAuth consent screen** -> **Test Users**.

### 3. PostgreSQL Connection Refused
- **Fix**: Verify PostgreSQL service is running (`systemctl status postgresql` or Windows Services). Ensure username, password, host, port (5432), and database name match `DATABASE_URL` in `.env`.

### 4. CORS Error in Browser Console
- **Fix**: Ensure `ALLOWED_ORIGINS="http://localhost:5173"` in `.env` and `FRONTEND_URL="http://localhost:5173"`.

---

## 📜 License

Licensed under the **MIT License**.

export interface User {
  id: number;
  username: string;
  email: string;
  full_name?: string;
  role: 'ADMIN' | 'ANALYST' | 'VIEWER';
  is_active: boolean;
  created_at: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user_id: number;
  username: string;
  role: 'ADMIN' | 'ANALYST' | 'VIEWER';
  full_name?: string;
}

export interface ConnectedAccount {
  id: number;
  provider: 'google' | 'microsoft';
  email: string;
  is_active: boolean;
  sync_status: 'CONNECTED' | 'SYNCING' | 'ERROR' | 'DISCONNECTED';
  last_sync_at?: string;
  error_message?: string;
  total_emails_analyzed: number;
  created_at: string;
}

export interface Mailbox {
  id: number;
  email_address: string;
  provider: string;
  display_name?: string;
  sync_status: 'IDLE' | 'SYNCING' | 'SUCCESS' | 'ERROR';
  last_sync_at?: string;
  total_emails_analyzed: number;
  is_active: boolean;
}

export interface AuthenticationResult {
  spf_result: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE' | 'TEMPERROR' | 'PERMERROR' | 'UNKNOWN';
  spf_domain?: string;
  spf_ip?: string;
  spf_explanation?: string;
  dkim_result: 'PASS' | 'FAIL' | 'NONE' | 'UNKNOWN';
  dkim_domain?: string;
  dkim_selector?: string;
  dkim_explanation?: string;
  dmarc_result: 'PASS' | 'FAIL' | 'NONE' | 'UNKNOWN';
  dmarc_policy?: string;
  dmarc_spf_aligned: boolean;
  dmarc_dkim_aligned: boolean;
  dmarc_explanation?: string;
}

export interface RiskReason {
  category: string;
  points: number;
  description: string;
}

export interface EmailAnalysis {
  risk_score: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  ai_classification: 'SAFE' | 'SUSPICIOUS' | 'PHISHING' | 'BEC' | 'MALWARE' | 'CREDENTIAL_THEFT' | 'OTHER';
  ai_confidence: number;
  ai_reasoning?: string;
  ai_flags_json?: Array<{ category: string; matched_pattern: string; count: number; description: string }>;
  domain_risk_score: number;
  domain_flags_json?: Array<{ type: string; severity: string; description: string }>;
  url_risk_score: number;
  url_flags_json?: Array<{ type: string; severity?: string; description: string }>;
  ip_risk_score: number;
  observed_sending_ip?: string;
  approx_country?: string;
  approx_city?: string;
  approx_org?: string;
  approx_asn?: string;
  identity_mismatch: boolean;
  identity_flags_json?: Array<{ type: string; severity: string; description: string }>;
  threat_intel_summary?: string;
  risk_reasons_json?: RiskReason[];
  analyzed_at?: string;
}

export interface Indicator {
  id: number;
  email_id?: number;
  ioc_type: 'IP' | 'DOMAIN' | 'URL' | 'HASH';
  value: string;
  context?: string;
  risk_score: number;
  reputation_status: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNAVAILABLE';
  is_malicious: boolean;
  created_at: string;
}

export interface EvidenceRecord {
  id: number;
  evidence_identifier: string;
  sha256_hash: string;
  source: string;
  original_size_bytes: number;
  is_verified: boolean;
  blockchain_anchor_hash?: string;
  blockchain_status: string;
  created_at: string;
}

export interface EmailListItem {
  id: number;
  mailbox_id?: number;
  sender_display_name?: string;
  sender_email: string;
  sender_domain?: string;
  recipient_email?: string;
  subject?: string;
  date_received?: string;
  risk_score: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  ai_classification: string;
  is_processed: boolean;
}

export interface EmailDetail extends EmailListItem {
  provider_message_id?: string;
  cc?: string;
  reply_to?: string;
  return_path?: string;
  body_plain?: string;
  body_html?: string;
  raw_headers_json?: Record<string, any>;
  raw_mime_sha256?: string;
  authentication_result?: AuthenticationResult;
  analysis?: EmailAnalysis;
  indicators: Indicator[];
  evidence_records: EvidenceRecord[];
}

export interface Alert {
  id: number;
  email_id: number;
  title: string;
  severity: 'HIGH' | 'CRITICAL';
  risk_score: number;
  message?: string;
  major_reasons_json?: string[];
  is_read: boolean;
  is_acknowledged: boolean;
  acknowledged_by?: string;
  created_at: string;
}

export interface ForensicReport {
  id: number;
  email_id: number;
  report_identifier: string;
  generated_by: string;
  pdf_filename?: string;
  summary?: string;
  report_metadata_json?: Record<string, any>;
  created_at: string;
}

export interface DashboardStats {
  total_analyzed: number;
  safe_count: number;
  suspicious_count: number;
  high_risk_count: number;
  critical_count: number;
  total_iocs_count: number;
  threat_trends: Array<{ date: string; threats: number; safe: number; total: number }>;
  risk_distribution: Array<{ name: string; count: number; color: string }>;
  top_malicious_domains: Array<{ domain: string; count: number }>;
  top_suspicious_ips: Array<{ ip: string; count: number }>;
  recent_alerts: Alert[];
}

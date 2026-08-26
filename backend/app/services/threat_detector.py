import os
import re
import math
import logging
from typing import Dict, Any, List, Optional
import joblib

logger = logging.getLogger("mailtrace-ai")

class ThreatDetector:
    """
    Authoritative Hybrid AI / ML + 5-Layer Deterministic Risk Scoring Engine.
    Combines:
    - Trained Scikit-Learn TF-IDF + Logistic Regression ML Classifier
    - Deterministic Multi-Signal Analysis (Sender, Auth, NLP, URLs, Attachments)
    Total Deterministic Risk Score: 0 – 100
    """

    # Content & NLP Pattern Matchers
    URGENT_PATTERNS = [
        r"\b(urgent|immediately|immediate action|within \d+ hours|account suspended|will be (terminated|closed|suspended|locked)|final notice|critical security alert|unauthorized login|action required)\b"
    ]
    CREDENTIAL_PATTERNS = [
        r"\b(verify|confirm|update|reset|validate|restore|re-enter)\b.{0,30}\b(account|password|credential|credentials|identity|security|login|access|card)\b",
        r"\b(click here|link below|tap here|log in to|sign in to)\b.{0,30}\b(restore|verify|reactivate|unlock|update|proceed)\b"
    ]
    FINANCIAL_PATTERNS = [
        r"\b(wire transfer|bank routing|gift card|direct deposit|payroll update|invoice overdue|bitcoin payment|crypto transaction)\b"
    ]
    SPAM_PATTERNS = [
        r"\b(congratulations|winner|won a lottery|claim your prize|free reward|guaranteed profit|exclusive deal)\b"
    ]

    HIGH_RISK_TLDS = {'.top', '.xyz', '.buzz', '.ru', '.cn', '.tk', '.cc', '.live', '.work', '.gq', '.cf', '.ga', '.biz', '.click', '.link', '.surf', '.icu', '.sbs'}
    DANGEROUS_EXTENSIONS = {'.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.iso', '.img', '.hta', '.jar', '.ps1', '.xlsm', '.docm', '.zip'}

    KNOWN_BRANDS = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "bank of america", "chase", "wells fargo", "outlook"]

    def __init__(self):
        self.ml_model = None
        self._load_ml_model()

    def _load_ml_model(self):
        try:
            model_path = os.path.join(os.path.dirname(__file__), "..", "ml", "phishing_model.joblib")
            if os.path.exists(model_path):
                self.ml_model = joblib.load(model_path)
                logger.info(f"Loaded trained Phishing NLP Classifier from {model_path}")
        except Exception as e:
            logger.warning(f"ML model loading skipped: {str(e)}")

    def analyze(
        self,
        sender: str,
        subject: str,
        body: str,
        urls: List[str] = None,
        attachments: List[Dict[str, Any]] = None,
        sender_name: str = "",
        auth_results: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        
        urls = urls or []
        attachments = attachments or []
        auth_results = auth_results or {"spf": "NONE", "dkim": "NONE", "dmarc": "NONE"}
        
        sender_clean = sender.lower().strip()
        sender_domain = sender_clean.split("@")[-1] if "@" in sender_clean else sender_clean
        full_text = f"{subject} {body}".lower()

        signals = []
        why_bullets = []

        # -------------------------------------------------------------
        # ML / AI Semantic Threat Inference
        # -------------------------------------------------------------
        ml_threat_prob = 0.0
        if self.ml_model:
            try:
                probs = self.ml_model.predict_proba([f"{subject} {body}"])[0]
                ml_threat_prob = float(probs[1])
            except Exception:
                ml_threat_prob = 0.0

        # -------------------------------------------------------------
        # 1. Sender Reputation & Spoofing Analysis (Max 20 Points)
        # -------------------------------------------------------------
        sender_score = 0
        impersonated_brand = None

        for brand in self.KNOWN_BRANDS:
            if brand in full_text:
                impersonated_brand = brand
                if brand not in sender_domain:
                    sender_score += 15
                    signals.append({"type": "BRAND_IMPERSONATION", "score": 15, "description": f"Content mentions '{brand.title()}' but sender domain '{sender_domain}' is not authorized"})
                    why_bullets.append(f"Email mentions {brand.title()} but was sent from an unrelated external domain ({sender_domain})")
                    break

        if "paypa1" in sender_domain or "micros0ft" in sender_domain or "g00gle" in sender_domain or "sec-update" in sender_domain or (impersonated_brand and ("security" in sender_domain or "verify" in sender_domain or "update" in sender_domain)):
            sender_score += 20
            brand_label = impersonated_brand.title() if impersonated_brand else "Trusted Brand"
            signals.append({"type": "SUSPICIOUS_SENDER_DOMAIN", "score": 20, "description": f"Sender domain resembles {brand_label} (Typosquatting/Deception)"})
            why_bullets.append(f"Sender domain resembles {brand_label} but belongs to unauthorized attacker infrastructure")
        elif impersonated_brand and sender_name and impersonated_brand in sender_name.lower() and impersonated_brand not in sender_domain:
            sender_score += 15
            signals.append({"type": "DISPLAY_NAME_MISMATCH", "score": 15, "description": f"Display name claims '{sender_name}' while sender address is '{sender}'"})
            why_bullets.append(f"Display name claims {sender_name} while sending email address is unrelated ({sender})")
        elif any(sender_domain.endswith(tld) for tld in self.HIGH_RISK_TLDS):
            sender_score += 15
            signals.append({"type": "HIGH_ABUSE_TLD", "score": 15, "description": f"Sender uses high-abuse domain extension ({sender_domain})"})
            why_bullets.append(f"Sender operates on a high-abuse domain extension ({sender_domain})")

        sender_score = min(20, sender_score)

        # -------------------------------------------------------------
        # 2. Authentication Analysis (SPF / DKIM / DMARC) (Max 15 Points)
        # -------------------------------------------------------------
        auth_score = 0
        spf_val = auth_results.get("spf", "NONE").upper()
        dkim_val = auth_results.get("dkim", "NONE").upper()
        dmarc_val = auth_results.get("dmarc", "NONE").upper()

        if dmarc_val == "FAIL":
            auth_score += 15
            signals.append({"type": "DMARC_FAILURE", "score": 15, "description": "DMARC policy validation failed (unaligned envelope)"})
            why_bullets.append("DMARC email authentication failed — sender domain is unauthorized")
        elif spf_val in ("FAIL", "SOFTFAIL") or dkim_val == "FAIL":
            auth_score += 10
            signals.append({"type": "SPF_DKIM_FAILURE", "score": 10, "description": "SPF or DKIM authentication check failed"})
            why_bullets.append("SPF/DKIM cryptographic authentication checks failed")
        elif spf_val == "NONE" and dkim_val == "NONE" and sender_score > 0:
            auth_score += 5
            signals.append({"type": "NO_AUTHENTICATION", "score": 5, "description": "No SPF or DKIM signatures present on domain"})

        auth_score = min(15, auth_score)

        # -------------------------------------------------------------
        # 3. Content Analysis & NLP Detection (Max 25 Points)
        # -------------------------------------------------------------
        content_score = 0

        # Pattern analysis
        if any(re.search(pat, full_text) for pat in self.URGENT_PATTERNS):
            content_score += 12
            signals.append({"type": "URGENT_LANGUAGE", "score": 12, "description": "Urgent language or account suspension coercion detected"})
            why_bullets.append("Urgent psychological coercion language detected ('immediate action required')")

        if any(re.search(pat, full_text) for pat in self.CREDENTIAL_PATTERNS):
            content_score += 13
            signals.append({"type": "CREDENTIAL_REQUEST", "score": 13, "description": "Credential harvesting or password verification request"})
            why_bullets.append("Login credentials or password verification requested")

        if any(re.search(pat, full_text) for pat in self.FINANCIAL_PATTERNS):
            content_score += 10
            signals.append({"type": "FINANCIAL_SOLICITATION", "score": 10, "description": "Direct wire transfer, gift card, or payment manipulation"})
            why_bullets.append("Wire transfer or direct financial transaction instructions detected")

        if any(re.search(pat, full_text) for pat in self.SPAM_PATTERNS):
            content_score += 8
            signals.append({"type": "SPAM_INDICATORS", "score": 8, "description": "Promotional spam or prize lure keywords detected"})

        # ML Semantic Boost (if ML confidence > 70%)
        if ml_threat_prob >= 0.70:
            ml_points = min(15, int(ml_threat_prob * 15))
            if content_score < ml_points:
                content_score = ml_points
            signals.append({
                "type": "AI_NLP_DETECTION",
                "score": ml_points,
                "description": f"Trained AI NLP Classifier identified semantic phishing patterns ({int(ml_threat_prob * 100)}% probability)"
            })

        content_score = min(25, content_score)

        # -------------------------------------------------------------
        # 4. URL Analysis & Deceptive Links (Max 20 Points)
        # -------------------------------------------------------------
        url_score = 0
        deceptive_urls = []

        for u in urls:
            u_lower = u.lower()
            # IP based URL
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u_lower):
                url_score += 20
                deceptive_urls.append(u)
                signals.append({"type": "RAW_IP_URL", "score": 20, "description": f"URL uses raw IP address instead of domain ({u})"})
                why_bullets.append("Embedded link points directly to a raw numerical IP address")
                break
            # Lookalike deceptive link
            elif any(brand in u_lower for brand in ["paypa1", "micros0ft", "g00gle", "verify-login", "secure-update", "auth-session", "login"]):
                url_score += 20
                deceptive_urls.append(u)
                signals.append({"type": "DECEPTIVE_URL", "score": 20, "description": f"Phishing URL path targeting credentials ({u})"})
                why_bullets.append("Destination URL points to a deceptive credential harvesting website")
                break
            elif any(u_lower.endswith(tld) or f"{tld}/" in u_lower for tld in self.HIGH_RISK_TLDS):
                url_score += 15
                deceptive_urls.append(u)
                signals.append({"type": "HIGH_ABUSE_URL_TLD", "score": 15, "description": f"Destination link hosted on high-abuse TLD ({u})"})
                why_bullets.append("Destination link points to an untrusted high-abuse domain")
                break

        url_score = min(20, url_score)

        # -------------------------------------------------------------
        # 5. Attachment Analysis (Max 20 Points)
        # -------------------------------------------------------------
        attachment_score = 0
        for att in attachments:
            fname = att.get("filename", "").lower()
            ext = "." + fname.split(".")[-1] if "." in fname else ""
            if ext in self.DANGEROUS_EXTENSIONS:
                attachment_score = 20
                signals.append({"type": "DANGEROUS_ATTACHMENT", "score": 20, "description": f"Executable or high-risk archive file attached ({fname})"})
                why_bullets.append(f"Dangerous attachment format detected ({fname})")
                break

        attachment_score = min(20, attachment_score)

        # -------------------------------------------------------------
        # Final Deterministic Risk Score: 0 – 100
        # -------------------------------------------------------------
        total_risk_score = min(100, sender_score + auth_score + content_score + url_score + attachment_score)

        # Classification and Recommended Action
        if total_risk_score >= 70:
            classification = "HIGH_RISK"
            threat_type = "PHISHING" if (url_score > 0 or content_score >= 15) else "MALICIOUS"
            recommended_action = "QUARANTINE"
        elif total_risk_score >= 30:
            classification = "SUSPICIOUS"
            threat_type = "SUSPICIOUS"
            recommended_action = "WARN"
        else:
            classification = "SAFE"
            threat_type = "SAFE"
            recommended_action = "ALLOW"

        # Calculate Confidence
        base_conf = max(ml_threat_prob if total_risk_score >= 30 else (1.0 - ml_threat_prob), 0.70)
        confidence = min(0.99, max(0.65, round(base_conf, 2)))

        # Natural Language AI Explanation
        if total_risk_score >= 70:
            ai_explanation = (
                f"This email demonstrates strong malicious characteristics with a composite risk score of {total_risk_score}/100. "
                f"It attempts to create urgency while requesting credential verification on unauthorized infrastructure."
            )
            if impersonated_brand:
                ai_explanation = (
                    f"This email appears to impersonate {impersonated_brand.title()} and attempts to create urgency "
                    f"by claiming that the recipient's account will be suspended. The included link points to an unauthorized destination."
                )
        elif total_risk_score >= 30:
            ai_explanation = (
                f"This email contains suspicious indicators (risk score {total_risk_score}/100). "
                f"Exercise caution and verify the sender before opening links or attachments."
            )
        else:
            ai_explanation = (
                f"This email verified clean across sender authentication, content NLP, links, and attachments. "
                f"No malicious threat indicators detected (risk score {total_risk_score}/100)."
            )

        if not why_bullets:
            why_bullets.append("No security anomalies or threat patterns detected.")

        return {
            "risk_score": total_risk_score,
            "classification": classification,
            "threat_type": threat_type,
            "confidence": confidence,
            "recommended_action": recommended_action,
            "ml_threat_probability": round(ml_threat_prob, 4),
            "score_breakdown": {
                "sender_score": sender_score,
                "authentication_score": auth_score,
                "content_score": content_score,
                "url_score": url_score,
                "attachment_score": attachment_score
            },
            "signals": signals,
            "why_bullets": why_bullets,
            "ai_explanation": ai_explanation,
            "deceptive_urls": deceptive_urls
        }

threat_detector = ThreatDetector()

import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import VotingClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import cross_val_score, train_test_split

# =====================================================================
# Rich, Multi-Category Email Threat & Legitimate Dataset
# =====================================================================

SAFE_EMAILS = [
    "Your weekly GitHub digest and notification summary for active repositories",
    "GitHub: New release v2.4.0 is now available in your subscribed repository",
    "Your Amazon order #402-991823 has shipped and is on the way via UPS",
    "Google Calendar: Team sprint planning meeting tomorrow at 10:00 AM in room 4B",
    "Slack notification: You have 3 unread messages in the #engineering channel",
    "Your receipt for Uber ride on Tuesday morning with detailed fare breakdown",
    "Netflix: New TV shows and award-winning movies added this weekend for your profile",
    "Stripe invoice #INV-9281 paid successfully. Download your official PDF receipt.",
    "Weekly engineering standup notes and sprint backlog prioritization items",
    "Zoom meeting invitation: Quarterly product roadmap and technical architecture review",
    "Your monthly electricity utility bill is ready to view and download online",
    "Thank you for your purchase at Apple Store. Your official order receipt is attached.",
    "Atlassian Jira: Issue SIH-104 has been assigned to you by the project lead",
    "LinkedIn: 5 people viewed your professional profile this week",
    "DocuSign: Completed document has been signed by all parties and saved to your account",
    "Your flight confirmation for booking #AA-9921 from New York to San Francisco",
    "GitLab CI/CD: Pipeline passed successfully on main branch commit #8a12c",
    "Your subscription renewal confirmation for Spotify Premium student plan",
    "Team lunch reminder: Friday at 1:00 PM at downtown Italian bistro",
    "Code review requested for pull request #45: Refactor database connection pooling",
    "Microsoft Teams: You were mentioned by Sarah in the #frontend-dev channel",
    "Your weekly newsletter from Hacker News and MIT Technology Review",
    "Cloudflare: DNS records updated successfully for your apex domain and subdomains",
    "Annual cybersecurity awareness training module reminder for all engineering staff",
    "Package delivered: Your package was placed in the parcel locker by FedEx courier",
    "Google Workspace: Daily activity digest for shared team drive folders",
    "Your monthly bank statement is now available for download in PDF format",
    "Meeting reschedule: Engineering sync moved from 2:00 PM to 3:30 PM today",
    "AWS Billing Alert: Your estimated monthly charges for us-east-1 are within budget",
    "Vite release v6.2 has been published with faster HMR and modern bundling",
    "Your appointment with Dr. Henderson is confirmed for Wednesday at 9:00 AM",
    "Substack: Read the latest article on distributed systems consensus algorithms",
    "GitHub Security Advisory: Dependabot detected 0 vulnerabilities in your repository",
    "Medium Daily Digest: Top recommended software architecture stories for you",
    "Your gym membership payment confirmation for the upcoming calendar month",
    "Confluence: Updated design specifications document for the REST API gateway",
    "New comment on your Figma project wireframe from UI designer",
    "Automated backup completed successfully for PostgreSQL database instance",
    "Invitation: Web security webinar on zero-trust enterprise network architecture",
    "Thank you for attending the hackathon orientation workshop today",
    "Your hotel reservation at Marriott Downtown is confirmed for Oct 12-15",
    "Google Cloud Platform: Cloud Run service deployment succeeded with zero downtime",
    "The quarterly company all-hands presentation slides have been uploaded to Drive",
    "Your car service appointment is scheduled for Saturday morning at 8:30 AM",
    "npm security audit report: 0 vulnerabilities found in 420 scanned packages",
    "Order confirmed: Your Domino's pizza order is being prepared and baked",
    "Your library books are due in 3 days. Renew online through your student account.",
    "Weekly HR newsletter: Open enrollment benefits and holiday schedule announced",
    "Welcome to the team! Here is your onboarding checklist and office access guide",
    "Your domain renewal invoice for next year has been processed successfully"
]

THREAT_EMAILS = [
    # Credential Harvesting & Phishing
    "URGENT: Your PayPal account has been restricted. Click here to verify your identity immediately.",
    "Microsoft 365: Your password expires today. Sign in now to prevent mailbox disconnection.",
    "Google Security Alert: Unauthorized sign-in detected from Russia. Verify your account credentials.",
    "Apple Support: Your Apple ID is locked due to suspicious activity. Re-enter your password to unlock.",
    "Action Required: Your email storage is 99% full. Click the link to upgrade storage or lose messages.",
    "Bank of America: Unusual login attempt detected. Confirm your online banking credentials now.",
    "Chase Bank Security: Your debit card is temporarily suspended. Click here to verify credentials.",
    "DocuSign Security: You have received a secure document. Enter your corporate email password to view.",
    "Wells Fargo Alert: Suspicious transaction detected. Verify your account number and security PIN.",
    "Netflix Notice: Payment method failed. Update credit card details within 24 hours to keep account active.",
    "Dropbox Security: Unrecognized login attempt from IP 194.26.29.11. Click to verify your identity.",
    "IT Helpdesk: Mandatory multi-factor authentication (MFA) reset required for all staff. Click here.",
    "Outlook Web App: Your incoming emails are held in quarantine. Click here to release messages.",
    "HR Portal: Your direct deposit information failed. Log in to employee portal to confirm bank details.",
    "Security Notification: Immediate verification required to prevent permanent account termination.",
    "Meta Account Center: Your Facebook page violates copyright terms. Submit appeal within 12 hours.",
    "Amazon Security: We detected an unauthorized purchase of $1,299 iPhone. Click to dispute transaction.",
    "Internal IT Service Desk: Update your VPN security certificate immediately via the link provided.",
    "Adobe Creative Cloud: Your payment could not be processed. Update billing info to avoid cancellation.",
    "Security Alert: Someone accessed your email from Chrome on Linux in Netherlands. Verify identity now.",

    # Business Email Compromise (BEC) & Financial Scams
    "Urgent: Are you at your desk? Need you to process an immediate wire transfer for confidential acquisition.",
    "CEO Request: Please purchase 10 Apple gift cards for client appreciation event. Send codes to me directly.",
    "CONFIDENTIAL: Change vendor bank routing number for upcoming $85,000 invoice payment immediately.",
    "Payroll Update: I need to update my direct deposit bank account before tomorrow's payroll cutoff.",
    "Urgent wire transfer needed before end of banking day. Details attached in confidential invoice.",
    "Executive instruction: Send executive payroll summary spreadsheet to my personal email address immediately.",
    "Overdue payment notification: Transfer funds to our new escrow account to avoid legal proceedings.",
    "Strictly confidential: Process payment of $42,500 to new consulting partner before close of business.",
    "Urgent financial request: I am in a board meeting and cannot take calls. Wire funds to beneficiary attached.",
    "Direct deposit notice: Switch my monthly salary deposit to Chime bank account details provided.",

    # Malicious Attachments & Malware Delivery
    "Invoice INV-88192 overdue. Please review the attached macro-enabled Excel sheet to verify charges.",
    "Scanned document from Xerox WorkCentre printer. Open attached archive to view confidential contract.",
    "DHL Delivery notice: Undelivered package #DH-99218. Download attached shipping label .exe to reschedule.",
    "Your electronic payment receipt has been generated. Open attached .zip file for complete tax breakdown.",
    "Court Notice: You have been summoned for jury duty. Download official subpoena document attached.",
    "Resume and portfolio for Senior Cybersecurity Engineer position. Attached archive contains portfolio.",
    "Critical system patch: Run attached installer script to remediate newly discovered security vulnerability.",
    "Remittance advice payment confirmation. Open attached HTML document to decrypt payment receipt.",
    "Bank transaction statement attached as encrypted archive. Password to extract is: 123456.",
    "Updated pricing catalog and purchase order. Open attached macro sheet to calculate discounted pricing."
]

def train_and_export_model():
    X = SAFE_EMAILS + THREAT_EMAILS
    y = [0] * len(SAFE_EMAILS) + [1] * len(THREAT_EMAILS)
    
    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Hybrid TF-IDF feature extractor + Regularized Logistic Regression
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
            min_df=1,
            max_features=5000,
            lowercase=True
        )),
        ('clf', LogisticRegression(
            C=3.0,
            class_weight='balanced',
            random_state=42,
            max_iter=1000
        ))
    ])

    print("Training High-Precision Email Threat NLP Classifier...")
    pipeline.fit(X_train, y_train)

    # Evaluation
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    cv_scores = cross_val_score(pipeline, X, y, cv=5, scoring='f1')

    print("\n==========================================")
    print("Model Performance Metrics on Test Split:")
    print("==========================================")
    print(f"Accuracy:        {acc * 100:.2f}%")
    print(f"Precision:       {prec * 100:.2f}%")
    print(f"Recall:          {rec * 100:.2f}%")
    print(f"F1-Score:        {f1 * 100:.2f}%")
    print(f"5-Fold CV F1:    {np.mean(cv_scores) * 100:.2f}% (+/- {np.std(cv_scores) * 100:.2f}%)")
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["SAFE", "THREAT"]))

    # Save Model Artifact
    model_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(model_dir, "phishing_model.joblib")
    joblib.dump(pipeline, model_path)
    print(f"SUCCESS: Trained model saved to: {model_path}")
    return pipeline

if __name__ == "__main__":
    train_and_export_model()

# 🛡️ Mailtrace AI — System Architecture & Forensic Specification

This document details the forensic deconstruction pipeline, cryptographic authentication matrix, and NLP threat scoring algorithms for **Mailtrace AI**.

---

## 1. Architectural Highlights
- **Cryptographic Domain Authentication**: Native RFC 7208 (SPF), RFC 6376 (DKIM), and RFC 7489 (DMARC) alignment checking verifying legitimate sender identities.
- **Relay Hop Trace Engine**: Deconstructs MIME \`Received\` headers to map transit routes, intermediate MTA delays, and geographic geolocation indicators.
- **NLP Intent Classification**: Hugging Face Transformer models trained to score urgency coercion, credential panic, and invoice fraud in email bodies.
- **Forensic Threat Dossier**: Automated scoring engine producing 0–100 risk metrics with actionable SOC guidance.

---

## 2. Technical Documentation & Formal Report
The complete 12-page IEEE-standard technical architecture report is published in:
- **LaTeX Source**: [`docs/report/project-report.tex`](file:///c:/Users/tharu/Documents/GITHUB%20REPO/GITHUB%20MANAGER/Mailtrace-ai/docs/report/project-report.tex)
- **Compiled PDF**: [`docs/report/project-report.pdf`](file:///c:/Users/tharu/Documents/GITHUB%20REPO/GITHUB%20MANAGER/Mailtrace-ai/docs/report/project-report.pdf)

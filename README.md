# 🛡️ AuthGuard — Identity Threat Detection & Response Engine

> **AI-Powered Failed Login Pattern Analyzer for Early Threat Detection**
> Built on Microsoft Azure | Team ShieldOps | Hack2Future 2026

![Azure](https://img.shields.io/badge/Microsoft_Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-Kusto_Query_Language-blue?style=for-the-badge)
![Power BI](https://img.shields.io/badge/Power_BI-F2C811?style=for-the-badge&logo=powerbi&logoColor=black)
![Teams](https://img.shields.io/badge/Microsoft_Teams-6264A7?style=for-the-badge&logo=microsoftteams&logoColor=white)

---

## 🎯 Overview

**AuthGuard** is a fully automated, cloud-native **identity threat detection and response engine** built entirely on Microsoft Azure. It detects 7 types of authentication attacks in real-time, enriches threats with IP reputation intelligence, and delivers alerts through 5 simultaneous channels — all for less than $1 in Azure costs.

### Key Highlights
- 🔍 **7 Attack Scenarios** simulated with realistic data
- 🧠 **8 KQL Detection Rules** with statistical behavioral analysis
- 🔄 **Fully Automated Pipeline** — zero manual intervention
- 📊 **15+ Dashboard Tiles** for SOC analysts and executives
- 📱 **5 Alert Channels** — Teams, Email, SMS, Sentinel, Azure Monitor
- 💰 **Total Cost: $0.41** out of $55 budget (0.75%)

---

## 🔴 Problem Statement

Organizations face **millions of failed login attempts daily** across multiple identity platforms. Security teams lack real-time visibility into attack patterns like:

- **Brute Force** — Repeated password guessing against single accounts
- **Password Spray** — Trying common passwords across many accounts
- **Credential Stuffing** — Using leaked credentials from breaches
- **Impossible Travel** — Same user from distant locations simultaneously

> 💡 **80% of breaches involve compromised credentials** (Verizon DBIR 2024)
> 💡 **Average breach cost: $4.88M** (IBM 2024)

---

## 🏗️ Solution Architecture

### Architecture Flow

**Python Simulator** (7 Attack Types)
⬇️ HTTP Data Collector API
**Azure Log Analytics** (8 KQL Detection Rules)
⬇️
**Azure Logic App** (Every 30 min)
⬇️
**Azure Function** → IP Reputation + Risk Score (0-100)
⬇️ Alerts sent to:
- ✅ Microsoft Teams (Adaptive Card)
- ✅ Outlook Email (HTML, IST timestamps)
- ✅ SMS (Azure Monitor)
- ✅ Microsoft Sentinel (SIEM + MITRE)
- ✅ Table Storage (Incident Log)
⬇️
**Azure Workbook Dashboard** (15+ Tiles) + **Power BI** (Executive)

### 6-Stage Pipeline

| Stage | Component | Description |
|-------|-----------|-------------|
| 1. **SIMULATE** | Python Simulator | Generates 7 attack scenarios → Log Analytics |
| 2. **DETECT** | KQL Engine | 8 detection rules analyze events in real-time |
| 3. **ENRICH** | Azure Function | Adds IP reputation + composite risk score (0-100) |
| 4. **ORCHESTRATE** | Logic App | Automates detection → enrichment → alerting |
| 5. **ALERT** | Multi-Channel | Teams, Email, SMS, Sentinel, Azure Monitor |
| 6. **VISUALIZE** | Dashboard | Workbook (15+ tiles), Power BI, Incident Log |

---

## ⭐ Key Features

### 🔍 Advanced Detection
- **Impossible Travel Detection** — Haversine geo-distance calculation
- **Composite Risk Scoring** — 0-100 score using 5 weighted signals
- **IP Reputation Engine** — TOR Exit Nodes, Botnet C2, Known Scanners

### 🤖 Full Automation
- Logic App runs every 30 minutes — zero manual intervention
- Automatic enrichment via Azure Function
- Multi-channel alerting fires simultaneously

### 🛡️ Enterprise SIEM Integration
- Microsoft Sentinel with 4 detection rules
- MITRE ATT&CK mapping (T1110, T1078)
- Proactive threat hunting queries

---

## 🔧 Technology Stack

| Category | Technology | Purpose |
|----------|-----------|---------|
| **Simulation** | Python 3.11+ | 7 attack scenario generator |
| **Log Store** | Azure Log Analytics | Central event ingestion and KQL engine |
| **Detection** | KQL | 8 real-time detection rules |
| **Enrichment** | Azure Functions | IP reputation and risk scoring |
| **Orchestration** | Azure Logic Apps | Automated pipeline |
| **SIEM** | Microsoft Sentinel | Enterprise SIEM and analytics rules |
| **XDR** | Microsoft Defender XDR | Unified security portal |
| **Alerting** | Azure Monitor | Native alerts (Email and SMS) |
| **Collaboration** | Microsoft Teams | SOC Adaptive Card alerts |
| **Email** | Office 365 Outlook | HTML-formatted alerts |
| **Dashboard** | Azure Workbooks | 15+ tile interactive dashboard |
| **Reporting** | Power BI | Executive-level reporting |
| **Storage** | Azure Table Storage | Incident audit trail (200+ records) |
| **IaC** | ARM Templates | Infrastructure-as-Code export |
| **Framework** | MITRE ATT&CK | T1110, T1078 mapping |

---

## 🎭 Attack Scenarios

| # | Attack Type | Description |
|---|------------|-------------|
| 1 | **Brute Force** | Single IP hammers single account |
| 2 | **Password Spray** | Single IP targets many accounts |
| 3 | **Credential Stuffing** | Multiple IPs target same account |
| 4 | **Impossible Travel** | Same user from distant locations |
| 5 | **Off-Hours Anomaly** | Failed logins during 7PM-8AM |
| 6 | **Account Enumeration** | Trying non-existent usernames |
| 7 | **Normal Baseline** | Legitimate failed logins |

---

## 📡 Detection Rules

### KQL Rules (8)

| Rule | File | Threshold |
|------|------|-----------|
| Brute Force | 01_brute_force.kql | 5+ failures per IP-user |
| Password Spray | 02_password_spray.kql | 3+ users per IP |
| Credential Stuffing | 03_credential_stuffing.kql | 3+ IPs per user |
| Impossible Travel | 04_impossible_travel.kql | 2+ distant locations |
| Off-Hours | 05_off_hours.kql | 3+ events outside 8AM-7PM |
| Account Enumeration | 06_account_enumeration.kql | 3+ invalid usernames |
| HVT Monitoring | 07_hvt_monitoring.kql | 3+ failures on admin accounts |
| Master Combined | 08_master_detection.kql | Union of all rules |

### Sentinel Rules (4)

| Rule | Severity | MITRE ATT&CK |
|------|----------|--------------|
| Brute Force | High | T1110 |
| Password Spray | High | T1110 |
| Impossible Travel | High | T1078 |
| Compromised Accounts | High | T1110 |

---

## 📱 Alert Channels

| Channel | Recipient | Content |
|---------|-----------|---------|
| 🟣 **Teams** | SOC Analysts | Interactive Adaptive Card |
| 📧 **Email** | Management | HTML table with IST timestamps |
| 📱 **SMS** | On-call Engineer | Mobile alert for escalation |
| 🔔 **Azure Monitor** | Operations | Native platform alert |
| 🛡️ **Sentinel** | Security Team | SIEM incidents and MITRE |

---

## 📊 Dashboard

15+ interactive tiles including:
- Key Metrics Grid
- Attack Timeline (Area Chart)
- Threat Distribution (Pie Chart)
- Top Targeted Users and Attacker IPs
- Geographic Distribution
- Active Threats (Real-Time)
- Risk Severity Breakdown
- MFA Status and Department Risk Analysis

---

## 🚀 Setup Guide

1. Create Resource Group and Log Analytics Workspace
2. Run simulator: `python simulate_pro.py --scenario mixed_pro --count 120`
3. Deploy Azure Function for threat enrichment
4. Import KQL detection queries
5. Configure Logic App orchestration
6. Enable Microsoft Sentinel and create analytics rules
7. Build Azure Workbook dashboard
8. Configure Azure Monitor alerts (Email + SMS)

> Detailed instructions: docs/setup_guide.md

---

## 📁 Project Structure

### Folders

- **simulator/** → simulate_pro.py
- **azure-function/** → function_app.py, requirements.txt
- **kql-queries/** → 9 KQL detection query files
- **logic-app/** → logic_app_code.json, adaptive_card.json
- **docs/** → architecture.md, setup_guide.md
- **Screenshots/** → All project screenshots

---

## 💰 Cost Analysis

| Metric | Value |
|--------|-------|
| **Total Budget** | $55.00 |
| **Total Spent** | $0.41 |
| **Budget Used** | 0.75% |
| **Architecture** | 100% Serverless |

> Enterprise-grade security detection for **less than $1**

---

## 🔮 Future Roadmap

| Phase | Enhancement | Timeline |
|-------|------------|----------|
| v2.1 | Real Entra ID sign-in logs | 1 month |
| v2.2 | Conditional Access auto-remediation | 2 months |
| v2.3 | ML-based adaptive thresholds | 3 months |
| v3.0 | Multi-tenant support | 4 months |
| v3.1 | Azure Marketplace packaging | 6 months |

---

## 👥 Team ShieldOps

| Name | Role |
|------|------|
| **Dheeraj Kachi** | Lead Developer |

---

## 🙏 Acknowledgments

- **Microsoft** — Azure cloud platform and hackathon partnership
- **CloudLabs (Spektra Systems)** — Sandbox environment support
- **Hack2Future 2026** — Hackathon platform and challenge

---

⭐ **Star this repo if you found it useful!**

---

<p align="center">
  <b>🛡️ AuthGuard — Securing Identities Before Breaches Happen</b><br>
  <i>Team ShieldOps | Hack2Future 2026 | Microsoft Azure</i>
</p>

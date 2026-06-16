# 🏗️ AuthGuard Pro v2.0 — Architecture Documentation

## Overview

AuthGuard Pro is a cloud-native identity threat detection and response engine built on Microsoft Azure. It follows a 6-stage automated pipeline.

## Architecture Diagram

```
Python Simulator (7 Attack Types)
        │
        │ HTTP Data Collector API
        ▼
Azure Log Analytics Workspace
        │
        │ 8 KQL Detection Rules
        ▼
Azure Logic App (Every 30 min)
        │
        ├──► Azure Function (IP Reputation + Risk Score 0-100)
        │
        ├──► Microsoft Teams (Adaptive Card → SOC Channel)
        ├──► Outlook Email (HTML formatted, IST timestamps)
        ├──► SMS (Azure Monitor Action Group)
        ├──► Microsoft Sentinel (SIEM Incidents + MITRE ATT&CK)
        ├──► Azure Table Storage (Incident Audit Trail)
        │
        ▼
Azure Workbook Dashboard (15+ Tiles) + Power BI (Executive)
```

## 6-Stage Pipeline

### Stage 1: DATA SIMULATION
- Python simulator generates 7 realistic attack scenarios
- Attack types: Brute Force, Password Spray, Credential Stuffing, Impossible Travel, Off-Hours Anomaly, Account Enumeration, Normal
- Data sent to Log Analytics via HTTP Data Collector API
- Includes: 15+ IPs, 20+ users, 10+ countries, MFA status, risk levels

### Stage 2: DETECTION ENGINE
- 8 KQL detection rules analyze events in real-time
- Statistical aggregation by IP, user, time windows
- Behavioral analysis for off-hours and impossible travel
- Configurable thresholds (no code changes needed)

### Stage 3: THREAT ENRICHMENT
- Azure Function (Python, serverless) processes detected threats
- IP Reputation scoring from simulated threat intelligence database
- Composite Risk Score (0-100) using 5 weighted signals:
  - Failure count impact: 30%
  - IP reputation: 25%
  - Attack type severity: 20%
  - High-value target status: 15%
  - Off-hours bonus: 10%
- Automated remediation recommendations generated

### Stage 4: ORCHESTRATION
- Azure Logic App runs automatically every 30 minutes
- Executes master KQL detection query
- Calls Azure Function for enrichment
- Routes alerts to 5 channels based on results
- Logs incidents to Azure Table Storage

### Stage 5: MULTI-CHANNEL ALERTING

| Channel | Target | Content |
|---------|--------|---------|
| Microsoft Teams | SOC Analysts | Interactive Adaptive Card |
| Outlook Email | Management | HTML table with IST time |
| SMS | On-call Engineer | Mobile alert for escalation |
| Azure Monitor | Operations | Native platform alert |
| Microsoft Sentinel | Security Team | SIEM incident + MITRE |

### Stage 6: VISUALIZATION
- Azure Workbook Dashboard with 15+ interactive tiles
- Power BI for executive-level reporting
- Azure Table Storage for persistent incident audit trail

## Microsoft Azure Services Used (15+)

| # | Service | Purpose |
|---|---------|---------|
| 1 | Log Analytics Workspace | Central log store + KQL engine |
| 2 | Azure Functions | Serverless threat enrichment |
| 3 | Azure Logic Apps | Automated orchestration |
| 4 | Microsoft Sentinel | Enterprise SIEM |
| 5 | Microsoft Defender XDR | Unified security portal |
| 6 | Azure Monitor | Native alerting (Email + SMS) |
| 7 | Azure Workbooks | Interactive dashboard |
| 8 | Azure Table Storage | Incident audit trail |
| 9 | Microsoft Teams | SOC Adaptive Card alerts |
| 10 | Office 365 Outlook | HTML email alerts |
| 11 | Power BI | Executive reporting |
| 12 | Azure Cloud Shell | Development environment |
| 13 | ARM Templates | Infrastructure-as-Code |
| 14 | Azure Storage (Blob) | Function App storage |
| 15 | Application Insights | Function monitoring |

## Security & Compliance

- **Authentication**: Azure AD / Entra ID with RBAC
- **Encryption**: TLS 1.2+ (transit) + Azure Storage encryption (rest)
- **API Security**: HMAC-SHA256 for Log Analytics, Function keys for API
- **Framework**: NIST Cybersecurity Framework aligned
- **Audit**: SOC 2 compliant incident logging
- **Cost Governance**: Budget alerts at 25%, 50%, 75%, 90%

## MITRE ATT&CK Mapping

| Tactic | Technique | Detection Rule |
|--------|-----------|---------------|
| Credential Access | T1110 — Brute Force | Brute Force, Password Spray |
| Credential Access | T1110.001 — Password Guessing | Brute Force Detection |
| Credential Access | T1110.003 — Password Spraying | Password Spray Detection |
| Credential Access | T1110.004 — Credential Stuffing | Credential Stuffing Detection |
| Initial Access | T1078 — Valid Accounts | Impossible Travel Detection |
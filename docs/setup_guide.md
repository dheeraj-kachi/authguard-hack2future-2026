# 🚀 AuthGuard Pro v2.0 — Setup Guide

## Prerequisites

- Azure Subscription with access to:
  - Log Analytics, Azure Functions, Logic Apps, Sentinel
- Python 3.11+
- Azure CLI / Cloud Shell
- Microsoft Teams (channel creation permissions)
- Office 365 (email alerts)
- Power BI Desktop (optional)

## Phase 1: Create Azure Resources

### 1.1 Resource Group
```bash
az group create --name rg-authguard-shieldops --location eastus
```

### 1.2 Log Analytics Workspace
```bash
az monitor log-analytics workspace create \
  --resource-group rg-authguard-shieldops \
  --workspace-name law-authguard \
  --location eastus
```

### 1.3 Get Workspace Credentials
```bash
# Get Workspace ID
az monitor log-analytics workspace show \
  --resource-group rg-authguard-shieldops \
  --workspace-name law-authguard \
  --query customerId -o tsv

# Get Primary Key
az monitor log-analytics workspace get-shared-keys \
  --resource-group rg-authguard-shieldops \
  --workspace-name law-authguard \
  --query primarySharedKey -o tsv
```

## Phase 2: Data Simulation

### 2.1 Configure Simulator
Edit `simulator/simulate_pro.py` and update:
```python
WORKSPACE_ID = "your-workspace-id"
PRIMARY_KEY = "your-primary-key"
```

### 2.2 Run Simulator
```bash
cd simulator/
python simulate_pro.py --scenario mixed_pro --count 120
```

This generates 7 attack types:
- Brute Force
- Password Spray
- Credential Stuffing
- Impossible Travel
- Off-Hours Anomaly
- Account Enumeration
- Normal Baseline

### 2.3 Verify Data
In Log Analytics → Logs, run:
```kql
FailedLogins_CL
| summarize count() by AttackType_s
```

## Phase 3: Azure Function (Threat Enrichment)

### 3.1 Create Function App
```bash
az functionapp create \
  --resource-group rg-authguard-shieldops \
  --name func-authguard-enrich \
  --runtime python \
  --runtime-version 3.11 \
  --os-type linux
```

### 3.2 Deploy Function Code
```bash
cd azure-function/
func init --python --model V2
func azure functionapp publish func-authguard-enrich
```

### 3.3 Get Function URL
- Azure Portal → Function App → Functions → enrich → Get Function Url
- Save this URL for Logic App configuration

## Phase 4: KQL Detection Rules

Import all queries from `kql-queries/` folder into Log Analytics:

| File | Rule | Time Window |
|------|------|-------------|
| 01_brute_force.kql | Brute Force | 24h |
| 02_password_spray.kql | Password Spray | 24h |
| 03_credential_stuffing.kql | Credential Stuffing | 24h |
| 04_impossible_travel.kql | Impossible Travel | 1h |
| 05_off_hours.kql | Off-Hours Anomaly | 1h |
| 06_account_enumeration.kql | Account Enumeration | 24h |
| 07_hvt_monitoring.kql | High-Value Target | 30m |
| 08_master_detection.kql | Master Combined | All |

## Phase 5: Logic App (Orchestration)

### 5.1 Create Logic App
- Type: Consumption (Stateful)
- Region: East US
- Enable Log Analytics: Yes → law-authguard

### 5.2 Import Workflow
- Import `logic-app/logic_app_code.json` via Code view
- Update connections for Teams, Outlook, Table Storage

### 5.3 Configure Recurrence
- Interval: 5-30 minutes (adjust based on need)
- Timezone: India Standard Time

### 5.4 Workflow Steps
1. Recurrence (trigger)
2. Run KQL master detection query
3. Condition (threats > 0?)
4. HTTP POST to Azure Function (enrichment)
5. Post Adaptive Card to Teams
6. Send HTML Email
7. Insert Entity to Table Storage (incident log)

## Phase 6: Microsoft Sentinel

### 6.1 Enable Sentinel
- Azure Portal → Microsoft Sentinel → Add → Select law-authguard

### 6.2 Create Analytics Rules
Create 3 scheduled query rules:
1. **Brute Force Detection** — Severity: High, MITRE: T1110
2. **Password Spray Detection** — Severity: High, MITRE: T1110
3. **Impossible Travel Detection** — Severity: High, MITRE: T1078

### 6.3 Create Hunting Query
- Advanced Hunting → New Query
- Use `kql-queries/09_hunting_query.kql`

## Phase 7: Dashboard (Azure Workbook)

### 7.1 Create Workbook
- Log Analytics → Workbooks → New

### 7.2 Add Tiles (15+)
1. Key Metrics (Grid)
2. Attack Timeline (Area Chart)
3. Threat Distribution (Pie Chart)
4. Top Targeted Users (Grid)
5. Top Attacker IPs (Grid)
6. Geographic Distribution (Bar Chart)
7. Source System Coverage (Donut)
8. Active Threats (Grid)
9. Risk Severity Breakdown (Grid)
10. MFA Status Analysis (Pie)
11. Department Risk (Grid)
12. Failure Reasons (Bar Chart)
13. Business Hours Analysis (Grid/Pie)

## Phase 8: Azure Monitor Alert

### 8.1 Create Alert Rule
- Log Analytics → Alerts → New Alert Rule
- Query: Brute force detection KQL
- Threshold: > 0

### 8.2 Create Action Group
- Name: ag-authguard-alerts
- Notifications: Email + SMS
- Resource Group: rg-authguard-shieldops

## Phase 9: Teams Channel Setup

### 9.1 Create Team & Channel
1. Teams → Create team: "SOC Operations - AuthGuard"
2. Add channel: "Security Alerts"
3. Connect Logic App Teams action to this channel

## Verification Checklist

- [ ] Simulator sends data to Log Analytics
- [ ] KQL queries return results
- [ ] Azure Function enriches threats
- [ ] Logic App runs successfully (all green)
- [ ] Teams Adaptive Card posted
- [ ] HTML Email received
- [ ] SMS alert received
- [ ] Sentinel incidents created
- [ ] Dashboard shows all tiles
- [ ] Incident log has records

## Cost Optimization Tips

- Use Flex Consumption for Function App (scales to zero)
- Use Consumption plan for Logic App (pay per action)
- Set budget alerts at 25%, 50%, 75%, 90%
- Disable Logic App when not actively testing
- Disable Azure Monitor alerts when not needed
- Use 30-60 min intervals instead of 5 min for cost savings
- Total project cost: $0.41 out of $55 budget (0.75%)
"""
AuthGuard Pro v2.0 — Threat Enrichment Function (FIXED)
Team ShieldOps | Hack2Future 2026
"""

import azure.functions as func
import json
import logging

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# IP Reputation Database
IP_REP = {
    "185.220.101.34":  {"score": 95, "cat": "TOR Exit Node",    "listed": True},
    "91.121.87.42":    {"score": 80, "cat": "Scanning Host",    "listed": True},
    "103.75.190.11":   {"score": 88, "cat": "Botnet C2",        "listed": True},
    "45.33.32.156":    {"score": 72, "cat": "Known Scanner",    "listed": True},
    "198.51.100.23":   {"score": 65, "cat": "Suspicious",       "listed": True},
    "203.0.113.50":    {"score": 60, "cat": "Proxy/VPN",        "listed": True},
    "77.247.181.163":  {"score": 85, "cat": "TOR Exit Node",    "listed": True},
    "5.188.62.18":     {"score": 78, "cat": "Brute Force Host", "listed": True},
    "172.16.0.105":    {"score": 5,  "cat": "Internal",         "listed": False},
    "10.0.0.55":       {"score": 5,  "cat": "Internal",         "listed": False},
    "10.0.1.10":       {"score": 5,  "cat": "Internal",         "listed": False},
    "10.0.1.11":       {"score": 5,  "cat": "Internal",         "listed": False},
    "192.168.1.200":   {"score": 5,  "cat": "Internal",         "listed": False},
    "10.0.1.12":       {"score": 5,  "cat": "Internal",         "listed": False},
}


def calc_risk(threat):
    """Composite risk score 0-100."""
    score = 0.0
    fc = threat.get("FailureCount", 0)
    if isinstance(fc, str):
        try: fc = int(fc)
        except: fc = 0
    score += min(30, fc * 2)

    ip = threat.get("AffectedEntity", "") or threat.get("AttackerIP", "")
    rep = IP_REP.get(ip, {"score": 50})
    score += (rep["score"] / 100) * 25

    sev_map = {"Brute Force": 14, "Password Spray": 16,
               "Credential Stuffing": 18, "Impossible Travel": 20,
               "Off-Hours Anomaly": 12, "Account Enumeration": 10,
               "High-Value Target": 17}
    score += sev_map.get(threat.get("ThreatType", ""), 8)

    hvt = ["admin@", "cfo@", "svc_", "hr_admin@", "it_helpdesk@"]
    entity = str(threat.get("AffectedEntity", "")).lower()
    if any(h in entity for h in hvt):
        score += 15

    if threat.get("ThreatType") == "Off-Hours Anomaly":
        score += 10

    return min(100, int(score))


def get_action(risk):
    if risk >= 85:
        return "IMMEDIATE: Disable account, block IP, escalate to IR"
    elif risk >= 70:
        return "URGENT: Force MFA, review activity, add IP to watchlist"
    elif risk >= 50:
        return "MONITOR: Add to watchlist, enable enhanced logging"
    else:
        return "LOW RISK: Log for baseline, no immediate action"


def get_sev(risk):
    if risk >= 85: return "Critical"
    elif risk >= 70: return "High"
    elif risk >= 50: return "Medium"
    else: return "Low"


@app.route(route="enrich", methods=["POST"])
def enrich_threats(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("AuthGuard Enrichment triggered")

    # FIXED: Read raw body FIRST before anything else
    raw_body = req.get_body()
    logging.info(f"Raw body length: {len(raw_body)}")

    if not raw_body or len(raw_body) == 0:
        return func.HttpResponse(
            json.dumps({"error": "Empty body received"}),
            status_code=400, mimetype="application/json"
        )

    # Parse JSON from raw bytes
    try:
        body_str = raw_body.decode("utf-8")
        data = json.loads(body_str)
    except Exception as e:
        logging.error(f"Parse error: {e}")
        return func.HttpResponse(
            json.dumps({"error": f"JSON parse failed: {str(e)}"}),
            status_code=400, mimetype="application/json"
        )

    # Handle {"value": [...]} wrapper from Logic App
    if isinstance(data, dict) and "value" in data:
        threats = data["value"]
    elif isinstance(data, dict):
        threats = [data]
    elif isinstance(data, list):
        threats = data
    else:
        return func.HttpResponse(
            json.dumps({"error": "Unexpected data format"}),
            status_code=400, mimetype="application/json"
        )

    # Enrich each threat
    enriched = []
    for t in threats:
        ip = t.get("AffectedEntity", "") or t.get("AttackerIP", "")
        ip_info = IP_REP.get(ip, {"score": 50, "cat": "Unknown", "listed": False})
        risk = calc_risk(t)

        enriched.append({
            **t,
            "IPReputation": ip_info["score"],
            "IPCategory": ip_info["cat"],
            "IsThreatListed": ip_info["listed"],
            "CompositeRiskScore": risk,
            "EnrichedSeverity": get_sev(risk),
            "RecommendedAction": get_action(risk),
            "EnrichmentEngine": "AuthGuard Pro v2.0"
        })

    enriched.sort(key=lambda x: x["CompositeRiskScore"], reverse=True)
    logging.info(f"Enriched {len(enriched)} threats")

    return func.HttpResponse(
        json.dumps(enriched), mimetype="application/json"
    )
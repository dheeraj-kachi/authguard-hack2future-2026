"""
================================================================
AuthGuard Pro v2.0 - Enhanced Failed Login Event Simulator
================================================================
Team     : ShieldOps
Challenge: Failed Login Pattern Analyzer for Early Threat Detection
Event    : Hack2Future 2026 ( Microsoft)

ENHANCEMENTS OVER v1:
  - 7 attack scenarios (added: impossible travel, off-hours, enumeration)
  - Geo-coordinates for each login (latitude/longitude)
  - 4 source systems (added: VPN Gateway)
  - Session IDs and MFA status tracking
  - High-value target flagging
  - Risk level pre-scoring
  - Richer metadata for better KQL analysis

USAGE:
  python simulate_pro.py --scenario mixed_pro --count 120
  python simulate_pro.py --scenario impossible_travel --count 15
  python simulate_pro.py --scenario off_hours --count 20
================================================================
"""

import hashlib, hmac, base64, json, random, requests
import datetime, argparse, time, sys, uuid, math

# ================================================================
# CONFIGURATION — PASTE YOUR VALUES HERE
# ================================================================
WORKSPACE_ID = "0cf16784-0d42-47b9-af4d-94989952c7e9"
PRIMARY_KEY  = "YjB/GulEdPls8s3w7BVRNpK9gHQAgaVNEIEFdZZyACr02xO0ASKGK86Pfqvq1MeEgXGQsSMx5vtnRE77bklHFA=="
LOG_TYPE     = "FailedLogins"

# ================================================================
# ENHANCED SYNTHETIC DATA POOLS
# ================================================================

# Users with department and risk classification
USERS = [
    {"upn": "admin@contoso.com",          "dept": "IT",       "hvt": True},
    {"upn": "cfo@contoso.com",            "dept": "Finance",  "hvt": True},
    {"upn": "svc_backup@contoso.com",     "dept": "IT",       "hvt": True},
    {"upn": "hr_admin@contoso.com",       "dept": "HR",       "hvt": True},
    {"upn": "john.doe@contoso.com",       "dept": "Sales",    "hvt": False},
    {"upn": "jane.smith@contoso.com",     "dept": "Marketing","hvt": False},
    {"upn": "maria.garcia@contoso.com",   "dept": "Engg",     "hvt": False},
    {"upn": "david.wilson@contoso.com",   "dept": "Engg",     "hvt": False},
    {"upn": "sarah.johnson@contoso.com",  "dept": "Support",  "hvt": False},
    {"upn": "mike.brown@contoso.com",     "dept": "Engg",     "hvt": False},
    {"upn": "lisa.anderson@contoso.com",  "dept": "Finance",  "hvt": False},
    {"upn": "robert.taylor@contoso.com",  "dept": "Legal",    "hvt": False},
    {"upn": "emily.davis@contoso.com",    "dept": "HR",       "hvt": False},
    {"upn": "james.martinez@contoso.com", "dept": "Sales",    "hvt": False},
    {"upn": "it_helpdesk@contoso.com",    "dept": "IT",       "hvt": True},
]

# Non-existent users for account enumeration attacks
FAKE_USERS = [
    "administrator@contoso.com", "root@contoso.com",
    "test@contoso.com", "backup@contoso.com",
    "sa@contoso.com", "user1@contoso.com",
    "support@contoso.com", "info@contoso.com",
]

# IPs with geographic coordinates for impossible travel detection
LOCATIONS_DB = {
    "185.220.101.34":  {"city": "Moscow",     "country": "Russia",      "lat": 55.755, "lon": 37.617},
    "91.121.87.42":    {"city": "Paris",       "country": "France",      "lat": 48.856, "lon": 2.352},
    "103.75.190.11":   {"city": "Beijing",     "country": "China",       "lat": 39.904, "lon": 116.407},
    "45.33.32.156":    {"city": "Fremont",     "country": "United States","lat": 37.548, "lon":-121.988},
    "198.51.100.23":   {"city": "Lagos",       "country": "Nigeria",     "lat": 6.524,  "lon": 3.379},
    "203.0.113.50":    {"city": "Sao Paulo",   "country": "Brazil",      "lat":-23.550, "lon":-46.633},
    "77.247.181.163":  {"city": "Bucharest",   "country": "Romania",     "lat": 44.426, "lon": 26.102},
    "5.188.62.18":     {"city": "Berlin",      "country": "Germany",     "lat": 52.520, "lon": 13.405},
    "172.16.0.105":    {"city": "Mumbai",      "country": "India",       "lat": 19.076, "lon": 72.877},
    "10.0.0.55":       {"city": "Pune",        "country": "India",       "lat": 18.520, "lon": 73.856},
    "10.0.1.10":       {"city": "Hyderabad",   "country": "India",       "lat": 17.385, "lon": 78.486},
    "10.0.1.11":       {"city": "Bangalore",   "country": "India",       "lat": 12.971, "lon": 77.594},
    "192.168.1.200":   {"city": "Chennai",     "country": "India",       "lat": 13.082, "lon": 80.270},
    "10.0.1.12":       {"city": "Delhi",       "country": "India",       "lat": 28.613, "lon": 77.209},
}

ATTACKER_IPS = list(LOCATIONS_DB.keys())[:8]    # External IPs
INTERNAL_IPS = list(LOCATIONS_DB.keys())[8:]     # Internal IPs

SOURCE_SYSTEMS = ["EntraID", "OnPremAD", "CustomWebApp", "VPNGateway"]

FAILURE_REASONS = [
    "Invalid password", "Account locked out",
    "Expired credentials", "Invalid username",
    "MFA challenge failed", "Account disabled",
    "IP blocked by Conditional Access",
    "Certificate validation failed"
]

APPLICATIONS = [
    "Microsoft 365 Portal", "Azure Portal",
    "VPN Gateway", "Internal HR System",
    "Exchange Online", "SharePoint Online",
    "Teams Desktop", "Dynamics 365"
]

DEVICES = [
    "Windows 11 / Edge 125", "Windows 10 / Chrome 126",
    "macOS / Safari 17", "Linux / curl 8.5",
    "Unknown / Python-requests", "Windows Server 2022 / PowerShell",
    "iOS 18 / Outlook Mobile", "Android 15 / Chrome Mobile"
]

MFA_STATUSES = [
    "Not challenged", "Challenge failed",
    "Challenge timeout", "MFA not configured",
    "Bypassed by policy"
]

# ================================================================
# AZURE LOG ANALYTICS HTTP DATA COLLECTOR API
# ================================================================

def build_signature(ws_id, key, date, content_length, method, ct, resource):
    """Build HMAC-SHA256 auth signature for Log Analytics API."""
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"{method}\n{content_length}\n{ct}\n{x_headers}\n{resource}"
    decoded_key = base64.b64decode(key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, string_to_hash.encode("utf-8"),
                 digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {ws_id}:{encoded_hash}"


def post_to_log_analytics(body, log_type=LOG_TYPE):
    """Send JSON event array to Log Analytics HTTP Data Collector API."""
    method, ct, resource = "POST", "application/json", "/api/logs"
    rfc1123 = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    sig = build_signature(WORKSPACE_ID, PRIMARY_KEY, rfc1123, len(body), method, ct, resource)
    uri = f"https://{WORKSPACE_ID}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
    headers = {
        "Content-Type": ct, "Authorization": sig,
        "Log-Type": log_type, "x-ms-date": rfc1123,
        "time-generated-field": "EventTimestamp"
    }
    r = requests.post(uri, data=body, headers=headers)
    if r.status_code == 200:
        print(f"  ✅ Posted {len(body)} bytes → '{log_type}_CL'")
    else:
        print(f"  ❌ HTTP {r.status_code}: {r.text}")
    return r.status_code


# ================================================================
# HELPER FUNCTIONS
# ================================================================

def get_location(ip):
    """Get geo data for an IP from our lookup table."""
    return LOCATIONS_DB.get(ip, {"city": "Unknown", "country": "Unknown",
                                  "lat": 0.0, "lon": 0.0})

def haversine_km(lat1, lon1, lat2, lon2):
    """Calculate distance in km between two coordinates."""
    R = 6371  # Earth's radius in km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat/2)**2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon/2)**2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

def make_event(user_info, ip, source, reason, time_offset_sec,
               attack_type, risk, extra=None):
    """Build a single enriched login event dictionary."""
    loc = get_location(ip)
    evt_time = (datetime.datetime.utcnow() -
                datetime.timedelta(seconds=time_offset_sec)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
    evt_hour = (datetime.datetime.utcnow() -
                datetime.timedelta(seconds=time_offset_sec)).hour

    event = {
        "EventTimestamp":       evt_time,
        "SourceSystem":         source,
        "UserPrincipalName":    user_info["upn"],
        "Department":           user_info["dept"],
        "IsHighValueTarget":    str(user_info["hvt"]),
        "SourceIPAddress":      ip,
        "City":                 loc["city"],
        "Country":              loc["country"],
        "Latitude":             loc["lat"],
        "Longitude":            loc["lon"],
        "LoginResult":          "Failure",
        "FailureReason":        reason,
        "ApplicationName":      random.choice(APPLICATIONS),
        "DeviceInfo":           random.choice(DEVICES),
        "MFAStatus":            random.choice(MFA_STATUSES),
        "SessionId":            str(uuid.uuid4())[:8],
        "RiskLevel":            risk,
        "AttackType":           attack_type,
        "LoginHour":            evt_hour,
        "FailureCode":          random.choice(["50126","50053","50057","53003"]),
    }
    if extra:
        event.update(extra)
    return event


# ================================================================
# ATTACK SCENARIO GENERATORS (7 Scenarios)
# ================================================================

def gen_brute_force(count=20):
    """BRUTE FORCE: One IP hammers one user repeatedly."""
    print("\n🔴 BRUTE FORCE — Single IP → Single User")
    user = random.choice([u for u in USERS if u["hvt"]])
    ip = random.choice(ATTACKER_IPS)
    events = [make_event(user, ip, random.choice(["EntraID","OnPremAD"]),
              "Invalid password", random.randint(0,600),
              "BruteForce", "High") for _ in range(count)]
    print(f"  → Target: {user['upn']} | IP: {ip} | Events: {count}")
    return events


def gen_password_spray(count=25):
    """PASSWORD SPRAY: One IP tries many users with common password."""
    print("\n🟠 PASSWORD SPRAY — Single IP → Many Users")
    ip = random.choice(ATTACKER_IPS)
    targets = random.sample(USERS, min(count, len(USERS)))
    events = [make_event(targets[i % len(targets)], ip, "EntraID",
              "Invalid password", random.randint(0,900),
              "PasswordSpray", "High") for i in range(count)]
    print(f"  → IP: {ip} | Users targeted: {len(targets)} | Events: {count}")
    return events


def gen_credential_stuffing(count=20):
    """CREDENTIAL STUFFING: Many IPs target one user (botnet/proxy)."""
    print("\n🟡 CREDENTIAL STUFFING — Many IPs → Single User")
    user = random.choice([u for u in USERS if u["hvt"]])
    ips = random.sample(ATTACKER_IPS, min(5, len(ATTACKER_IPS)))
    events = [make_event(user, random.choice(ips),
              random.choice(SOURCE_SYSTEMS),
              random.choice(["Invalid password","Expired credentials"]),
              random.randint(0,600), "CredentialStuffing", "Critical")
              for _ in range(count)]
    print(f"  → Target: {user['upn']} | IPs: {len(ips)} | Events: {count}")
    return events


def gen_impossible_travel(count=10):
    """
    ★ IMPOSSIBLE TRAVEL: Same user logs in from two distant cities
    within minutes — physically impossible. This is a KEY differentiator
    that most teams won't implement.

    Example: User logs in from Mumbai (India) then Moscow (Russia)
    5 minutes later. Distance: ~4500km. Speed needed: ~54,000 km/h!
    """
    print("\n🌍 IMPOSSIBLE TRAVEL — Same User, Distant Locations, Short Gap")
    user = random.choice(USERS)

    # Pick two geographically distant IPs
    travel_pairs = [
        ("10.0.0.55", "185.220.101.34"),   # Pune → Moscow (~4500km)
        ("172.16.0.105", "103.75.190.11"), # Mumbai → Beijing (~3800km)
        ("10.0.1.10", "45.33.32.156"),     # Hyderabad → Fremont (~14000km)
        ("10.0.0.55", "198.51.100.23"),    # Pune → Lagos (~6400km)
    ]

    events = []
    for i in range(0, count, 2):
        ip1, ip2 = random.choice(travel_pairs)
        loc1, loc2 = get_location(ip1), get_location(ip2)
        dist = haversine_km(loc1["lat"], loc1["lon"], loc2["lat"], loc2["lon"])

        # Login 1: Normal location, T minutes ago
        base_offset = random.randint(60, 300)
        events.append(make_event(user, ip1, "EntraID", "Invalid password",
                      base_offset, "ImpossibleTravel", "Critical",
                      {"TravelDistanceKm": round(dist, 1),
                       "TravelTimeMin": 5,
                       "RequiredSpeedKmh": round(dist / (5/60), 0)}))

        # Login 2: Distant location, only 5 minutes later
        events.append(make_event(user, ip2, "EntraID", "Invalid password",
                      base_offset - 300, "ImpossibleTravel", "Critical",
                      {"TravelDistanceKm": round(dist, 1),
                       "TravelTimeMin": 5,
                       "RequiredSpeedKmh": round(dist / (5/60), 0)}))

    print(f"  → User: {user['upn']} | Pairs: {count//2} | Distances: 3800-14000 km")
    return events


def gen_off_hours(count=15):
    """
    ★ OFF-HOURS ANOMALY: Logins at unusual times (2-5 AM).
    Normal business hours are 8 AM - 7 PM IST.
    Off-hours logins are a strong indicator of compromised accounts.
    """
    print("\n🌙 OFF-HOURS ANOMALY — Logins at 2-5 AM")
    events = []
    for i in range(count):
        user = random.choice(USERS)
        # Force login hour to be between 2-5 AM (off-hours)
        off_hour = random.randint(2, 5)
        now = datetime.datetime.utcnow()
        # Calculate offset to reach the target off-hour
        target = now.replace(hour=off_hour, minute=random.randint(0,59),
                            second=random.randint(0,59))
        if target > now:
            target -= datetime.timedelta(days=1)
        offset = int((now - target).total_seconds())

        events.append(make_event(user, random.choice(ATTACKER_IPS),
                      random.choice(SOURCE_SYSTEMS),
                      random.choice(FAILURE_REASONS),
                      offset, "OffHoursAnomaly", "High",
                      {"IsOffHours": "True",
                       "NormalHoursStart": 8,
                       "NormalHoursEnd": 19}))
    print(f"  → Users: various | Hours: 2-5 AM | Events: {count}")
    return events


def gen_account_enumeration(count=20):
    """
    ★ ACCOUNT ENUMERATION: Rapid attempts with non-existent usernames.
    Attackers try common usernames to discover valid accounts.
    """
    print("\n🔍 ACCOUNT ENUMERATION — Non-existent Usernames")
    ip = random.choice(ATTACKER_IPS)
    events = []
    for i in range(count):
        fake_user = {"upn": random.choice(FAKE_USERS), "dept": "Unknown", "hvt": False}
        events.append(make_event(fake_user, ip, "EntraID",
                      "Invalid username", random.randint(0, 300),
                      "AccountEnumeration", "Medium"))
    print(f"  → IP: {ip} | Fake users tried: {len(FAKE_USERS)} | Events: {count}")
    return events


def gen_normal(count=15):
    """NORMAL BASELINE: Random scattered failures (everyday typos)."""
    print("\n🟢 NORMAL — Baseline noise (should NOT trigger alerts)")
    events = [make_event(random.choice(USERS), random.choice(INTERNAL_IPS),
              random.choice(SOURCE_SYSTEMS),
              random.choice(["Invalid password","MFA challenge failed"]),
              random.randint(0, 1800), "None", "Low")
              for _ in range(count)]
    print(f"  → Scattered across users/IPs | Events: {count}")
    return events


def gen_mixed_pro(count=120):
    """
    ★ MIXED PRO: All 7 scenarios combined — the BEST dataset for demo.
    Creates the most realistic and challenging dataset for the detection
    engine. This is what you should run before your demo video.
    """
    print("\n🏆 MIXED PRO — All 7 attack scenarios + baseline noise")
    n = count
    events = []
    events.extend(gen_brute_force(n // 7))
    events.extend(gen_password_spray(n // 7))
    events.extend(gen_credential_stuffing(n // 7))
    events.extend(gen_impossible_travel(max(2, n // 10)))
    events.extend(gen_off_hours(n // 7))
    events.extend(gen_account_enumeration(n // 7))
    events.extend(gen_normal(n - len(events)))
    random.shuffle(events)
    print(f"\n📊 Total events generated: {len(events)}")
    return events


# ================================================================
# MAIN
# ================================================================
def main():
    parser = argparse.ArgumentParser(
        description="AuthGuard Pro v2.0 — Enhanced Simulator")
    parser.add_argument("--scenario",
        choices=["brute_force","password_spray","credential_stuffing",
                 "impossible_travel","off_hours","account_enumeration",
                 "normal","mixed_pro"],
        default="mixed_pro")
    parser.add_argument("--count", type=int, default=120)
    args = parser.parse_args()

    if "PASTE_YOUR" in WORKSPACE_ID:
        print("❌ Update WORKSPACE_ID and PRIMARY_KEY first!")
        sys.exit(1)

    print("=" * 60)
    print("🛡️  AuthGuard Pro v2.0 — Enhanced Simulator")
    print("   Team ShieldOps | Hack2Future 2026")
    print(f"   Scenario: {args.scenario} | Count: {args.count}")
    print("=" * 60)

    scenarios = {
        "brute_force": gen_brute_force,
        "password_spray": gen_password_spray,
        "credential_stuffing": gen_credential_stuffing,
        "impossible_travel": gen_impossible_travel,
        "off_hours": gen_off_hours,
        "account_enumeration": gen_account_enumeration,
        "normal": gen_normal,
        "mixed_pro": gen_mixed_pro,
    }

    events = scenarios[args.scenario](args.count)

    # Send in batches
    batch_size = 200
    total = 0
    print(f"\n📤 Sending {len(events)} events...")
    for i in range(0, len(events), batch_size):
        batch = events[i:i+batch_size]
        if post_to_log_analytics(json.dumps(batch)) == 200:
            total += len(batch)
        time.sleep(1)

    print(f"\n{'='*60}")
    print(f"✅ SENT: {total}/{len(events)} events")
    print(f"⏱️  Data appears in ~3-5 minutes")
    print(f"📊 Table: {LOG_TYPE}_CL")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
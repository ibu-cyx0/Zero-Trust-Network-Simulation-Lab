"""
Zero Trust Policy Engine
Identity-Aware Access Control with Continuous Verification
Author: Mohamed Ibrahim H
"""

import json
import hashlib
import os
from datetime import datetime, timezone

POLICY_DIR = os.path.dirname(__file__)
LOG_FILE   = os.path.join(os.path.dirname(__file__), "..", "monitor", "access_log.json")

# ── ZERO TRUST POLICIES ───────────────────────────────────────────────────────
# Rule: Never trust, always verify
# Every request must prove: WHO + WHAT DEVICE + FROM WHERE + WHEN

POLICIES = {
    "allow_rules": [
        {
            "id": "ZT-001",
            "name": "SOC Analyst — Splunk Access",
            "user_role":    "soc_analyst",
            "resource":     "splunk_dashboard",
            "allowed_ips":  ["10.0.1.0/24"],
            "mfa_required": True,
            "hours":        [8, 20],
            "device_trust": "managed",
            "action":       "ALLOW"
        },
        {
            "id": "ZT-002",
            "name": "Admin — Server SSH",
            "user_role":    "admin",
            "resource":     "ssh_server",
            "allowed_ips":  ["10.0.1.10"],
            "mfa_required": True,
            "hours":        [7, 19],
            "device_trust": "managed",
            "action":       "ALLOW"
        },
        {
            "id": "ZT-003",
            "name": "Developer — Dev Server",
            "user_role":    "developer",
            "resource":     "dev_server",
            "allowed_ips":  ["10.0.2.0/24"],
            "mfa_required": True,
            "hours":        [6, 22],
            "device_trust": "managed",
            "action":       "ALLOW"
        },
    ],
    "deny_rules": [
        {"id": "ZT-D001", "name": "Block All External by Default",  "src": "external", "action": "DENY"},
        {"id": "ZT-D002", "name": "Block Unmanaged Devices",        "device_trust": "unmanaged", "action": "DENY"},
        {"id": "ZT-D003", "name": "Block After-Hours Admin Access", "user_role": "admin", "hours_after": 19, "action": "DENY"},
        {"id": "ZT-D004", "name": "Block Lateral Movement",        "src_zone": "dmz", "dst_zone": "internal", "action": "DENY"},
    ]
}

# ── SIMULATED USERS ───────────────────────────────────────────────────────────
USERS = {
    "ibrahim.soc":  {"role": "soc_analyst",  "mfa": True,  "device": "managed"},
    "admin.root":   {"role": "admin",         "mfa": True,  "device": "managed"},
    "dev.user1":    {"role": "developer",     "mfa": True,  "device": "managed"},
    "unknown.user": {"role": "guest",         "mfa": False, "device": "unmanaged"},
    "attacker":     {"role": "guest",         "mfa": False, "device": "unmanaged"},
}

def now_utc():
    return datetime.now(timezone.utc).isoformat()

def ip_in_range(ip, cidr):
    """Simple CIDR check."""
    try:
        if "/" not in cidr:
            return ip == cidr
        net, bits = cidr.split("/")
        bits = int(bits)
        def ip2int(a): return sum(int(x)<<(24-8*i) for i,x in enumerate(a.split(".")))
        mask = (0xFFFFFFFF << (32-bits)) & 0xFFFFFFFF
        return (ip2int(ip) & mask) == (ip2int(net) & mask)
    except:
        return False

def evaluate_request(username, resource, src_ip, hour=None):
    """
    Zero Trust evaluation: every request is denied by default.
    Must explicitly match an allow rule with all conditions satisfied.
    """
    hour = hour or datetime.now(timezone.utc).hour
    user = USERS.get(username, {"role": "unknown", "mfa": False, "device": "unmanaged"})

    result = {
        "timestamp":   now_utc(),
        "username":    username,
        "user_role":   user["role"],
        "resource":    resource,
        "src_ip":      src_ip,
        "hour":        hour,
        "mfa":         user["mfa"],
        "device":      user["device"],
        "verdict":     "DENY",
        "rule_matched": "ZT-DEFAULT-DENY",
        "reason":      "No matching allow rule — Zero Trust default deny",
        "risk_score":  100,
    }

    # Check deny rules first
    if user["device"] == "unmanaged":
        result.update({"verdict":"DENY","rule_matched":"ZT-D002","reason":"Unmanaged device — denied","risk_score":95})
        log_event(result); return result

    # Check allow rules
    for rule in POLICIES["allow_rules"]:
        if rule["user_role"] != user["role"]: continue
        if rule["resource"]  != resource:     continue
        if rule["mfa_required"] and not user["mfa"]:
            result.update({"reason":"MFA not satisfied","rule_matched":rule["id"],"risk_score":80})
            log_event(result); return result
        if rule["device_trust"] != user["device"]:
            result.update({"reason":"Device not trusted","rule_matched":rule["id"],"risk_score":85})
            log_event(result); return result

        ip_ok = any(ip_in_range(src_ip, allowed) for allowed in rule["allowed_ips"])
        if not ip_ok:
            result.update({"reason":f"IP {src_ip} not in allowed range","rule_matched":rule["id"],"risk_score":75})
            log_event(result); return result

        h_min, h_max = rule["hours"]
        if not (h_min <= hour <= h_max):
            result.update({"verdict":"DENY","reason":f"Outside allowed hours ({h_min}:00–{h_max}:00)","rule_matched":rule["id"],"risk_score":70})
            log_event(result); return result

        # All checks passed
        result.update({"verdict":"ALLOW","rule_matched":rule["id"],"reason":f"All Zero Trust checks passed — {rule['name']}","risk_score":5})
        log_event(result); return result

    log_event(result)
    return result

def log_event(event):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            try: logs = json.load(f)
            except: logs = []
    logs.append(event)
    with open(LOG_FILE, "w") as f:
        json.dump(logs[-500:], f, indent=2)

def simulate_access_events():
    """Simulate realistic Zero Trust access events."""
    events = [
        ("ibrahim.soc",  "splunk_dashboard", "10.0.1.15",  9,  "Normal SOC analyst login"),
        ("admin.root",   "ssh_server",       "10.0.1.10",  8,  "Admin SSH during hours"),
        ("unknown.user", "splunk_dashboard", "192.168.1.5",14,  "Unknown user attempt"),
        ("attacker",     "ssh_server",       "45.142.212.100",3,"External brute force"),
        ("dev.user1",    "dev_server",       "10.0.2.20",  11,  "Developer access"),
        ("admin.root",   "ssh_server",       "10.0.1.10",  22,  "After-hours admin (blocked)"),
        ("ibrahim.soc",  "ssh_server",       "10.0.1.15",  10,  "Analyst accessing wrong resource"),
        ("dev.user1",    "splunk_dashboard", "10.0.2.20",  13,  "Dev accessing SIEM (blocked)"),
        ("admin.root",   "ssh_server",       "10.0.1.10",  9,   "Admin normal hours"),
        ("attacker",     "dev_server",       "185.220.101.47",2, "APT lateral movement attempt"),
    ]

    print("\n── Zero Trust Access Evaluation ─────────────────────────────")
    results = []
    for username, resource, ip, hour, desc in events:
        r = evaluate_request(username, resource, ip, hour)
        icon = "✅ ALLOW" if r["verdict"] == "ALLOW" else "🔴 DENY "
        print(f"  {icon} | {desc}")
        print(f"         User: {username} | IP: {ip} | Rule: {r['rule_matched']}")
        print(f"         Reason: {r['reason']}\n")
        results.append(r)

    allowed = sum(1 for r in results if r["verdict"]=="ALLOW")
    denied  = sum(1 for r in results if r["verdict"]=="DENY")
    print(f"── Summary: {allowed} ALLOWED | {denied} DENIED ──────────────────────")
    return results

if __name__ == "__main__":
    print("="*60)
    print("  ZERO TRUST POLICY ENGINE  |  Mohamed Ibrahim H")
    print("="*60)
    simulate_access_events()
    print(f"\n[✓] Access log saved → monitor/access_log.json")

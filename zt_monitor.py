"""
Zero Trust Continuous Monitor
Real-time anomaly detection and risk scoring
Simulates Wazuh SIEM alert integration
Author: Mohamed Ibrahim H
"""

import json
import os
import random
from datetime import datetime, timezone

MONITOR_DIR = os.path.dirname(__file__)
LOG_FILE    = os.path.join(MONITOR_DIR, "access_log.json")
ALERT_FILE  = os.path.join(MONITOR_DIR, "alerts.json")

ALERT_RULES = [
    {"id":"MON-001","name":"Brute Force Detected",      "condition":"failed_logins>=5",  "severity":"CRITICAL","score":95},
    {"id":"MON-002","name":"After-Hours Access",        "condition":"hour_outside_range", "severity":"HIGH",    "score":75},
    {"id":"MON-003","name":"External IP Access Attempt","condition":"external_ip",        "severity":"HIGH",    "score":80},
    {"id":"MON-004","name":"Unmanaged Device",          "condition":"unmanaged_device",   "severity":"HIGH",    "score":85},
    {"id":"MON-005","name":"Privilege Escalation",      "condition":"wrong_resource",     "severity":"MEDIUM",  "score":60},
    {"id":"MON-006","name":"Lateral Movement Attempt",  "condition":"lateral_movement",   "severity":"CRITICAL","score":98},
]

def now_utc():
    return datetime.now(timezone.utc).isoformat()

def generate_live_events():
    """Generate realistic network events for continuous monitoring."""
    return [
        {"time":now_utc(),"src_ip":"10.0.1.15","dst":"splunk_dashboard","user":"ibrahim.soc","action":"ALLOW","type":"normal","zone":"internal"},
        {"time":now_utc(),"src_ip":"45.142.212.100","dst":"ssh_server","user":"unknown","action":"DENY","type":"brute_force","zone":"external","failed_attempts":47},
        {"time":now_utc(),"src_ip":"10.0.1.10","dst":"ssh_server","user":"admin.root","action":"ALLOW","type":"normal","zone":"internal"},
        {"time":now_utc(),"src_ip":"185.220.101.47","dst":"dev_server","user":"attacker","action":"DENY","type":"lateral_movement","zone":"external"},
        {"time":now_utc(),"src_ip":"10.0.2.20","dst":"splunk_dashboard","user":"dev.user1","action":"DENY","type":"wrong_resource","zone":"internal"},
        {"time":now_utc(),"src_ip":"10.0.1.10","dst":"ssh_server","user":"admin.root","action":"DENY","type":"after_hours","zone":"internal","hour":22},
        {"time":now_utc(),"src_ip":"192.168.1.99","dst":"dev_server","user":"unknown.user","action":"DENY","type":"unmanaged","zone":"guest"},
        {"time":now_utc(),"src_ip":"10.0.2.21","dst":"dev_server","user":"dev.user1","action":"ALLOW","type":"normal","zone":"internal"},
    ]

def analyze_events(events):
    """Correlate events and generate Wazuh-style alerts."""
    alerts = []
    for event in events:
        matched_rules = []

        if event.get("failed_attempts", 0) >= 5 or event.get("type") == "brute_force":
            matched_rules.append(ALERT_RULES[0])
        if event.get("type") == "after_hours":
            matched_rules.append(ALERT_RULES[1])
        if event.get("zone") == "external" and event["action"] == "DENY":
            matched_rules.append(ALERT_RULES[2])
        if event.get("type") == "unmanaged":
            matched_rules.append(ALERT_RULES[3])
        if event.get("type") == "wrong_resource":
            matched_rules.append(ALERT_RULES[4])
        if event.get("type") == "lateral_movement":
            matched_rules.append(ALERT_RULES[5])

        for rule in matched_rules:
            alerts.append({
                "alert_id":   f"ZT-ALERT-{len(alerts)+1:04d}",
                "rule_id":    rule["id"],
                "rule_name":  rule["name"],
                "severity":   rule["severity"],
                "risk_score": rule["score"],
                "src_ip":     event["src_ip"],
                "user":       event["user"],
                "resource":   event["dst"],
                "action":     event["action"],
                "zone":       event.get("zone","unknown"),
                "timestamp":  event["time"],
                "mitre_tactic": get_mitre(rule["id"]),
            })

    # Save alerts
    os.makedirs(MONITOR_DIR, exist_ok=True)
    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)

    return alerts

def get_mitre(rule_id):
    mapping = {
        "MON-001": "T1110 — Brute Force",
        "MON-002": "T1078 — Valid Accounts (Off-hours)",
        "MON-003": "T1133 — External Remote Services",
        "MON-004": "T1200 — Hardware Additions",
        "MON-005": "T1078 — Valid Accounts (Misuse)",
        "MON-006": "T1021 — Remote Services (Lateral Movement)",
    }
    return mapping.get(rule_id, "Unknown")

def run_monitor():
    print("\n" + "="*60)
    print("  ZERO TRUST MONITOR  |  Mohamed Ibrahim H")
    print("="*60)

    events = generate_live_events()
    alerts = analyze_events(events)

    print(f"\n[*] Analyzed {len(events)} events → {len(alerts)} alerts fired\n")
    sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for a in alerts:
        sev[a["severity"]] = sev.get(a["severity"],0)+1
        icon = "🔴" if a["severity"]=="CRITICAL" else "🟠" if a["severity"]=="HIGH" else "🟡"
        print(f"  {icon} [{a['severity']:<8}] {a['rule_name']}")
        print(f"     MITRE: {a['mitre_tactic']}")
        print(f"     User: {a['user']} | IP: {a['src_ip']} | Score: {a['risk_score']}/100\n")

    print(f"── Alert Summary ────────────────────────────")
    for s,c in sev.items():
        if c: print(f"  {s:<10}: {c}")
    print(f"[✓] Alerts saved → monitor/alerts.json")
    return alerts

if __name__ == "__main__":
    run_monitor()

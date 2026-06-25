"""
Zero Trust Network Simulation Lab — Main Runner
Author: Mohamed Ibrahim H
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from policies.policy_engine import simulate_access_events
from monitor.zt_monitor import run_monitor
from scripts.segmentation import run as run_segmentation

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     ZERO TRUST NETWORK SIMULATION LAB  v1.0                 ║
║     Never Trust. Always Verify. | Mohamed Ibrahim H          ║
╚══════════════════════════════════════════════════════════════╝
    """)
    print("► STEP 1: Network Segmentation & pfSense Rules")
    run_segmentation()

    print("\n► STEP 2: Zero Trust Policy Engine")
    events = simulate_access_events()

    print("\n► STEP 3: Continuous Monitoring & Alerts")
    alerts = run_monitor()

    allowed = sum(1 for e in events if e.get("verdict")=="ALLOW")
    denied  = sum(1 for e in events if e.get("verdict")=="DENY")
    crits   = sum(1 for a in alerts if a.get("severity")=="CRITICAL")

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  ✓  Network Zones    : 4 isolated segments                  ║
║  ✓  Firewall Rules   : 13 micro-segmentation rules          ║
║  ✓  Access Requests  : {len(events)} evaluated                           ║
║  ✓  Allowed          : {allowed}  |  Denied: {denied}                      ║
║  ✓  Critical Alerts  : {crits}                                        ║
║  ✓  Dashboard        : dashboard/index.html                 ║
╚══════════════════════════════════════════════════════════════╝
    """)

if __name__ == "__main__":
    main()

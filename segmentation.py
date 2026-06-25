"""
Zero Trust Network Segmentation
Generates pfSense firewall rules + network topology
Implements micro-segmentation per Zero Trust model
Author: Mohamed Ibrahim H
"""

import json
import os

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "docs")

# ── NETWORK ZONES ─────────────────────────────────────────────────────────────
ZONES = {
    "INTERNET":  {"subnet": "0.0.0.0/0",     "trust": 0,   "color": "#ff3860"},
    "DMZ":       {"subnet": "10.0.0.0/24",   "trust": 10,  "color": "#ff8c00"},
    "SOC_NET":   {"subnet": "10.0.1.0/24",   "trust": 80,  "color": "#00d4ff"},
    "DEV_NET":   {"subnet": "10.0.2.0/24",   "trust": 70,  "color": "#7c3aed"},
    "MGMT_NET":  {"subnet": "10.0.3.0/24",   "trust": 90,  "color": "#00ff88"},
    "GUEST_NET": {"subnet": "192.168.1.0/24","trust": 5,   "color": "#ffd600"},
}

# ── HOSTS ─────────────────────────────────────────────────────────────────────
HOSTS = [
    {"name":"pfsense-fw",    "ip":"10.0.0.1",  "zone":"DMZ",      "role":"Firewall/Router"},
    {"name":"wazuh-siem",    "ip":"10.0.1.5",  "zone":"SOC_NET",  "role":"SIEM Server"},
    {"name":"splunk-server", "ip":"10.0.1.10", "zone":"SOC_NET",  "role":"Splunk Enterprise"},
    {"name":"soc-workstation","ip":"10.0.1.15","zone":"SOC_NET",  "role":"Analyst Workstation"},
    {"name":"dev-server",    "ip":"10.0.2.10", "zone":"DEV_NET",  "role":"Dev Server"},
    {"name":"dev-ws-1",      "ip":"10.0.2.20", "zone":"DEV_NET",  "role":"Dev Workstation"},
    {"name":"mgmt-server",   "ip":"10.0.3.5",  "zone":"MGMT_NET", "role":"Admin Server"},
    {"name":"guest-laptop",  "ip":"192.168.1.10","zone":"GUEST_NET","role":"Guest Device"},
]

# ── PFSENSE FIREWALL RULES ────────────────────────────────────────────────────
FIREWALL_RULES = [
    # Default deny all
    {"id":"FW-000","action":"block","src":"any","dst":"any","proto":"any","desc":"Default deny all — Zero Trust baseline"},

    # Internet → DMZ only (limited)
    {"id":"FW-001","action":"pass","src":"!RFC1918","dst":"10.0.0.0/24","proto":"tcp","port":"443","desc":"HTTPS inbound to DMZ only"},

    # SOC Net rules
    {"id":"FW-010","action":"pass","src":"10.0.1.0/24","dst":"10.0.1.10","proto":"tcp","port":"8000,8089","desc":"SOC → Splunk web + API"},
    {"id":"FW-011","action":"pass","src":"10.0.1.0/24","dst":"10.0.1.5","proto":"tcp","port":"1514,55000","desc":"SOC → Wazuh manager"},
    {"id":"FW-012","action":"block","src":"10.0.1.0/24","dst":"10.0.2.0/24","proto":"any","desc":"SOC → Dev: block lateral movement"},
    {"id":"FW-013","action":"block","src":"10.0.1.0/24","dst":"10.0.3.0/24","proto":"any","desc":"SOC → MGMT: block (not needed)"},

    # Admin (MGMT) rules
    {"id":"FW-020","action":"pass","src":"10.0.3.5","dst":"any","proto":"tcp","port":"22","desc":"Admin SSH to all — time-restricted"},
    {"id":"FW-021","action":"pass","src":"10.0.3.5","dst":"10.0.1.5","proto":"tcp","port":"55000","desc":"Admin → Wazuh API"},

    # Dev Net rules
    {"id":"FW-030","action":"pass","src":"10.0.2.0/24","dst":"10.0.2.10","proto":"tcp","port":"22,80,443","desc":"Dev → Dev Server"},
    {"id":"FW-031","action":"block","src":"10.0.2.0/24","dst":"10.0.1.0/24","proto":"any","desc":"Dev → SOC: block (micro-seg)"},
    {"id":"FW-032","action":"block","src":"10.0.2.0/24","dst":"10.0.3.0/24","proto":"any","desc":"Dev → MGMT: block"},

    # Guest Net — highly restricted
    {"id":"FW-040","action":"pass","src":"192.168.1.0/24","dst":"!RFC1918","proto":"tcp","port":"80,443","desc":"Guest → Internet only"},
    {"id":"FW-041","action":"block","src":"192.168.1.0/24","dst":"10.0.0.0/8","proto":"any","desc":"Guest → Internal: BLOCK ALL"},
]

def generate_pfsense_xml():
    """Generate pfSense-compatible firewall rule export."""
    rules_xml = '<?xml version="1.0"?>\n<pfsense>\n  <filter>\n'
    for r in FIREWALL_RULES:
        act = "pass" if r["action"]=="pass" else "block"
        rules_xml += f"""    <rule>
      <id>{r['id']}</id>
      <type>{act}</type>
      <source><address>{r['src']}</address></source>
      <destination><address>{r['dst']}</address></destination>
      <protocol>{r['proto']}</protocol>
      <descr>{r['desc']}</descr>
    </rule>\n"""
    rules_xml += '  </filter>\n</pfsense>'
    return rules_xml

def print_topology():
    print("\n── Zero Trust Network Topology ──────────────────────────────")
    print("""
  ┌─────────────────────────────────────────────────────────┐
  │                      INTERNET                           │
  │                   (Trust Level: 0)                      │
  └──────────────────────────┬──────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │   pfSense FW    │  ← 10.0.0.1
                    │  (DMZ Gateway)  │
                    └────────┬────────┘
          ┌──────────┬───────┴────────┬──────────┐
          │          │                │          │
   ┌──────▼──┐  ┌────▼────┐  ┌───────▼──┐  ┌───▼──────┐
   │ SOC_NET │  │ DEV_NET │  │ MGMT_NET │  │ GUEST    │
   │10.0.1/24│  │10.0.2/24│  │10.0.3/24 │  │192.168/24│
   │Trust:80 │  │Trust:70 │  │Trust:90  │  │Trust:5   │
   └─────────┘  └─────────┘  └──────────┘  └──────────┘
   Splunk       Dev Server    Admin Mgmt    Internet Only
   Wazuh        Dev WS        SSH Bastion   No Internal
   SOC-WS                                  Access
    """)

def run():
    print("="*60)
    print("  ZERO TRUST SEGMENTATION  |  Mohamed Ibrahim H")
    print("="*60)
    print_topology()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Save rules
    with open(os.path.join(OUTPUT_DIR,"firewall_rules.json"),"w") as f:
        json.dump(FIREWALL_RULES, f, indent=2)

    with open(os.path.join(OUTPUT_DIR,"network_zones.json"),"w") as f:
        json.dump({"zones":ZONES,"hosts":HOSTS}, f, indent=2)

    xml = generate_pfsense_xml()
    with open(os.path.join(OUTPUT_DIR,"pfsense_rules.xml"),"w") as f:
        f.write(xml)

    print(f"\n[✓] {len(FIREWALL_RULES)} firewall rules generated")
    print(f"[✓] {len(ZONES)} network zones defined")
    print(f"[✓] pfSense XML export → docs/pfsense_rules.xml")
    print(f"[✓] Network zones → docs/network_zones.json")

if __name__ == "__main__":
    run()

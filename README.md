# 🔐 Zero Trust Network Simulation Lab

> **Identity-Aware Micro-Segmentation with Continuous Verification**  
> *pfSense · Wazuh · VirtualBox · Python Policy Engine*

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![pfSense](https://img.shields.io/badge/pfSense-Firewall-darkblue?logo=pfsense&logoColor=white)
![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-00d4aa)
![NIST](https://img.shields.io/badge/NIST-800--207-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📌 Overview

A fully functional **Zero Trust Network Architecture (ZTNA)** simulation built with VirtualBox VMs, pfSense firewall, and Wazuh SIEM. Implements the **NIST SP 800-207** Zero Trust standard with:

> **"Never Trust. Always Verify."** — Every request is denied by default, then verified against identity, device posture, IP, time, and MFA before access is granted.

---

## 🏗️ Network Architecture

```
                        ┌─────────────────────┐
                        │       INTERNET       │
                        │     Trust Level: 0   │
                        └──────────┬──────────┘
                                   │
                          ┌────────▼────────┐
                          │   pfSense FW    │  10.0.0.1
                          │  Default: DENY  │  ← All traffic
                          └────────┬────────┘
           ┌──────────┬────────────┴───────────┬──────────┐
           │          │                        │          │
    ┌──────▼──┐  ┌────▼────┐  ┌───────────────▼──┐  ┌───▼──────┐
    │ SOC_NET │  │ DEV_NET │  │     MGMT_NET      │  │ GUEST    │
    │10.0.1/24│  │10.0.2/24│  │    10.0.3/24      │  │192.168/24│
    │Trust:80 │  │Trust:70 │  │    Trust:90       │  │Trust:5   │
    └─────────┘  └─────────┘  └───────────────────┘  └──────────┘
    Splunk        Dev Server    Admin/SSH Bastion      Internet
    Wazuh         Dev WS        Management Only        Only
    SOC WS
```

---

## 🖥️ VM Setup (VirtualBox)

| VM | OS | IP | Role |
|---|---|---|---|
| **pfsense-fw** | pfSense 2.7 | 10.0.0.1 | Firewall / Router |
| **wazuh-siem** | Ubuntu 22.04 | 10.0.1.5 | Wazuh SIEM Server |
| **splunk-server** | Ubuntu 22.04 | 10.0.1.10 | Splunk Enterprise |
| **soc-workstation** | Ubuntu 22.04 | 10.0.1.15 | SOC Analyst WS |
| **dev-server** | Ubuntu 22.04 | 10.0.2.10 | Dev Server |
| **mgmt-server** | Ubuntu 22.04 | 10.0.3.5 | Admin Bastion |

---

## 📁 Project Structure

```
zero-trust-lab/
├── policies/
│   └── policy_engine.py         # Zero Trust access evaluator
├── monitor/
│   ├── zt_monitor.py            # Wazuh-style alert correlation
│   ├── access_log.json          # All access events (auto-generated)
│   └── alerts.json              # Fired alerts (auto-generated)
├── scripts/
│   └── segmentation.py          # Network zone + pfSense rule generator
├── docs/
│   ├── pfsense_rules.xml        # pfSense firewall export
│   ├── firewall_rules.json      # All 13 micro-segmentation rules
│   └── network_zones.json       # Zone definitions + host inventory
├── dashboard/
│   └── index.html               # Live ZT monitoring dashboard
├── main.py                      # Full pipeline runner
└── README.md
```

---

## ⚙️ Setup & Run

```bash
git clone https://github.com/ibu-cyx0/zero-trust-lab
cd zero-trust-lab
pip install -r requirements.txt

# Run full simulation
python main.py

# Open dashboard
open dashboard/index.html
```

---

## 🔐 Zero Trust Policy Engine

Every access request is evaluated against **5 conditions** — all must pass:

```python
# Evaluation order (deny-first)
1. Device Trust    → Is this a managed/corporate device?
2. MFA Status      → Has the user authenticated with MFA?
3. User Role       → Does this role have access to this resource?
4. Source IP       → Is the IP in the allowed subnet for this resource?
5. Time Window     → Is access within allowed hours?

# Result
→ ALL PASS  : ALLOW (log event, low risk score)
→ ANY FAIL  : DENY  (log event, high risk score, alert if suspicious)
```

---

## 🛡️ pfSense Firewall Rules (13 Rules)

| Rule ID | Action | Source | Destination | Description |
|---|---|---|---|---|
| FW-000 | BLOCK | any | any | Default deny all |
| FW-001 | PASS | Internet | DMZ:443 | HTTPS inbound only |
| FW-010 | PASS | SOC_NET | Splunk:8000 | SOC → Splunk Web |
| FW-012 | BLOCK | SOC_NET | DEV_NET | Block lateral movement |
| FW-020 | PASS | MGMT:3.5 | any:22 | Admin SSH (time-restricted) |
| FW-031 | BLOCK | DEV_NET | SOC_NET | Dev → SOC micro-seg |
| FW-041 | BLOCK | GUEST | 10.0.0.0/8 | Guest → Internal BLOCK |

---

## 🚨 MITRE ATT&CK Detections

| Alert | MITRE Technique | Severity |
|---|---|---|
| Brute Force SSH | T1110 — Brute Force | 🔴 CRITICAL |
| Lateral Movement | T1021 — Remote Services | 🔴 CRITICAL |
| External IP Access | T1133 — External Remote Services | 🟠 HIGH |
| Unmanaged Device | T1200 — Hardware Additions | 🟠 HIGH |
| After-Hours Access | T1078 — Valid Accounts | 🟠 HIGH |
| Privilege Misuse | T1078 — Valid Accounts | 🟡 MEDIUM |

---

## 📊 Results

```
Access Requests Evaluated : 10
Requests Allowed          : 4  (40%)
Requests Denied           : 6  (60%)
Critical Alerts Fired     : 2
Total Alerts              : 7
Firewall Rules Applied    : 13
Network Zones Isolated    : 4
```

---

## 🗺️ Roadmap

- [ ] OpenVPN + certificate-based identity
- [ ] Automated IP blocklist from Wazuh → pfSense
- [ ] LDAP/Active Directory integration
- [ ] Dashboard live Wazuh API integration
- [ ] Automated incident playbook (Python)

---

## 👤 Author

**Mohamed Ibrahim H**  
EC-Council Certified SOC Analyst (CSA) | Splunk Core Certified User | Cisco Cyber Ops Associate

- GitHub: [@ibu-cyx0](https://github.com/ibu-cyx0)
- TryHackMe: [@IbrahimCyb3r4](https://tryhackme.com/p/IbrahimCyb3r4)
- Email: ibrahim.cybrx@gmail.com

---

## 📄 License

MIT License

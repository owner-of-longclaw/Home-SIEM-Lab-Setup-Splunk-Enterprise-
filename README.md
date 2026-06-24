# Home-SIEM-Lab-Setup-Splunk-Enterprise
🛡️ Home SIEM Lab — Splunk Enterprise  Show Image Show Image Show Image Show Image   A hands-on home lab built to simulate real-world SOC operations — ingesting logs from Windows 10 and Ubuntu hosts into Splunk Enterprise, executing live attack scenarios, and building detection queries to identify malicious activity.

📌 Objective

The goal of this lab was to gain practical experience with SIEM operations by deploying Splunk Enterprise in a multi-OS environment, configuring Universal Forwarders on live hosts, and simulating adversarial techniques to detect threats through log analysis and custom SPL queries.

🏗️ Lab Architecture

┌──────────────────────────────────────────────────────┐
│                   Home Lab Network                   │
│                                                      │
│  ┌─────────────────┐      ┌─────────────────┐        │
│  │   Windows 10    │      │     Ubuntu      │        │
│  │  (Endpoint)     │      │  (Endpoint)     │        │
│  │                 │      │                 │        │
│  │ Splunk UF Agent │      │ Splunk UF Agent │        │
│  └────────┬────────┘      └────────┬────────┘        │
│           │                        │                  │
│           └──────────┬─────────────┘                  │
│                      ▼                                │
│          ┌───────────────────────┐                    │
│          │   Splunk Enterprise   │                    │
│          │   (SIEM / Indexer)    │                    │
│          │   Dashboards, Alerts  │                    │
│          │   SPL Query Engine    │                    │
│          └───────────────────────┘                    │
└──────────────────────────────────────────────────────┘


⚙️ Environment Setup

Component        Details 
SIEM Platform :  Splunk Enterprise (local install)
Host 1        :  Windows 10 — Splunk Universal Forwarder
Host 2        :  Ubuntu — Splunk Universal Forwarder
Log Sources   :  Windows Event Logs, Syslog, Auth logs
Data Inputs   :  WinEventLog, monitor stanza (Ubuntu)





























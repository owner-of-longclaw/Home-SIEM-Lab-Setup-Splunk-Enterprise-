 
# 🛡️ Home SIEM Lab — Splunk Enterprise

![Splunk](https://img.shields.io/badge/Splunk-Enterprise-black?style=flat&logo=splunk&logoColor=white)
![Platform](https://img.shields.io/badge/Hosts-Windows%2010%20%7C%20Ubuntu-blue?style=flat)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=flat)
![Focus](https://img.shields.io/badge/Focus-Threat%20Detection%20%7C%20Log%20Analysis-orange?style=flat)

> A hands-on home lab built to simulate real-world SOC operations — ingesting logs from Windows 10 and Ubuntu hosts into Splunk Enterprise, executing live attack scenarios, and building detection queries to identify malicious activity.

---

## 📌 Objective

The goal of this lab was to gain practical experience with SIEM operations by deploying Splunk Enterprise in a multi-OS environment, configuring Universal Forwarders on live hosts, and simulating adversarial techniques to detect threats through log analysis and custom SPL queries.

---

## 🏗️ Lab Architecture

```
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
```

---

## ⚙️ Environment Setup

| Component | Details |
|---|---|
| SIEM Platform | Splunk Enterprise (local install) |
| Host 1 | Windows 10 — Splunk Universal Forwarder |
| Host 2 | Ubuntu — Splunk Universal Forwarder |
| Log Sources | Windows Event Logs, Syslog, Auth logs |
| Data Inputs | WinEventLog, monitor stanza (Ubuntu) |

### Logs Monitored

**Windows 10:**
- Security Event Logs (Event ID 4625 — failed logins, 4688 — process creation)
- PowerShell Script Block Logging
- System & Application logs

**Ubuntu:**
- `/var/log/auth.log` — SSH authentication events
- `/var/log/syslog` — system activity
- `/var/log/kern.log` — kernel messages

---

## ⚔️ Attack Simulations

### 1. SSH Brute-Force Attack

**What was done:**
Simulated a brute-force attack against the Ubuntu host using repeated failed SSH login attempts from an attacker machine. Generated a high volume of authentication failures in `/var/log/auth.log`.

**Detection — SPL Query:**
```spl
index=main sourcetype="linux_secure" "Failed password"
| stats count by src_ip, user
| where count > 10
| sort -count
```

**What to look for:**
- Multiple failed login attempts from a single source IP
- Short time window between attempts (indicates automation)
- Eventual successful login after failures (credential stuffing)

---

### 2. Suspicious PowerShell Execution

**What was done:**
Executed encoded PowerShell commands on the Windows 10 host to simulate a common attacker technique for evading detection — such as downloading a payload or running scripts in memory.

**Detection — SPL Query:**
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
CommandLine="*powershell*" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*bypass*")
| table _time, ComputerName, User, CommandLine
| sort -_time
```

**What to look for:**
- `-EncodedCommand` or `-enc` flags (Base64-encoded payload)
- `-ExecutionPolicy Bypass` flag
- Unusual parent processes spawning PowerShell (e.g. Word, Excel)

---

### 3. Malware Beaconing

**What was done:**
Simulated periodic outbound network connections (beaconing behavior) from the Windows host to mimic malware checking in with a C2 (Command & Control) server at regular intervals.

**Detection — SPL Query:**
```spl
index=main sourcetype="WinEventLog"
| bucket _time span=1m
| stats count by _time, dest_ip, src_ip
| eventstats avg(count) as avg_count, stdev(count) as stdev_count by dest_ip
| where count > (avg_count + stdev_count)
| table _time, src_ip, dest_ip, count, avg_count
```

**What to look for:**
- Regular, periodic connections to the same external IP
- Consistent byte sizes per connection
- Connections occurring at off-hours or fixed intervals

---

## 🔍 Key Skills Demonstrated

- **SIEM Deployment** — Installed and configured Splunk Enterprise with multi-host log ingestion
- **Log Management** — Configured Universal Forwarders, inputs.conf, and props.conf for accurate parsing
- **Threat Detection** — Wrote custom SPL queries to detect brute-force, encoded commands, and beaconing
- **Adversarial Simulation** — Executed live attack scenarios and validated detections against real log data
- **Incident Analysis** — Identified IOCs, anomalous patterns, and mapped findings to MITRE ATT&CK techniques

---

## 🗺️ MITRE ATT&CK Mapping

| Attack Simulated | Tactic | Technique |
|---|---|---|
| SSH Brute-Force | Credential Access | T1110 — Brute Force |
| Encoded PowerShell | Defense Evasion | T1027 — Obfuscated Files or Information |
| Malware Beaconing | Command & Control | T1071 — Application Layer Protocol |

---

## 📚 Key Learnings

- Understood how Universal Forwarders collect and ship logs to a central Splunk indexer
- Gained hands-on experience writing SPL queries for real-world threat patterns
- Learned how attackers evade detection using encoded PowerShell and periodic beaconing
- Practiced correlating events across multiple hosts to build a complete attack picture
- Improved ability to distinguish between noisy but benign activity and genuine IOCs

---

## 🛠️ Tools & Technologies

`Splunk Enterprise` `Universal Forwarder` `SPL` `Windows Event Logs` `Syslog` `PowerShell` `MITRE ATT&CK`

---

## 👤 Author

**Shyam Ravi**
CEH | SOC Aspirant | Splunk SIEM
[LinkedIn](https://linkedin.com/in/) • [GitHub](https://github.com/)

---

> ⚠️ This lab is built purely for educational purposes in a controlled home environment. All attack simulations were performed on systems I own and operate.














# Mini SOC / Threat Detection Lab

A cybersecurity home lab simulating a functional Security Operations Centre (SOC) using Python, Flask, and Linux. Built to detect, record, and respond to real attack patterns in a controlled VirtualBox environment.

## Features

- Real-time log monitoring via continuous `auth.log` parsing
- Multi-pattern threat detection engine (5 attack patterns)
- Structured JSON alert generation with severity classification
- Auto-block attackers via `iptables` on HIGH severity
- State persistence across monitor restarts
- Flask web dashboard with live alert visualization and charts

## Detection Patterns

| Pattern | Description | Severity |
|---|---|---|
| BRUTE_FORCE | Failed SSH password attempts with username tracking | LOW / MEDIUM / HIGH |
| INVALID_USER_PROBE | Attempts targeting non-existent usernames | LOW |
| SUCCESSFUL_LOGIN_AFTER_FAILURES | Critical — attacker gained access after brute force | HIGH |
| SUDO_FAILURE | Failed privilege escalation attempts | MEDIUM |
| NEW_USER_CREATED | Backdoor account creation detected | HIGH |

## Auto-Response

When an IP reaches HIGH severity (6+ failed attempts), the monitor automatically executes:

```bash
sudo iptables -A INPUT -s <ip> -j DROP
```

All traffic from the attacker is silently dropped at the kernel level.

## Technologies

- Python 3
- Flask
- Linux (Ubuntu)
- iptables
- VirtualBox
- Kali Linux (attack simulation)
- Git / GitHub

## Lab Architecture

- **Ubuntu VM** — victim machine running SSH, `live_monitor.py`, and `dashboard.py`
- **Kali Linux VM** — attacker machine for simulating brute force and other attacks
- **Main Desktop** — development environment, VS Code, Git

## Dashboard

Flask web dashboard accessible at `http://127.0.0.1:5000` featuring:

- Live alert table with alert type, IP/user, severity, targeted usernames, and timestamps
- Severity distribution pie chart
- Failed attempts per IP bar chart
- IP address summary table

## Goal

Build hands-on experience with:

- Detection engineering
- Log analysis and parsing
- Security automation and auto-response
- Python scripting
- Linux system security
- SOC workflows and alert triage

# Security Operations Center (SOC) Analyst Alert Investigation Hub

## 🛡️ About This Project

Welcome to the central hub for all alert investigations handled in our SOC Simulation environment using **TryHackMe**. This repository serves as a live **field notebook** for tracking how various alerts are analyzed, categorized, escalated, or dismissed based on real-time threat assessment principles.

---

## 🔍 Role of a SOC Analyst

A **Security Operations Center (SOC) Analyst** is the front-line cyber defender. Their daily responsibilities revolve around:

- Monitoring streams of security alerts from various systems and tools
- Triaging alerts based on severity and business impact
- Investigating suspicious activities using SIEM and threat intelligence tools
- Responding to incidents with clear documentation and escalation
- Communicating with internal teams when real threats are detected

Every day, a SOC Analyst dives into an ocean of logs, behaviors, alerts, and threat reports to detect patterns of compromise.

---

## ⚠️ Nature of Alerts in Daily SOC Life

Alerts are triggered day in and day out — some are **true positives**, others are **false alarms**. It is the analyst's job to:

- Sift through hundreds of these notifications
- Investigate the ones that seem malicious or anomalous
- Decide if they pose a real threat
- Recommend escalation, mitigation, or dismissal

---

## 🚨 Prioritizing Alerts: What Gets Attention First?

Not every alert is treated the same. Here's how we assign priority:

1. **Critical** – Active exploitation, malware outbreaks, privilege abuse
2. **High** – Credential compromise, lateral movement, policy violations
3. **Medium** – Suspicious logins, strange behavior from known systems
4. **Low** – Recon attempts, spam, uncommon behavior requiring monitoring

We use both **technical severity** and **business impact** to determine what’s urgent.

---

## 🧰 Day-to-Day Tools Used by SOC Analysts

### SIEM (Security Information and Event Management)
- **Microsoft Sentinel**
- **Splunk**
- **Elastic SIEM**
- **IBM QRadar**

### Threat Intelligence & URL Analysis
- [VirusTotal](https://www.virustotal.com)
- [URLScan.io](https://urlscan.io)
- [AbuseIPDB](https://www.abuseipdb.com)
- [Any.Run](https://any.run)
- [IPVoid](https://www.ipvoid.com)

### System & Endpoint Analysis
- Windows Event Viewer
- Sysinternals Tools
- Microsoft Defender for Endpoint (MDE)
- Process Explorer
- Netstat, Wireshark, Nmap

### Investigation Aids
- MITRE ATT&CK Matrix
- Cyber Kill Chain Mapping
- Kusto Query Language (KQL)
- PowerShell for memory and live system checks
- Jira or ServiceNow for ticketing

---

## 🧠 How We Work

- Investigate one alert at a time
- Use a **realistic simulation approach** (based on internal SOC workflows)
- Perform URL and IP validation
- Check for artifacts in SIEM
- Correlate multiple logs to identify patterns
- Document every single case in detailed reports

Each alert below is presented in **point-wise format**, detailing the source, nature of alert, investigation steps, and the decision taken.

---

## 📋 Alert Investigation Index

Below is a list of investigated alerts, organized for clarity:

1. **[Alert 1: Suspicious URL Detected Blocked by Firewall (Status: Escalated – Phishing Confirmed)](https://github.com/Bharathkasyap/SOC_Simulations_Case_Reports/blob/main/src/Alert1/Alert1%3AAccess_to_Blacklisted_External_URL_Blocked_by_Firewall.md)**
2. **[Alert 4: Inbound Email Containing Suspicious External Link clicked by the user (Escalated)](https://github.com/Bharathkasyap/SOC_Simulations_Case_Reports/blob/main/src/Alert4/Inbound_Email_Containing_Suspicious_External_Link_Clicked_by_User.md)**


> Each alert report is documented in its own folder under `/alerts/` with screenshots, logs, SIEM queries, and conclusions.

---

## 📂 Folder Structure

SOC-Alert-Investigation/

│

├── alerts/

│ ├── alert1/

│ ├── alert2/

│ └── ...
└── README.md ← You are here



---

## 📢 Note to Viewers

This project is part of an **SOC simulation** using publicly available tools and platforms like TryHackMe. The alerts are real in format, synthetic in generation, and the investigation methodology mirrors actual industry practices to help viewers grow into capable analysts.

---

**Stay Sharp. Think Like an Attacker. Defend Like a Professional.**


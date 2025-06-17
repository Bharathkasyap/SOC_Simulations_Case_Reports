# 🚨 Incident Report: Access to Blacklisted External URL Blocked by Firewall

## 🔍 Overview

This report documents the analysis and resolution of a firewall alert triggered when a user from the internal network attempted to access a URL that matched a known threat intelligence feed or organizational blacklist. The firewall successfully blocked the request and prevented any communication with the external host.

<div align="center">
  <img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert1/AlertAssignment.png" width="300" />
</div>

<br>


---

## 📅 Time of Activity

* **Date:** June 17th 2025
* **Time:** 22:03:11 UTC

---

## 🧾 Alert Metadata

* **Alert ID:** 8816
* **Alert Name:** Access to Blacklisted External URL Blocked by Firewall
* **Severity:** High
* **Source:** Firewall
* **Rule Triggered:** Blocked Websites
* **Protocol:** TCP
* **Application:** web-browsing

---

## 🌐 Network Details

* **Source IP:** 10.20.2.17
* **Source Port:** 34257
* **Destination IP:** 67.199.248.11
* **Destination Port:** 80
* **URL:** [http://bit.ly/3sHkX3da12340](http://bit.ly/3sHkX3da12340)

---

## 🔬 Threat Intelligence Analysis

* **VirusTotal:** 2 out of 97 vendors flagged the URL as **phishing** (Criminal IP and PhishLabs).
  <div align="center">
<img src =src/Alert1/Findings2.png width="300">
</div>
 </br>
 
* **ANY.RUN Sandbox:** Link resulted in a 404 error, no malware payload or command-and-control behavior observed.
  <div align="center">
<img src =src/Alert1/Findings1.png width="300">
</div>
 </br>
  
* **URLScan.io:** No malicious redirection, DNS resolves to Bitly hosted on Google Cloud Platform.
  <div align="center">
<img src =src/Alert1/Findings3.png width="300">
</div>
 </br>
  
* **AbuseIPDB:** No reports found for the IP address or URL.
  <div align="center">
<img src =src/Alert1/Findings4.png width="300">
</div>
 </br>
---

## 🛡️ Final Classification

* **True Positive** – The URL matched known malicious indicators, though it was not active at the time of investigation.

---

## 📝 Reasoning for Classification

* The alert is **valid**, triggered by access to a blacklisted domain.
* The request was **blocked successfully** at the firewall.
* URL was previously **active in phishing campaigns**, according to multiple threat feeds.
* No active **exploit or malware** was detected during sandbox execution.

---

## ⛔ Escalation Status

* **Not escalated** – No signs of compromise or lateral movement.

---

## 🧩 Indicators of Compromise (IOCs)

* **URL:** [http://bit.ly/3sHkX3da12340](http://bit.ly/3sHkX3da12340)
* **Destination IP:** 67.199.248.11
* **Reputation Hits:** Criminal IP, PhishLabs

---

## ✅ Recommended Actions

* Provide security awareness to the user associated with source IP 10.20.2.17.
* Monitor for future access attempts to blacklisted or shortener URLs.
* Continue updating URL blacklists and threat intelligence feeds.
* No immediate remediation or containment required.

---

## 🧠 Splunk Query Guidance (For Real Environments)

If Splunk logs were available, the following queries could be used to investigate further:

**Query to identify this specific connection attempt:**

```spl
index=firewall_logs source_ip="10.20.2.17" dest_ip="67.199.248.11" url="http://bit.ly/3sHkX3da12340"
```

**Query to identify other users accessing similar domains:**

```spl
index=firewall_logs url="bit.ly" OR url="*.ly" OR url_category="URL Shorteners"
```

**Query to check if user visited any suspicious redirect or payload URL after shortener access:**

```spl
index=webproxy OR index=dns_logs source_ip="10.20.2.17"
```

These queries help in detecting whether the user attempted to access other malicious URLs or triggered additional alerts. In this case, since logs were not available, simulated analysis confirmed no further activity.

---
Time of activity:
June 17th 2025, 22:03:11 UTC

List of Affected Entities:
Source IP: 10.20.2.17
Destination IP: 67.199.248.11
URL: http://bit.ly/3sHkX3da12340

Reason for Classifying as True Positive:

The firewall alert was triggered due to an outbound connection attempt to a blacklisted URL, which is a valid detection based on organizational security policy.

VirusTotal classified the URL as malicious by two security vendors (Criminal IP and PhishLabs), identifying phishing behavior.

Although the URL is no longer active and returns a 404 error, it was likely flagged in earlier campaigns and was still present in reputation feeds at the time of access.

The use of a URL shortener (bit.ly) for redirection further supports the phishing potential of the link.

Reason for Escalating the Alert:
No escalation required. The firewall successfully blocked the request. Sandbox analysis confirmed no active threat behavior or malware execution. The destination was unreachable at the time of testing.

Recommended Remediation Actions:

Notify the user associated with the source IP and provide phishing awareness guidance.

Monitor the source system for any repeated access to blocked or suspicious domains.

Continue threat feed updates to maintain detection accuracy against similar domains.

No endpoint isolation or forensics needed as no impact was observed.

List of Attack Indicators:

URL: http://bit.ly/3sHkX3da12340

Destination IP: 67.199.248.11

Application: web-browsing

Action Taken: blocked

Rule: Blocked Websites

VirusTotal vendors marking as phishing: Criminal IP, PhishLabs

Sandbox result: No threat behavior detected, URL inactive

Does this alert require escalation?
No

## 📌 Status

* **Resolved – True Positive (No Risk Observed)**

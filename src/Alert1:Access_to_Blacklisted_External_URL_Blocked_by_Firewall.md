# 🚨 Incident Report: Access to Blacklisted External URL Blocked by Firewall

## 🔍 Overview

This report documents the analysis and resolution of a firewall alert triggered when a user from the internal network attempted to access a URL that matched a known threat intelligence feed or organizational blacklist. The firewall successfully blocked the request and prevented any communication with the external host.

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
* **ANY.RUN Sandbox:** Link resulted in a 404 error, no malware payload or command-and-control behavior observed.
* **URLScan.io:** No malicious redirection, DNS resolves to Bitly hosted on Google Cloud Platform.
* **AbuseIPDB:** No reports found for the IP address or URL.

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

## 📌 Status

* **Resolved – True Positive (No Risk Observed)**

# Alert 4: Inbound Email Containing Suspicious External Link Clicked by User


## 📘 Scenario Explanation:
This alert was triggered when an inbound phishing email reached the user’s mailbox, crafted to appear as a security notification from Microsoft. The sender used a typo-squatted domain (`m1crosoftsupport.co`) to impersonate Microsoft and included a malicious link urging the user to “Review Activity.”

Upon review of the **firewall logs**, it was observed that the internal user device (`10.20.2.25`) made an outbound HTTPS connection to the phishing domain (`45.148.10.131`), confirming that the link was clicked. Although the phishing site currently returns a DNS resolution failure, this does not negate the threat it posed at the time of delivery.

<div align="center">
  <img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/AssignedAlert.png" width="800" />
</div>

<br>
---

## 🕒 Time of activity:
June 18th 2025 between 01:17:23 and 01:18:32 UTC

---

## 🧑‍💻 List of Affected Entities:
- **Recipient Email:** c.allen@thetrydaily.thm  
- **Sender Email:** no-reply@m1crosoftsupport.co  
- **Phishing Link:** https://m1crosoftsupport.co/login  
- **Destination IP:** 45.148.10.131  
- **User Device IP:** 10.20.2.25  
- **Email Subject:** Unusual Sign-In Activity on Your Microsoft Account

---

## 🔍 Online Tool Analysis:

### ✅ VirusTotal:
- Result: **0/97 vendors flagged the domain** as malicious.
- However, the domain was registered in a suspicious pattern (`m1crosoftsupport.co`) clearly intended to mimic Microsoft.
- Link used: `https://m1crosoftsupport.co/login`
<div align="center">
  <img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/TotalVirus.png" width="800" />
</div>


<br>
### ✅ AnyRun Sandbox:
- URL rendered unreachable.
- Confirmed that the domain could not serve a payload.
- However, the infrastructure used appears to have been **dismantled or expired**, which often happens **post-campaign**.
<div align="center">
  <img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/AnyVirus.png" width="800" />
</div>

### ✅ URLScan.io:
- Response: **DNS Error** - could not resolve domain.
- Indicates the domain was taken down, but might have been active at the time the email was sent.
- 
<div align="center">
  <img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/URLScanIO.png" width="800" />
</div>

### ✅ AbuseIPDB:
- Result: **404 Page Not Found**.
- No listings associated with the IP at present, but this does not rule out abuse during its active time.

<div align="center">
  <img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/AbuseIPDB.png" width="800" />
</div>

---

## ✅ Reason for Classifying as True Positive:
- The domain `m1crosoftsupport.co` is a **malicious impersonation** of Microsoft using typo-squatting.
- The email employed **urgency-based social engineering** to encourage user action.
- **Firewall logs confirmed** that the user clicked the link and traffic to the phishing domain was allowed.
- Despite the domain appearing inactive now, it was likely part of a **live phishing infrastructure** when accessed.
- The attack was **not simulated or internally generated**, indicating a real threat.

<table>
  <tr>
    <td><img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/SplunkLogs2.png" width="550"></td>
    <td><img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/SplunkLogs1.png" width="550"></td>
       
</table>

<div align="center">
  <img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/SplunkLogs2.png" width="450" style="margin-right: 20px;">
  <img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/SplunkLogs1.png" width="450">
</div>


<div align="center">
  <img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/SplunkLogs2.png" width="450" />
</div>

<div align="center">
  <img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/SplunkLogs1.png" width="450" />
</div>
---

## 🚨 Reason for Escalating the Alert:
- User interaction with a phishing link means **potential credential compromise**.
- Immediate escalation ensures containment, password reset, and follow-up investigation.
- Even if the phishing page is inactive now, it could have logged credentials when the user accessed it.
- Escalating allows us to:
  - Investigate user’s device
  - Block associated domains and IPs
  - Launch awareness campaigns for similar spoofing attempts
  - Perform a broader tenant-wide search

---

## 🛠️ Recommended Remediation Actions:
- **Reset credentials** for user c.allen@thetrydaily.thm immediately.
- Conduct a **forensic investigation** on the user’s device (`10.20.2.25`) for malware traces.
- Block domain `m1crosoftsupport.co` and IP `45.148.10.131` at the firewall and proxy layers.
- Conduct a **tenant-wide search** for other emails from the same spoofed domain.
- Educate the user on **phishing awareness**, especially impersonation and typo-squatting tactics.
- Create alerting rules in SIEM for **known impersonation domains** and suspicious URL clicks.

---

## 🧾 List of Attack Indicators:
- **Phishing Domain:** `m1crosoftsupport.co`  
- **URL Clicked:** `https://m1crosoftsupport.co/login`  
- **Sender Address:** `no-reply@m1crosoftsupport.co`  
- **Subject Line:** *Unusual Sign-In Activity on Your Microsoft Account*  
- **Destination IP:** `45.148.10.131`  
- **User Host IP:** `10.20.2.25`  
- **Protocol:** HTTPS (TCP Port 443)  
- **Firewall Action:** Allowed  
- **Email Timestamp:** `2025-06-18T00:17:23.962`  
- **Click Timestamp:** `2025-06-18T00:18:32.962`

---


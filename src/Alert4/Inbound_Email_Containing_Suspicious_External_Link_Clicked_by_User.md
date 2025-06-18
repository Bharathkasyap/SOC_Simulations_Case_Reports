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

## 🧪 Splunk Log-Based Confirmation of User Click
After reviewing the logs collected via Splunk, it was confirmed that the inbound phishing email containing the suspicious domain https://m1crosoftsupport.co/login was successfully delivered to the user's inbox at 01:17:23 UTC. Shortly thereafter, at 01:18:32 UTC, firewall logs captured via Splunk showed that the same user device (10.20.2.25) initiated an outbound HTTPS connection to the phishing domain.

This timeline clearly demonstrates that the user clicked on the embedded phishing link, resulting in successful network communication with the external site. Although the phishing domain was later found to be inactive through external sandbox and reputation tools, the user interaction with the infrastructure is an indication of real exposure.

This behavior meets the threshold for a True Positive classification and warrants escalation, as user credentials may have been compromised during the short window when the phishing domain was accessible.

<table>
  <tr>
    <td><img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/SplunkLogs2.png" width="550"></td>
    <td><img src="https://github.com/Bharathkasyap/SOC_Simulations_Case_Reprots/blob/main/src/Alert4/SplunkLogs1.png" width="550"></td>
       
</table>

---


## ✅ Reason for Classifying as True Positive:
- The domain `m1crosoftsupport.co` is a **malicious impersonation** of Microsoft using typo-squatting.
- The email employed **urgency-based social engineering** to encourage user action.
- **Firewall logs confirmed** that the user clicked the link and traffic to the phishing domain was allowed.
- Despite the domain appearing inactive now, it was likely part of a **live phishing infrastructure** when accessed.
- The attack was **not simulated or internally generated**, indicating a real threat.

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

## ✅ Final Incident Report (Format as per the SOC system)

### Is it a True Positive:
Yes

### Time of activity:
June 18th 2025 between 01:17:23 and 01:18:32 UTC

### List of Affected Entities:
- Email Recipient: c.allen@thetrydaily.thm
- Sender: no-reply@m1crosoftsupport.co
- Phishing URL Clicked: https://m1crosoftsupport.co/login
- Source Device IP: 10.20.2.25
- Destination IP: 45.148.10.131 (Phishing server)

### Reason for Classifying as True Positive:
- The email originated from a typo-squatted domain impersonating Microsoft (m1crosoftsupport.co).
- The message contained social engineering language encouraging urgent action.
- The recipient clicked on the phishing link — confirmed via firewall logs showing allowed HTTP(S) traffic to the phishing domain.
- Email content and sender are not part of any legitimate workflow or known contact, supporting its classification as malicious.

### Reason for Escalating the Alert:
- This is now an active compromise attempt. The user interaction could have resulted in credential theft or session hijacking.
- The phishing infrastructure may still be collecting data despite currently showing inactive pages.
- Similar emails may have been sent to other employees using the same spoofing infrastructure.
- Response and awareness are required from Incident Response, IT, and Security Awareness teams.


### Recommended Remediation Actions:
- Immediately initiate credential reset for the affected user.
- Perform endpoint scan on the user’s machine (IP: 10.20.2.25) for any dropped malware or changes.
- Add phishing domain and destination IP to blocklists in email and web proxy.
- Perform email sweep across the domain to identify similar phishing attempts.
- Educate the user on phishing techniques and impersonation threats.
- Add a detection rule to alert on future access to typo-squatted domains mimicking Microsoft.

### List of Attack Indicators:
- Spoofed Domain: m1crosoftsupport.co
- URL Clicked: https://m1crosoftsupport.co/login
- Destination IP: 45.148.10.131
- Sender: no-reply@m1crosoftsupport.co
- Subject: Unusual Sign-In Activity on Your Microsoft Account
- Source Device IP: 10.20.2.25
- Protocol: HTTPS (TCP Port 443)
- Email Received at: 2025-06-18T00:17:23.962
- Click Registered at: 2025-06-18T00:18:32.962

### Does this alert require escalation?
Yes

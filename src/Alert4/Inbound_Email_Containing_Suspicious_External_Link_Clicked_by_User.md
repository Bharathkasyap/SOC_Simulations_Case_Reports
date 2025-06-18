# Alert 4: Inbound Email Containing Suspicious External Link Clicked by User

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

## ✅ Reason for Classifying as True Positive:
- The domain `m1crosoftsupport.co` is a clear **typo-squatted impersonation** of the legitimate Microsoft domain.
- The email used **social engineering tactics** (urgent security warning) to prompt user interaction.
- **Firewall logs confirm the user clicked the phishing link**, with a successful outbound connection from internal IP `10.20.2.25` to the phishing domain.
- Email came from an untrusted external sender and was not part of any known business communication.
- Indicators match common phishing campaigns used to harvest credentials through impersonation.

---

## 🚨 Reason for Escalating the Alert:
- The user interaction implies **first-stage compromise** and raises the possibility of credential exposure.
- Even if the phishing page is no longer live, the attacker could have captured credentials at the time of access.
- Escalation ensures **password reset, device investigation, and organization-wide phishing sweeps** are triggered.
- Infrastructure may be reused in future attacks on other employees unless proactively blocked.

---

## 🛠️ Recommended Remediation Actions:
- **Immediately reset the credentials** of the affected user.
- Perform **endpoint forensic scan** of the device with IP `10.20.2.25` for signs of malware or further compromise.
- Add `m1crosoftsupport.co` and `45.148.10.131` to **email, proxy, and firewall blocklists**.
- Search tenant-wide for similar phishing attempts and **alert other potential targets**.
- Train user on identifying **lookalike domains and phishing patterns**.
- Create SIEM rules to detect **outbound requests to suspicious or typo-squatted domains**.

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

<div align="center">
<img src=../../Alert4/AlertAssignment.png width="300">
</div>

</br>






# Alert 4: Inbound Email Containing Suspicious External Link Clicked by User

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

## 📘 Scenario Explanation:
This alert was triggered when an inbound phishing email reached the user’s mailbox, crafted to appear as a security notification from Microsoft. The sender used a typo-squatted domain (`m1crosoftsupport.co`) to impersonate Microsoft and included a malicious link urging the user to “Review Activity.”

Upon review of the **firewall logs**, it was observed that the internal user device (`10.20.2.25`) made an outbound HTTPS connection to the phishing domain (`45.148.10.131`) confirming that the link was clicked. Although the phishing site currently returns a DNS resolution failure, this does not negate the threat it posed at the time of delivery.

---

## 🔍 Online Tool Analysis:

### ✅ VirusTotal:
- Result: **0/97 vendors flagged the domain** as malicious.
- However, the domain was registered in a suspicious pattern (`m1crosoftsupport.co`) clearly intended to mimic Microsoft.
- Link used: `https://m1crosoftsupport.co/login`

### ✅ AnyRun Sandbox:
- URL rendered unreachable.
- Confirmed that the domain could not serve a payload.
- However, the infrastructure used appears to have been **dismantled or expired**, which often happens **post-campaign**.

### ✅ URLScan.io:
- Response: **DNS Error** - could not resolve domain.
- Indicates the domain was taken down, but might have been active at the time the email was sent.

### ✅ AbuseIPDB:
- Result: **404 Page Not Found**.
- No listings associated with the IP at present, but this does not rule out abuse during its active time.

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

<div align="center">
<img src=../../Alert4/AlertAssignment.png width="300">
</div>

</br>


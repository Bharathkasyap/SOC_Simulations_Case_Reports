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

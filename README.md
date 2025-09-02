# 📧 Phishing Detection & Threat Hunting Lab  

## 🔹 Overview  
Phishing remains the most common entry point for attackers in 2025. This project simulates phishing email activity and related web proxy traffic, then applies **threat hunting, detection queries, and Sigma rules** to identify suspicious behavior.  

The lab demonstrates **real-world SOC analyst skills**: log analysis, SIEM rule building, and MITRE ATT&CK mapping.  

---

## 🔹 Dataset  

The project includes two synthetic but realistic datasets:  

1. **Email Logs (`datasets/email_logs.csv`)**  
   Suspicious patterns include lookalike domains, malicious attachments (`.exe`, `.zip`, `.xlsm`), and SPF/DKIM failures.  

2. **Proxy Logs (`datasets/proxy_logs.csv`)**  
   Suspicious patterns include connections to phishing domains and credential exfiltration attempts.  

---

## 🔹 Detection Logic  

### 📌 SPL (Splunk Queries)  

**1. Detect suspicious email senders:**  
```spl
index=email_logs
| where like(sender, "%paypa1.com%") OR like(sender, "%micr0soft%")
| table _time, sender, recipient, subject, attachment_name
```

**2. Detect malicious attachments:**  
```spl
index=email_logs
| where attachment_type IN ("exe", "zip", "xlsm")
| stats count by sender, attachment_name, recipient
```

**3. Detect proxy traffic to phishing domains:**  
```spl
index=proxy_logs
| regex destination_url=".*(phish|drive-fake|cdn).*"
| stats count by user, destination_url, http_status
```

---

### 📌 Sigma Rule (Suspicious Attachment)  

```yaml
title: Suspicious Email Attachment
id: 123e4567-e89b-12d3-a456-426614174000
status: experimental
description: Detects potentially malicious email attachments in logs
author: Tirthraj Sisodiya
logsource:
  category: email
  product: exchange
detection:
  selection:
    attachment_type|contains:
      - "exe"
      - "zip"
      - "xlsm"
  condition: selection
fields:
  - timestamp
  - sender
  - recipient
  - attachment_name
falsepositives:
  - Internal testing files
level: high
```

---

## 🔹 MITRE ATT&CK Mapping  

| Technique | ID | Description |  
|-----------|----|-------------|  
| Spearphishing Attachment | T1566.001 | Emails with malicious attachments |  
| Spearphishing Link | T1566.002 | Emails with malicious URLs |  
| Web Protocols (C2) | T1071.001 | C2 via HTTP/HTTPS |  
| Email Collection | T1114 | Attacker harvesting victim’s emails |  

---

## 🔹 Results  

✅ Successfully identified:  
- Fake email domains  
- Malicious attachments  
- Phishing domain access via proxy logs  

📊 This lab shows **how phishing campaigns are detected in real SOC workflows** using email + proxy correlation.  

---

## 🔹 Skills Demonstrated  

- Threat Hunting (Email + Proxy log analysis)  
- SIEM Rule Writing (Splunk SPL, Sigma)  
- MITRE ATT&CK Mapping  
- Log Correlation for Incident Detection  

---

⚡ **Author:** Tirthraj Sisodiya  
🔗 LinkedIn: [linkedin.com/in/tirthraj-cybersecurity](https://linkedin.com/in/tirthraj-cybersecurity)  

# SOC127 - SQL Injection Detected (Event ID: 60)

## Executive Summary

On February 14, 2021, the Security Operations Center (SOC) received an alert for a SQL Injection attack originating from the host **PentestMachine** (172.16.20.5) and targeting the **gitServer** (172.16.20.4). While the request URL contained a clear and valid SQL injection payload, the investigation revealed multiple strong indicators that this was part of a planned and authorized penetration test. The source hostname, the username `kali`, and a `User-Agent` string explicitly stating "Penetration Test - Do not Contain" all confirm the non-malicious context of this activity. The alert is therefore classified as a **False Positive**, as it represents authorized security testing.

## Incident Details

The initial alert was triggered by a URL containing a classic SQL injection payload:

<img width="1444" height="536" alt="image" src="https://github.com/user-attachments/assets/388c4aed-43df-4b8b-832e-875e8d24afc8" />

| | |
| :--- | :--- |
| **Date of Incident**| February 14, 2021 |
| **Source Host**| PentestMachine (172.16.20.5) |
| **Username**| kali |
| **Destination Host**| gitServer (172.16.20.4) |
| **Attack Type**| SQL Injection (Authorized Test) |
| **User Agent**| Penetration Test - Do not Contain |
| **Case Link**| *([Case link ](https://app.letsdefend.io/case-management/casedetail/sohankanna/60))* |

## Investigation and Analysis

### 1. Alert Triage and Contextual Clues

The investigation immediately focused on several key contextual clues from the alert data that pointed away from a real attack:
*   **Source Hostname (`PentestMachine`) and Username (`kali`):** Both of these strongly indicate a system specifically configured for security testing. "Kali" is the name of a popular Linux distribution used for penetration testing.
*   **User-Agent (`Penetration Test - Do not Contain`):** This is the most definitive piece of evidence. The user or tool has set a custom User-Agent string to explicitly inform monitoring systems that this activity is part of an authorized test and that containment actions should not be taken.
*   **Internal Source:** The attack originates from an internal IP address (`172.16.20.5`), which is more common for an internal security team conducting a test than for an external attacker who has already gained a foothold.

### 2. Payload and Log Analysis

While the context points to a test, the payload itself is a valid SQL injection attempt.
*   **Payload:** `...id=1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)` - This is a classic UNION-based SQL injection designed to extract all columns (`SELECT *`) from the `db.users` table.
*   **Log Confirmation:** A review of the network logs confirms the GET request containing this payload was sent from the PentestMachine to the gitServer, and the `Device Action` was `Allowed`.
    <img width="668" height="281" alt="image" src="https://github.com/user-attachments/assets/4beae36a-5f85-4efe-b350-3bea20f461f4" />

### 3. Final Assessment

All indicators collectively confirm this was a planned and authorized security assessment. The SIEM rule correctly identified the technical pattern of a SQL injection attack but lacked the context to understand it was part of a test.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Proxy/Web Server Logs
*   **Skills Demonstrated:** False Positive Analysis, Contextual Triage, Recognition of Pentesting Procedures, SQL Injection Payload Recognition.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **No.** Although the payload is technically malicious, the intent is for authorized testing.
*   **What Is The Attack Type?** **SQL Injection (Authorized Test).**
*   **Incident Classification:** **False Positive.**

## Conclusion and Recommendations

The alert for SOC127 was a **false positive**. The activity detected was a SQL injection attempt performed as part of a legitimate, authorized penetration test. The SIEM rule worked as designed by flagging the attack pattern, but human analysis confirmed the benign context of the event.

**Recommendations:**

1.  **Close Alert:** The alert should be closed as a False Positive, with a note indicating it was related to an authorized penetration test.
2.  **Deconfliction and Communication:** To prevent future false positives and unnecessary investigations, it is critical to improve communication between the SOC and the team conducting the penetration test.
    *   The pentesting team should provide the SOC with the source IP addresses of their testing machines and the general timeframe of their assessment.
    *   This allows the SOC to create temporary alert suppression rules for these specific IPs, ensuring that real attacks from other sources are still detected while ignoring the authorized testing noise.
3.  **Vulnerability Reporting:** The successful SQL injection attempt (indicated by `Device Action: Allowed`) should be officially documented by the penetration testing team and reported to the owners of the **gitServer** application for remediation.

























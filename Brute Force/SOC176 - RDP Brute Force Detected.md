# 	SOC176 - RDP Brute Force Detected

## Executive Summary

On March 7, 2024, the Security Operations Center (SOC) received an alert for a Remote Desktop Protocol (RDP) brute-force attack targeting the host **Matthew** (172.16.17.148). The investigation confirmed a sustained attack from the IP address **218.92.0.56**, which has a significant history of malicious reports. Log analysis revealed numerous failed login attempts (Windows Event ID 4625) followed by a definitive **successful login** (Windows Event ID 4624) for the user account `Matthew`. This is a **True Positive** for a critical security breach, as an external attacker has gained interactive remote access to an internal system. The incident requires immediate containment and escalation.

## Incident Details

The initial alert was triggered by a high volume of RDP login failures from a single source:

<img width="1433" height="631" alt="image" src="https://github.com/user-attachments/assets/420bb467-a1d5-44c6-8b92-82fecfd09591" />

| | |
| :--- | :--- |
| **Date of Incident**| March 7, 2024 |
| **Attacker IP**| 218.92.0.56 |
| **Destination Host**| Matthew (172.16.17.148) |
| **Compromised Account**| `Matthew` |
| **Attack Type**| RDP Brute-Force Attack |
| **Case Link**| *[(Case link)](https://app.letsdefend.io/case-management/casedetail/sohankanna/234)* |

## Investigation and Analysis

### 1. Threat Intelligence

The source IP address `218.92.0.56` was analyzed against multiple threat intelligence platforms, confirming its hostile nature.
*   **VirusTotal:** 7 security vendors flagged the IP as malicious.
    <img width="1708" height="785" alt="image" src="https://github.com/user-attachments/assets/5c688b2b-c0ac-4bb5-8436-27b5edbfe481" />
*   **AbuseIPDB:** The IP has been reported over **455,000 times**, indicating it is a persistent and high-volume source of attacks.
    <img width="1762" height="795" alt="image" src="https://github.com/user-attachments/assets/edf97d3b-6c34-4507-9186-1f3e2cc1c60d" />

### 2. Log Analysis - The Brute-Force Pattern

An analysis of the Windows Security Event Logs on the host "Matthew" revealed a classic brute-force pattern from the attacker's IP. The logs show a large number of **Event ID 4625 (An account failed to log on)** events. The attacker attempted various common usernames like `sysadmin`.

<img width="796" height="328" alt="image" src="https://github.com/user-attachments/assets/07042698-5b7c-4014-97d8-57f4b63722c4" />
<img width="803" height="346" alt="image" src="https://github.com/user-attachments/assets/ff5ceb8c-771d-48b3-b728-383922f32c7a" />
<img width="804" height="356" alt="image" src="https://github.com/user-attachments/assets/e0a6a96b-4792-4fd5-9e39-a724f0f9879c" />

### 3. Log Analysis - Confirmation of Compromise

The most critical finding was an **Event ID 4624 (An account was successfully logged on)** originating from the same attacker IP.

<img width="796" height="361" alt="image" src="https://github.com/user-attachments/assets/34390c6c-6b7a-4269-81aa-cab960188b87" />

*   **Username:** `Matthew`
*   **Event ID:** 4624 (Successful Logon)
*   **Logon Type:** 10 (RemoteInteractive) - This type specifically confirms the login was via RDP or Terminal Services.
*   **Source IP:** `218.92.0.56`

This log entry is undeniable proof that the attacker successfully guessed the password for the `Matthew` account and gained remote control of the machine.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Windows Event Logs, VirusTotal, AbuseIPDB
*   **Skills Demonstrated:** RDP Attack Analysis, Windows Log Analysis (Event IDs 4624/4625), Threat Intelligence Correlation.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It was a brute-force attack from a known-bad IP.
*   **What Is The Attack Type?** **RDP Brute-Force.**
*   **Was the Attack Successful?** **Yes.** Confirmed by a successful login event (ID 4624).
*   **Should the device be isolated?** **Yes.** The host is compromised and under attacker control.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC176 was a **true positive** for a successful RDP brute-force attack. An external attacker has compromised the `Matthew` user account and gained interactive access to the host `172.16.17.148`. This is a critical security breach that could lead to ransomware deployment, data theft, or lateral movement.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host Immediately:** Disconnect the host **Matthew** (172.16.17.148) from the network to terminate the attacker's session and prevent further malicious activity.
2.  **CREDENTIALS - Disable Account:** Immediately disable the `Matthew` user account in Active Directory to prevent its use.
3.  **ESCALATE:** Escalate this incident to the Tier 2/Incident Response (IR) team for immediate forensic investigation.
4.  **INVESTIGATION:** The IR team must analyze the host to determine the attacker's actions post-compromise. This includes checking for persistence mechanisms, malware installation, credential dumping, and signs of lateral movement.
5.  **REMEDIATION (Long-Term Security Hardening):**
    *   **Disable Public RDP:** RDP should **never** be directly exposed to the internet. Access should be restricted to a VPN with Multi-Factor Authentication (MFA).
    *   **Enforce Strong Passwords:** Implement and enforce a strong password policy for all users.
    *   **Account Lockout Policy:** Configure a strict account lockout policy to automatically disable accounts after a small number of failed login attempts.
6.  **BLOCK INDICATORS:** Block the attacker's IP address `218.92.0.56` at the network firewall.

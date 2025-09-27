# 	SOC210 - Possible Brute Force Detected on VPN

## Executive Summary

On June 21, 2023, the Security Operations Center (SOC) received a high-severity alert for a brute-force attack against the corporate VPN. The investigation confirmed that the source IP **37.19.221.229**, an address with a history of malicious activity, conducted a methodical attack. Log analysis shows the attacker first performed user enumeration before focusing on the valid account `mane@letsdefend.io` and successfully guessing the password. The logs contain a definitive **"Login Successful"** event, confirming the breach. This is a **True Positive** for a critical security incident, as an external attacker has gained unauthorized access to the corporate network.

## Incident Details

The initial alert was triggered by a successful login following numerous failed attempts from the same source:

<img width="1524" height="562" alt="image" src="https://github.com/user-attachments/assets/798fbe72-b0c0-4a25-a884-7fa1a9d76e94" />

| | |
| :--- | :--- |
| **Date of Incident**| June 21, 2023 |
| **Attacker IP**| 37.19.221.229 |
| **Destination Service**| vpn-letsdefend.io |
| **Compromised Account**| `mane@letsdefend.io` |
| **Affected Host**| Mane (Associated with the user) |
| **Attack Type**| Brute-Force Attack (Password Guessing) |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/162))* |

## Investigation and Analysis

### 1. Threat Intelligence

The attacker's IP address `37.19.221.229` was analyzed against public threat intelligence databases.
*   **VirusTotal:** Showed a low detection rate, with only 1 vendor flagging it as malicious.
    <img width="1827" height="817" alt="image" src="https://github.com/user-attachments/assets/07b82d45-0a4a-430e-a095-558b38ff2e21" />
*   **AbuseIPDB:** Provided stronger evidence, showing 60 reports for activities including honeypot attacks and spam, confirming a history of malicious behavior.
    <img width="1663" height="773" alt="image" src="https://github.com/user-attachments/assets/0b5ba93b-181a-4059-a90b-8ec227689c4a" />

### 2. Log Analysis: The Brute-Force Attack Chain

An analysis of the VPN authentication logs revealed a classic, multi-stage brute-force pattern.

*   **Stage 1: User Enumeration:** The attacker first tried to discover valid usernames by guessing common patterns. The logs show attempts against non-existent users like `sane@letsdefend.io` and `zane@letsdefend.io`.
    <img width="648" height="299" alt="image" src="https://github.com/user-attachments/assets/85bdfa63-1af4-47ee-a56c-c12d18f76e66" />
    <img width="643" height="285" alt="image" src="https://github.com/user-attachments/assets/fb6381b9-f0eb-4b42-bc83-79f8d4914390" />

*   **Stage 2: Password Guessing:** After discovering a valid username, `mane@letsdefend.io`, the attacker pivoted to password brute-forcing. The logs show failed attempts where the "user name is correct but the password is wrong."
    <img width="636" height="285" alt="image" src="https://github.com/user-attachments/assets/43790e08-bb53-4d94-90f7-e21281da783a" />

*   **Stage 3: Successful Compromise:** The attack culminated in a definitive **"Login Successful"** log entry for the user `mane@letsdefend.io` from the attacker's IP. This is the "smoking gun" that confirms the account compromise.
    <img width="643" height="309" alt="image" src="https://github.com/user-attachments/assets/70c45686-5d74-48a8-9779-cb11b41447d5" />

### 3. Post-Compromise Check

A review of the endpoint security logs for the host "Mane" did not reveal any immediate execution of malicious commands or files after the successful login. However, this does not diminish the severity of the incident. The attacker has a valid foothold on the network and may be in a reconnaissance phase or waiting to act.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, VPN Logs, VirusTotal, AbuseIPDB
*   **Skills Demonstrated:** Brute-Force Attack Analysis, Log Correlation, User Enumeration Recognition.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It was a brute-force attack from an IP with a history of abuse.
*   **What Is The Attack Type?** **Brute-Force Attack.**
*   **Was the Attack Successful?** **Yes.** Confirmed by a "Login Successful" log event.
*   **Does the device need to be isolated?** **Yes.** The user's account is compromised, and their machine must be treated as potentially hostile.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC210 was a **true positive** for a successful VPN brute-force attack. An external attacker has compromised the `mane@letsdefend.io` account and gained access to the corporate network. This represents a critical breach of the network perimeter and requires immediate and decisive action.

**Recommendations:**

1.  **CONTAINMENT - Disable Account and Terminate Session:** Immediately disable the `mane@letsdefend.io` user account in Active Directory. Concurrently, terminate all active VPN sessions associated with this user to sever the attacker's connection.
2.  **CONTAINMENT - Isolate Host:** Isolate the user's primary machine ("Mane") from the network to prevent it from being used as a pivot point.
3.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team for a full investigation into post-compromise activity.
4.  **INVESTIGATION:** The IR team must analyze all network and authentication logs for activity from the compromised user account and the attacker's IP since the time of the successful login. The investigation should hunt for any signs of lateral movement, internal reconnaissance, or data access.
5.  **REMEDIATION (Long-Term Security Hardening):**
    *   **Enforce MFA on VPN:** This is the single most effective control to prevent brute-force attacks. Multi-Factor Authentication must be implemented on the VPN immediately.
    *   **Account Lockout Policy:** Implement a strict account lockout policy on the VPN to automatically disable accounts after a small number of failed login attempts.
6.  **BLOCK INDICATORS:** Block the attacker's IP address `37.19.221.229` at the network firewall.

# SOC246 - Forced Authentication Detected


## Executive Summary

On December 12, 2023, the Security Operations Center (SOC) received an alert for a forced authentication attack against the **WebServer_Test** host, specifically the login page for `test-frontend.letsdefend.io`. The investigation confirmed that the source IP **120.48.36.175** conducted a high-volume brute-force attack. Log analysis revealed definitive proof of success: a log entry showing **"User Login Successful"** for the **`admin`** account. This is a **True Positive** for a critical security breach, as a privileged account has been compromised. The incident requires immediate escalation for containment and further investigation into post-compromise activity.

## Incident Details

The initial alert was triggered by a high rate of POST requests to a login page from a single IP:

<img width="1476" height="591" alt="image" src="https://github.com/user-attachments/assets/5f7a818e-95eb-4f29-869a-8ce44dbe6180" />

| | |
| :--- | :--- |
| **Date of Incident**| December 12, 2023 |
| **Attacker IP**| 120.48.36.175 |
| **Destination Host**| WebServer_Test (`test-frontend.letsdefend.io` at 104.26.15.61) |
| **Compromised Account**| `admin` |
| **Attack Type**| Brute-Force Attack |
| **Case Link**| *([Case link ](https://app.letsdefend.io/case-management/casedetail/sohankanna/208))* |

## Investigation and Analysis

### 1. Log Analysis - Identifying the Brute-Force Pattern

The alert was triggered by `Multiple POST requests...from the same IP to the fixed URI "/accounts/login"`. A review of the web server logs confirmed this activity, showing a large number of login attempts originating from the attacker IP `120.48.36.175`. This pattern is characteristic of a brute-force or password-spraying attack, where an attacker systematically tries different credentials.

<img width="814" height="387" alt="image" src="https://github.com/user-attachments/assets/b5cf0edb-6d13-4554-b704-252235e007fe" />
<img width="798" height="387" alt="image" src="https://github.com/user-attachments/assets/5020c0fc-1118-4ea8-bf13-b9ccd242f716" />
<img width="819" height="403" alt="image" src="https://github.com/user-attachments/assets/0e05c5c9-3a33-44ff-aeb2-f1051946b51b" />

### 2. Confirmation of Successful Compromise

While investigating the logs, a single entry provided definitive proof that the attack was successful. This log entry explicitly states that a login for the user **`admin`** was successful.

<img width="813" height="363" alt="image" src="https://github.com/user-attachments/assets/aeacc46e-5ebf-431a-9fd7-af95d5fc2a09" />

*   **Date:** Dec, 12, 2023, 02:15 PM
*   **Source:** 120.48.36.175
*   **Username:** `admin`
*   **Action:** `User Login Successful`

The compromise of a privileged account like `admin` is a critical security event, granting the attacker a high level of access to the web application.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Web Server Logs
*   **Skills Demonstrated:** Brute-Force Attack Analysis, Log Correlation, Incident Triage.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It was a high-volume brute-force attack.
*   **What Is The Attack Type?** **Brute-Force Attack.**
*   **Was the Attack Successful?** **Yes.** The `admin` account was successfully compromised.
*   **Do You Need Tier 2 Escalation?** **Yes.** A confirmed administrative account compromise is a critical incident.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC246 was a **true positive** for a successful brute-force attack. The attacker gained unauthorized access to the application's `admin` account. The immediate priority is to contain the threat and investigate the extent of the attacker's post-compromise activities.

**Recommendations:**

1.  **CONTAINMENT - Immediate Account and Session Invalidation:**
    *   Immediately reset the password for the `admin` account.
    *   Invalidate all active sessions for the `admin` user to force a logout of the attacker.
2.  **BLOCK INDICATORS:** Block the attacker's IP address `120.48.36.175` at the network firewall or WAF.
3.  **ESCALATE:** Immediately escalate this incident to the Tier 2/Incident Response (IR) team.
4.  **INVESTIGATION:** The IR team must conduct an investigation to determine what actions the attacker took after successfully logging in. This includes checking for data exfiltration, changes to application settings, user creation, or any signs of pivoting to other systems.
5.  **REMEDIATION - Implement Stronger Authentication Controls:**
    *   **Account Lockout:** Implement a strict account lockout policy after a small number of failed login attempts.
    *   **Multi-Factor Authentication (MFA):** Enforce MFA on all accounts, especially for privileged users like `admin`.
    *   **Rate-Limiting:** Configure the WAF or load balancer to rate-limit login attempts from a single IP address.

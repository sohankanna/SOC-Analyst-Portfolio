# SOC135 - Multiple FTP Connection Attempt (Event ID:72)

## Executive Summary

On March 7, 2021, the Security Operations Center (SOC) received an alert for multiple failed FTP connection attempts against the **gitServer** (172.16.20.4). The investigation confirmed that an external IP address, **42.192.84.19**, was conducting a low-sophistication brute-force attack against the FTP service's web interface (`webUI.php`). Log analysis shows the attacker repeatedly attempting to log in as the `admin` user with a list of common, weak passwords (e.g., "123456", "admin", "password"). All observed login attempts were **Rejected**. The attack was **unsuccessful**. This is a **True Positive** for a real attack attempt, but no compromise occurred.

## Incident Details

The initial alert was triggered by a high rate of connection attempts to an FTP service:

<img width="1456" height="551" alt="image" src="https://github.com/user-attachments/assets/0867bfeb-0d6d-4503-97df-d2aedee67bcf" />

| | |
| :--- | :--- |
| **Date of Incident**| March 7, 2021 |
| **Attacker IP**| 42.192.84.19 |
| **Destination Host**| gitServer (172.16.20.4) |
| **Target Service**| FTP (`/ftp/webUI.php`) |
| **Target Username**| `admin` |
| **Attack Type**| Brute-Force Attack |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/72))* |

## Investigation and Analysis

### 1. Alert Context: Brute-Force Attacks

The rule `SOC135 - Multiple FTP Connection Attempt` is designed to detect brute-force attacks, a common technique where an attacker systematically tries a large number of usernames and/or passwords in the hope of guessing the correct combination. FTP is a frequent target for such attacks, as a compromised FTP server can be used for malware hosting or data exfiltration.

### 2. Log Analysis: Confirming the Attack Pattern and Outcome

A review of the FTP application logs provided a clear and definitive picture of the attacker's actions and the outcome.
*   **Attack Pattern:** The logs show a series of sequential login attempts from the same source IP (`42.192.84.19`), all targeting the same username (`admin`) but with different, common passwords. This is the classic signature of a password-guessing brute-force attack.
    <img width="704" height="333" alt="image" src="https://github.com/user-attachments/assets/6a393b6b-ce6b-4145-9a78-61794ffa743b" />
    <img width="851" height="346" alt="image" src="https://github.com/user-attachments/assets/96a95ad9-6d7a-4c7a-b70c-cd3eb3fdd14d" />
    <img width="789" height="335" alt="image" src="https://github.com/user-attachments/assets/1180e857-3f48-433c-94d2-44987d88bcd7" />
    <img width="839" height="393" alt="image" src="https://github.com/user-attachments/assets/7e4967c4-31b3-4b5e-a043-8ca15f9c8ec4" />

*   **Outcome:** Critically, the **Status** for every single observed attempt is **Rejected**. This confirms that the attacker did not guess the correct password and failed to gain access to the FTP server. The attack was unsuccessful.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, FTP Application Logs
*   **Skills Demonstrated:** Brute-Force Attack Analysis, Log Correlation, Triage.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It is a brute-force password guessing attack.
*   **What Is The Attack Type?** **Brute-Force Attack.**
*   **Was the Attack Successful?** **No.** All login attempts were rejected.
*   **Do You Need Tier 2 Escalation?** **No.** The attack was unsuccessful and was blocked by the application's authentication mechanism.
*   **Incident Classification:** **True Positive.** (The alert correctly identified an attack attempt).

## Conclusion and Recommendations

The alert for SOC135 was a **true positive**. An external attacker attempted to brute-force the `admin` account on the `gitServer`'s FTP web interface. The investigation confirms that the attack **failed** because the server was configured with a strong password that was not on the attacker's list of common guesses. No compromise occurred.

**Recommendations:**

1.  **Acknowledge Prevention:** Note that the use of a strong, non-default password was the key security control that prevented this compromise.
2.  **BLOCK INDICATORS:** Block the attacker's IP address `42.192.84.19` at the network firewall to prevent them from continuing this attack or attempting others.
3.  **Security Hardening:** This failed attack serves as a valuable warning. The following hardening measures should be implemented:
    *   **Disable External FTP Access:** If there is no business requirement for the FTP server to be accessible from the public internet, its access should be restricted to internal networks only.
    *   **Implement Account Lockout:** Configure the FTP application to automatically lock an account (e.g., for 15 minutes) after a small number of failed login attempts (e.g., 5). This would have stopped this brute-force attack much more quickly.
    *   **Enforce MFA:** If possible, enable Multi-Factor Authentication on the FTP login.
4.  **Close Alert:** The alert can be closed, noting that it was a True Positive for an *attempt* but the outcome was *unsuccessful*.






































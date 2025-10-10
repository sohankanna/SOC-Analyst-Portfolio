# SOC123 - Enumeration Tool Detected (Event ID: 56)

## Executive Summary

On February 13, 2021, the Security Operations Center (SOC) received an alert for an enumeration tool being downloaded to the **gitServer** (172.16.20.4). The investigation confirmed that the user `Jack` used `wget` to download **LinEnum.sh**, a well-known Linux privilege escalation enumeration script, from a public GitHub repository. Endpoint logs provide a clear, step-by-step timeline showing the user downloading the script, making it executable, and then running it. This activity represents unauthorized internal reconnaissance. While the tool itself is not malware, its execution is a serious security policy violation and a common TTP for an attacker (or a malicious insider) preparing to escalate privileges. The alert is a **True Positive**.

## Incident Details

The initial alert was triggered by the download of a known enumeration script:

<img width="1456" height="549" alt="image" src="https://github.com/user-attachments/assets/2b80cbf1-9128-4a94-907e-c1b76551c5cb" />

| | |
| :--- | :--- |
| **Date of Incident**| February 13, 2021 |
| **Source Host**| gitServer (172.16.20.4) |
| **Username**| Jack |
| **Tool Used**| LinEnum.sh |
| **Request URL**| `https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh` |
| **Attack Type**| Internal Reconnaissance / Privilege Escalation Discovery |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/56))* |

## Investigation and Analysis

### 1. Alert Context: Enumeration Tools

The rule `SOC123 - Enumeration Tool Detected` is designed to flag the presence of scripts and tools used for reconnaissance. **LinEnum** is a widely used script that automates the process of checking a Linux system for potential privilege escalation vectors. It searches for:
*   Kernel and OS version information.
*   Weak file permissions on sensitive files (e.g., `/etc/shadow`).
*   SUID/GUID files.
*   Running processes and services.
*   Scheduled tasks (cron jobs).
*   Unmounted filesystems.

While it can be used by system administrators, its primary use in the wild is by penetration testers and malicious actors who have gained an initial foothold and are looking for a way to become `root`.

### 2. Confirmation of Download and Execution

The investigation confirmed the entire attack chain through multiple log sources.
*   **Network Logs:** Log management confirmed the `wget` request from the `gitServer` to `raw.githubusercontent.com` to download `LinEnum.sh`. The `Device Action: Allowed` shows that this download was not blocked.
    <img width="663" height="241" alt="image" src="https://github.com/user-attachments/assets/5e3cca62-4dbe-4af3-9c28-902db0c3f1fc" />
*   **Endpoint Logs (The "Smoking Gun"):** The EDR's command-line history provides a definitive timeline of the user's actions:
    1.  **`wget ... -o /tmp/ah22idah.sh`:** The user downloaded the script and saved it to the `/tmp` directory with a randomized name (`ah22idah.sh`) in a likely attempt to hide its identity.
    2.  **`chmod +x /tmp/ah22idah.sh`:** The user made the downloaded script executable.
    3.  **`./tmp/ah22idah.sh`:** The user executed the script. This initiated the local system reconnaissance.

    <img width="1000" height="243" alt="image" src="https://github.com/user-attachments/assets/80ad4131-17c7-49f6-9e5b-c630b7b54be1" />
    <img width="952" height="210" alt="image" src="https://github.com/user-attachments/assets/a221d549-63e3-48a2-88a5-aa66fa8aa7f5" />

### 3. Final Assessment

The evidence unequivocally shows that an internal user, `Jack`, intentionally downloaded and executed a privilege escalation enumeration tool on the `gitServer`. This is a significant security event, as it could indicate either a malicious insider attempting to escalate their privileges or that the `Jack` user account has been compromised by an external attacker who is now performing internal reconnaissance.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Network Logs
*   **Skills Demonstrated:** Reconnaissance Triage, Linux Command Line Analysis, TTP Recognition, Log Correlation.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** The activity is unauthorized reconnaissance using a known hacking/pentesting tool.
*   **What Is The Attack Type?** **Internal Reconnaissance.**
*   **Was the Attack Successful?** **Yes.** The tool was successfully downloaded and executed.
*   **Do You Need Tier 2 Escalation?** **Yes.** Unauthorized reconnaissance and a potential privilege escalation attempt is a serious incident that requires further investigation.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC123 was a **true positive**. A user, `Jack`, downloaded and ran a known privilege escalation enumeration script on the `gitServer`. This action is a severe violation of security policy and a strong indicator of either a malicious insider or a compromised user account.

**Recommendations:**

1.  **CONTAINMENT - Isolate Host and Disable Account:**
    *   Immediately isolate the **gitServer** (172.16.20.4) from the network to prevent any potential privilege escalation or lateral movement.
    *   Immediately disable the `Jack` user account to prevent any further activity.
2.  **ESCALATE:** Escalate this incident immediately to the Tier 2/Incident Response team, the user's manager, and the appropriate HR or Insider Threat team.
3.  **INVESTIGATION:** A two-pronged investigation is required:
    *   **Technical:** The IR team must analyze the `gitServer` to determine how the `Jack` account was being used (e.g., was it via a normal SSH session, a web shell?) and to review the output of the `LinEnum.sh` script (if it was logged) to see what vulnerabilities were found.
    *   **Human:** The appropriate team must interview the user `Jack` to determine the intent behind this action. Was it curiosity, a malicious act, or was their account compromised?
4.  **REMEDIATION:**
    *   **Unauthorized Software:** The downloaded script should be deleted.
    *   **Policy Enforcement:** Implement stricter application control and command-line logging to detect and block the execution of unauthorized scripts and tools.












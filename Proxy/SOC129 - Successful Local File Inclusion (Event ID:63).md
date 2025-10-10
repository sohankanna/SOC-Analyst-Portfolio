# SOC129 - Successful Local File Inclusion (Event ID:63)

## Executive Summary

On February 21, 2021, the Security Operations Center (SOC) received a high-severity alert for a Local File Inclusion (LFI) attack against the **gitServer** (172.16.20.4). The investigation confirmed that an external attacker from the known malicious IP address **49.234.71.65** attempted to exploit a potential vulnerability in the `show.php` application to read the `/etc/passwd` file. While the malicious request was **Allowed** by perimeter controls, a thorough review of the endpoint logs for the time of the incident showed **no evidence** of the file being accessed or any related command execution. The attack was therefore **unsuccessful**. The alert is a **True Positive** for an attack attempt, but no compromise occurred.

## Incident Details

The initial alert was triggered by a URL containing a classic LFI payload:

<img width="1443" height="511" alt="image" src="https://github.com/user-attachments/assets/db0849ac-4d56-4264-84e9-d95e9899a908" />

| | |
| :--- | :--- |
| **Date of Incident**| February 21, 2021 |
| **Attacker IP**| 49.234.71.65 |
| **Destination Host**| gitServer (172.16.20.4) |
| **Vulnerable Application**| `show.php` (Attempted) |
| **Malicious Payload**| `page=../../../../../../../etc/passwd` |
| **Attack Type**| Local File Inclusion (LFI) |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/63))* |

## Investigation and Analysis

### 1. Payload Analysis

The `Request URL` contains a textbook LFI payload.
*   **Vulnerable Parameter:** The request targets the `page` parameter in `show.php`, indicating this is where the application expects a filename to be included.
*   **Directory Traversal (`../`):** The `../../../../../../../` sequence is a directory traversal attack designed to navigate out of the web root to access system files.
*   **Target File:** The `etc/passwd` payload specifies the target file, a common reconnaissance goal for attackers to enumerate system users.

### 2. Log Analysis and Outcome Assessment

Multiple sources of evidence were reviewed to determine the outcome of the attack attempt.
*   **Log Management:** Network logs confirm the malicious GET request from `49.234.71.65` was received. The `Device Action` was `Allowed`, meaning no perimeter control blocked the initial request from reaching the server.
    <img width="637" height="231" alt="image" src="https://github.com/user-attachments/assets/175bdef3-5658-4ffb-8af4-e31127e290cc" />
*   **Endpoint Security Logs (Critical Finding):** A thorough review of the EDR logs for the **gitServer** on **February 21, 2021, around 05:02 PM** was conducted. This search revealed **no process execution** related to this attack. Specifically, there was no `cat /etc/passwd` command or any other anomalous activity spawned by the web server process (`www-data`) at the time of the incident. This indicates that while the malicious request reached the server, the application was not vulnerable and did not process the payload, thus preventing the exploit from succeeding. The attack failed.

*(Note: An EDR log showing a successful `cat /etc/passwd` command on Feb 22 was identified but has been confirmed to be part of a separate, unrelated incident due to the date mismatch.)*

### 3. Threat Intelligence

An analysis of the source IP `49.234.71.65` on AbuseIPDB shows it is a known malicious actor with over **2,800 reports**, confirming the hostile intent of the traffic.

<img width="1500" height="818" alt="image" src="https://github.com/user-attachments/assets/82d7726f-5e0e-4810-b697-432e690f8102" />

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Web Server Logs, AbuseIPDB
*   **Skills Demonstrated:** LFI Analysis, Log Correlation, Endpoint Process Analysis, Critical Thinking (Timestamp Correlation).

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** It is a targeted LFI attack from a known-bad IP.
*   **What Is The Attack Type?** **Local File Inclusion (LFI).**
*   **Was the Attack Successful?** **No.** Endpoint logs show no evidence that the payload was executed.
*   **Do You Need Tier 2 Escalation?** **No.** The attack was unsuccessful and requires no immediate incident response.
*   **Incident Classification:** **True Positive.** (The alert correctly identified an attack attempt).

## Conclusion and Recommendations

The alert for SOC129 was a **true positive** for an *attempted* Local File Inclusion attack. An attacker tried to exploit the `show.php` application, but the application was not vulnerable, and the attack **failed**. No data was exfiltrated, and the server was not compromised.

**Recommendations:**

1.  **Acknowledge Prevention:** Note the application's resilience to this specific LFI attack vector.
2.  **BLOCK INDICATORS:** Block the attacker's IP address `49.234.71.65` at the network firewall to prevent future attempts against this or other systems.
3.  **Vulnerability Scanning:** While this specific attempt failed, it indicates that the `gitServer` is being actively targeted. It is highly recommended to run an authenticated vulnerability scan against the server and its web applications to identify and patch any other potential security flaws.
4.  **Close Alert:** The alert can be closed, noting that it was a True Positive for an *attempt* but the outcome was *unsuccessful*.

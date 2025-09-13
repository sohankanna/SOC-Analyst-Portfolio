# SOC170 - Passwd Found in Requested URL - Possible LFI Attack

## Executive Summary

On March 1, 2022, the Security Operations Center (SOC) received an alert for a potential Local File Inclusion (LFI) attack targeting **WebServer1006** (172.16.17.13). The attack originated from the IP address **106.55.45.162**. The attacker attempted to use a directory traversal payload to access the sensitive `/etc/passwd` file. Log analysis confirmed the attack attempt but also showed that it was **unsuccessful**. The server responded with an **HTTP 500 Internal Server Error** and a response size of zero, indicating that the application failed to process the malicious request and no data was exfiltrated. The incident is a **True Positive**, but the attack failed and requires no escalation.

## Incident Details

The initial alert was triggered by the presence of "passwd" in a requested URL:

<img width="1490" height="608" alt="image" src="https://github.com/user-attachments/assets/684970c6-37cd-4543-9849-daf9df0a9a54" />

| | |
| :--- | :--- |
| **Date of Incident** | March 1, 2022 |
| **Source IP Address** | 106.55.45.162 |
| **Destination Host** | WebServer1006 (172.16.17.13) |
| **Attack Type** | Local File Inclusion (LFI) |
| **Malicious Payload** | `https://172.16.17.13/?file=../../../../etc/passwd` |
| **Case Link** | [View Full Case on LetsDefend.io](https://app.letsdefend.io/case-management/casedetail/sohankanna/120) |

## Investigation and Analysis

### 1. Payload Analysis

The requested URL contained a classic LFI payload. The `../../../../` is a directory traversal sequence designed to navigate up from the web application's root directory to the filesystem's root, in order to access the `/etc/passwd` file, which contains a list of user accounts on a Linux system.

### 2. Log Analysis and Confirmation of Failure

A review of the logs for the source IP `106.55.45.162` confirmed the GET request containing the malicious payload.

<img width="1565" height="453" alt="image" src="https://github.com/user-attachments/assets/b4d094c6-b9b8-4a0a-b348-f7929e40ed7f" />

However, the details of the server's response clearly indicate that the attack was unsuccessful:

<img width="641" height="347" alt="image" src="https://github.com/user-attachments/assets/29b1c5f6-1b2a-45f4-be1e-0b738c8f25d4" />

*   **HTTP Response Status: 500 (Internal Server Error):** This response means the server encountered an unexpected condition that prevented it from fulfilling the request. The malicious input likely caused an error in the application's code, effectively stopping the attack.
*   **HTTP Response Size: 0:** A zero-byte response is critical evidence. It confirms that no data, specifically the contents of the `/etc/passwd` file, was sent back to the attacker.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Log Management
*   **Skills Demonstrated:** Web Attack Analysis (LFI), Log Correlation, HTTP Protocol Analysis.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** The request contained a clear LFI payload with malicious intent.
*   **What Is The Attack Type?** **Local File Inclusion (LFI).**
*   **What Is the Direction of Traffic?** **Internet → Company Network.**
*   **Was the Attack Successful?** **No.** The server returned a 500 error and no data was exfiltrated.
*   **Do You Need Tier 2 Escalation?** **No.** The attack was automatically prevented by the application's error handling.
*   **Incident Classification:** **True Positive.**

## Conclusion and Recommendations

The alert for SOC170 was a **true positive** for an attempted LFI attack. The investigation confirms that while the application appears to be vulnerable to directory traversal, the attack was thwarted by the server's internal error handling. No sensitive data was compromised.

**Recommendations:**

1.  **Acknowledge Prevention:** Note the successful, albeit likely unintentional, prevention of the attack.
2.  **Block Malicious IP:** Add the source IP address `106.55.45.162` to the network firewall's blocklist to prevent further attempts from this actor.
3.  **Vulnerability Remediation:** While the attack failed, the fact that it triggered a 500 error instead of being gracefully handled (e.g., with a "File Not Found" error) suggests a potential vulnerability. Escalate this finding to the web development team. They should review the application's code to implement proper input validation and sanitization on the `file` parameter to prevent directory traversal attempts.

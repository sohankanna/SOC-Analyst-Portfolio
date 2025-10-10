# SOC102 - Proxy - Suspicious URL Detected (Event ID:26)


## Executive Summary

On October 29, 2020, the Security Operations Center (SOC) received a high-severity alert for a suspicious URL accessed from the host **BillPRD** (172.16.17.47). The investigation confirmed that a user attempted to download a malicious executable (`ac.exe`) from a known-malicious domain. However, several key indicators, most notably the **`User-Agent`** string "Firewall Test - Dont Block," confirm this was not a genuine user infection but a deliberate and authorized security test. The firewall/proxy successfully identified the threat, and the **Device Action** was **Blocked**. The alert is a **True Positive** for detecting a malicious pattern, but the event itself represents a successful security control validation, not a compromise.

## Incident Details

The initial alert was triggered by a request for a malicious executable:

<img width="1451" height="535" alt="image" src="https://github.com/user-attachments/assets/a30cbe8e-340f-4861-b870-3fb926191eee" />

| | |
| :--- | :--- |
| **Date of Incident**| October 29, 2020 |
| **Source Host**| BillPRD (172.16.17.47) |
| **Username**| Bill |
| **Malicious URL**| `http://jamesrlongacre.ac.ug/ac.exe` |
| **Malicious IP**| 217.8.117.77 |
| **User Agent**| Firewall Test - Dont Block |
| **Event Type**| Security Control Test |
| **Case Link**| *([Case link ](https://app.letsdefend.io/case-management/casedetail/sohankanna/26))* |

## Investigation and Analysis

### 1. Alert Context: A Deliberate Security Test

The most critical piece of evidence in this alert is the `User-Agent` string: **"Firewall Test - Dont Block"**. This is a clear, human-readable message indicating that a security team member or an automated tool was intentionally attempting to access a malicious resource to verify that security controls (like a web proxy or firewall) are working correctly. The intent was to see if the firewall would block the download.

### 2. Threat Intelligence Verification

The investigation confirmed that the resource used for the test was indeed malicious, making the test a valid one.
*   **URL Analysis (VirusTotal):** The full URL, `http://jamesrlongacre.ac.ug/ac.exe`, was flagged as malicious by **10 security vendors**.
    <img width="1596" height="727" alt="image" src="https://github.com/user-attachments/assets/1e009794-56be-4e22-814d-8378b234f910" />
*   **IP Analysis (VirusTotal):** The destination IP address, `217.8.117.77`, was also flagged as malicious by **9 vendors**.
    <img width="1645" height="733" alt="image" src="https://github.com/user-attachments/assets/a77c1eec-2e41-4277-8450-8ede0e953a77" />

This confirms that the test was conducted against a legitimate, known threat.

### 3. Confirmation of Successful Prevention (Test Passed)

The outcome of the test is clearly documented in the alert details. The **`Device Action: Blocked`** status is the definitive proof that the firewall/proxy performed its function correctly. It identified the request to a malicious URL and blocked the download of `ac.exe`. The malicious file never reached the endpoint, and no compromise occurred. The test was successful.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Proxy Logs, VirusTotal
*   **Skills Demonstrated:** Contextual Triage, Threat Intelligence Correlation, Security Control Validation.

## Playbook Solution: Incident Classification

*   **Is Traffic Malicious?** **Yes.** The requested resource is a confirmed malicious file.
*   **What Is The Attack Type?** **N/A (Security Control Test).**
*   **Was the Attack Successful?** **No.** The download was successfully blocked by the firewall.
*   **Do You Need Tier 2 Escalation?** **No.** This was a successful, planned security test.
*   **Incident Classification:** **True Positive.** (The alert correctly identified a malicious pattern, even though the context was a test).

## Conclusion and Recommendations

The alert for SOC102 was a **true positive**. The SIEM rule correctly detected a request for a malicious executable. However, the investigation confirmed the context was not a genuine attack but an authorized **firewall test**. The test was successful, as the firewall **blocked** the malicious download.

**Recommendations:**

1.  **Acknowledge Prevention:** Note the successful block by the firewall. This is a positive outcome that should be communicated to the network security team.
2.  **Close Alert:** The alert can be closed as a True Positive, with a note clarifying that it was a successful and blocked security control test.
3.  **Improve Deconfliction Process:** This event highlights a need for better communication. The team conducting security tests should inform the SOC of their planned activities, including source IPs and timing. This allows the SOC to de-prioritize or temporarily suppress alerts from known testing sources, enabling them to focus on real, unknown threats.














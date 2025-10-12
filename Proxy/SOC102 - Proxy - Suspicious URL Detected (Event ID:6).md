# SOC102 - Proxy - Suspicious URL Detected (Event ID:6)

## Executive Summary

On August 29, 2020, the Security Operations Center (SOC) received an alert for a suspicious URL accessed from the device **SusieHost** (172.148.17.5). The investigation confirmed that the user `Susie2020` attempted a direct-to-IP connection to **`193.161.193.99`**, a known malicious address. Threat intelligence from VirusTotal and AbuseIPDB confirmed the IP's association with malicious activity. The corporate web proxy or security gateway successfully identified the threat, and the **Device Action** was **Blocked**. This is a **True Positive** for a real threat, but the attack was **unsuccessful** as the connection was prevented.

## Incident Details

The initial alert was triggered by a user's device attempting to connect directly to a malicious IP address:

<img width="1464" height="529" alt="image" src="https://github.com/user-attachments/assets/b2216fda-6c9f-41b2-8931-d830f273519b" />

| | |
| :--- | :--- |
| **Date of Incident**| August 29, 2020 |
| **Source Host**| SusieHost (172.148.17.5) |
| **Username**| Susie2020 |
| **Malicious IP**| 193.161.193.99 |
| **Attack Type**| Malicious Website / C2 Communication |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/6))* |

## Investigation and Analysis

### 1. Alert Triage and Log Analysis

The investigation began by analyzing the alert details, which pointed to a high-risk activity. A "direct-to-IP" web request (where a user's browser navigates to an IP address instead of a domain name) is inherently suspicious and often associated with malicious infrastructure.
*   **Log Confirmation:** A review of the proxy logs confirmed that the user's device made a GET request for `http://193.161.193.99`.
    <img width="921" height="431" alt="image" src="https://github.com/user-attachments/assets/d1ac3f5b-1283-4bec-9095-744b3d09219d" />

### 2. Threat Intelligence Analysis

An analysis of the destination IP address provided definitive confirmation of its malicious nature.
*   **VirusTotal:** The IP address `193.161.193.99` was flagged as malicious by **18 security vendors**, a very strong indicator of hostile infrastructure.
    <img width="1796" height="831" alt="image" src="https://github.com/user-attachments/assets/1e86bcb7-9dda-4933-8c4c-6ef6c67eb810" />
*   **AbuseIPDB:** The IP has over 40 reports for malicious activities, further corroborating the VirusTotal findings.
    <img width="1677" height="827" alt="image" src="https://github.com/user-attachments/assets/6b9fbfda-9e5d-474e-80d4-0094a98842f4" />

### 3. Confirmation of Successful Prevention

The most critical finding of this investigation is that the attack was stopped before it could cause harm. The **`Device Action: Blocked`** status in the SIEM alert is the definitive piece of evidence. This proves that the corporate web security gateway functioned correctly, identified the destination IP as malicious based on its reputation, and blocked the connection. The user's device never successfully communicated with the malicious server.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Proxy Logs, VirusTotal, AbuseIPDB
*   **Skills Demonstrated:** Triage, Threat Intelligence Correlation, Security Control Validation.

## Playbook Solution: Incident Classification

*   **Analyze URL/IP:** **Malicious.** The IP is flagged by numerous TI vendors.
*   **Was the Attack Successful?** **No.** The connection was blocked by the web proxy.
*   **Do You Need Tier 2 Escalation?** **No.** The threat was successfully neutralized by an automated control.
*   **Incident Classification:** **True Positive.** (The alert correctly identified an attempted connection to a malicious IP).

## Conclusion and Recommendations

The alert for SOC102 was a **true positive**. A user's device attempted to connect to a known malicious IP address. The investigation confirms the malicious nature of the destination but, most importantly, confirms that the connection was successfully **blocked** by the web proxy. No systems were compromised.

**Recommendations:**

1.  **Acknowledge Prevention:** Note the successful prevention by the web security gateway.
2.  **Close Alert:** The alert can be closed as a True Positive, with the outcome noted as "Blocked" or "Prevented."
3.  **Investigate Initial Vector:** The critical follow-up action is to determine *why* the user's device attempted to connect to this IP. The User-Agent indicates an iPhone. This could be from a link in a phishing email, a text message (smishing), or a malicious advertisement on a webpage. An interview with the user (`Susie`) is necessary to investigate the root cause.
4.  **Verify Block Rules:** Ensure the malicious IP `193.161.193.99` is permanently on the web filter's and firewall's blocklist.

# SOC133 - Suspicious Request to New Registered Domain (Event ID:69)


## Executive Summary

On February 28, 2021, the Security Operations Center (SOC) received an alert for a suspicious request to a newly registered domain (`amesiana.com`) originating from the host **KatharinePRD** (172.16.15.78). The investigation confirmed that the user `Leo` accessed the website. Threat intelligence analysis from VirusTotal showed no malicious indicators for the domain at the time. A review of endpoint and network logs confirmed the visit but showed **no evidence** of any file downloads or further suspicious activity. The domain is now offline, preventing a retrospective content analysis. Given the lack of malicious indicators, the activity is assessed as benign, and the alert is classified as a **False Positive**.

## Incident Details

The initial alert was triggered by a rule flagging traffic to a domain registered within a short timeframe:

<img width="1473" height="530" alt="image" src="https://github.com/user-attachments/assets/ac180041-59c0-4eba-ab96-987eac63cd03" />

| | |
| :--- | :--- |
| **Date of Incident**| February 28, 2021 |
| **Source Host**| KatharinePRD (172.16.15.78) |
| **Username**| Leo |
| **Destination Host**| amesiana.com (23.227.38.71) |
| **Request URL**| `https://amesiana.com/` |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/69))* |

## Investigation and Analysis

### 1. Alert Context: The Risk of Newly Registered Domains (NRDs)

The rule `SOC133 - Suspicious Request to New Registered Domain` is an important proactive measure. Threat actors frequently register new domains for specific phishing campaigns or as malware C2 servers. These "Newly Registered Domains" (NRDs) often have no negative reputation for the first few hours or days of their existence, allowing them to bypass basic reputation-based security filters. Flagging all traffic to NRDs allows analysts to scrutinize this potentially high-risk activity.

### 2. Threat Intelligence and Log Analysis

The investigation focused on finding any evidence of malicious intent or impact.
*   **Threat Intelligence (VirusTotal):** A check of the domain `amesiana.com` on VirusTotal showed **zero detections**. While not a guarantee of safety for an NRD, it means there were no immediate, known indicators of malice at the time.
    <img width="1668" height="862" alt="image" src="https://github.com/user-attachments/assets/a75b69c8-a343-4cc8-b3f5-c920d15254a7" />
*   **Domain Status:** The domain `amesiana.com` no longer resolves to an IP address. This is common for both short-lived malicious sites and legitimate temporary projects or expired domains.
    <img width="1355" height="459" alt="image" src="https://github.com/user-attachments/assets/7eab64e4-9bff-4e0e-b9d1-59327d1a9725" />
*   **Endpoint and Network Logs:** Logs confirm that the user's browser, `chrome.exe`, accessed the site and the `Device Action` was `Allowed`. Crucially, a review of subsequent traffic showed no file downloads, no form POSTs, and no other suspicious connections originating from the host after the visit.
    <img width="1038" height="119" alt="image" src="https://github.com/user-attachments/assets/d990c2bf-4039-454c-8b8a-981fe9833f30" />

### 3. Final Assessment

The evidence indicates that a user visited a newly created website that was not inherently malicious. This could have been a new blog, a small business, a marketing landing page, or any number of benign sites. The alert correctly flagged the activity based on the domain's age, but human analysis found no malicious indicators. Therefore, the incident is a false positive.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, EDR, Proxy Logs, VirusTotal, DNS Tools
*   **Skills Demonstrated:** False Positive Analysis, NRD (Newly Registered Domain) Triage, Log Correlation.

## Playbook Solution: Incident Classification

*   **Analyze URL:** **Non-malicious** (at the time of analysis, with no negative indicators).
*   **Incident Classification:** **False Positive.**

## Conclusion and Recommendations

The alert for SOC133 was a **false positive**. The rule logic was correct in identifying a connection to a newly registered domain, but the investigation determined the activity was benign and posed no threat.

**Recommendations:**

1.  **Close Alert:** The alert should be closed as a False Positive, with a note detailing that the destination was a non-malicious NRD.
2.  **Rule Tuning:** The SOC should consider tuning the `SOC133` rule. Rather than triggering a "Medium" severity alert for any NRD visit, it could be set to "Low" or "Informational." The severity could then be dynamically increased if the visit is followed by other suspicious events, such as:
    *   A file download (`.exe`, `.zip`, `.docm`, etc.).
    *   A POST request (indicating a form submission).
    *   Connections to other suspicious domains/IPs.
    This would help reduce analyst fatigue while still maintaining visibility into this risk category.



# SOC110 - Proxy - Cryptojacking Detected (Event ID:40)


## Executive Summary

On January 2, 2021, the Security Operations Center (SOC) received a critical alert for a potential cryptojacking activity originating from the host **BillPRD** (172.16.17.47). The alert was triggered by the user `Bill` accessing a URL shortened with `bit.ly`. An investigation was launched to determine the final destination of the shortened link. Using a URL expander, the `bit.ly` link was resolved to a standard YouTube video, specifically a "rickroll," a common internet prank. The destination is benign, and no malicious activity occurred. The alert is therefore classified as a **False Positive**, likely triggered by an overly broad rule that flags all traffic to URL shorteners.

## Incident Details

The initial alert was triggered by a user accessing a URL shortener, which can sometimes be used to hide malicious domains:

<img width="1492" height="509" alt="image" src="https://github.com/user-attachments/assets/f1a9f1a1-2b96-4851-a612-020313011d77" />

| | |
| :--- | :--- |
| **Date of Incident**| January 2, 2021 |
| **Source Host**| BillPRD (172.16.17.47) |
| **Username**| Bill |
| **Destination Host**| bit.ly (67.199.248.10) |
| **Request URL**| `https://bit.ly/3hNuByx` |
| **Suspected Tactic**| Cryptojacking |
| **Case Link**| *([Case link](https://app.letsdefend.io/case-management/casedetail/sohankanna/40))* |

## Investigation and Analysis

### 1. Alert Context: Cryptojacking and URL Shorteners

The rule `SOC110 - Proxy - Cryptojacking Detected` is designed to detect activity associated with browser-based cryptocurrency mining. Attackers often use URL shorteners like `bit.ly` to obscure the true destination of their malicious websites or mining scripts, which is likely why this rule was triggered. Any traffic to a URL shortener can be considered suspicious until the final destination is verified.

### 2. URL Analysis and De-obfuscation

The core of the investigation was to determine the true destination of the shortened link.
*   **Log Confirmation:** A review of the proxy logs confirmed that the user's `chrome.exe` process made a GET request for the URL `https://bit.ly/3hNuByx`, and the `Device Action` was `Allowed`.
    <img width="1132" height="376" alt="image" src="https://github.com/user-attachments/assets/2ab84db2-198a-4265-bf72-1a1722ce7c86" />
*   **URL Expansion:** An online URL expander tool was used to resolve the `bit.ly` link. The tool revealed that the link was not directing to a malicious site, but was a simple redirect to a YouTube video.
    <img width="1432" height="689" alt="image" src="https://github.com/user-attachments/assets/b14b223d-d27c-4b49-a7ac-2aec2e21037f" />
*   **Final Destination:** The final URL is a link to Rick Astley's "Never Gonna Give You Up" on YouTube, a harmless and well-known internet prank known as a "rickroll."

### 3. Final Assessment

The evidence confirms that the user clicked on a harmless link. The SIEM rule, while well-intentioned, generated a false positive because it triggered on the use of a URL shortener without verifying the final destination's maliciousness. No cryptojacking or other malicious activity occurred.

## Skills and Tools Utilized

*   **Tools Used:** SIEM, Proxy Logs, URL Expander
*   **Skills Demonstrated:** False Positive Analysis, Phishing Triage, Use of Debofuscation Tools.

## Playbook Solution: Incident Classification

*   **Analyze URL:** **Non-malicious.** The URL resolves to a harmless YouTube video.
*   **Incident Classification:** **False Positive.**

## Conclusion and Recommendations

The alert for SOC110 was a **false positive**. The investigation confirmed that a user accessed a `bit.ly` link that redirected to a benign YouTube video. The alert was triggered by an overly broad detection rule.

**Recommendations:**

1.  **Close Alert:** The alert should be closed as a False Positive, with notes detailing the findings.
2.  **Rule Tuning:** The SOC team should review the logic for the rule `SOC110 - Proxy - Cryptojacking Detected`. Triggering a critical alert for all traffic to `bit.ly` is inefficient and prone to false positives. The rule should be tuned to be more specific, requiring additional indicators before firing, such as:
    *   Traffic to a URL shortener *that then redirects* to a domain on a threat intelligence list.
    *   Traffic to a URL shortener followed by the download of a specific file type (e.g., `.js`, `.exe`).
    *   Specific URL patterns within the shortened link that are associated with known cryptojacking services.
















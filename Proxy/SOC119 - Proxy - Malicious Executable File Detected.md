# SOC119 - Proxy - Malicious Executable File Detected

## Executive Summary

On March 21, 2021, the Security Operations Center (SOC) received a medium-severity alert for a potentially malicious executable file being downloaded. The traffic originated from the user **Susie** on host **SusieHost** (172.16.17.5) and was directed to the domain **win-rar.com**. An investigation into the destination URL and domain confirmed that the user was downloading the legitimate WinRAR file compression utility from its official website. The activity was benign, and the alert is therefore classified as a **False Positive**. No malicious activity occurred, and no further action is required.

## Incident Details

The initial alert was received from the proxy/SIEM dashboard:

<img width="1487" height="609" alt="image" src="https://github.com/user-attachments/assets/b042d13f-3311-492e-ad2b-c6cf77a0d8b6" />

| | |
| :--- | :--- |
| **Date of Incident** | March 21, 2021 |
| **Source Host** | SusieHost (172.16.17.5) |
| **Username** | Susie |
| **Destination Host** | win-rar.com (51.195.68.163) |
| **Request URL** | `https://www.win-rar.com/postdownload.html?&L=0&Version=32bit` |
| **Case Link** | [View Full Case on LetsDefend.io](https://app.letsdefend.io/case-management/casedetail/sohankanna/83) |

## Investigation and Analysis

### 1. Alert Triage and URL Analysis

The investigation began by analyzing the `Request URL` that triggered the alert. The URL, `https://www.win-rar.com/postdownload.html`, points to the official domain for the WinRAR software, a widely-used and legitimate file archiver utility.

### 2. Threat Intelligence Verification

To confirm the legitimacy of the domain and URL, it was checked against threat intelligence platforms like VirusTotal. The analysis showed that the domain is clean and is indeed the official distribution point for WinRAR.
<img width="1811" height="805" alt="image" src="https://github.com/user-attachments/assets/fe94a5ec-e073-4230-ab9c-35c16f6c57c8" />


<img width="1480" height="884" alt="image" src="https://github.com/user-attachments/assets/70d57261-2009-4b1c-a73b-fec50f4f8744" />

The `Device Action: Allowed` is the expected behavior for a user downloading a known-good application from a reputable source. The activity is consistent with a standard software installation and does not indicate a threat.

## Skills and Tools Utilized

*   **Tools Used:** SIEM / Proxy Logs, VirusTotal
*   **Skills Demonstrated:** Log Analysis, Threat Intelligence Verification, False Positive Analysis.

## Playbook Solution: Incident Classification

*   **Analyze URL Address:** **Non-malicious.** The URL belongs to the official WinRAR website.
*   **Is Traffic Malicious?** **No.** The traffic is a legitimate software download.
*   **What Is The Attack Type?** **N/A (False Positive).**
*   **Was the Attack Successful?** **N/A.** There was no attack.
*   **Do You Need Tier 2 Escalation?** **No.** The alert is a false positive.
*   **Incident Classification:** **False Positive.**

## Conclusion and Recommendations

The alert for SOC119 was a **false positive**. The detection rule was likely triggered by the download of an `.exe` file, but the investigation confirmed the file was the legitimate WinRAR installer from its official source. This is a benign event.

**Recommendations:**

1.  **Close Alert:** The alert should be closed as a False Positive with a note detailing the findings.
2.  **Rule Tuning:** The SOC team should consider tuning the rule `SOC119 - Proxy - Malicious Executable File Detected`. To reduce future false positives, reputable and commonly used software domains like `www.win-rar.com` could be added to an allowlist for this specific rule.
